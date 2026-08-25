package loom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip44"

	"github.com/sharegap/grasp-gitea/internal/cashu"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type testDispatchSigner struct{ key nostr.SecretKey }

func (s testDispatchSigner) PublicKey() string { return s.key.Public().Hex() }
func (s testDispatchSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	return ev.Sign(s.key)
}
func (s testDispatchSigner) NIP44Encrypt(_ context.Context, target nostr.PubKey, plaintext string) (string, error) {
	key, err := nip44.GenerateConversationKey(target, s.key)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, key)
}

func signedWorkerAd(t *testing.T, worker nostr.SecretKey, created time.Time, software string, price string) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{
		Kind: relay.KindLoomWorkerAd, CreatedAt: nostr.Timestamp(created.Unix()),
		Tags: nostr.Tags{
			{"S", software, "1.0", "/usr/bin/" + software},
			{"A", "linux/amd64"}, {"price", "https://mint.invalid", price, "sat"},
			{"metric", "second"}, {"min_duration", "0"}, {"max_duration", "3600"},
		},
		Content: "{}",
	}
	if err := ev.Sign(worker); err != nil {
		t.Fatal(err)
	}
	return ev
}

func signedCurrentWorkerAd(t *testing.T, worker nostr.SecretKey, created time.Time, trustedUnpaid bool) *nostr.Event {
	t.Helper()
	content := `{"capabilities":{"features":[]}}`
	if trustedUnpaid {
		content = `{"capabilities":{"features":["trusted_unpaid_internal_jobs"]}}`
	}
	ev := &nostr.Event{
		Kind: relay.KindLoomWorkerAd, CreatedAt: nostr.Timestamp(created.Unix()),
		Tags: nostr.Tags{
			{"S", "act", "0.2.89", "/usr/local/bin/act"},
			{"price", "cashu", "0.1", "sat", "https://mint.sharegap.net"},
			{"metric", "second"}, {"min_duration", "10"}, {"max_duration", "3600"},
		},
		Content: content,
	}
	if err := ev.Sign(worker); err != nil {
		t.Fatal(err)
	}
	return ev
}

func signedCurrentWorkerAdWithQueue(t *testing.T, worker nostr.SecretKey, created time.Time, depth, max int) *nostr.Event {
	t.Helper()
	ev := signedCurrentWorkerAd(t, worker, created, true)
	ev.Content = fmt.Sprintf(`{"max_concurrent_jobs":%d,"current_queue_depth":%d,"capabilities":{"features":["trusted_unpaid_internal_jobs"]}}`, max, depth)
	if err := ev.Sign(worker); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestWorkerPoolAllowlistCanonicalLatestAndPaymentGate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := nostr.Generate()
	outsider := nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{
		Allowlist: []string{worker.Public().Hex()}, RequiredSoftware: []string{"act"},
		AdTTL: time.Hour, FutureSkew: time.Minute,
	})
	if err := pool.HandleEvent(signedWorkerAd(t, outsider, now, "act", "0"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Select(now, 15*time.Minute, false); ok {
		t.Fatal("non-allowlisted worker was selected")
	}
	first := signedWorkerAd(t, worker, now, "act", "0")
	second := signedWorkerAd(t, worker, now, "act", "0")
	second.Content = `{"revision":2}`
	if err := second.Sign(worker); err != nil {
		t.Fatal(err)
	}
	winner, loser := first, second
	if !canonicalNewer(*winner, *loser) {
		winner, loser = loser, winner
	}
	if err := pool.HandleEvent(winner, now); err != nil {
		t.Fatal(err)
	}
	if err := pool.HandleEvent(loser, now); err != nil {
		t.Fatal(err)
	}
	selected, ok := pool.Select(now, 15*time.Minute, false)
	if !ok || selected.Event.ID != winner.ID {
		t.Fatalf("selected %s, want canonical %s", selected.Event.ID.Hex(), winner.ID.Hex())
	}

	priced := signedWorkerAd(t, worker, now.Add(time.Second), "act", "2")
	if err := pool.HandleEvent(priced, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Select(now.Add(time.Second), 15*time.Minute, false); ok {
		t.Fatal("priced worker selected without static payment")
	}
	if _, ok := pool.Select(now.Add(time.Second), 15*time.Minute, true); !ok {
		t.Fatal("priced worker rejected with static payment configured")
	}
	trustedPriced := signedCurrentWorkerAd(t, worker, now.Add(2*time.Second), true)
	if err := pool.HandleEvent(trustedPriced, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Select(now.Add(2*time.Second), 30*time.Minute, false); !ok {
		t.Fatal("trusted unpaid worker rejected in trusted-fleet mode")
	}
	future := signedWorkerAd(t, worker, now.Add(2*time.Minute), "act", "0")
	if err := pool.HandleEvent(future, now); err == nil {
		t.Fatal("future-skewed worker advertisement accepted")
	}
}

func TestWorkerPoolRejectsPricedCurrentAdWithoutTrustedUnpaidFeature(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{
		Allowlist: []string{worker.Public().Hex()}, RequiredSoftware: []string{"act"},
		AdTTL: time.Hour, FutureSkew: time.Minute,
	})
	if err := pool.HandleEvent(signedCurrentWorkerAd(t, worker, now, false), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Select(now, 30*time.Minute, false); ok {
		t.Fatal("priced current-format worker selected without payment or trusted unpaid feature")
	}
	if selected, ok := pool.SelectForMint(now, 30*time.Minute, "https://mint.sharegap.net"); !ok || selected.Prices["https://mint.sharegap.net"] != 1 {
		t.Fatalf("current-format Cashu price not selectable in paid mode: %#v %v", selected.Prices, ok)
	}
}

func TestWorkerPoolSkipsFullWorkerAndAcceptsNewerCapacity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{
		Allowlist: []string{worker.Public().Hex()}, RequiredSoftware: []string{"act"},
		AdTTL: time.Hour, FutureSkew: time.Minute,
	})
	if err := pool.HandleEvent(signedCurrentWorkerAdWithQueue(t, worker, now, 4, 4), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Select(now, 30*time.Minute, false); ok {
		t.Fatal("worker advertising a full queue was selected")
	}
	if err := pool.HandleEvent(signedCurrentWorkerAdWithQueue(t, worker, now.Add(time.Second), 3, 4), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	selected, ok := pool.Select(now.Add(time.Second), 30*time.Minute, false)
	if !ok {
		t.Fatal("worker with available queue capacity was rejected")
	}
	if selected.QueueDepth != 3 || selected.MaxJobs != 4 {
		t.Fatalf("queue telemetry = depth %d max %d, want 3/4", selected.QueueDepth, selected.MaxJobs)
	}
}

func TestBuildWorkerCommandDefaultUsesIsolatedWorkspace(t *testing.T) {
	req := testDispatchRequest(nostr.Generate().Public().Hex())
	cmd, args, err := buildWorkerCommand("", req)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "sh" || len(args) != 7 {
		t.Fatalf("default command = %q %#v", cmd, args)
	}
	script := args[1]
	for _, want := range []string{
		"mktemp -d",
		"trap 'rm -rf \"$workdir\"' EXIT",
		"$workdir/repo",
		"${HOME:-}/.docker/config.json",
		"$workdir/docker-config",
		"--container-options",
		"/root/.docker",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("default script missing %q: %s", want, script)
		}
	}
	if args[3] != req.CloneURL || args[4] != req.CommitSHA || args[5] != req.Trigger || args[6] != req.WorkflowPath {
		t.Fatalf("default command args = %#v", args)
	}
}

func TestDispatcherPersistsBeforePublishAndNIP44RoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "loom.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	worker := nostr.Generate()
	operator := nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}, AdTTL: time.Hour})
	if err := pool.HandleEvent(signedWorkerAd(t, worker, now, "act", "0"), now); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(DispatcherConfig{
		Enabled: true, MaxDuration: 15 * time.Minute, RelayURLs: []string{"wss://relay.invalid"},
		JobTTL: time.Hour, MaxJobs: 20,
	}, pool, st, testDispatchSigner{operator}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var published []nostr.Event
	d.publish = func(_ context.Context, ev *nostr.Event) error {
		// The attempt and both exact signed payloads must already exist.
		if _, err := st.GetLoomJobByWorkflowRunID(ctx, ev.ID.Hex()); err != nil && ev.Kind == relay.KindHiveWorkflowRun {
			t.Fatalf("workflow was published before persistence: %v", err)
		}
		published = append(published, *ev)
		return nil
	}
	req := testDispatchRequest(operator.Public().Hex())
	handled, err := d.Dispatch(ctx, req)
	if err != nil || !handled {
		t.Fatalf("Dispatch = %v, %v", handled, err)
	}
	if len(published) != 2 || published[0].Kind != relay.KindHiveWorkflowRun || published[1].Kind != relay.KindLoomJobRequest {
		t.Fatalf("published kinds = %#v", published)
	}
	run, request := published[0], published[1]
	if tagValue(run.Tags, "a") != "30617:"+req.OwnerPubkey+":"+req.RepoID ||
		tagValue(run.Tags, "commit") != req.CommitSHA || tagValue(run.Tags, "branch") != req.Branch ||
		tagValue(run.Tags, "trigger") != req.Trigger || tagValue(run.Tags, "triggered-by") != req.TriggeredBy ||
		tagValue(run.Tags, "workflow") != req.WorkflowPath || tagValue(run.Tags, "publisher") == "" ||
		tagValue(run.Tags, "t") != "hive-ci" {
		t.Fatalf("invalid kind-5401 tags: %#v", run.Tags)
	}
	secretTag := request.Tags.Find("secret")
	argsTag := request.Tags.Find("args")
	if tagValue(request.Tags, "p") != worker.Public().Hex() || tagValue(request.Tags, "cmd") == "" ||
		argsTag == nil || len(argsTag) < 2 || tagValue(request.Tags, "e") != run.ID.Hex() ||
		secretTag == nil || len(secretTag) != 3 || secretTag[1] != "HIVE_CI_NSEC" ||
		request.Tags.Find("payment") != nil {
		t.Fatalf("invalid kind-5100 tags: %#v", request.Tags)
	}
	key, _ := dispatchKey(req)
	job, err := st.GetLoomJobByDispatchKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if job.WorkflowRunEvent == "" || job.JobRequestEvent == "" || job.DispatchState != "published" {
		t.Fatalf("durable dispatch = %#v", job)
	}
	secret := tagValue(published[1].Tags, "secret")
	if tag := published[1].Tags.Find("secret"); tag != nil && len(tag) >= 3 {
		secret = tag[2]
	}
	conversation, err := nip44.GenerateConversationKey(operator.Public(), worker)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := nip44.Decrypt(secret, conversation)
	if err != nil {
		t.Fatal(err)
	}
	prefix, decoded, err := nip19.Decode(plaintext)
	if err != nil || prefix != "nsec" {
		t.Fatalf("decrypted HIVE_CI_NSEC = %q, %v", plaintext, err)
	}
	ephemeral, ok := decoded.(nostr.SecretKey)
	if !ok || ephemeral.Public().Hex() != job.PublisherPub {
		t.Fatal("decrypted HIVE_CI_NSEC does not match stored publisher")
	}
	if handled, err := d.Dispatch(ctx, req); err != nil || !handled {
		t.Fatalf("duplicate Dispatch = %v, %v", handled, err)
	}
	if len(published) != 2 {
		t.Fatal("already-published logical dispatch was published again")
	}
}

func TestDispatcherRetryReusesExactEventIDs(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	worker, operator := nostr.Generate(), nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}, AdTTL: time.Hour})
	if err := pool.HandleEvent(signedWorkerAd(t, worker, now, "act", "0"), now); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(DispatcherConfig{Enabled: true, MaxDuration: 15 * time.Minute,
		RelayURLs: []string{"wss://relay.invalid"}}, pool, st, testDispatchSigner{operator}, nil)
	var firstIDs []nostr.ID
	d.publish = func(_ context.Context, ev *nostr.Event) error {
		firstIDs = append(firstIDs, ev.ID)
		return errors.New("relay unavailable")
	}
	req := testDispatchRequest(operator.Public().Hex())
	handled, err := d.Dispatch(ctx, req)
	if !handled || err == nil {
		t.Fatalf("first dispatch = %v, %v", handled, err)
	}
	if len(firstIDs) != 2 {
		t.Fatalf("first publish count = %d", len(firstIDs))
	}
	var retryIDs []nostr.ID
	d.publish = func(_ context.Context, ev *nostr.Event) error {
		retryIDs = append(retryIDs, ev.ID)
		return nil
	}
	handled, err = d.Dispatch(ctx, req)
	if err != nil || !handled {
		t.Fatalf("retry dispatch = %v, %v", handled, err)
	}
	if len(retryIDs) != 2 || retryIDs[0] != firstIDs[0] || retryIDs[1] != firstIDs[1] {
		t.Fatalf("retry IDs = %v, want %v", retryIDs, firstIDs)
	}
}

type countingCashuWallet struct {
	createCalls int
	redeemCalls int
	last        cashu.PaymentRequest
}

func (w *countingCashuWallet) CreatePayment(_ context.Context, req cashu.PaymentRequest) (cashu.Payment, error) {
	w.createCalls++
	w.last = req
	return cashu.Payment{Token: fmt.Sprintf("cashu-token-%d", w.createCalls), QuoteID: "quote-1", Amount: req.Amount}, nil
}
func (w *countingCashuWallet) RedeemChange(context.Context, string) (uint64, error) {
	w.redeemCalls++
	return 1, nil
}
func (w *countingCashuWallet) ReceivePubkey() string { return "02" + stringsOf('c', 64) }
func (w *countingCashuWallet) Close() error          { return nil }

func TestDispatcherCashuSpendIsExactAndNeverRepeated(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "cashu.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	worker, operator := nostr.Generate(), nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}, AdTTL: time.Hour})
	if err := pool.HandleEvent(signedWorkerAd(t, worker, now, "act", "2"), now); err != nil {
		t.Fatal(err)
	}
	wallet := &countingCashuWallet{}
	d := NewDispatcher(DispatcherConfig{Enabled: true, PaymentMode: "cashu", MintURL: "https://mint.invalid",
		MaxDuration: 15 * time.Minute, MaxPayment: 2000, RelayURLs: []string{"wss://relay.invalid"}},
		pool, st, testDispatchSigner{operator}, nil, wallet)
	var firstIDs []nostr.ID
	d.publish = func(_ context.Context, ev *nostr.Event) error {
		firstIDs = append(firstIDs, ev.ID)
		return errors.New("relay unavailable")
	}
	req := testDispatchRequest(operator.Public().Hex())
	if handled, err := d.Dispatch(ctx, req); !handled || err == nil {
		t.Fatalf("first paid dispatch = %v, %v", handled, err)
	}
	if wallet.createCalls != 1 || wallet.last.Amount != 1800 || wallet.last.WorkerPubkey != worker.Public().Hex() {
		t.Fatalf("wallet calls=%d request=%+v", wallet.createCalls, wallet.last)
	}
	key, _ := dispatchKey(req)
	spend, err := st.GetLoomCashuSpend(ctx, key)
	if err != nil || spend.State != "ready" || spend.Token != "cashu-token-1" || spend.Amount != 1800 {
		t.Fatalf("durable spend = %+v, %v", spend, err)
	}
	var retryIDs []nostr.ID
	d.publish = func(_ context.Context, ev *nostr.Event) error {
		retryIDs = append(retryIDs, ev.ID)
		if ev.Kind == relay.KindLoomJobRequest && tagValue(ev.Tags, "payment") != "cashu-token-1" {
			t.Fatalf("retry changed token: %#v", ev.Tags)
		}
		return nil
	}
	if handled, err := d.Dispatch(ctx, req); err != nil || !handled {
		t.Fatalf("paid retry = %v, %v", handled, err)
	}
	if wallet.createCalls != 1 || len(retryIDs) != 2 || retryIDs[0] != firstIDs[0] || retryIDs[1] != firstIDs[1] {
		t.Fatalf("retry double-paid or changed events: calls=%d first=%v retry=%v", wallet.createCalls, firstIDs, retryIDs)
	}
	d.maxPayment = 1000
	over := req
	over.SourceEventID = stringsOf('f', 64)
	over.CommitSHA = stringsOf('f', 40)
	if handled, err := d.Dispatch(ctx, over); handled || err == nil {
		t.Fatalf("over-budget dispatch = %v, %v", handled, err)
	}
	if wallet.createCalls != 1 {
		t.Fatal("over-budget worker reached the wallet")
	}
}

func TestDispatcherCancelsSupersededSameRef(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	worker, operator := nostr.Generate(), nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}, AdTTL: time.Hour})
	if err := pool.HandleEvent(signedWorkerAd(t, worker, now, "act", "0"), now); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(DispatcherConfig{Enabled: true, MaxDuration: 15 * time.Minute,
		RelayURLs: []string{"wss://relay.invalid"}}, pool, st, testDispatchSigner{operator}, nil)
	var published []nostr.Event
	d.publish = func(_ context.Context, ev *nostr.Event) error { published = append(published, *ev); return nil }
	first := testDispatchRequest(operator.Public().Hex())
	if handled, err := d.Dispatch(ctx, first); err != nil || !handled {
		t.Fatal(handled, err)
	}
	firstKey, _ := dispatchKey(first)
	old, err := st.GetLoomJobByDispatchKey(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.SourceEventID = stringsOf('d', 64)
	second.CommitSHA = stringsOf('e', 40)
	if handled, err := d.Dispatch(ctx, second); err != nil || !handled {
		t.Fatal(handled, err)
	}
	var cancel *nostr.Event
	for i := range published {
		if published[i].Kind == relay.KindLoomJobCancel {
			cancel = &published[i]
		}
	}
	if cancel == nil || tagValue(cancel.Tags, "e") != old.JobRequestID || tagValue(cancel.Tags, "p") != old.WorkerPub {
		t.Fatalf("missing/malformed supersession cancellation: %#v", cancel)
	}
	old, err = st.GetLoomJobByWorkflowRunID(ctx, old.WorkflowRunID)
	if err != nil || old.CancelState != "published" {
		t.Fatalf("cancellation outbox = %+v, %v", old, err)
	}
}

func TestDispatcherAmbiguousCashuReservationFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "ambiguous.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	worker, operator := nostr.Generate(), nostr.Generate()
	req := testDispatchRequest(operator.Public().Hex())
	key, _ := dispatchKey(req)
	if _, claimed, err := st.ReserveLoomCashuSpend(ctx, store.LoomCashuSpend{
		DispatchKey: key, WorkerPub: worker.Public().Hex(), WorkerAdID: stringsOf('a', 64), MintURL: "https://mint.invalid",
		Amount: 1800, PricePerSecond: 2, DurationSeconds: 900,
	}, time.Now().UTC()); err != nil || !claimed {
		t.Fatalf("reserve crash window = %v, %v", claimed, err)
	}
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}})
	wallet := &countingCashuWallet{}
	d := NewDispatcher(DispatcherConfig{Enabled: true, PaymentMode: "cashu", MintURL: "https://mint.invalid",
		MaxDuration: 15 * time.Minute, MaxPayment: 2000, RelayURLs: []string{"wss://relay.invalid"}},
		pool, st, testDispatchSigner{operator}, nil, wallet)
	if handled, err := d.Dispatch(ctx, req); handled || err == nil || !strings.Contains(err.Error(), "refusing a second payment") {
		t.Fatalf("ambiguous dispatch = %v, %v", handled, err)
	}
	if wallet.createCalls != 0 {
		t.Fatal("ambiguous reserved spend invoked wallet again")
	}
}

func TestEphemeralPublisherIsolatedAcrossWorkers(t *testing.T) {
	operator, firstWorker, secondWorker := nostr.Generate(), nostr.Generate(), nostr.Generate()
	d := &Dispatcher{signer: testDispatchSigner{operator}}
	req := testDispatchRequest(operator.Public().Hex())
	first, err := d.buildAttempt(context.Background(), req, "first", firstWorker.Public().Hex(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.buildAttempt(context.Background(), req, "second", secondWorker.Public().Hex(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if first.PublisherPub == second.PublisherPub {
		t.Fatal("ephemeral HIVE_CI_NSEC publisher reused across workers")
	}
}

func testDispatchRequest(owner string) DispatchRequest {
	return DispatchRequest{
		SourceEventID: stringsOf('a', 64), OwnerPubkey: owner,
		Owner: "alice", RepoName: "repo", RepoID: "repo",
		CloneURL:  "https://git.example/alice/repo.git",
		CommitSHA: stringsOf('b', 40), WorkflowPath: ".github/workflows/ci.yml",
		Branch: "main", Trigger: "push", TriggeredBy: owner,
	}
}

func stringsOf(ch byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = ch
	}
	return string(out)
}

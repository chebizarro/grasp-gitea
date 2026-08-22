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

type testDispatchRevalidator struct {
	requestErr error
	retryErr   error
	requests   int
	retries    int
}

func (v *testDispatchRevalidator) ValidateDispatchRequest(context.Context, DispatchRequest) error {
	v.requests++
	return v.requestErr
}

func (v *testDispatchRevalidator) RevalidateDispatch(context.Context, store.LoomJob) error {
	v.retries++
	return v.retryErr
}

func allowTestDispatch(d *Dispatcher) *testDispatchRevalidator {
	v := &testDispatchRevalidator{}
	d.SetDispatchRevalidator(v)
	return v
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
	future := signedWorkerAd(t, worker, now.Add(2*time.Minute), "act", "0")
	if err := pool.HandleEvent(future, now); err == nil {
		t.Fatal("future-skewed worker advertisement accepted")
	}
}

func TestWorkerPoolRevalidatesExactFreshAdvertisement(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := nostr.Generate()
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}, AdTTL: time.Minute, FutureSkew: time.Second})
	first := signedWorkerAd(t, worker, now, "act", "0")
	if err := pool.HandleEvent(first, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Revalidate(worker.Public().Hex(), first.ID.Hex(), now, 15*time.Minute, false, ""); !ok {
		t.Fatal("fresh exact advertisement failed revalidation")
	}
	replacement := signedWorkerAd(t, worker, now.Add(time.Second), "act", "0")
	if err := pool.HandleEvent(replacement, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := pool.Revalidate(worker.Public().Hex(), first.ID.Hex(), now.Add(time.Second), 15*time.Minute, false, ""); ok {
		t.Fatal("replaced advertisement remained valid")
	}
	if _, ok := pool.Revalidate(worker.Public().Hex(), replacement.ID.Hex(), now.Add(2*time.Minute), 15*time.Minute, false, ""); ok {
		t.Fatal("stale advertisement remained valid")
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
	allowTestDispatch(d)
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
	req.TriggerEnvelopeID = strings.Repeat("6", 64)
	req.TriggerSource = store.TriggerSourceNIP34MergeStatus
	req.TriggerID = req.SourceEventID
	req.Actor = req.TriggeredBy
	req.EvidenceJSON = `{"kind":1631}`
	req.PREventID = strings.Repeat("1", 64)
	req.StatusEventID = strings.Repeat("2", 64)
	req.SourceEventID = req.StatusEventID
	req.TriggerID = req.StatusEventID
	req.SourceCommit = strings.Repeat("5", 40)
	req.SourceTree = strings.Repeat("3", 40)
	req.PatchDigest = strings.Repeat("4", 64)
	req.RepoAddress = "30617:" + req.OwnerPubkey + ":" + req.RepoID
	req.PolicyVersion = "hiveci.nip34-merge-status.v1"
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
		tagValue(run.Tags, "t") != "hive-ci" || tagValue(run.Tags, "trigger-envelope") != req.TriggerEnvelopeID ||
		tagValue(run.Tags, "trigger-source") != req.TriggerSource || tagValue(run.Tags, "trigger-id") != req.TriggerID ||
		tagValue(run.Tags, "actor") != req.Actor || tagValue(run.Tags, "evidence-digest") == "" ||
		tagValue(run.Tags, "pr-event") != req.PREventID || tagValue(run.Tags, "status-event") != req.StatusEventID ||
		tagValue(run.Tags, "source-commit") != req.SourceCommit ||
		tagValue(run.Tags, "source-tree") != req.SourceTree || tagValue(run.Tags, "patch-digest") != req.PatchDigest ||
		tagValue(run.Tags, "repo-address") != req.RepoAddress || tagValue(run.Tags, "policy") != req.PolicyVersion ||
		tagValue(run.Tags, "pr") != req.PREventID || tagValue(run.Tags, "review") != req.ReviewEventID ||
		tagValue(run.Tags, "audit") != req.AuditEventID || tagValue(run.Tags, "reviewer") != req.ReviewerPubkey ||
		tagValue(run.Tags, "tree") != req.CommitTree || tagValue(run.Tags, "workflow-digest") != req.WorkflowDigest ||
		tagValue(run.Tags, "source-provenance") != req.SourceProvenanceRef ||
		tagValue(run.Tags, "source-repo") != req.SourceRepoIdentity ||
		tagValue(run.Tags, "source-clone") != req.CloneURL ||
		tagValue(run.Tags, "requester") != req.Actor || tagValue(run.Tags, "idempotency") != req.TriggerEnvelopeID ||
		tagValue(run.Tags, "worker") != worker.Public().Hex() || tagValue(run.Tags, "worker-ad") == "" ||
		tagValue(run.Tags, "worker-capability") == "" || tagValue(run.Tags, "policy-digest") != req.ReviewPolicySHA256 {
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
	if job.WorkflowRunEvent == "" || job.JobRequestEvent == "" || job.DispatchState != "published" ||
		job.WorkerAdID != tagValue(run.Tags, "worker-ad") {
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
	correlated, err := st.GetLoomJobByTriggerEnvelope(ctx, req.TriggerEnvelopeID, req.WorkflowPath)
	if err != nil || correlated.WorkflowRunID != job.WorkflowRunID || store.LoomJobTerminal(correlated) {
		t.Fatalf("trigger correlation = %#v, %v", correlated, err)
	}
	if applied, err := st.ApplyLoomStatus(ctx, job.WorkflowRunID, store.LoomStatusUpdate{
		State: store.LoomStatusSuccess, Context: Context("hive-ci", req.WorkflowPath),
		Source: store.LoomSourceWorkflowResult, ProtocolEventID: "terminal-result",
	}, time.Now().UTC()); err != nil || !applied {
		t.Fatalf("apply terminal result = %v, %v", applied, err)
	}
	correlated, err = st.GetLoomJobByTriggerEnvelope(ctx, req.TriggerEnvelopeID, req.WorkflowPath)
	if err != nil || !store.LoomJobTerminal(correlated) {
		t.Fatalf("terminal trigger lookup = %#v, %v", correlated, err)
	}
	if handled, err := d.Dispatch(ctx, req); !handled || !errors.Is(err, store.ErrTriggerConflict) {
		t.Fatalf("terminal exact replay = %v, %v, want non-retryable conflict", handled, err)
	}
	if len(published) != 2 {
		t.Fatal("terminal exact replay published or created another run")
	}
	if _, err := st.SweepLoomJobs(ctx, time.Now().UTC().Add(2*time.Hour), time.Hour, 20); err != nil {
		t.Fatal(err)
	}
	if handled, err := d.Dispatch(ctx, req); !handled || !errors.Is(err, store.ErrTriggerConflict) {
		t.Fatalf("post-sweep replay = %v, %v, want durable conflict", handled, err)
	}
	if len(published) != 2 {
		t.Fatal("post-sweep replay reached publication")
	}
	conflict := req
	conflict.EvidenceJSON = `{"kind":1631,"conflict":true}`
	if handled, err := d.Dispatch(ctx, conflict); !handled || !errors.Is(err, store.ErrTriggerConflict) {
		t.Fatalf("conflicting Dispatch = %v, %v, want terminal conflict", handled, err)
	}
}

func TestDispatchKeyRejectsInconsistentMergeEnvelope(t *testing.T) {
	valid := testDispatchRequest(strings.Repeat("a", 64))
	valid.TriggerEnvelopeID = strings.Repeat("6", 64)
	valid.TriggerSource = store.TriggerSourceNIP34MergeStatus
	valid.TriggerID = valid.SourceEventID
	valid.Actor = valid.TriggeredBy
	valid.EvidenceJSON = `{"kind":1631}`
	valid.PREventID = strings.Repeat("1", 64)
	valid.StatusEventID = valid.SourceEventID
	valid.SourceCommit = strings.Repeat("5", 40)
	valid.SourceTree = strings.Repeat("3", 40)
	valid.PatchDigest = strings.Repeat("4", 64)
	valid.RepoAddress = "30617:" + valid.OwnerPubkey + ":" + valid.RepoID
	valid.PolicyVersion = "hiveci.nip34-merge-status.v1"
	if _, err := dispatchKey(valid); err != nil {
		t.Fatalf("valid merge envelope: %v", err)
	}

	tests := map[string]func(*DispatchRequest){
		"partial": func(req *DispatchRequest) {
			req.TriggerEnvelopeID = ""
		},
		"different status source": func(req *DispatchRequest) {
			req.StatusEventID = strings.Repeat("2", 64)
		},
		"different repository": func(req *DispatchRequest) {
			req.RepoAddress = "30617:" + req.OwnerPubkey + ":other"
		},
		"malformed envelope id": func(req *DispatchRequest) {
			req.TriggerEnvelopeID = "not-an-id"
		},
		"missing provenance": func(req *DispatchRequest) {
			req.SourceProvenanceRef = ""
		},
		"malformed provenance": func(req *DispatchRequest) {
			req.SourceProvenanceRef = store.SourceProvenanceReferencePrefix + "nope"
		},
		"mutable source identity": func(req *DispatchRequest) {
			req.SourceRepoIdentity = "refs/heads/main"
		},
		"credential-bearing clone URL": func(req *DispatchRequest) {
			req.CloneURL = "https://user:secret@example.com/repo.git"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := valid
			mutate(&req)
			if _, err := dispatchKey(req); err == nil {
				t.Fatal("inconsistent merge envelope was accepted")
			}
		})
	}
}

func TestDispatchKeyBindsCredentialFreeCloneTransport(t *testing.T) {
	original := testDispatchRequest(strings.Repeat("a", 64))
	originalKey, err := dispatchKey(original)
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.CloneURL = "https://mirror.example/alice/repo.git"
	changedKey, err := dispatchKey(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedKey == originalKey {
		t.Fatal("clone transport change did not alter dispatch key")
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
	allowTestDispatch(d)
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
	allowTestDispatch(d)
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
	allowTestDispatch(d)
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
	second.TriggerEnvelopeID = stringsOf('7', 64)
	second.TriggerID = second.SourceEventID
	second.StatusEventID = second.SourceEventID
	second.CommitSHA = stringsOf('e', 40)
	second.SourceCommit = stringsOf('e', 40)
	second.SourceTree = stringsOf('a', 40)
	second.PatchDigest = stringsOf('b', 64)
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
	now := time.Now().UTC().Truncate(time.Second)
	ad := signedWorkerAd(t, worker, now, "act", "2")
	req := testDispatchRequest(operator.Public().Hex())
	key, _ := dispatchKey(req)
	if _, claimed, err := st.ReserveLoomCashuSpend(ctx, store.LoomCashuSpend{
		DispatchKey: key, WorkerPub: worker.Public().Hex(), WorkerAdID: ad.ID.Hex(), MintURL: "https://mint.invalid",
		Amount: 1800, PricePerSecond: 2, DurationSeconds: 900,
	}, now); err != nil || !claimed {
		t.Fatalf("reserve crash window = %v, %v", claimed, err)
	}
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{worker.Public().Hex()}})
	if err := pool.HandleEvent(ad, now); err != nil {
		t.Fatal(err)
	}
	wallet := &countingCashuWallet{}
	d := NewDispatcher(DispatcherConfig{Enabled: true, PaymentMode: "cashu", MintURL: "https://mint.invalid",
		MaxDuration: 15 * time.Minute, MaxPayment: 2000, RelayURLs: []string{"wss://relay.invalid"}},
		pool, st, testDispatchSigner{operator}, nil, wallet)
	allowTestDispatch(d)
	if handled, err := d.Dispatch(ctx, req); !handled || err == nil || !strings.Contains(err.Error(), "refusing a second payment") {
		t.Fatalf("ambiguous dispatch = %v, %v", handled, err)
	}
	if wallet.createCalls != 0 {
		t.Fatal("ambiguous reserved spend invoked wallet again")
	}
}

func TestEphemeralPublisherIsolatedAcrossWorkers(t *testing.T) {
	operator, firstWorker, secondWorker := nostr.Generate(), nostr.Generate(), nostr.Generate()
	now := time.Now().UTC().Truncate(time.Second)
	pool := NewWorkerPool(WorkerPoolConfig{Allowlist: []string{firstWorker.Public().Hex(), secondWorker.Public().Hex()}, AdTTL: time.Hour})
	firstAd, secondAd := signedWorkerAd(t, firstWorker, now, "act", "0"), signedWorkerAd(t, secondWorker, now, "act", "0")
	if err := pool.HandleEvent(firstAd, now); err != nil {
		t.Fatal(err)
	}
	if err := pool.HandleEvent(secondAd, now); err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{signer: testDispatchSigner{operator}, pool: pool, maxDuration: 15 * time.Minute}
	req := testDispatchRequest(operator.Public().Hex())
	first, err := d.buildAttempt(context.Background(), req, "first", WorkerAd{Event: *firstAd}, "", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.buildAttempt(context.Background(), req, "second", WorkerAd{Event: *secondAd}, "", now)
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
		TriggerEnvelopeID: stringsOf('6', 64), TriggerSource: store.TriggerSourceNIP34MergeStatus,
		TriggerID: stringsOf('a', 64), Actor: owner, EvidenceJSON: `{"kind":1631}`,
		PREventID: stringsOf('1', 64), StatusEventID: stringsOf('a', 64),
		SourceCommit: stringsOf('5', 40), SourceTree: stringsOf('3', 40), PatchDigest: stringsOf('4', 64),
		RepoAddress: "30617:" + owner + ":repo", PolicyVersion: "hiveci.nip34-merge-status.v1",
		ReviewEventID: stringsOf('d', 64), AuditEventID: stringsOf('e', 64), ReviewerPubkey: owner,
		ReviewRootEventID: stringsOf('f', 64), ReviewBaseCommit: stringsOf('7', 40),
		ReviewPolicyVersion: "review-policy-v1", ReviewPolicySHA256: stringsOf('8', 64),
		CommitTree: stringsOf('9', 40), WorkflowDigest: stringsOf('c', 64),
		SourceProvenanceRef: store.SourceProvenanceReferencePrefix + stringsOf('0', 64),
		SourceRepoIdentity:  "30617:" + owner + ":repo",
	}
}

func stringsOf(ch byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = ch
	}
	return string(out)
}

func TestBuildWorkerCommandRejectsMutableBranchAndCredentialedTransport(t *testing.T) {
	req := testDispatchRequest(strings.Repeat("a", 64))
	if _, _, err := buildWorkerCommand(`["sh","-c","git checkout {branch}"]`, req); err == nil {
		t.Fatal("mutable branch placeholder was accepted as build input")
	}
	if _, _, err := buildWorkerCommand(`["sh","-c","git clone {clone_url}"]`, req); err == nil {
		t.Fatal("request-controlled placeholder embedded in shell script was accepted")
	}
	cmd, args, err := buildWorkerCommand(`["sh","-c","git clone --no-checkout \"$1\" repo","hive-ci","{clone_url}"]`, req)
	if err != nil || cmd != "sh" || len(args) != 4 || args[3] != req.CloneURL {
		t.Fatalf("structured positional placeholder rejected: cmd=%q args=%q err=%v", cmd, args, err)
	}
	secretURL := "https://build-user:super-secret@example.com/repo.git"
	req.CloneURL = secretURL
	if _, err := dispatchKey(req); err == nil {
		t.Fatal("credential-bearing clone URL was accepted")
	} else if strings.Contains(err.Error(), "build-user") || strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), secretURL) {
		t.Fatalf("credential-bearing clone URL disclosed in error: %v", err)
	}
}

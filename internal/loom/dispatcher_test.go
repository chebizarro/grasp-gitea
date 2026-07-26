package loom

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip44"

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

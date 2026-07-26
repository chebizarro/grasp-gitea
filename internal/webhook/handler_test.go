// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/echofp"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// A valid 32-byte (64 hex char) Nostr public key used across tests. The npub
// below is an arbitrary human-readable label; the handler must NEVER place it
// in "p" or "a" tag positions (those require hex per NIP-01/NIP-34).
var testDeliverySequence atomic.Uint64

const (
	testPubkeyHex = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"
	testNpub      = "npub1sdrqlzptdw40d96079a7g2kevrncr54u2mnmgjsf7wj4rahmumzqz2r2f7"
	testRepoID    = "myrepo"
	testGiteaID   = int64(42)
)

// fakePublisher captures the events the handler emits so tests can assert on
// the exact NIP-34 output without a live relay connection.
type fakePublisher struct {
	mu          sync.Mutex
	events      []*nostr.Event
	republished []int64
	ciPushes    []ciPush
	failPublish bool

	fetched     []string
	fetchResult *nostr.Event
	fetchErr    error
}

type ciPush struct {
	repoID             int64
	ref, before, after string
}

type fakeActorSigner struct {
	enabled bool
}

func (f fakeActorSigner) Enabled() bool { return f.enabled }

type queuedEvent struct {
	kind         int
	authorPubkey string
	scope        string
	dedupeKey    string
	event        nostr.Event
}

type fakeOutbox struct {
	mu     sync.Mutex
	events []queuedEvent
}

func (f *fakeOutbox) Enqueue(_ context.Context, kind int, authorPubkey string, scope string, unsignedEvent *nostr.Event, dedupeKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *unsignedEvent
	f.events = append(f.events, queuedEvent{kind: kind, authorPubkey: authorPubkey, scope: scope, dedupeKey: dedupeKey, event: cp})
	return nil
}

func (f *fakeOutbox) all() []queuedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]queuedEvent, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakePublisher) PublishEvent(_ context.Context, ev *nostr.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Emulate signing: the real publisher sets ev.ID after signing, and the
	// handler relies on ev.ID to build the follow-up status event's "e" tag.
	if ev.ID == (nostr.ID{}) {
		ev.ID = nostr.MustIDFromHex(fmt.Sprintf("deadbeef%056x", len(f.events)))
	}
	if f.failPublish {
		return fmt.Errorf("simulated relay failure")
	}
	cp := *ev
	f.events = append(f.events, &cp)
	return nil
}

func (f *fakePublisher) RepublishForGiteaRepo(_ context.Context, giteaRepoID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.republished = append(f.republished, giteaRepoID)
	return nil
}

func (f *fakePublisher) HandleWebhookPushCI(_ context.Context, giteaRepoID int64, ref, before, after, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ciPushes = append(f.ciPushes, ciPush{giteaRepoID, ref, before, after})
	return nil
}

func (f *fakePublisher) FetchEvent(_ context.Context, id string) (*nostr.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetched = append(f.fetched, id)
	return f.fetchResult, f.fetchErr
}

func (f *fakePublisher) kinds() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, 0, len(f.events))
	for _, ev := range f.events {
		out = append(out, int(ev.Kind))
	}
	return out
}

func (f *fakePublisher) firstOfKind(kind int) *nostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range f.events {
		if int(ev.Kind) == kind {
			return ev
		}
	}
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestHandler(t *testing.T, secret string) (*Handler, *fakePublisher, *store.SQLiteStore) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	fake := &fakePublisher{}
	h := &Handler{pub: fake, store: st, secret: secret, logger: testLogger()}
	return h, fake, st
}

func seedMapping(t *testing.T, st *store.SQLiteStore) {
	t.Helper()
	m := store.Mapping{
		Npub:        testNpub,
		RepoID:      testRepoID,
		Pubkey:      testPubkeyHex,
		Owner:       "org1",
		RepoName:    testRepoID,
		GiteaRepoID: testGiteaID,
		CloneURL:    "https://git.example/org1/myrepo.git",
		SourceEvent: "seed",
	}
	if err := st.UpsertMapping(context.Background(), m); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
}

func setupBareRepo(t *testing.T, h *Handler) string {
	t.Helper()
	tmp := t.TempDir()
	work := filepath.Join(tmp, "work")
	reposDir := filepath.Join(tmp, "git", "repositories")
	runGit(t, tmp, "init", "-b", "main", work)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("root\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGit(t, work, "add", "README.md")
	runGit(t, work, "commit", "-m", "root")
	root := strings.TrimSpace(runGitOutput(t, work, "rev-parse", "HEAD"))
	repoPath := filepath.Join(reposDir, "org1", "myrepo.git")
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("mkdir repos dir: %v", err)
	}
	runGit(t, tmp, "clone", "--bare", work, repoPath)
	h.SetRepositoriesDir(reposDir)
	return root
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = runGitOutput(t, dir, args...)
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.com",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

const testActorPubkeyHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func seedActorGrant(t *testing.T, st *store.SQLiteStore, userID int64, login string, pubkey string) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{
		Pubkey:      pubkey,
		Npub:        "npub1actor",
		GiteaUserID: userID,
		GiteaUser:   login,
		LastLoginAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed identity link: %v", err)
	}
	if err := st.UpsertSignerGrant(ctx, store.SignerGrant{
		Pubkey:          pubkey,
		ClientSeckeyEnc: []byte("encrypted-client-secret"),
		BunkerURIEnc:    []byte("encrypted-bunker-uri"),
		Relays:          `[]`,
		Permissions:     `["sign_event"]`,
		GrantedAt:       time.Now().UTC(),
		Status:          "active",
	}); err != nil {
		t.Fatalf("seed signer grant: %v", err)
	}
}

// post drives ServeHTTP with a JSON payload and an optional valid HMAC.
func post(t *testing.T, h *Handler, eventType string, payload any, secret string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/gitea", bytes.NewReader(body))
	req.Header.Set("X-Gitea-Event", eventType)
	req.Header.Set("X-Gitea-Delivery", fmt.Sprintf("test-delivery-%d", testDeliverySequence.Add(1)))
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Gitea-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// assertTagsWellFormed verifies that every "p" tag is a 64-char hex pubkey and
// every "a" tag is a valid NIP-34 coordinate "30617:<hex-pubkey>:<repo-id>".
// The "r" tag is intentionally allowed to carry an npub-based human ref.
func assertTagsWellFormed(t *testing.T, ev *nostr.Event) {
	t.Helper()
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			if !isHex64(tag[1]) {
				t.Errorf("kind %d: 'p' tag is not a 64-hex pubkey: %q", ev.Kind, tag[1])
			}
		case "a":
			want := fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID)
			if tag[1] != want {
				t.Errorf("kind %d: 'a' tag = %q, want %q", ev.Kind, tag[1], want)
			}
		}
	}
}

func TestServeHTTP_MethodNotAllowed(t *testing.T) {
	h, _, _ := newTestHandler(t, "")
	req := httptest.NewRequest(http.MethodGet, "/webhook/gitea", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rr.Code)
	}
}

func TestServeHTTP_HMACRejectAndAccept(t *testing.T) {
	const secret = "s3cr3t"
	h, fake, st := newTestHandler(t, secret)
	seedMapping(t, st)

	payload := PushPayload{Ref: "refs/heads/main", After: "a1", Repository: Repository{ID: testGiteaID}}

	// Wrong signature -> 401, nothing published.
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook/gitea", bytes.NewReader(body))
	req.Header.Set("X-Gitea-Event", "push")
	req.Header.Set("X-Gitea-Signature", "deadbeef")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad-HMAC status = %d, want 401", rr.Code)
	}
	if len(fake.republished) != 0 {
		t.Fatalf("bad-HMAC should not have republished, got %v", fake.republished)
	}

	// Correct signature -> 200, republish + CI push invoked.
	rr = post(t, h, "push", payload, secret)
	if rr.Code != http.StatusOK {
		t.Fatalf("good-HMAC status = %d, want 200", rr.Code)
	}
	if len(fake.republished) != 1 || fake.republished[0] != testGiteaID {
		t.Fatalf("expected republish for repo %d, got %v", testGiteaID, fake.republished)
	}
	if len(fake.ciPushes) != 1 || fake.ciPushes[0].ref != "refs/heads/main" {
		t.Fatalf("expected one CI push for refs/heads/main, got %v", fake.ciPushes)
	}
}

func TestWebhookDeliveryPersistsBefore200AndRetries(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	h.retriesEnabled = false
	fake.failPublish = true

	payload := IssuePayload{Action: "opened", Number: 9, Repository: Repository{ID: testGiteaID}}
	payload.Issue.Title = "durable issue"
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/gitea", bytes.NewReader(body))
	req.Header.Set("X-Gitea-Event", "issues")
	req.Header.Set("X-Gitea-Delivery", "durable-delivery-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after durable receipt", rr.Code)
	}

	delivery, err := st.GetWebhookDelivery(context.Background(), "durable-delivery-1")
	if err != nil {
		t.Fatalf("get persisted delivery: %v", err)
	}
	if delivery.State != store.WebhookDeliveryPending || delivery.Attempts != 1 || delivery.LastError == "" {
		t.Fatalf("failed delivery not pending for retry: %#v", delivery)
	}

	fake.failPublish = false
	if _, err := st.MarkWebhookDeliveryRetry(context.Background(), delivery.DeliveryID, time.Now().Add(-time.Second), delivery.LastError); err != nil {
		t.Fatalf("make delivery due: %v", err)
	}
	h.retryPendingWebhookDeliveries()
	delivery, err = st.GetWebhookDelivery(context.Background(), delivery.DeliveryID)
	if err != nil {
		t.Fatalf("reload delivery: %v", err)
	}
	if delivery.State != store.WebhookDeliveryDone {
		t.Fatalf("retried delivery state = %q, want done (last error %q)", delivery.State, delivery.LastError)
	}
	if fake.firstOfKind(KindIssue) == nil {
		t.Fatal("retry did not publish bridge-signed fallback event")
	}
}

func TestPush_UnknownRepoIsNoOp(t *testing.T) {
	h, fake, _ := newTestHandler(t, "") // no mapping seeded
	payload := PushPayload{Ref: "refs/heads/main", After: "a1", Repository: Repository{ID: 999}}
	rr := post(t, h, "push", payload, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(fake.republished) != 0 || len(fake.events) != 0 || len(fake.ciPushes) != 0 {
		t.Fatalf("unknown repo must be a no-op; got republished=%v events=%d ci=%v",
			fake.republished, len(fake.events), fake.ciPushes)
	}
}

func TestPR_OpenedEmitsNIP34Schema(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	euc := setupBareRepo(t, h)

	payload := PullRequestPayload{
		Action: "opened",
		Number: 7,
		Repository: Repository{
			ID:            testGiteaID,
			CloneURL:      "https://git.example/org1/myrepo.git",
			DefaultBranch: "main",
		},
	}
	payload.PullRequest.Title = "Add feature"
	payload.PullRequest.Body = "body text"
	payload.PullRequest.State = "open"
	payload.PullRequest.Head.Ref = "feature"
	payload.PullRequest.Head.SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	payload.PullRequest.Base.Ref = "main"

	rr := post(t, h, "pull_request", payload, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	prEv := fake.firstOfKind(KindPROpen)
	if prEv == nil {
		t.Fatalf("no kind %d (PR open) event; got kinds %v", KindPROpen, fake.kinds())
	}
	assertTagsWellFormed(t, prEv)
	requireTag(t, prEv, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, prEv, "p", testPubkeyHex)
	requireTag(t, prEv, "r", euc)
	requireTag(t, prEv, "subject", "Add feature")
	requireTag(t, prEv, "c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	requireTag(t, prEv, "clone", "https://git.example/org1/myrepo.git")
	requireTag(t, prEv, "branch-name", "feature")
	forbidTag(t, prEv, "title")
	forbidTag(t, prEv, "head")
	forbidTag(t, prEv, "base")
	if fake.firstOfKind(KindPRUpdate) != nil {
		t.Fatalf("opened PR must not emit kind %d", KindPRUpdate)
	}
}

func TestPR_LinkedContributorEnqueuesUnsignedActorEvents(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	seedActorGrant(t, st, 101, "alice", testActorPubkeyHex)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)

	payload := PullRequestPayload{
		Action:     "opened",
		Number:     7,
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 101, Login: "alice"},
	}
	payload.PullRequest.Title = "Add feature"
	payload.PullRequest.Body = "body text"
	payload.PullRequest.State = "open"
	payload.PullRequest.Head.Ref = "feature"
	payload.PullRequest.Base.Ref = "main"

	rr := post(t, h, "pull_request", payload, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(fake.events) != 0 {
		t.Fatalf("signer-enabled linked actor must not bridge-sign; published=%d", len(fake.events))
	}
	queued := outbox.all()
	if len(queued) != 1 {
		t.Fatalf("queued events = %d, want PR open only: %#v", len(queued), queued)
	}
	pr := queued[0]
	if pr.kind != KindPROpen || pr.authorPubkey != testActorPubkeyHex {
		t.Fatalf("queued PR = kind %d author %q, want kind %d author %s", pr.kind, pr.authorPubkey, KindPROpen, testActorPubkeyHex)
	}
	if pr.event.PubKey.Hex() != testActorPubkeyHex || pr.event.Sig != [64]byte{} {
		t.Fatalf("queued PR event should be unsigned and authored by actor, got pubkey=%q sig=%q", pr.event.PubKey, pr.event.Sig)
	}
	assertTagsWellFormed(t, &pr.event)
	requireTag(t, &pr.event, "subject", "Add feature")
	forbidTag(t, &pr.event, "title")
	forbidTag(t, &pr.event, "head")
	forbidTag(t, &pr.event, "base")
}

func TestIssue_LinkedContributorEnqueuesUnsignedActorEvents(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	seedActorGrant(t, st, 202, "bob", testActorPubkeyHex)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)

	payload := IssuePayload{
		Action:     "opened",
		Number:     3,
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 202, Login: "bob"},
	}
	payload.Issue.Title = "Bug report"
	payload.Issue.Body = "details"
	payload.Issue.State = "open"

	post(t, h, "issues", payload, "")
	if len(fake.events) != 0 {
		t.Fatalf("signer-enabled linked issue must not bridge-sign; published=%d", len(fake.events))
	}
	queued := outbox.all()
	if len(queued) != 1 {
		t.Fatalf("queued events = %d, want issue root", len(queued))
	}
	if queued[0].kind != KindIssue || queued[0].authorPubkey != testActorPubkeyHex || queued[0].event.PubKey.Hex() != testActorPubkeyHex || queued[0].event.Sig != [64]byte{} {
		t.Fatalf("unexpected queued issue: %#v", queued[0])
	}
	assertTagsWellFormed(t, &queued[0].event)
	requireTag(t, &queued[0].event, "subject", "Bug report")
	forbidTag(t, &queued[0].event, "title")
	forbidTag(t, &queued[0].event, "r")
	forbidTag(t, &queued[0].event, "action")
}

func TestPR_UnlinkedContributorPersistsPendingWhenSignerEnabled(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)
	before := metrics.Snapshot()["unlinked_actor_skipped"]

	payload := PullRequestPayload{
		Action:     "opened",
		Number:     9,
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 303, Login: "carol"},
	}
	payload.PullRequest.State = "open"

	post(t, h, "pull_request", payload, "")
	if len(fake.events) != 0 {
		t.Fatalf("unlinked signer-enabled actor must not bridge-sign; published=%d", len(fake.events))
	}
	if queued := outbox.all(); len(queued) != 0 {
		t.Fatalf("unlinked actor should not enqueue, got %#v", queued)
	}
	pending, err := st.ListPendingActorEvents(context.Background(), 303, 10)
	if err != nil {
		t.Fatalf("ListPendingActorEvents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending rows = %d, want 1", len(pending))
	}
	row := pending[0]
	if row.Kind != KindPROpen || row.Scope != "repo:42:pr:9:opened" || row.DedupeKey == "" {
		t.Fatalf("unexpected pending row: %#v", row)
	}
	if !strings.Contains(row.DedupeKey, "webhook:repo:42:pr:9:opened") {
		t.Fatalf("pending dedupe key %q missing webhook scope", row.DedupeKey)
	}
	var stored nostr.Event
	if err := json.Unmarshal([]byte(row.UnsignedEventJSON), &stored); err != nil {
		t.Fatalf("unmarshal pending event: %v", err)
	}
	if stored.PubKey != (nostr.PubKey{}) || stored.Sig != [64]byte{} || stored.ID != (nostr.ID{}) {
		t.Fatalf("pending event should be unsigned/no author, got pubkey=%q sig=%q id=%q", stored.PubKey, stored.Sig, stored.ID)
	}
	requireTag(t, &stored, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	after := metrics.Snapshot()["unlinked_actor_skipped"]
	if after != before+1 {
		t.Fatalf("unlinked_actor_skipped delta = %d, want 1 (before=%d after=%d)", after-before, before, after)
	}

	seedActorGrant(t, st, 303, "carol", testActorPubkeyHex)
	backfiller := NewActorBackfiller(st, outbox, testLogger())
	if count, err := backfiller.EnqueuePending(context.Background(), 303, testActorPubkeyHex); err != nil || count != 1 {
		t.Fatalf("backfill pending PR root: count=%d err=%v", count, err)
	}
	queued := outbox.all()
	if len(queued) != 1 {
		t.Fatalf("backfilled queue = %#v, want one PR root", queued)
	}
	root, err := st.GetThreadRoot(context.Background(), "pr", testGiteaID, 9)
	if err != nil {
		t.Fatalf("get finalized PR thread root: %v", err)
	}
	if root.NostrEventID != queued[0].event.ID.Hex() || root.Pubkey != testActorPubkeyHex || root.Kind != KindPROpen {
		t.Fatalf("unexpected finalized PR thread root: %#v", root)
	}
	if _, err := st.GetReflectedEvent(context.Background(), root.NostrEventID); err != nil {
		t.Fatalf("backfilled PR root lacks Nostr/Gitea mapping: %v", err)
	}
}

func TestActorBackfillerEnqueuesPendingRowsAndDeletesThem(t *testing.T) {
	_, _, st := newTestHandler(t, "")
	ctx := context.Background()
	unsigned := nostr.Event{Kind: KindIssue, CreatedAt: nostr.Timestamp(123), Tags: nostr.Tags{{"subject", "Backfill me"}}, Content: "body"}
	b, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SavePendingActorEvent(ctx, store.PendingActorEvent{
		GiteaUserID:       202,
		Kind:              KindIssue,
		UnsignedEventJSON: string(b),
		Scope:             "repo:42:issue:3:opened",
		DedupeKey:         "pending-issue-key",
	}, time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC), 500, 30*24*time.Hour); err != nil {
		t.Fatalf("SavePendingActorEvent: %v", err)
	}

	outbox := &fakeOutbox{}
	backfiller := NewActorBackfiller(st, outbox, testLogger())
	before := metrics.Snapshot()["actor_events_backfilled"]
	count, err := backfiller.EnqueuePending(ctx, 202, testActorPubkeyHex)
	if err != nil {
		t.Fatalf("EnqueuePending: %v", err)
	}
	if count != 1 {
		t.Fatalf("backfilled count = %d, want 1", count)
	}
	queued := outbox.all()
	if len(queued) != 1 {
		t.Fatalf("queued = %#v, want one", queued)
	}
	if queued[0].kind != KindIssue || queued[0].authorPubkey != testActorPubkeyHex || queued[0].dedupeKey != "pending-issue-key" {
		t.Fatalf("unexpected queued event: %#v", queued[0])
	}
	if queued[0].event.PubKey.Hex() != testActorPubkeyHex || queued[0].event.Sig != [64]byte{} || queued[0].event.ID == (nostr.ID{}) {
		t.Fatalf("backfilled event should be authored/unsigned/id computed, got pubkey=%q sig=%q id=%q", queued[0].event.PubKey, queued[0].event.Sig, queued[0].event.ID)
	}
	pending, err := st.ListPendingActorEvents(ctx, 202, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending rows after backfill = %#v, want empty", pending)
	}
	after := metrics.Snapshot()["actor_events_backfilled"]
	if after != before+1 {
		t.Fatalf("actor_events_backfilled delta = %d, want 1", after-before)
	}
}

func TestPR_SignerDisabledKeepsLegacyBridgeSigning(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: false}, outbox, st)

	payload := PullRequestPayload{
		Action:     "opened",
		Number:     10,
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 404, Login: "dave"},
	}
	payload.PullRequest.State = "open"

	post(t, h, "pull_request", payload, "")
	if fake.firstOfKind(KindPROpen) == nil {
		t.Fatalf("signer disabled should use legacy bridge publisher; got %v", fake.kinds())
	}
	if queued := outbox.all(); len(queued) != 0 {
		t.Fatalf("signer disabled should not enqueue actor events, got %#v", queued)
	}
}

func TestPR_MergedEmitsAppliedStatus(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	euc := setupBareRepo(t, h)

	open := PullRequestPayload{Action: "opened", Number: 8, Repository: Repository{ID: testGiteaID, DefaultBranch: "main"}}
	open.PullRequest.Title = "Merge me"
	open.PullRequest.State = "open"
	open.PullRequest.Head.Ref = "feature"
	open.PullRequest.Head.SHA = "1111111111111111111111111111111111111111"
	open.PullRequest.Base.Ref = "main"
	post(t, h, "pull_request", open, "")
	prEv := fake.firstOfKind(KindPROpen)
	if prEv == nil {
		t.Fatalf("open PR missing; got %v", fake.kinds())
	}

	payload := PullRequestPayload{Action: "closed", Number: 8, Repository: Repository{ID: testGiteaID, DefaultBranch: "main"}}
	payload.PullRequest.State = "closed"
	payload.PullRequest.Merged = true
	payload.PullRequest.MergedCommitID = "2222222222222222222222222222222222222222"
	post(t, h, "pull_request", payload, "")
	status := fake.firstOfKind(KindStatusApplied)
	if status == nil {
		t.Fatalf("merged PR should emit kind %d (applied); got %v", KindStatusApplied, fake.kinds())
	}
	requireTag(t, status, "e", prEv.ID.Hex(), "", "root")
	requireTag(t, status, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, status, "p", testPubkeyHex)
	requireTag(t, status, "r", euc)
	requireTag(t, status, "merge-commit", "2222222222222222222222222222222222222222")
	requireTag(t, status, "r", "2222222222222222222222222222222222222222")
}

func TestPR_SynchronizedEmitsTipUpdateAndCloseEmitsStatus(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	seedActorGrant(t, st, 101, "alice", testActorPubkeyHex)
	euc := setupBareRepo(t, h)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)

	open := PullRequestPayload{
		Action: "opened",
		Number: 7,
		Repository: Repository{
			ID:            testGiteaID,
			CloneURL:      "https://git.example/org1/myrepo.git",
			DefaultBranch: "main",
		},
		Sender: User{ID: 101, Login: "alice"},
	}
	open.PullRequest.Title = "Add feature"
	open.PullRequest.Head.Ref = "feature"
	open.PullRequest.Head.SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	open.PullRequest.Base.Ref = "main"
	post(t, h, "pull_request", open, "")

	queued := outbox.all()
	if len(queued) != 1 || queued[0].kind != KindPROpen {
		t.Fatalf("open queued = %#v, want one PR open", queued)
	}
	root := queued[0].event

	syncPayload := open
	syncPayload.Action = "synchronized"
	syncPayload.PullRequest.Head.SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	syncPayload.PullRequest.MergeBase = "cccccccccccccccccccccccccccccccccccccccc"
	post(t, h, "pull_request", syncPayload, "")

	queued = outbox.all()
	if len(queued) != 2 {
		t.Fatalf("after synchronized queued = %d, want open + update: %#v", len(queued), queued)
	}
	update := queued[1].event
	if update.Kind != KindPRUpdate {
		t.Fatalf("synchronized emitted kind %d, want %d", update.Kind, KindPRUpdate)
	}
	requireTag(t, &update, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, &update, "p", testPubkeyHex)
	requireTag(t, &update, "r", euc)
	requireTag(t, &update, "E", root.ID.Hex())
	requireTag(t, &update, "P", testActorPubkeyHex)
	requireTag(t, &update, "c", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	requireTag(t, &update, "clone", "https://git.example/org1/myrepo.git")
	requireTag(t, &update, "merge-base", "cccccccccccccccccccccccccccccccccccccccc")
	forbidTag(t, &update, "action")

	closePayload := open
	closePayload.Action = "closed"
	closePayload.PullRequest.State = "closed"
	post(t, h, "pull_request", closePayload, "")

	queued = outbox.all()
	if len(queued) != 3 {
		t.Fatalf("after close queued = %d, want open + update + status: %#v", len(queued), queued)
	}
	status := queued[2].event
	if status.Kind != KindStatusClosed {
		t.Fatalf("close emitted kind %d, want %d", status.Kind, KindStatusClosed)
	}
	requireTag(t, &status, "e", root.ID.Hex(), "", "root")
	requireTag(t, &status, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, &status, "p", testPubkeyHex)
	requireTag(t, &status, "p", testActorPubkeyHex)
	requireTag(t, &status, "r", euc)
	updates := 0
	for _, q := range queued {
		if q.kind == KindPRUpdate {
			updates++
		}
	}
	if updates != 1 {
		t.Fatalf("PRUpdate count = %d, want exactly one synchronized update", updates)
	}
	if len(fake.events) != 0 {
		t.Fatalf("actor path should not bridge-sign, got %d events", len(fake.events))
	}
}

func TestIssueCommentEmitsNIP22ThreadedComment(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	seedActorGrant(t, st, 202, "bob", testActorPubkeyHex)
	outbox := &fakeOutbox{}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)

	issue := IssuePayload{
		Action:     "opened",
		Number:     3,
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 202, Login: "bob"},
	}
	issue.Issue.Number = 3
	issue.Issue.Title = "Bug report"
	issue.Issue.Body = "details"
	post(t, h, "issues", issue, "")
	queued := outbox.all()
	if len(queued) != 1 || queued[0].kind != KindIssue {
		t.Fatalf("issue open queued = %#v", queued)
	}
	root := queued[0].event

	// Simulate a process restart: only SQLite state is carried into the new
	// handler, not the old in-memory Handler value.
	h = &Handler{pub: fake, store: st, logger: testLogger(), actorLookup: st}
	h.SetActorSigning(fakeActorSigner{enabled: true}, outbox, st)

	comment := IssueCommentPayload{
		Action:     "created",
		Issue:      Issue{Number: 3},
		Comment:    Comment{ID: 55, Body: "plain comment"},
		Repository: Repository{ID: testGiteaID},
		Sender:     User{ID: 202, Login: "bob"},
	}
	post(t, h, "issue_comment", comment, "")

	queued = outbox.all()
	if len(queued) != 2 {
		t.Fatalf("queued = %d, want issue + comment: %#v", len(queued), queued)
	}
	cm := queued[1].event
	if cm.Kind != KindComment {
		t.Fatalf("comment kind = %d, want %d", cm.Kind, KindComment)
	}
	if cm.Content != "plain comment" {
		t.Fatalf("comment content = %q", cm.Content)
	}
	requireTag(t, &cm, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, &cm, "E", root.ID.Hex(), "", testActorPubkeyHex)
	requireTag(t, &cm, "K", fmt.Sprint(KindIssue))
	requireTag(t, &cm, "P", testActorPubkeyHex)
	requireTag(t, &cm, "e", root.ID.Hex(), "", testActorPubkeyHex)
	requireTag(t, &cm, "k", fmt.Sprint(KindIssue))
	requireTag(t, &cm, "p", testActorPubkeyHex)
	if len(fake.events) != 0 {
		t.Fatalf("actor path should not bridge-sign, got %d events", len(fake.events))
	}
}

func TestIssue_OpenedEmitsNIP34Schema(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	payload := IssuePayload{Action: "opened", Number: 3, Repository: Repository{ID: testGiteaID}}
	payload.Issue.Title = "Bug report"
	payload.Issue.Body = "details"
	payload.Issue.State = "open"

	post(t, h, "issues", payload, "")

	issueEv := fake.firstOfKind(KindIssue)
	if issueEv == nil {
		t.Fatalf("no kind %d (issue) event; got %v", KindIssue, fake.kinds())
	}
	assertTagsWellFormed(t, issueEv)
	requireTag(t, issueEv, "a", fmt.Sprintf("30617:%s:%s", testPubkeyHex, testRepoID))
	requireTag(t, issueEv, "p", testPubkeyHex)
	requireTag(t, issueEv, "subject", "Bug report")
	forbidTag(t, issueEv, "title")
	forbidTag(t, issueEv, "r")
	forbidTag(t, issueEv, "action")
}

func TestIssueOpenedSkipsBridgeReflectedObject(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-issue-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      3,
		Kind:            KindIssue,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.Issue("Reflected issue", "already came from Nostr"),
	}); err != nil {
		t.Fatalf("record reflected event: %v", err)
	}

	payload := IssuePayload{Action: "opened", Number: 3, Repository: Repository{ID: testGiteaID}}
	payload.Issue.Title = "Reflected issue"
	payload.Issue.Body = "already came from Nostr"
	post(t, h, "issues", payload, "")
	post(t, h, "issues", payload, "")

	if got := fake.kinds(); len(got) != 0 {
		t.Fatalf("duplicate bridge-reflected issue webhooks echoed to Nostr: %v", got)
	}

	now = now.Add(6 * time.Minute)
	post(t, h, "issues", payload, "")
	if got := fake.kinds(); len(got) != 1 || got[0] != KindIssue {
		t.Fatalf("expected webhook to publish after guard expiry, got %v", got)
	}
}

func TestIssueOpenedDifferentContentWithinWindowPublishes(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-issue-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      3,
		Kind:            KindIssue,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.Issue("Reflected issue", "already came from Nostr"),
	}); err != nil {
		t.Fatalf("record reflected event: %v", err)
	}

	payload := IssuePayload{Action: "opened", Number: 3, Repository: Repository{ID: testGiteaID}}
	payload.Issue.Title = "Reflected issue"
	payload.Issue.Body = "genuine user edit"
	post(t, h, "issues", payload, "")

	if got := fake.kinds(); len(got) != 1 || got[0] != KindIssue {
		t.Fatalf("fingerprint mismatch should publish, got %v", got)
	}
}

func TestPROpenedSkipsBridgeReflectedObject(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-pr-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      7,
		Kind:            KindPROpen,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.PROpen("Reflected PR", "already came from Nostr"),
	}); err != nil {
		t.Fatalf("record reflected PR event: %v", err)
	}

	payload := PullRequestPayload{Action: "opened", Number: 7, Repository: Repository{ID: testGiteaID}}
	payload.PullRequest.Number = 7
	payload.PullRequest.Title = "Reflected PR"
	payload.PullRequest.Body = "already came from Nostr"
	payload.PullRequest.State = "open"
	payload.PullRequest.Head.Ref = "nostr-pr"
	payload.PullRequest.Base.Ref = "main"
	post(t, h, "pull_request", payload, "")
	post(t, h, "pull_request", payload, "")

	if got := fake.kinds(); len(got) != 0 {
		t.Fatalf("duplicate bridge-reflected PR webhooks echoed to Nostr: %v", got)
	}
}

func TestPRSynchronizedSkipsBridgeReflectedUpdateOnce(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	h.rememberThread(context.Background(), "pr", testGiteaID, 7, threadRef{EventID: "root-pr-event", Pubkey: testActorPubkeyHex, Kind: KindPROpen})
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-pr-update-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      7,
		HeadBranch:      "nostr-pr",
		Kind:            KindPRUpdate,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.PRUpdate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	}); err != nil {
		t.Fatalf("record reflected PR update event: %v", err)
	}

	payload := PullRequestPayload{Action: "synchronized", Number: 7, Repository: Repository{ID: testGiteaID}}
	payload.PullRequest.Number = 7
	payload.PullRequest.Head.SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	payload.PullRequest.Head.Ref = "nostr-pr"
	payload.PullRequest.Base.Ref = "main"
	post(t, h, "pull_request", payload, "")
	post(t, h, "pull_request", payload, "")

	if got := fake.kinds(); len(got) != 0 {
		t.Fatalf("duplicate bridge-reflected PR-update webhooks echoed to Nostr: %v", got)
	}
}

func TestIssueClosedSkipsBridgeReflectedStatusDuplicates(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	h.rememberThread(context.Background(), "issue", testGiteaID, 3, threadRef{EventID: "root-issue-event", Pubkey: testActorPubkeyHex, Kind: KindIssue})
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-status-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      3,
		Kind:            KindStatusClosed,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.IssueStatus("closed"),
	}); err != nil {
		t.Fatalf("record reflected status event: %v", err)
	}

	payload := IssuePayload{Action: "closed", Number: 3, Repository: Repository{ID: testGiteaID}}
	payload.Issue.Number = 3
	payload.Issue.State = "closed"
	post(t, h, "issues", payload, "")
	post(t, h, "issues", payload, "")

	if got := fake.kinds(); len(got) != 0 {
		t.Fatalf("duplicate bridge-reflected status webhooks echoed to Nostr: %v", got)
	}
}

func TestIssueCommentSkipsBridgeReflectedDuplicates(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.echoGuardWindow = 5 * time.Minute
	h.rememberThread(context.Background(), "issue", testGiteaID, 3, threadRef{EventID: "root-issue-event", Pubkey: testActorPubkeyHex, Kind: KindIssue})
	if _, err := st.RecordReflectedEvent(context.Background(), store.ReflectedEvent{
		NostrEventID:    "nostr-comment-event",
		GiteaRepoID:     testGiteaID,
		GiteaIndex:      3,
		Kind:            KindComment,
		EchoArmedAt:     now,
		EchoFingerprint: echofp.Comment("comment from Nostr"),
	}); err != nil {
		t.Fatalf("record reflected comment event: %v", err)
	}

	payload := IssueCommentPayload{Action: "created", Repository: Repository{ID: testGiteaID}}
	payload.Issue.Number = 3
	payload.Comment.ID = 101
	payload.Comment.Body = "comment from Nostr"
	post(t, h, "issue_comment", payload, "")
	post(t, h, "issue_comment", payload, "")

	if got := fake.kinds(); len(got) != 0 {
		t.Fatalf("duplicate bridge-reflected comment webhooks echoed to Nostr: %v", got)
	}
}

func TestIssue_LabeledEmitsNIP32Label(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	payload := IssuePayload{Action: "labeled", Number: 5, Repository: Repository{ID: testGiteaID}}
	payload.Label.Name = "enhancement"

	post(t, h, "issues", payload, "")

	labelEv := fake.firstOfKind(KindNIP32Label)
	if labelEv == nil {
		t.Fatalf("labeled issue should emit kind %d; got %v", KindNIP32Label, fake.kinds())
	}
	assertTagsWellFormed(t, labelEv)
	if l := labelEv.Tags.Find("l"); l == nil || len(l) < 2 || l[1] != "enhancement" {
		t.Errorf("label 'l' tag = %v, want enhancement", l)
	}
	requireTag(t, labelEv, "action", "apply")

	unlabeled := payload
	unlabeled.Action = "unlabeled"
	post(t, h, "issues", unlabeled, "")
	var removal *nostr.Event
	for _, ev := range fake.events {
		if int(ev.Kind) == KindNIP32Label {
			if action := ev.Tags.Find("action"); action != nil && len(action) >= 2 && action[1] == "remove" {
				removal = ev
				break
			}
		}
	}
	if removal == nil {
		t.Fatal("unlabeled issue did not emit distinct action=remove representation")
	}
}

// TestNoNpubInSemanticTags is a broad regression guard: across all event types,
// no "p" or "a" tag may ever contain a bech32 npub.
func TestNoNpubInSemanticTags(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	pr := PullRequestPayload{Action: "opened", Number: 1, Repository: Repository{ID: testGiteaID}}
	pr.PullRequest.State = "open"
	post(t, h, "pull_request", pr, "")

	iss := IssuePayload{Action: "opened", Number: 2, Repository: Repository{ID: testGiteaID}}
	iss.Issue.State = "open"
	post(t, h, "issues", iss, "")

	lbl := IssuePayload{Action: "labeled", Number: 2, Repository: Repository{ID: testGiteaID}}
	lbl.Label.Name = "x"
	post(t, h, "issues", lbl, "")

	if len(fake.events) == 0 {
		t.Fatal("expected events to be published")
	}
	for _, ev := range fake.events {
		for _, tag := range ev.Tags {
			if len(tag) < 2 {
				continue
			}
			if (tag[0] == "p" || tag[0] == "a") && strings.Contains(tag[1], "npub1") {
				t.Errorf("kind %d: semantic tag %q contains bech32 npub: %q", ev.Kind, tag[0], tag[1])
			}
		}
	}
}

func TestEarliestUniqueCommitReturnsRootCommit(t *testing.T) {
	h, _, st := newTestHandler(t, "")
	seedMapping(t, st)
	want := setupBareRepo(t, h)
	got, err := EarliestUniqueCommit(context.Background(), filepath.Join(h.repositoriesDir, "org1", "myrepo.git"), "main")
	if err != nil {
		t.Fatalf("EarliestUniqueCommit: %v", err)
	}
	if got != want {
		t.Fatalf("EarliestUniqueCommit = %s, want root %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// refs/nostr/<event-id> patch-push handling (phase1-cwt)
// ---------------------------------------------------------------------------

const (
	testPatchEventID   = "1111111111111111111111111111111111111111111111111111111111111111"
	testPatchAuthorHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCommitSHA      = "cafebabecafebabecafebabecafebabecafebabe"
)

func tagValues(ev *nostr.Event, key string) []string {
	var out []string
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == key {
			out = append(out, tag[1])
		}
	}
	return out
}

func firstTagValue(ev *nostr.Event, key string) string {
	vs := tagValues(ev, key)
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func requireTag(t *testing.T, ev *nostr.Event, key string, want ...string) nostr.Tag {
	t.Helper()
	for _, tag := range ev.Tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(want) == 0 {
			return tag
		}
		if len(tag) < 1+len(want) {
			continue
		}
		matched := true
		for i, v := range want {
			if tag[i+1] != v {
				matched = false
				break
			}
		}
		if matched {
			return tag
		}
	}
	t.Fatalf("kind %d missing tag %q with values %v in %#v", ev.Kind, key, want, ev.Tags)
	return nil
}

func forbidTag(t *testing.T, ev *nostr.Event, key string) {
	t.Helper()
	for _, tag := range ev.Tags {
		if len(tag) > 0 && tag[0] == key {
			t.Fatalf("kind %d unexpectedly has %q tag: %#v", ev.Kind, key, tag)
		}
	}
}

func patchPush(eventID string) PushPayload {
	return PushPayload{
		Ref:        "refs/nostr/" + eventID,
		After:      testCommitSHA,
		Repository: Repository{ID: testGiteaID},
	}
}

func TestPatchPush_EmitsAppliedStatus(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	euc := setupBareRepo(t, h)
	fake.fetchResult = nil // patch not found on relays

	rr := post(t, h, "push", patchPush(testPatchEventID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	if len(fake.fetched) != 1 || fake.fetched[0] != testPatchEventID {
		t.Fatalf("expected FetchEvent(%q), got %v", testPatchEventID, fake.fetched)
	}

	ev := fake.firstOfKind(KindStatusApplied)
	if ev == nil {
		t.Fatalf("expected kind %d (applied) status; got %v", KindStatusApplied, fake.kinds())
	}
	assertTagsWellFormed(t, ev)
	requireTag(t, ev, "e", testPatchEventID, "", "root")
	requireTag(t, ev, "r", euc)
	if got := firstTagValue(ev, "applied-as-commits"); got != testCommitSHA {
		t.Errorf("'applied-as-commits' = %q, want %q", got, testCommitSHA)
	}
	requireTag(t, ev, "r", testCommitSHA)
	if got := firstTagValue(ev, "p"); got != testPubkeyHex {
		t.Errorf("'p' tag = %q, want maintainer hex %q", got, testPubkeyHex)
	}
	// Repo state is still published for the push.
	if len(fake.republished) != 1 {
		t.Errorf("expected repo-state republish, got %v", fake.republished)
	}
}

func TestPatchPush_RecordsPendingRef(t *testing.T) {
	h, _, st := newTestHandler(t, "")
	seedMapping(t, st)

	post(t, h, "push", patchPush(testPatchEventID), "")

	pending, err := st.ListPendingNostrRefsOlderThan(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ListPendingNostrRefsOlderThan: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending rows = %d, want 1", len(pending))
	}
	if pending[0].EventID != testPatchEventID || pending[0].TipSHA != testCommitSHA || pending[0].GiteaRepoID != testGiteaID {
		t.Fatalf("unexpected pending row: %#v", pending[0])
	}
}

func TestPatchPush_DifferingRelayTipRejected(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	fake.fetchResult = &nostr.Event{
		Kind: KindPatch,
		Tags: nostr.Tags{{"c", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	}
	mapping, err := st.GetMappingByGiteaRepoID(context.Background(), testGiteaID)
	if err != nil {
		t.Fatalf("mapping: %v", err)
	}

	err = h.handlePatchPush(context.Background(), testPatchEventID, patchPush(testPatchEventID), mapping)
	if !errors.Is(err, refsnostr.ErrDifferingTip) {
		t.Fatalf("expected ErrDifferingTip, got %v", err)
	}
	if fake.firstOfKind(KindStatusApplied) != nil {
		t.Fatalf("differing tip should not emit applied status")
	}
	pending, err := st.ListPendingNostrRefsOlderThan(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ListPendingNostrRefsOlderThan: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("differing tip should not be recorded pending, got %#v", pending)
	}
}

func TestPatchPush_AttributesPatchAuthor(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	fake.fetchResult = &nostr.Event{Kind: KindPatch, PubKey: nostr.MustPubKeyFromHex(testPatchAuthorHex)}

	post(t, h, "push", patchPush(testPatchEventID), "")

	ev := fake.firstOfKind(KindStatusApplied)
	if ev == nil {
		t.Fatalf("expected applied status; got %v", fake.kinds())
	}
	ps := tagValues(ev, "p")
	if len(ps) != 2 {
		t.Fatalf("expected 2 'p' tags (maintainer + author), got %v", ps)
	}
	if ps[0] != testPubkeyHex || ps[1] != testPatchAuthorHex {
		t.Errorf("'p' tags = %v, want [%s %s]", ps, testPubkeyHex, testPatchAuthorHex)
	}
	for _, p := range ps {
		if !isHex64(p) {
			t.Errorf("'p' tag not hex64: %q", p)
		}
	}
}

func TestPatchPush_InvalidEventIDSkipsStatus(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	post(t, h, "push", patchPush("not-a-hex-id"), "")

	if fake.firstOfKind(KindStatusApplied) != nil {
		t.Errorf("malformed refs/nostr id must not emit an applied status")
	}
	if len(fake.fetched) != 0 {
		t.Errorf("should not fetch for malformed id, got %v", fake.fetched)
	}
	// The push itself is still processed for repo state.
	if len(fake.republished) != 1 {
		t.Errorf("expected repo-state republish, got %v", fake.republished)
	}
}

func TestPatchPush_FetchErrorStillEmits(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)
	fake.fetchErr = fmt.Errorf("relays unreachable")

	post(t, h, "push", patchPush(testPatchEventID), "")

	ev := fake.firstOfKind(KindStatusApplied)
	if ev == nil {
		t.Fatalf("applied status should still be emitted on fetch error; got %v", fake.kinds())
	}
	if ps := tagValues(ev, "p"); len(ps) != 1 {
		t.Errorf("fetch error => no author attribution; want 1 'p' tag, got %v", ps)
	}
}

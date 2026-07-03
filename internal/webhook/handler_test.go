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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// A valid 32-byte (64 hex char) Nostr public key used across tests. The npub
// below is an arbitrary human-readable label; the handler must NEVER place it
// in "p" or "a" tag positions (those require hex per NIP-01/NIP-34).
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

func (f *fakePublisher) PublishEvent(_ context.Context, ev *nostr.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Emulate signing: the real publisher sets ev.ID after signing, and the
	// handler relies on ev.ID to build the follow-up status event's "e" tag.
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("deadbeef%056x", len(f.events))
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
		out = append(out, ev.Kind)
	}
	return out
}

func (f *fakePublisher) firstOfKind(kind int) *nostr.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range f.events {
		if ev.Kind == kind {
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

// post drives ServeHTTP with a JSON payload and an optional valid HMAC.
func post(t *testing.T, h *Handler, eventType string, payload any, secret string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/gitea", bytes.NewReader(body))
	req.Header.Set("X-Gitea-Event", eventType)
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

func TestPR_OpenedEmitsHexTaggedEvents(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	payload := PullRequestPayload{
		Action:     "opened",
		Number:     7,
		Repository: Repository{ID: testGiteaID},
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

	prEv := fake.firstOfKind(KindPROpen)
	if prEv == nil {
		t.Fatalf("no kind %d (PR open) event; got kinds %v", KindPROpen, fake.kinds())
	}
	assertTagsWellFormed(t, prEv)

	statusEv := fake.firstOfKind(KindStatusOpen)
	if statusEv == nil {
		t.Fatalf("no kind %d (status open) event; got kinds %v", KindStatusOpen, fake.kinds())
	}
	assertTagsWellFormed(t, statusEv)

	// The status event must reference the PR event via an "e" tag and carry
	// the repo "a" coordinate (regression guard for the missing-a-tag bug).
	if e := statusEv.Tags.GetFirst([]string{"e", ""}); e == nil || (*e)[1] != prEv.ID {
		t.Errorf("status 'e' tag = %v, want PR event id %q", e, prEv.ID)
	}
	if a := statusEv.Tags.GetFirst([]string{"a", ""}); a == nil {
		t.Errorf("status event missing 'a' repo coordinate tag")
	}
}

func TestPR_MergedEmitsAppliedStatus(t *testing.T) {
	h, fake, st := newTestHandler(t, "")
	seedMapping(t, st)

	payload := PullRequestPayload{Action: "closed", Number: 8, Repository: Repository{ID: testGiteaID}}
	payload.PullRequest.State = "closed"
	payload.PullRequest.Merged = true

	post(t, h, "pull_request", payload, "")
	if fake.firstOfKind(KindStatusApplied) == nil {
		t.Fatalf("merged PR should emit kind %d (applied); got %v", KindStatusApplied, fake.kinds())
	}
}

func TestIssue_OpenedEmitsHexTaggedEvents(t *testing.T) {
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
	if fake.firstOfKind(KindStatusOpen) == nil {
		t.Fatalf("open issue should emit kind %d status; got %v", KindStatusOpen, fake.kinds())
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
	if l := labelEv.Tags.GetFirst([]string{"l", ""}); l == nil || (*l)[1] != "enhancement" {
		t.Errorf("label 'l' tag = %v, want enhancement", l)
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
	if got := firstTagValue(ev, "e"); got != testPatchEventID {
		t.Errorf("'e' tag = %q, want patch id %q", got, testPatchEventID)
	}
	if got := firstTagValue(ev, "applied-as-commits"); got != testCommitSHA {
		t.Errorf("'applied-as-commits' = %q, want %q", got, testCommitSHA)
	}
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
	fake.fetchResult = &nostr.Event{Kind: KindPatch, PubKey: testPatchAuthorHex}

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

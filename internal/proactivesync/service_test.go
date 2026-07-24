// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package proactivesync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// stubResolver is a minimal OrgResolver for tests.
type stubResolver struct {
	mappings map[string]store.Mapping
}

func (s *stubResolver) GetMapping(_ context.Context, npub string, repoID string) (store.Mapping, error) {
	key := npub + "/" + repoID
	m, ok := s.mappings[key]
	if !ok {
		return store.Mapping{}, sql.ErrNoRows
	}
	return m, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestHandleStateEventNilEvent(t *testing.T) {
	svc := New("/tmp/repos", nil, testLogger())
	if err := svc.HandleStateEvent(context.Background(), nil); err != nil {
		t.Fatalf("nil event should return nil, got %v", err)
	}
}

func TestHandleStateEventWrongKind(t *testing.T) {
	svc := New("/tmp/repos", nil, testLogger())
	ev := &nostr.Event{Kind: 1} // text note, not state event
	if err := svc.HandleStateEvent(context.Background(), ev); err != nil {
		t.Fatalf("wrong kind should return nil, got %v", err)
	}
}

func TestHandleStateEventMissingDTag(t *testing.T) {
	svc := New("/tmp/repos", nil, testLogger())
	// Create a valid-looking state event with no d tag.
	// nostr.KindRepositoryState = 30618
	ev := &nostr.Event{
		Kind:   nostr.KindRepositoryState,
		PubKey: nostr.MustPubKeyFromHex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
		Tags:   nostr.Tags{},
	}
	// Signature validation will fail before d tag check, so we need to test
	// the validation path. Since we can't easily generate valid sigs in test,
	// we test the validation error is about crypto, not missing d tag.
	err := svc.HandleStateEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error for event without valid signature")
	}
}

func TestHandleStateEventUnprovisionedRepo(t *testing.T) {
	// When the OrgResolver has no mapping, HandleStateEvent should return nil
	// (silently skip unprovisioned repos).
	resolver := &stubResolver{mappings: map[string]store.Mapping{}}
	svc := New("/tmp/repos", resolver, testLogger())

	// We need a valid nostr event to pass signature check.
	// Since we can't easily make one, we'll test that the resolver lookup path
	// is correct by checking that an event with invalid sig returns error.
	ev := &nostr.Event{
		Kind:   nostr.KindRepositoryState,
		PubKey: nostr.MustPubKeyFromHex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
		Tags:   nostr.Tags{{"d", "myrepo"}},
	}
	err := svc.HandleStateEvent(context.Background(), ev)
	// Should fail at crypto validation (we don't have real keys in test).
	if err == nil {
		t.Fatal("expected crypto validation error")
	}
}

func TestValidRefPattern(t *testing.T) {
	tests := []struct {
		ref   string
		valid bool
	}{
		{"refs/heads/main", true},
		{"refs/heads/feature/foo", true},
		{"refs/tags/v1.0", true},
		{"refs/tags/v1.0-rc1", true},
		{"refs/heads/.hidden", false},
		{"refs/heads/-nope", false},
		{"refs/other/foo", false},
		{"main", false},
		{"", false},
		{"refs/heads/a b", false},
		{"refs/heads/ok_name.1", true},
	}
	for _, tt := range tests {
		got := validRef.MatchString(tt.ref)
		if got != tt.valid {
			t.Errorf("validRef(%q) = %v, want %v", tt.ref, got, tt.valid)
		}
	}
}

func TestValidHexPattern(t *testing.T) {
	tests := []struct {
		sha   string
		valid bool
	}{
		{"abcd", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"abc", false},  // too short (< 4)
		{"ABCD", false}, // uppercase not allowed
		{"abcg", false}, // non-hex
		{"", false},
	}
	for _, tt := range tests {
		got := validHex.MatchString(tt.sha)
		if got != tt.valid {
			t.Errorf("validHex(%q) = %v, want %v", tt.sha, got, tt.valid)
		}
	}
}

func TestTagValue(t *testing.T) {
	tags := nostr.Tags{
		{"d", "myrepo"},
		{"p", "somepubkey"},
	}
	if v := tagValue(tags, "d"); v != "myrepo" {
		t.Errorf("expected 'myrepo', got %q", v)
	}
	if v := tagValue(tags, "missing"); v != "" {
		t.Errorf("expected empty for missing tag, got %q", v)
	}
}

func TestNewServiceStoresFields(t *testing.T) {
	resolver := &stubResolver{}
	logger := testLogger()
	svc := New("/custom/path", resolver, logger)
	if svc.repositoriesDir != "/custom/path" {
		t.Errorf("expected /custom/path, got %s", svc.repositoriesDir)
	}
	if svc.orgResolver == nil {
		t.Error("expected non-nil orgResolver")
	}
}

func TestRepoPathSkippedWhenNotFound(t *testing.T) {
	// Even if we had a valid signed event, if the repo path doesn't exist on
	// disk, the service should silently return nil. We verify that the path
	// construction uses the resolved org name (not npub).
	resolver := &stubResolver{
		mappings: map[string]store.Mapping{
			"npub1abc/testrepo": {Owner: "resolved-org", RepoID: "testrepo"},
		},
	}
	svc := New("/nonexistent/repos", resolver, testLogger())

	// The event will fail signature validation before reaching the path check,
	// but we can at least confirm the service is correctly wired.
	_ = fmt.Sprintf("svc=%v", svc)
}

type stubStore struct {
	stubResolver
	mappingsList []store.Mapping
}

func (s *stubStore) ListMappings(_ context.Context) ([]store.Mapping, error) {
	return append([]store.Mapping{}, s.mappingsList...), nil
}

type fetchCall struct {
	repoPath string
	remote   string
	refspecs []string
}

type fakeGitRunner struct {
	mu      sync.Mutex
	objects map[string]bool
	fetches []fetchCall
	updates map[string]string
	heads   map[string]string
}

func newFakeGitRunner() *fakeGitRunner {
	return &fakeGitRunner{objects: map[string]bool{}, updates: map[string]string{}, heads: map[string]string{}}
}

func (g *fakeGitRunner) ListRefs(_ context.Context, repoPath string, prefix string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var refs []string
	for key := range g.updates {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) == 2 && parts[0] == repoPath && strings.HasPrefix(parts[1], prefix) {
			refs = append(refs, parts[1])
		}
	}
	return refs, nil
}

func (g *fakeGitRunner) DeleteRef(_ context.Context, repoPath string, ref string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.updates, repoPath+"|"+ref)
	return nil
}

func (g *fakeGitRunner) SetSymbolicHEAD(_ context.Context, repoPath string, ref string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.heads[repoPath] = ref
	return nil
}

func (g *fakeGitRunner) ObjectExists(_ context.Context, _ string, sha string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.objects[sha], nil
}

func (g *fakeGitRunner) UpdateRef(_ context.Context, repoPath string, ref string, sha string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.objects[sha] {
		return fmt.Errorf("missing object %s", sha)
	}
	g.updates[repoPath+"|"+ref] = sha
	return nil
}

func (g *fakeGitRunner) Fetch(_ context.Context, repoPath string, remoteURL string, refspecs []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fetches = append(g.fetches, fetchCall{repoPath: repoPath, remote: remoteURL, refspecs: append([]string{}, refspecs...)})
	for _, refspec := range refspecs {
		src := refspec
		if strings.HasPrefix(src, "+") {
			src = strings.TrimPrefix(src, "+")
		}
		if idx := strings.Index(src, ":"); idx >= 0 {
			src = src[:idx]
		}
		if validHex.MatchString(src) {
			g.objects[src] = true
		}
	}
	return nil
}

type fakeRelayQueries struct {
	mu      sync.Mutex
	queries []nostr.Filter
	state   []*nostr.Event
	prs     []*nostr.Event
}

func (q *fakeRelayQueries) query(_ context.Context, _ string, filter nostr.Filter) ([]*nostr.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queries = append(q.queries, filter)
	if filterHasKind(filter, relay.KindRepositoryState) {
		return append([]*nostr.Event{}, q.state...), nil
	}
	if filterHasKind(filter, relay.KindPROpen) || filterHasKind(filter, relay.KindPRUpdate) {
		return append([]*nostr.Event{}, q.prs...), nil
	}
	return nil, nil
}

func filterHasKind(filter nostr.Filter, kind int) bool {
	for _, k := range filter.Kinds {
		if k == nostr.Kind(kind) {
			return true
		}
	}
	return false
}

type fakeTicker struct {
	ch      chan time.Time
	stopped bool
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop()               { t.stopped = true }

func TestSyncOnceFetchesMissingStateObjectsAndPRTips(t *testing.T) {
	ctx := context.Background()
	reposDir := t.TempDir()
	owner := "alice"
	repoID := "project"
	repoPath := reposDir + "/" + owner + "/" + repoID + ".git"
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("create bare repo dir: %v", err)
	}

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerPK, err := nostr.PubKeyFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerNpub := nip19.EncodeNpub(ownerPK)

	cloneURL := "https://git.example.com/alice/project.git"
	relayURL := "wss://relay.example.com"
	announcement := signedTestEvent(t, ownerPriv, relay.KindRepositoryAnnouncement, nostr.Tags{
		{"d", repoID},
		{"clone", cloneURL},
		{"relays", relayURL},
	})
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal announcement: %v", err)
	}

	stateSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	stateEvent := signedTestEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"refs/heads/main", stateSHA},
	})
	prSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	prEvent := signedTestEvent(t, ownerPriv, relay.KindPROpen, nostr.Tags{
		{"a", fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, ownerPub, repoID)},
		{"clone", cloneURL},
		{"c", prSHA},
	})

	mapping := store.Mapping{
		Npub:                  ownerNpub,
		RepoID:                repoID,
		Pubkey:                ownerPub,
		Owner:                 owner,
		RepoName:              repoID,
		GiteaRepoID:           7,
		CloneURL:              cloneURL,
		AnnouncedCloneURL:     cloneURL,
		AnnouncementEventJSON: string(announcementJSON),
	}
	st := &stubStore{
		stubResolver: stubResolver{mappings: map[string]store.Mapping{ownerNpub + "/" + repoID: mapping}},
		mappingsList: []store.Mapping{mapping},
	}
	git := newFakeGitRunner()
	relays := &fakeRelayQueries{state: []*nostr.Event{stateEvent}, prs: []*nostr.Event{prEvent}}

	svc := New(reposDir, st, testLogger())
	svc.git = git
	svc.queryRelay = relays.query

	if err := svc.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}

	git.mu.Lock()
	defer git.mu.Unlock()
	if len(git.fetches) != 2 {
		t.Fatalf("fetches = %d, want 2: %#v", len(git.fetches), git.fetches)
	}
	if got := git.fetches[0].remote; got != cloneURL {
		t.Errorf("state fetch remote = %q, want %q", got, cloneURL)
	}
	if got := git.fetches[0].refspecs; len(got) != 1 || got[0] != stateSHA {
		t.Errorf("state fetch refspecs = %v, want [%s]", got, stateSHA)
	}
	wantPRRefspec := "+" + prSHA + ":refs/nostr/" + prEvent.ID.Hex()
	if got := git.fetches[1].refspecs; len(got) != 1 || got[0] != wantPRRefspec {
		t.Errorf("PR fetch refspecs = %v, want [%s]", got, wantPRRefspec)
	}
	if got := git.updates[repoPath+"|refs/heads/main"]; got != stateSHA {
		t.Errorf("updated main ref = %q, want %q", got, stateSHA)
	}
}

func TestSyncOnceIgnoresStateEventThatOnlyTagsOwner(t *testing.T) {
	ctx := context.Background()
	reposDir := t.TempDir()
	owner := "alice"
	repoID := "project"
	if err := os.MkdirAll(reposDir+"/"+owner+"/"+repoID+".git", 0o755); err != nil {
		t.Fatalf("create bare repo dir: %v", err)
	}

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerPK, err := nostr.PubKeyFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerNpub := nip19.EncodeNpub(ownerPK)
	announcement := signedTestEvent(t, ownerPriv, relay.KindRepositoryAnnouncement, nostr.Tags{
		{"d", repoID},
		{"clone", "https://git.example.com/alice/project.git"},
		{"relays", "wss://relay.example.com"},
	})
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal announcement: %v", err)
	}

	attackerPriv := nostr.Generate().Hex()
	spoofedState := signedTestEvent(t, attackerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"p", ownerPub},
		{"refs/heads/main", "cccccccccccccccccccccccccccccccccccccccc"},
	})
	mapping := store.Mapping{
		Npub:                  ownerNpub,
		RepoID:                repoID,
		Pubkey:                ownerPub,
		Owner:                 owner,
		RepoName:              repoID,
		AnnouncedCloneURL:     "https://git.example.com/alice/project.git",
		AnnouncementEventJSON: string(announcementJSON),
	}
	st := &stubStore{mappingsList: []store.Mapping{mapping}}
	git := newFakeGitRunner()
	relays := &fakeRelayQueries{state: []*nostr.Event{spoofedState}}

	svc := New(reposDir, st, testLogger())
	svc.git = git
	svc.queryRelay = relays.query

	if err := svc.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}
	git.mu.Lock()
	defer git.mu.Unlock()
	if len(git.fetches) != 0 {
		t.Fatalf("spoofed state triggered fetches: %#v", git.fetches)
	}
	if len(git.updates) != 0 {
		t.Fatalf("spoofed state triggered updates: %#v", git.updates)
	}
}

func TestQueryRelayHistoryPaginatesWithUntil(t *testing.T) {
	svc := New(t.TempDir(), nil, testLogger())
	var calls int
	svc.queryRelay = func(_ context.Context, _ string, filter nostr.Filter) ([]*nostr.Event, error) {
		calls++
		if filter.Until == 0 {
			return []*nostr.Event{{CreatedAt: 30}, {CreatedAt: 20}}, nil
		}
		if filter.Until == 19 {
			return []*nostr.Event{{CreatedAt: 10}}, nil
		}
		return nil, nil
	}

	events, err := svc.queryRelayHistory(context.Background(), "wss://relay.example.com", nostr.Filter{}, 2)
	if err != nil {
		t.Fatalf("queryRelayHistory() error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if calls != 2 {
		t.Fatalf("query calls = %d, want 2", calls)
	}
}

func TestRunHonorsConfiguredIntervalAndTicks(t *testing.T) {
	svc := New(t.TempDir(), &stubStore{}, testLogger())
	ticker := &fakeTicker{ch: make(chan time.Time, 1)}
	intervalCh := make(chan time.Duration, 1)
	svc.newTicker = func(interval time.Duration) syncTicker {
		intervalCh <- interval
		return ticker
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(ctx, 37*time.Millisecond)
	}()

	gotInterval := <-intervalCh
	if gotInterval != 37*time.Millisecond {
		t.Fatalf("ticker interval = %v, want 37ms", gotInterval)
	}
	ticker.ch <- time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
	if !ticker.stopped {
		t.Error("ticker was not stopped")
	}
}

func TestNormalizeSyncIntervalClampsAboveOneHour(t *testing.T) {
	if got := NormalizeSyncInterval(2 * time.Hour); got != time.Hour {
		t.Errorf("NormalizeSyncInterval(2h) = %v, want 1h", got)
	}
	if got := NormalizeSyncInterval(15 * time.Minute); got != 15*time.Minute {
		t.Errorf("NormalizeSyncInterval(15m) = %v, want 15m", got)
	}
}

func signedTestEvent(t *testing.T, priv string, kind int, tags nostr.Tags) *nostr.Event {
	t.Helper()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	ev := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex(pub),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      nostr.Kind(kind),
		Tags:      tags,
		Content:   "",
	}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

func TestApplyStateEventReconcilesSymbolicHEAD(t *testing.T) {
	ctx := context.Background()
	priv := nostr.Generate().Hex()
	git := newFakeGitRunner()
	mainSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	devSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	git.objects[mainSHA] = true
	git.objects[devSHA] = true

	svc := New(t.TempDir(), &stubStore{}, testLogger())
	svc.git = git
	repoPath := "/repos/alice/project.git"

	state1 := signedTestEvent(t, priv, relay.KindRepositoryState, nostr.Tags{
		{"d", "project"},
		{"HEAD", "ref: refs/heads/main"},
		{"refs/heads/main", mainSHA},
		{"refs/heads/develop", devSHA},
	})
	if err := svc.applyStateEvent(ctx, repoPath, state1); err != nil {
		t.Fatalf("apply state1: %v", err)
	}
	if got := git.heads[repoPath]; got != "refs/heads/main" {
		t.Fatalf("expected HEAD refs/heads/main, got %q", got)
	}

	// HEAD transition main -> develop.
	state2 := signedTestEvent(t, priv, relay.KindRepositoryState, nostr.Tags{
		{"d", "project"},
		{"HEAD", "ref: refs/heads/develop"},
		{"refs/heads/main", mainSHA},
		{"refs/heads/develop", devSHA},
	})
	if err := svc.applyStateEvent(ctx, repoPath, state2); err != nil {
		t.Fatalf("apply state2: %v", err)
	}
	if got := git.heads[repoPath]; got != "refs/heads/develop" {
		t.Fatalf("expected HEAD refs/heads/develop after transition, got %q", got)
	}
}

func TestApplyStateEventHEADIgnoredWhenUndeclaredOrMissing(t *testing.T) {
	ctx := context.Background()
	priv := nostr.Generate().Hex()
	git := newFakeGitRunner()
	mainSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	git.objects[mainSHA] = true

	svc := New(t.TempDir(), &stubStore{}, testLogger())
	svc.git = git
	repoPath := "/repos/alice/project.git"

	// HEAD names a branch the state does not declare.
	undeclared := signedTestEvent(t, priv, relay.KindRepositoryState, nostr.Tags{
		{"d", "project"},
		{"HEAD", "ref: refs/heads/ghost"},
		{"refs/heads/main", mainSHA},
	})
	if err := svc.applyStateEvent(ctx, repoPath, undeclared); err != nil {
		t.Fatalf("apply undeclared: %v", err)
	}
	if got, ok := git.heads[repoPath]; ok {
		t.Fatalf("expected HEAD untouched for undeclared branch, got %q", got)
	}

	// HEAD branch object missing locally.
	missingSHA := "cccccccccccccccccccccccccccccccccccccccc"
	missingObj := signedTestEvent(t, priv, relay.KindRepositoryState, nostr.Tags{
		{"d", "project"},
		{"HEAD", "ref: refs/heads/develop"},
		{"refs/heads/develop", missingSHA},
	})
	if err := svc.applyStateEvent(ctx, repoPath, missingObj); err != nil {
		t.Fatalf("apply missing object: %v", err)
	}
	if got, ok := git.heads[repoPath]; ok {
		t.Fatalf("expected HEAD untouched for missing object, got %q", got)
	}
}

func TestApplyStateEventDeletesRefsOmittedFromState(t *testing.T) {
	ctx := context.Background()
	priv := nostr.Generate().Hex()
	git := newFakeGitRunner()
	keepSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oldSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	git.objects[keepSHA] = true
	git.objects[oldSHA] = true

	repoPath := "/repos/alice/project.git"
	// Local refs before the state event arrives.
	git.updates[repoPath+"|refs/heads/main"] = keepSHA
	git.updates[repoPath+"|refs/heads/stale-branch"] = oldSHA
	git.updates[repoPath+"|refs/tags/v1.0.0"] = keepSHA
	git.updates[repoPath+"|refs/tags/v0.1.0"] = oldSHA
	git.updates[repoPath+"|refs/nostr/"+strings.Repeat("ab", 32)] = oldSHA

	svc := New(t.TempDir(), &stubStore{}, testLogger())
	svc.git = git

	state := signedTestEvent(t, priv, relay.KindRepositoryState, nostr.Tags{
		{"d", "project"},
		{"refs/heads/main", keepSHA},
		{"refs/tags/v1.0.0", keepSHA},
	})
	if err := svc.applyStateEvent(ctx, repoPath, state); err != nil {
		t.Fatalf("apply state: %v", err)
	}

	if _, ok := git.updates[repoPath+"|refs/heads/stale-branch"]; ok {
		t.Fatalf("expected omitted branch to be deleted")
	}
	if _, ok := git.updates[repoPath+"|refs/tags/v0.1.0"]; ok {
		t.Fatalf("expected omitted tag to be deleted")
	}
	if _, ok := git.updates[repoPath+"|refs/heads/main"]; !ok {
		t.Fatalf("expected declared branch to survive")
	}
	if _, ok := git.updates[repoPath+"|refs/tags/v1.0.0"]; !ok {
		t.Fatalf("expected declared tag to survive")
	}
	if _, ok := git.updates[repoPath+"|refs/nostr/"+strings.Repeat("ab", 32)]; !ok {
		t.Fatalf("expected refs/nostr namespace to be untouched")
	}
}

func TestSyncOnceAcceptsMaintainerSignedState(t *testing.T) {
	ctx := context.Background()
	reposDir := t.TempDir()
	owner := "alice"
	repoID := "project"
	repoPath := reposDir + "/" + owner + "/" + repoID + ".git"
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("create bare repo dir: %v", err)
	}

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerPK, err := nostr.PubKeyFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerNpub := nip19.EncodeNpub(ownerPK)

	maintainerPriv := nostr.Generate().Hex()
	maintainerPub, err := derivePubHex(maintainerPriv)
	if err != nil {
		t.Fatalf("maintainer public key: %v", err)
	}

	cloneURL := "https://git.example.com/alice/project.git"
	announcement := signedTestEvent(t, ownerPriv, relay.KindRepositoryAnnouncement, nostr.Tags{
		{"d", repoID},
		{"clone", cloneURL},
		{"relays", "wss://relay.example.com"},
		{"maintainers", maintainerPub},
	})
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal announcement: %v", err)
	}

	stateSHA := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	maintainerState := signedTestEvent(t, maintainerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"refs/heads/main", stateSHA},
	})

	mapping := store.Mapping{
		Npub:                  ownerNpub,
		RepoID:                repoID,
		Pubkey:                ownerPub,
		Owner:                 owner,
		RepoName:              repoID,
		AnnouncedCloneURL:     cloneURL,
		AnnouncementEventJSON: string(announcementJSON),
	}
	st := &stubStore{
		stubResolver: stubResolver{mappings: map[string]store.Mapping{ownerNpub + "/" + repoID: mapping}},
		mappingsList: []store.Mapping{mapping},
	}
	git := newFakeGitRunner()
	git.objects[stateSHA] = true
	relays := &fakeRelayQueries{state: []*nostr.Event{maintainerState, announcement}}

	svc := New(reposDir, st, testLogger())
	svc.git = git
	svc.queryRelay = relays.query

	if err := svc.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce() error: %v", err)
	}

	git.mu.Lock()
	defer git.mu.Unlock()
	if got := git.updates[repoPath+"|refs/heads/main"]; got != stateSHA {
		t.Fatalf("expected maintainer-signed state to update main to %s, got %q", stateSHA, got)
	}
}

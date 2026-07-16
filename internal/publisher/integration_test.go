// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/slicestore"
	"fiatjaf.com/nostr/khatru"

	relaypkg "github.com/sharegap/grasp-gitea/internal/relay"
	appstore "github.com/sharegap/grasp-gitea/internal/store"
)

func TestRepublishForGiteaRepoPublishesStateAndSkipsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relay := newTestRelay(t)
	st := newTestStore(t)
	repositoriesDir := t.TempDir()
	repoPath := createBareRepoFixture(t, repositoriesDir, "alice", "project")

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerNpub, err := encodeNpubFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner npub: %v", err)
	}
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "project-repo-id",
		Pubkey:        ownerPub,
		Owner:         "alice",
		RepoName:      "project",
		GiteaRepoID:   42,
		CloneURL:      "https://git.example/alice/project.git",
		SourceEvent:   "seed-event",
		HookInstalled: true,
	})

	svc, err := New(genNsec(t), st, []string{relay.url}, repositoriesDir, discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}

	if err := svc.RepublishForGiteaRepo(ctx, 42); err != nil {
		t.Fatalf("RepublishForGiteaRepo first call: %v", err)
	}

	savedStateEvents := relay.savedEventsByKind(relaypkg.KindRepositoryState)
	if len(savedStateEvents) != 1 {
		t.Fatalf("relay saved %d kind:%d events, want 1", len(savedStateEvents), relaypkg.KindRepositoryState)
	}
	stateEvent := savedStateEvents[0]
	if !stateEvent.VerifySignature() {
		t.Fatalf("state event signature invalid")
	}
	if stateEvent.PubKey.Hex() != svc.bridgePubKey {
		t.Fatalf("state event pubkey = %q, want bridge pubkey %q", stateEvent.PubKey, svc.bridgePubKey)
	}
	if got, ok := firstVal(stateEvent, "d"); !ok || got != "project-repo-id" {
		t.Fatalf("state event d tag = %q (present %v), want project-repo-id", got, ok)
	}
	if got, ok := firstVal(stateEvent, "p"); !ok || got != ownerPub {
		t.Fatalf("state event p tag = %q (present %v), want owner pubkey", got, ok)
	}

	head, branches, tags, err := snapshotRefs(ctx, repoPath)
	if err != nil {
		t.Fatalf("snapshot fixture refs: %v", err)
	}
	if head != "main" {
		t.Fatalf("fixture HEAD = %q, want main", head)
	}
	assertRefTag(t, stateEvent, "refs/heads/main", branches["main"])
	assertRefTag(t, stateEvent, "refs/heads/feature", branches["feature"])
	assertRefTag(t, stateEvent, "refs/tags/v1.0", tags["v1.0"])
	assertRefTag(t, stateEvent, "HEAD", "ref: refs/heads/main")

	queried := relay.query(t, nostr.Filter{Kinds: []nostr.Kind{relaypkg.KindRepositoryState}, Limit: 10})
	if len(queried) != 1 {
		t.Fatalf("relay query returned %d kind:%d events, want 1", len(queried), relaypkg.KindRepositoryState)
	}
	if queried[0].ID != stateEvent.ID {
		t.Fatalf("queried state event ID = %q, want saved event ID %q", queried[0].ID, stateEvent.ID)
	}

	gotMapping, err := st.GetMapping(ctx, ownerNpub, "project-repo-id")
	if err != nil {
		t.Fatalf("get mapping after publish: %v", err)
	}
	if gotMapping.LastStateEventID != stateEvent.ID.Hex() {
		t.Fatalf("LastStateEventID = %q, want %q", gotMapping.LastStateEventID, stateEvent.ID)
	}
	if gotMapping.LastStateDigest == "" {
		t.Fatal("LastStateDigest was not recorded")
	}

	beforeSecondCall := relay.savedEventCount()
	if err := svc.RepublishForGiteaRepo(ctx, 42); err != nil {
		t.Fatalf("RepublishForGiteaRepo second call: %v", err)
	}
	if afterSecondCall := relay.savedEventCount(); afterSecondCall != beforeSecondCall {
		t.Fatalf("unchanged digest published %d new events, want 0", afterSecondCall-beforeSecondCall)
	}
}

func TestRepublishForGiteaRepoEnqueuesOwnerSignedStateWhenGrantPresent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st := newTestStore(t)
	repositoriesDir := t.TempDir()
	createBareRepoFixture(t, repositoriesDir, "alice", "signed")

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerNpub, err := encodeNpubFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner npub: %v", err)
	}
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "signed-repo-id",
		Pubkey:        ownerPub,
		Owner:         "alice",
		RepoName:      "signed",
		GiteaRepoID:   4242,
		CloneURL:      "https://git.example/alice/signed.git",
		SourceEvent:   "seed-event",
		HookInstalled: true,
	})
	if err := st.UpsertSignerGrant(ctx, appstore.SignerGrant{
		Pubkey:          ownerPub,
		ClientSeckeyEnc: []byte("ciphertext-client"),
		BunkerURIEnc:    []byte("ciphertext-bunker"),
		Relays:          `[]`,
		Permissions:     `["sign_event"]`,
		GrantedAt:       time.Now().UTC(),
		Status:          "active",
	}); err != nil {
		t.Fatalf("seed signer grant: %v", err)
	}

	svc, err := New(genNsec(t), st, nil, repositoriesDir, discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	outbox := &fakeStateOutbox{}
	svc.SetOwnerStateSigning(fakeStateSigner{enabled: true}, outbox)

	if err := svc.RepublishForGiteaRepo(ctx, 4242); err != nil {
		t.Fatalf("RepublishForGiteaRepo: %v", err)
	}

	if len(outbox.calls) != 1 {
		t.Fatalf("outbox enqueue calls = %d, want 1", len(outbox.calls))
	}
	call := outbox.calls[0]
	if call.kind != relaypkg.KindRepositoryState {
		t.Fatalf("enqueued kind = %d, want %d", call.kind, relaypkg.KindRepositoryState)
	}
	if call.authorPubkey != ownerPub {
		t.Fatalf("enqueued author = %q, want owner pubkey %q", call.authorPubkey, ownerPub)
	}
	if call.event.PubKey.Hex() != ownerPub {
		t.Fatalf("unsigned event pubkey = %q, want owner pubkey %q", call.event.PubKey, ownerPub)
	}
	if call.event.ID != (nostr.ID{}) || call.event.Sig != [64]byte{} {
		t.Fatalf("enqueued event should be unsigned, got id=%q sig=%q", call.event.ID, call.event.Sig)
	}
	if got, ok := firstVal(&call.event, "d"); !ok || got != "signed-repo-id" {
		t.Fatalf("enqueued event d tag = %q (present %v), want signed-repo-id", got, ok)
	}
	if call.scope != "repo:alice/signed" {
		t.Fatalf("scope = %q, want repo:alice/signed", call.scope)
	}
	if !strings.HasPrefix(call.dedupeKey, "repo-state:4242:signed-repo-id:") {
		t.Fatalf("dedupe key = %q, want stable repo-state prefix", call.dedupeKey)
	}
}

func TestRepublishForGiteaRepoFallsBackToBridgeWhenOwnerGrantMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relay := newTestRelay(t)
	st := newTestStore(t)
	repositoriesDir := t.TempDir()
	createBareRepoFixture(t, repositoriesDir, "carol", "fallback")

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerNpub, err := encodeNpubFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner npub: %v", err)
	}
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "fallback-repo-id",
		Pubkey:        ownerPub,
		Owner:         "carol",
		RepoName:      "fallback",
		GiteaRepoID:   5150,
		CloneURL:      "https://git.example/carol/fallback.git",
		SourceEvent:   "seed-event",
		HookInstalled: true,
	})

	svc, err := New(genNsec(t), st, []string{relay.url}, repositoriesDir, discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	outbox := &fakeStateOutbox{}
	svc.SetOwnerStateSigning(fakeStateSigner{enabled: true}, outbox)

	if err := svc.RepublishForGiteaRepo(ctx, 5150); err != nil {
		t.Fatalf("RepublishForGiteaRepo: %v", err)
	}
	if len(outbox.calls) != 0 {
		t.Fatalf("outbox enqueue calls = %d, want 0 without owner grant", len(outbox.calls))
	}
	savedStateEvents := relay.savedEventsByKind(relaypkg.KindRepositoryState)
	if len(savedStateEvents) != 1 {
		t.Fatalf("relay saved %d kind:%d events, want 1", len(savedStateEvents), relaypkg.KindRepositoryState)
	}
	stateEvent := savedStateEvents[0]
	if stateEvent.PubKey.Hex() != svc.bridgePubKey {
		t.Fatalf("fallback pubkey = %q, want bridge pubkey %q", stateEvent.PubKey, svc.bridgePubKey)
	}
	if !stateEvent.VerifySignature() {
		t.Fatalf("fallback signature invalid")
	}
	if got, ok := firstVal(stateEvent, "p"); !ok || got != ownerPub {
		t.Fatalf("fallback p tag = %q (present %v), want owner pubkey", got, ok)
	}
}

func TestRepublishForGiteaRepoRebroadcastsCachedAnnouncement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relay := newTestRelay(t)
	st := newTestStore(t)
	repositoriesDir := t.TempDir()
	createBareRepoFixture(t, repositoriesDir, "bob", "announced")

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner public key: %v", err)
	}
	ownerNpub, err := encodeNpubFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner npub: %v", err)
	}
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "announced-repo-id",
		Pubkey:        ownerPub,
		Owner:         "bob",
		RepoName:      "announced",
		GiteaRepoID:   77,
		CloneURL:      "https://git.example/bob/announced.git",
		SourceEvent:   "seed-event",
		HookInstalled: true,
	})

	announcement := nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex(ownerPub),
		CreatedAt: nostr.Timestamp(1700000000),
		Kind:      relaypkg.KindRepositoryAnnouncement,
		Tags: nostr.Tags{
			{"d", "announced-repo-id"},
			{"name", "announced"},
			{"clone", "https://git.example/bob/announced.git"},
		},
		Content: "owner signed announcement",
	}
	if err := announcement.Sign(mustSK(ownerPriv)); err != nil {
		t.Fatalf("sign announcement: %v", err)
	}
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal announcement: %v", err)
	}
	if err := st.SetAnnouncementEvent(ctx, ownerNpub, "announced-repo-id", string(announcementJSON), announcement.ID.Hex()); err != nil {
		t.Fatalf("cache announcement event: %v", err)
	}

	svc, err := New(genNsec(t), st, []string{relay.url}, repositoriesDir, discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	if err := svc.RepublishForGiteaRepo(ctx, 77); err != nil {
		t.Fatalf("RepublishForGiteaRepo: %v", err)
	}

	savedAnnouncements := relay.savedEventsByKind(relaypkg.KindRepositoryAnnouncement)
	if len(savedAnnouncements) != 1 {
		t.Fatalf("relay saved %d kind:%d announcements, want 1", len(savedAnnouncements), relaypkg.KindRepositoryAnnouncement)
	}
	assertSameEvent(t, &announcement, savedAnnouncements[0])

	queried := relay.query(t, nostr.Filter{IDs: []nostr.ID{announcement.ID}, Limit: 1})
	if len(queried) != 1 {
		t.Fatalf("relay query by announcement ID returned %d events, want 1", len(queried))
	}
	assertSameEvent(t, &announcement, queried[0])

	gotMapping, err := st.GetMapping(ctx, ownerNpub, "announced-repo-id")
	if err != nil {
		t.Fatalf("get mapping after republish: %v", err)
	}
	if gotMapping.LastRepublishedAnnouncementID != announcement.ID.Hex() {
		t.Fatalf("LastRepublishedAnnouncementID = %q, want %q", gotMapping.LastRepublishedAnnouncementID, announcement.ID)
	}
	if gotMapping.LastRepublishedAnnouncementAt.IsZero() {
		t.Fatal("LastRepublishedAnnouncementAt was not recorded")
	}
}

func TestFetchEventRoundTripsThroughRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relay := newTestRelay(t)
	svc, err := New("", nil, []string{relay.url}, t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}

	priv := nostr.Generate().Hex()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	ev := nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex(pub),
		CreatedAt: nostr.Timestamp(1700000100),
		Kind:      1,
		Tags:      nostr.Tags{{"t", "fetch-roundtrip"}},
		Content:   "fetch me from the relay",
	}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	publishDirectly(t, ctx, relay.url, ev)

	got, err := svc.FetchEvent(ctx, ev.ID.Hex())
	if err != nil {
		t.Fatalf("FetchEvent: %v", err)
	}
	if got == nil {
		t.Fatal("FetchEvent returned nil event")
	}
	assertSameEvent(t, &ev, got)
}

type fakeStateSigner struct {
	enabled bool
}

func (s fakeStateSigner) Enabled() bool { return s.enabled }

type fakeStateOutbox struct {
	calls []fakeStateOutboxCall
}

type fakeStateOutboxCall struct {
	kind         int
	authorPubkey string
	scope        string
	dedupeKey    string
	event        nostr.Event
}

func (o *fakeStateOutbox) Enqueue(_ context.Context, kind int, authorPubkey string, scope string, unsignedEvent *nostr.Event, dedupeKey string) error {
	call := fakeStateOutboxCall{
		kind:         kind,
		authorPubkey: authorPubkey,
		scope:        scope,
		dedupeKey:    dedupeKey,
	}
	if unsignedEvent != nil {
		call.event = *cloneEvent(unsignedEvent)
	}
	o.calls = append(o.calls, call)
	return nil
}

type testRelay struct {
	url    string
	server *httptest.Server
	store  *slicestore.SliceStore

	mu    sync.Mutex
	saved []*nostr.Event
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()

	rl := khatru.NewRelay()
	rl.Log = log.New(io.Discard, "", 0)

	ss := &slicestore.SliceStore{}
	if err := ss.Init(); err != nil {
		t.Fatalf("init slicestore: %v", err)
	}

	tr := &testRelay{store: ss}
	rl.UseEventstore(ss, 1000)
	rl.OnEventSaved = func(ctx context.Context, ev nostr.Event) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.saved = append(tr.saved, cloneEvent(&ev))
	}

	tr.server = httptest.NewServer(rl)
	tr.url = "ws" + strings.TrimPrefix(tr.server.URL, "http")
	t.Cleanup(func() {
		tr.server.Close()
		ss.Close()
	})
	return tr
}

func (tr *testRelay) query(t *testing.T, filter nostr.Filter) []*nostr.Event {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, err := nostr.RelayConnect(ctx, tr.url, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("connect relay for query: %v", err)
	}
	defer r.Close()

	var events []*nostr.Event
	for ev := range r.QueryEvents(filter) {
		e := ev
		events = append(events, &e)
	}
	return events
}

func (tr *testRelay) savedEventsByKind(kind int) []*nostr.Event {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	out := make([]*nostr.Event, 0)
	for _, ev := range tr.saved {
		if int(ev.Kind) == kind {
			out = append(out, cloneEvent(ev))
		}
	}
	return out
}

func (tr *testRelay) savedEventCount() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.saved)
}

func newTestStore(t *testing.T) *appstore.SQLiteStore {
	t.Helper()

	st, err := appstore.Open(filepath.Join(t.TempDir(), "publisher.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return st
}

func seedMapping(t *testing.T, ctx context.Context, st *appstore.SQLiteStore, m appstore.Mapping) {
	t.Helper()
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
}

func createBareRepoFixture(t *testing.T, repositoriesDir, owner, repoName string) string {
	t.Helper()

	repoPath := filepath.Join(repositoriesDir, owner, repoName+".git")
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("create repo owner dir: %v", err)
	}
	runGit(t, "", "init", "--bare", repoPath)

	workDir := filepath.Join(t.TempDir(), "work")
	runGit(t, "", "init", "-b", "main", workDir)
	writeFile(t, filepath.Join(workDir, "README.md"), "# "+repoName+"\n")
	runGit(t, workDir, "add", "README.md")
	runGit(t, workDir, "-c", "user.name=Grasp Test", "-c", "user.email=grasp@example.invalid", "commit", "-m", "initial commit")
	runGit(t, workDir, "tag", "v1.0")
	runGit(t, workDir, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(workDir, "feature.txt"), "feature\n")
	runGit(t, workDir, "add", "feature.txt")
	runGit(t, workDir, "-c", "user.name=Grasp Test", "-c", "user.email=grasp@example.invalid", "commit", "-m", "feature commit")
	runGit(t, workDir, "remote", "add", "origin", repoPath)
	runGit(t, workDir, "push", "origin", "main", "feature", "--tags")
	runGit(t, "", "--git-dir", repoPath, "symbolic-ref", "HEAD", "refs/heads/main")

	return repoPath
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func publishDirectly(t *testing.T, ctx context.Context, relayURL string, ev nostr.Event) {
	t.Helper()

	r, err := nostr.RelayConnect(ctx, relayURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("connect relay for publish: %v", err)
	}
	defer r.Close()
	if err := r.Publish(ctx, ev); err != nil {
		t.Fatalf("publish direct event: %v", err)
	}
}

func assertRefTag(t *testing.T, ev *nostr.Event, key, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("test expected non-empty value for %s", key)
	}
	got, ok := firstVal(ev, key)
	if !ok {
		t.Fatalf("missing tag %q", key)
	}
	if got != want {
		t.Fatalf("tag %q = %q, want %q", key, got, want)
	}
}

func assertSameEvent(t *testing.T, want, got *nostr.Event) {
	t.Helper()
	if want.ID != got.ID || want.PubKey != got.PubKey || want.CreatedAt != got.CreatedAt || want.Kind != got.Kind || want.Content != got.Content || want.Sig != got.Sig {
		t.Fatalf("event mismatch\nwant: %+v\n got: %+v", want, got)
	}
	if !reflect.DeepEqual(want.Tags, got.Tags) {
		t.Fatalf("event tags mismatch\nwant: %#v\n got: %#v", want.Tags, got.Tags)
	}
}

func cloneEvent(ev *nostr.Event) *nostr.Event {
	if ev == nil {
		return nil
	}
	clone := *ev
	clone.Tags = make(nostr.Tags, len(ev.Tags))
	for i, tag := range ev.Tags {
		clone.Tags[i] = append(nostr.Tag(nil), tag...)
	}
	return &clone
}

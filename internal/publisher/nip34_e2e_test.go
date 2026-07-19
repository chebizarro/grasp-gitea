// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fiatjaf/eventstore/slicestore"
	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestOutboundNIP34AnnouncementAndStateEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relayServer := khatru.NewRelay()
	relayStore := slicestore.SliceStore{}
	relayStore.Init()
	relayServer.StoreEvent = append(relayServer.StoreEvent, relayStore.SaveEvent)
	relayServer.QueryEvents = append(relayServer.QueryEvents, relayStore.QueryEvents)
	relayServer.DeleteEvent = append(relayServer.DeleteEvent, relayStore.DeleteEvent)
	httpServer := httptest.NewServer(relayServer)
	t.Cleanup(httpServer.Close)
	relayURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	repositoriesDir := t.TempDir()
	repoPath := filepath.Join(repositoriesDir, "cascadia", "grasp-gitea.git")
	commitSHA := createBareRepository(t, repoPath)

	ownerKey := nostr.GeneratePrivateKey()
	ownerPubkey, err := nostr.GetPublicKey(ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	ownerNpub, err := nip19.EncodePublicKey(ownerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	announcement := &nostr.Event{
		Kind:      relay.KindRepositoryAnnouncement,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"d", "grasp-gitea"},
			{"name", "grasp-gitea"},
			{"clone", "https://git.example/cascadia/grasp-gitea.git"},
			{"relays", relayURL},
		},
	}
	if err := announcement.Sign(ownerKey); err != nil {
		t.Fatal(err)
	}
	announcementJSON, err := announcement.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(filepath.Join(t.TempDir(), "publisher.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.UpsertMapping(ctx, store.Mapping{
		Npub: ownerNpub, RepoID: "grasp-gitea", Pubkey: ownerPubkey,
		Owner: "cascadia", RepoName: "grasp-gitea", GiteaRepoID: 32,
		CloneURL: "https://git.example/cascadia/grasp-gitea.git", SourceEvent: announcement.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAnnouncementEvent(ctx, ownerNpub, "grasp-gitea", string(announcementJSON), announcement.ID); err != nil {
		t.Fatal(err)
	}

	bridgeKey := nostr.GeneratePrivateKey()
	bridgePubkey, err := nostr.GetPublicKey(bridgeKey)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewWithSigner(
		testExternalSigner{key: bridgeKey, pubkey: bridgePubkey}, db,
		[]string{relayURL}, repositoriesDir,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RepublishForGiteaRepo(ctx, 32); err != nil {
		t.Fatal(err)
	}

	client, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.QuerySync(ctx, nostr.Filter{
		Kinds: []int{relay.KindRepositoryAnnouncement, relay.KindRepositoryState},
		Tags:  nostr.TagMap{"d": []string{"grasp-gitea"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("relay returned %d fp-32 events, want 2", len(events))
	}

	var gotAnnouncement, gotState *nostr.Event
	for _, event := range events {
		if err := nostrverify.ValidateEventIDAndSignature(event); err != nil {
			t.Fatalf("independent verification failed for kind %d: %v", event.Kind, err)
		}
		switch event.Kind {
		case relay.KindRepositoryAnnouncement:
			gotAnnouncement = event
		case relay.KindRepositoryState:
			gotState = event
		}
	}
	if gotAnnouncement == nil || gotState == nil {
		t.Fatalf("missing event kinds: announcement=%t state=%t", gotAnnouncement != nil, gotState != nil)
	}
	if gotAnnouncement.ID != announcement.ID || gotAnnouncement.PubKey != ownerPubkey {
		t.Fatal("30617 was not republished verbatim with owner authority")
	}
	assertEventTag(t, gotAnnouncement, "d", "grasp-gitea")
	assertEventTag(t, gotAnnouncement, "clone", "https://git.example/cascadia/grasp-gitea.git")
	if gotState.PubKey != bridgePubkey {
		t.Fatal("30618 was not signed by the configured bridge signer")
	}
	assertEventTag(t, gotState, "d", "grasp-gitea")
	assertEventTag(t, gotState, "p", ownerPubkey)
	assertEventTag(t, gotState, "refs/heads/main", commitSHA)

	t.Logf("EVIDENCE kind=30617 id=%s signer=%s signature=valid", gotAnnouncement.ID, gotAnnouncement.PubKey)
	t.Logf("EVIDENCE kind=30618 id=%s signer=%s owner=%s ref=refs/heads/main sha=%s signature=valid", gotState.ID, gotState.PubKey, ownerPubkey, commitSHA)
}

func createBareRepository(t *testing.T, repoPath string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, nil, "init", "--bare", repoPath)
	emptyTree := runGit(t, nil, "--git-dir", repoPath, "hash-object", "-t", "tree", "--stdin", "-w")
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=fp-32", "GIT_AUTHOR_EMAIL=fp-32@example.invalid", "GIT_AUTHOR_DATE=2000-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=fp-32", "GIT_COMMITTER_EMAIL=fp-32@example.invalid", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	commitSHA := runGit(t, env, "--git-dir", repoPath, "commit-tree", emptyTree, "-m", "fp-32 e2e")
	runGit(t, nil, "--git-dir", repoPath, "update-ref", "refs/heads/main", commitSHA)
	runGit(t, nil, "--git-dir", repoPath, "symbolic-ref", "HEAD", "refs/heads/main")
	return commitSHA
}

func runGit(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func assertEventTag(t *testing.T, event *nostr.Event, key, want string) {
	t.Helper()
	tag := event.Tags.GetFirst([]string{key, ""})
	if tag == nil || len(*tag) < 2 || (*tag)[1] != want {
		t.Fatalf("kind %d tag %q mismatch: got %v want %q", event.Kind, key, tag, want)
	}
}

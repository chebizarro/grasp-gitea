package proactivesync

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
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
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip19"

	relaysub "github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// TestGRASP02LocalValidation is a local, network-real validation harness for
// the behavior advertised by GRASP-02. It uses actual WebSocket relays, SQLite
// persistence, and Git object/ref operations; only the one-hour wait is
// replaced by a manually fired ticker.
func TestGRASP02LocalValidation(t *testing.T) {
	if DefaultSyncInterval != time.Hour {
		t.Fatalf("default proactive sync interval = %v, want 1h", DefaultSyncInterval)
	}

	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	runGit(t, "", "init", "-b", "main", source)
	runGit(t, source, "config", "user.name", "GRASP-02 validation")
	runGit(t, source, "config", "user.email", "grasp02@example.invalid")
	stateSHA := commitFile(t, source, "state.txt", "historic state\n", "historic state")
	prSHA := commitFile(t, source, "pr.txt", "pull request tip\n", "pull request tip")

	ownerSK := nostr.Generate()
	maintainerSK := nostr.Generate()
	recursiveSK := nostr.Generate()
	repoID := "project"
	ownerNpub := nip19.EncodeNpub(ownerSK.Public())
	coord := fmt.Sprintf("%d:%s:%s", relaysub.KindRepositoryAnnouncement, ownerSK.Public().Hex(), repoID)

	brokenRelay := "ws://127.0.0.1:1"
	brokenClone := filepath.Join(root, "missing-source.git")
	ownerAnnouncement := signValidationEvent(t, ownerSK, relaysub.KindRepositoryAnnouncement, nostr.Tags{
		{"d", repoID},
		{"clone", brokenClone},
		{"clone", source},
		{"maintainers", maintainerSK.Public().Hex()},
	})
	maintainerAnnouncement := signValidationEvent(t, maintainerSK, relaysub.KindRepositoryAnnouncement, nostr.Tags{
		{"d", repoID},
		{"maintainers", recursiveSK.Public().Hex()},
	})
	historicState := signValidationEvent(t, recursiveSK, relaysub.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"refs/heads/main", stateSHA},
	})
	prEvent := signValidationEvent(t, ownerSK, relaysub.KindPROpen, nostr.Tags{
		{"a", coord},
		{"clone", brokenClone},
		{"clone", source},
		{"c", prSHA},
	})

	relayA, relayAURL, relayAQueries := newValidationRelay(t, []nostr.Event{ownerAnnouncement, prEvent})
	relayB, relayBURL, relayBQueries := newValidationRelay(t, []nostr.Event{maintainerAnnouncement, historicState})
	ownerAnnouncement.Tags = append(ownerAnnouncement.Tags, nostr.Tag{"relays", brokenRelay, relayAURL, relayBURL})
	resignValidationEvent(t, ownerSK, &ownerAnnouncement)
	// Replace the unsigned relay-less copy with the final cached/served event.
	relayA.validationReplaceEvents([]nostr.Event{ownerAnnouncement, prEvent})

	announcementJSON := mustEventJSON(t, ownerAnnouncement)
	dbPath := filepath.Join(root, "mappings.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open mapping store: %v", err)
	}
	mapping := store.Mapping{
		Npub:                  ownerNpub,
		RepoID:                repoID,
		Pubkey:                ownerSK.Public().Hex(),
		Owner:                 "alice",
		RepoName:              repoID,
		AnnouncedCloneURL:     source,
		AnnouncementEventJSON: announcementJSON,
	}
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatalf("persist mapping: %v", err)
	}
	if err := st.SetAnnouncementEvent(ctx, ownerNpub, repoID, announcementJSON, ownerAnnouncement.ID.Hex()); err != nil {
		t.Fatalf("persist cached announcement: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close mapping store before restart: %v", err)
	}

	repoPath := filepath.Join(root, "repositories", "alice", repoID+".git")
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("create repository parent: %v", err)
	}
	runGit(t, "", "init", "--bare", repoPath)

	// Reopen the persisted store and drive the scheduler's one-hour tick. This
	// proves the sweep has no in-memory prerequisite after process restart.
	restarted, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen mapping store: %v", err)
	}
	defer restarted.Close()
	persistedMappings, err := restarted.ListMappings(ctx)
	if err != nil || len(persistedMappings) != 1 {
		t.Fatalf("persisted mappings after restart = %d, err=%v, want 1", len(persistedMappings), err)
	}
	persisted := persistedMappings[0]
	cached, err := cachedAnnouncement(persisted)
	if err != nil || cached == nil {
		t.Fatalf("cached announcement after restart: event=%v err=%v", cached != nil, err)
	}
	if got := announcementRelayURLs(cached); len(got) != 3 {
		t.Fatalf("announcement relays after restart = %v, want 3", got)
	}
	persistedRepoPath := repoPathForMapping(filepath.Join(root, "repositories"), persisted)
	if _, err := os.Stat(persistedRepoPath); err != nil {
		t.Fatalf("persisted repository path %q: %v", persistedRepoPath, err)
	}
	svc := New(filepath.Join(root, "repositories"), restarted, validationLogger())
	svc.git = validationGitRunner{}
	ticker := &fakeTicker{ch: make(chan time.Time, 1)}
	intervalSeen := make(chan time.Duration, 1)
	svc.newTicker = func(interval time.Duration) syncTicker {
		intervalSeen <- interval
		return ticker
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	t.Cleanup(cancelRun)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		svc.Run(runCtx, DefaultSyncInterval)
	}()
	if got := <-intervalSeen; got != time.Hour {
		t.Fatalf("scheduler interval = %v, want 1h", got)
	}
	ticker.ch <- time.Now()
	waitFor(t, "scheduled historic queries", func() bool {
		return relayAQueries.Load() > 0 || relayBQueries.Load() > 0
	})
	waitForRef(t, repoPath, "refs/heads/main", stateSHA)
	waitForRef(t, repoPath, "refs/nostr/"+prEvent.ID.Hex(), prSHA)
	cancelRun()
	<-runDone
	if !ticker.stopped {
		t.Fatal("hourly scheduler did not stop its ticker")
	}
	if relayAQueries.Load() == 0 || relayBQueries.Load() == 0 {
		t.Fatalf("historic sweep did not query every healthy announcement relay: relayA=%d relayB=%d", relayAQueries.Load(), relayBQueries.Load())
	}

	// Subscribe to both announcement relays (plus a broken source) and prove
	// each healthy relay can independently deliver a live recursive-maintainer
	// state update without the broken relay preventing progress.
	liveCtx, cancelLive := context.WithCancel(ctx)
	t.Cleanup(cancelLive)
	subscriber := relaysub.New([]string{brokenRelay, relayAURL, relayBURL}, func(ctx context.Context, ev *nostr.Event, _ string) error {
		return svc.HandleStateEvent(ctx, ev)
	}, validationLogger())
	subscriber.Run(liveCtx)
	waitFor(t, "live subscriptions", func() bool {
		_, listenersA := relayA.Stats()
		_, listenersB := relayB.Stats()
		return listenersA > 0 && listenersB > 0
	})

	liveASHA := commitFile(t, source, "live-a.txt", "relay A live update\n", "relay A live update")
	fetchObject(t, repoPath, source, liveASHA)
	liveA := signValidationEvent(t, recursiveSK, relaysub.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"refs/heads/main", liveASHA},
	})
	if _, err := relayA.AddEvent(ctx, liveA); err != nil {
		t.Fatalf("publish live state on relay A: %v", err)
	}
	relayA.ForceBroadcastEvent(liveA)
	waitForRef(t, repoPath, "refs/heads/main", liveASHA)

	liveBSHA := commitFile(t, source, "live-b.txt", "relay B live update\n", "relay B live update")
	fetchObject(t, repoPath, source, liveBSHA)
	liveB := signValidationEvent(t, recursiveSK, relaysub.KindRepositoryState, nostr.Tags{
		{"d", repoID},
		{"refs/heads/main", liveBSHA},
	})
	if _, err := relayB.AddEvent(ctx, liveB); err != nil {
		t.Fatalf("publish live state on relay B: %v", err)
	}
	relayB.ForceBroadcastEvent(liveB)
	waitForRef(t, repoPath, "refs/heads/main", liveBSHA)

	cancelLive()
	subscriber.Wait()
}

type validationRelay struct {
	*khatru.Relay
	mu     sync.RWMutex
	events []nostr.Event
}

func newValidationRelay(t *testing.T, initial []nostr.Event) (*validationRelay, string, *atomic.Int64) {
	t.Helper()
	vr := &validationRelay{Relay: khatru.NewRelay(), events: append([]nostr.Event(nil), initial...)}
	queries := &atomic.Int64{}
	vr.StoreEvent = func(_ context.Context, event nostr.Event) error {
		vr.mu.Lock()
		defer vr.mu.Unlock()
		vr.events = append(vr.events, event)
		return nil
	}
	vr.ReplaceEvent = vr.StoreEvent
	vr.QueryStored = func(_ context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		queries.Add(1)
		vr.mu.RLock()
		events := append([]nostr.Event(nil), vr.events...)
		vr.mu.RUnlock()
		return func(yield func(nostr.Event) bool) {
			yielded := 0
			for i := len(events) - 1; i >= 0; i-- {
				if !filter.Matches(events[i]) {
					continue
				}
				if filter.Limit > 0 && yielded >= filter.Limit {
					return
				}
				yielded++
				if !yield(events[i]) {
					return
				}
			}
		}
	}
	server := httptest.NewServer(vr)
	t.Cleanup(server.Close)
	return vr, "ws" + strings.TrimPrefix(server.URL, "http"), queries
}

func (r *validationRelay) validationReplaceEvents(events []nostr.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append([]nostr.Event(nil), events...)
}

type validationGitRunner struct{ execGitRunner }

func (validationGitRunner) Fetch(ctx context.Context, repoPath string, remoteURL string, refspecs []string) error {
	args := []string{"--git-dir", repoPath, "fetch", "--no-tags", remoteURL}
	args = append(args, refspecs...)
	if out, err := exec.CommandContext(ctx, "git", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("git fetch failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func validationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func signValidationEvent(t *testing.T, sk nostr.SecretKey, kind int, tags nostr.Tags) nostr.Event {
	t.Helper()
	ev := nostr.Event{
		PubKey:    sk.Public(),
		CreatedAt: nostr.Now(),
		Kind:      nostr.Kind(kind),
		Tags:      tags,
	}
	resignValidationEvent(t, sk, &ev)
	return ev
}

func resignValidationEvent(t *testing.T, sk nostr.SecretKey, ev *nostr.Event) {
	t.Helper()
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign validation event: %v", err)
	}
}

func mustEventJSON(t *testing.T, ev nostr.Event) string {
	t.Helper()
	data, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(data)
}

func commitFile(t *testing.T, repo, name, content, message string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	runGit(t, repo, "add", name)
	runGit(t, repo, "commit", "-m", message)
	return strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
}

func fetchObject(t *testing.T, repoPath, source, sha string) {
	t.Helper()
	runGit(t, "", "--git-dir", repoPath, "fetch", "--no-tags", source, sha)
}

func waitForRef(t *testing.T, repoPath, ref, want string) {
	t.Helper()
	waitFor(t, ref, func() bool {
		cmd := exec.Command("git", "--git-dir", repoPath, "rev-parse", "--verify", ref)
		out, err := cmd.Output()
		return err == nil && strings.TrimSpace(string(out)) == want
	})
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out)
}

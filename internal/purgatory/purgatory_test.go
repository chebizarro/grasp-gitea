package purgatory

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/store"
)

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func openTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "purgatory.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

type fakeObjects struct {
	mu   sync.Mutex
	shas map[string]bool
}

func (f *fakeObjects) exists(_ context.Context, _ string, sha string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shas[sha]
}

func (f *fakeObjects) add(sha string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shas[sha] = true
}

func stateEvent(t *testing.T, sha string) *nostr.Event {
	t.Helper()
	sk := nostr.Generate()
	ev := nostr.Event{
		Kind:      30618,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"d", "repo"}, {"refs/heads/main", sha}},
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &ev
}

func TestHoldReleasesWhenObjectsArrive(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	objects := &fakeObjects{shas: map[string]bool{}}

	var mu sync.Mutex
	var released []string
	release := func(_ context.Context, ev nostr.Event) error {
		mu.Lock()
		defer mu.Unlock()
		released = append(released, ev.ID.Hex())
		return nil
	}

	svc := New(st, release, testLogger(), WithObjectChecker(objects.exists))
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev := stateEvent(t, sha)

	held, err := svc.Hold(ctx, ev, "/repos/o/r.git")
	if err != nil || !held {
		t.Fatalf("expected event to be held, held=%v err=%v", held, err)
	}

	// Not released while data is missing.
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(released) != 0 {
		t.Fatalf("expected no release before git data arrives")
	}

	// Atomic release once objects arrive.
	objects.add(sha)
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(released) != 1 || released[0] != ev.ID.Hex() {
		t.Fatalf("expected release of %s, got %v", ev.ID.Hex(), released)
	}
	if remaining, _ := st.ListPurgatoryEvents(ctx); len(remaining) != 0 {
		t.Fatalf("expected purgatory emptied after release")
	}

	// Event with data already present is not held at all.
	present := stateEvent(t, sha)
	if held, err := svc.Hold(ctx, present, "/repos/o/r.git"); err != nil || held {
		t.Fatalf("expected event with present objects not to be held, held=%v err=%v", held, err)
	}
}

func TestExpiryAfterTTL(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	objects := &fakeObjects{shas: map[string]bool{}}

	current := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return current }
	released := 0
	svc := New(st, func(context.Context, nostr.Event) error { released++; return nil },
		testLogger(), WithObjectChecker(objects.exists), WithClock(clock), WithTTL(30*time.Minute))

	ev := stateEvent(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if held, err := svc.Hold(ctx, ev, "/repos/o/r.git"); err != nil || !held {
		t.Fatalf("hold: held=%v err=%v", held, err)
	}

	current = current.Add(31 * time.Minute)
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if released != 0 {
		t.Fatalf("expired event must not be released")
	}
	if remaining, _ := st.ListPurgatoryEvents(ctx); len(remaining) != 0 {
		t.Fatalf("expected expired event discarded")
	}
}

func TestRestartSafety(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "purgatory.db")
	objects := &fakeObjects{shas: map[string]bool{}}
	sha := "cccccccccccccccccccccccccccccccccccccccc"
	ev := stateEvent(t, sha)

	st1, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc1 := New(st1, func(context.Context, nostr.Event) error { return nil }, testLogger(), WithObjectChecker(objects.exists))
	if held, err := svc1.Hold(ctx, ev, "/repos/o/r.git"); err != nil || !held {
		t.Fatalf("hold: %v", err)
	}
	_ = st1.Close()

	// New process: backlog survives, release happens after data arrives.
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	released := 0
	svc2 := New(st2, func(context.Context, nostr.Event) error { released++; return nil }, testLogger(), WithObjectChecker(objects.exists))
	objects.add(sha)
	if err := svc2.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if released != 1 {
		t.Fatalf("expected event released after restart, got %d", released)
	}
}

func TestRequiredSHAsPerKind(t *testing.T) {
	sha := "dddddddddddddddddddddddddddddddddddddddd"
	state := stateEvent(t, sha)
	if got := RequiredSHAs(state); len(got) != 1 || got[0] != sha {
		t.Fatalf("state event SHAs = %v", got)
	}

	pr := &nostr.Event{Kind: 1618, Tags: nostr.Tags{{"a", "30617:pk:repo"}, {"c", sha}}}
	if got := RequiredSHAs(pr); len(got) != 1 || got[0] != sha {
		t.Fatalf("pr event SHAs = %v", got)
	}

	announcement := &nostr.Event{Kind: 30617, Tags: nostr.Tags{{"d", "repo"}}}
	if got := RequiredSHAs(announcement); len(got) != 0 {
		t.Fatalf("announcement should require no objects, got %v", got)
	}
}

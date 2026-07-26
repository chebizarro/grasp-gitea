package nostrauthz_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
	"github.com/sharegap/grasp-gitea/internal/outbox"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type trackingClock struct {
	now time.Time
}

func (c trackingClock) Now() time.Time { return c.now }
func (c trackingClock) NewTicker(time.Duration) outbox.Ticker {
	return trackingTicker{ch: make(chan time.Time)}
}

type trackingTicker struct {
	ch chan time.Time
}

func (t trackingTicker) C() <-chan time.Time { return t.ch }
func (trackingTicker) Stop()                 {}

type grantSigner struct {
	key nostr.SecretKey
}

func (s grantSigner) SignWithGrant(_ context.Context, _ string, ev *nostr.Event) error {
	return ev.Sign(s.key)
}

type acceptingPublisher struct{}

func (acceptingPublisher) PublishSigned(context.Context, *nostr.Event) error { return nil }

func TestOwnerSignedOutboxAdvancesMappingStateDigest(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "outbox-tracking.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	owner := nostr.Generate()
	npub := nip19.EncodeNpub(owner.Public())
	mapping := store.Mapping{
		Npub:        npub,
		RepoID:      "project",
		Pubkey:      owner.Public().Hex(),
		Owner:       "alice",
		RepoName:    "project",
		GiteaRepoID: 42,
	}
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatalf("upsert mapping: %v", err)
	}

	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	cfg := outbox.DefaultConfig()
	cfg.BatchSize = 1
	worker := outbox.New(
		st,
		grantSigner{key: owner},
		acceptingPublisher{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		outbox.WithClock(trackingClock{now: now}),
		outbox.WithConfig(cfg),
	)

	branches := map[string]string{"main": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	unsigned := nostr.Event{
		Kind: nostr.KindRepositoryState,
		Tags: nostr.Tags{
			{"d", "project"},
			{"refs/heads/main", branches["main"]},
			{"HEAD", "ref: refs/heads/main"},
		},
	}
	if err := worker.Enqueue(ctx, int(nostr.KindRepositoryState), owner.Public().Hex(), "repo:alice/project", &unsigned, "state-tracking"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	worker.DrainOnce(ctx)

	got, err := st.GetMapping(ctx, npub, "project")
	if err != nil {
		t.Fatalf("get mapping: %v", err)
	}
	wantDigest := nostrstate.RepositoryStateDigest("main", branches, map[string]string{})
	if got.LastStateDigest != wantDigest {
		t.Fatalf("last_state_digest = %q, want %q", got.LastStateDigest, wantDigest)
	}
	if got.LastStateEventID == "" || !got.LastStatePublishedAt.Equal(now) {
		t.Fatalf("publication tracking incomplete: event=%q at=%s", got.LastStateEventID, got.LastStatePublishedAt)
	}
}

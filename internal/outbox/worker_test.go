// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package outbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) NewTicker(time.Duration) Ticker {
	return fakeTicker{ch: make(chan time.Time)}
}
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type fakeTicker struct {
	ch chan time.Time
}

func (t fakeTicker) C() <-chan time.Time { return t.ch }
func (t fakeTicker) Stop()               {}

type signCall struct {
	pubkey string
	event  nostr.Event
}

type fakeSigner struct {
	err   error
	calls []signCall
	ids   []string
}

func (s *fakeSigner) SignWithGrant(_ context.Context, pubkey string, ev *nostr.Event) error {
	s.calls = append(s.calls, signCall{pubkey: pubkey, event: *ev})
	if s.err != nil {
		return s.err
	}
	id := fmt.Sprintf("signed-event-%d", len(s.calls))
	if idx := len(s.calls) - 1; idx < len(s.ids) && s.ids[idx] != "" {
		id = s.ids[idx]
	}
	ev.ID = fakeEventID(id)
	ev.Sig = [64]byte{1}
	return nil
}

type fakePublisher struct {
	err       error
	published []nostr.Event
}

func (p *fakePublisher) PublishSigned(_ context.Context, ev *nostr.Event) error {
	if p.err != nil {
		return p.err
	}
	p.published = append(p.published, *ev)
	return nil
}

func TestDrainOnceSuccessSignsPublishesAndMarksPublished(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clock := &fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
	signer := &fakeSigner{ids: []string{"event-success-id"}}
	publisher := &fakePublisher{}
	worker := New(st, signer, publisher, testLogger(), WithClock(clock), WithConfig(testConfig()))

	unsigned := &nostr.Event{Content: "queued content", Tags: nostr.Tags{{"d", "repo"}}}
	if err := worker.Enqueue(ctx, 30617, testAuthorPubkey, "repo:owner/name", unsigned, "success-key"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	worker.DrainOnce(ctx)

	if len(signer.calls) != 1 {
		t.Fatalf("expected 1 signer call, got %d", len(signer.calls))
	}
	if signer.calls[0].pubkey != testAuthorPubkey || signer.calls[0].event.PubKey.Hex() != testAuthorPubkey {
		t.Fatalf("signer got wrong pubkey: call=%q event=%q", signer.calls[0].pubkey, signer.calls[0].event.PubKey)
	}
	if signer.calls[0].event.Kind != 30617 {
		t.Fatalf("signer got kind %d", signer.calls[0].event.Kind)
	}
	if len(publisher.published) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(publisher.published))
	}
	if publisher.published[0].ID != fakeEventID("event-success-id") {
		t.Fatalf("published event ID = %q", publisher.published[0].ID.Hex())
	}

	rows := recentOutboundEvents(t, st)
	if len(rows) != 1 {
		t.Fatalf("expected 1 outbound row, got %d", len(rows))
	}
	row := rows[0]
	if row.State != store.OutboundStatePublished {
		t.Fatalf("state = %q, want published", row.State)
	}
	if row.PublishedEventID != fakeEventID("event-success-id").Hex() {
		t.Fatalf("published_event_id = %q", row.PublishedEventID)
	}
	if row.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0", row.Attempts)
	}
}

func TestDrainOnceRetryBackoffAndMaxAttemptsDeadLetter(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clock := &fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
	signer := &fakeSigner{err: errors.New("signer offline")}
	publisher := &fakePublisher{}
	cfg := testConfig()
	cfg.InitialBackoff = time.Minute
	cfg.MaxBackoff = 10 * time.Minute
	cfg.MaxAttempts = 3
	cfg.MaxAge = time.Hour
	worker := New(st, signer, publisher, testLogger(), WithClock(clock), WithConfig(cfg))

	if err := worker.Enqueue(ctx, 30617, testAuthorPubkey, "repo", &nostr.Event{Content: "retry me"}, "retry-key"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	worker.DrainOnce(ctx)
	row := onlyOutboundEvent(t, st)
	if row.State != store.OutboundStatePending {
		t.Fatalf("after first failure state = %q", row.State)
	}
	if row.Attempts != 1 {
		t.Fatalf("after first failure attempts = %d", row.Attempts)
	}
	wantNext := clock.Now().Add(time.Minute)
	if !row.NextAttemptAt.Equal(wantNext) {
		t.Fatalf("after first failure next_attempt_at = %s, want %s", row.NextAttemptAt, wantNext)
	}

	worker.DrainOnce(ctx)
	if len(signer.calls) != 1 {
		t.Fatalf("not-yet-due row was signed again; calls = %d", len(signer.calls))
	}

	clock.Advance(time.Minute)
	worker.DrainOnce(ctx)
	row = onlyOutboundEvent(t, st)
	if row.State != store.OutboundStatePending {
		t.Fatalf("after second failure state = %q", row.State)
	}
	if row.Attempts != 2 {
		t.Fatalf("after second failure attempts = %d", row.Attempts)
	}
	wantNext = clock.Now().Add(2 * time.Minute)
	if !row.NextAttemptAt.Equal(wantNext) {
		t.Fatalf("after second failure next_attempt_at = %s, want %s", row.NextAttemptAt, wantNext)
	}

	clock.Advance(2 * time.Minute)
	worker.DrainOnce(ctx)
	row = onlyOutboundEvent(t, st)
	if row.State != store.OutboundStateDead {
		t.Fatalf("after max attempts state = %q, want dead", row.State)
	}
	if row.Attempts != 3 {
		t.Fatalf("after max attempts attempts = %d", row.Attempts)
	}
	if row.LastError != "signer offline" {
		t.Fatalf("last_error = %q", row.LastError)
	}
	if len(publisher.published) != 0 {
		t.Fatalf("published on signer failure: %d events", len(publisher.published))
	}
}

func TestDrainOnceMaxAgeDeadLetter(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clock := &fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
	signer := &fakeSigner{err: errors.New("signer offline")}
	worker := New(st, signer, &fakePublisher{}, testLogger(), WithClock(clock), WithConfig(testConfig()))

	if err := worker.Enqueue(ctx, 30617, testAuthorPubkey, "repo", &nostr.Event{Content: "expire me"}, "ttl-key"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	clock.Advance(testConfig().MaxAge)

	worker.DrainOnce(ctx)

	row := onlyOutboundEvent(t, st)
	if row.State != store.OutboundStateDead {
		t.Fatalf("state = %q, want dead", row.State)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", row.Attempts)
	}
}

func TestEnqueueDedupePublishesOnlyOnce(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clock := &fakeClock{now: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
	signer := &fakeSigner{ids: []string{"deduped-event"}}
	publisher := &fakePublisher{}
	worker := New(st, signer, publisher, testLogger(), WithClock(clock), WithConfig(testConfig()))

	for i := 0; i < 2; i++ {
		if err := worker.Enqueue(ctx, 30617, testAuthorPubkey, "repo", &nostr.Event{Content: fmt.Sprintf("content-%d", i)}, "same-key"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	rows := recentOutboundEvents(t, st)
	if len(rows) != 1 {
		t.Fatalf("dedupe created %d rows, want 1", len(rows))
	}

	worker.DrainOnce(ctx)
	worker.DrainOnce(ctx)

	if len(signer.calls) != 1 {
		t.Fatalf("signer calls = %d, want 1", len(signer.calls))
	}
	if len(publisher.published) != 1 {
		t.Fatalf("publisher calls = %d, want 1", len(publisher.published))
	}
	row := onlyOutboundEvent(t, st)
	if row.State != store.OutboundStatePublished || row.PublishedEventID != fakeEventID("deduped-event").Hex() {
		t.Fatalf("row after drain = state %q published_event_id %q", row.State, row.PublishedEventID)
	}
}

func TestPublishedRowsAreNeverRepublished(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	inserted, err := st.EnqueueOutboundEvent(ctx, store.OutboundEvent{
		DedupeKey:        "already-published",
		Kind:             30617,
		AuthorPubkey:     "author-pubkey",
		UnsignedJSON:     `{"content":"already done"}`,
		State:            store.OutboundStatePublished,
		PublishedEventID: "existing-event-id",
	}, now)
	if err != nil {
		t.Fatalf("insert published row: %v", err)
	}
	if !inserted {
		t.Fatal("published row was not inserted")
	}

	signer := &fakeSigner{ids: []string{"should-not-happen"}}
	publisher := &fakePublisher{}
	worker := New(st, signer, publisher, testLogger(), WithClock(&fakeClock{now: now}), WithConfig(testConfig()))

	worker.DrainOnce(ctx)

	if len(signer.calls) != 0 {
		t.Fatalf("published row was signed %d times", len(signer.calls))
	}
	if len(publisher.published) != 0 {
		t.Fatalf("published row was republished %d times", len(publisher.published))
	}
	row := onlyOutboundEvent(t, st)
	if row.State != store.OutboundStatePublished || row.PublishedEventID != "existing-event-id" {
		t.Fatalf("row changed unexpectedly: state=%q published_event_id=%q", row.State, row.PublishedEventID)
	}
}

func openTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Interval = time.Hour
	cfg.BatchSize = 10
	cfg.ClaimLease = time.Minute
	cfg.InitialBackoff = time.Minute
	cfg.MaxBackoff = 10 * time.Minute
	cfg.MaxAttempts = 3
	cfg.MaxAge = time.Hour
	cfg.SignTimeout = time.Second
	cfg.PublishTimeout = time.Second
	return cfg
}

func recentOutboundEvents(t *testing.T, st *store.SQLiteStore) []store.OutboundEvent {
	t.Helper()
	rows, err := st.RecentOutboundEvents(context.Background(), 100)
	if err != nil {
		t.Fatalf("recent outbound events: %v", err)
	}
	return rows
}

func onlyOutboundEvent(t *testing.T, st *store.SQLiteStore) store.OutboundEvent {
	t.Helper()
	rows := recentOutboundEvents(t, st)
	if len(rows) != 1 {
		t.Fatalf("got %d outbound rows, want 1", len(rows))
	}
	return rows[0]
}

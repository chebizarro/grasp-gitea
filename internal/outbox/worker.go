// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nostrstate"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// Signer signs an event as the requested author pubkey using a stored grant.
type Signer interface {
	SignWithGrant(ctx context.Context, pubkey string, evt *nostr.Event) error
}

// Publisher publishes an already-signed event to relays. It must not mutate or sign the event.
type Publisher interface {
	PublishSigned(ctx context.Context, evt *nostr.Event) error
}

// Clock makes the worker deterministic in tests.
type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker is the subset of time.Ticker used by Worker.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }
func (realClock) NewTicker(d time.Duration) Ticker {
	return realTicker{Ticker: time.NewTicker(d)}
}

type realTicker struct{ *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.Ticker.C }

// Store is the persistent queue dependency used by Worker.
type Store interface {
	EnqueueOutboundEvent(ctx context.Context, ev store.OutboundEvent, now time.Time) (bool, error)
	ClaimDueOutboundEvents(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]store.OutboundEvent, error)
	MarkOutboundPublished(ctx context.Context, id int64, publishedEventID string) error
	RecordStatePublished(ctx context.Context, npub, repoID, digest, stateEventID string, at time.Time) error
	MarkOutboundRetry(ctx context.Context, id int64, nextAttemptAt time.Time, lastErr string) error
	MarkOutboundDead(ctx context.Context, id int64, lastErr string) error
	OutboundQueueCounts(ctx context.Context) (store.OutboundQueueCounts, error)
}

// Config controls queue draining behavior.
type Config struct {
	Interval       time.Duration
	BatchSize      int
	ClaimLease     time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxAttempts    int
	MaxAge         time.Duration
	SignTimeout    time.Duration
	PublishTimeout time.Duration
}

// DefaultConfig returns conservative production defaults.
func DefaultConfig() Config {
	return Config{
		Interval:       5 * time.Second,
		BatchSize:      25,
		ClaimLease:     2 * time.Minute,
		InitialBackoff: 30 * time.Second,
		MaxBackoff:     30 * time.Minute,
		MaxAttempts:    12,
		MaxAge:         24 * time.Hour,
		SignTimeout:    30 * time.Second,
		PublishTimeout: 30 * time.Second,
	}
}

// Worker drains persisted unsigned events by signing them with user grants and publishing them.
type Worker struct {
	store     Store
	signer    Signer
	publisher Publisher
	clock     Clock
	logger    *slog.Logger
	cfg       Config
}

// New constructs an outbound signing queue worker.
func New(st Store, signer Signer, publisher Publisher, logger *slog.Logger, opts ...Option) *Worker {
	w := &Worker{
		store:     st,
		signer:    signer,
		publisher: publisher,
		clock:     realClock{},
		logger:    logger,
		cfg:       DefaultConfig(),
	}
	if w.logger == nil {
		w.logger = slog.Default()
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

type Option func(*Worker)

func WithClock(clock Clock) Option {
	return func(w *Worker) {
		if clock != nil {
			w.clock = clock
		}
	}
}

func WithConfig(cfg Config) Option {
	return func(w *Worker) {
		if cfg.Interval > 0 {
			w.cfg.Interval = cfg.Interval
		}
		if cfg.BatchSize > 0 {
			w.cfg.BatchSize = cfg.BatchSize
		}
		if cfg.ClaimLease > 0 {
			w.cfg.ClaimLease = cfg.ClaimLease
		}
		if cfg.InitialBackoff > 0 {
			w.cfg.InitialBackoff = cfg.InitialBackoff
		}
		if cfg.MaxBackoff > 0 {
			w.cfg.MaxBackoff = cfg.MaxBackoff
		}
		if cfg.MaxAttempts > 0 {
			w.cfg.MaxAttempts = cfg.MaxAttempts
		}
		if cfg.MaxAge > 0 {
			w.cfg.MaxAge = cfg.MaxAge
		}
		if cfg.SignTimeout > 0 {
			w.cfg.SignTimeout = cfg.SignTimeout
		}
		if cfg.PublishTimeout > 0 {
			w.cfg.PublishTimeout = cfg.PublishTimeout
		}
	}
}

// Enqueue persists an unsigned event for asynchronous signing and publication.
// Duplicate dedupe keys are ignored.
func (w *Worker) Enqueue(ctx context.Context, kind int, authorPubkey string, scope string, unsignedEvent *nostr.Event, dedupeKey string) error {
	if w == nil || w.store == nil {
		return fmt.Errorf("outbox store is required")
	}
	if unsignedEvent == nil {
		return fmt.Errorf("unsigned event is required")
	}
	dedupeKey = strings.TrimSpace(dedupeKey)
	if dedupeKey == "" {
		return fmt.Errorf("dedupe key is required")
	}
	authorPubkey = strings.TrimSpace(authorPubkey)
	if authorPubkey == "" {
		return fmt.Errorf("author pubkey is required")
	}
	authorPK, err := nostr.PubKeyFromHex(authorPubkey)
	if err != nil {
		return fmt.Errorf("invalid author pubkey %q: %w", authorPubkey, err)
	}
	unsignedEvent.Kind = nostr.Kind(kind)
	unsignedEvent.PubKey = authorPK
	b, err := json.Marshal(unsignedEvent)
	if err != nil {
		return fmt.Errorf("marshal unsigned event: %w", err)
	}
	inserted, err := w.store.EnqueueOutboundEvent(ctx, store.OutboundEvent{
		DedupeKey:    dedupeKey,
		Kind:         kind,
		AuthorPubkey: authorPubkey,
		Scope:        scope,
		UnsignedJSON: string(b),
	}, w.clock.Now())
	if err != nil {
		return err
	}
	if inserted {
		w.refreshDepth(ctx)
	}
	return nil
}

// Run drains due outbound rows until ctx is canceled.
func (w *Worker) Run(ctx context.Context) {
	if w == nil {
		return
	}
	w.DrainOnce(ctx)
	ticker := w.clock.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			w.DrainOnce(ctx)
		}
	}
}

// DrainOnce claims and processes one batch of due rows. It is exported for deterministic tests.
func (w *Worker) DrainOnce(ctx context.Context) {
	if w.store == nil || w.signer == nil || w.publisher == nil {
		if w.logger != nil {
			w.logger.Warn("outbox worker missing dependency")
		}
		return
	}
	now := w.clock.Now()
	rows, err := w.store.ClaimDueOutboundEvents(ctx, now, w.cfg.BatchSize, w.cfg.ClaimLease)
	if err != nil {
		w.logger.Error("claim outbound events failed", "error", err)
		return
	}
	for _, row := range rows {
		if err := w.process(ctx, row); err != nil {
			w.logger.Warn("outbound event processing failed", "id", row.ID, "dedupe_key", row.DedupeKey, "error", err)
		}
	}
	w.refreshDepth(ctx)
}

func (w *Worker) process(ctx context.Context, row store.OutboundEvent) error {
	var ev nostr.Event
	if err := json.Unmarshal([]byte(row.UnsignedJSON), &ev); err != nil {
		return w.fail(ctx, row, fmt.Errorf("unmarshal unsigned event: %w", err))
	}
	authorPK, err := nostr.PubKeyFromHex(row.AuthorPubkey)
	if err != nil {
		return w.fail(ctx, row, fmt.Errorf("invalid author pubkey %q: %w", row.AuthorPubkey, err))
	}
	ev.Kind = nostr.Kind(row.Kind)
	ev.PubKey = authorPK

	var stateNpub, stateRepoID, stateDigest string
	if ev.Kind == nostr.KindRepositoryState {
		d := ev.Tags.Find("d")
		if d == nil || len(d) < 2 || strings.TrimSpace(d[1]) == "" {
			return w.fail(ctx, row, fmt.Errorf("owner-signed repository state missing d tag"))
		}
		stateRepoID = strings.TrimSpace(d[1])
		stateDigest, err = nostrstate.EventStateDigest(&ev)
		if err != nil {
			return w.fail(ctx, row, fmt.Errorf("digest owner-signed repository state: %w", err))
		}
		stateNpub = nip19.EncodeNpub(authorPK)
	}

	signCtx, signCancel := context.WithTimeout(ctx, w.cfg.SignTimeout)
	err = w.signer.SignWithGrant(signCtx, row.AuthorPubkey, &ev)
	signCancel()
	if err != nil {
		return w.fail(ctx, row, err)
	}

	publishCtx, publishCancel := context.WithTimeout(ctx, w.cfg.PublishTimeout)
	err = w.publisher.PublishSigned(publishCtx, &ev)
	publishCancel()
	if err != nil {
		return w.fail(ctx, row, err)
	}

	if ev.Kind == nostr.KindRepositoryState {
		if err := w.store.RecordStatePublished(ctx, stateNpub, stateRepoID, stateDigest, ev.ID.Hex(), w.clock.Now()); err != nil {
			return fmt.Errorf("record owner-signed state publication: %w", err)
		}
	}
	if err := w.store.MarkOutboundPublished(ctx, row.ID, ev.ID.Hex()); err != nil {
		return fmt.Errorf("mark outbound published: %w", err)
	}
	metrics.IncOutboxPublished()
	return nil
}

func (w *Worker) fail(ctx context.Context, row store.OutboundEvent, cause error) error {
	lastErr := truncateError(cause)
	now := w.clock.Now()
	if w.shouldDeadLetter(row, now) {
		if err := w.store.MarkOutboundDead(ctx, row.ID, lastErr); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("mark outbound dead: %w", err)
		}
		metrics.IncOutboxDeadLettered()
		return cause
	}
	next := now.Add(w.backoff(row.Attempts + 1))
	if err := w.store.MarkOutboundRetry(ctx, row.ID, next, lastErr); err != nil {
		return fmt.Errorf("mark outbound retry: %w", err)
	}
	metrics.IncOutboxRetried()
	return cause
}

func (w *Worker) shouldDeadLetter(row store.OutboundEvent, now time.Time) bool {
	if w.cfg.MaxAttempts > 0 && row.Attempts+1 >= w.cfg.MaxAttempts {
		return true
	}
	if w.cfg.MaxAge > 0 && !row.CreatedAt.IsZero() && now.Sub(row.CreatedAt) >= w.cfg.MaxAge {
		return true
	}
	return false
}

func (w *Worker) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := w.cfg.InitialBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= w.cfg.MaxBackoff {
			return w.cfg.MaxBackoff
		}
	}
	return d
}

func (w *Worker) refreshDepth(ctx context.Context) {
	counts, err := w.store.OutboundQueueCounts(ctx)
	if err != nil {
		if w.logger != nil {
			w.logger.Warn("refresh outbox queue depth failed", "error", err)
		}
		return
	}
	metrics.SetOutboxQueueDepth(counts.Pending)
}

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 1000 {
		return msg[:1000]
	}
	return msg
}

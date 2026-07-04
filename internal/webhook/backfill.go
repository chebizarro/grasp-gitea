// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const defaultPendingActorBackfillLimit = 500

// PendingActorEventStore is the storage subset used by ActorBackfiller.
type PendingActorEventStore interface {
	ListPendingActorEvents(ctx context.Context, giteaUserID int64, limit int) ([]store.PendingActorEvent, error)
	DeletePendingActorEvent(ctx context.Context, id int64) error
}

// ActorBackfiller enqueues previously skipped unsigned actor events once a
// Gitea user links a NIP-46 signer pubkey.
type ActorBackfiller struct {
	store  PendingActorEventStore
	outbox ActorOutbox
	logger *slog.Logger
	limit  int
}

// NewActorBackfiller creates a pending actor event backfiller.
func NewActorBackfiller(st PendingActorEventStore, outbox ActorOutbox, logger *slog.Logger) *ActorBackfiller {
	if logger == nil {
		logger = slog.Default()
	}
	return &ActorBackfiller{store: st, outbox: outbox, logger: logger.With("component", "webhook.actor_backfill"), limit: defaultPendingActorBackfillLimit}
}

// EnqueuePending loads pending rows for the Gitea user, stamps each unsigned
// event with the linked pubkey, enqueues it to the normal outbox, and deletes
// the pending row after enqueue succeeds. The outbox dedupe key makes retries
// and repeated login polls idempotent.
func (b *ActorBackfiller) EnqueuePending(ctx context.Context, giteaUserID int64, linkedPubkey string) (int, error) {
	if b == nil || b.store == nil || b.outbox == nil {
		return 0, nil
	}
	if giteaUserID == 0 || linkedPubkey == "" {
		return 0, nil
	}
	limit := b.limit
	if limit <= 0 {
		limit = defaultPendingActorBackfillLimit
	}
	rows, err := b.store.ListPendingActorEvents(ctx, giteaUserID, limit)
	if err != nil {
		return 0, fmt.Errorf("list pending actor events for user %d: %w", giteaUserID, err)
	}

	count := 0
	for _, row := range rows {
		var ev nostr.Event
		if err := json.Unmarshal([]byte(row.UnsignedEventJSON), &ev); err != nil {
			return count, fmt.Errorf("unmarshal pending actor event %d: %w", row.ID, err)
		}
		ev.Kind = row.Kind
		ev.PubKey = linkedPubkey
		ev.Sig = ""
		ev.ID = ev.GetID()
		if err := b.outbox.Enqueue(ctx, row.Kind, linkedPubkey, row.Scope, &ev, row.DedupeKey); err != nil {
			return count, fmt.Errorf("enqueue pending actor event %d: %w", row.ID, err)
		}
		if err := b.store.DeletePendingActorEvent(ctx, row.ID); err != nil {
			return count, fmt.Errorf("delete pending actor event %d: %w", row.ID, err)
		}
		metrics.IncActorEventsBackfilled()
		count++
	}
	if count > 0 && b.logger != nil {
		b.logger.Info("backfilled pending actor events", "gitea_user_id", giteaUserID, "pubkey", linkedPubkey, "count", count)
	}
	return count, nil
}

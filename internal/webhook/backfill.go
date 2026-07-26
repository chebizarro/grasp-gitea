// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const defaultPendingActorBackfillLimit = 500

// PendingActorEventStore is the storage subset used by ActorBackfiller.
type PendingActorEventStore interface {
	ListPendingActorEvents(ctx context.Context, giteaUserID int64, limit int) ([]store.PendingActorEvent, error)
	DeletePendingActorEvent(ctx context.Context, id int64) error
	FinalizePendingThreadRoot(ctx context.Context, dedupeKey, eventID, pubkey string) (store.ThreadRoot, bool, error)
	DeletePendingThreadRoot(ctx context.Context, dedupeKey string) error
	RecordNostrObjectMapping(ctx context.Context, ref store.ReflectedEvent) (bool, error)
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
		linkedPK, err := nostr.PubKeyFromHexCheap(linkedPubkey)
		if err != nil {
			return count, fmt.Errorf("invalid linked pubkey %q: %w", linkedPubkey, err)
		}
		ev.Kind = nostr.Kind(row.Kind)
		ev.PubKey = linkedPK
		ev.Sig = [64]byte{}
		ev.ID = ev.GetID()
		if err := b.outbox.Enqueue(ctx, row.Kind, linkedPubkey, row.Scope, &ev, row.DedupeKey); err != nil {
			return count, fmt.Errorf("enqueue pending actor event %d: %w", row.ID, err)
		}
		root, hasRoot, err := b.store.FinalizePendingThreadRoot(ctx, row.DedupeKey, ev.ID.Hex(), linkedPubkey)
		if err != nil {
			return count, fmt.Errorf("finalize pending actor thread %d: %w", row.ID, err)
		}
		if hasRoot {
			if _, err := b.store.RecordNostrObjectMapping(ctx, store.ReflectedEvent{
				NostrEventID: ev.ID.Hex(),
				GiteaRepoID:  root.GiteaRepoID,
				GiteaIndex:   root.GiteaIndex,
				Kind:         root.Kind,
			}); err != nil {
				return count, fmt.Errorf("record backfilled actor root mapping %d: %w", row.ID, err)
			}
		}
		if err := b.store.DeletePendingActorEvent(ctx, row.ID); err != nil {
			return count, fmt.Errorf("delete pending actor event %d: %w", row.ID, err)
		}
		if hasRoot {
			if err := b.store.DeletePendingThreadRoot(ctx, row.DedupeKey); err != nil {
				return count, fmt.Errorf("delete pending actor thread %d: %w", row.ID, err)
			}
		}
		metrics.IncActorEventsBackfilled()
		count++
	}
	if count > 0 && b.logger != nil {
		b.logger.Info("backfilled pending actor events", "gitea_user_id", giteaUserID, "pubkey", linkedPubkey, "count", count)
	}
	return count, nil
}

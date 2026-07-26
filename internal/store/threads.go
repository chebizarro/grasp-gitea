// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	WebhookDeliveryPending = "pending"
	WebhookDeliveryDone    = "done"
)

// ThreadRoot durably maps a Gitea issue or pull request to its Nostr root.
type ThreadRoot struct {
	ObjectType   string
	GiteaRepoID  int64
	GiteaIndex   int64
	NostrEventID string
	Pubkey       string
	Kind         int
	UpdatedAt    time.Time
}

// WebhookDelivery is a durably recorded Gitea webhook receipt.
type WebhookDelivery struct {
	DeliveryID    string
	EventType     string
	Payload       []byte
	State         string
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	CreatedAt     time.Time
	CompletedAt   time.Time
}

func (s *SQLiteStore) ensureReflectionTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS reflection_threads (
			object_type TEXT NOT NULL,
			gitea_repo_id INTEGER NOT NULL,
			gitea_index INTEGER NOT NULL,
			nostr_event_id TEXT NOT NULL,
			pubkey TEXT NOT NULL,
			kind INTEGER NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (object_type, gitea_repo_id, gitea_index),
			UNIQUE (nostr_event_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_reflection_threads_event
			ON reflection_threads(nostr_event_id)`,
		`CREATE TABLE IF NOT EXISTS pending_thread_roots (
			dedupe_key TEXT PRIMARY KEY,
			object_type TEXT NOT NULL,
			gitea_repo_id INTEGER NOT NULL,
			gitea_index INTEGER NOT NULL,
			kind INTEGER NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			delivery_id TEXT PRIMARY KEY,
			event_type TEXT NOT NULL,
			payload BLOB NOT NULL,
			state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'done')),
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TEXT NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			completed_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
			ON webhook_deliveries(state, next_attempt_at, created_at)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize reflection persistence: %w", err)
		}
	}
	return nil
}

// UpsertThreadRoot records the latest Nostr root for one Gitea object.
func (s *SQLiteStore) UpsertThreadRoot(ctx context.Context, root ThreadRoot) error {
	root.ObjectType = strings.TrimSpace(root.ObjectType)
	root.NostrEventID = strings.TrimSpace(root.NostrEventID)
	root.Pubkey = strings.TrimSpace(root.Pubkey)
	if root.ObjectType == "" || root.GiteaRepoID <= 0 || root.GiteaIndex <= 0 || root.NostrEventID == "" || root.Kind == 0 {
		return fmt.Errorf("complete thread root identity is required")
	}
	if root.UpdatedAt.IsZero() {
		root.UpdatedAt = time.Now().UTC()
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO reflection_threads(object_type, gitea_repo_id, gitea_index, nostr_event_id, pubkey, kind, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(object_type, gitea_repo_id, gitea_index) DO UPDATE SET
			nostr_event_id = excluded.nostr_event_id,
			pubkey = excluded.pubkey,
			kind = excluded.kind,
			updated_at = excluded.updated_at
	`, root.ObjectType, root.GiteaRepoID, root.GiteaIndex, root.NostrEventID, root.Pubkey, root.Kind,
		root.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("upsert reflection thread root: %w", err)
	}
	return nil
}

// GetThreadRoot returns the persisted root for a Gitea object.
func (s *SQLiteStore) GetThreadRoot(ctx context.Context, objectType string, giteaRepoID, giteaIndex int64) (ThreadRoot, error) {
	if err := s.ensureReflectionTables(ctx); err != nil {
		return ThreadRoot{}, err
	}
	return scanThreadRoot(s.db.QueryRowContext(ctx, `
		SELECT object_type, gitea_repo_id, gitea_index, nostr_event_id, pubkey, kind, updated_at
		FROM reflection_threads
		WHERE object_type = ? AND gitea_repo_id = ? AND gitea_index = ?
	`, objectType, giteaRepoID, giteaIndex))
}

// GetThreadRootByEventID resolves a standard root-only NIP-22 reference.
func (s *SQLiteStore) GetThreadRootByEventID(ctx context.Context, eventID string) (ThreadRoot, error) {
	if err := s.ensureReflectionTables(ctx); err != nil {
		return ThreadRoot{}, err
	}
	return scanThreadRoot(s.db.QueryRowContext(ctx, `
		SELECT object_type, gitea_repo_id, gitea_index, nostr_event_id, pubkey, kind, updated_at
		FROM reflection_threads WHERE nostr_event_id = ?
	`, eventID))
}

type threadRootScanner interface {
	Scan(dest ...any) error
}

func scanThreadRoot(row threadRootScanner) (ThreadRoot, error) {
	var root ThreadRoot
	var updatedAt string
	if err := row.Scan(&root.ObjectType, &root.GiteaRepoID, &root.GiteaIndex, &root.NostrEventID, &root.Pubkey, &root.Kind, &updatedAt); err != nil {
		return ThreadRoot{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return ThreadRoot{}, fmt.Errorf("parse thread root updated_at: %w", err)
	}
	root.UpdatedAt = parsed
	return root, nil
}

// SavePendingThreadRoot associates a deferred actor root with its pending
// event dedupe key so backfill can finalize the signed event id.
func (s *SQLiteStore) SavePendingThreadRoot(ctx context.Context, dedupeKey string, root ThreadRoot) error {
	dedupeKey = strings.TrimSpace(dedupeKey)
	root.ObjectType = strings.TrimSpace(root.ObjectType)
	if dedupeKey == "" || root.ObjectType == "" || root.GiteaRepoID <= 0 || root.GiteaIndex <= 0 || root.Kind == 0 {
		return fmt.Errorf("complete pending thread root identity is required")
	}
	if root.UpdatedAt.IsZero() {
		root.UpdatedAt = time.Now().UTC()
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO pending_thread_roots(dedupe_key, object_type, gitea_repo_id, gitea_index, kind, created_at)
		VALUES(?, ?, ?, ?, ?, ?)
	`, dedupeKey, root.ObjectType, root.GiteaRepoID, root.GiteaIndex, root.Kind,
		root.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// FinalizePendingThreadRoot moves deferred root metadata into the durable root
// table after backfill computes the actor-authored event id.
func (s *SQLiteStore) FinalizePendingThreadRoot(ctx context.Context, dedupeKey, eventID, pubkey string) (ThreadRoot, bool, error) {
	if err := s.ensureReflectionTables(ctx); err != nil {
		return ThreadRoot{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ThreadRoot{}, false, err
	}
	defer tx.Rollback()

	var root ThreadRoot
	var createdAt string
	err = tx.QueryRowContext(ctx, `
		SELECT object_type, gitea_repo_id, gitea_index, kind, created_at
		FROM pending_thread_roots WHERE dedupe_key = ?
	`, dedupeKey).Scan(&root.ObjectType, &root.GiteaRepoID, &root.GiteaIndex, &root.Kind, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ThreadRoot{}, false, nil
	}
	if err != nil {
		return ThreadRoot{}, false, err
	}
	root.NostrEventID = strings.TrimSpace(eventID)
	root.Pubkey = strings.TrimSpace(pubkey)
	root.UpdatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ThreadRoot{}, false, fmt.Errorf("parse pending thread root created_at: %w", err)
	}
	if root.NostrEventID == "" || root.Pubkey == "" {
		return ThreadRoot{}, false, fmt.Errorf("final thread event id and pubkey are required")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO reflection_threads(object_type, gitea_repo_id, gitea_index, nostr_event_id, pubkey, kind, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(object_type, gitea_repo_id, gitea_index) DO UPDATE SET
			nostr_event_id = excluded.nostr_event_id,
			pubkey = excluded.pubkey,
			kind = excluded.kind,
			updated_at = excluded.updated_at
	`, root.ObjectType, root.GiteaRepoID, root.GiteaIndex, root.NostrEventID, root.Pubkey, root.Kind,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return ThreadRoot{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ThreadRoot{}, false, err
	}
	return root, true, nil
}

// DeletePendingThreadRoot removes finalized deferred metadata after the actor
// event and Nostr/Gitea object mapping are both durably queued/recorded.
func (s *SQLiteStore) DeletePendingThreadRoot(ctx context.Context, dedupeKey string) error {
	if err := s.ensureReflectionTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_thread_roots WHERE dedupe_key = ?`, dedupeKey)
	return err
}

// SaveWebhookDelivery durably records a delivery before it is acknowledged.
// Duplicate delivery ids return the existing row without replacing the payload.
func (s *SQLiteStore) SaveWebhookDelivery(ctx context.Context, delivery WebhookDelivery) (WebhookDelivery, bool, error) {
	delivery.DeliveryID = strings.TrimSpace(delivery.DeliveryID)
	delivery.EventType = strings.TrimSpace(delivery.EventType)
	if delivery.DeliveryID == "" {
		return WebhookDelivery{}, false, fmt.Errorf("delivery id is required")
	}
	if delivery.CreatedAt.IsZero() {
		delivery.CreatedAt = time.Now().UTC()
	}
	if delivery.NextAttemptAt.IsZero() {
		delivery.NextAttemptAt = delivery.CreatedAt
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return WebhookDelivery{}, false, err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO webhook_deliveries(
			delivery_id, event_type, payload, state, attempts, next_attempt_at, last_error, created_at, completed_at
		) VALUES(?, ?, ?, ?, 0, ?, '', ?, '')
	`, delivery.DeliveryID, delivery.EventType, delivery.Payload, WebhookDeliveryPending,
		delivery.NextAttemptAt.UTC().Format(time.RFC3339Nano), delivery.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return WebhookDelivery{}, false, fmt.Errorf("save webhook delivery: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return WebhookDelivery{}, false, err
	}
	saved, err := s.GetWebhookDelivery(ctx, delivery.DeliveryID)
	return saved, n > 0, err
}

// GetWebhookDelivery returns one persisted delivery.
func (s *SQLiteStore) GetWebhookDelivery(ctx context.Context, deliveryID string) (WebhookDelivery, error) {
	if err := s.ensureReflectionTables(ctx); err != nil {
		return WebhookDelivery{}, err
	}
	return scanWebhookDelivery(s.db.QueryRowContext(ctx, webhookDeliverySelectSQL()+` WHERE delivery_id = ?`, deliveryID))
}

// ListDueWebhookDeliveries returns pending deliveries ready for retry.
func (s *SQLiteStore) ListDueWebhookDeliveries(ctx context.Context, now time.Time, limit int) ([]WebhookDelivery, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, webhookDeliverySelectSQL()+`
		WHERE state = ? AND next_attempt_at <= ?
		ORDER BY next_attempt_at ASC, created_at ASC
		LIMIT ?
	`, WebhookDeliveryPending, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deliveries []WebhookDelivery
	for rows.Next() {
		delivery, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

// MarkWebhookDeliveryDone marks a successfully handled delivery.
func (s *SQLiteStore) MarkWebhookDeliveryDone(ctx context.Context, deliveryID string, completedAt time.Time) error {
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET state = ?, last_error = '', completed_at = ?
		WHERE delivery_id = ?
	`, WebhookDeliveryDone, completedAt.UTC().Format(time.RFC3339Nano), deliveryID)
	return err
}

// MarkWebhookDeliveryRetry records a failed attempt and its next retry time.
func (s *SQLiteStore) MarkWebhookDeliveryRetry(ctx context.Context, deliveryID string, nextAttemptAt time.Time, lastError string) (int, error) {
	if nextAttemptAt.IsZero() {
		nextAttemptAt = time.Now().UTC()
	}
	if len(lastError) > 1000 {
		lastError = lastError[:1000]
	}
	if err := s.ensureReflectionTables(ctx); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_deliveries
		SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
		WHERE delivery_id = ? AND state = ?
	`, nextAttemptAt.UTC().Format(time.RFC3339Nano), lastError, deliveryID, WebhookDeliveryPending)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, sql.ErrNoRows
	}
	var attempts int
	if err := s.db.QueryRowContext(ctx, `SELECT attempts FROM webhook_deliveries WHERE delivery_id = ?`, deliveryID).Scan(&attempts); err != nil {
		return 0, err
	}
	return attempts, nil
}

func webhookDeliverySelectSQL() string {
	return `SELECT delivery_id, event_type, payload, state, attempts, next_attempt_at, last_error, created_at, completed_at FROM webhook_deliveries`
}

type webhookDeliveryScanner interface {
	Scan(dest ...any) error
}

func scanWebhookDelivery(row webhookDeliveryScanner) (WebhookDelivery, error) {
	var delivery WebhookDelivery
	var nextAttemptAt, createdAt, completedAt string
	if err := row.Scan(&delivery.DeliveryID, &delivery.EventType, &delivery.Payload, &delivery.State, &delivery.Attempts,
		&nextAttemptAt, &delivery.LastError, &createdAt, &completedAt); err != nil {
		return WebhookDelivery{}, err
	}
	var err error
	delivery.NextAttemptAt, err = time.Parse(time.RFC3339Nano, nextAttemptAt)
	if err != nil {
		return WebhookDelivery{}, fmt.Errorf("parse webhook next_attempt_at: %w", err)
	}
	delivery.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return WebhookDelivery{}, fmt.Errorf("parse webhook created_at: %w", err)
	}
	if completedAt != "" {
		delivery.CompletedAt, err = time.Parse(time.RFC3339Nano, completedAt)
		if err != nil {
			return WebhookDelivery{}, fmt.Errorf("parse webhook completed_at: %w", err)
		}
	}
	return delivery, nil
}

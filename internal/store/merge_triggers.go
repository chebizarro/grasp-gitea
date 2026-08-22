// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAmbiguousPRRevision means two different revisions have the same newest
// Nostr timestamp. A caller must not guess which force-pushed tip was reviewed.
var ErrAmbiguousPRRevision = errors.New("ambiguous latest pull-request revision")

const maxPendingMergeStatuses = 4096

// ReviewedPRRevision is the immutable subset of a canonical NIP-34 PR event
// needed to bind a later applied status to the exact reviewed source.
type ReviewedPRRevision struct {
	EventID        string
	RootEventID    string
	RepoAddress    string
	Kind           int
	AuthorPubkey   string
	SourceCommit   string
	EventCreatedAt int64
	EventJSON      string
	ObservedAt     time.Time
}

// AcceptedRepositoryState is the latest authorized kind-30618 snapshot seen
// for a repository coordinate. EventJSON is retained so validation is
// recoverable after restart and never depends on mutable local refs alone.
type AcceptedRepositoryState struct {
	RepoAddress    string
	EventID        string
	AuthorPubkey   string
	EventCreatedAt int64
	EventJSON      string
	AcceptedAt     time.Time
}

// MergeTriggerEnvelope is the single immutable authorization and source-state
// claim made before any Hive workflow request is emitted.
type MergeTriggerEnvelope struct {
	IdempotencyKey string
	PREventID      string
	StatusEventID  string
	SourceCommit   string
	SourceTree     string
	PatchDigest    string
	AcceptedCommit string
	RepoAddress    string
	PolicyVersion  string
	Branch         string
	CreatedAt      time.Time
}

// PendingMergeStatus retains a cryptographically valid status while its PR or
// accepted-state dependencies arrive out of order. It is also the crash marker
// between envelope claim and idempotent workflow dispatch.
type PendingMergeStatus struct {
	EventID     string
	EventJSON   string
	SourceRelay string
	LastError   string
	ObservedAt  time.Time
}

func (s *SQLiteStore) EnsureMergeTriggerTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS hiveci_reviewed_pr_revisions (
			event_id TEXT PRIMARY KEY,
			root_event_id TEXT NOT NULL,
			repo_address TEXT NOT NULL,
			event_kind INTEGER NOT NULL,
			author_pubkey TEXT NOT NULL,
			source_commit TEXT NOT NULL,
			event_created_at INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			observed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_pr_revision_latest
			ON hiveci_reviewed_pr_revisions(root_event_id, repo_address, event_created_at DESC, event_id ASC)`,
		`CREATE TABLE IF NOT EXISTS hiveci_accepted_repository_states (
			repo_address TEXT PRIMARY KEY,
			event_id TEXT NOT NULL UNIQUE,
			author_pubkey TEXT NOT NULL,
			event_created_at INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			accepted_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS hiveci_merge_trigger_envelopes (
			idempotency_key TEXT PRIMARY KEY,
			pr_event_id TEXT NOT NULL,
			status_event_id TEXT NOT NULL UNIQUE,
			source_commit TEXT NOT NULL,
			source_tree TEXT NOT NULL,
			patch_digest TEXT NOT NULL,
			accepted_commit TEXT NOT NULL,
			repo_address TEXT NOT NULL,
			policy_version TEXT NOT NULL,
			branch TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_merge_trigger_pr
			ON hiveci_merge_trigger_envelopes(repo_address, pr_event_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS hiveci_pending_merge_statuses (
			event_id TEXT PRIMARY KEY,
			event_json TEXT NOT NULL,
			source_relay TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			observed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_pending_merge_statuses_observed
			ON hiveci_pending_merge_statuses(observed_at, event_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize HiveCI merge-trigger persistence: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) SavePendingMergeStatus(ctx context.Context, pending PendingMergeStatus) error {
	pending.EventID = strings.TrimSpace(pending.EventID)
	pending.EventJSON = strings.TrimSpace(pending.EventJSON)
	pending.SourceRelay = strings.TrimSpace(pending.SourceRelay)
	pending.LastError = strings.TrimSpace(pending.LastError)
	if pending.EventID == "" || pending.EventJSON == "" {
		return fmt.Errorf("pending merge status event is required")
	}
	if pending.ObservedAt.IsZero() {
		pending.ObservedAt = time.Now().UTC()
	}
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hiveci_pending_merge_statuses(event_id, event_json, source_relay, last_error, observed_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(event_id) DO UPDATE SET
			source_relay = excluded.source_relay,
			last_error = excluded.last_error
		WHERE hiveci_pending_merge_statuses.event_json = excluded.event_json
	`, pending.EventID, pending.EventJSON, pending.SourceRelay, pending.LastError, pending.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save pending merge status: %w", err)
	}
	// Bound unresolved relay input without deleting claimed/recoverable trigger
	// envelopes. Newest authorized statuses are retained for later dependency
	// arrival; older unresolved input must be redelivered by the relay.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM hiveci_pending_merge_statuses WHERE event_id IN (
			SELECT event_id FROM hiveci_pending_merge_statuses
			ORDER BY observed_at DESC, event_id DESC LIMIT -1 OFFSET ?
		)
	`, maxPendingMergeStatuses); err != nil {
		return fmt.Errorf("bound pending merge statuses: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListPendingMergeStatuses(ctx context.Context, limit int) ([]PendingMergeStatus, error) {
	if limit <= 0 || limit > 1024 {
		limit = 256
	}
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, event_json, source_relay, last_error, observed_at
		FROM hiveci_pending_merge_statuses ORDER BY observed_at, event_id LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []PendingMergeStatus
	for rows.Next() {
		var item PendingMergeStatus
		var observedAt int64
		if err := rows.Scan(&item.EventID, &item.EventJSON, &item.SourceRelay, &item.LastError, &observedAt); err != nil {
			return nil, err
		}
		item.ObservedAt = time.Unix(observedAt, 0).UTC()
		pending = append(pending, item)
	}
	return pending, rows.Err()
}

func (s *SQLiteStore) DeletePendingMergeStatus(ctx context.Context, eventID string) error {
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM hiveci_pending_merge_statuses WHERE event_id = ?`, strings.TrimSpace(eventID))
	return err
}

// SaveReviewedPRRevision records an immutable PR root or update. Replays are
// accepted only when every security-relevant field is identical.
func (s *SQLiteStore) SaveReviewedPRRevision(ctx context.Context, revision ReviewedPRRevision) error {
	normalizeReviewedPRRevision(&revision)
	if revision.EventID == "" || revision.RootEventID == "" || revision.RepoAddress == "" ||
		revision.Kind == 0 || revision.AuthorPubkey == "" || revision.SourceCommit == "" ||
		revision.EventCreatedAt <= 0 || revision.EventJSON == "" {
		return fmt.Errorf("complete reviewed PR revision is required")
	}
	if revision.ObservedAt.IsZero() {
		revision.ObservedAt = time.Now().UTC()
	}
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO hiveci_reviewed_pr_revisions(
			event_id, root_event_id, repo_address, event_kind, author_pubkey,
			source_commit, event_created_at, event_json, observed_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, revision.EventID, revision.RootEventID, revision.RepoAddress, revision.Kind,
		revision.AuthorPubkey, revision.SourceCommit, revision.EventCreatedAt,
		revision.EventJSON, revision.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save reviewed PR revision: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 {
		return nil
	}
	existing, err := s.GetReviewedPRRevision(ctx, revision.EventID)
	if err != nil {
		return err
	}
	if !sameReviewedPRRevision(existing, revision) {
		return fmt.Errorf("reviewed PR revision %q immutable identity mismatch", revision.EventID)
	}
	return nil
}

func (s *SQLiteStore) GetReviewedPRRevision(ctx context.Context, eventID string) (ReviewedPRRevision, error) {
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return ReviewedPRRevision{}, err
	}
	return scanReviewedPRRevision(s.db.QueryRowContext(ctx, `
		SELECT event_id, root_event_id, repo_address, event_kind, author_pubkey,
			source_commit, event_created_at, event_json, observed_at
		FROM hiveci_reviewed_pr_revisions WHERE event_id = ?
	`, strings.TrimSpace(eventID)))
}

// GetLatestReviewedPRRevision returns the uniquely newest revision. Equal-time
// divergent events are rejected instead of using an arbitrary force-push tip.
func (s *SQLiteStore) GetLatestReviewedPRRevision(ctx context.Context, rootEventID, repoAddress string) (ReviewedPRRevision, error) {
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return ReviewedPRRevision{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, root_event_id, repo_address, event_kind, author_pubkey,
			source_commit, event_created_at, event_json, observed_at
		FROM hiveci_reviewed_pr_revisions
		WHERE root_event_id = ? AND repo_address = ?
		ORDER BY event_created_at DESC, event_id ASC LIMIT 2
	`, strings.TrimSpace(rootEventID), strings.TrimSpace(repoAddress))
	if err != nil {
		return ReviewedPRRevision{}, err
	}
	defer rows.Close()
	var revisions []ReviewedPRRevision
	for rows.Next() {
		revision, err := scanReviewedPRRevision(rows)
		if err != nil {
			return ReviewedPRRevision{}, err
		}
		revisions = append(revisions, revision)
	}
	if err := rows.Err(); err != nil {
		return ReviewedPRRevision{}, err
	}
	if len(revisions) == 0 {
		return ReviewedPRRevision{}, sql.ErrNoRows
	}
	if len(revisions) > 1 && revisions[0].EventCreatedAt == revisions[1].EventCreatedAt &&
		(revisions[0].EventID != revisions[1].EventID || revisions[0].SourceCommit != revisions[1].SourceCommit) {
		return ReviewedPRRevision{}, ErrAmbiguousPRRevision
	}
	return revisions[0], nil
}

func (s *SQLiteStore) SaveAcceptedRepositoryState(ctx context.Context, state AcceptedRepositoryState) error {
	normalizeAcceptedRepositoryState(&state)
	if state.RepoAddress == "" || state.EventID == "" || state.AuthorPubkey == "" ||
		state.EventCreatedAt <= 0 || state.EventJSON == "" {
		return fmt.Errorf("complete accepted repository state is required")
	}
	if state.AcceptedAt.IsZero() {
		state.AcceptedAt = time.Now().UTC()
	}
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hiveci_accepted_repository_states(
			repo_address, event_id, author_pubkey, event_created_at, event_json, accepted_at
		) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_address) DO UPDATE SET
			event_id = excluded.event_id,
			author_pubkey = excluded.author_pubkey,
			event_created_at = excluded.event_created_at,
			event_json = excluded.event_json,
			accepted_at = excluded.accepted_at
		WHERE hiveci_accepted_repository_states.event_created_at < excluded.event_created_at
			OR (hiveci_accepted_repository_states.event_created_at = excluded.event_created_at
				AND hiveci_accepted_repository_states.event_id > excluded.event_id)
	`, state.RepoAddress, state.EventID, state.AuthorPubkey, state.EventCreatedAt,
		state.EventJSON, state.AcceptedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save accepted repository state: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetAcceptedRepositoryState(ctx context.Context, repoAddress string) (AcceptedRepositoryState, error) {
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return AcceptedRepositoryState{}, err
	}
	var state AcceptedRepositoryState
	var acceptedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT repo_address, event_id, author_pubkey, event_created_at, event_json, accepted_at
		FROM hiveci_accepted_repository_states WHERE repo_address = ?
	`, strings.TrimSpace(repoAddress)).Scan(&state.RepoAddress, &state.EventID, &state.AuthorPubkey,
		&state.EventCreatedAt, &state.EventJSON, &acceptedAt)
	if err != nil {
		return AcceptedRepositoryState{}, err
	}
	state.AcceptedAt = time.Unix(acceptedAt, 0).UTC()
	return state, nil
}

// ClaimMergeTriggerEnvelope atomically persists an immutable trigger. A replay
// returns the already stored envelope; conflicting identity is always an error.
func (s *SQLiteStore) ClaimMergeTriggerEnvelope(ctx context.Context, envelope MergeTriggerEnvelope) (MergeTriggerEnvelope, bool, error) {
	normalizeMergeTriggerEnvelope(&envelope)
	if envelope.IdempotencyKey == "" || envelope.PREventID == "" || envelope.StatusEventID == "" ||
		envelope.SourceCommit == "" || envelope.SourceTree == "" || envelope.PatchDigest == "" ||
		envelope.AcceptedCommit == "" || envelope.RepoAddress == "" || envelope.PolicyVersion == "" || envelope.Branch == "" {
		return MergeTriggerEnvelope{}, false, fmt.Errorf("complete merge-trigger envelope is required")
	}
	if envelope.CreatedAt.IsZero() {
		envelope.CreatedAt = time.Now().UTC()
	}
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return MergeTriggerEnvelope{}, false, err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO hiveci_merge_trigger_envelopes(
			idempotency_key, pr_event_id, status_event_id, source_commit, source_tree,
			patch_digest, accepted_commit, repo_address, policy_version, branch, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, envelope.IdempotencyKey, envelope.PREventID, envelope.StatusEventID,
		envelope.SourceCommit, envelope.SourceTree, envelope.PatchDigest,
		envelope.AcceptedCommit, envelope.RepoAddress, envelope.PolicyVersion, envelope.Branch,
		envelope.CreatedAt.UTC().Unix())
	if err != nil {
		return MergeTriggerEnvelope{}, false, fmt.Errorf("claim merge-trigger envelope: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return MergeTriggerEnvelope{}, false, err
	}
	stored, err := s.GetMergeTriggerEnvelopeByStatusID(ctx, envelope.StatusEventID)
	if err != nil {
		return MergeTriggerEnvelope{}, false, err
	}
	if !sameMergeTriggerEnvelope(stored, envelope) {
		return MergeTriggerEnvelope{}, false, fmt.Errorf("merge status %q immutable envelope mismatch", envelope.StatusEventID)
	}
	return stored, inserted > 0, nil
}

func (s *SQLiteStore) GetMergeTriggerEnvelopeByStatusID(ctx context.Context, statusEventID string) (MergeTriggerEnvelope, error) {
	if err := s.EnsureMergeTriggerTables(ctx); err != nil {
		return MergeTriggerEnvelope{}, err
	}
	var envelope MergeTriggerEnvelope
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT idempotency_key, pr_event_id, status_event_id, source_commit, source_tree,
			patch_digest, accepted_commit, repo_address, policy_version, branch, created_at
		FROM hiveci_merge_trigger_envelopes WHERE status_event_id = ?
	`, strings.TrimSpace(statusEventID)).Scan(&envelope.IdempotencyKey, &envelope.PREventID,
		&envelope.StatusEventID, &envelope.SourceCommit, &envelope.SourceTree,
		&envelope.PatchDigest, &envelope.AcceptedCommit, &envelope.RepoAddress, &envelope.PolicyVersion,
		&envelope.Branch, &createdAt)
	if err != nil {
		return MergeTriggerEnvelope{}, err
	}
	envelope.CreatedAt = time.Unix(createdAt, 0).UTC()
	return envelope, nil
}

type reviewedPRRevisionScanner interface{ Scan(...any) error }

func scanReviewedPRRevision(scanner reviewedPRRevisionScanner) (ReviewedPRRevision, error) {
	var revision ReviewedPRRevision
	var observedAt int64
	if err := scanner.Scan(&revision.EventID, &revision.RootEventID, &revision.RepoAddress,
		&revision.Kind, &revision.AuthorPubkey, &revision.SourceCommit,
		&revision.EventCreatedAt, &revision.EventJSON, &observedAt); err != nil {
		return ReviewedPRRevision{}, err
	}
	revision.ObservedAt = time.Unix(observedAt, 0).UTC()
	return revision, nil
}

func normalizeReviewedPRRevision(revision *ReviewedPRRevision) {
	revision.EventID = strings.TrimSpace(revision.EventID)
	revision.RootEventID = strings.TrimSpace(revision.RootEventID)
	revision.RepoAddress = strings.TrimSpace(revision.RepoAddress)
	revision.AuthorPubkey = strings.TrimSpace(revision.AuthorPubkey)
	revision.SourceCommit = strings.ToLower(strings.TrimSpace(revision.SourceCommit))
	revision.EventJSON = strings.TrimSpace(revision.EventJSON)
}

func sameReviewedPRRevision(a, b ReviewedPRRevision) bool {
	normalizeReviewedPRRevision(&a)
	normalizeReviewedPRRevision(&b)
	return a.EventID == b.EventID && a.RootEventID == b.RootEventID &&
		a.RepoAddress == b.RepoAddress && a.Kind == b.Kind &&
		a.AuthorPubkey == b.AuthorPubkey && a.SourceCommit == b.SourceCommit &&
		a.EventCreatedAt == b.EventCreatedAt && a.EventJSON == b.EventJSON
}

func normalizeAcceptedRepositoryState(state *AcceptedRepositoryState) {
	state.RepoAddress = strings.TrimSpace(state.RepoAddress)
	state.EventID = strings.TrimSpace(state.EventID)
	state.AuthorPubkey = strings.TrimSpace(state.AuthorPubkey)
	state.EventJSON = strings.TrimSpace(state.EventJSON)
}

func normalizeMergeTriggerEnvelope(envelope *MergeTriggerEnvelope) {
	envelope.IdempotencyKey = strings.TrimSpace(envelope.IdempotencyKey)
	envelope.PREventID = strings.TrimSpace(envelope.PREventID)
	envelope.StatusEventID = strings.TrimSpace(envelope.StatusEventID)
	envelope.SourceCommit = strings.ToLower(strings.TrimSpace(envelope.SourceCommit))
	envelope.SourceTree = strings.ToLower(strings.TrimSpace(envelope.SourceTree))
	envelope.PatchDigest = strings.ToLower(strings.TrimSpace(envelope.PatchDigest))
	envelope.AcceptedCommit = strings.ToLower(strings.TrimSpace(envelope.AcceptedCommit))
	envelope.RepoAddress = strings.TrimSpace(envelope.RepoAddress)
	envelope.PolicyVersion = strings.TrimSpace(envelope.PolicyVersion)
	envelope.Branch = strings.TrimSpace(envelope.Branch)
}

func sameMergeTriggerEnvelope(a, b MergeTriggerEnvelope) bool {
	normalizeMergeTriggerEnvelope(&a)
	normalizeMergeTriggerEnvelope(&b)
	return a.IdempotencyKey == b.IdempotencyKey && a.PREventID == b.PREventID &&
		a.StatusEventID == b.StatusEventID && a.SourceCommit == b.SourceCommit &&
		a.SourceTree == b.SourceTree && a.PatchDigest == b.PatchDigest &&
		a.AcceptedCommit == b.AcceptedCommit &&
		a.RepoAddress == b.RepoAddress && a.PolicyVersion == b.PolicyVersion &&
		a.Branch == b.Branch
}

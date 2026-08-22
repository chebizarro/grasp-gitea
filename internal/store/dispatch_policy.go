// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const maxDispatchPolicyEvidencePerRepo = 8192

// DispatchReviewEvidence is the immutable provenance carried by one signed
// Drydock kind-1111 review event. The event is not itself an approval.
type DispatchReviewEvidence struct {
	EventID        string
	ReviewerPubkey string
	RepoAddress    string
	RootEventID    string
	PatchEventID   string
	BaseCommit     string
	TipCommit      string
	DiffSHA256     string
	EventCreatedAt int64
	EventJSON      string
	ObservedAt     time.Time
}

// DispatchReviewAudit is a canonical Cascadia kind-4903 review attestation.
// Outcome is persisted even when it is not "approved" so a later resolver can
// fail closed on conflicting or revoked attestations.
type DispatchReviewAudit struct {
	EventID        string
	ReviewerPubkey string
	ReviewEventID  string
	RepoAddress    string
	Commit         string
	Outcome        string
	EventCreatedAt int64
	EventJSON      string
	ObservedAt     time.Time
}

// RepositoryAuthorityEvent is the canonical latest kind-30617 announcement
// for one (author, repository identifier). The resolver reconstructs current
// recursive maintainer authority exclusively from these durable signed events.
type RepositoryAuthorityEvent struct {
	AuthorPubkey   string
	RepoID         string
	EventID        string
	EventCreatedAt int64
	EventJSON      string
	ObservedAt     time.Time
}

func (s *SQLiteStore) EnsureDispatchPolicyTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS hiveci_dispatch_review_evidence (
			event_id TEXT PRIMARY KEY,
			reviewer_pubkey TEXT NOT NULL,
			repo_address TEXT NOT NULL,
			root_event_id TEXT NOT NULL,
			patch_event_id TEXT NOT NULL,
			base_commit TEXT NOT NULL,
			tip_commit TEXT NOT NULL,
			diff_sha256 TEXT NOT NULL,
			event_created_at INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			observed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_dispatch_review_source
			ON hiveci_dispatch_review_evidence(repo_address, patch_event_id, tip_commit, event_created_at DESC, event_id ASC)`,
		`CREATE TABLE IF NOT EXISTS hiveci_dispatch_review_audits (
			event_id TEXT PRIMARY KEY,
			reviewer_pubkey TEXT NOT NULL,
			review_event_id TEXT NOT NULL,
			repo_address TEXT NOT NULL,
			commit_sha TEXT NOT NULL,
			outcome TEXT NOT NULL,
			event_created_at INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			observed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_dispatch_audit_source
			ON hiveci_dispatch_review_audits(repo_address, commit_sha, event_created_at DESC, event_id ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_dispatch_audit_review
			ON hiveci_dispatch_review_audits(review_event_id, event_created_at DESC, event_id ASC)`,
		`CREATE TABLE IF NOT EXISTS hiveci_repository_authority_events (
			author_pubkey TEXT NOT NULL,
			repo_id TEXT NOT NULL,
			event_id TEXT NOT NULL UNIQUE,
			event_created_at INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			observed_at INTEGER NOT NULL,
			PRIMARY KEY(author_pubkey, repo_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_repository_authority_repo
			ON hiveci_repository_authority_events(repo_id, event_created_at DESC, event_id ASC)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize HiveCI dispatch-policy persistence: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) SaveDispatchReviewEvidence(ctx context.Context, evidence DispatchReviewEvidence) error {
	normalizeDispatchReviewEvidence(&evidence)
	if evidence.EventID == "" || evidence.ReviewerPubkey == "" || evidence.RepoAddress == "" ||
		evidence.RootEventID == "" || evidence.PatchEventID == "" || evidence.BaseCommit == "" ||
		evidence.TipCommit == "" || evidence.DiffSHA256 == "" || evidence.EventCreatedAt <= 0 || evidence.EventJSON == "" {
		return fmt.Errorf("complete dispatch review evidence is required")
	}
	if evidence.ObservedAt.IsZero() {
		evidence.ObservedAt = time.Now().UTC()
	}
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_dispatch_review_evidence(
		event_id, reviewer_pubkey, repo_address, root_event_id, patch_event_id,
		base_commit, tip_commit, diff_sha256, event_created_at, event_json, observed_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, evidence.EventID, evidence.ReviewerPubkey,
		evidence.RepoAddress, evidence.RootEventID, evidence.PatchEventID, evidence.BaseCommit,
		evidence.TipCommit, evidence.DiffSHA256, evidence.EventCreatedAt, evidence.EventJSON,
		evidence.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save dispatch review evidence: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		existing, err := s.GetDispatchReviewEvidence(ctx, evidence.EventID)
		if err != nil {
			return err
		}
		if !sameDispatchReviewEvidence(existing, evidence) {
			return fmt.Errorf("dispatch review evidence %q immutable identity mismatch", evidence.EventID)
		}
		return nil
	}
	return s.boundDispatchPolicyTable(ctx, "hiveci_dispatch_review_evidence", evidence.RepoAddress)
}

func (s *SQLiteStore) GetDispatchReviewEvidence(ctx context.Context, eventID string) (DispatchReviewEvidence, error) {
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return DispatchReviewEvidence{}, err
	}
	var evidence DispatchReviewEvidence
	var observedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT event_id, reviewer_pubkey, repo_address, root_event_id,
		patch_event_id, base_commit, tip_commit, diff_sha256, event_created_at, event_json, observed_at
		FROM hiveci_dispatch_review_evidence WHERE event_id = ?`, strings.TrimSpace(eventID)).Scan(
		&evidence.EventID, &evidence.ReviewerPubkey, &evidence.RepoAddress, &evidence.RootEventID,
		&evidence.PatchEventID, &evidence.BaseCommit, &evidence.TipCommit, &evidence.DiffSHA256,
		&evidence.EventCreatedAt, &evidence.EventJSON, &observedAt)
	if err != nil {
		return DispatchReviewEvidence{}, err
	}
	evidence.ObservedAt = time.Unix(observedAt, 0).UTC()
	return evidence, nil
}

func (s *SQLiteStore) SaveDispatchReviewAudit(ctx context.Context, audit DispatchReviewAudit) error {
	normalizeDispatchReviewAudit(&audit)
	if audit.EventID == "" || audit.ReviewerPubkey == "" || audit.ReviewEventID == "" ||
		audit.RepoAddress == "" || audit.Commit == "" || audit.Outcome == "" ||
		audit.EventCreatedAt <= 0 || audit.EventJSON == "" {
		return fmt.Errorf("complete dispatch review audit is required")
	}
	if audit.ObservedAt.IsZero() {
		audit.ObservedAt = time.Now().UTC()
	}
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_dispatch_review_audits(
		event_id, reviewer_pubkey, review_event_id, repo_address, commit_sha,
		outcome, event_created_at, event_json, observed_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, audit.EventID, audit.ReviewerPubkey,
		audit.ReviewEventID, audit.RepoAddress, audit.Commit, audit.Outcome,
		audit.EventCreatedAt, audit.EventJSON, audit.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save dispatch review audit: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		existing, err := s.GetDispatchReviewAudit(ctx, audit.EventID)
		if err != nil {
			return err
		}
		if !sameDispatchReviewAudit(existing, audit) {
			return fmt.Errorf("dispatch review audit %q immutable identity mismatch", audit.EventID)
		}
		return nil
	}
	return s.boundDispatchPolicyTable(ctx, "hiveci_dispatch_review_audits", audit.RepoAddress)
}

func (s *SQLiteStore) GetDispatchReviewAudit(ctx context.Context, eventID string) (DispatchReviewAudit, error) {
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return DispatchReviewAudit{}, err
	}
	return scanDispatchReviewAudit(s.db.QueryRowContext(ctx, `SELECT event_id, reviewer_pubkey,
		review_event_id, repo_address, commit_sha, outcome, event_created_at, event_json, observed_at
		FROM hiveci_dispatch_review_audits WHERE event_id = ?`, strings.TrimSpace(eventID)))
}

// ListDispatchReviewAuditsForSource returns every canonical attestation for an
// exact repository/commit. The resolver deliberately sees conflicts instead
// of selecting a convenient approval.
func (s *SQLiteStore) ListDispatchReviewAuditsForSource(ctx context.Context, repoAddress, commit string) ([]DispatchReviewAudit, error) {
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, reviewer_pubkey, review_event_id,
		repo_address, commit_sha, outcome, event_created_at, event_json, observed_at
		FROM hiveci_dispatch_review_audits WHERE repo_address = ? AND commit_sha = ?
		ORDER BY event_created_at DESC, event_id ASC`, strings.TrimSpace(repoAddress), strings.ToLower(strings.TrimSpace(commit)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var audits []DispatchReviewAudit
	for rows.Next() {
		audit, err := scanDispatchReviewAudit(rows)
		if err != nil {
			return nil, err
		}
		audits = append(audits, audit)
	}
	return audits, rows.Err()
}

func (s *SQLiteStore) SaveRepositoryAuthorityEvent(ctx context.Context, event RepositoryAuthorityEvent) error {
	event.AuthorPubkey = strings.ToLower(strings.TrimSpace(event.AuthorPubkey))
	event.RepoID = strings.TrimSpace(event.RepoID)
	event.EventID = strings.ToLower(strings.TrimSpace(event.EventID))
	event.EventJSON = strings.TrimSpace(event.EventJSON)
	if event.AuthorPubkey == "" || event.RepoID == "" || event.EventID == "" || event.EventCreatedAt <= 0 || event.EventJSON == "" {
		return fmt.Errorf("complete repository authority event is required")
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO hiveci_repository_authority_events(
		author_pubkey, repo_id, event_id, event_created_at, event_json, observed_at
	) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(author_pubkey, repo_id) DO UPDATE SET
		event_id=excluded.event_id, event_created_at=excluded.event_created_at,
		event_json=excluded.event_json, observed_at=excluded.observed_at
	WHERE `+replaceableEventSQL("hiveci_repository_authority_events.event_created_at",
		"hiveci_repository_authority_events.event_id", "excluded.event_created_at", "excluded.event_id"),
		event.AuthorPubkey, event.RepoID, event.EventID, event.EventCreatedAt,
		event.EventJSON, event.ObservedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save repository authority event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListRepositoryAuthorityEvents(ctx context.Context, repoID string) ([]RepositoryAuthorityEvent, error) {
	if err := s.EnsureDispatchPolicyTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT author_pubkey, repo_id, event_id,
		event_created_at, event_json, observed_at FROM hiveci_repository_authority_events
		WHERE repo_id = ? ORDER BY author_pubkey`, strings.TrimSpace(repoID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []RepositoryAuthorityEvent
	for rows.Next() {
		var event RepositoryAuthorityEvent
		var observedAt int64
		if err := rows.Scan(&event.AuthorPubkey, &event.RepoID, &event.EventID,
			&event.EventCreatedAt, &event.EventJSON, &observedAt); err != nil {
			return nil, err
		}
		event.ObservedAt = time.Unix(observedAt, 0).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *SQLiteStore) boundDispatchPolicyTable(ctx context.Context, table, repoAddress string) error {
	if table != "hiveci_dispatch_review_evidence" && table != "hiveci_dispatch_review_audits" {
		return fmt.Errorf("unsupported dispatch-policy table")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE event_id IN (
		SELECT event_id FROM `+table+` WHERE repo_address = ?
		ORDER BY event_created_at DESC, event_id ASC LIMIT -1 OFFSET ?
	)`, repoAddress, maxDispatchPolicyEvidencePerRepo)
	return err
}

type dispatchReviewAuditScanner interface{ Scan(...any) error }

func scanDispatchReviewAudit(row dispatchReviewAuditScanner) (DispatchReviewAudit, error) {
	var audit DispatchReviewAudit
	var observedAt int64
	if err := row.Scan(&audit.EventID, &audit.ReviewerPubkey, &audit.ReviewEventID,
		&audit.RepoAddress, &audit.Commit, &audit.Outcome, &audit.EventCreatedAt,
		&audit.EventJSON, &observedAt); err != nil {
		return DispatchReviewAudit{}, err
	}
	audit.ObservedAt = time.Unix(observedAt, 0).UTC()
	return audit, nil
}

func normalizeDispatchReviewEvidence(evidence *DispatchReviewEvidence) {
	evidence.EventID = strings.ToLower(strings.TrimSpace(evidence.EventID))
	evidence.ReviewerPubkey = strings.ToLower(strings.TrimSpace(evidence.ReviewerPubkey))
	evidence.RepoAddress = strings.TrimSpace(evidence.RepoAddress)
	evidence.RootEventID = strings.ToLower(strings.TrimSpace(evidence.RootEventID))
	evidence.PatchEventID = strings.ToLower(strings.TrimSpace(evidence.PatchEventID))
	evidence.BaseCommit = strings.ToLower(strings.TrimSpace(evidence.BaseCommit))
	evidence.TipCommit = strings.ToLower(strings.TrimSpace(evidence.TipCommit))
	evidence.DiffSHA256 = strings.ToLower(strings.TrimSpace(evidence.DiffSHA256))
	evidence.EventJSON = strings.TrimSpace(evidence.EventJSON)
}

func normalizeDispatchReviewAudit(audit *DispatchReviewAudit) {
	audit.EventID = strings.ToLower(strings.TrimSpace(audit.EventID))
	audit.ReviewerPubkey = strings.ToLower(strings.TrimSpace(audit.ReviewerPubkey))
	audit.ReviewEventID = strings.ToLower(strings.TrimSpace(audit.ReviewEventID))
	audit.RepoAddress = strings.TrimSpace(audit.RepoAddress)
	audit.Commit = strings.ToLower(strings.TrimSpace(audit.Commit))
	audit.Outcome = strings.ToLower(strings.TrimSpace(audit.Outcome))
	audit.EventJSON = strings.TrimSpace(audit.EventJSON)
}

func sameDispatchReviewEvidence(a, b DispatchReviewEvidence) bool {
	normalizeDispatchReviewEvidence(&a)
	normalizeDispatchReviewEvidence(&b)
	return a.EventID == b.EventID && a.ReviewerPubkey == b.ReviewerPubkey &&
		a.RepoAddress == b.RepoAddress && a.RootEventID == b.RootEventID &&
		a.PatchEventID == b.PatchEventID && a.BaseCommit == b.BaseCommit &&
		a.TipCommit == b.TipCommit && a.DiffSHA256 == b.DiffSHA256 &&
		a.EventCreatedAt == b.EventCreatedAt && a.EventJSON == b.EventJSON
}

func sameDispatchReviewAudit(a, b DispatchReviewAudit) bool {
	normalizeDispatchReviewAudit(&a)
	normalizeDispatchReviewAudit(&b)
	return a.EventID == b.EventID && a.ReviewerPubkey == b.ReviewerPubkey &&
		a.ReviewEventID == b.ReviewEventID && a.RepoAddress == b.RepoAddress &&
		a.Commit == b.Commit && a.Outcome == b.Outcome &&
		a.EventCreatedAt == b.EventCreatedAt && a.EventJSON == b.EventJSON
}

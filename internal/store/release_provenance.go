// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	ReleaseProvenanceSchemaV1    = "hiveci.release-provenance.v1"
	ReleaseIdentityPrefix        = "hiveci-release:v1:"
	releaseConflictQuarantineMsg = "immutable release identity already contains different content"
)

var (
	ErrReleaseProvenanceConflict = errors.New("release provenance conflict")
	releaseHex64                 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	releaseOCIDigest             = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ReleaseProvenanceRecord is the durable successful terminal attestation. A
// row is written only after every registry object is addressable and the
// terminal event has been signed. ContentDigest excludes the Nostr timestamp
// and signature; it is the exact-replay/conflict boundary for ReleaseIdentity.
type ReleaseProvenanceRecord struct {
	ReleaseIdentity    string
	SchemaVersion      string
	ContentDigest      string
	RegistryRepository string
	ManifestDigest     string
	SBOMDigest         string
	ProvenanceDigest   string
	SignedEventID      string
	SignedEventJSON    string
	CreatedAt          time.Time
}

// ReleaseQuarantineRecord preserves a rejected candidate without rebinding
// the successful release. CandidateJSON is canonical candidate evidence; for
// a conflict racing at commit it is the signed event, while a conflict found
// before upload/signing stores the unsigned canonical release result.
type ReleaseQuarantineRecord struct {
	ID                       int64
	ReleaseIdentity          string
	ExistingContentDigest    string
	ConflictingContentDigest string
	CandidateJSON            string
	Reason                   string
	QuarantinedAt            time.Time
}

// ReleaseCommitResult returns the authoritative record. Replay is true only
// when the exact candidate content was already committed.
type ReleaseCommitResult struct {
	Record ReleaseProvenanceRecord
	Replay bool
}

// ReleaseProvenanceStore is the atomic release identity and quarantine
// boundary shared by SQLite and Postgres.
type ReleaseProvenanceStore interface {
	GetReleaseProvenance(context.Context, string) (ReleaseProvenanceRecord, error)
	CommitReleaseProvenance(context.Context, ReleaseProvenanceRecord) (ReleaseCommitResult, error)
	QuarantineReleaseConflict(context.Context, string, string, string) error
	ListReleaseQuarantine(context.Context, string) ([]ReleaseQuarantineRecord, error)
}

var (
	_ ReleaseProvenanceStore = (*SQLiteStore)(nil)
	_ ReleaseProvenanceStore = (*PostgresStore)(nil)
)

// ReleaseProvenanceConflictError is terminal. The conflicting candidate is
// durably quarantined in the same transaction that observes the authoritative
// successful row.
type ReleaseProvenanceConflictError struct {
	ReleaseIdentity string
}

func (e *ReleaseProvenanceConflictError) Error() string {
	return fmt.Sprintf("%s: %s", ErrReleaseProvenanceConflict, e.ReleaseIdentity)
}
func (e *ReleaseProvenanceConflictError) Unwrap() error      { return ErrReleaseProvenanceConflict }
func (e *ReleaseProvenanceConflictError) NonRetryable() bool { return true }

func validateReleaseProvenanceRecord(record *ReleaseProvenanceRecord) error {
	record.ReleaseIdentity = strings.ToLower(strings.TrimSpace(record.ReleaseIdentity))
	record.SchemaVersion = strings.TrimSpace(record.SchemaVersion)
	record.ContentDigest = strings.ToLower(strings.TrimSpace(record.ContentDigest))
	record.RegistryRepository = strings.TrimSpace(record.RegistryRepository)
	record.ManifestDigest = strings.ToLower(strings.TrimSpace(record.ManifestDigest))
	record.SBOMDigest = strings.ToLower(strings.TrimSpace(record.SBOMDigest))
	record.ProvenanceDigest = strings.ToLower(strings.TrimSpace(record.ProvenanceDigest))
	record.SignedEventID = strings.ToLower(strings.TrimSpace(record.SignedEventID))
	record.SignedEventJSON = strings.TrimSpace(record.SignedEventJSON)
	if !strings.HasPrefix(record.ReleaseIdentity, ReleaseIdentityPrefix) ||
		!releaseHex64.MatchString(strings.TrimPrefix(record.ReleaseIdentity, ReleaseIdentityPrefix)) {
		return fmt.Errorf("valid HiveCI release identity is required")
	}
	if record.SchemaVersion != ReleaseProvenanceSchemaV1 ||
		!releaseOCIDigest.MatchString(record.ContentDigest) ||
		!releaseOCIDigest.MatchString(record.ManifestDigest) ||
		!releaseOCIDigest.MatchString(record.SBOMDigest) ||
		!releaseOCIDigest.MatchString(record.ProvenanceDigest) {
		return fmt.Errorf("complete release provenance schema and SHA-256 digests are required")
	}
	if record.RegistryRepository == "" || strings.ContainsAny(record.RegistryRepository, "\x00\r\n\t") {
		return fmt.Errorf("registry repository is required")
	}
	if !releaseHex64.MatchString(record.SignedEventID) || !json.Valid([]byte(record.SignedEventJSON)) {
		return fmt.Errorf("complete signed release event is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	return nil
}

const sqliteReleaseDDL = `CREATE TABLE IF NOT EXISTS hiveci_release_provenance (
	release_identity TEXT PRIMARY KEY,
	schema_version TEXT NOT NULL,
	content_digest TEXT NOT NULL,
	registry_repository TEXT NOT NULL,
	manifest_digest TEXT NOT NULL,
	sbom_digest TEXT NOT NULL,
	provenance_digest TEXT NOT NULL,
	signed_event_id TEXT NOT NULL UNIQUE,
	signed_event_json TEXT NOT NULL,
	created_at INTEGER NOT NULL
)`

const sqliteReleaseQuarantineDDL = `CREATE TABLE IF NOT EXISTS hiveci_release_quarantine (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	release_identity TEXT NOT NULL,
	existing_content_digest TEXT NOT NULL,
	conflicting_content_digest TEXT NOT NULL,
	candidate_json TEXT NOT NULL,
	reason TEXT NOT NULL,
	quarantined_at INTEGER NOT NULL,
	UNIQUE(release_identity, conflicting_content_digest)
)`

func (s *SQLiteStore) EnsureReleaseProvenanceTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	for _, stmt := range []string{
		sqliteReleaseDDL,
		sqliteReleaseQuarantineDDL,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_release_quarantine_identity
			ON hiveci_release_quarantine(release_identity, quarantined_at, id)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize HiveCI release provenance persistence: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) GetReleaseProvenance(ctx context.Context, identity string) (ReleaseProvenanceRecord, error) {
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return ReleaseProvenanceRecord{}, err
	}
	return scanReleaseProvenance(s.db.QueryRowContext(ctx, `SELECT release_identity,
		schema_version, content_digest, registry_repository, manifest_digest, sbom_digest,
		provenance_digest, signed_event_id, signed_event_json, created_at
		FROM hiveci_release_provenance WHERE release_identity = ?`, strings.ToLower(strings.TrimSpace(identity))))
}

func (s *SQLiteStore) CommitReleaseProvenance(ctx context.Context, candidate ReleaseProvenanceRecord) (ReleaseCommitResult, error) {
	if err := validateReleaseProvenanceRecord(&candidate); err != nil {
		return ReleaseCommitResult{}, err
	}
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return ReleaseCommitResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_release_provenance(
		release_identity, schema_version, content_digest, registry_repository, manifest_digest,
		sbom_digest, provenance_digest, signed_event_id, signed_event_json, created_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, candidate.ReleaseIdentity, candidate.SchemaVersion,
		candidate.ContentDigest, candidate.RegistryRepository, candidate.ManifestDigest,
		candidate.SBOMDigest, candidate.ProvenanceDigest, candidate.SignedEventID,
		candidate.SignedEventJSON, candidate.CreatedAt.UTC().Unix())
	if err != nil {
		return ReleaseCommitResult{}, fmt.Errorf("commit release provenance: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	if inserted == 1 {
		if err := tx.Commit(); err != nil {
			return ReleaseCommitResult{}, err
		}
		return ReleaseCommitResult{Record: candidate}, nil
	}
	existing, err := scanReleaseProvenance(tx.QueryRowContext(ctx, `SELECT release_identity,
		schema_version, content_digest, registry_repository, manifest_digest, sbom_digest,
		provenance_digest, signed_event_id, signed_event_json, created_at
		FROM hiveci_release_provenance WHERE release_identity = ?`, candidate.ReleaseIdentity))
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	if existing.ContentDigest == candidate.ContentDigest {
		if err := tx.Commit(); err != nil {
			return ReleaseCommitResult{}, err
		}
		return ReleaseCommitResult{Record: existing, Replay: true}, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_release_quarantine(
		release_identity, existing_content_digest, conflicting_content_digest,
		candidate_json, reason, quarantined_at
	) VALUES(?, ?, ?, ?, ?, ?)`, candidate.ReleaseIdentity, existing.ContentDigest,
		candidate.ContentDigest, candidate.SignedEventJSON, releaseConflictQuarantineMsg,
		time.Now().UTC().Unix()); err != nil {
		return ReleaseCommitResult{}, fmt.Errorf("quarantine release conflict: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ReleaseCommitResult{}, err
	}
	return ReleaseCommitResult{}, &ReleaseProvenanceConflictError{ReleaseIdentity: candidate.ReleaseIdentity}
}

func (s *SQLiteStore) ListReleaseQuarantine(ctx context.Context, identity string) ([]ReleaseQuarantineRecord, error) {
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, release_identity, existing_content_digest,
		conflicting_content_digest, candidate_json, reason, quarantined_at
		FROM hiveci_release_quarantine WHERE release_identity = ? ORDER BY id`,
		strings.ToLower(strings.TrimSpace(identity)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReleaseQuarantineRows(rows)
}

func (s *SQLiteStore) QuarantineReleaseConflict(ctx context.Context, identity, contentDigest, candidateJSON string) error {
	identity = strings.ToLower(strings.TrimSpace(identity))
	contentDigest = strings.ToLower(strings.TrimSpace(contentDigest))
	candidateJSON = strings.TrimSpace(candidateJSON)
	if !strings.HasPrefix(identity, ReleaseIdentityPrefix) ||
		!releaseHex64.MatchString(strings.TrimPrefix(identity, ReleaseIdentityPrefix)) ||
		!releaseOCIDigest.MatchString(contentDigest) || !json.Valid([]byte(candidateJSON)) {
		return fmt.Errorf("valid conflicting release candidate is required")
	}
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT content_digest FROM hiveci_release_provenance
		WHERE release_identity = ?`, identity).Scan(&existing); err != nil {
		return err
	}
	if existing == contentDigest {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_release_quarantine(
		release_identity, existing_content_digest, conflicting_content_digest,
		candidate_json, reason, quarantined_at
	) VALUES(?, ?, ?, ?, ?, ?)`, identity, existing, contentDigest, candidateJSON,
		releaseConflictQuarantineMsg, time.Now().UTC().Unix()); err != nil {
		return fmt.Errorf("quarantine release conflict: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return &ReleaseProvenanceConflictError{ReleaseIdentity: identity}
}

const postgresReleaseDDL = `CREATE TABLE IF NOT EXISTS hiveci_release_provenance (
	release_identity TEXT PRIMARY KEY,
	schema_version TEXT NOT NULL,
	content_digest TEXT NOT NULL,
	registry_repository TEXT NOT NULL,
	manifest_digest TEXT NOT NULL,
	sbom_digest TEXT NOT NULL,
	provenance_digest TEXT NOT NULL,
	signed_event_id TEXT NOT NULL UNIQUE,
	signed_event_json TEXT NOT NULL,
	created_at BIGINT NOT NULL
)`

const postgresReleaseQuarantineDDL = `CREATE TABLE IF NOT EXISTS hiveci_release_quarantine (
	id BIGSERIAL PRIMARY KEY,
	release_identity TEXT NOT NULL,
	existing_content_digest TEXT NOT NULL,
	conflicting_content_digest TEXT NOT NULL,
	candidate_json TEXT NOT NULL,
	reason TEXT NOT NULL,
	quarantined_at BIGINT NOT NULL,
	UNIQUE(release_identity, conflicting_content_digest)
)`

func (s *PostgresStore) EnsureReleaseProvenanceTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres store is not configured")
	}
	for _, stmt := range []string{
		postgresReleaseDDL,
		postgresReleaseQuarantineDDL,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_release_quarantine_identity
			ON hiveci_release_quarantine(release_identity, quarantined_at, id)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize HiveCI release provenance persistence: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) GetReleaseProvenance(ctx context.Context, identity string) (ReleaseProvenanceRecord, error) {
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return ReleaseProvenanceRecord{}, err
	}
	return scanReleaseProvenance(s.db.QueryRowContext(ctx, `SELECT release_identity,
		schema_version, content_digest, registry_repository, manifest_digest, sbom_digest,
		provenance_digest, signed_event_id, signed_event_json, created_at
		FROM hiveci_release_provenance WHERE release_identity = $1`, strings.ToLower(strings.TrimSpace(identity))))
}

func (s *PostgresStore) CommitReleaseProvenance(ctx context.Context, candidate ReleaseProvenanceRecord) (ReleaseCommitResult, error) {
	if err := validateReleaseProvenanceRecord(&candidate); err != nil {
		return ReleaseCommitResult{}, err
	}
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return ReleaseCommitResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO hiveci_release_provenance(
		release_identity, schema_version, content_digest, registry_repository, manifest_digest,
		sbom_digest, provenance_digest, signed_event_id, signed_event_json, created_at
	) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	ON CONFLICT(release_identity) DO NOTHING`, candidate.ReleaseIdentity, candidate.SchemaVersion,
		candidate.ContentDigest, candidate.RegistryRepository, candidate.ManifestDigest,
		candidate.SBOMDigest, candidate.ProvenanceDigest, candidate.SignedEventID,
		candidate.SignedEventJSON, candidate.CreatedAt.UTC().Unix())
	if err != nil {
		return ReleaseCommitResult{}, fmt.Errorf("commit release provenance: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	if inserted == 1 {
		if err := tx.Commit(); err != nil {
			return ReleaseCommitResult{}, err
		}
		return ReleaseCommitResult{Record: candidate}, nil
	}
	existing, err := scanReleaseProvenance(tx.QueryRowContext(ctx, `SELECT release_identity,
		schema_version, content_digest, registry_repository, manifest_digest, sbom_digest,
		provenance_digest, signed_event_id, signed_event_json, created_at
		FROM hiveci_release_provenance WHERE release_identity = $1 FOR UPDATE`, candidate.ReleaseIdentity))
	if err != nil {
		return ReleaseCommitResult{}, err
	}
	if existing.ContentDigest == candidate.ContentDigest {
		if err := tx.Commit(); err != nil {
			return ReleaseCommitResult{}, err
		}
		return ReleaseCommitResult{Record: existing, Replay: true}, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hiveci_release_quarantine(
		release_identity, existing_content_digest, conflicting_content_digest,
		candidate_json, reason, quarantined_at
	) VALUES($1, $2, $3, $4, $5, $6)
	ON CONFLICT(release_identity, conflicting_content_digest) DO NOTHING`,
		candidate.ReleaseIdentity, existing.ContentDigest, candidate.ContentDigest,
		candidate.SignedEventJSON, releaseConflictQuarantineMsg, time.Now().UTC().Unix()); err != nil {
		return ReleaseCommitResult{}, fmt.Errorf("quarantine release conflict: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ReleaseCommitResult{}, err
	}
	return ReleaseCommitResult{}, &ReleaseProvenanceConflictError{ReleaseIdentity: candidate.ReleaseIdentity}
}

func (s *PostgresStore) ListReleaseQuarantine(ctx context.Context, identity string) ([]ReleaseQuarantineRecord, error) {
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, release_identity, existing_content_digest,
		conflicting_content_digest, candidate_json, reason, quarantined_at
		FROM hiveci_release_quarantine WHERE release_identity = $1 ORDER BY id`,
		strings.ToLower(strings.TrimSpace(identity)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReleaseQuarantineRows(rows)
}

func (s *PostgresStore) QuarantineReleaseConflict(ctx context.Context, identity, contentDigest, candidateJSON string) error {
	identity = strings.ToLower(strings.TrimSpace(identity))
	contentDigest = strings.ToLower(strings.TrimSpace(contentDigest))
	candidateJSON = strings.TrimSpace(candidateJSON)
	if !strings.HasPrefix(identity, ReleaseIdentityPrefix) ||
		!releaseHex64.MatchString(strings.TrimPrefix(identity, ReleaseIdentityPrefix)) ||
		!releaseOCIDigest.MatchString(contentDigest) || !json.Valid([]byte(candidateJSON)) {
		return fmt.Errorf("valid conflicting release candidate is required")
	}
	if err := s.EnsureReleaseProvenanceTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	if err := tx.QueryRowContext(ctx, `SELECT content_digest FROM hiveci_release_provenance
		WHERE release_identity = $1 FOR UPDATE`, identity).Scan(&existing); err != nil {
		return err
	}
	if existing == contentDigest {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hiveci_release_quarantine(
		release_identity, existing_content_digest, conflicting_content_digest,
		candidate_json, reason, quarantined_at
	) VALUES($1, $2, $3, $4, $5, $6)
	ON CONFLICT(release_identity, conflicting_content_digest) DO NOTHING`,
		identity, existing, contentDigest, candidateJSON, releaseConflictQuarantineMsg,
		time.Now().UTC().Unix()); err != nil {
		return fmt.Errorf("quarantine release conflict: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return &ReleaseProvenanceConflictError{ReleaseIdentity: identity}
}

type releaseRowScanner interface {
	Scan(...any) error
}

func scanReleaseProvenance(row releaseRowScanner) (ReleaseProvenanceRecord, error) {
	var record ReleaseProvenanceRecord
	var createdAt int64
	err := row.Scan(&record.ReleaseIdentity, &record.SchemaVersion, &record.ContentDigest,
		&record.RegistryRepository, &record.ManifestDigest, &record.SBOMDigest,
		&record.ProvenanceDigest, &record.SignedEventID, &record.SignedEventJSON, &createdAt)
	if err != nil {
		return ReleaseProvenanceRecord{}, err
	}
	record.CreatedAt = time.Unix(createdAt, 0).UTC()
	if err := validateReleaseProvenanceRecord(&record); err != nil {
		return ReleaseProvenanceRecord{}, fmt.Errorf("stored release provenance is invalid: %w", err)
	}
	return record, nil
}

type releaseRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func scanReleaseQuarantineRows(rows releaseRows) ([]ReleaseQuarantineRecord, error) {
	var records []ReleaseQuarantineRecord
	for rows.Next() {
		var record ReleaseQuarantineRecord
		var quarantinedAt int64
		if err := rows.Scan(&record.ID, &record.ReleaseIdentity, &record.ExistingContentDigest,
			&record.ConflictingContentDigest, &record.CandidateJSON, &record.Reason,
			&quarantinedAt); err != nil {
			return nil, err
		}
		record.QuarantinedAt = time.Unix(quarantinedAt, 0).UTC()
		records = append(records, record)
	}
	return records, rows.Err()
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	DomainAffiliationVerified        = "verified"
	DomainAffiliationStale           = "stale"
	DomainAffiliationConfirmedAbsent = "confirmed_absent"

	DomainFailureConfirmedAbsent = "confirmed_absent"
	DomainFailureIndeterminate   = "indeterminate"
)

// DomainAffiliation is structured, durable evidence of a pubkey's current
// relationship with an exact NIP-05 host. It is intentionally independent of
// the derived Gitea namespace stored on NostrIdentityLink.
type DomainAffiliation struct {
	CanonicalIdentifier string    `json:"canonical_identifier,omitempty"`
	LocalPart           string    `json:"local_part,omitempty"`
	Host                string    `json:"host,omitempty"`
	Pubkey              string    `json:"pubkey"`
	VerifiedAt          time.Time `json:"verified_at,omitempty"`
	CheckedAt           time.Time `json:"checked_at"`
	Status              string    `json:"status"`
	FailureClass        string    `json:"failure_class,omitempty"`
	FailureCode         string    `json:"failure_code,omitempty"`
	FailureDetail       string    `json:"failure_detail,omitempty"`
}

func (s *SQLiteStore) UpsertDomainAffiliation(ctx context.Context, a DomainAffiliation) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_affiliations(canonical_identifier, local_part, host, pubkey, verified_at, checked_at, status, failure_class, failure_code, failure_detail)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			canonical_identifier=excluded.canonical_identifier,
			local_part=excluded.local_part,
			host=excluded.host,
			verified_at=excluded.verified_at,
			checked_at=excluded.checked_at,
			status=excluded.status,
			failure_class=excluded.failure_class,
			failure_code=excluded.failure_code,
			failure_detail=excluded.failure_detail
		WHERE domain_affiliations.checked_at <= excluded.checked_at
	`, a.CanonicalIdentifier, a.LocalPart, a.Host, a.Pubkey, affiliationTime(a.VerifiedAt), affiliationTime(a.CheckedAt),
		a.Status, a.FailureClass, a.FailureCode, a.FailureDetail)
	return err
}

func (s *SQLiteStore) GetDomainAffiliation(ctx context.Context, pubkey string) (DomainAffiliation, error) {
	return scanDomainAffiliation(s.db.QueryRowContext(ctx, domainAffiliationSelect+` WHERE pubkey = ?`, pubkey))
}

func (s *SQLiteStore) ListVerifiedDomainAffiliations(ctx context.Context, host string, checkedAfter time.Time, limit int) ([]DomainAffiliation, error) {
	rows, err := s.db.QueryContext(ctx, domainAffiliationSelect+` WHERE host = ? AND status = ? AND checked_at >= ? ORDER BY pubkey LIMIT ?`,
		host, DomainAffiliationVerified, affiliationTime(checkedAfter), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDomainAffiliations(rows)
}

func (s *PostgresStore) UpsertDomainAffiliation(ctx context.Context, a DomainAffiliation) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_affiliations(canonical_identifier, local_part, host, pubkey, verified_at, checked_at, status, failure_class, failure_code, failure_detail)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT(pubkey) DO UPDATE SET
			canonical_identifier=excluded.canonical_identifier,
			local_part=excluded.local_part,
			host=excluded.host,
			verified_at=excluded.verified_at,
			checked_at=excluded.checked_at,
			status=excluded.status,
			failure_class=excluded.failure_class,
			failure_code=excluded.failure_code,
			failure_detail=excluded.failure_detail
		WHERE domain_affiliations.checked_at <= excluded.checked_at
	`, a.CanonicalIdentifier, a.LocalPart, a.Host, a.Pubkey, affiliationTime(a.VerifiedAt), affiliationTime(a.CheckedAt),
		a.Status, a.FailureClass, a.FailureCode, a.FailureDetail)
	return err
}

func (s *PostgresStore) GetDomainAffiliation(ctx context.Context, pubkey string) (DomainAffiliation, error) {
	return scanDomainAffiliation(s.db.QueryRowContext(ctx, domainAffiliationSelect+` WHERE pubkey = $1`, pubkey))
}

func (s *PostgresStore) ListVerifiedDomainAffiliations(ctx context.Context, host string, checkedAfter time.Time, limit int) ([]DomainAffiliation, error) {
	rows, err := s.db.QueryContext(ctx, domainAffiliationSelect+` WHERE host = $1 AND status = $2 AND checked_at >= $3 ORDER BY pubkey LIMIT $4`,
		host, DomainAffiliationVerified, affiliationTime(checkedAfter), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDomainAffiliations(rows)
}

const domainAffiliationSelect = `SELECT canonical_identifier, local_part, host, pubkey, verified_at, checked_at, status, failure_class, failure_code, failure_detail FROM domain_affiliations`

type affiliationScanner interface {
	Scan(dest ...any) error
}

func scanDomainAffiliation(row affiliationScanner) (DomainAffiliation, error) {
	var a DomainAffiliation
	var verifiedAt, checkedAt string
	if err := row.Scan(&a.CanonicalIdentifier, &a.LocalPart, &a.Host, &a.Pubkey, &verifiedAt, &checkedAt,
		&a.Status, &a.FailureClass, &a.FailureCode, &a.FailureDetail); err != nil {
		return DomainAffiliation{}, err
	}
	var err error
	if verifiedAt != "" {
		a.VerifiedAt, err = time.Parse(time.RFC3339, verifiedAt)
		if err != nil {
			return DomainAffiliation{}, fmt.Errorf("parse domain affiliation verified_at: %w", err)
		}
	}
	a.CheckedAt, err = time.Parse(time.RFC3339, checkedAt)
	if err != nil {
		return DomainAffiliation{}, fmt.Errorf("parse domain affiliation checked_at: %w", err)
	}
	return a, nil
}

func scanDomainAffiliations(rows *sql.Rows) ([]DomainAffiliation, error) {
	result := make([]DomainAffiliation, 0)
	for rows.Next() {
		a, err := scanDomainAffiliation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func affiliationTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

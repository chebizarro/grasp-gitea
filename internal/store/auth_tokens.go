// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Bridge token lifecycle states derived from row fields.
const (
	BridgeTokenStateActive  = "active"
	BridgeTokenStateExpired = "expired"
	BridgeTokenStateRevoked = "revoked"
)

// Gitea hidden-PAT credential states.
const (
	PATStateProvisioning = "provisioning"
	PATStateActive       = "active"
	PATStateRetiring     = "retiring"
	PATStateOrphaned     = "orphaned"
	PATStateError        = "error"
)

// ErrBridgeTokenLimit is returned when a pubkey already holds the maximum
// number of active bridge tokens.
var ErrBridgeTokenLimit = errors.New("active bridge token limit reached")

// ErrBridgeTokenNotFound is returned for missing or non-owned tokens.
var ErrBridgeTokenNotFound = errors.New("bridge token not found")

// BridgeToken is an opaque grasp_v1_ credential accepted at the proxy edge.
// Only the SHA-256 digest of the plaintext token is persisted.
type BridgeToken struct {
	ID             string    `json:"id"`
	TokenHash      []byte    `json:"-"`
	TokenSuffix    string    `json:"token_suffix"`
	Pubkey         string    `json:"pubkey"`
	GiteaUserID    int64     `json:"gitea_user_id"`
	Name           string    `json:"name"`
	Scopes         []string  `json:"scopes"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
	LastUsedAt     time.Time `json:"last_used_at,omitempty"`
	CreatedEventID string    `json:"-"`
}

// State derives the lifecycle state at the supplied instant.
func (t BridgeToken) State(now time.Time) string {
	if !t.RevokedAt.IsZero() {
		return BridgeTokenStateRevoked
	}
	if !now.Before(t.ExpiresAt) {
		return BridgeTokenStateExpired
	}
	return BridgeTokenStateActive
}

// GiteaPATCredential is the encrypted hidden Gitea PAT backing one Gitea user.
type GiteaPATCredential struct {
	GiteaUserID    int64
	Generation     int64
	GiteaUser      string
	PATName        string
	GiteaTokenID   int64
	Ciphertext     []byte
	KeyID          string
	GiteaScopes    []string
	State          string
	CreatedAt      time.Time
	ActivatedAt    time.Time
	RetiredAt      time.Time
	DeleteAttempts int
	LastError      string
}

// AuthAuditEvent is an append-only record of authentication activity. It must
// never contain token plaintext, PATs, Authorization headers, or raw events.
type AuthAuditEvent struct {
	OccurredAt        time.Time
	EventType         string
	Pubkey            string
	TokenID           string
	GiteaUserID       int64
	Surface           string
	Action            string
	Outcome           string
	RequestID         string
	SourceFingerprint string
	Detail            string
}

// InsertBridgeToken stores a new token, enforcing the per-pubkey active limit
// with a single conditional INSERT so concurrent mints cannot both pass a
// separate count check. maxActive <= 0 disables the limit.
func (s *SQLiteStore) InsertBridgeToken(ctx context.Context, t BridgeToken, maxActive int) error {
	scopes, err := marshalScopeList(t.Scopes)
	if err != nil {
		return err
	}
	issued := t.IssuedAt.UTC().Format(time.RFC3339)
	expires := t.ExpiresAt.UTC().Format(time.RFC3339)

	if maxActive <= 0 {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO bridge_tokens(id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, created_event_id)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, t.ID, t.TokenHash, t.TokenSuffix, t.Pubkey, t.GiteaUserID, t.Name, scopes, issued, expires, t.CreatedEventID); err != nil {
			return fmt.Errorf("insert bridge token: %w", err)
		}
		return nil
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO bridge_tokens(id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, created_event_id)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE (SELECT COUNT(*) FROM bridge_tokens WHERE pubkey = ? AND revoked_at = '' AND expires_at > ?) < ?
	`, t.ID, t.TokenHash, t.TokenSuffix, t.Pubkey, t.GiteaUserID, t.Name, scopes, issued, expires, t.CreatedEventID,
		t.Pubkey, issued, maxActive)
	if err != nil {
		return fmt.Errorf("insert bridge token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBridgeTokenLimit
	}
	return nil
}

// GetBridgeTokenByHash loads a token row by plaintext digest. Callers decide
// state via BridgeToken.State; revoked/expired rows are still returned.
func (s *SQLiteStore) GetBridgeTokenByHash(ctx context.Context, hash []byte) (BridgeToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, revoked_at, last_used_at, created_event_id
		FROM bridge_tokens WHERE token_hash = ?
	`, hash)
	return scanBridgeToken(row)
}

// ListBridgeTokens returns a page of the pubkey's tokens, newest first.
func (s *SQLiteStore) ListBridgeTokens(ctx context.Context, pubkey string, limit, offset int) ([]BridgeToken, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, revoked_at, last_used_at, created_event_id
		FROM bridge_tokens WHERE pubkey = ?
		ORDER BY issued_at DESC, id ASC LIMIT ? OFFSET ?
	`, pubkey, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeToken
	for rows.Next() {
		t, err := scanBridgeToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeBridgeToken marks an owned, not-yet-revoked token revoked. It returns
// ErrBridgeTokenNotFound for unknown ids, other owners, or double revocation,
// so handlers can answer 404 without an ownership oracle.
func (s *SQLiteStore) RevokeBridgeToken(ctx context.Context, pubkey, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = ?
		WHERE id = ? AND pubkey = ? AND revoked_at = ''
	`, now.UTC().Format(time.RFC3339), id, pubkey)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBridgeTokenNotFound
	}
	return nil
}

// RotateBridgeToken atomically revokes an owned active token and inserts its
// replacement. The replacement's subject (pubkey and Gitea user id) is copied
// from the revoked row so a handler mistake can never change the token
// subject during rotation. The old token remains valid if any step fails.
func (s *SQLiteStore) RotateBridgeToken(ctx context.Context, pubkey, oldID string, replacement BridgeToken, now time.Time) error {
	scopes, err := marshalScopeList(replacement.Scopes)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	nowStr := now.UTC().Format(time.RFC3339)
	var subjectPubkey string
	var subjectGiteaUserID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT pubkey, gitea_user_id FROM bridge_tokens
		WHERE id = ? AND pubkey = ? AND revoked_at = '' AND expires_at > ?
	`, oldID, pubkey, nowStr).Scan(&subjectPubkey, &subjectGiteaUserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBridgeTokenNotFound
		}
		return err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = ?
		WHERE id = ? AND pubkey = ? AND revoked_at = ''
	`, nowStr, oldID, pubkey)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBridgeTokenNotFound
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO bridge_tokens(id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, created_event_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, replacement.ID, replacement.TokenHash, replacement.TokenSuffix, subjectPubkey, subjectGiteaUserID,
		replacement.Name, scopes, replacement.IssuedAt.UTC().Format(time.RFC3339),
		replacement.ExpiresAt.UTC().Format(time.RFC3339), replacement.CreatedEventID); err != nil {
		return fmt.Errorf("insert rotated bridge token: %w", err)
	}
	return tx.Commit()
}

// RevokeBridgeTokensForGiteaUser revokes every active token mapped to a Gitea
// user (identity-link repair, orphaned account cleanup).
func (s *SQLiteStore) RevokeBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = ?
		WHERE gitea_user_id = ? AND revoked_at = ''
	`, now.UTC().Format(time.RFC3339), giteaUserID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountActiveBridgeTokensForGiteaUser supports PAT retirement decisions.
func (s *SQLiteStore) CountActiveBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM bridge_tokens
		WHERE gitea_user_id = ? AND revoked_at = '' AND expires_at > ?
	`, giteaUserID, now.UTC().Format(time.RFC3339)).Scan(&n)
	return n, err
}

// TouchBridgeTokenUsage records last_used_at only when the previous value is
// older than cutoff. The condition lives in SQL so concurrent proxy requests
// that all observe the same stale value still produce a single write.
func (s *SQLiteStore) TouchBridgeTokenUsage(ctx context.Context, id string, now, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET last_used_at = ?
		WHERE id = ? AND (last_used_at = '' OR last_used_at <= ?)
	`, now.UTC().Format(time.RFC3339), id, cutoff.UTC().Format(time.RFC3339))
	return err
}

// ResealPATCredential swaps a PAT's ciphertext to a new key, but only if the
// row still holds the ciphertext the caller decrypted (compare-and-swap), so
// a concurrent rotation is never clobbered.
func (s *SQLiteStore) ResealPATCredential(ctx context.Context, giteaUserID, generation int64, expectedCiphertext, ciphertext []byte, keyID string) (int64, error) {
	if len(ciphertext) == 0 || keyID == "" {
		return 0, fmt.Errorf("pat reseal requires ciphertext and key id")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET pat_ciphertext = ?, key_id = ?
		WHERE gitea_user_id = ? AND generation = ? AND pat_ciphertext = ?
	`, ciphertext, keyID, giteaUserID, generation, expectedCiphertext)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListGiteaUsersWithoutActiveTokens returns Gitea user ids that hold an active
// PAT but no unexpired, unrevoked bridge token, mapped to the most recent
// instant any of their tokens was still usable. Retirement grace is measured
// from that instant. A token ceases to be usable when it is revoked or when
// it expires, whichever happens first — a revoked token's later expires_at is
// not a usable moment.
func (s *SQLiteStore) ListGiteaUsersWithoutActiveTokens(ctx context.Context, now time.Time, limit int) (map[int64]time.Time, error) {
	if limit <= 0 {
		limit = 100
	}
	nowStr := now.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.gitea_user_id, COALESCE(MAX(
			CASE WHEN t.revoked_at != '' AND t.revoked_at < t.expires_at
			     THEN t.revoked_at ELSE t.expires_at END), '')
		FROM gitea_pat_credentials c
		LEFT JOIN bridge_tokens t ON t.gitea_user_id = c.gitea_user_id
		WHERE c.state = ?
		  AND NOT EXISTS (
			SELECT 1 FROM bridge_tokens a
			WHERE a.gitea_user_id = c.gitea_user_id AND a.revoked_at = '' AND a.expires_at > ?
		  )
		GROUP BY c.gitea_user_id
		LIMIT ?
	`, PATStateActive, nowStr, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[int64]time.Time{}
	for rows.Next() {
		var userID int64
		var lastUsable string
		if err := rows.Scan(&userID, &lastUsable); err != nil {
			return nil, err
		}
		var since time.Time
		if lastUsable != "" {
			parsed, err := time.Parse(time.RFC3339, lastUsable)
			if err != nil {
				return nil, fmt.Errorf("parse token retirement basis for user %d: %w", userID, err)
			}
			since = parsed
		}
		out[userID] = since
	}
	return out, rows.Err()
}

// RetireActivePATCredential moves a user's active PAT into the pending
// deletion queue (state retiring, retired_at unset).
func (s *SQLiteStore) RetireActivePATCredential(ctx context.Context, giteaUserID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = ?, retired_at = ''
		WHERE gitea_user_id = ? AND state = ?
	`, PATStateRetiring, giteaUserID, PATStateActive)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReservePATCredential atomically assigns the next generation for a Gitea
// user and persists a provisioning placeholder row. The returned generation
// and PAT name ("<prefix>-<userID>-<generation>") are definitive, so callers
// encrypt the PAT plaintext with AAD bound to them and then call
// FinalizePATCredential. The generation is computed inside the INSERT itself;
// concurrent reservations cannot observe the same value.
func (s *SQLiteStore) ReservePATCredential(ctx context.Context, giteaUserID int64, giteaUser, namePrefix string, giteaScopes []string, now time.Time) (generation int64, patName string, err error) {
	scopes, err := marshalScopeList(giteaScopes)
	if err != nil {
		return 0, "", err
	}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO gitea_pat_credentials(gitea_user_id, generation, gitea_user, pat_name, pat_ciphertext, key_id, gitea_scopes, state, created_at)
		SELECT ?, g.next, ?, ? || '-' || CAST(? AS TEXT) || '-' || CAST(g.next AS TEXT), X'', '', ?, ?, ?
		FROM (SELECT COALESCE(MAX(generation), 0) + 1 AS next FROM gitea_pat_credentials WHERE gitea_user_id = ?) AS g
		RETURNING generation, pat_name
	`, giteaUserID, giteaUser, namePrefix, giteaUserID, scopes, PATStateProvisioning,
		now.UTC().Format(time.RFC3339), giteaUserID).Scan(&generation, &patName)
	if err != nil {
		return 0, "", fmt.Errorf("reserve pat credential: %w", err)
	}
	return generation, patName, nil
}

// FinalizePATCredential stores the encrypted PAT plaintext and Gitea's
// numeric token id on a reserved provisioning row.
func (s *SQLiteStore) FinalizePATCredential(ctx context.Context, giteaUserID, generation, giteaTokenID int64, ciphertext []byte, keyID string) error {
	if len(ciphertext) == 0 || keyID == "" {
		return fmt.Errorf("pat finalization requires ciphertext and key id")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET pat_ciphertext = ?, key_id = ?, gitea_token_id = ?
		WHERE gitea_user_id = ? AND generation = ? AND state = ?
	`, ciphertext, keyID, giteaTokenID, giteaUserID, generation, PATStateProvisioning)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("pat credential user=%d generation=%d is not provisioning", giteaUserID, generation)
	}
	return nil
}

// ActivatePATCredential promotes a finalized provisioning PAT to active and
// demotes any previously active PAT to retiring, atomically
// (create-before-retire). Activation requires prior finalization so an active
// row always carries usable ciphertext.
func (s *SQLiteStore) ActivatePATCredential(ctx context.Context, giteaUserID, generation int64, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	nowStr := now.UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = ?, retired_at = ''
		WHERE gitea_user_id = ? AND state = ?
	`, PATStateRetiring, giteaUserID, PATStateActive); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = ?, activated_at = ?
		WHERE gitea_user_id = ? AND generation = ? AND state = ? AND length(pat_ciphertext) > 0 AND key_id != ''
	`, PATStateActive, nowStr, giteaUserID, generation, PATStateProvisioning)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("pat credential user=%d generation=%d is not a finalized provisioning row", giteaUserID, generation)
	}
	return tx.Commit()
}

// GetActivePATCredential loads the single active PAT for a Gitea user.
func (s *SQLiteStore) GetActivePATCredential(ctx context.Context, giteaUserID int64) (GiteaPATCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials WHERE gitea_user_id = ? AND state = ?
	`, giteaUserID, PATStateActive)
	return scanPATCredential(row)
}

// ListPATCredentialsPendingDeletion returns retiring rows whose Gitea-side
// token has not been deleted yet (retired_at unset), so reconciliation never
// re-deletes already-retired PATs.
func (s *SQLiteStore) ListPATCredentialsPendingDeletion(ctx context.Context, limit int) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials WHERE state = ? AND retired_at = ''
		ORDER BY created_at ASC LIMIT ?
	`, PATStateRetiring, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GiteaPATCredential
	for rows.Next() {
		cred, err := scanPATCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

// ListPATCredentialsUnderStaleKey returns credentials whose ciphertext is
// sealed under a key other than the active one, so a proactive sweep can
// re-encrypt them and let retired credential keys be removed from the ring.
// Only states that must remain decryptable are considered.
func (s *SQLiteStore) ListPATCredentialsUnderStaleKey(ctx context.Context, activeKeyID string, limit int) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials
		WHERE key_id != ? AND key_id != '' AND length(pat_ciphertext) > 0
		  AND (state = ? OR (state = ? AND retired_at = ''))
		ORDER BY created_at ASC LIMIT ?
	`, activeKeyID, PATStateActive, PATStateRetiring, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GiteaPATCredential
	for rows.Next() {
		cred, err := scanPATCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

// ListStalePATCredentialsInState returns rows in a given state created before
// `before`, so a reconciliation sweep can recover work stranded by a crash
// (e.g. a provisioning row never finalized) without racing a fresh in-flight
// row.
func (s *SQLiteStore) ListStalePATCredentialsInState(ctx context.Context, state string, before time.Time, limit int) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials
		WHERE state = ? AND created_at < ?
		ORDER BY created_at ASC LIMIT ?
	`, state, before.UTC().Format(time.RFC3339), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GiteaPATCredential
	for rows.Next() {
		cred, err := scanPATCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

// ListTerminalPATCredentials returns error/orphaned rows for reconciliation,
// ordered by delete_attempts ascending so a permanently-failing row drops to
// the back of the queue and never starves rows behind it (fair retry).
func (s *SQLiteStore) ListTerminalPATCredentials(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials WHERE state = ?
		ORDER BY delete_attempts ASC, created_at ASC LIMIT ?
	`, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GiteaPATCredential
	for rows.Next() {
		cred, err := scanPATCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

// RecordTerminalDeleteFailure bumps delete_attempts and records the error
// while preserving the row's terminal state, so failing rows sort to the
// back of the fair-retry queue.
func (s *SQLiteStore) RecordTerminalDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials
		SET delete_attempts = delete_attempts + 1, last_error = ?
		WHERE gitea_user_id = ? AND generation = ?
	`, lastError, giteaUserID, generation)
	return err
}

// DeletePATCredential removes a terminal reconciled row after its Gitea PAT
// is confirmed gone. Used by the reconciliation sweep to clear error and
// orphaned rows once their Gitea-side deletion succeeds.
func (s *SQLiteStore) DeletePATCredential(ctx context.Context, giteaUserID, generation int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM gitea_pat_credentials WHERE gitea_user_id = ? AND generation = ?
	`, giteaUserID, generation)
	return err
}

// ListPATCredentialsByState supports cleanup/reconciliation sweeps.
func (s *SQLiteStore) ListPATCredentialsByState(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error
		FROM gitea_pat_credentials WHERE state = ?
		ORDER BY created_at ASC LIMIT ?
	`, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GiteaPATCredential
	for rows.Next() {
		cred, err := scanPATCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

// SetPATCredentialState transitions a PAT row and records an optional error.
func (s *SQLiteStore) SetPATCredentialState(ctx context.Context, giteaUserID, generation int64, state, lastError string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = ?, last_error = ?
		WHERE gitea_user_id = ? AND generation = ?
	`, state, lastError, giteaUserID, generation)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("pat credential user=%d generation=%d not found", giteaUserID, generation)
	}
	return nil
}

// MarkPATCredentialRetired records completed Gitea-side deletion of a PAT.
// Completion is denoted by state='retiring' with a non-empty retired_at;
// rows still awaiting deletion have state='retiring' and retired_at=”.
func (s *SQLiteStore) MarkPATCredentialRetired(ctx context.Context, giteaUserID, generation int64, now time.Time) error {
	return s.setPATRetirement(ctx, giteaUserID, generation, now, "")
}

// RecordPATDeleteFailure increments the delete counter and stores the error.
func (s *SQLiteStore) RecordPATDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET delete_attempts = delete_attempts + 1, last_error = ?
		WHERE gitea_user_id = ? AND generation = ?
	`, lastError, giteaUserID, generation)
	return err
}

func (s *SQLiteStore) setPATRetirement(ctx context.Context, giteaUserID, generation int64, now time.Time, lastError string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = ?, retired_at = ?, last_error = ?
		WHERE gitea_user_id = ? AND generation = ?
	`, PATStateRetiring, now.UTC().Format(time.RFC3339), lastError, giteaUserID, generation)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("pat credential user=%d generation=%d not found", giteaUserID, generation)
	}
	return nil
}

// ClaimNIP98Event atomically claims a verified NIP-98 event id. It returns
// false when the event was already consumed (replay).
func (s *SQLiteStore) ClaimNIP98Event(ctx context.Context, eventID, pubkey, method string, targetHash []byte, now, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO nip98_replay_claims(event_id, pubkey, method, target_hash, claimed_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?)
	`, eventID, pubkey, method, targetHash,
		now.UTC().Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// CleanupExpiredReplayClaims deletes claims whose freshness window has passed.
func (s *SQLiteStore) CleanupExpiredReplayClaims(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM nip98_replay_claims WHERE expires_at <= ?
	`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertAuthAuditEvent appends one audit record.
func (s *SQLiteStore) InsertAuthAuditEvent(ctx context.Context, ev AuthAuditEvent) error {
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_audit_events(occurred_at, event_type, pubkey, token_id, gitea_user_id, surface, action, outcome, request_id, source_fingerprint, detail)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, occurred.UTC().Format(time.RFC3339), ev.EventType, ev.Pubkey, ev.TokenID, ev.GiteaUserID,
		ev.Surface, ev.Action, ev.Outcome, ev.RequestID, ev.SourceFingerprint, ev.Detail)
	return err
}

// ListAuthAuditEvents returns recent audit events of a given type, newest
// first. An empty eventType returns all types. Intended for operator/
// diagnostic reads and tests, not the hot path.
func (s *SQLiteStore) ListAuthAuditEvents(ctx context.Context, eventType string, limit int) ([]AuthAuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT occurred_at, event_type, pubkey, token_id, gitea_user_id, surface, action, outcome, request_id, source_fingerprint, detail
		FROM auth_audit_events`
	args := []any{}
	if eventType != "" {
		query += ` WHERE event_type = ?`
		args = append(args, eventType)
	}
	query += ` ORDER BY occurred_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuthAuditEvent
	for rows.Next() {
		var ev AuthAuditEvent
		var occurred string
		if err := rows.Scan(&occurred, &ev.EventType, &ev.Pubkey, &ev.TokenID, &ev.GiteaUserID,
			&ev.Surface, &ev.Action, &ev.Outcome, &ev.RequestID, &ev.SourceFingerprint, &ev.Detail); err != nil {
			return nil, err
		}
		if occurred != "" {
			ev.OccurredAt, _ = time.Parse(time.RFC3339, occurred)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// CleanupAuthAuditEvents enforces audit retention.
func (s *SQLiteStore) CleanupAuthAuditEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM auth_audit_events WHERE occurred_at < ?
	`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBridgeToken(row rowScanner) (BridgeToken, error) {
	var t BridgeToken
	var scopes, issuedAt, expiresAt, revokedAt, lastUsedAt string
	if err := row.Scan(&t.ID, &t.TokenHash, &t.TokenSuffix, &t.Pubkey, &t.GiteaUserID, &t.Name,
		&scopes, &issuedAt, &expiresAt, &revokedAt, &lastUsedAt, &t.CreatedEventID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BridgeToken{}, ErrBridgeTokenNotFound
		}
		return BridgeToken{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
		return BridgeToken{}, fmt.Errorf("decode bridge token scopes for %s: %w", t.ID, err)
	}
	var err error
	if t.IssuedAt, err = time.Parse(time.RFC3339, issuedAt); err != nil {
		return BridgeToken{}, fmt.Errorf("parse bridge token issued_at for %s: %w", t.ID, err)
	}
	if t.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return BridgeToken{}, fmt.Errorf("parse bridge token expires_at for %s: %w", t.ID, err)
	}
	if revokedAt != "" {
		if t.RevokedAt, err = time.Parse(time.RFC3339, revokedAt); err != nil {
			return BridgeToken{}, fmt.Errorf("parse bridge token revoked_at for %s: %w", t.ID, err)
		}
	}
	if lastUsedAt != "" {
		if t.LastUsedAt, err = time.Parse(time.RFC3339, lastUsedAt); err != nil {
			return BridgeToken{}, fmt.Errorf("parse bridge token last_used_at for %s: %w", t.ID, err)
		}
	}
	return t, nil
}

func scanPATCredential(row rowScanner) (GiteaPATCredential, error) {
	var cred GiteaPATCredential
	var scopes, createdAt, activatedAt, retiredAt string
	if err := row.Scan(&cred.GiteaUserID, &cred.Generation, &cred.GiteaUser, &cred.PATName,
		&cred.GiteaTokenID, &cred.Ciphertext, &cred.KeyID, &scopes, &cred.State, &createdAt, &activatedAt, &retiredAt,
		&cred.DeleteAttempts, &cred.LastError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GiteaPATCredential{}, sql.ErrNoRows
		}
		return GiteaPATCredential{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &cred.GiteaScopes); err != nil {
		return GiteaPATCredential{}, fmt.Errorf("decode pat scopes for user %d: %w", cred.GiteaUserID, err)
	}
	var err error
	if cred.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return GiteaPATCredential{}, fmt.Errorf("parse pat created_at for user %d: %w", cred.GiteaUserID, err)
	}
	if activatedAt != "" {
		if cred.ActivatedAt, err = time.Parse(time.RFC3339, activatedAt); err != nil {
			return GiteaPATCredential{}, fmt.Errorf("parse pat activated_at for user %d: %w", cred.GiteaUserID, err)
		}
	}
	if retiredAt != "" {
		if cred.RetiredAt, err = time.Parse(time.RFC3339, retiredAt); err != nil {
			return GiteaPATCredential{}, fmt.Errorf("parse pat retired_at for user %d: %w", cred.GiteaUserID, err)
		}
	}
	return cred, nil
}

func marshalScopeList(scopes []string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return "", fmt.Errorf("encode scopes: %w", err)
	}
	return string(b), nil
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore is the shared transactional AuthStore backend for
// active-active deployment (docs/designs/phase6-active-active.md). It holds
// exactly the auth state every bridge replica must agree on; the rest of the
// bridge's state stays in the node-local SQLite store.
//
// Representation matches the SQLite reference implementation byte-for-byte:
// timestamps are RFC3339 UTC TEXT (empty string = unset), scopes are JSON
// arrays, secrets are BYTEA. This keeps every comparison (” vs value,
// lexicographic time ordering) semantically identical across backends, so
// the conformance suite — not translation code — is the compatibility proof.
type PostgresStore struct {
	db *sql.DB
}

// OpenPostgres connects and ensures the auth schema. The DSN is a standard
// libpq/pgx URL, e.g. postgres://user:pass@host:5432/db?sslmode=disable.
func OpenPostgres(dsn string) (*PostgresStore, error) {
	return openPostgres(dsn, "")
}

// OpenPostgresInSchema opens the store inside a dedicated Postgres schema
// (created if absent). Tests use it to give each case a fresh namespace on
// one shared server.
func OpenPostgresInSchema(dsn, schema string) (*PostgresStore, error) {
	return openPostgres(dsn, schema)
}

func openPostgres(dsn, schema string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if schema != "" {
		if !isSafePgIdent(schema) {
			db.Close()
			return nil, fmt.Errorf("invalid postgres schema name %q", schema)
		}
		if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
		db.Close()
		// Pin the pool's connections to the schema via a connection-scoped
		// runtime option (never ALTER ROLE: that is global and racy).
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		db, err = sql.Open("pgx", dsn+sep+"options="+url.QueryEscape("-csearch_path="+schema))
		if err != nil {
			return nil, fmt.Errorf("reopen postgres in schema: %w", err)
		}
	}
	s := &PostgresStore{db: db}
	if err := s.ensureSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DropSchema removes a test schema and everything in it.
func (s *PostgresStore) DropSchema(ctx context.Context, schema string) error {
	if !isSafePgIdent(schema) {
		return fmt.Errorf("invalid postgres schema name %q", schema)
	}
	_, err := s.db.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	return err
}

// isSafePgIdent allows only lowercase alphanumerics and underscore, starting
// with a letter — schema names are interpolated into DDL.
func isSafePgIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Close releases the connection pool.
func (s *PostgresStore) Close() error { return s.db.Close() }

// Ping verifies connectivity.
func (s *PostgresStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Name and Check let the shared auth backend participate in API readiness.
func (s *PostgresStore) Name() string                    { return "postgres_auth_store" }
func (s *PostgresStore) Check(ctx context.Context) error { return s.Ping(ctx) }

// HasAuthState reports whether the store contains durable auth state.
func (s *PostgresStore) HasAuthState(ctx context.Context) (bool, error) {
	var present int
	err := s.db.QueryRowContext(ctx, `
		SELECT CASE WHEN
			EXISTS(SELECT 1 FROM nostr_identity_links) OR
			EXISTS(SELECT 1 FROM bridge_tokens) OR
			EXISTS(SELECT 1 FROM signer_grants)
		THEN 1 ELSE 0 END
	`).Scan(&present)
	return present != 0, err
}

const schemaMigrationLeaseKey = int64(0x6772_6173_705f_6464) // "grasp_dd"

func (s *PostgresStore) ensureSchema() error {
	// CREATE TABLE IF NOT EXISTS is not race-free in Postgres system catalogs
	// when two fresh replicas initialize the same schema concurrently. Serialize
	// bootstrap DDL across every process using one session advisory lock.
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("postgres schema connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLeaseKey); err != nil {
		return fmt.Errorf("postgres schema lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, schemaMigrationLeaseKey) }()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS nip98_replay_claims (
			event_id TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			method TEXT NOT NULL,
			target_hash BYTEA NOT NULL,
			claimed_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_nip98_replay_expiry ON nip98_replay_claims(expires_at);`,
		`CREATE TABLE IF NOT EXISTS auth_challenges (
			nonce TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			redirect_uri TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			consumed INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS nip46_sessions (
			session_token TEXT PRIMARY KEY,
			bunker_pubkey TEXT NOT NULL,
			client_pubkey TEXT NOT NULL,
			state TEXT NOT NULL,
			redirect_uri TEXT NOT NULL DEFAULT '',
			result_pubkey TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS bridge_signer_sessions (
			bunker_uri TEXT PRIMARY KEY,
			client_seckey_enc BYTEA NOT NULL,
			client_pubkey TEXT NOT NULL,
			signer_pubkey TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_ok_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS signer_grants (
			pubkey TEXT PRIMARY KEY,
			client_seckey_enc BYTEA NOT NULL,
			bunker_uri_enc BYTEA NOT NULL,
			relays TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL DEFAULT '',
			granted_at TEXT NOT NULL,
			revoked_at TEXT NOT NULL DEFAULT '',
			last_ok_at TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active'
		);`,
		`CREATE TABLE IF NOT EXISTS nostr_identity_links (
			pubkey TEXT PRIMARY KEY,
			npub TEXT NOT NULL,
			gitea_user_id BIGINT NOT NULL UNIQUE,
			gitea_user TEXT NOT NULL,
			nip05 TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS domain_affiliations (
			canonical_identifier TEXT NOT NULL DEFAULT '',
			local_part TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT '',
			pubkey TEXT PRIMARY KEY,
			verified_at TEXT NOT NULL DEFAULT '',
			checked_at TEXT NOT NULL,
			status TEXT NOT NULL,
			failure_class TEXT NOT NULL DEFAULT '',
			failure_code TEXT NOT NULL DEFAULT '',
			failure_detail TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_domain_affiliations_host_status ON domain_affiliations(host, status);`,
		`CREATE INDEX IF NOT EXISTS idx_domain_affiliations_host_status_checked ON domain_affiliations(host, status, checked_at);`,
		`CREATE TABLE IF NOT EXISTS managed_tenants (
			host TEXT PRIMARY KEY, policy TEXT NOT NULL, state TEXT NOT NULL,
			org_name TEXT NOT NULL UNIQUE, provisioning_marker TEXT NOT NULL UNIQUE,
			gitea_org_id BIGINT NOT NULL DEFAULT 0,
			reader_team_id BIGINT NOT NULL DEFAULT 0, version BIGINT NOT NULL,
			reconciled_version BIGINT NOT NULL DEFAULT 0, last_reconciled_at TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS tenant_memberships (
			host TEXT NOT NULL REFERENCES managed_tenants(host), pubkey TEXT NOT NULL,
			gitea_user_id BIGINT NOT NULL, gitea_user TEXT NOT NULL, evidence_status TEXT NOT NULL,
			verified_at TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL,
			granted INTEGER NOT NULL DEFAULT 0, tenant_orphaned INTEGER NOT NULL DEFAULT 0,
			access_state TEXT NOT NULL DEFAULT '', reconciled_at TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL, PRIMARY KEY(host,pubkey)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_tenant_memberships_host_granted ON tenant_memberships(host, granted);`,
		`CREATE TABLE IF NOT EXISTS bridge_tokens (
			id TEXT PRIMARY KEY,
			token_hash BYTEA NOT NULL UNIQUE,
			token_suffix TEXT NOT NULL,
			pubkey TEXT NOT NULL,
			gitea_user_id BIGINT NOT NULL,
			name TEXT NOT NULL,
			scopes TEXT NOT NULL,
			issued_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			revoked_at TEXT NOT NULL DEFAULT '',
			last_used_at TEXT NOT NULL DEFAULT '',
			created_event_id TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_bridge_tokens_pubkey ON bridge_tokens(pubkey);`,
		`CREATE INDEX IF NOT EXISTS idx_bridge_tokens_gitea_user ON bridge_tokens(gitea_user_id);`,
		`CREATE TABLE IF NOT EXISTS gitea_pat_credentials (
			gitea_user_id BIGINT NOT NULL,
			generation BIGINT NOT NULL,
			gitea_user TEXT NOT NULL,
			pat_name TEXT NOT NULL UNIQUE,
			gitea_token_id BIGINT NOT NULL DEFAULT 0,
			pat_ciphertext BYTEA NOT NULL,
			key_id TEXT NOT NULL,
			gitea_scopes TEXT NOT NULL,
			state TEXT NOT NULL,
			created_at TEXT NOT NULL,
			activated_at TEXT NOT NULL DEFAULT '',
			retired_at TEXT NOT NULL DEFAULT '',
			delete_attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (gitea_user_id, generation)
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_gitea_pat_one_active ON gitea_pat_credentials(gitea_user_id) WHERE state = 'active';`,
		`CREATE INDEX IF NOT EXISTS idx_gitea_pat_state ON gitea_pat_credentials(state);`,
		`CREATE TABLE IF NOT EXISTS auth_audit_events (
			id BIGSERIAL PRIMARY KEY,
			occurred_at TEXT NOT NULL,
			event_type TEXT NOT NULL,
			pubkey TEXT NOT NULL DEFAULT '',
			token_id TEXT NOT NULL DEFAULT '',
			gitea_user_id BIGINT NOT NULL DEFAULT 0,
			surface TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			outcome TEXT NOT NULL DEFAULT '',
			request_id TEXT NOT NULL DEFAULT '',
			source_fingerprint TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT ''
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres schema: %w", err)
		}
	}
	return nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// WithUserLock runs fn while holding an exclusive per-Gitea-user advisory
// lock honored across every node sharing this store. A dedicated pooled
// connection pins the lock's session for the duration; the lock never wraps
// a database transaction, because fn legitimately performs external work
// (Gitea HTTP calls) that must not hold a transaction open.
func (s *PostgresStore) WithUserLock(ctx context.Context, giteaUserID int64, fn func(ctx context.Context) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire lock connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx,
		`SELECT pg_advisory_lock(hashtextextended('pat_user:' || $1, 0))`, fmt.Sprintf("%d", giteaUserID)); err != nil {
		return fmt.Errorf("acquire user lock: %w", err)
	}
	defer func() {
		// Unlock on the SAME session. If the connection died, the session
		// lock is released by the server automatically.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx),
			`SELECT pg_advisory_unlock(hashtextextended('pat_user:' || $1, 0))`, fmt.Sprintf("%d", giteaUserID))
	}()
	return fn(ctx)
}

// maintenanceLeaseKey is the fixed advisory-lock key for the single-leader
// maintenance role. Arbitrary but stable; must not collide with the
// per-user PAT lock keyspace (those are hashtextextended of 'pat_user:<id>').
const maintenanceLeaseKey = int64(0x6772_6173_705f_6d74) // "grasp_mt"

// TryMaintenanceLease attempts pg_try_advisory_lock on a dedicated pooled
// connection. Non-blocking: a follower returns acquired=false at once. If the
// leader's process dies, its session ends and Postgres frees the lock, so the
// next tick re-elects. release() unlocks and returns the connection.
func (s *PostgresStore) WithTenantLock(ctx context.Context, host string, fn func(context.Context) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant lock connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, "tenant:"+host); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "tenant:"+host)
	}()
	return fn(ctx)
}

func (s *PostgresStore) TryMaintenanceLease(ctx context.Context) (bool, func(), error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("acquire lease connection: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, maintenanceLeaseKey).Scan(&got); err != nil {
		conn.Close()
		return false, nil, fmt.Errorf("try maintenance lease: %w", err)
	}
	if !got {
		conn.Close()
		return false, nil, nil
	}
	release := func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, maintenanceLeaseKey)
		conn.Close()
	}
	return true, release, nil
}

// --- NIP-98 replay ledger ---

// ClaimNIP98Event is single-use across every node sharing this store: the
// primary-key conflict, not a read-check, enforces it.
func (s *PostgresStore) ClaimNIP98Event(ctx context.Context, eventID, pubkey, method string, targetHash []byte, now, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO nip98_replay_claims(event_id, pubkey, method, target_hash, claimed_at, expires_at)
		VALUES($1, $2, $3, $4, $5, $6)
		ON CONFLICT (event_id) DO NOTHING
	`, eventID, pubkey, method, targetHash, ts(now), ts(expiresAt))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *PostgresStore) CleanupExpiredReplayClaims(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nip98_replay_claims WHERE expires_at <= $1`, ts(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Challenges ---

func (s *PostgresStore) CreateChallenge(ctx context.Context, c AuthChallenge) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_challenges(nonce, url, method, redirect_uri, created_at, expires_at, consumed)
		VALUES($1, $2, $3, $4, $5, $6, 0)
	`, c.Nonce, c.URL, c.Method, c.RedirectURI, ts(c.CreatedAt), ts(c.ExpiresAt))
	return err
}

func (s *PostgresStore) GetChallenge(ctx context.Context, nonce string) (AuthChallenge, error) {
	var c AuthChallenge
	var consumed int
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT nonce, url, method, redirect_uri, created_at, expires_at, consumed
		FROM auth_challenges WHERE nonce = $1
	`, nonce).Scan(&c.Nonce, &c.URL, &c.Method, &c.RedirectURI, &createdAt, &expiresAt, &consumed)
	if err != nil {
		return AuthChallenge{}, err
	}
	c.Consumed = consumed != 0
	if c.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return AuthChallenge{}, fmt.Errorf("parse created_at for challenge %s: %w", nonce, err)
	}
	if c.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return AuthChallenge{}, fmt.Errorf("parse expires_at for challenge %s: %w", nonce, err)
	}
	return c, nil
}

func (s *PostgresStore) ConsumeChallenge(ctx context.Context, nonce string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_challenges SET consumed = 1 WHERE nonce = $1 AND consumed = 0
	`, nonce)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("challenge %s not found or already consumed", nonce)
	}
	return nil
}

func (s *PostgresStore) DeleteExpiredChallenges(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_challenges WHERE expires_at < $1`, ts(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- NIP-46 sessions & signer grants ---

func (s *PostgresStore) CreateNIP46Session(ctx context.Context, sess NIP46Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nip46_sessions(session_token, bunker_pubkey, client_pubkey, state, redirect_uri, result_pubkey, error, created_at, expires_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, sess.SessionToken, sess.BunkerPubkey, sess.ClientPubkey, sess.State,
		sess.RedirectURI, sess.ResultPubkey, sess.Error, ts(sess.CreatedAt), ts(sess.ExpiresAt))
	return err
}

func (s *PostgresStore) GetNIP46Session(ctx context.Context, token string) (NIP46Session, error) {
	var sess NIP46Session
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT session_token, bunker_pubkey, client_pubkey, state, redirect_uri, result_pubkey, error, created_at, expires_at
		FROM nip46_sessions WHERE session_token = $1
	`, token).Scan(&sess.SessionToken, &sess.BunkerPubkey, &sess.ClientPubkey,
		&sess.State, &sess.RedirectURI, &sess.ResultPubkey, &sess.Error, &createdAt, &expiresAt)
	if err != nil {
		return NIP46Session{}, err
	}
	if sess.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return NIP46Session{}, fmt.Errorf("parse created_at for session %s: %w", token, err)
	}
	if sess.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return NIP46Session{}, fmt.Errorf("parse expires_at for session %s: %w", token, err)
	}
	return sess, nil
}

func (s *PostgresStore) UpdateNIP46SessionState(ctx context.Context, token string, state string, resultPubkey string, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE nip46_sessions SET state = $1, result_pubkey = $2, error = $3 WHERE session_token = $4
	`, state, resultPubkey, errMsg, token)
	return err
}

func (s *PostgresStore) DeleteExpiredNIP46Sessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nip46_sessions WHERE expires_at < $1`, ts(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) UpsertSignerGrant(ctx context.Context, grant SignerGrant) error {
	if grant.GrantedAt.IsZero() {
		grant.GrantedAt = time.Now().UTC()
	}
	if grant.Status == "" {
		grant.Status = "active"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO signer_grants(pubkey, client_seckey_enc, bunker_uri_enc, relays, permissions, granted_at, revoked_at, last_ok_at, status)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT(pubkey) DO UPDATE SET
			client_seckey_enc = excluded.client_seckey_enc,
			bunker_uri_enc = excluded.bunker_uri_enc,
			relays = excluded.relays,
			permissions = excluded.permissions,
			granted_at = excluded.granted_at,
			revoked_at = excluded.revoked_at,
			last_ok_at = excluded.last_ok_at,
			status = excluded.status
	`, grant.Pubkey, grant.ClientSeckeyEnc, grant.BunkerURIEnc, grant.Relays, grant.Permissions,
		ts(grant.GrantedAt), formatOptionalTime(grant.RevokedAt), formatOptionalTime(grant.LastOKAt), grant.Status)
	return err
}

func (s *PostgresStore) GetSignerGrant(ctx context.Context, pubkey string) (SignerGrant, error) {
	var grant SignerGrant
	var grantedAt, revokedAt, lastOKAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, client_seckey_enc, bunker_uri_enc, relays, permissions, granted_at, revoked_at, last_ok_at, status
		FROM signer_grants WHERE pubkey = $1
	`, pubkey).Scan(&grant.Pubkey, &grant.ClientSeckeyEnc, &grant.BunkerURIEnc, &grant.Relays,
		&grant.Permissions, &grantedAt, &revokedAt, &lastOKAt, &grant.Status)
	if err != nil {
		return SignerGrant{}, err
	}
	if grant.GrantedAt, err = time.Parse(time.RFC3339, grantedAt); err != nil {
		return SignerGrant{}, fmt.Errorf("parse granted_at for signer grant %s: %w", pubkey, err)
	}
	if grant.RevokedAt, err = parseOptionalTime(revokedAt); err != nil {
		return SignerGrant{}, fmt.Errorf("parse revoked_at for signer grant %s: %w", pubkey, err)
	}
	if grant.LastOKAt, err = parseOptionalTime(lastOKAt); err != nil {
		return SignerGrant{}, fmt.Errorf("parse last_ok_at for signer grant %s: %w", pubkey, err)
	}
	return grant, nil
}

func (s *PostgresStore) RevokeSignerGrant(ctx context.Context, pubkey string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE signer_grants SET revoked_at = $1, status = 'revoked' WHERE pubkey = $2`, ts(at), pubkey)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) RecordSignerGrantOK(ctx context.Context, pubkey string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE signer_grants SET last_ok_at = $1 WHERE pubkey = $2`, ts(at), pubkey)
	return err
}

func (s *PostgresStore) GetBridgeSignerSession(ctx context.Context, bunkerURI string) (BridgeSignerSession, error) {
	var sess BridgeSignerSession
	var createdAt, lastOKAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT bunker_uri, client_seckey_enc, client_pubkey, signer_pubkey, created_at, last_ok_at
		FROM bridge_signer_sessions WHERE bunker_uri = $1`, bunkerURI).
		Scan(&sess.BunkerURI, &sess.ClientSeckeyEnc, &sess.ClientPubkey, &sess.SignerPubkey, &createdAt, &lastOKAt)
	if err != nil {
		return BridgeSignerSession{}, err
	}
	if sess.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return BridgeSignerSession{}, fmt.Errorf("parse created_at for bridge signer session: %w", err)
	}
	if sess.LastOKAt, err = parseOptionalTime(lastOKAt); err != nil {
		return BridgeSignerSession{}, fmt.Errorf("parse last_ok_at for bridge signer session: %w", err)
	}
	return sess, nil
}

func (s *PostgresStore) UpsertBridgeSignerSession(ctx context.Context, sess BridgeSignerSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bridge_signer_sessions(bunker_uri, client_seckey_enc, client_pubkey, signer_pubkey, created_at, last_ok_at)
		VALUES($1, $2, $3, $4, $5, $6)
		ON CONFLICT(bunker_uri) DO UPDATE SET
			client_seckey_enc = excluded.client_seckey_enc,
			client_pubkey = excluded.client_pubkey,
			signer_pubkey = excluded.signer_pubkey,
			last_ok_at = excluded.last_ok_at
	`, sess.BunkerURI, sess.ClientSeckeyEnc, sess.ClientPubkey, sess.SignerPubkey,
		ts(sess.CreatedAt), formatOptionalTime(sess.LastOKAt))
	if err != nil {
		return fmt.Errorf("upsert bridge signer session: %w", err)
	}
	return nil
}

func (s *PostgresStore) TouchBridgeSignerSession(ctx context.Context, bunkerURI string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bridge_signer_sessions SET last_ok_at = $1 WHERE bunker_uri = $2`, ts(at), bunkerURI)
	return err
}

// --- Identity links ---

func (s *PostgresStore) GetIdentityLinkByPubkey(ctx context.Context, pubkey string) (NostrIdentityLink, error) {
	var link NostrIdentityLink
	var createdAt, updatedAt, lastLoginAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE pubkey = $1
	`, pubkey).Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
		&link.NIP05, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return NostrIdentityLink{}, err
	}
	if link.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse created_at for link %s: %w", pubkey, err)
	}
	if link.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse updated_at for link %s: %w", pubkey, err)
	}
	if lastLoginAt != "" {
		if link.LastLoginAt, err = time.Parse(time.RFC3339, lastLoginAt); err != nil {
			return NostrIdentityLink{}, fmt.Errorf("parse last_login_at for link %s: %w", pubkey, err)
		}
	}
	return link, nil
}

func (s *PostgresStore) GetIdentityLinkByGiteaUserID(ctx context.Context, userID int64) (NostrIdentityLink, error) {
	var link NostrIdentityLink
	var createdAt, updatedAt, lastLoginAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE gitea_user_id = $1
	`, userID).Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
		&link.NIP05, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return NostrIdentityLink{}, err
	}
	if link.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse created_at for Gitea user %d: %w", userID, err)
	}
	if link.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse updated_at for Gitea user %d: %w", userID, err)
	}
	if lastLoginAt != "" {
		if link.LastLoginAt, err = time.Parse(time.RFC3339, lastLoginAt); err != nil {
			return NostrIdentityLink{}, fmt.Errorf("parse last_login_at for Gitea user %d: %w", userID, err)
		}
	}
	return link, nil
}

func (s *PostgresStore) ListIdentityLinksAfter(ctx context.Context, afterPubkey string, limit int) ([]NostrIdentityLink, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE pubkey > $1 ORDER BY pubkey LIMIT $2
	`, afterPubkey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := make([]NostrIdentityLink, 0)
	for rows.Next() {
		var link NostrIdentityLink
		var createdAt, updatedAt, lastLoginAt string
		if err := rows.Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
			&link.NIP05, &createdAt, &updatedAt, &lastLoginAt); err != nil {
			return nil, err
		}
		if link.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at for link %s: %w", link.Pubkey, err)
		}
		if link.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
			return nil, fmt.Errorf("parse updated_at for link %s: %w", link.Pubkey, err)
		}
		if lastLoginAt != "" {
			if link.LastLoginAt, err = time.Parse(time.RFC3339, lastLoginAt); err != nil {
				return nil, fmt.Errorf("parse last_login_at for link %s: %w", link.Pubkey, err)
			}
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

func (s *PostgresStore) UpsertIdentityLink(ctx context.Context, link NostrIdentityLink) error {
	now := ts(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nostr_identity_links(pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT(pubkey) DO UPDATE SET
			npub = excluded.npub,
			gitea_user_id = excluded.gitea_user_id,
			gitea_user = excluded.gitea_user,
			nip05 = excluded.nip05,
			updated_at = excluded.updated_at,
			last_login_at = excluded.last_login_at
	`, link.Pubkey, link.Npub, link.GiteaUserID, link.GiteaUser, link.NIP05,
		now, now, ts(link.LastLoginAt))
	return err
}

func (s *PostgresStore) UpdateLastLogin(ctx context.Context, pubkey string) error {
	now := ts(time.Now())
	_, err := s.db.ExecContext(ctx, `
		UPDATE nostr_identity_links SET last_login_at = $1, updated_at = $2 WHERE pubkey = $3
	`, now, now, pubkey)
	return err
}

// --- Bridge tokens ---

func (s *PostgresStore) InsertBridgeToken(ctx context.Context, t BridgeToken, maxActive int) error {
	scopes, err := marshalScopeList(t.Scopes)
	if err != nil {
		return err
	}
	issued, expires := ts(t.IssuedAt), ts(t.ExpiresAt)

	if maxActive <= 0 {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO bridge_tokens(id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, created_event_id)
			VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, t.ID, t.TokenHash, t.TokenSuffix, t.Pubkey, t.GiteaUserID, t.Name, scopes, issued, expires, t.CreatedEventID); err != nil {
			return fmt.Errorf("insert bridge token: %w", err)
		}
		return nil
	}

	// Under READ COMMITTED, a bare conditional INSERT is NOT atomic: two
	// concurrent mints can both observe count < limit (the conformance
	// suite's ConcurrentMintsNeverExceedLimit proves it). A transaction-
	// scoped advisory lock keyed on the subject serializes mints for one
	// pubkey across every node sharing this store, without blocking other
	// subjects.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('bridge_tokens:' || $1, 0))`, t.Pubkey); err != nil {
		return fmt.Errorf("acquire mint lock: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO bridge_tokens(id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, created_event_id)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		WHERE (SELECT COUNT(*) FROM bridge_tokens WHERE pubkey = $11 AND revoked_at = '' AND expires_at > $12) < $13
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
	return tx.Commit()
}

func (s *PostgresStore) GetBridgeTokenByHash(ctx context.Context, hash []byte) (BridgeToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, revoked_at, last_used_at, created_event_id
		FROM bridge_tokens WHERE token_hash = $1
	`, hash)
	t, err := scanBridgeToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BridgeToken{}, ErrBridgeTokenNotFound
	}
	return t, err
}

func (s *PostgresStore) ListBridgeTokens(ctx context.Context, pubkey string, limit, offset int) ([]BridgeToken, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_suffix, pubkey, gitea_user_id, name, scopes, issued_at, expires_at, revoked_at, last_used_at, created_event_id
		FROM bridge_tokens WHERE pubkey = $1
		ORDER BY issued_at DESC, id ASC LIMIT $2 OFFSET $3
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

func (s *PostgresStore) RevokeBridgeToken(ctx context.Context, pubkey, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = $1
		WHERE id = $2 AND pubkey = $3 AND revoked_at = ''
	`, ts(now), id, pubkey)
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

func (s *PostgresStore) RotateBridgeToken(ctx context.Context, pubkey, oldID string, replacement BridgeToken, now time.Time) error {
	scopes, err := marshalScopeList(replacement.Scopes)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	nowStr := ts(now)
	var subjectPubkey string
	var subjectGiteaUserID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT pubkey, gitea_user_id FROM bridge_tokens
		WHERE id = $1 AND pubkey = $2 AND revoked_at = '' AND expires_at > $3
		FOR UPDATE
	`, oldID, pubkey, nowStr).Scan(&subjectPubkey, &subjectGiteaUserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBridgeTokenNotFound
		}
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = $1
		WHERE id = $2 AND pubkey = $3 AND revoked_at = ''
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
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, replacement.ID, replacement.TokenHash, replacement.TokenSuffix, subjectPubkey, subjectGiteaUserID,
		replacement.Name, scopes, ts(replacement.IssuedAt), ts(replacement.ExpiresAt), replacement.CreatedEventID); err != nil {
		return fmt.Errorf("insert rotated bridge token: %w", err)
	}
	return tx.Commit()
}

func (s *PostgresStore) RevokeBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET revoked_at = $1
		WHERE gitea_user_id = $2 AND revoked_at = ''
	`, ts(now), giteaUserID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) CountActiveBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM bridge_tokens
		WHERE gitea_user_id = $1 AND revoked_at = '' AND expires_at > $2
	`, giteaUserID, ts(now)).Scan(&n)
	return n, err
}

func (s *PostgresStore) TouchBridgeTokenUsage(ctx context.Context, id string, now, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE bridge_tokens SET last_used_at = $1
		WHERE id = $2 AND (last_used_at = '' OR last_used_at <= $3)
	`, ts(now), id, ts(cutoff))
	return err
}

// --- Hidden PAT credentials ---

func (s *PostgresStore) ReservePATCredential(ctx context.Context, giteaUserID int64, giteaUser, namePrefix string, giteaScopes []string, now time.Time) (generation int64, patName string, err error) {
	scopes, err := marshalScopeList(giteaScopes)
	if err != nil {
		return 0, "", err
	}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO gitea_pat_credentials(gitea_user_id, generation, gitea_user, pat_name, pat_ciphertext, key_id, gitea_scopes, state, created_at)
		SELECT $1, g.next, $2, $3 || '-' || $1::text || '-' || g.next::text, ''::bytea, '', $4, $5, $6
		FROM (SELECT COALESCE(MAX(generation), 0) + 1 AS next FROM gitea_pat_credentials WHERE gitea_user_id = $1) AS g
		RETURNING generation, pat_name
	`, giteaUserID, giteaUser, namePrefix, scopes, PATStateProvisioning, ts(now)).
		Scan(&generation, &patName)
	if err != nil {
		return 0, "", fmt.Errorf("reserve pat credential: %w", err)
	}
	return generation, patName, nil
}

func (s *PostgresStore) FinalizePATCredential(ctx context.Context, giteaUserID, generation, giteaTokenID int64, ciphertext []byte, keyID string) error {
	if len(ciphertext) == 0 || keyID == "" {
		return fmt.Errorf("pat finalization requires ciphertext and key id")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET pat_ciphertext = $1, key_id = $2, gitea_token_id = $3
		WHERE gitea_user_id = $4 AND generation = $5 AND state = $6
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

func (s *PostgresStore) ActivatePATCredential(ctx context.Context, giteaUserID, generation int64, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = $1, retired_at = ''
		WHERE gitea_user_id = $2 AND state = $3
	`, PATStateRetiring, giteaUserID, PATStateActive); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = $1, activated_at = $2
		WHERE gitea_user_id = $3 AND generation = $4 AND state = $5 AND octet_length(pat_ciphertext) > 0 AND key_id != ''
	`, PATStateActive, ts(now), giteaUserID, generation, PATStateProvisioning)
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

const pgPATColumns = `gitea_user_id, generation, gitea_user, pat_name, gitea_token_id, pat_ciphertext, key_id, gitea_scopes, state, created_at, activated_at, retired_at, delete_attempts, last_error`

func (s *PostgresStore) GetActivePATCredential(ctx context.Context, giteaUserID int64) (GiteaPATCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+pgPATColumns+` FROM gitea_pat_credentials WHERE gitea_user_id = $1 AND state = $2
	`, giteaUserID, PATStateActive)
	return scanPATCredential(row)
}

func (s *PostgresStore) ResealPATCredential(ctx context.Context, giteaUserID, generation int64, expectedCiphertext, ciphertext []byte, keyID string) (int64, error) {
	if len(ciphertext) == 0 || keyID == "" {
		return 0, fmt.Errorf("pat reseal requires ciphertext and key id")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET pat_ciphertext = $1, key_id = $2
		WHERE gitea_user_id = $3 AND generation = $4 AND pat_ciphertext = $5
	`, ciphertext, keyID, giteaUserID, generation, expectedCiphertext)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) SetPATCredentialState(ctx context.Context, giteaUserID, generation int64, state, lastError string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = $1, last_error = $2
		WHERE gitea_user_id = $3 AND generation = $4
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

func (s *PostgresStore) RetireActivePATCredential(ctx context.Context, giteaUserID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = $1, retired_at = ''
		WHERE gitea_user_id = $2 AND state = $3
	`, PATStateRetiring, giteaUserID, PATStateActive)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) MarkPATCredentialRetired(ctx context.Context, giteaUserID, generation int64, now time.Time) error {
	return s.pgSetPATRetirement(ctx, giteaUserID, generation, now, "")
}

func (s *PostgresStore) RecordPATDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials
		SET delete_attempts = delete_attempts + 1, last_error = $1
		WHERE gitea_user_id = $2 AND generation = $3
	`, lastError, giteaUserID, generation)
	return err
}

func (s *PostgresStore) RecordTerminalDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error {
	return s.RecordPATDeleteFailure(ctx, giteaUserID, generation, lastError)
}

func (s *PostgresStore) DeletePATCredential(ctx context.Context, giteaUserID, generation int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM gitea_pat_credentials WHERE gitea_user_id = $1 AND generation = $2
	`, giteaUserID, generation)
	return err
}

func (s *PostgresStore) pgSetPATRetirement(ctx context.Context, giteaUserID, generation int64, now time.Time, lastError string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE gitea_pat_credentials SET state = $1, retired_at = $2, last_error = $3
		WHERE gitea_user_id = $4 AND generation = $5
	`, PATStateRetiring, ts(now), lastError, giteaUserID, generation)
	return err
}

func (s *PostgresStore) ListGiteaUsersWithoutActiveTokens(ctx context.Context, now time.Time, limit int) (map[int64]time.Time, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.gitea_user_id, COALESCE(MAX(
			CASE WHEN t.revoked_at != '' AND t.revoked_at < t.expires_at
			     THEN t.revoked_at ELSE t.expires_at END), '')
		FROM gitea_pat_credentials c
		LEFT JOIN bridge_tokens t ON t.gitea_user_id = c.gitea_user_id
		WHERE c.state = $1
		  AND NOT EXISTS (
			SELECT 1 FROM bridge_tokens a
			WHERE a.gitea_user_id = c.gitea_user_id AND a.revoked_at = '' AND a.expires_at > $2
		  )
		GROUP BY c.gitea_user_id
		LIMIT $3
	`, PATStateActive, ts(now), limit)
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

func (s *PostgresStore) listPATs(ctx context.Context, where string, limit int, args ...any) ([]GiteaPATCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pgPATColumns+` FROM gitea_pat_credentials `+where, args...)
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

func (s *PostgresStore) ListPATCredentialsPendingDeletion(ctx context.Context, limit int) ([]GiteaPATCredential, error) {
	return s.listPATs(ctx, `WHERE state = $1 AND retired_at = '' ORDER BY created_at ASC LIMIT $2`, limit, PATStateRetiring)
}

func (s *PostgresStore) ListPATCredentialsByState(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error) {
	return s.listPATs(ctx, `WHERE state = $1 ORDER BY created_at ASC LIMIT $2`, limit, state)
}

func (s *PostgresStore) ListPATCredentialsUnderStaleKey(ctx context.Context, activeKeyID string, limit int) ([]GiteaPATCredential, error) {
	return s.listPATs(ctx, `WHERE key_id != $1 AND key_id != '' AND octet_length(pat_ciphertext) > 0
		AND (state = $2 OR (state = $3 AND retired_at = '')) ORDER BY created_at ASC LIMIT $4`,
		limit, activeKeyID, PATStateActive, PATStateRetiring)
}

func (s *PostgresStore) ListStalePATCredentialsInState(ctx context.Context, state string, before time.Time, limit int) ([]GiteaPATCredential, error) {
	return s.listPATs(ctx, `WHERE state = $1 AND created_at < $2 ORDER BY created_at ASC LIMIT $3`,
		limit, state, ts(before))
}

func (s *PostgresStore) ListTerminalPATCredentials(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error) {
	return s.listPATs(ctx, `WHERE state = $1 ORDER BY delete_attempts ASC, created_at ASC LIMIT $2`, limit, state)
}

// --- Audit ledger ---

func (s *PostgresStore) InsertAuthAuditEvent(ctx context.Context, ev AuthAuditEvent) error {
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_audit_events(occurred_at, event_type, pubkey, token_id, gitea_user_id, surface, action, outcome, request_id, source_fingerprint, detail)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, ts(occurred), ev.EventType, ev.Pubkey, ev.TokenID, ev.GiteaUserID,
		ev.Surface, ev.Action, ev.Outcome, ev.RequestID, ev.SourceFingerprint, ev.Detail)
	return err
}

func (s *PostgresStore) ListAuthAuditEvents(ctx context.Context, eventType string, limit int) ([]AuthAuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT occurred_at, event_type, pubkey, token_id, gitea_user_id, surface, action, outcome, request_id, source_fingerprint, detail
		FROM auth_audit_events`
	args := []any{}
	if eventType != "" {
		query += ` WHERE event_type = $1 ORDER BY occurred_at DESC, id DESC LIMIT $2`
		args = append(args, eventType, limit)
	} else {
		query += ` ORDER BY occurred_at DESC, id DESC LIMIT $1`
		args = append(args, limit)
	}
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

func (s *PostgresStore) CleanupAuthAuditEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_audit_events WHERE occurred_at < $1`, ts(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PostgresStore must satisfy the same contract as the SQLite reference.
var _ AuthStore = (*PostgresStore)(nil)

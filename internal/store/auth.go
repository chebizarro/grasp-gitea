package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Auth-related table structs

type LoginChallenge struct {
	ID          string
	OAuth2State string
	RedirectURI string
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

type OAuth2AuthCode struct {
	Code        string
	Pubkey      string
	Npub        string
	RedirectURI string
	ExpiresAt   time.Time
	UsedAt      *time.Time
}

type IdentityLink struct {
	Pubkey        string    `json:"pubkey"`
	Npub          string    `json:"npub"`
	NIP05         string    `json:"nip05"`
	GiteaUserID   int64     `json:"gitea_user_id"`
	GiteaUsername string    `json:"gitea_username"`
	CreatedAt     time.Time `json:"created_at"`
	LastLoginAt   time.Time `json:"last_login_at"`
}

type OAuth2AccessToken struct {
	Token     string
	Pubkey    string
	ExpiresAt time.Time
}

// ErrNotFound is returned when a record doesn't exist.
var ErrNotFound = errors.New("not found")

// ErrExpired is returned when a token/challenge has expired.
var ErrExpired = errors.New("expired")

// ErrAlreadyConsumed is returned when a nonce has already been used.
var ErrAlreadyConsumed = errors.New("already consumed")

// initAuthSchema creates the auth-related tables. Called from Open().
func (s *SQLiteStore) initAuthSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS login_challenges (
			id TEXT PRIMARY KEY,
			oauth2_state TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			consumed_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS oauth2_auth_codes (
			code TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			npub TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS nostr_identity_links (
			pubkey TEXT PRIMARY KEY,
			npub TEXT NOT NULL,
			nip05 TEXT NOT NULL DEFAULT '',
			gitea_user_id INTEGER NOT NULL,
			gitea_username TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			last_login_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
			token TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("init auth schema: %w", err)
		}
	}
	return nil
}

// --- Login challenges ---

func (s *SQLiteStore) CreateChallenge(ctx context.Context, id, oauth2State, redirectURI string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO login_challenges(id, oauth2_state, redirect_uri, expires_at) VALUES(?, ?, ?, ?)`,
		id, oauth2State, redirectURI, expiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ConsumeChallenge atomically marks the challenge as consumed and returns it.
// Returns ErrNotFound, ErrExpired, or ErrAlreadyConsumed on failure.
func (s *SQLiteStore) ConsumeChallenge(ctx context.Context, id string) (LoginChallenge, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoginChallenge{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var c LoginChallenge
	var expiresAtStr string
	var consumedAtStr sql.NullString

	err = tx.QueryRowContext(ctx,
		`SELECT id, oauth2_state, redirect_uri, expires_at, consumed_at FROM login_challenges WHERE id = ?`, id,
	).Scan(&c.ID, &c.OAuth2State, &c.RedirectURI, &expiresAtStr, &consumedAtStr)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginChallenge{}, ErrNotFound
	}
	if err != nil {
		return LoginChallenge{}, err
	}

	c.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	if consumedAtStr.Valid {
		t, _ := time.Parse(time.RFC3339, consumedAtStr.String)
		c.ConsumedAt = &t
		return LoginChallenge{}, ErrAlreadyConsumed
	}
	if time.Now().After(c.ExpiresAt) {
		return LoginChallenge{}, ErrExpired
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err = tx.ExecContext(ctx,
		`UPDATE login_challenges SET consumed_at = ? WHERE id = ?`, now, id,
	); err != nil {
		return LoginChallenge{}, err
	}

	if err = tx.Commit(); err != nil {
		return LoginChallenge{}, err
	}
	return c, nil
}

// --- OAuth2 auth codes ---

func (s *SQLiteStore) CreateAuthCode(ctx context.Context, code, pubkey, npub, redirectURI string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth2_auth_codes(code, pubkey, npub, redirect_uri, expires_at) VALUES(?, ?, ?, ?, ?)`,
		code, pubkey, npub, redirectURI, expiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ConsumeAuthCode atomically marks the code as used and returns it.
func (s *SQLiteStore) ConsumeAuthCode(ctx context.Context, code string) (OAuth2AuthCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuth2AuthCode{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var ac OAuth2AuthCode
	var expiresAtStr string
	var usedAtStr sql.NullString

	err = tx.QueryRowContext(ctx,
		`SELECT code, pubkey, npub, redirect_uri, expires_at, used_at FROM oauth2_auth_codes WHERE code = ?`, code,
	).Scan(&ac.Code, &ac.Pubkey, &ac.Npub, &ac.RedirectURI, &expiresAtStr, &usedAtStr)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuth2AuthCode{}, ErrNotFound
	}
	if err != nil {
		return OAuth2AuthCode{}, err
	}

	ac.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	if usedAtStr.Valid {
		return OAuth2AuthCode{}, ErrAlreadyConsumed
	}
	if time.Now().After(ac.ExpiresAt) {
		return OAuth2AuthCode{}, ErrExpired
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err = tx.ExecContext(ctx,
		`UPDATE oauth2_auth_codes SET used_at = ? WHERE code = ?`, now, code,
	); err != nil {
		return OAuth2AuthCode{}, err
	}

	if err = tx.Commit(); err != nil {
		return OAuth2AuthCode{}, err
	}
	return ac, nil
}

// --- Identity links ---

func (s *SQLiteStore) UpsertIdentityLink(ctx context.Context, link IdentityLink) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nostr_identity_links(pubkey, npub, nip05, gitea_user_id, gitea_username, created_at, last_login_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			npub = excluded.npub,
			nip05 = excluded.nip05,
			gitea_user_id = excluded.gitea_user_id,
			gitea_username = excluded.gitea_username,
			last_login_at = excluded.last_login_at
	`, link.Pubkey, link.Npub, link.NIP05, link.GiteaUserID, link.GiteaUsername,
		link.CreatedAt.UTC().Format(time.RFC3339), now,
	)
	return err
}

func (s *SQLiteStore) GetIdentityLinkByPubkey(ctx context.Context, pubkey string) (IdentityLink, bool, error) {
	var link IdentityLink
	var createdAtStr, lastLoginAtStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT pubkey, npub, nip05, gitea_user_id, gitea_username, created_at, last_login_at
		 FROM nostr_identity_links WHERE pubkey = ?`, pubkey,
	).Scan(&link.Pubkey, &link.Npub, &link.NIP05, &link.GiteaUserID, &link.GiteaUsername, &createdAtStr, &lastLoginAtStr)
	if errors.Is(err, sql.ErrNoRows) {
		return IdentityLink{}, false, nil
	}
	if err != nil {
		return IdentityLink{}, false, err
	}
	link.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	link.LastLoginAt, _ = time.Parse(time.RFC3339, lastLoginAtStr)
	return link, true, nil
}

// --- Access tokens ---

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *SQLiteStore) CreateAccessToken(ctx context.Context, token, pubkey string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth2_access_tokens(token, pubkey, expires_at) VALUES(?, ?, ?)`,
		token, pubkey, expiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) GetAccessToken(ctx context.Context, token string) (OAuth2AccessToken, error) {
	var t OAuth2AccessToken
	var expiresAtStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT token, pubkey, expires_at FROM oauth2_access_tokens WHERE token = ?`, token,
	).Scan(&t.Token, &t.Pubkey, &expiresAtStr)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuth2AccessToken{}, ErrNotFound
	}
	if err != nil {
		return OAuth2AccessToken{}, err
	}
	t.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	if time.Now().After(t.ExpiresAt) {
		return OAuth2AccessToken{}, ErrExpired
	}
	return t, nil
}

func (s *SQLiteStore) DeleteExpiredTokens(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth2_access_tokens WHERE expires_at < ?`, now,
	)
	return err
}

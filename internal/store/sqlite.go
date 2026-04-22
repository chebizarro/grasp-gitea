package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// AuthChallenge represents a login challenge/nonce issued for NIP-98 auth.
type AuthChallenge struct {
	Nonce       string    `json:"nonce"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	RedirectURI string    `json:"redirect_uri,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Consumed    bool      `json:"consumed"`
}

// NIP46Session tracks an in-flight or completed NIP-46 bunker login session.
type NIP46Session struct {
	SessionToken string    `json:"session_token"`
	BunkerPubkey string    `json:"bunker_pubkey"`
	ClientPubkey string    `json:"client_pubkey"`
	State        string    `json:"state"` // pending, complete, error
	RedirectURI  string    `json:"redirect_uri,omitempty"`
	ResultPubkey string    `json:"result_pubkey,omitempty"` // verified signer pubkey on success
	Error        string    `json:"error,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// NostrIdentityLink binds a Nostr pubkey to a Gitea user.
type NostrIdentityLink struct {
	Pubkey      string    `json:"pubkey"`
	Npub        string    `json:"npub"`
	GiteaUserID int64     `json:"gitea_user_id"`
	GiteaUser   string    `json:"gitea_user"`
	NIP05       string    `json:"nip05,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

type Mapping struct {
	Npub              string    `json:"npub"`
	RepoID            string    `json:"repo_id"`
	Pubkey            string    `json:"pubkey"`
	Owner             string    `json:"owner"`
	RepoName          string    `json:"repo_name"`
	GiteaRepoID       int64     `json:"gitea_repo_id"`
	CloneURL          string    `json:"clone_url"`
	AnnouncedCloneURL string    `json:"announced_clone_url,omitempty"`
	SourceEvent       string    `json:"source_event"`
	HookInstalled     bool      `json:"hook_installed"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type SQLiteStore struct {
	db *sql.DB
}

func Open(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS mappings (
			npub TEXT NOT NULL,
			repo_id TEXT NOT NULL,
			pubkey TEXT NOT NULL,
			owner TEXT NOT NULL,
			repo_name TEXT NOT NULL,
			gitea_repo_id INTEGER NOT NULL,
			clone_url TEXT NOT NULL,
			source_event TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (npub, repo_id)
		);`,
		`CREATE TABLE IF NOT EXISTS processed_events (
			event_id TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			kind INTEGER NOT NULL,
			seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS auth_challenges (
			nonce TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			method TEXT NOT NULL DEFAULT 'POST',
			redirect_uri TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			consumed INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS nostr_identity_links (
			pubkey TEXT PRIMARY KEY,
			npub TEXT NOT NULL,
			gitea_user_id INTEGER NOT NULL,
			gitea_user TEXT NOT NULL,
			nip05 TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS nip46_sessions (
			session_token TEXT PRIMARY KEY,
			bunker_pubkey TEXT NOT NULL,
			client_pubkey TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'pending',
			redirect_uri TEXT NOT NULL DEFAULT '',
			result_pubkey TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init sqlite schema: %w", err)
		}
	}

	// Migration: add announced_clone_url column if it doesn't exist.
	// SQLite has no IF NOT EXISTS for ALTER TABLE, so we ignore the
	// "duplicate column" error.
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN announced_clone_url TEXT NOT NULL DEFAULT ''`)

	// Migration: add hook_installed column to track provisioning completion.
	// Existing rows default to 1 (true) since they were fully provisioned.
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN hook_installed INTEGER NOT NULL DEFAULT 1`)

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) EventProcessed(ctx context.Context, eventID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM processed_events WHERE event_id = ?`, eventID).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) MarkEventProcessed(ctx context.Context, eventID string, pubkey string, kind int) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO processed_events(event_id, pubkey, kind) VALUES(?, ?, ?)`, eventID, pubkey, kind)
	return err
}

func (s *SQLiteStore) MappingExists(ctx context.Context, npub string, repoID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM mappings WHERE npub = ? AND repo_id = ? LIMIT 1`, npub, repoID).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) ProvisionCountSince(ctx context.Context, pubkey string, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM mappings WHERE pubkey = ? AND created_at >= ?`, pubkey, since.UTC().Format(time.RFC3339)).Scan(&count)
	return count, err
}

func (s *SQLiteStore) UpsertMapping(ctx context.Context, m Mapping) error {
	now := time.Now().UTC().Format(time.RFC3339)
	hookVal := 0
	if m.HookInstalled {
		hookVal = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mappings(npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(npub, repo_id) DO UPDATE SET
			pubkey = excluded.pubkey,
			owner = excluded.owner,
			repo_name = excluded.repo_name,
			gitea_repo_id = excluded.gitea_repo_id,
			clone_url = excluded.clone_url,
			announced_clone_url = excluded.announced_clone_url,
			source_event = excluded.source_event,
			hook_installed = excluded.hook_installed,
			updated_at = excluded.updated_at
	`, m.Npub, m.RepoID, m.Pubkey, m.Owner, m.RepoName, m.GiteaRepoID, m.CloneURL, m.AnnouncedCloneURL, m.SourceEvent, hookVal, now, now)
	return err
}

func (s *SQLiteStore) ListMappings(ctx context.Context) ([]Mapping, error) {
	return s.listMappingsWhere(ctx, "1=1")
}

// ListUnhookedMappings returns mappings where hook installation was not completed.
// These represent interrupted provisioning that needs reconciliation on startup.
func (s *SQLiteStore) ListUnhookedMappings(ctx context.Context) ([]Mapping, error) {
	return s.listMappingsWhere(ctx, "hook_installed = 0")
}

// SetHookInstalled marks a mapping's hook as installed (or not).
func (s *SQLiteStore) SetHookInstalled(ctx context.Context, npub string, repoID string, installed bool) error {
	val := 0
	if installed {
		val = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE mappings SET hook_installed = ?, updated_at = ? WHERE npub = ? AND repo_id = ?`,
		val, time.Now().UTC().Format(time.RFC3339), npub, repoID)
	return err
}

func (s *SQLiteStore) listMappingsWhere(ctx context.Context, where string) ([]Mapping, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed, created_at, updated_at
		FROM mappings
		WHERE `+where+`
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Mapping, 0)
	for rows.Next() {
		var m Mapping
		var hookVal int
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID, &m.CloneURL, &m.AnnouncedCloneURL, &m.SourceEvent, &hookVal, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		m.HookInstalled = hookVal != 0
		var parseErr error
		m.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse created_at for %s/%s: %w", m.Npub, m.RepoID, parseErr)
		}
		m.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse updated_at for %s/%s: %w", m.Npub, m.RepoID, parseErr)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) GetMapping(ctx context.Context, npub string, repoID string) (Mapping, error) {
	var m Mapping
	var hookVal int
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed, created_at, updated_at
		FROM mappings WHERE npub = ? AND repo_id = ? LIMIT 1
	`, npub, repoID).Scan(&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID, &m.CloneURL, &m.AnnouncedCloneURL, &m.SourceEvent, &hookVal, &createdAt, &updatedAt)
	if err != nil {
		return Mapping{}, err
	}
	m.HookInstalled = hookVal != 0
	var parseErr error
	m.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return Mapping{}, fmt.Errorf("parse created_at for %s/%s: %w", m.Npub, m.RepoID, parseErr)
	}
	m.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
	if parseErr != nil {
		return Mapping{}, fmt.Errorf("parse updated_at for %s/%s: %w", m.Npub, m.RepoID, parseErr)
	}
	return m, nil
}

// --- Auth challenge methods ---

// CreateChallenge persists a new auth challenge nonce.
func (s *SQLiteStore) CreateChallenge(ctx context.Context, c AuthChallenge) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_challenges(nonce, url, method, redirect_uri, created_at, expires_at, consumed)
		VALUES(?, ?, ?, ?, ?, ?, 0)
	`, c.Nonce, c.URL, c.Method, c.RedirectURI,
		c.CreatedAt.UTC().Format(time.RFC3339),
		c.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// GetChallenge retrieves a challenge by nonce. Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetChallenge(ctx context.Context, nonce string) (AuthChallenge, error) {
	var c AuthChallenge
	var consumed int
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT nonce, url, method, redirect_uri, created_at, expires_at, consumed
		FROM auth_challenges WHERE nonce = ?
	`, nonce).Scan(&c.Nonce, &c.URL, &c.Method, &c.RedirectURI, &createdAt, &expiresAt, &consumed)
	if err != nil {
		return AuthChallenge{}, err
	}
	c.Consumed = consumed != 0
	var parseErr error
	c.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return AuthChallenge{}, fmt.Errorf("parse created_at for challenge %s: %w", nonce, parseErr)
	}
	c.ExpiresAt, parseErr = time.Parse(time.RFC3339, expiresAt)
	if parseErr != nil {
		return AuthChallenge{}, fmt.Errorf("parse expires_at for challenge %s: %w", nonce, parseErr)
	}
	return c, nil
}

// ConsumeChallenge marks a challenge as consumed. Returns an error if already consumed.
func (s *SQLiteStore) ConsumeChallenge(ctx context.Context, nonce string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_challenges SET consumed = 1
		WHERE nonce = ? AND consumed = 0
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

// DeleteExpiredChallenges removes challenges past their expiration time.
func (s *SQLiteStore) DeleteExpiredChallenges(ctx context.Context) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_challenges WHERE expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Nostr identity link methods ---

// UpsertIdentityLink creates or updates a Nostr-to-Gitea identity link.
func (s *SQLiteStore) UpsertIdentityLink(ctx context.Context, link NostrIdentityLink) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nostr_identity_links(pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			npub = excluded.npub,
			gitea_user_id = excluded.gitea_user_id,
			gitea_user = excluded.gitea_user,
			nip05 = excluded.nip05,
			updated_at = excluded.updated_at,
			last_login_at = excluded.last_login_at
	`, link.Pubkey, link.Npub, link.GiteaUserID, link.GiteaUser, link.NIP05,
		now, now, link.LastLoginAt.UTC().Format(time.RFC3339))
	return err
}

// GetIdentityLinkByPubkey retrieves the identity link for a Nostr pubkey.
// Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetIdentityLinkByPubkey(ctx context.Context, pubkey string) (NostrIdentityLink, error) {
	var link NostrIdentityLink
	var createdAt, updatedAt, lastLoginAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE pubkey = ?
	`, pubkey).Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
		&link.NIP05, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return NostrIdentityLink{}, err
	}
	var parseErr error
	link.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse created_at for link %s: %w", pubkey, parseErr)
	}
	link.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
	if parseErr != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse updated_at for link %s: %w", pubkey, parseErr)
	}
	if lastLoginAt != "" {
		link.LastLoginAt, parseErr = time.Parse(time.RFC3339, lastLoginAt)
		if parseErr != nil {
			return NostrIdentityLink{}, fmt.Errorf("parse last_login_at for link %s: %w", pubkey, parseErr)
		}
	}
	return link, nil
}

// GetIdentityLinkByGiteaUserID retrieves the identity link for a Gitea user.
// Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetIdentityLinkByGiteaUserID(ctx context.Context, userID int64) (NostrIdentityLink, error) {
	var link NostrIdentityLink
	var createdAt, updatedAt, lastLoginAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE gitea_user_id = ?
	`, userID).Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
		&link.NIP05, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return NostrIdentityLink{}, err
	}
	var parseErr error
	link.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse created_at for link (user %d): %w", userID, parseErr)
	}
	link.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
	if parseErr != nil {
		return NostrIdentityLink{}, fmt.Errorf("parse updated_at for link (user %d): %w", userID, parseErr)
	}
	if lastLoginAt != "" {
		link.LastLoginAt, parseErr = time.Parse(time.RFC3339, lastLoginAt)
		if parseErr != nil {
			return NostrIdentityLink{}, fmt.Errorf("parse last_login_at for link (user %d): %w", userID, parseErr)
		}
	}
	return link, nil
}

// UpdateLastLogin updates the last_login_at timestamp for a pubkey.
func (s *SQLiteStore) UpdateLastLogin(ctx context.Context, pubkey string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		UPDATE nostr_identity_links SET last_login_at = ?, updated_at = ? WHERE pubkey = ?
	`, now, now, pubkey)
	return err
}

// ListIdentityLinks returns all Nostr identity links.
func (s *SQLiteStore) ListIdentityLinks(ctx context.Context) ([]NostrIdentityLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []NostrIdentityLink
	for rows.Next() {
		var link NostrIdentityLink
		var createdAt, updatedAt, lastLoginAt string
		if err := rows.Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
			&link.NIP05, &createdAt, &updatedAt, &lastLoginAt); err != nil {
			return nil, err
		}
		var parseErr error
		link.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse created_at for link %s: %w", link.Pubkey, parseErr)
		}
		link.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse updated_at for link %s: %w", link.Pubkey, parseErr)
		}
		if lastLoginAt != "" {
			link.LastLoginAt, parseErr = time.Parse(time.RFC3339, lastLoginAt)
			if parseErr != nil {
				return nil, fmt.Errorf("parse last_login_at for link %s: %w", link.Pubkey, parseErr)
			}
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// --- NIP-46 session methods ---

// CreateNIP46Session persists a new NIP-46 login session.
func (s *SQLiteStore) CreateNIP46Session(ctx context.Context, sess NIP46Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nip46_sessions(session_token, bunker_pubkey, client_pubkey, state, redirect_uri, result_pubkey, error, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sess.SessionToken, sess.BunkerPubkey, sess.ClientPubkey, sess.State,
		sess.RedirectURI, sess.ResultPubkey, sess.Error,
		sess.CreatedAt.UTC().Format(time.RFC3339),
		sess.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// GetNIP46Session retrieves a session by token. Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetNIP46Session(ctx context.Context, token string) (NIP46Session, error) {
	var sess NIP46Session
	var createdAt, expiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT session_token, bunker_pubkey, client_pubkey, state, redirect_uri, result_pubkey, error, created_at, expires_at
		FROM nip46_sessions WHERE session_token = ?
	`, token).Scan(&sess.SessionToken, &sess.BunkerPubkey, &sess.ClientPubkey,
		&sess.State, &sess.RedirectURI, &sess.ResultPubkey, &sess.Error,
		&createdAt, &expiresAt)
	if err != nil {
		return NIP46Session{}, err
	}
	var parseErr error
	sess.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return NIP46Session{}, fmt.Errorf("parse created_at for session %s: %w", token, parseErr)
	}
	sess.ExpiresAt, parseErr = time.Parse(time.RFC3339, expiresAt)
	if parseErr != nil {
		return NIP46Session{}, fmt.Errorf("parse expires_at for session %s: %w", token, parseErr)
	}
	return sess, nil
}

// UpdateNIP46SessionState updates a session's state and result fields.
func (s *SQLiteStore) UpdateNIP46SessionState(ctx context.Context, token string, state string, resultPubkey string, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE nip46_sessions SET state = ?, result_pubkey = ?, error = ? WHERE session_token = ?
	`, state, resultPubkey, errMsg, token)
	return err
}

// DeleteExpiredNIP46Sessions removes sessions past their expiration time.
func (s *SQLiteStore) DeleteExpiredNIP46Sessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `DELETE FROM nip46_sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

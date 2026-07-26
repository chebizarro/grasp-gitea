package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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

// SignerGrant stores a reusable NIP-46 signing authorization.
// ClientSeckeyEnc and BunkerURIEnc are ciphertext blobs; plaintext signer
// secrets and bunker URIs must never be persisted.
type SignerGrant struct {
	Pubkey          string
	ClientSeckeyEnc []byte
	BunkerURIEnc    []byte
	Relays          string
	Permissions     string
	GrantedAt       time.Time
	RevokedAt       *time.Time
	LastOKAt        *time.Time
	Status          string
}

const (
	OutboundStatePending   = "pending"
	OutboundStatePublished = "published"
	OutboundStateDead      = "dead"
)

// OutboundEvent is a persisted unsigned event awaiting user-grant signing and relay publication.
type OutboundEvent struct {
	ID               int64     `json:"id"`
	DedupeKey        string    `json:"dedupe_key"`
	Kind             int       `json:"kind"`
	AuthorPubkey     string    `json:"author_pubkey"`
	Scope            string    `json:"scope"`
	UnsignedJSON     string    `json:"unsigned_json"`
	State            string    `json:"state"`
	Attempts         int       `json:"attempts"`
	NextAttemptAt    time.Time `json:"next_attempt_at"`
	LastError        string    `json:"last_error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	PublishedEventID string    `json:"published_event_id,omitempty"`
}

// OutboundQueueCounts summarizes outbound_events by state.
type OutboundQueueCounts struct {
	Pending   int64 `json:"pending"`
	Published int64 `json:"published"`
	Dead      int64 `json:"dead"`
}

// PendingActorEvent is an unsigned collaboration event that could not be
// attributed at webhook time because the acting Gitea user had not linked an
// active NIP-46 signer grant yet.
type PendingActorEvent struct {
	ID                int64     `json:"id"`
	GiteaUserID       int64     `json:"gitea_user_id"`
	Kind              int       `json:"kind"`
	UnsignedEventJSON string    `json:"unsigned_event_json"`
	Scope             string    `json:"scope"`
	DedupeKey         string    `json:"dedupe_key"`
	CreatedAt         time.Time `json:"created_at"`
}

// UserGraspList stores the latest owner-signed kind:10317 event observed for
// a provisioned repository owner. CreatedAt is the Nostr event created_at value
// and is used for NIP-01 replaceable-event ordering.
type UserGraspList struct {
	Pubkey            string `json:"pubkey"`
	EventJSON         string `json:"event_json"`
	EventID           string `json:"event_id"`
	CreatedAt         int64  `json:"created_at"`
	LastRepublishedID string `json:"last_republished_id,omitempty"`
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

	// Mirror republish fields: cached owner-signed announcement and publish tracking.
	AnnouncementEventJSON         string    `json:"announcement_event_json,omitempty"`
	AnnouncementEventID           string    `json:"announcement_event_id,omitempty"`
	LastRepublishedAnnouncementID string    `json:"last_republished_announcement_id,omitempty"`
	LastRepublishedAnnouncementAt time.Time `json:"last_republished_announcement_at,omitempty"`
	LastStateDigest               string    `json:"last_state_digest,omitempty"`
	LastStateEventID              string    `json:"last_state_event_id,omitempty"`
	LastStatePublishedAt          time.Time `json:"last_state_published_at,omitempty"`
}

// PendingNostrRef tracks an observed refs/nostr/<event-id> push until the
// relay accepts a matching PR/PR-update event or the lifecycle reaper deletes
// the temporary ref.
type PendingNostrRef struct {
	EventID     string    `json:"event_id"`
	TipSHA      string    `json:"tip_sha"`
	GiteaRepoID int64     `json:"gitea_repo_id"`
	Owner       string    `json:"owner"`
	RepoName    string    `json:"repo_name"`
	FirstSeenAt time.Time `json:"first_seen_at"`
}

// ReflectedEvent records a Nostr-originated collaboration event that the bridge
// materialised into a Gitea object. Webhook handling consults these rows to
// avoid echoing bridge-created objects back to Nostr.
type ReflectedEvent struct {
	NostrEventID    string    `json:"nostr_event_id"`
	GiteaRepoID     int64     `json:"gitea_repo_id"`
	GiteaIndex      int64     `json:"gitea_index"`
	HeadBranch      string    `json:"gitea_head_branch,omitempty"`
	Kind            int       `json:"kind"`
	CreatedAt       time.Time `json:"created_at"`
	EchoArmedAt     time.Time `json:"echo_armed_at,omitempty"`
	EchoFingerprint string    `json:"echo_fingerprint,omitempty"`
}

const DefaultEchoGuardWindow = 5 * time.Minute

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
		`CREATE TABLE IF NOT EXISTS reflected_events (
			nostr_event_id TEXT PRIMARY KEY,
			gitea_repo_id INTEGER NOT NULL,
			gitea_index INTEGER NOT NULL,
			gitea_head_branch TEXT NOT NULL DEFAULT '',
			kind INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			echo_pending INTEGER NOT NULL DEFAULT 1,
			echo_consumed_at TEXT NOT NULL DEFAULT '',
			echo_armed_at TEXT NOT NULL DEFAULT '',
			echo_fingerprint TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS pending_nostr_refs (
			event_id TEXT NOT NULL,
			tip_sha TEXT NOT NULL,
			gitea_repo_id INTEGER NOT NULL,
			owner TEXT NOT NULL,
			repo_name TEXT NOT NULL,
			first_seen_at TEXT NOT NULL,
			PRIMARY KEY (gitea_repo_id, event_id)
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
			last_login_at TEXT NOT NULL DEFAULT '',
			UNIQUE (gitea_user_id)
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
		`CREATE TABLE IF NOT EXISTS bridge_signer_sessions (
			bunker_uri TEXT PRIMARY KEY,
			client_seckey_enc BLOB NOT NULL,
			client_pubkey TEXT NOT NULL,
			signer_pubkey TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			last_ok_at TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS signer_grants (
			pubkey TEXT PRIMARY KEY,
			client_seckey_enc BLOB NOT NULL,
			bunker_uri_enc BLOB NOT NULL,
			relays TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL DEFAULT '',
			granted_at TEXT NOT NULL,
			revoked_at TEXT NOT NULL DEFAULT '',
			last_ok_at TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active'
		);`,
		`CREATE TABLE IF NOT EXISTS outbound_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			dedupe_key TEXT NOT NULL UNIQUE,
			kind INTEGER NOT NULL,
			author_pubkey TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			unsigned_json TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'published', 'dead')),
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TEXT NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			published_event_id TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS purgatory_events (
			event_id TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			kind INTEGER NOT NULL,
			d_tag TEXT NOT NULL DEFAULT '',
			event_json TEXT NOT NULL,
			required_shas TEXT NOT NULL,
			repo_path TEXT NOT NULL,
			accepted_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS pending_actor_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			gitea_user_id INTEGER NOT NULL,
			kind INTEGER NOT NULL,
			unsigned_event_json TEXT NOT NULL,
			scope TEXT NOT NULL,
			dedupe_key TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS user_grasp_list (
			pubkey TEXT PRIMARY KEY,
			event_json TEXT NOT NULL,
			event_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_republished_id TEXT NOT NULL DEFAULT ''
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

	// Migration: add mirror republish tracking columns.
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN announcement_event_json TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN announcement_event_id TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN last_republished_announcement_id TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN last_republished_announcement_at TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN last_state_digest TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN last_state_event_id TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE mappings ADD COLUMN last_state_published_at TEXT NOT NULL DEFAULT ''`)

	// Migration: add reflected-event head branch and echo guard columns. Existing
	// rows keep an empty head branch and are treated as pending bridge-origin
	// echoes because they predate one-shot consumption.
	_, _ = db.Exec(`ALTER TABLE reflected_events ADD COLUMN gitea_head_branch TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE reflected_events ADD COLUMN echo_pending INTEGER NOT NULL DEFAULT 1`)
	_, _ = db.Exec(`ALTER TABLE reflected_events ADD COLUMN echo_consumed_at TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE reflected_events ADD COLUMN echo_armed_at TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE reflected_events ADD COLUMN echo_fingerprint TEXT NOT NULL DEFAULT ''`)

	// Migration: the original identity-link table used gitea_username and did
	// not track updated_at. Preserve existing links while adopting the canonical
	// column names used by the authentication service.
	_, _ = db.Exec(`ALTER TABLE nostr_identity_links ADD COLUMN gitea_user TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE nostr_identity_links ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`UPDATE nostr_identity_links SET gitea_user = gitea_username WHERE gitea_user = ''`)
	_, _ = db.Exec(`UPDATE nostr_identity_links SET updated_at = created_at WHERE updated_at = ''`)
	var duplicateGiteaUserIDs string
	if err := db.QueryRow(`SELECT COALESCE(group_concat(gitea_user_id, ', '), '') FROM (SELECT gitea_user_id FROM nostr_identity_links GROUP BY gitea_user_id HAVING COUNT(*) > 1 ORDER BY gitea_user_id)`).Scan(&duplicateGiteaUserIDs); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("check duplicate Gitea identity mappings: %w", err)
	}
	if duplicateGiteaUserIDs != "" {
		_ = db.Close()
		return nil, fmt.Errorf("duplicate Gitea identity mappings for user IDs %s; resolve them before restart", duplicateGiteaUserIDs)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_nostr_identity_links_gitea_user_id ON nostr_identity_links(gitea_user_id)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enforce unique Gitea identity mapping: %w", err)
	}

	// Migration: early NIP-46 sessions used status/auth_code/error_msg. Retain
	// their state while moving to the canonical state/result_pubkey/error names.
	_, _ = db.Exec(`ALTER TABLE nip46_sessions ADD COLUMN state TEXT NOT NULL DEFAULT 'pending'`)
	_, _ = db.Exec(`ALTER TABLE nip46_sessions ADD COLUMN result_pubkey TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE nip46_sessions ADD COLUMN error TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`UPDATE nip46_sessions SET state = status WHERE status != ''`)
	_, _ = db.Exec(`UPDATE nip46_sessions SET result_pubkey = auth_code WHERE auth_code != ''`)
	_, _ = db.Exec(`UPDATE nip46_sessions SET error = error_msg WHERE error_msg != ''`)

	// Index for looking up mappings by Gitea repo ID (used by mirror sync callback).
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_mappings_gitea_repo_id ON mappings(gitea_repo_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_nostr_refs_first_seen_at ON pending_nostr_refs(first_seen_at)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_reflected_events_gitea_object ON reflected_events(gitea_repo_id, gitea_index, kind)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_reflected_events_echo_guard ON reflected_events(echo_pending, echo_armed_at)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_outbound_events_due ON outbound_events(state, next_attempt_at, id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_outbound_events_created_at ON outbound_events(created_at)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_actor_events_user_created ON pending_actor_events(gitea_user_id, created_at, id)`)

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// EnqueueOutboundEvent inserts an unsigned outbound event unless its dedupe key already exists.
// It returns true when a new row was inserted; duplicate dedupe keys are a no-op.
func (s *SQLiteStore) EnqueueOutboundEvent(ctx context.Context, ev OutboundEvent, now time.Time) (bool, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ev.NextAttemptAt.IsZero() {
		ev.NextAttemptAt = now
	}
	if ev.State == "" {
		ev.State = OutboundStatePending
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO outbound_events(dedupe_key, kind, author_pubkey, scope, unsigned_json, state, attempts, next_attempt_at, last_error, created_at, published_event_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ev.DedupeKey, ev.Kind, ev.AuthorPubkey, ev.Scope, ev.UnsignedJSON, ev.State, ev.Attempts,
		ev.NextAttemptAt.UTC().Format(time.RFC3339), ev.LastError, now.UTC().Format(time.RFC3339), ev.PublishedEventID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// ClaimDueOutboundEvents leases due pending events by moving next_attempt_at forward.
// If the worker crashes after claim, rows become due again after the lease expires.
func (s *SQLiteStore) ClaimDueOutboundEvents(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]OutboundEvent, error) {
	if limit <= 0 {
		limit = 1
	}
	if lease <= 0 {
		lease = time.Minute
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	claimUntil := now.Add(lease).UTC().Format(time.RFC3339)
	dueAt := now.UTC().Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM outbound_events
		WHERE state = ? AND next_attempt_at <= ?
		ORDER BY next_attempt_at ASC, id ASC
		LIMIT ?
	`, OutboundStatePending, dueAt, limit)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	claimed := make([]OutboundEvent, 0, len(ids))
	for _, id := range ids {
		res, err := tx.ExecContext(ctx, `
			UPDATE outbound_events SET next_attempt_at = ?
			WHERE id = ? AND state = ? AND next_attempt_at <= ?
		`, claimUntil, id, OutboundStatePending, dueAt)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		row := tx.QueryRowContext(ctx, outboundEventSelectSQL()+` WHERE id = ?`, id)
		ev, err := scanOutboundEvent(row)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, ev)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

// MarkOutboundPublished marks a pending outbound row as published and records the Nostr event id.
func (s *SQLiteStore) MarkOutboundPublished(ctx context.Context, id int64, publishedEventID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE outbound_events SET state = ?, published_event_id = ?, last_error = ''
		WHERE id = ? AND state = ?
	`, OutboundStatePublished, publishedEventID, id, OutboundStatePending)
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

// MarkOutboundRetry bumps attempts and schedules the next retry for a pending outbound row.
func (s *SQLiteStore) MarkOutboundRetry(ctx context.Context, id int64, nextAttemptAt time.Time, lastErr string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE outbound_events
		SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
		WHERE id = ? AND state = ?
	`, nextAttemptAt.UTC().Format(time.RFC3339), lastErr, id, OutboundStatePending)
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

// MarkOutboundDead moves a pending outbound row to the dead-letter state.
func (s *SQLiteStore) MarkOutboundDead(ctx context.Context, id int64, lastErr string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE outbound_events
		SET state = ?, attempts = attempts + 1, last_error = ?
		WHERE id = ? AND state = ?
	`, OutboundStateDead, lastErr, id, OutboundStatePending)
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

// OutboundQueueCounts returns counts for each queue state.
func (s *SQLiteStore) OutboundQueueCounts(ctx context.Context) (OutboundQueueCounts, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(1) FROM outbound_events GROUP BY state`)
	if err != nil {
		return OutboundQueueCounts{}, err
	}
	defer rows.Close()

	var counts OutboundQueueCounts
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return OutboundQueueCounts{}, err
		}
		switch state {
		case OutboundStatePending:
			counts.Pending = count
		case OutboundStatePublished:
			counts.Published = count
		case OutboundStateDead:
			counts.Dead = count
		}
	}
	return counts, rows.Err()
}

// RecentOutboundEvents returns recent outbound rows for admin inspection.
func (s *SQLiteStore) RecentOutboundEvents(ctx context.Context, limit int) ([]OutboundEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, outboundEventSelectSQL()+`
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OutboundEvent
	for rows.Next() {
		ev, err := scanOutboundEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

type outboundEventScanner interface {
	Scan(dest ...any) error
}

func outboundEventSelectSQL() string {
	return `SELECT id, dedupe_key, kind, author_pubkey, scope, unsigned_json, state, attempts, next_attempt_at, last_error, created_at, published_event_id FROM outbound_events`
}

func scanOutboundEvent(scanner outboundEventScanner) (OutboundEvent, error) {
	var ev OutboundEvent
	var nextAttemptAt, createdAt string
	if err := scanner.Scan(&ev.ID, &ev.DedupeKey, &ev.Kind, &ev.AuthorPubkey, &ev.Scope, &ev.UnsignedJSON,
		&ev.State, &ev.Attempts, &nextAttemptAt, &ev.LastError, &createdAt, &ev.PublishedEventID); err != nil {
		return OutboundEvent{}, err
	}
	var err error
	ev.NextAttemptAt, err = time.Parse(time.RFC3339, nextAttemptAt)
	if err != nil {
		return OutboundEvent{}, fmt.Errorf("parse outbound next_attempt_at for %d: %w", ev.ID, err)
	}
	ev.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return OutboundEvent{}, fmt.Errorf("parse outbound created_at for %d: %w", ev.ID, err)
	}
	return ev, nil
}

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 1000 {
		return msg[:1000]
	}
	return msg
}

// SavePendingActorEvent stores an unsigned actor event for later enqueue once
// the Gitea user links an active signer grant. Duplicate dedupe keys are no-ops.
// It trims rows for the same user older than maxAge and oldest rows beyond
// maxPerUser. It returns whether a row was inserted and how many old rows were
// trimmed.
func (s *SQLiteStore) SavePendingActorEvent(ctx context.Context, ev PendingActorEvent, now time.Time, maxPerUser int, maxAge time.Duration) (bool, int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ev.GiteaUserID == 0 {
		return false, 0, fmt.Errorf("gitea_user_id is required")
	}
	if strings.TrimSpace(ev.DedupeKey) == "" {
		return false, 0, fmt.Errorf("dedupe_key is required")
	}
	if maxPerUser <= 0 {
		maxPerUser = 500
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback()

	var trimmed int64
	if maxAge > 0 {
		cutoff := now.Add(-maxAge).UTC().Format(time.RFC3339)
		res, err := tx.ExecContext(ctx, `DELETE FROM pending_actor_events WHERE gitea_user_id = ? AND created_at < ?`, ev.GiteaUserID, cutoff)
		if err != nil {
			return false, 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, 0, err
		}
		trimmed += n
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO pending_actor_events(gitea_user_id, kind, unsigned_event_json, scope, dedupe_key, created_at)
		VALUES(?, ?, ?, ?, ?, ?)
	`, ev.GiteaUserID, ev.Kind, ev.UnsignedEventJSON, ev.Scope, ev.DedupeKey, now.UTC().Format(time.RFC3339))
	if err != nil {
		return false, 0, err
	}
	insertedRows, err := res.RowsAffected()
	if err != nil {
		return false, 0, err
	}

	res, err = tx.ExecContext(ctx, `
		DELETE FROM pending_actor_events
		WHERE gitea_user_id = ?
			AND id NOT IN (
				SELECT id FROM pending_actor_events
				WHERE gitea_user_id = ?
				ORDER BY created_at DESC, id DESC
				LIMIT ?
			)
	`, ev.GiteaUserID, ev.GiteaUserID, maxPerUser)
	if err != nil {
		return false, 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, 0, err
	}
	trimmed += n

	if err := tx.Commit(); err != nil {
		return false, 0, err
	}
	return insertedRows > 0, trimmed, nil
}

// ListPendingActorEvents returns pending actor rows for one Gitea user ordered
// from oldest to newest so backfill preserves webhook order.
func (s *SQLiteStore) ListPendingActorEvents(ctx context.Context, giteaUserID int64, limit int) ([]PendingActorEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, pendingActorEventSelectSQL()+`
		WHERE gitea_user_id = ?
		ORDER BY created_at ASC, id ASC
		LIMIT ?
	`, giteaUserID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PendingActorEvent
	for rows.Next() {
		ev, err := scanPendingActorEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// DeletePendingActorEvent deletes one pending actor row after it has been
// enqueued to the outbound signing queue.
func (s *SQLiteStore) DeletePendingActorEvent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_actor_events WHERE id = ?`, id)
	return err
}

func pendingActorEventSelectSQL() string {
	return `SELECT id, gitea_user_id, kind, unsigned_event_json, scope, dedupe_key, created_at FROM pending_actor_events `
}

type pendingActorEventScanner interface {
	Scan(dest ...any) error
}

func scanPendingActorEvent(scanner pendingActorEventScanner) (PendingActorEvent, error) {
	var ev PendingActorEvent
	var createdAt string
	if err := scanner.Scan(&ev.ID, &ev.GiteaUserID, &ev.Kind, &ev.UnsignedEventJSON, &ev.Scope, &ev.DedupeKey, &createdAt); err != nil {
		return PendingActorEvent{}, err
	}
	parsed, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return PendingActorEvent{}, fmt.Errorf("parse pending actor event created_at for %d: %w", ev.ID, err)
	}
	ev.CreatedAt = parsed
	return ev, nil
}

// UpsertSignerGrant creates or replaces a durable NIP-46 signer grant.
func (s *SQLiteStore) UpsertSignerGrant(ctx context.Context, grant SignerGrant) error {
	if grant.GrantedAt.IsZero() {
		grant.GrantedAt = time.Now().UTC()
	}
	if grant.Status == "" {
		grant.Status = "active"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO signer_grants(pubkey, client_seckey_enc, bunker_uri_enc, relays, permissions, granted_at, revoked_at, last_ok_at, status)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		grant.GrantedAt.UTC().Format(time.RFC3339), formatOptionalTime(grant.RevokedAt),
		formatOptionalTime(grant.LastOKAt), grant.Status)
	return err
}

// GetSignerGrant returns a stored signer grant by pubkey.
func (s *SQLiteStore) GetSignerGrant(ctx context.Context, pubkey string) (SignerGrant, error) {
	var grant SignerGrant
	var grantedAt, revokedAt, lastOKAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, client_seckey_enc, bunker_uri_enc, relays, permissions, granted_at, revoked_at, last_ok_at, status
		FROM signer_grants WHERE pubkey = ?
	`, pubkey).Scan(&grant.Pubkey, &grant.ClientSeckeyEnc, &grant.BunkerURIEnc, &grant.Relays,
		&grant.Permissions, &grantedAt, &revokedAt, &lastOKAt, &grant.Status)
	if err != nil {
		return SignerGrant{}, err
	}
	var parseErr error
	grant.GrantedAt, parseErr = time.Parse(time.RFC3339, grantedAt)
	if parseErr != nil {
		return SignerGrant{}, fmt.Errorf("parse granted_at for signer grant %s: %w", pubkey, parseErr)
	}
	grant.RevokedAt, parseErr = parseOptionalTime(revokedAt)
	if parseErr != nil {
		return SignerGrant{}, fmt.Errorf("parse revoked_at for signer grant %s: %w", pubkey, parseErr)
	}
	grant.LastOKAt, parseErr = parseOptionalTime(lastOKAt)
	if parseErr != nil {
		return SignerGrant{}, fmt.Errorf("parse last_ok_at for signer grant %s: %w", pubkey, parseErr)
	}
	return grant, nil
}

// RevokeSignerGrant marks a signer grant as revoked without deleting its audit row.
func (s *SQLiteStore) RevokeSignerGrant(ctx context.Context, pubkey string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE signer_grants SET revoked_at = ?, status = 'revoked' WHERE pubkey = ?`, at.UTC().Format(time.RFC3339), pubkey)
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

// RecordSignerGrantOK updates the last successful signer health/sign timestamp.
func (s *SQLiteStore) RecordSignerGrantOK(ctx context.Context, pubkey string, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE signer_grants SET last_ok_at = ? WHERE pubkey = ?`, at.UTC().Format(time.RFC3339), pubkey)
	return err
}

func formatOptionalTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseOptionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
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

// RecordReflectedEvent records a Nostr event that was reflected into Gitea.
// It returns true when a new row was inserted; duplicate Nostr event IDs are a no-op.
func (s *SQLiteStore) RecordReflectedEvent(ctx context.Context, ref ReflectedEvent) (bool, error) {
	if ref.CreatedAt.IsZero() {
		ref.CreatedAt = time.Now().UTC()
	}
	if ref.EchoArmedAt.IsZero() {
		ref.EchoArmedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO reflected_events(nostr_event_id, gitea_repo_id, gitea_index, gitea_head_branch, kind, created_at, echo_pending, echo_consumed_at, echo_armed_at, echo_fingerprint)
		VALUES(?, ?, ?, ?, ?, ?, 1, '', ?, ?)
	`, ref.NostrEventID, ref.GiteaRepoID, ref.GiteaIndex, ref.HeadBranch, ref.Kind, ref.CreatedAt.UTC().Format(time.RFC3339), ref.EchoArmedAt.UTC().Format(time.RFC3339), ref.EchoFingerprint)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// RecordNostrObjectMapping records a Nostr event ID to Gitea object mapping
// without arming the webhook echo guard. This is used for Gitea-origin events
// that were published to Nostr and may later be referenced by Nostr comments or
// status events.
func (s *SQLiteStore) RecordNostrObjectMapping(ctx context.Context, ref ReflectedEvent) (bool, error) {
	if ref.CreatedAt.IsZero() {
		ref.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO reflected_events(nostr_event_id, gitea_repo_id, gitea_index, gitea_head_branch, kind, created_at, echo_pending, echo_consumed_at, echo_armed_at, echo_fingerprint)
		VALUES(?, ?, ?, ?, ?, ?, 0, '', '', '')
	`, ref.NostrEventID, ref.GiteaRepoID, ref.GiteaIndex, ref.HeadBranch, ref.Kind, ref.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// GetReflectedEvent returns the reflected Gitea object for a Nostr event ID.
func (s *SQLiteStore) GetReflectedEvent(ctx context.Context, nostrEventID string) (ReflectedEvent, error) {
	var ref ReflectedEvent
	var createdAt, echoArmedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT nostr_event_id, gitea_repo_id, gitea_index, gitea_head_branch, kind, created_at, echo_armed_at, echo_fingerprint
		FROM reflected_events WHERE nostr_event_id = ?
	`, nostrEventID).Scan(&ref.NostrEventID, &ref.GiteaRepoID, &ref.GiteaIndex, &ref.HeadBranch, &ref.Kind, &createdAt, &echoArmedAt, &ref.EchoFingerprint)
	if err != nil {
		return ReflectedEvent{}, err
	}
	parsed, parseErr := time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return ReflectedEvent{}, fmt.Errorf("parse reflected event created_at for %s: %w", nostrEventID, parseErr)
	}
	ref.CreatedAt = parsed
	if echoArmedAt != "" {
		armedAt, parseErr := time.Parse(time.RFC3339, echoArmedAt)
		if parseErr != nil {
			return ReflectedEvent{}, fmt.Errorf("parse reflected event echo_armed_at for %s: %w", nostrEventID, parseErr)
		}
		ref.EchoArmedAt = armedAt
	}
	return ref, nil
}

// CheckReflectedGiteaEcho reports whether a Gitea webhook matches an armed
// Nostr-origin echo guard. Matching is non-consuming: duplicate deliveries with
// the same fingerprint are suppressed throughout the guard window. Expired
// guards are lazily disarmed before checking.
func (s *SQLiteStore) CheckReflectedGiteaEcho(ctx context.Context, giteaRepoID int64, giteaIndex int64, kind int, fingerprint string, now time.Time, window time.Duration) (bool, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if window <= 0 {
		window = DefaultEchoGuardWindow
	}
	if _, err := s.DisarmExpiredEchoGuards(ctx, now, window); err != nil {
		return false, err
	}
	cutoff := now.UTC().Add(-window).Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		UPDATE reflected_events
		SET echo_consumed_at = ?
		WHERE gitea_repo_id = ? AND gitea_index = ? AND kind = ?
			AND echo_pending = 1
			AND COALESCE(NULLIF(echo_armed_at, ''), created_at) >= ?
			AND (echo_fingerprint = ? OR echo_fingerprint = '')
	`, now.UTC().Format(time.RFC3339), giteaRepoID, giteaIndex, kind, cutoff, fingerprint)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// DisarmExpiredEchoGuards clears echo guards that are older than the guard
// window. It is safe to call lazily from webhook checks or periodically from a
// maintenance loop.
func (s *SQLiteStore) DisarmExpiredEchoGuards(ctx context.Context, now time.Time, window time.Duration) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if window <= 0 {
		window = DefaultEchoGuardWindow
	}
	cutoff := now.UTC().Add(-window).Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		UPDATE reflected_events
		SET echo_pending = 0
		WHERE echo_pending = 1
			AND COALESCE(NULLIF(echo_armed_at, ''), created_at) < ?
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// WasReflectedGiteaObject reports whether a Gitea repo/index/kind was created
// or updated by the bridge while reflecting a Nostr event.
func (s *SQLiteStore) WasReflectedGiteaObject(ctx context.Context, giteaRepoID int64, giteaIndex int64, kind int) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM reflected_events
		WHERE gitea_repo_id = ? AND gitea_index = ? AND kind = ?
		LIMIT 1
	`, giteaRepoID, giteaIndex, kind).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
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

// HasProvisionedOwnerPubkey reports whether pubkey owns at least one fully
// provisioned repository mapping. It is used to avoid amplifying arbitrary
// kind:10317 user GRASP lists from unknown pubkeys.
func (s *SQLiteStore) HasProvisionedOwnerPubkey(ctx context.Context, pubkey string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM mappings WHERE pubkey = ? AND hook_installed = 1 LIMIT 1`, pubkey).Scan(&exists)
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
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed,
			announcement_event_json, announcement_event_id,
			last_republished_announcement_id, last_republished_announcement_at,
			last_state_digest, last_state_event_id, last_state_published_at,
			created_at, updated_at
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
		var createdAt, updatedAt string
		var lastRepubAnnAt, lastStatePubAt string
		if err := rows.Scan(
			&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID,
			&m.CloneURL, &m.AnnouncedCloneURL, &m.SourceEvent, &hookVal,
			&m.AnnouncementEventJSON, &m.AnnouncementEventID,
			&m.LastRepublishedAnnouncementID, &lastRepubAnnAt,
			&m.LastStateDigest, &m.LastStateEventID, &lastStatePubAt,
			&createdAt, &updatedAt,
		); err != nil {
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
		if lastRepubAnnAt != "" {
			m.LastRepublishedAnnouncementAt, _ = time.Parse(time.RFC3339, lastRepubAnnAt)
		}
		if lastStatePubAt != "" {
			m.LastStatePublishedAt, _ = time.Parse(time.RFC3339, lastStatePubAt)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RecordPendingNostrRef records or refreshes an observed refs/nostr/<event-id>
// push. Updating first_seen_at on conflict treats a changed/refreshed tip as a
// new 20-minute acceptance window.
func (s *SQLiteStore) RecordPendingNostrRef(ctx context.Context, ref PendingNostrRef) error {
	firstSeen := ref.FirstSeenAt
	if firstSeen.IsZero() {
		firstSeen = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_nostr_refs(event_id, tip_sha, gitea_repo_id, owner, repo_name, first_seen_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(gitea_repo_id, event_id) DO UPDATE SET
			tip_sha = excluded.tip_sha,
			owner = excluded.owner,
			repo_name = excluded.repo_name,
			first_seen_at = excluded.first_seen_at
	`, ref.EventID, ref.TipSHA, ref.GiteaRepoID, ref.Owner, ref.RepoName, firstSeen.UTC().Format(time.RFC3339))
	return err
}

// ListPendingNostrRefsOlderThan returns pending refs whose acceptance window
// has expired.
func (s *SQLiteStore) ListPendingNostrRefsOlderThan(ctx context.Context, cutoff time.Time) ([]PendingNostrRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, tip_sha, gitea_repo_id, owner, repo_name, first_seen_at
		FROM pending_nostr_refs
		WHERE first_seen_at <= ?
		ORDER BY first_seen_at ASC
	`, cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PendingNostrRef
	for rows.Next() {
		var ref PendingNostrRef
		var firstSeen string
		if err := rows.Scan(&ref.EventID, &ref.TipSHA, &ref.GiteaRepoID, &ref.Owner, &ref.RepoName, &firstSeen); err != nil {
			return nil, err
		}
		parsed, parseErr := time.Parse(time.RFC3339, firstSeen)
		if parseErr != nil {
			return nil, fmt.Errorf("parse first_seen_at for refs/nostr/%s: %w", ref.EventID, parseErr)
		}
		ref.FirstSeenAt = parsed
		out = append(out, ref)
	}
	return out, rows.Err()
}

// DeletePendingNostrRef removes a pending refs/nostr lifecycle row.
func (s *SQLiteStore) DeletePendingNostrRef(ctx context.Context, giteaRepoID int64, eventID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_nostr_refs WHERE gitea_repo_id = ? AND event_id = ?`, giteaRepoID, eventID)
	return err
}

func (s *SQLiteStore) GetMapping(ctx context.Context, npub string, repoID string) (Mapping, error) {
	return s.getMappingWhere(ctx, "npub = ? AND repo_id = ?", npub, repoID)
}

// GetProvisionedMappingByRepoAddr looks up a fully provisioned repository by
// the components of a NIP-34 repo coordinate: 30617:<pubkey>:<repo-id>.
func (s *SQLiteStore) GetProvisionedMappingByRepoAddr(ctx context.Context, pubkey string, repoID string) (Mapping, error) {
	return s.getMappingWhere(ctx, "pubkey = ? AND repo_id = ? AND hook_installed = 1", pubkey, repoID)
}

func (s *SQLiteStore) getMappingWhere(ctx context.Context, where string, args ...any) (Mapping, error) {
	var m Mapping
	var hookVal int
	var createdAt, updatedAt string
	var lastRepubAnnAt, lastStatePubAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed,
			announcement_event_json, announcement_event_id,
			last_republished_announcement_id, last_republished_announcement_at,
			last_state_digest, last_state_event_id, last_state_published_at,
			created_at, updated_at
		FROM mappings WHERE `+where+` LIMIT 1
	`, args...).Scan(
		&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID,
		&m.CloneURL, &m.AnnouncedCloneURL, &m.SourceEvent, &hookVal,
		&m.AnnouncementEventJSON, &m.AnnouncementEventID,
		&m.LastRepublishedAnnouncementID, &lastRepubAnnAt,
		&m.LastStateDigest, &m.LastStateEventID, &lastStatePubAt,
		&createdAt, &updatedAt,
	)
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
	if lastRepubAnnAt != "" {
		m.LastRepublishedAnnouncementAt, _ = time.Parse(time.RFC3339, lastRepubAnnAt)
	}
	if lastStatePubAt != "" {
		m.LastStatePublishedAt, _ = time.Parse(time.RFC3339, lastStatePubAt)
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

// --- User GRASP list cache methods ---

// UpsertUserGraspListEvent stores a kind:10317 event if it is the first event
// for the owner pubkey or has a newer created_at than the cached event. It
// returns true only when the cache was inserted or replaced.
func (s *SQLiteStore) UpsertUserGraspListEvent(ctx context.Context, list UserGraspList) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO user_grasp_list(pubkey, event_json, event_id, created_at, last_republished_id)
		VALUES(?, ?, ?, ?, '')
		ON CONFLICT(pubkey) DO UPDATE SET
			event_json = excluded.event_json,
			event_id = excluded.event_id,
			created_at = excluded.created_at
		WHERE user_grasp_list.created_at < excluded.created_at
	`, list.Pubkey, list.EventJSON, list.EventID, list.CreatedAt)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// GetUserGraspList returns the cached kind:10317 event for an owner pubkey.
func (s *SQLiteStore) GetUserGraspList(ctx context.Context, pubkey string) (UserGraspList, error) {
	var list UserGraspList
	err := s.db.QueryRowContext(ctx, `
		SELECT pubkey, event_json, event_id, created_at, last_republished_id
		FROM user_grasp_list WHERE pubkey = ?
	`, pubkey).Scan(&list.Pubkey, &list.EventJSON, &list.EventID, &list.CreatedAt, &list.LastRepublishedID)
	if err != nil {
		return UserGraspList{}, err
	}
	return list, nil
}

// RecordUserGraspListRepublished records the event ID last rebroadcast from
// the owner-signed kind:10317 cache.
func (s *SQLiteStore) RecordUserGraspListRepublished(ctx context.Context, pubkey, eventID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_grasp_list SET last_republished_id = ? WHERE pubkey = ?`, eventID, pubkey)
	return err
}

// --- Mirror republish methods ---

// GetMappingByGiteaRepoID looks up a mapping by its Gitea repository ID.
// Returns sql.ErrNoRows if not found.
func (s *SQLiteStore) GetMappingByGiteaRepoID(ctx context.Context, giteaRepoID int64) (Mapping, error) {
	var m Mapping
	var hookVal int
	var createdAt, updatedAt string
	var lastRepubAnnAt, lastStatePubAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, announced_clone_url, source_event, hook_installed,
			announcement_event_json, announcement_event_id,
			last_republished_announcement_id, last_republished_announcement_at,
			last_state_digest, last_state_event_id, last_state_published_at,
			created_at, updated_at
		FROM mappings WHERE gitea_repo_id = ? LIMIT 1
	`, giteaRepoID).Scan(
		&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID,
		&m.CloneURL, &m.AnnouncedCloneURL, &m.SourceEvent, &hookVal,
		&m.AnnouncementEventJSON, &m.AnnouncementEventID,
		&m.LastRepublishedAnnouncementID, &lastRepubAnnAt,
		&m.LastStateDigest, &m.LastStateEventID, &lastStatePubAt,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return Mapping{}, err
	}
	m.HookInstalled = hookVal != 0
	var parseErr error
	m.CreatedAt, parseErr = time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return Mapping{}, fmt.Errorf("parse created_at: %w", parseErr)
	}
	m.UpdatedAt, parseErr = time.Parse(time.RFC3339, updatedAt)
	if parseErr != nil {
		return Mapping{}, fmt.Errorf("parse updated_at: %w", parseErr)
	}
	if lastRepubAnnAt != "" {
		m.LastRepublishedAnnouncementAt, _ = time.Parse(time.RFC3339, lastRepubAnnAt)
	}
	if lastStatePubAt != "" {
		m.LastStatePublishedAt, _ = time.Parse(time.RFC3339, lastStatePubAt)
	}
	return m, nil
}

// SetAnnouncementEvent caches the raw owner-signed announcement event JSON and ID.
func (s *SQLiteStore) SetAnnouncementEvent(ctx context.Context, npub, repoID, eventJSON, eventID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		UPDATE mappings SET announcement_event_json = ?, announcement_event_id = ?, updated_at = ?
		WHERE npub = ? AND repo_id = ?
	`, eventJSON, eventID, now, npub, repoID)
	return err
}

// RecordAnnouncementRepublished records that the cached announcement was republished.
func (s *SQLiteStore) RecordAnnouncementRepublished(ctx context.Context, npub, repoID, announcementEventID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE mappings SET last_republished_announcement_id = ?, last_republished_announcement_at = ?
		WHERE npub = ? AND repo_id = ?
	`, announcementEventID, at.UTC().Format(time.RFC3339), npub, repoID)
	return err
}

// RecordStatePublished records the digest and event ID of the last published state event.
func (s *SQLiteStore) RecordStatePublished(ctx context.Context, npub, repoID, digest, stateEventID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE mappings SET last_state_digest = ?, last_state_event_id = ?, last_state_published_at = ?
		WHERE npub = ? AND repo_id = ?
	`, digest, stateEventID, at.UTC().Format(time.RFC3339), npub, repoID)
	return err
}

// --- NIP-46 session methods ---

// CreateNIP46Session persists a new NIP-46 login session.
func (s *SQLiteStore) CreateNIP46Session(ctx context.Context, sess NIP46Session) error {
	if hasLegacyNIP46Columns(s.db) {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO nip46_sessions(
				session_token, bunker_pubkey, client_pubkey, oauth2_state, redirect_uri,
				status, auth_code, error_msg, created_at, expires_at,
				state, result_pubkey, error
			) VALUES(?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, sess.SessionToken, sess.BunkerPubkey, sess.ClientPubkey, sess.RedirectURI,
			sess.State, sess.ResultPubkey, sess.Error,
			sess.CreatedAt.UTC().Format(time.RFC3339), sess.ExpiresAt.UTC().Format(time.RFC3339),
			sess.State, sess.ResultPubkey, sess.Error)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nip46_sessions(session_token, bunker_pubkey, client_pubkey, state, redirect_uri, result_pubkey, error, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sess.SessionToken, sess.BunkerPubkey, sess.ClientPubkey, sess.State,
		sess.RedirectURI, sess.ResultPubkey, sess.Error,
		sess.CreatedAt.UTC().Format(time.RFC3339),
		sess.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func hasLegacyNIP46Columns(db *sql.DB) bool {
	rows, err := db.Query(`PRAGMA table_info(nip46_sessions)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false
		}
		if name == "oauth2_state" {
			return true
		}
	}
	return false
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

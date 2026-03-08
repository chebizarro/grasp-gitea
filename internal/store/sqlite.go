package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Mapping struct {
	Npub        string    `json:"npub"`
	RepoID      string    `json:"repo_id"`
	Pubkey      string    `json:"pubkey"`
	Owner       string    `json:"owner"`
	RepoName    string    `json:"repo_name"`
	GiteaRepoID int64     `json:"gitea_repo_id"`
	CloneURL    string    `json:"clone_url"`
	SourceEvent string    `json:"source_event"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init sqlite schema: %w", err)
		}
	}

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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mappings(npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, source_event, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(npub, repo_id) DO UPDATE SET
			pubkey = excluded.pubkey,
			owner = excluded.owner,
			repo_name = excluded.repo_name,
			gitea_repo_id = excluded.gitea_repo_id,
			clone_url = excluded.clone_url,
			source_event = excluded.source_event,
			updated_at = excluded.updated_at
	`, m.Npub, m.RepoID, m.Pubkey, m.Owner, m.RepoName, m.GiteaRepoID, m.CloneURL, m.SourceEvent, now, now)
	return err
}

func (s *SQLiteStore) ListMappings(ctx context.Context) ([]Mapping, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT npub, repo_id, pubkey, owner, repo_name, gitea_repo_id, clone_url, source_event, created_at, updated_at
		FROM mappings
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Mapping, 0)
	for rows.Next() {
		var m Mapping
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&m.Npub, &m.RepoID, &m.Pubkey, &m.Owner, &m.RepoName, &m.GiteaRepoID, &m.CloneURL, &m.SourceEvent, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		m.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		out = append(out, m)
	}
	return out, rows.Err()
}

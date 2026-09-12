package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// WritableUpstreamMigration preserves both sides of a mirror-to-upstream
// topology switch. The old pull mirror is never modified or deleted.
type WritableUpstreamMigration struct {
	Npub, RepoID                       string
	OldOwner, OldRepoName, OldCloneURL string
	NewOwner, NewRepoName, NewCloneURL string
	TargetMarker                       string
	OldGiteaRepoID, NewGiteaRepoID     int64
	Active                             bool
	ExpectedMappingUpdatedAt           time.Time
	CreatedAt, UpdatedAt               time.Time
}

func scanWritableUpstream(row interface{ Scan(...any) error }) (WritableUpstreamMigration, error) {
	var m WritableUpstreamMigration
	var active int
	var created, updated string
	var mappingUpdated string
	err := row.Scan(&m.Npub, &m.RepoID, &m.OldOwner, &m.OldRepoName, &m.OldGiteaRepoID, &m.OldCloneURL,
		&m.NewOwner, &m.NewRepoName, &m.NewGiteaRepoID, &m.NewCloneURL, &m.TargetMarker, &active, &mappingUpdated, &created, &updated)
	if err != nil {
		return m, err
	}
	m.Active = active != 0
	m.ExpectedMappingUpdatedAt, err = parseStoreTime(mappingUpdated)
	if err != nil {
		return m, err
	}
	m.CreatedAt, err = parseStoreTime(created)
	if err == nil {
		m.UpdatedAt, err = parseStoreTime(updated)
	}
	return m, err
}

const writableUpstreamSelect = `SELECT npub,repo_id,old_owner,old_repo_name,old_gitea_repo_id,old_clone_url,new_owner,new_repo_name,new_gitea_repo_id,new_clone_url,target_marker,active,mapping_updated_at,created_at,updated_at FROM writable_upstream_migrations`

func (s *SQLiteStore) GetWritableUpstreamMigration(ctx context.Context, npub, repoID string) (WritableUpstreamMigration, error) {
	return scanWritableUpstream(s.db.QueryRowContext(ctx, writableUpstreamSelect+` WHERE npub=? AND repo_id=?`, npub, repoID))
}

// PrepareWritableUpstream records the exact source mapping and deterministic
// target name before any Gitea repository is created. This prevents a retry
// from silently adopting an unrelated pre-existing repository.
func (s *SQLiteStore) PrepareWritableUpstream(ctx context.Context, m WritableUpstreamMigration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM mappings WHERE npub=? AND repo_id=? AND owner=? AND repo_name=? AND gitea_repo_id=? AND updated_at=? AND migrating=0`, m.Npub, m.RepoID, m.OldOwner, m.OldRepoName, m.OldGiteaRepoID, m.ExpectedMappingUpdatedAt.UTC().Format(time.RFC3339)).Scan(&exists)
	if err != nil {
		return fmt.Errorf("mapping prepare compare-and-swap rejected: %w", err)
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO writable_upstream_migrations(npub,repo_id,old_owner,old_repo_name,old_gitea_repo_id,old_clone_url,new_owner,new_repo_name,new_gitea_repo_id,new_clone_url,target_marker,active,mapping_updated_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.Npub, m.RepoID, m.OldOwner, m.OldRepoName, m.OldGiteaRepoID, m.OldCloneURL, m.NewOwner, m.NewRepoName, 0, "", m.TargetMarker, 0, tt(m.ExpectedMappingUpdatedAt), tt(now), tt(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ActivateWritableUpstream atomically changes only the physical mapping when
// it still names the exact expected pull mirror, and records a rollback row in
// the same transaction.
func (s *SQLiteStore) ActivateWritableUpstream(ctx context.Context, m WritableUpstreamMigration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	insert, err := tx.ExecContext(ctx, `INSERT INTO writable_upstream_migrations(npub,repo_id,old_owner,old_repo_name,old_gitea_repo_id,old_clone_url,new_owner,new_repo_name,new_gitea_repo_id,new_clone_url,target_marker,active,mapping_updated_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(npub,repo_id) DO UPDATE SET old_owner=excluded.old_owner,old_repo_name=excluded.old_repo_name,old_gitea_repo_id=excluded.old_gitea_repo_id,old_clone_url=excluded.old_clone_url,new_owner=excluded.new_owner,new_repo_name=excluded.new_repo_name,new_gitea_repo_id=excluded.new_gitea_repo_id,new_clone_url=excluded.new_clone_url,target_marker=excluded.target_marker,active=1,updated_at=excluded.updated_at WHERE writable_upstream_migrations.active=0`,
		m.Npub, m.RepoID, m.OldOwner, m.OldRepoName, m.OldGiteaRepoID, m.OldCloneURL, m.NewOwner, m.NewRepoName, m.NewGiteaRepoID, m.NewCloneURL, m.TargetMarker, 1, tt(m.ExpectedMappingUpdatedAt), tt(now), tt(now))
	if err != nil {
		return err
	}
	if n, err := insert.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("an active writable-upstream migration already exists")
	}
	result, err := tx.ExecContext(ctx, `UPDATE mappings SET owner=?,repo_name=?,gitea_repo_id=?,clone_url=?,hook_installed=1,updated_at=? WHERE npub=? AND repo_id=? AND owner=? AND repo_name=? AND gitea_repo_id=? AND updated_at=? AND migrating=0`,
		m.NewOwner, m.NewRepoName, m.NewGiteaRepoID, m.NewCloneURL, tt(now), m.Npub, m.RepoID, m.OldOwner, m.OldRepoName, m.OldGiteaRepoID, m.ExpectedMappingUpdatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("mapping compare-and-swap rejected: %w", sql.ErrNoRows)
	}
	return tx.Commit()
}

// RollbackWritableUpstream restores the preserved pull-mirror mapping only if
// the mapping still names the exact activated upstream.
func (s *SQLiteStore) RollbackWritableUpstream(ctx context.Context, npub, repoID string, expectedNewID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	m, err := scanWritableUpstream(tx.QueryRowContext(ctx, writableUpstreamSelect+` WHERE npub=? AND repo_id=? AND active=1`, npub, repoID))
	if err != nil {
		return err
	}
	if m.NewGiteaRepoID != expectedNewID {
		return fmt.Errorf("upstream repository id mismatch")
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE mappings SET owner=?,repo_name=?,gitea_repo_id=?,clone_url=?,hook_installed=1,updated_at=? WHERE npub=? AND repo_id=? AND owner=? AND repo_name=? AND gitea_repo_id=? AND migrating=0`,
		m.OldOwner, m.OldRepoName, m.OldGiteaRepoID, m.OldCloneURL, tt(now), npub, repoID, m.NewOwner, m.NewRepoName, m.NewGiteaRepoID)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		if err != nil {
			return err
		}
		return fmt.Errorf("mapping rollback compare-and-swap rejected: %w", sql.ErrNoRows)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE writable_upstream_migrations SET active=0,updated_at=? WHERE npub=? AND repo_id=? AND active=1`, tt(now), npub, repoID); err != nil {
		return err
	}
	return tx.Commit()
}

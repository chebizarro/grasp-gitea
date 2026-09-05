package store

import (
	"context"
	"database/sql"
	"time"
)

const (
	MigrationStepPrepared          = "prepared"
	MigrationStepQuiesced          = "quiesced"
	MigrationStepTransferred       = "transferred"
	MigrationStepRenamed           = "renamed"
	MigrationStepMappingUpdated    = "mapping_updated"
	MigrationStepHookVerified      = "hook_verified"
	MigrationStepCollaboratorReady = "collaborator_ready"
)

// RepoMigration is the durable rollback journal for one existing-repository
// move. The original and target physical paths are captured before quiescing.
type RepoMigration struct {
	Npub         string    `json:"npub"`
	RepoID       string    `json:"repo_id"`
	Pubkey       string    `json:"pubkey"`
	TenantHost   string    `json:"tenant_host"`
	OldOwner     string    `json:"old_owner"`
	OldRepoName  string    `json:"old_repo_name"`
	NewOwner     string    `json:"new_owner"`
	NewRepoName  string    `json:"new_repo_name"`
	GiteaRepoID  int64     `json:"gitea_repo_id"`
	Collaborator string    `json:"collaborator"`
	Step         string    `json:"step"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

const migrationSelect = `SELECT npub,repo_id,pubkey,tenant_host,old_owner,old_repo_name,new_owner,new_repo_name,gitea_repo_id,collaborator,step,created_at,updated_at FROM repo_migrations`

type migrationScanner interface{ Scan(...any) error }

func scanMigration(s migrationScanner) (RepoMigration, error) {
	var m RepoMigration
	var created, updated string
	if err := s.Scan(&m.Npub, &m.RepoID, &m.Pubkey, &m.TenantHost, &m.OldOwner, &m.OldRepoName, &m.NewOwner, &m.NewRepoName, &m.GiteaRepoID, &m.Collaborator, &m.Step, &created, &updated); err != nil {
		return m, err
	}
	var err error
	m.CreatedAt, err = parseStoreTime(created)
	if err != nil {
		return m, err
	}
	m.UpdatedAt, err = parseStoreTime(updated)
	return m, err
}

func migrationArgs(m RepoMigration) []any {
	return []any{m.Npub, m.RepoID, m.Pubkey, m.TenantHost, m.OldOwner, m.OldRepoName, m.NewOwner, m.NewRepoName, m.GiteaRepoID, m.Collaborator, m.Step, tt(m.CreatedAt), tt(m.UpdatedAt)}
}

func (s *SQLiteStore) CreateRepoMigration(ctx context.Context, m RepoMigration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repo_migrations(npub,repo_id,pubkey,tenant_host,old_owner,old_repo_name,new_owner,new_repo_name,gitea_repo_id,collaborator,step,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, migrationArgs(m)...)
	return err
}
func (s *PostgresStore) CreateRepoMigration(ctx context.Context, m RepoMigration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO repo_migrations(npub,repo_id,pubkey,tenant_host,old_owner,old_repo_name,new_owner,new_repo_name,gitea_repo_id,collaborator,step,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, migrationArgs(m)...)
	return err
}
func (s *SQLiteStore) UpdateRepoMigrationStep(ctx context.Context, npub, repoID, step string, at time.Time) error {
	r, err := s.db.ExecContext(ctx, `UPDATE repo_migrations SET step=?,updated_at=? WHERE npub=? AND repo_id=?`, step, tt(at), npub, repoID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
func (s *PostgresStore) UpdateRepoMigrationStep(ctx context.Context, npub, repoID, step string, at time.Time) error {
	r, err := s.db.ExecContext(ctx, `UPDATE repo_migrations SET step=$1,updated_at=$2 WHERE npub=$3 AND repo_id=$4`, step, tt(at), npub, repoID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
func scanMigrations(rows *sql.Rows) ([]RepoMigration, error) {
	defer rows.Close()
	var out []RepoMigration
	for rows.Next() {
		m, err := scanMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (s *SQLiteStore) ListRepoMigrations(ctx context.Context) ([]RepoMigration, error) {
	rows, err := s.db.QueryContext(ctx, migrationSelect+` ORDER BY created_at,npub,repo_id`)
	if err != nil {
		return nil, err
	}
	return scanMigrations(rows)
}
func (s *PostgresStore) ListRepoMigrations(ctx context.Context) ([]RepoMigration, error) {
	rows, err := s.db.QueryContext(ctx, migrationSelect+` ORDER BY created_at,npub,repo_id`)
	if err != nil {
		return nil, err
	}
	return scanMigrations(rows)
}
func (s *SQLiteStore) DeleteRepoMigration(ctx context.Context, npub, repoID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM repo_migrations WHERE npub=? AND repo_id=?`, npub, repoID)
	return err
}
func (s *PostgresStore) DeleteRepoMigration(ctx context.Context, npub, repoID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM repo_migrations WHERE npub=$1 AND repo_id=$2`, npub, repoID)
	return err
}

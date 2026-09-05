package store

import (
	"context"
	"database/sql"
	"time"
)

type TenantSCIMToken struct {
	Host        string
	TokenHash   []byte
	TokenSuffix string
	Generation  int64
	UpdatedAt   time.Time
}

type SCIMUser struct {
	Host, ID, UserName, ExternalID, Pubkey string
	ProfileJSON                            string
	Active                                 bool
	Version                                int64
	CreatedAt, UpdatedAt                   time.Time
}

type SCIMGroup struct {
	Host, ID, DisplayName string
	Active                bool
	Version               int64
	CreatedAt, UpdatedAt  time.Time
}

func scanSCIMToken(s tenantScanner) (TenantSCIMToken, error) {
	var v TenantSCIMToken
	var at string
	if err := s.Scan(&v.Host, &v.TokenHash, &v.TokenSuffix, &v.Generation, &at); err != nil {
		return v, err
	}
	var err error
	v.UpdatedAt, err = parseStoreTime(at)
	return v, err
}
func (s *SQLiteStore) UpsertTenantSCIMToken(c context.Context, v TenantSCIMToken) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_scim_tokens(host,token_hash,token_suffix,generation,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET token_hash=excluded.token_hash,token_suffix=excluded.token_suffix,generation=excluded.generation,pending_token_hash=NULL,pending_token_suffix='',pending_generation=0,updated_at=excluded.updated_at`, v.Host, v.TokenHash, v.TokenSuffix, v.Generation, tt(v.UpdatedAt))
	return e
}
func (s *PostgresStore) UpsertTenantSCIMToken(c context.Context, v TenantSCIMToken) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_scim_tokens(host,token_hash,token_suffix,generation,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(host) DO UPDATE SET token_hash=excluded.token_hash,token_suffix=excluded.token_suffix,generation=excluded.generation,pending_token_hash=NULL,pending_token_suffix='',pending_generation=0,updated_at=excluded.updated_at`, v.Host, v.TokenHash, v.TokenSuffix, v.Generation, tt(v.UpdatedAt))
	return e
}
func (s *SQLiteStore) StageTenantSCIMToken(c context.Context, v TenantSCIMToken) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_scim_tokens(host,pending_token_hash,pending_token_suffix,pending_generation,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET pending_token_hash=excluded.pending_token_hash,pending_token_suffix=excluded.pending_token_suffix,pending_generation=excluded.pending_generation,updated_at=excluded.updated_at`, v.Host, v.TokenHash, v.TokenSuffix, v.Generation, tt(v.UpdatedAt))
	return e
}
func (s *PostgresStore) StageTenantSCIMToken(c context.Context, v TenantSCIMToken) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_scim_tokens(host,pending_token_hash,pending_token_suffix,pending_generation,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(host) DO UPDATE SET pending_token_hash=excluded.pending_token_hash,pending_token_suffix=excluded.pending_token_suffix,pending_generation=excluded.pending_generation,updated_at=excluded.updated_at`, v.Host, v.TokenHash, v.TokenSuffix, v.Generation, tt(v.UpdatedAt))
	return e
}
func activateSCIMToken(c context.Context, tx *sql.Tx, pg bool, host string, hash []byte, version int64, at time.Time) (bool, error) {
	q := `UPDATE tenant_scim_tokens SET token_hash=pending_token_hash,token_suffix=pending_token_suffix,generation=pending_generation,pending_token_hash=NULL,pending_token_suffix='',pending_generation=0,updated_at=? WHERE host=? AND pending_token_hash=?`
	args := []any{tt(at), host, hash}
	if pg {
		q = `UPDATE tenant_scim_tokens SET token_hash=pending_token_hash,token_suffix=pending_token_suffix,generation=pending_generation,pending_token_hash=NULL,pending_token_suffix='',pending_generation=0,updated_at=$1 WHERE host=$2 AND pending_token_hash=$3`
	}
	r, e := tx.ExecContext(c, q, args...)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	q = `UPDATE managed_tenants SET version=version+1,reconciled_version=version+1,updated_at=? WHERE host=? AND version=?`
	args = []any{tt(at), host, version}
	if pg {
		q = `UPDATE managed_tenants SET version=version+1,reconciled_version=version+1,updated_at=$1 WHERE host=$2 AND version=$3`
	}
	r, e = tx.ExecContext(c, q, args...)
	if e != nil {
		return false, e
	}
	n, e = r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	return true, tx.Commit()
}
func (s *SQLiteStore) ActivateTenantSCIMToken(c context.Context, h string, p []byte, v int64, at time.Time) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return activateSCIMToken(c, tx, false, h, p, v, at)
}
func (s *PostgresStore) ActivateTenantSCIMToken(c context.Context, h string, p []byte, v int64, at time.Time) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return activateSCIMToken(c, tx, true, h, p, v, at)
}
func (s *SQLiteStore) ClearPendingTenantSCIMToken(c context.Context, h string, p []byte) error {
	_, e := s.db.ExecContext(c, `UPDATE tenant_scim_tokens SET pending_token_hash=NULL,pending_token_suffix='',pending_generation=0 WHERE host=? AND pending_token_hash=?`, h, p)
	return e
}
func (s *PostgresStore) ClearPendingTenantSCIMToken(c context.Context, h string, p []byte) error {
	_, e := s.db.ExecContext(c, `UPDATE tenant_scim_tokens SET pending_token_hash=NULL,pending_token_suffix='',pending_generation=0 WHERE host=$1 AND pending_token_hash=$2`, h, p)
	return e
}
func (s *SQLiteStore) GetTenantSCIMToken(c context.Context, h string) (TenantSCIMToken, error) {
	return scanSCIMToken(s.db.QueryRowContext(c, `SELECT host,token_hash,token_suffix,generation,updated_at FROM tenant_scim_tokens WHERE host=? AND token_hash IS NOT NULL`, h))
}
func (s *PostgresStore) GetTenantSCIMToken(c context.Context, h string) (TenantSCIMToken, error) {
	return scanSCIMToken(s.db.QueryRowContext(c, `SELECT host,token_hash,token_suffix,generation,updated_at FROM tenant_scim_tokens WHERE host=$1 AND token_hash IS NOT NULL`, h))
}
func (s *SQLiteStore) GetTenantSCIMTokenByHash(c context.Context, h []byte) (TenantSCIMToken, error) {
	return scanSCIMToken(s.db.QueryRowContext(c, `SELECT host,token_hash,token_suffix,generation,updated_at FROM tenant_scim_tokens WHERE token_hash=?`, h))
}
func (s *PostgresStore) GetTenantSCIMTokenByHash(c context.Context, h []byte) (TenantSCIMToken, error) {
	return scanSCIMToken(s.db.QueryRowContext(c, `SELECT host,token_hash,token_suffix,generation,updated_at FROM tenant_scim_tokens WHERE token_hash=$1`, h))
}

func scanSCIMUser(s tenantScanner) (SCIMUser, error) {
	var v SCIMUser
	var a int
	var ca, ua string
	if e := s.Scan(&v.Host, &v.ID, &v.UserName, &v.ExternalID, &v.Pubkey, &a, &v.ProfileJSON, &v.Version, &ca, &ua); e != nil {
		return v, e
	}
	var e error
	v.Active = a != 0
	if v.CreatedAt, e = parseStoreTime(ca); e != nil {
		return v, e
	}
	v.UpdatedAt, e = parseStoreTime(ua)
	return v, e
}
func scanSCIMGroup(s tenantScanner) (SCIMGroup, error) {
	var v SCIMGroup
	var a int
	var ca, ua string
	if e := s.Scan(&v.Host, &v.ID, &v.DisplayName, &a, &v.Version, &ca, &ua); e != nil {
		return v, e
	}
	var e error
	v.Active = a != 0
	if v.CreatedAt, e = parseStoreTime(ca); e != nil {
		return v, e
	}
	v.UpdatedAt, e = parseStoreTime(ua)
	return v, e
}

const scimUserSelect = `SELECT host,id,user_name,external_id,pubkey,active,profile_json,version,created_at,updated_at FROM scim_users`
const scimGroupSelect = `SELECT host,id,display_name,active,version,created_at,updated_at FROM scim_groups`

func (s *SQLiteStore) CreateSCIMUser(c context.Context, v SCIMUser) error {
	_, e := s.db.ExecContext(c, `INSERT INTO scim_users(host,id,user_name,external_id,pubkey,active,profile_json,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, v.Host, v.ID, v.UserName, v.ExternalID, v.Pubkey, boolInt(v.Active), v.ProfileJSON, v.Version, tt(v.CreatedAt), tt(v.UpdatedAt))
	return e
}
func (s *PostgresStore) CreateSCIMUser(c context.Context, v SCIMUser) error {
	_, e := s.db.ExecContext(c, `INSERT INTO scim_users(host,id,user_name,external_id,pubkey,active,profile_json,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, v.Host, v.ID, v.UserName, v.ExternalID, v.Pubkey, boolInt(v.Active), v.ProfileJSON, v.Version, tt(v.CreatedAt), tt(v.UpdatedAt))
	return e
}
func (s *SQLiteStore) GetSCIMUser(c context.Context, h, id string) (SCIMUser, error) {
	return scanSCIMUser(s.db.QueryRowContext(c, scimUserSelect+` WHERE host=? AND id=?`, h, id))
}
func (s *PostgresStore) GetSCIMUser(c context.Context, h, id string) (SCIMUser, error) {
	return scanSCIMUser(s.db.QueryRowContext(c, scimUserSelect+` WHERE host=$1 AND id=$2`, h, id))
}
func (s *SQLiteStore) GetSCIMUserHost(c context.Context, id string) (string, error) {
	var h string
	e := s.db.QueryRowContext(c, `SELECT host FROM scim_users WHERE id=?`, id).Scan(&h)
	return h, e
}
func (s *PostgresStore) GetSCIMUserHost(c context.Context, id string) (string, error) {
	var h string
	e := s.db.QueryRowContext(c, `SELECT host FROM scim_users WHERE id=$1`, id).Scan(&h)
	return h, e
}
func (s *SQLiteStore) UpdateSCIMUser(c context.Context, v SCIMUser, x int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE scim_users SET user_name=?,external_id=?,pubkey=?,active=?,profile_json=?,version=?,updated_at=? WHERE host=? AND id=? AND version=?`, v.UserName, v.ExternalID, v.Pubkey, boolInt(v.Active), v.ProfileJSON, v.Version, tt(v.UpdatedAt), v.Host, v.ID, x)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (s *PostgresStore) UpdateSCIMUser(c context.Context, v SCIMUser, x int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE scim_users SET user_name=$1,external_id=$2,pubkey=$3,active=$4,profile_json=$5,version=$6,updated_at=$7 WHERE host=$8 AND id=$9 AND version=$10`, v.UserName, v.ExternalID, v.Pubkey, boolInt(v.Active), v.ProfileJSON, v.Version, tt(v.UpdatedAt), v.Host, v.ID, x)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func scanSCIMUsers(r *sql.Rows) ([]SCIMUser, error) {
	defer r.Close()
	out := []SCIMUser{}
	for r.Next() {
		v, e := scanSCIMUser(r)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, r.Err()
}
func (s *SQLiteStore) ListSCIMUsers(c context.Context, h string, o, l int) ([]SCIMUser, int, error) {
	var n int
	if e := s.db.QueryRowContext(c, `SELECT count(*) FROM scim_users WHERE host=?`, h).Scan(&n); e != nil {
		return nil, 0, e
	}
	r, e := s.db.QueryContext(c, scimUserSelect+` WHERE host=? ORDER BY user_name,id LIMIT ? OFFSET ?`, h, l, o)
	if e != nil {
		return nil, 0, e
	}
	v, e := scanSCIMUsers(r)
	return v, n, e
}
func (s *PostgresStore) ListSCIMUsers(c context.Context, h string, o, l int) ([]SCIMUser, int, error) {
	var n int
	if e := s.db.QueryRowContext(c, `SELECT count(*) FROM scim_users WHERE host=$1`, h).Scan(&n); e != nil {
		return nil, 0, e
	}
	r, e := s.db.QueryContext(c, scimUserSelect+` WHERE host=$1 ORDER BY user_name,id LIMIT $2 OFFSET $3`, h, l, o)
	if e != nil {
		return nil, 0, e
	}
	v, e := scanSCIMUsers(r)
	return v, n, e
}

func (s *SQLiteStore) CreateSCIMGroup(c context.Context, v SCIMGroup) error {
	_, e := s.db.ExecContext(c, `INSERT INTO scim_groups(host,id,display_name,active,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, v.Host, v.ID, v.DisplayName, boolInt(v.Active), v.Version, tt(v.CreatedAt), tt(v.UpdatedAt))
	return e
}
func (s *PostgresStore) CreateSCIMGroup(c context.Context, v SCIMGroup) error {
	_, e := s.db.ExecContext(c, `INSERT INTO scim_groups(host,id,display_name,active,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, v.Host, v.ID, v.DisplayName, boolInt(v.Active), v.Version, tt(v.CreatedAt), tt(v.UpdatedAt))
	return e
}
func (s *SQLiteStore) GetSCIMGroup(c context.Context, h, id string) (SCIMGroup, error) {
	return scanSCIMGroup(s.db.QueryRowContext(c, scimGroupSelect+` WHERE host=? AND id=?`, h, id))
}
func (s *PostgresStore) GetSCIMGroup(c context.Context, h, id string) (SCIMGroup, error) {
	return scanSCIMGroup(s.db.QueryRowContext(c, scimGroupSelect+` WHERE host=$1 AND id=$2`, h, id))
}
func (s *SQLiteStore) GetSCIMGroupHost(c context.Context, id string) (string, error) {
	var h string
	e := s.db.QueryRowContext(c, `SELECT host FROM scim_groups WHERE id=?`, id).Scan(&h)
	return h, e
}
func (s *PostgresStore) GetSCIMGroupHost(c context.Context, id string) (string, error) {
	var h string
	e := s.db.QueryRowContext(c, `SELECT host FROM scim_groups WHERE id=$1`, id).Scan(&h)
	return h, e
}
func (s *SQLiteStore) UpdateSCIMGroup(c context.Context, v SCIMGroup, x int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE scim_groups SET display_name=?,active=?,version=?,updated_at=? WHERE host=? AND id=? AND version=?`, v.DisplayName, boolInt(v.Active), v.Version, tt(v.UpdatedAt), v.Host, v.ID, x)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (s *PostgresStore) UpdateSCIMGroup(c context.Context, v SCIMGroup, x int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE scim_groups SET display_name=$1,active=$2,version=$3,updated_at=$4 WHERE host=$5 AND id=$6 AND version=$7`, v.DisplayName, boolInt(v.Active), v.Version, tt(v.UpdatedAt), v.Host, v.ID, x)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func scanSCIMGroups(r *sql.Rows) ([]SCIMGroup, error) {
	defer r.Close()
	out := []SCIMGroup{}
	for r.Next() {
		v, e := scanSCIMGroup(r)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, r.Err()
}
func (s *SQLiteStore) ListSCIMGroups(c context.Context, h string, o, l int) ([]SCIMGroup, int, error) {
	var n int
	if e := s.db.QueryRowContext(c, `SELECT count(*) FROM scim_groups WHERE host=?`, h).Scan(&n); e != nil {
		return nil, 0, e
	}
	r, e := s.db.QueryContext(c, scimGroupSelect+` WHERE host=? ORDER BY display_name,id LIMIT ? OFFSET ?`, h, l, o)
	if e != nil {
		return nil, 0, e
	}
	v, e := scanSCIMGroups(r)
	return v, n, e
}
func (s *PostgresStore) ListSCIMGroups(c context.Context, h string, o, l int) ([]SCIMGroup, int, error) {
	var n int
	if e := s.db.QueryRowContext(c, `SELECT count(*) FROM scim_groups WHERE host=$1`, h).Scan(&n); e != nil {
		return nil, 0, e
	}
	r, e := s.db.QueryContext(c, scimGroupSelect+` WHERE host=$1 ORDER BY display_name,id LIMIT $2 OFFSET $3`, h, l, o)
	if e != nil {
		return nil, 0, e
	}
	v, e := scanSCIMGroups(r)
	return v, n, e
}

func scanStrings(r *sql.Rows) ([]string, error) {
	defer r.Close()
	out := []string{}
	for r.Next() {
		var v string
		if e := r.Scan(&v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, r.Err()
}
func (s *SQLiteStore) ListSCIMGroupMembers(c context.Context, h, g string) ([]string, error) {
	r, e := s.db.QueryContext(c, `SELECT user_id FROM scim_group_members WHERE host=? AND group_id=? ORDER BY user_id`, h, g)
	if e != nil {
		return nil, e
	}
	return scanStrings(r)
}
func (s *PostgresStore) ListSCIMGroupMembers(c context.Context, h, g string) ([]string, error) {
	r, e := s.db.QueryContext(c, `SELECT user_id FROM scim_group_members WHERE host=$1 AND group_id=$2 ORDER BY user_id`, h, g)
	if e != nil {
		return nil, e
	}
	return scanStrings(r)
}
func replaceMembers(ctx context.Context, tx *sql.Tx, postgres bool, h, g string, ids []string, x int64, at time.Time) (bool, error) {
	q := `UPDATE scim_groups SET version=?,updated_at=? WHERE host=? AND id=? AND version=?`
	args := []any{x + 1, tt(at), h, g, x}
	if postgres {
		q = `UPDATE scim_groups SET version=$1,updated_at=$2 WHERE host=$3 AND id=$4 AND version=$5`
	}
	r, e := tx.ExecContext(ctx, q, args...)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	dq := `DELETE FROM scim_group_members WHERE host=? AND group_id=?`
	if postgres {
		dq = `DELETE FROM scim_group_members WHERE host=$1 AND group_id=$2`
	}
	if _, e = tx.ExecContext(ctx, dq, h, g); e != nil {
		return false, e
	}
	for _, id := range ids {
		iq := `INSERT INTO scim_group_members(host,group_id,user_id,updated_at) VALUES(?,?,?,?)`
		if postgres {
			iq = `INSERT INTO scim_group_members(host,group_id,user_id,updated_at) VALUES($1,$2,$3,$4)`
		}
		if _, e = tx.ExecContext(ctx, iq, h, g, id, tt(at)); e != nil {
			return false, e
		}
	}
	return true, tx.Commit()
}
func (s *SQLiteStore) ReplaceSCIMGroupMembers(c context.Context, h, g string, ids []string, x int64, at time.Time) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return replaceMembers(c, tx, false, h, g, ids, x, at)
}
func (s *PostgresStore) ReplaceSCIMGroupMembers(c context.Context, h, g string, ids []string, x int64, at time.Time) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return replaceMembers(c, tx, true, h, g, ids, x, at)
}
func applySCIMUser(c context.Context, tx *sql.Tx, pg bool, u SCIMUser, userVersion, tenantVersion int64, create bool) (bool, error) {
	var r sql.Result
	var e error
	if create {
		q := `INSERT INTO scim_users(host,id,user_name,external_id,pubkey,active,profile_json,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`
		if pg {
			q = `INSERT INTO scim_users(host,id,user_name,external_id,pubkey,active,profile_json,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
		}
		r, e = tx.ExecContext(c, q, u.Host, u.ID, u.UserName, u.ExternalID, u.Pubkey, boolInt(u.Active), u.ProfileJSON, u.Version, tt(u.CreatedAt), tt(u.UpdatedAt))
	} else {
		q := `UPDATE scim_users SET user_name=?,external_id=?,pubkey=?,active=?,profile_json=?,version=?,updated_at=? WHERE host=? AND id=? AND version=?`
		if pg {
			q = `UPDATE scim_users SET user_name=$1,external_id=$2,pubkey=$3,active=$4,profile_json=$5,version=$6,updated_at=$7 WHERE host=$8 AND id=$9 AND version=$10`
		}
		r, e = tx.ExecContext(c, q, u.UserName, u.ExternalID, u.Pubkey, boolInt(u.Active), u.ProfileJSON, u.Version, tt(u.UpdatedAt), u.Host, u.ID, userVersion)
	}
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	q := `UPDATE managed_tenants SET version=version+1,updated_at=? WHERE host=? AND version=?`
	if pg {
		q = `UPDATE managed_tenants SET version=version+1,updated_at=$1 WHERE host=$2 AND version=$3`
	}
	r, e = tx.ExecContext(c, q, tt(u.UpdatedAt), u.Host, tenantVersion)
	if e != nil {
		return false, e
	}
	n, e = r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	return true, tx.Commit()
}
func (s *SQLiteStore) ApplySCIMUserAndAdvanceTenant(c context.Context, u SCIMUser, uv, tv int64, create bool) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return applySCIMUser(c, tx, false, u, uv, tv, create)
}
func (s *PostgresStore) ApplySCIMUserAndAdvanceTenant(c context.Context, u SCIMUser, uv, tv int64, create bool) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return applySCIMUser(c, tx, true, u, uv, tv, create)
}
func applySCIMGroup(c context.Context, tx *sql.Tx, pg bool, g SCIMGroup, ids []string, groupVersion, tenantVersion int64, create bool) (bool, error) {
	var r sql.Result
	var e error
	if create {
		q := `INSERT INTO scim_groups(host,id,display_name,active,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`
		if pg {
			q = `INSERT INTO scim_groups(host,id,display_name,active,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)`
		}
		r, e = tx.ExecContext(c, q, g.Host, g.ID, g.DisplayName, boolInt(g.Active), g.Version, tt(g.CreatedAt), tt(g.UpdatedAt))
	} else {
		q := `UPDATE scim_groups SET display_name=?,active=?,version=?,updated_at=? WHERE host=? AND id=? AND version=?`
		if pg {
			q = `UPDATE scim_groups SET display_name=$1,active=$2,version=$3,updated_at=$4 WHERE host=$5 AND id=$6 AND version=$7`
		}
		r, e = tx.ExecContext(c, q, g.DisplayName, boolInt(g.Active), g.Version, tt(g.UpdatedAt), g.Host, g.ID, groupVersion)
	}
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	q := `DELETE FROM scim_group_members WHERE host=? AND group_id=?`
	if pg {
		q = `DELETE FROM scim_group_members WHERE host=$1 AND group_id=$2`
	}
	if _, e = tx.ExecContext(c, q, g.Host, g.ID); e != nil {
		return false, e
	}
	for _, id := range ids {
		q = `INSERT INTO scim_group_members(host,group_id,user_id,updated_at) VALUES(?,?,?,?)`
		if pg {
			q = `INSERT INTO scim_group_members(host,group_id,user_id,updated_at) VALUES($1,$2,$3,$4)`
		}
		if _, e = tx.ExecContext(c, q, g.Host, g.ID, id, tt(g.UpdatedAt)); e != nil {
			return false, e
		}
	}
	q = `UPDATE managed_tenants SET version=version+1,updated_at=? WHERE host=? AND version=?`
	if pg {
		q = `UPDATE managed_tenants SET version=version+1,updated_at=$1 WHERE host=$2 AND version=$3`
	}
	r, e = tx.ExecContext(c, q, tt(g.UpdatedAt), g.Host, tenantVersion)
	if e != nil {
		return false, e
	}
	n, e = r.RowsAffected()
	if e != nil || n != 1 {
		return false, e
	}
	return true, tx.Commit()
}
func (s *SQLiteStore) ApplySCIMGroupAndAdvanceTenant(c context.Context, g SCIMGroup, ids []string, gv, tv int64, create bool) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return applySCIMGroup(c, tx, false, g, ids, gv, tv, create)
}
func (s *PostgresStore) ApplySCIMGroupAndAdvanceTenant(c context.Context, g SCIMGroup, ids []string, gv, tv int64, create bool) (bool, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	return applySCIMGroup(c, tx, true, g, ids, gv, tv, create)
}

func (s *SQLiteStore) ListSCIMAuthorizedUsers(c context.Context, h string) ([]SCIMUser, error) {
	r, e := s.db.QueryContext(c, scimUserSelect+` u WHERE u.host=? AND u.active=1 AND EXISTS(SELECT 1 FROM scim_group_members m JOIN scim_groups g ON g.host=m.host AND g.id=m.group_id WHERE m.host=u.host AND m.user_id=u.id AND g.active=1) ORDER BY u.pubkey`, h)
	if e != nil {
		return nil, e
	}
	return scanSCIMUsers(r)
}
func (s *PostgresStore) ListSCIMAuthorizedUsers(c context.Context, h string) ([]SCIMUser, error) {
	r, e := s.db.QueryContext(c, scimUserSelect+` u WHERE u.host=$1 AND u.active=1 AND EXISTS(SELECT 1 FROM scim_group_members m JOIN scim_groups g ON g.host=m.host AND g.id=m.group_id WHERE m.host=u.host AND m.user_id=u.id AND g.active=1) ORDER BY u.pubkey`, h)
	if e != nil {
		return nil, e
	}
	return scanSCIMUsers(r)
}

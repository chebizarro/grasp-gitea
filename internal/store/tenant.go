package store

import (
	"context"
	"database/sql"
	"time"
)

const (
	TenantPolicyDirectoryOnly = "directory-only"
	TenantPolicySharedRead    = "shared-read"
	TenantStatePending        = "pending"
	TenantStateActive         = "active"
	TenantStateSuspended      = "suspended"
	TenantStateKilled         = "killed"
	TenantAccessGranted       = "granted"
	TenantAccessPolicyRemoved = "policy_removed"
	TenantAccessRevoked       = "revoked"
)

type ManagedTenant struct {
	Host               string    `json:"host"`
	Policy             string    `json:"policy"`
	State              string    `json:"state"`
	OrgName            string    `json:"org_name"`
	ProvisioningMarker string    `json:"-"`
	GiteaOrgID         int64     `json:"gitea_org_id,omitempty"`
	ReaderTeamID       int64     `json:"reader_team_id,omitempty"`
	Version            int64     `json:"version"`
	ReconciledVersion  int64     `json:"reconciled_version"`
	LastReconciledAt   time.Time `json:"last_reconciled_at,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}
type TenantMembership struct {
	Host           string    `json:"host"`
	Pubkey         string    `json:"pubkey"`
	GiteaUserID    int64     `json:"gitea_user_id"`
	GiteaUser      string    `json:"gitea_user"`
	EvidenceStatus string    `json:"evidence_status"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
	Granted        bool      `json:"granted"`
	TenantOrphaned bool      `json:"tenant_orphaned"`
	AccessState    string    `json:"access_state"`
	ReconciledAt   time.Time `json:"reconciled_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const tenantSelect = `SELECT host,policy,state,org_name,provisioning_marker,gitea_org_id,reader_team_id,version,reconciled_version,last_reconciled_at,last_error,created_at,updated_at FROM managed_tenants`
const membershipSelect = `SELECT host,pubkey,gitea_user_id,gitea_user,evidence_status,verified_at,checked_at,granted,tenant_orphaned,access_state,reconciled_at,updated_at FROM tenant_memberships`

type tenantScanner interface{ Scan(...any) error }

func scanTenant(s tenantScanner) (ManagedTenant, error) {
	var t ManagedTenant
	var lr, ca, ua string
	if e := s.Scan(&t.Host, &t.Policy, &t.State, &t.OrgName, &t.ProvisioningMarker, &t.GiteaOrgID, &t.ReaderTeamID, &t.Version, &t.ReconciledVersion, &lr, &t.LastError, &ca, &ua); e != nil {
		return t, e
	}
	var e error
	if lr != "" {
		t.LastReconciledAt, e = parseStoreTime(lr)
		if e != nil {
			return t, e
		}
	}
	t.CreatedAt, e = parseStoreTime(ca)
	if e != nil {
		return t, e
	}
	t.UpdatedAt, e = parseStoreTime(ua)
	return t, e
}
func scanMembership(s tenantScanner) (TenantMembership, error) {
	var m TenantMembership
	var va, ca, ra, ua string
	var g, o int
	if e := s.Scan(&m.Host, &m.Pubkey, &m.GiteaUserID, &m.GiteaUser, &m.EvidenceStatus, &va, &ca, &g, &o, &m.AccessState, &ra, &ua); e != nil {
		return m, e
	}
	var e error
	if va != "" {
		m.VerifiedAt, e = parseStoreTime(va)
		if e != nil {
			return m, e
		}
	}
	m.CheckedAt, e = parseStoreTime(ca)
	if e != nil {
		return m, e
	}
	if ra != "" {
		m.ReconciledAt, e = parseStoreTime(ra)
		if e != nil {
			return m, e
		}
	}
	m.UpdatedAt, e = parseStoreTime(ua)
	m.Granted = g != 0
	m.TenantOrphaned = o != 0
	return m, e
}
func tt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(storeTimeLayout)
}
func tenantArgs(t ManagedTenant) []any {
	return []any{t.Host, t.Policy, t.State, t.OrgName, t.ProvisioningMarker, t.GiteaOrgID, t.ReaderTeamID, t.Version, t.ReconciledVersion, tt(t.LastReconciledAt), t.LastError, tt(t.CreatedAt), tt(t.UpdatedAt)}
}
func (s *SQLiteStore) CreateManagedTenant(c context.Context, t ManagedTenant) error {
	_, e := s.db.ExecContext(c, `INSERT INTO managed_tenants(host,policy,state,org_name,provisioning_marker,gitea_org_id,reader_team_id,version,reconciled_version,last_reconciled_at,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, tenantArgs(t)...)
	return e
}
func (s *PostgresStore) CreateManagedTenant(c context.Context, t ManagedTenant) error {
	_, e := s.db.ExecContext(c, `INSERT INTO managed_tenants(host,policy,state,org_name,provisioning_marker,gitea_org_id,reader_team_id,version,reconciled_version,last_reconciled_at,last_error,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, tenantArgs(t)...)
	return e
}
func (s *SQLiteStore) GetManagedTenant(c context.Context, h string) (ManagedTenant, error) {
	return scanTenant(s.db.QueryRowContext(c, tenantSelect+` WHERE host=?`, h))
}
func (s *PostgresStore) GetManagedTenant(c context.Context, h string) (ManagedTenant, error) {
	return scanTenant(s.db.QueryRowContext(c, tenantSelect+` WHERE host=$1`, h))
}
func scanTenants(r *sql.Rows) ([]ManagedTenant, error) {
	defer r.Close()
	var out []ManagedTenant
	for r.Next() {
		t, e := scanTenant(r)
		if e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, r.Err()
}
func (s *SQLiteStore) ListManagedTenants(c context.Context) ([]ManagedTenant, error) {
	r, e := s.db.QueryContext(c, tenantSelect+` ORDER BY host`)
	if e != nil {
		return nil, e
	}
	return scanTenants(r)
}
func (s *PostgresStore) ListManagedTenants(c context.Context) ([]ManagedTenant, error) {
	r, e := s.db.QueryContext(c, tenantSelect+` ORDER BY host`)
	if e != nil {
		return nil, e
	}
	return scanTenants(r)
}
func (s *SQLiteStore) UpdateManagedTenant(c context.Context, t ManagedTenant, v int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE managed_tenants SET policy=?,state=?,org_name=?,provisioning_marker=?,gitea_org_id=?,reader_team_id=?,version=?,reconciled_version=?,last_reconciled_at=?,last_error=?,created_at=?,updated_at=? WHERE host=? AND version=? AND org_name=? AND provisioning_marker=? AND (gitea_org_id=0 OR gitea_org_id=?) AND (reader_team_id=0 OR reader_team_id=?)`, t.Policy, t.State, t.OrgName, t.ProvisioningMarker, t.GiteaOrgID, t.ReaderTeamID, t.Version, t.ReconciledVersion, tt(t.LastReconciledAt), t.LastError, tt(t.CreatedAt), tt(t.UpdatedAt), t.Host, v, t.OrgName, t.ProvisioningMarker, t.GiteaOrgID, t.ReaderTeamID)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (s *PostgresStore) UpdateManagedTenant(c context.Context, t ManagedTenant, v int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE managed_tenants SET policy=$1,state=$2,org_name=$3,provisioning_marker=$4,gitea_org_id=$5,reader_team_id=$6,version=$7,reconciled_version=$8,last_reconciled_at=$9,last_error=$10,created_at=$11,updated_at=$12 WHERE host=$13 AND version=$14 AND org_name=$15 AND provisioning_marker=$16 AND (gitea_org_id=0 OR gitea_org_id=$17) AND (reader_team_id=0 OR reader_team_id=$18)`, t.Policy, t.State, t.OrgName, t.ProvisioningMarker, t.GiteaOrgID, t.ReaderTeamID, t.Version, t.ReconciledVersion, tt(t.LastReconciledAt), t.LastError, tt(t.CreatedAt), tt(t.UpdatedAt), t.Host, v, t.OrgName, t.ProvisioningMarker, t.GiteaOrgID, t.ReaderTeamID)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func membershipArgs(m TenantMembership) []any {
	g, o := 0, 0
	if m.Granted {
		g = 1
	}
	if m.TenantOrphaned {
		o = 1
	}
	return []any{m.Host, m.Pubkey, m.GiteaUserID, m.GiteaUser, m.EvidenceStatus, tt(m.VerifiedAt), tt(m.CheckedAt), g, o, m.AccessState, tt(m.ReconciledAt), tt(m.UpdatedAt)}
}
func (s *SQLiteStore) UpsertTenantMembership(c context.Context, m TenantMembership) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_memberships(host,pubkey,gitea_user_id,gitea_user,evidence_status,verified_at,checked_at,granted,tenant_orphaned,access_state,reconciled_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host,pubkey) DO UPDATE SET gitea_user_id=excluded.gitea_user_id,gitea_user=excluded.gitea_user,evidence_status=excluded.evidence_status,verified_at=excluded.verified_at,checked_at=excluded.checked_at,updated_at=excluded.updated_at WHERE tenant_memberships.checked_at<excluded.checked_at`, membershipArgs(m)...)
	return e
}
func (s *PostgresStore) UpsertTenantMembership(c context.Context, m TenantMembership) error {
	_, e := s.db.ExecContext(c, `INSERT INTO tenant_memberships(host,pubkey,gitea_user_id,gitea_user,evidence_status,verified_at,checked_at,granted,tenant_orphaned,access_state,reconciled_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(host,pubkey) DO UPDATE SET gitea_user_id=excluded.gitea_user_id,gitea_user=excluded.gitea_user,evidence_status=excluded.evidence_status,verified_at=excluded.verified_at,checked_at=excluded.checked_at,updated_at=excluded.updated_at WHERE tenant_memberships.checked_at<excluded.checked_at`, membershipArgs(m)...)
	return e
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (s *SQLiteStore) UpdateTenantMembershipAccess(c context.Context, host, pubkey, state string, granted, orphaned bool, at, checked time.Time, tenantVersion int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE tenant_memberships SET access_state=?,granted=?,tenant_orphaned=?,reconciled_at=? WHERE host=? AND pubkey=? AND checked_at=? AND EXISTS(SELECT 1 FROM managed_tenants WHERE host=? AND version=?) AND (?=0 OR EXISTS(SELECT 1 FROM domain_affiliations WHERE pubkey=? AND checked_at=?))`, state, boolInt(granted), boolInt(orphaned), tt(at), host, pubkey, tt(checked), host, tenantVersion, boolInt(granted), pubkey, tt(checked))
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (s *PostgresStore) UpdateTenantMembershipAccess(c context.Context, host, pubkey, state string, granted, orphaned bool, at, checked time.Time, tenantVersion int64) (bool, error) {
	r, e := s.db.ExecContext(c, `UPDATE tenant_memberships SET access_state=$1,granted=$2,tenant_orphaned=$3,reconciled_at=$4 WHERE host=$5 AND pubkey=$6 AND checked_at=$7 AND EXISTS(SELECT 1 FROM managed_tenants WHERE host=$8 AND version=$9) AND ($10=0 OR EXISTS(SELECT 1 FROM domain_affiliations WHERE pubkey=$11 AND checked_at=$12))`, state, boolInt(granted), boolInt(orphaned), tt(at), host, pubkey, tt(checked), host, tenantVersion, boolInt(granted), pubkey, tt(checked))
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}

func scanMemberships(r *sql.Rows) ([]TenantMembership, error) {
	defer r.Close()
	var out []TenantMembership
	for r.Next() {
		m, e := scanMembership(r)
		if e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, r.Err()
}
func (s *SQLiteStore) ListTenantMemberships(c context.Context, h string) ([]TenantMembership, error) {
	r, e := s.db.QueryContext(c, membershipSelect+` WHERE host=? ORDER BY pubkey`, h)
	if e != nil {
		return nil, e
	}
	return scanMemberships(r)
}
func (s *PostgresStore) ListTenantMemberships(c context.Context, h string) ([]TenantMembership, error) {
	r, e := s.db.QueryContext(c, membershipSelect+` WHERE host=$1 ORDER BY pubkey`, h)
	if e != nil {
		return nil, e
	}
	return scanMemberships(r)
}
func (s *SQLiteStore) HasTenantState(c context.Context) (bool, error) {
	var p int
	e := s.db.QueryRowContext(c, `SELECT CASE WHEN EXISTS(SELECT 1 FROM domain_affiliations) OR EXISTS(SELECT 1 FROM managed_tenants) OR EXISTS(SELECT 1 FROM tenant_memberships) THEN 1 ELSE 0 END`).Scan(&p)
	return p != 0, e
}
func (s *PostgresStore) HasTenantState(c context.Context) (bool, error) {
	var p int
	e := s.db.QueryRowContext(c, `SELECT CASE WHEN EXISTS(SELECT 1 FROM domain_affiliations) OR EXISTS(SELECT 1 FROM managed_tenants) OR EXISTS(SELECT 1 FROM tenant_memberships) THEN 1 ELSE 0 END`).Scan(&p)
	return p != 0, e
}

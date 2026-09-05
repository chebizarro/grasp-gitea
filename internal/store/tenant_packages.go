package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"
)

const (
	TenantPackageFamilyDocker  = "docker"
	TenantPackageFamilyNPM     = "npm"
	TenantPackageFamilyGeneric = "generic"

	TenantPackageAllocationExplicit = "explicit"
	TenantPackageAllocationOpen     = "open-allocation"

	TenantPackageTargetPubkey = "pubkey"
	TenantPackageTargetTeam   = "team"

	TenantPackageVisibilityPrivate = "private"
	TenantPackageVisibilityPublic  = "public"
)

type TenantPackagePolicy struct {
	Host            string    `json:"host"`
	Enabled         bool      `json:"enabled"`
	AllowedFamilies []string  `json:"allowed_families"`
	AllocationMode  string    `json:"allocation_mode"`
	Version         int64     `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type TenantPackageAllocation struct {
	Host                 string    `json:"host"`
	Family               string    `json:"family"`
	Name                 string    `json:"name"`
	TargetType           string    `json:"target_type"`
	TargetID             string    `json:"target_id"`
	Visibility           string    `json:"visibility"`
	Orphaned             bool      `json:"orphaned"`
	OrphanReason         string    `json:"orphan_reason,omitempty"`
	Pending              bool      `json:"pending"`
	ReservationID        string    `json:"-"`
	ReservationExpiresAt time.Time `json:"reservation_expires_at,omitempty"`
	Version              int64     `json:"version"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

const packagePolicySelect = `SELECT host,enabled,allowed_families,allocation_mode,version,created_at,updated_at FROM tenant_package_policies`
const packageAllocationSelect = `SELECT host,family,name,target_type,target_id,visibility,orphaned,orphan_reason,pending,reservation_id,reservation_expires_at,version,created_at,updated_at FROM tenant_package_allocations`

func scanPackagePolicy(s tenantScanner) (TenantPackagePolicy, error) {
	var p TenantPackagePolicy
	var enabled int
	var families, created, updated string
	if err := s.Scan(&p.Host, &enabled, &families, &p.AllocationMode, &p.Version, &created, &updated); err != nil {
		return p, err
	}
	p.Enabled = enabled != 0
	if err := json.Unmarshal([]byte(families), &p.AllowedFamilies); err != nil {
		return p, err
	}
	var err error
	p.CreatedAt, err = parseStoreTime(created)
	if err == nil {
		p.UpdatedAt, err = parseStoreTime(updated)
	}
	return p, err
}

func packageFamiliesJSON(families []string) (string, error) {
	families = append([]string(nil), families...)
	sort.Strings(families)
	b, err := json.Marshal(families)
	return string(b), err
}

func (s *SQLiteStore) GetTenantPackagePolicy(ctx context.Context, host string) (TenantPackagePolicy, error) {
	return scanPackagePolicy(s.db.QueryRowContext(ctx, packagePolicySelect+` WHERE host=?`, host))
}
func (s *PostgresStore) GetTenantPackagePolicy(ctx context.Context, host string) (TenantPackagePolicy, error) {
	return scanPackagePolicy(s.db.QueryRowContext(ctx, packagePolicySelect+` WHERE host=$1`, host))
}
func (s *SQLiteStore) UpdateTenantPackagePolicy(ctx context.Context, p TenantPackagePolicy, expected int64) (bool, error) {
	families, err := packageFamiliesJSON(p.AllowedFamilies)
	if err != nil {
		return false, err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE tenant_package_policies SET enabled=?,allowed_families=?,allocation_mode=?,version=?,updated_at=? WHERE host=? AND version=?`, boolInt(p.Enabled), families, p.AllocationMode, p.Version, tt(p.UpdatedAt), p.Host, expected)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *PostgresStore) UpdateTenantPackagePolicy(ctx context.Context, p TenantPackagePolicy, expected int64) (bool, error) {
	families, err := packageFamiliesJSON(p.AllowedFamilies)
	if err != nil {
		return false, err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE tenant_package_policies SET enabled=$1,allowed_families=$2,allocation_mode=$3,version=$4,updated_at=$5 WHERE host=$6 AND version=$7`, boolInt(p.Enabled), families, p.AllocationMode, p.Version, tt(p.UpdatedAt), p.Host, expected)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func scanPackageAllocation(s tenantScanner) (TenantPackageAllocation, error) {
	var a TenantPackageAllocation
	var orphaned, pending int
	var reservedUntil, created, updated string
	if err := s.Scan(&a.Host, &a.Family, &a.Name, &a.TargetType, &a.TargetID, &a.Visibility, &orphaned, &a.OrphanReason, &pending, &a.ReservationID, &reservedUntil, &a.Version, &created, &updated); err != nil {
		return a, err
	}
	a.Orphaned = orphaned != 0
	a.Pending = pending != 0
	var err error
	if reservedUntil != "" {
		a.ReservationExpiresAt, err = parseStoreTime(reservedUntil)
		if err != nil {
			return a, err
		}
	}
	a.CreatedAt, err = parseStoreTime(created)
	if err == nil {
		a.UpdatedAt, err = parseStoreTime(updated)
	}
	return a, err
}
func allocationArgs(a TenantPackageAllocation) []any {
	return []any{a.Host, a.Family, a.Name, a.TargetType, a.TargetID, a.Visibility, boolInt(a.Orphaned), a.OrphanReason, boolInt(a.Pending), a.ReservationID, tt(a.ReservationExpiresAt), a.Version, tt(a.CreatedAt), tt(a.UpdatedAt)}
}
func (s *SQLiteStore) CreateTenantPackageAllocation(ctx context.Context, a TenantPackageAllocation) (bool, error) {
	r, err := s.db.ExecContext(ctx, `INSERT INTO tenant_package_allocations(host,family,name,target_type,target_id,visibility,orphaned,orphan_reason,pending,reservation_id,reservation_expires_at,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host,family,name) DO NOTHING`, allocationArgs(a)...)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *PostgresStore) CreateTenantPackageAllocation(ctx context.Context, a TenantPackageAllocation) (bool, error) {
	r, err := s.db.ExecContext(ctx, `INSERT INTO tenant_package_allocations(host,family,name,target_type,target_id,visibility,orphaned,orphan_reason,pending,reservation_id,reservation_expires_at,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(host,family,name) DO NOTHING`, allocationArgs(a)...)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *SQLiteStore) GetTenantPackageAllocation(ctx context.Context, host, family, name string) (TenantPackageAllocation, error) {
	return scanPackageAllocation(s.db.QueryRowContext(ctx, packageAllocationSelect+` WHERE host=? AND family=? AND name=?`, host, family, name))
}
func (s *PostgresStore) GetTenantPackageAllocation(ctx context.Context, host, family, name string) (TenantPackageAllocation, error) {
	return scanPackageAllocation(s.db.QueryRowContext(ctx, packageAllocationSelect+` WHERE host=$1 AND family=$2 AND name=$3`, host, family, name))
}
func scanPackageAllocations(rows *sql.Rows) ([]TenantPackageAllocation, error) {
	defer rows.Close()
	var out []TenantPackageAllocation
	for rows.Next() {
		a, err := scanPackageAllocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *SQLiteStore) ListTenantPackageAllocations(ctx context.Context, host, family string) ([]TenantPackageAllocation, error) {
	q, args := packageAllocationSelect+` WHERE host=?`, []any{host}
	if family != "" {
		q += ` AND family=?`
		args = append(args, family)
	}
	q += ` ORDER BY family,name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanPackageAllocations(rows)
}
func (s *PostgresStore) ListTenantPackageAllocations(ctx context.Context, host, family string) ([]TenantPackageAllocation, error) {
	q, args := packageAllocationSelect+` WHERE host=$1`, []any{host}
	if family != "" {
		q += ` AND family=$2`
		args = append(args, family)
	}
	q += ` ORDER BY family,name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanPackageAllocations(rows)
}
func (s *SQLiteStore) UpdateTenantPackageAllocation(ctx context.Context, a TenantPackageAllocation, expected int64) (bool, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE tenant_package_allocations SET target_type=?,target_id=?,visibility=?,orphaned=?,orphan_reason=?,pending=?,reservation_id=?,reservation_expires_at=?,version=?,updated_at=? WHERE host=? AND family=? AND name=? AND version=? AND ((target_type=? AND target_id=? AND (orphaned=0 OR ?=1)) OR orphaned=1)`, a.TargetType, a.TargetID, a.Visibility, boolInt(a.Orphaned), a.OrphanReason, boolInt(a.Pending), a.ReservationID, tt(a.ReservationExpiresAt), a.Version, tt(a.UpdatedAt), a.Host, a.Family, a.Name, expected, a.TargetType, a.TargetID, boolInt(a.Orphaned))
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *PostgresStore) UpdateTenantPackageAllocation(ctx context.Context, a TenantPackageAllocation, expected int64) (bool, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE tenant_package_allocations SET target_type=$1,target_id=$2,visibility=$3,orphaned=$4,orphan_reason=$5,pending=$6,reservation_id=$7,reservation_expires_at=$8,version=$9,updated_at=$10 WHERE host=$11 AND family=$12 AND name=$13 AND version=$14 AND ((target_type=$15 AND target_id=$16 AND (orphaned=0 OR $17=1)) OR orphaned=1)`, a.TargetType, a.TargetID, a.Visibility, boolInt(a.Orphaned), a.OrphanReason, boolInt(a.Pending), a.ReservationID, tt(a.ReservationExpiresAt), a.Version, tt(a.UpdatedAt), a.Host, a.Family, a.Name, expected, a.TargetType, a.TargetID, boolInt(a.Orphaned))
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *SQLiteStore) DeleteTenantPackageReservation(ctx context.Context, host, family, name, reservationID string) (bool, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM tenant_package_allocations WHERE host=? AND family=? AND name=? AND pending=1 AND reservation_id=?`, host, family, name, reservationID)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *PostgresStore) DeleteTenantPackageReservation(ctx context.Context, host, family, name, reservationID string) (bool, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM tenant_package_allocations WHERE host=$1 AND family=$2 AND name=$3 AND pending=1 AND reservation_id=$4`, host, family, name, reservationID)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

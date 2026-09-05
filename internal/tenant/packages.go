package tenant

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

var (
	ErrPackageDenied       = errors.New("tenant package access denied")
	ErrPackageAuthRequired = errors.New("tenant package authentication required")
)

type PackagePolicyPatch struct {
	ExpectedVersion int64
	Enabled         *bool
	AllowedFamilies *[]string
	AllocationMode  *string
}
type PackageAllocationRequest struct {
	Family     string `json:"family"`
	Name       string `json:"name"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Visibility string `json:"visibility"`
}
type PackagePrincipal struct {
	Pubkey      string
	GiteaUserID int64
	GiteaUser   string
}
type PackageCoordinate struct {
	Owner    string
	Family   string
	Name     string
	Write    bool
	Creation bool
}
type PackageAuthorizationRequest struct {
	Coordinates          []PackageCoordinate
	Principal            *PackagePrincipal
	RegistryContinuation bool
}
type PackageReservation struct {
	Host, Family, Name, ID string
	FinalizeOnSuccess      bool
}
type PackageAuthorizationDecision struct {
	Managed      bool
	PublicRead   bool
	Reservations []PackageReservation
}

var packageNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func validPackageFamily(f string) bool {
	switch f {
	case store.TenantPackageFamilyDocker, store.TenantPackageFamilyNPM, store.TenantPackageFamilyGeneric:
		return true
	}
	return false
}
func normalizePackageName(family, name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !validPackageFamily(family) || strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") {
		return "", fmt.Errorf("invalid %s package name %q", family, name)
	}
	if family == store.TenantPackageFamilyDocker {
		for _, part := range strings.Split(name, "/") {
			if !packageNameRE.MatchString(part) {
				return "", fmt.Errorf("invalid docker package name %q", name)
			}
		}
	} else if family == store.TenantPackageFamilyNPM && strings.HasPrefix(name, "@") {
		parts := strings.Split(strings.TrimPrefix(name, "@"), "/")
		if len(parts) != 2 || !packageNameRE.MatchString(parts[0]) || !packageNameRE.MatchString(parts[1]) {
			return "", fmt.Errorf("invalid npm package name %q", name)
		}
	} else if !packageNameRE.MatchString(name) {
		return "", fmt.Errorf("invalid %s package name %q", family, name)
	}
	return name, nil
}

func (s *Service) GetPackagePolicy(ctx context.Context, raw string) (store.TenantPackagePolicy, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.TenantPackagePolicy{}, err
	}
	if _, err = s.store.GetManagedTenant(ctx, h); errors.Is(err, sql.ErrNoRows) {
		return store.TenantPackagePolicy{}, ErrNotFound
	} else if err != nil {
		return store.TenantPackagePolicy{}, err
	}
	return s.store.GetTenantPackagePolicy(ctx, h)
}
func (s *Service) UpdatePackagePolicy(ctx context.Context, raw string, patch PackagePolicyPatch) (store.TenantPackagePolicy, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.TenantPackagePolicy{}, err
	}
	var out store.TenantPackagePolicy
	err = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		if _, e := s.store.GetManagedTenant(ctx, h); errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		} else if e != nil {
			return e
		}
		p, e := s.store.GetTenantPackagePolicy(ctx, h)
		if e != nil {
			return e
		}
		if patch.ExpectedVersion <= 0 || p.Version != patch.ExpectedVersion {
			return ErrConflict
		}
		if patch.Enabled != nil {
			p.Enabled = *patch.Enabled
		}
		if patch.AllocationMode != nil {
			if *patch.AllocationMode != store.TenantPackageAllocationExplicit && *patch.AllocationMode != store.TenantPackageAllocationOpen {
				return fmt.Errorf("invalid allocation mode")
			}
			p.AllocationMode = *patch.AllocationMode
		}
		if patch.AllowedFamilies != nil {
			seen := map[string]bool{}
			p.AllowedFamilies = nil
			for _, family := range *patch.AllowedFamilies {
				family = strings.ToLower(family)
				if !validPackageFamily(family) {
					return fmt.Errorf("invalid package family %q", family)
				}
				if !seen[family] {
					seen[family] = true
					p.AllowedFamilies = append(p.AllowedFamilies, family)
				}
			}
			sort.Strings(p.AllowedFamilies)
		}
		p.Version++
		p.UpdatedAt = s.now().UTC()
		ok, e := s.store.UpdateTenantPackagePolicy(ctx, p, patch.ExpectedVersion)
		if e != nil {
			return e
		}
		if !ok {
			return ErrConflict
		}
		out = p
		return nil
	})
	return out, err
}
func (s *Service) CreatePackageAllocation(ctx context.Context, raw string, req PackageAllocationRequest) (store.TenantPackageAllocation, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.TenantPackageAllocation{}, err
	}
	req.Family = strings.ToLower(req.Family)
	req.Name, err = normalizePackageName(req.Family, req.Name)
	if err != nil {
		return store.TenantPackageAllocation{}, err
	}
	if req.TargetType != store.TenantPackageTargetPubkey && req.TargetType != store.TenantPackageTargetTeam {
		return store.TenantPackageAllocation{}, fmt.Errorf("invalid allocation target")
	}
	if req.TargetID == "" {
		return store.TenantPackageAllocation{}, fmt.Errorf("invalid allocation target")
	}
	if req.Visibility == "" {
		req.Visibility = store.TenantPackageVisibilityPrivate
	}
	if req.Visibility != store.TenantPackageVisibilityPrivate && req.Visibility != store.TenantPackageVisibilityPublic {
		return store.TenantPackageAllocation{}, fmt.Errorf("invalid package visibility")
	}
	var out store.TenantPackageAllocation
	err = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		if _, e := s.store.GetManagedTenant(ctx, h); errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		} else if e != nil {
			return e
		}
		if req.TargetType == store.TenantPackageTargetPubkey {
			link, e := s.store.GetIdentityLinkByPubkey(ctx, req.TargetID)
			if e != nil {
				return ErrConflict
			}
			member, e := s.currentMember(ctx, h, PackagePrincipal{Pubkey: req.TargetID, GiteaUserID: link.GiteaUserID, GiteaUser: link.GiteaUser})
			if e != nil {
				return e
			}
			if !member {
				return ErrConflict
			}
		}
		if req.TargetType == store.TenantPackageTargetTeam {
			g, e := s.store.GetSCIMGroup(ctx, h, req.TargetID)
			if e != nil || !g.Active {
				return ErrConflict
			}
		}
		now := s.now().UTC()
		a := store.TenantPackageAllocation{Host: h, Family: req.Family, Name: req.Name, TargetType: req.TargetType, TargetID: req.TargetID, Visibility: req.Visibility, Version: 1, CreatedAt: now, UpdatedAt: now}
		created, e := s.store.CreateTenantPackageAllocation(ctx, a)
		if e != nil {
			return e
		}
		if !created {
			existing, e := s.store.GetTenantPackageAllocation(ctx, h, req.Family, req.Name)
			if e != nil {
				return e
			}
			if existing.Orphaned {
				a.CreatedAt = existing.CreatedAt
				a.Version = existing.Version + 1
				ok, e := s.store.UpdateTenantPackageAllocation(ctx, a, existing.Version)
				if e != nil {
					return e
				}
				if !ok {
					return ErrConflict
				}
				out = a
				return nil
			}
			if existing.TargetType != a.TargetType || existing.TargetID != a.TargetID || existing.Visibility != a.Visibility {
				return ErrConflict
			}
			out = existing
			return nil
		}
		out = a
		return nil
	})
	return out, err
}
func (s *Service) ListPackageAllocations(ctx context.Context, raw, family string) ([]store.TenantPackageAllocation, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return nil, err
	}
	if family != "" && !validPackageFamily(family) {
		return nil, fmt.Errorf("invalid package family")
	}
	if _, err = s.store.GetManagedTenant(ctx, h); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return s.store.ListTenantPackageAllocations(ctx, h, family)
}

func (s *Service) currentMember(ctx context.Context, host string, p PackagePrincipal) (bool, error) {
	link, err := s.store.GetIdentityLinkByPubkey(ctx, p.Pubkey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if link.GiteaUserID != p.GiteaUserID || link.GiteaUser != p.GiteaUser {
		return false, nil
	}
	a, err := s.store.GetDomainAffiliation(ctx, p.Pubkey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	now := s.now().UTC()
	verifiedFresh := a.Status == store.DomainAffiliationVerified && !a.CheckedAt.IsZero() && now.Sub(a.CheckedAt) <= s.affiliationMaxAge
	staleWithinBound := a.Status == store.DomainAffiliationStale && !a.VerifiedAt.IsZero() && now.Sub(a.VerifiedAt) < s.affiliationMaxAge
	eligible := a.Host == host && (verifiedFresh || staleWithinBound)
	if !eligible {
		return false, nil
	}
	if _, err := s.store.GetTenantSCIMToken(ctx, host); err == nil {
		users, e := s.store.ListSCIMAuthorizedUsers(ctx, host)
		if e != nil {
			return false, e
		}
		for _, u := range users {
			if u.Pubkey == p.Pubkey {
				return true, nil
			}
		}
		return false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return true, nil
}
func (s *Service) targetEligible(ctx context.Context, host string, a store.TenantPackageAllocation, principal PackagePrincipal) (bool, error) {
	member, err := s.currentMember(ctx, host, principal)
	if err != nil || !member {
		return member, err
	}
	if a.TargetType == store.TenantPackageTargetPubkey {
		return a.TargetID == principal.Pubkey, nil
	}
	group, err := s.store.GetSCIMGroup(ctx, host, a.TargetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !group.Active {
		return false, nil
	}
	ids, err := s.store.ListSCIMGroupMembers(ctx, host, a.TargetID)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		u, e := s.store.GetSCIMUser(ctx, host, id)
		if e != nil {
			return false, e
		}
		if u.Active && u.Pubkey == principal.Pubkey {
			return true, nil
		}
	}
	return false, nil
}
func (s *Service) orphan(ctx context.Context, a store.TenantPackageAllocation, reason string) error {
	if a.Orphaned {
		return nil
	}
	a.Orphaned = true
	a.OrphanReason = reason
	expected := a.Version
	a.Version++
	a.UpdatedAt = s.now().UTC()
	ok, err := s.store.UpdateTenantPackageAllocation(ctx, a, expected)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConflict
	}
	return nil
}
func (s *Service) allocationOwnerLive(ctx context.Context, host string, a store.TenantPackageAllocation) (bool, error) {
	switch a.TargetType {
	case store.TenantPackageTargetPubkey:
		link, e := s.store.GetIdentityLinkByPubkey(ctx, a.TargetID)
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		return s.currentMember(ctx, host, PackagePrincipal{Pubkey: a.TargetID, GiteaUserID: link.GiteaUserID, GiteaUser: link.GiteaUser})
	case store.TenantPackageTargetTeam:
		group, e := s.store.GetSCIMGroup(ctx, host, a.TargetID)
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if !group.Active {
			return false, nil
		}
		ids, e := s.store.ListSCIMGroupMembers(ctx, host, a.TargetID)
		if e != nil {
			return false, e
		}
		for _, id := range ids {
			u, e := s.store.GetSCIMUser(ctx, host, id)
			if e != nil {
				return false, e
			}
			if !u.Active {
				continue
			}
			link, e := s.store.GetIdentityLinkByPubkey(ctx, u.Pubkey)
			if e != nil {
				if errors.Is(e, sql.ErrNoRows) {
					continue
				}
				return false, e
			}
			live, e := s.currentMember(ctx, host, PackagePrincipal{Pubkey: u.Pubkey, GiteaUserID: link.GiteaUserID, GiteaUser: link.GiteaUser})
			if e != nil {
				return false, e
			}
			if live {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Service) reconcilePackageAllocations(ctx context.Context, host string) error {
	allocations, err := s.store.ListTenantPackageAllocations(ctx, host, "")
	if err != nil {
		return err
	}
	for _, a := range allocations {
		if a.Orphaned || a.Pending {
			continue
		}
		live, e := s.allocationOwnerLive(ctx, host, a)
		if e != nil {
			return e
		}
		if !live {
			if e = s.orphan(ctx, a, "allocation owner no longer authorized"); e != nil {
				return e
			}
		}
	}
	return nil
}

func (s *Service) AuthorizePackageRequest(ctx context.Context, req PackageAuthorizationRequest) (PackageAuthorizationDecision, error) {
	if len(req.Coordinates) == 0 {
		return PackageAuthorizationDecision{}, nil
	}
	var tenantRecord store.ManagedTenant
	managed := false
	for i, c := range req.Coordinates {
		t, err := s.store.GetManagedTenantByOrgName(ctx, c.Owner)
		if errors.Is(err, sql.ErrNoRows) {
			if managed {
				return PackageAuthorizationDecision{Managed: true}, ErrPackageDenied
			}
			continue
		}
		if err != nil {
			return PackageAuthorizationDecision{}, err
		}
		if !managed {
			tenantRecord = t
			managed = true
		} else if tenantRecord.Host != t.Host {
			return PackageAuthorizationDecision{Managed: true}, ErrPackageDenied
		}
		name, err := normalizePackageName(c.Family, c.Name)
		if err != nil {
			return PackageAuthorizationDecision{Managed: true}, ErrPackageDenied
		}
		req.Coordinates[i].Name = name
	}
	if !managed {
		return PackageAuthorizationDecision{}, nil
	}
	for _, c := range req.Coordinates {
		if c.Owner != tenantRecord.OrgName {
			return PackageAuthorizationDecision{Managed: true}, ErrPackageDenied
		}
	}
	decision := PackageAuthorizationDecision{Managed: true}
	err := s.store.WithTenantLock(ctx, tenantRecord.Host, func(ctx context.Context) error {
		t, err := s.store.GetManagedTenant(ctx, tenantRecord.Host)
		if err != nil {
			return err
		}
		if t.State != store.TenantStateActive {
			return ErrPackageDenied
		}
		policy, err := s.store.GetTenantPackagePolicy(ctx, t.Host)
		if err != nil {
			return err
		}
		if !policy.Enabled {
			return ErrPackageDenied
		}
		allowed := map[string]bool{}
		for _, f := range policy.AllowedFamilies {
			allowed[f] = true
		}
		allPublic := true
		for _, c := range req.Coordinates {
			if !allowed[c.Family] {
				return ErrPackageDenied
			}
			now := s.now().UTC()
			a, err := s.store.GetTenantPackageAllocation(ctx, t.Host, c.Family, c.Name)
			if err == nil && a.Pending && !a.ReservationExpiresAt.After(now) {
				_, e := s.store.DeleteTenantPackageReservation(ctx, t.Host, c.Family, c.Name, a.ReservationID)
				if e != nil {
					return e
				}
				err = sql.ErrNoRows
			}
			if errors.Is(err, sql.ErrNoRows) && policy.AllocationMode == store.TenantPackageAllocationOpen {
				if !c.Creation || req.Principal == nil {
					if c.Write {
						return ErrPackageDenied
					}
					return ErrPackageDenied
				}
				member, e := s.currentMember(ctx, t.Host, *req.Principal)
				if e != nil {
					return e
				}
				if !member {
					return ErrPackageDenied
				}
				var raw [16]byte
				if _, e = rand.Read(raw[:]); e != nil {
					return e
				}
				reservationID := hex.EncodeToString(raw[:])
				candidate := store.TenantPackageAllocation{Host: t.Host, Family: c.Family, Name: c.Name, TargetType: store.TenantPackageTargetPubkey, TargetID: req.Principal.Pubkey, Visibility: store.TenantPackageVisibilityPrivate, Pending: true, ReservationID: reservationID, ReservationExpiresAt: now.Add(15 * time.Minute), Version: 1, CreatedAt: now, UpdatedAt: now}
				if _, e = s.store.CreateTenantPackageAllocation(ctx, candidate); e != nil {
					return e
				}
				a, err = s.store.GetTenantPackageAllocation(ctx, t.Host, c.Family, c.Name)
			}
			if errors.Is(err, sql.ErrNoRows) {
				return ErrPackageDenied
			}
			if err != nil {
				return err
			}
			if a.Orphaned {
				return ErrPackageDenied
			}
			ownerLive, e := s.allocationOwnerLive(ctx, t.Host, a)
			if e != nil {
				return e
			}
			if !ownerLive {
				if !a.Pending {
					_ = s.orphan(ctx, a, "allocation owner no longer authorized")
				}
				return ErrPackageDenied
			}
			if a.Pending {
				if !c.Write {
					return ErrPackageDenied
				}
				if req.RegistryContinuation {
					if c.Creation {
						decision.Reservations = append(decision.Reservations, PackageReservation{Host: t.Host, Family: c.Family, Name: c.Name, ID: a.ReservationID, FinalizeOnSuccess: true})
					}
					allPublic = false
					continue
				}
				if !c.Creation {
					return ErrPackageDenied
				}
				if req.Principal == nil {
					return ErrPackageAuthRequired
				}
				ok, e := s.targetEligible(ctx, t.Host, a, *req.Principal)
				if e != nil {
					return e
				}
				if !ok {
					return ErrPackageDenied
				}
				decision.Reservations = append(decision.Reservations, PackageReservation{Host: t.Host, Family: c.Family, Name: c.Name, ID: a.ReservationID, FinalizeOnSuccess: c.Family != store.TenantPackageFamilyDocker})
				allPublic = false
				continue
			}
			if a.Visibility != store.TenantPackageVisibilityPublic {
				allPublic = false
			}
			if req.RegistryContinuation {
				continue
			}
			if !c.Write && a.Visibility == store.TenantPackageVisibilityPublic {
				continue
			}
			if req.Principal == nil {
				return ErrPackageAuthRequired
			}
			ok, e := s.targetEligible(ctx, t.Host, a, *req.Principal)
			if e != nil {
				return e
			}
			if !ok {
				return ErrPackageDenied
			}
		}
		decision.PublicRead = allPublic
		return nil
	})
	return decision, err
}

func (s *Service) CompletePackageRequest(ctx context.Context, decision PackageAuthorizationDecision, success bool) error {
	for _, reservation := range decision.Reservations {
		if err := s.store.WithTenantLock(ctx, reservation.Host, func(ctx context.Context) error {
			a, err := s.store.GetTenantPackageAllocation(ctx, reservation.Host, reservation.Family, reservation.Name)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if !a.Pending || a.ReservationID != reservation.ID {
				return nil
			}
			if !success {
				_, err = s.store.DeleteTenantPackageReservation(ctx, reservation.Host, reservation.Family, reservation.Name, reservation.ID)
				return err
			}
			if !reservation.FinalizeOnSuccess {
				return nil
			}
			expected := a.Version
			a.Pending = false
			a.ReservationID = ""
			a.ReservationExpiresAt = time.Time{}
			a.Version++
			a.UpdatedAt = s.now().UTC()
			ok, err := s.store.UpdateTenantPackageAllocation(ctx, a, expected)
			if err != nil {
				return err
			}
			if !ok {
				return ErrConflict
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

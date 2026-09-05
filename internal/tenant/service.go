package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const ReaderTeamName = "grasp-domain-readers-v1"

var (
	ErrNotFound       = errors.New("tenant not found")
	ErrConflict       = errors.New("tenant state conflict")
	ErrWorkerRequired = errors.New("shared-read requires the tenant revocation worker")
)

type giteaAPI interface {
	CreateManagedOrganization(context.Context, string, string) (gitea.Organization, error)
	GetOrganization(context.Context, string) (gitea.Organization, error)
	CreateTeam(context.Context, string, gitea.TeamSpec) (gitea.Team, error)
	ListTeams(context.Context, string) ([]gitea.Team, error)
	GetTeam(context.Context, int64) (gitea.Team, error)
	ListTeamMembers(context.Context, int64) ([]gitea.User, error)
	AddTeamMember(context.Context, int64, string) error
	RemoveTeamMember(context.Context, int64, string) error
}

type Service struct {
	store  store.AuthStore
	gitea  giteaAPI
	worker bool
	log    *slog.Logger
	now    func() time.Time
}

func New(st store.AuthStore, client giteaAPI, worker bool, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: st, gitea: client, worker: worker, log: logger, now: time.Now}
}

func CanonicalHost(raw string) (string, error) { return nip05resolve.CanonicalizeHost(raw) }
func newProvisioningMarker() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "grasp-tenant-provisioning:" + hex.EncodeToString(b[:]), nil
}

func managedTeamMatches(team gitea.Team, t store.ManagedTenant) bool {
	return team.ID > 0 && team.Name == ReaderTeamName && team.Description == t.ProvisioningMarker && team.Organization != nil && team.Organization.ID == t.GiteaOrgID && team.Permission == "none" && team.IncludesAllRepositories && !team.CanCreateOrgRepo && len(team.UnitsMap) == 1 && team.UnitsMap["repo.code"] == "read"
}

func ReservedOrgName(host string) (string, error) {
	h, err := CanonicalHost(host)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(h))
	return fmt.Sprintf("grasp-t-%x", sum[:16]), nil
}

func (s *Service) Get(ctx context.Context, raw string) (store.ManagedTenant, error) {
	h, e := CanonicalHost(raw)
	if e != nil {
		return store.ManagedTenant{}, e
	}
	t, e := s.store.GetManagedTenant(ctx, h)
	if errors.Is(e, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, e
}

func (s *Service) Approve(ctx context.Context, raw, policy string) (store.ManagedTenant, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.ManagedTenant{}, err
	}
	if policy == "" {
		policy = store.TenantPolicyDirectoryOnly
	}
	if policy != store.TenantPolicyDirectoryOnly && policy != store.TenantPolicySharedRead {
		return store.ManagedTenant{}, fmt.Errorf("invalid tenant policy %q", policy)
	}
	if policy == store.TenantPolicySharedRead && !s.worker {
		return store.ManagedTenant{}, ErrWorkerRequired
	}
	var out store.ManagedTenant
	err = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		t, e := s.store.GetManagedTenant(ctx, h)
		if e == nil {
			if t.State == store.TenantStateKilled {
				return ErrConflict
			}
			if t.Policy == policy {
				out = t
				return nil
			}
			t.Policy = policy
			t.Version++
			t.UpdatedAt = s.now().UTC()
			ok, e := s.store.UpdateManagedTenant(ctx, t, t.Version-1)
			if e != nil {
				return e
			}
			if !ok {
				return ErrConflict
			}
			out = t
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		name, e := ReservedOrgName(h)
		if e != nil {
			return e
		}
		marker, e := newProvisioningMarker()
		if e != nil {
			return e
		}
		now := s.now().UTC()
		t = store.ManagedTenant{Host: h, Policy: policy, State: store.TenantStatePending, OrgName: name, ProvisioningMarker: marker, Version: 1, CreatedAt: now, UpdatedAt: now}
		if e = s.store.CreateManagedTenant(ctx, t); e != nil {
			return e
		}
		out = t
		return nil
	})
	if err == nil && out.ReaderTeamID > 0 {
		err = s.reconcileHost(ctx, h)
	}
	return out, err
}

func (s *Service) Create(ctx context.Context, raw string) (store.ManagedTenant, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.ManagedTenant{}, err
	}
	var out store.ManagedTenant
	err = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		t, e := s.store.GetManagedTenant(ctx, h)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if t.State == store.TenantStateKilled {
			return ErrConflict
		}
		if t.GiteaOrgID > 0 && t.ReaderTeamID > 0 {
			out = t
			return nil
		}
		if t.State != store.TenantStatePending {
			return ErrConflict
		}
		if t.ProvisioningMarker == "" {
			return fmt.Errorf("%w: missing provisioning marker", ErrConflict)
		}
		if t.GiteaOrgID == 0 {
			org, createErr := s.gitea.CreateManagedOrganization(ctx, t.OrgName, t.ProvisioningMarker)
			if createErr != nil {
				org, e = s.gitea.GetOrganization(ctx, t.OrgName)
				if e != nil || org.UserName != t.OrgName || org.Visibility != "private" || org.Description != t.ProvisioningMarker {
					return createErr
				}
			}
			t.GiteaOrgID = org.ID
			t.Version++
			t.UpdatedAt = s.now().UTC()
			ok, e := s.store.UpdateManagedTenant(ctx, t, t.Version-1)
			if e != nil || !ok {
				if e == nil {
					e = ErrConflict
				}
				return e
			}
		}
		pinnedOrg, e := s.gitea.GetOrganization(ctx, t.OrgName)
		if e != nil || pinnedOrg.ID != t.GiteaOrgID || pinnedOrg.UserName != t.OrgName || pinnedOrg.Visibility != "private" || pinnedOrg.Description != t.ProvisioningMarker {
			if e != nil {
				return e
			}
			return fmt.Errorf("%w: persisted organization pin no longer matches", ErrConflict)
		}
		teamSpec := gitea.TeamSpec{Name: ReaderTeamName, Description: t.ProvisioningMarker, IncludesAllRepositories: true, CanCreateOrgRepo: false, Permission: "none", UnitsMap: map[string]string{"repo.code": "read"}}
		team, createErr := s.gitea.CreateTeam(ctx, t.OrgName, teamSpec)
		if createErr != nil {
			teams, e := s.gitea.ListTeams(ctx, t.OrgName)
			if e != nil {
				return createErr
			}
			team = gitea.Team{}
			for _, candidate := range teams {
				if candidate.Name == ReaderTeamName && candidate.Description == t.ProvisioningMarker && candidate.Organization != nil && candidate.Organization.ID == t.GiteaOrgID {
					team = candidate
					break
				}
			}
			if team.ID == 0 {
				return createErr
			}
		}
		if !managedTeamMatches(team, t) {
			return fmt.Errorf("%w: managed team response did not match provisioning intent", ErrConflict)
		}
		t.ReaderTeamID = team.ID
		t.State = store.TenantStateActive
		t.Version++
		t.UpdatedAt = s.now().UTC()
		ok, e := s.store.UpdateManagedTenant(ctx, t, t.Version-1)
		if e != nil || !ok {
			if e == nil {
				e = ErrConflict
			}
			return e
		}
		out = t
		return nil
	})
	if err == nil && out.Policy == store.TenantPolicySharedRead {
		err = s.reconcileHost(ctx, h)
		if err == nil {
			out, _ = s.Get(ctx, h)
		}
	}
	return out, err
}

func (s *Service) transition(ctx context.Context, raw, to string) (store.ManagedTenant, error) {
	h, e := CanonicalHost(raw)
	if e != nil {
		return store.ManagedTenant{}, e
	}
	var out store.ManagedTenant
	e = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		t, e := s.store.GetManagedTenant(ctx, h)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if t.State == to {
			out = t
			return nil
		}
		if t.State == store.TenantStateKilled {
			return ErrConflict
		}
		if to == store.TenantStateSuspended && t.State != store.TenantStateActive {
			return ErrConflict
		}
		if to == store.TenantStateActive && t.State != store.TenantStateSuspended {
			return ErrConflict
		}
		if to == store.TenantStateActive && t.Policy == store.TenantPolicySharedRead && !s.worker {
			return ErrWorkerRequired
		}
		t.State = to
		t.Version++
		t.UpdatedAt = s.now().UTC()
		ok, e := s.store.UpdateManagedTenant(ctx, t, t.Version-1)
		if e != nil {
			return e
		}
		if !ok {
			return ErrConflict
		}
		out = t
		return nil
	})
	if e == nil && out.ReaderTeamID > 0 {
		e = s.reconcileHost(ctx, h)
		if e == nil {
			out, _ = s.Get(ctx, h)
		}
	}
	return out, e
}
func (s *Service) Suspend(ctx context.Context, h string) (store.ManagedTenant, error) {
	return s.transition(ctx, h, store.TenantStateSuspended)
}
func (s *Service) Resume(ctx context.Context, h string) (store.ManagedTenant, error) {
	return s.transition(ctx, h, store.TenantStateActive)
}
func (s *Service) Kill(ctx context.Context, h string) (store.ManagedTenant, error) {
	return s.transition(ctx, h, store.TenantStateKilled)
}

// RotateSCIMToken mints the only credential accepted for a tenant's inbound
// SCIM surface. Only its SHA-256 digest is persisted.
func (s *Service) RotateSCIMToken(ctx context.Context, raw string) (store.ManagedTenant, string, error) {
	h, err := CanonicalHost(raw)
	if err != nil {
		return store.ManagedTenant{}, "", err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return store.ManagedTenant{}, "", err
	}
	plaintext := "grasp_scim_" + base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(plaintext))
	var out store.ManagedTenant
	err = s.store.WithTenantLock(ctx, h, func(ctx context.Context) error {
		t, e := s.store.GetManagedTenant(ctx, h)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if t.State == store.TenantStateSuspended || t.State == store.TenantStateKilled {
			return ErrConflict
		}
		generation := int64(1)
		if old, e := s.store.GetTenantSCIMToken(ctx, h); e == nil {
			generation = old.Generation + 1
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		pending := store.TenantSCIMToken{Host: h, TokenHash: digest[:], TokenSuffix: plaintext[len(plaintext)-8:], Generation: generation, UpdatedAt: s.now().UTC()}
		if e := s.store.StageTenantSCIMToken(ctx, pending); e != nil {
			return e
		}
		if e := s.reconcileLocked(ctx, h, true); e != nil {
			_ = s.store.ClearPendingTenantSCIMToken(ctx, h, digest[:])
			_ = s.reconcileLocked(ctx, h, false)
			return fmt.Errorf("enforce SCIM authorization before token activation: %w", e)
		}
		ok, e := s.store.ActivateTenantSCIMToken(ctx, h, digest[:], t.Version, s.now().UTC())
		if e != nil || !ok {
			_ = s.store.ClearPendingTenantSCIMToken(ctx, h, digest[:])
			if e == nil {
				e = ErrConflict
			}
			return e
		}
		out, e = s.store.GetManagedTenant(ctx, h)
		return e
	})
	if err != nil {
		return store.ManagedTenant{}, "", err
	}
	return out, plaintext, nil
}

// ReconcileHost applies declared authorization state through the pinned team.
func (s *Service) ReconcileHost(ctx context.Context, host string) error {
	return s.reconcileHost(ctx, host)
}

func (s *Service) Name() string { return "tenant_reconciliation" }
func (s *Service) Check(ctx context.Context) error {
	tenants, err := s.store.ListManagedTenants(ctx)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	for _, t := range tenants {
		needsDeny := t.ReaderTeamID > 0 && (t.State == store.TenantStateSuspended || t.State == store.TenantStateKilled || t.Policy == store.TenantPolicyDirectoryOnly)
		needsFresh := t.State == store.TenantStateActive && t.Policy == store.TenantPolicySharedRead
		if (needsDeny || needsFresh) && (t.ReconciledVersion != t.Version || t.LastError != "") {
			return fmt.Errorf("tenant %s has unreconciled policy", t.Host)
		}
		if needsFresh && (t.LastReconciledAt.IsZero() || now.Sub(t.LastReconciledAt) > 45*time.Minute) {
			return fmt.Errorf("tenant %s reconciliation is stale", t.Host)
		}
	}
	return nil
}

func (s *Service) ValidateStartup(ctx context.Context) error {
	ts, e := s.store.ListManagedTenants(ctx)
	if e != nil {
		return e
	}
	if s.worker {
		return nil
	}
	for _, t := range ts {
		if t.Policy == store.TenantPolicySharedRead && t.State != store.TenantStateKilled {
			return ErrWorkerRequired
		}
	}
	return nil
}

// ReconcileAll is intended to run under the shared maintenance lease.
func (s *Service) ReconcileAll(ctx context.Context) error {
	ts, e := s.store.ListManagedTenants(ctx)
	if e != nil {
		return e
	}
	var first error
	for _, t := range ts {
		if e = s.reconcileHost(ctx, t.Host); e != nil {
			if first == nil {
				first = e
			}
			s.log.Error("tenant reconciliation failed", "host", t.Host, "error", e)
		}
	}
	return first
}

func (s *Service) reconcileHost(ctx context.Context, host string) error {
	return s.store.WithTenantLock(ctx, host, func(ctx context.Context) error { return s.reconcileLocked(ctx, host, false) })
}
func (s *Service) setAccess(ctx context.Context, t store.ManagedTenant, m store.TenantMembership, state string, granted, orphaned bool, now time.Time) (bool, error) {
	return s.store.UpdateTenantMembershipAccess(ctx, t.Host, m.Pubkey, state, granted, orphaned, now, m.CheckedAt, t.Version)
}

func (s *Service) reconcileLocked(ctx context.Context, host string, forceSCIM bool) error {
	t, err := s.store.GetManagedTenant(ctx, host)
	if err != nil {
		return err
	}
	if t.ReaderTeamID == 0 {
		return nil
	}
	now := s.now().UTC()
	org, orgErr := s.gitea.GetOrganization(ctx, t.OrgName)
	orgValid := orgErr == nil && org.ID == t.GiteaOrgID && org.UserName == t.OrgName && org.Visibility == "private" && org.Description == t.ProvisioningMarker
	team, teamErr := s.gitea.GetTeam(ctx, t.ReaderTeamID)
	safeToMutate := teamErr == nil && team.Organization != nil && team.Organization.ID == t.GiteaOrgID
	if !safeToMutate {
		if teamErr != nil {
			return s.recordError(ctx, t, teamErr)
		}
		return s.recordError(ctx, t, fmt.Errorf("pinned team no longer belongs to pinned organization"))
	}
	teamIdentityValid := team.Name == ReaderTeamName && team.Description == t.ProvisioningMarker
	teamPolicyValid := teamIdentityValid && team.Permission == "none" && team.IncludesAllRepositories && !team.CanCreateOrgRepo && len(team.UnitsMap) == 1 && team.UnitsMap["repo.code"] == "read"
	actual, err := s.gitea.ListTeamMembers(ctx, t.ReaderTeamID)
	if err != nil {
		return s.recordError(ctx, t, err)
	}
	actualByID := map[int64]gitea.User{}
	for _, u := range actual {
		actualByID[u.ID] = u
	}
	existing, err := s.store.ListTenantMemberships(ctx, host)
	if err != nil {
		return s.recordError(ctx, t, err)
	}
	byID := map[int64]store.TenantMembership{}
	byPubkey := map[string]store.TenantMembership{}
	for _, m := range existing {
		byID[m.GiteaUserID] = m
		byPubkey[m.Pubkey] = m
	}
	desired := map[int64]store.TenantMembership{}
	observed := map[int64]store.TenantMembership{}
	scimEnabled := forceSCIM
	scimAuthorized := map[string]bool{}
	_, tokenErr := s.store.GetTenantSCIMToken(ctx, host)
	if tokenErr == nil {
		scimEnabled = true
	}
	if tokenErr != nil && !errors.Is(tokenErr, sql.ErrNoRows) {
		return s.recordError(ctx, t, tokenErr)
	}
	if scimEnabled {
		users, e := s.store.ListSCIMAuthorizedUsers(ctx, host)
		if e != nil {
			return s.recordError(ctx, t, e)
		}
		for _, u := range users {
			scimAuthorized[u.Pubkey] = true
		}
	}
	after := ""
	for {
		links, e := s.store.ListIdentityLinksAfter(ctx, after, 200)
		if e != nil {
			return s.recordError(ctx, t, e)
		}
		if len(links) == 0 {
			break
		}
		for _, link := range links {
			after = link.Pubkey
			a, e := s.store.GetDomainAffiliation(ctx, link.Pubkey)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return s.recordError(ctx, t, e)
			}
			if e != nil {
				continue
			}
			_, wasMember := byPubkey[link.Pubkey]
			if a.Host != host && !wasMember {
				continue
			}
			status := a.Status
			if a.Host != host {
				status = "host_moved"
			}
			m := store.TenantMembership{Host: host, Pubkey: link.Pubkey, GiteaUserID: link.GiteaUserID, GiteaUser: link.GiteaUser, EvidenceStatus: status, VerifiedAt: a.VerifiedAt, CheckedAt: a.CheckedAt, UpdatedAt: now}
			if e := s.store.UpsertTenantMembership(ctx, m); e != nil {
				return e
			}
			observed[link.GiteaUserID] = m
			affiliationEligible := a.Host == host && (a.Status == store.DomainAffiliationVerified || (a.Status == store.DomainAffiliationStale && !a.VerifiedAt.IsZero() && now.Sub(a.VerifiedAt) < 24*time.Hour))
			authorizationEligible := !scimEnabled || scimAuthorized[link.Pubkey]
			if affiliationEligible && authorizationEligible {
				desired[link.GiteaUserID] = m
			}
		}
		if len(links) < 200 {
			break
		}
	}
	scimConflict := false
	if scimEnabled {
		for id := range actualByID {
			if _, declared := desired[id]; !declared {
				scimConflict = true
				break
			}
		}
	}
	grantEnabled := s.worker && orgValid && teamPolicyValid && !scimConflict && t.State == store.TenantStateActive && t.Policy == store.TenantPolicySharedRead
	for id, m := range desired {
		if grantEnabled {
			ok, e := s.setAccess(ctx, t, m, store.TenantAccessPolicyRemoved, false, false, now)
			if e != nil {
				return e
			}
			if !ok {
				return ErrConflict
			}
			if _, present := actualByID[id]; !present {
				if e := s.gitea.AddTeamMember(ctx, t.ReaderTeamID, m.GiteaUser); e != nil {
					return s.recordError(ctx, t, e)
				}
			}
			ok, e = s.setAccess(ctx, t, m, store.TenantAccessGranted, true, false, now)
			if e != nil {
				return e
			}
			if !ok {
				_ = s.gitea.RemoveTeamMember(ctx, t.ReaderTeamID, m.GiteaUser)
				return ErrConflict
			}
		} else {
			ok, e := s.setAccess(ctx, t, m, store.TenantAccessPolicyRemoved, false, false, now)
			if e != nil {
				return e
			}
			if !ok {
				return ErrConflict
			}
		}
	}
	for id, m := range observed {
		if _, eligible := desired[id]; eligible {
			continue
		}
		if _, present := actualByID[id]; present {
			continue
		}
		state, orphaned := store.TenantAccessRevoked, true
		if scimEnabled {
			state, orphaned = store.TenantAccessPolicyRemoved, false
		}
		ok, e := s.setAccess(ctx, t, m, state, false, orphaned, now)
		if e != nil {
			return e
		}
		if !ok {
			return ErrConflict
		}
	}
	for id, u := range actualByID {
		if _, ok := desired[id]; grantEnabled && ok {
			continue
		}
		if e := s.gitea.RemoveTeamMember(ctx, t.ReaderTeamID, u.Login); e != nil {
			return s.recordError(ctx, t, e)
		}
		m, ok := observed[id]
		if !ok {
			m, ok = byID[id]
		}
		if !ok {
			m = store.TenantMembership{Host: host, Pubkey: "unknown:" + fmt.Sprint(id), GiteaUserID: id, GiteaUser: u.Login, EvidenceStatus: "unmanaged", CheckedAt: now, UpdatedAt: now}
			if e := s.store.UpsertTenantMembership(ctx, m); e != nil {
				return e
			}
		}
		state := store.TenantAccessRevoked
		orphaned := true
		if _, eligible := desired[id]; eligible || scimEnabled {
			state = store.TenantAccessPolicyRemoved
			orphaned = false
		}
		ok, e := s.setAccess(ctx, t, m, state, false, orphaned, now)
		if e != nil {
			return e
		}
		if !ok {
			return ErrConflict
		}
	}
	if !orgValid {
		if orgErr != nil {
			return s.recordError(ctx, t, orgErr)
		}
		return s.recordError(ctx, t, fmt.Errorf("tenant organization identity, marker, or visibility drift"))
	}
	if !teamPolicyValid {
		if teamErr != nil {
			return s.recordError(ctx, t, teamErr)
		}
		return s.recordError(ctx, t, fmt.Errorf("tenant reader team identity or unit policy drift"))
	}
	t.ReconciledVersion = t.Version
	t.LastReconciledAt = now
	t.LastError = ""
	ok, e := s.store.UpdateManagedTenant(ctx, t, t.Version)
	if e != nil {
		return e
	}
	if !ok {
		return ErrConflict
	}
	return nil
}

func (s *Service) recordError(ctx context.Context, t store.ManagedTenant, cause error) error {
	t.LastError = cause.Error()
	t.LastReconciledAt = s.now().UTC()
	_, _ = s.store.UpdateManagedTenant(ctx, t, t.Version)
	return cause
}

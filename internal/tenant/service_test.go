package tenant

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeGitea struct {
	org           gitea.Organization
	team          gitea.Team
	members       map[int64]gitea.User
	collaborators map[string]bool
	removeErr     error
}

func (f *fakeGitea) CreateManagedOrganization(_ context.Context, n, marker string) (gitea.Organization, error) {
	if f.org.ID != 0 {
		return gitea.Organization{}, errors.New("organization already exists")
	}
	f.org = gitea.Organization{ID: 11, UserName: n, Visibility: "private", Description: marker}
	return f.org, nil
}
func (f *fakeGitea) GetOrganization(context.Context, string) (gitea.Organization, error) {
	return f.org, nil
}
func (f *fakeGitea) CreateTeam(_ context.Context, _ string, s gitea.TeamSpec) (gitea.Team, error) {
	if f.team.ID != 0 {
		return gitea.Team{}, errors.New("team already exists")
	}
	f.team = gitea.Team{ID: 22, Name: s.Name, Description: s.Description, Organization: &f.org, IncludesAllRepositories: s.IncludesAllRepositories, CanCreateOrgRepo: s.CanCreateOrgRepo, Permission: s.Permission, UnitsMap: s.UnitsMap}
	return f.team, nil
}
func (f *fakeGitea) ListTeams(context.Context, string) ([]gitea.Team, error) {
	if f.team.ID == 0 {
		return nil, nil
	}
	return []gitea.Team{f.team}, nil
}
func (f *fakeGitea) GetTeam(context.Context, int64) (gitea.Team, error) { return f.team, nil }
func (f *fakeGitea) ListTeamMembers(context.Context, int64) ([]gitea.User, error) {
	var out []gitea.User
	for _, u := range f.members {
		out = append(out, u)
	}
	return out, nil
}
func (f *fakeGitea) AddTeamMember(_ context.Context, _ int64, u string) error {
	f.members[9] = gitea.User{ID: 9, Login: u}
	return nil
}
func (f *fakeGitea) RemoveTeamMember(_ context.Context, _ int64, _ string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.members, 9)
	return nil
}

func setup(t *testing.T) (*Service, *store.SQLiteStore, *fakeGitea) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fg := &fakeGitea{members: map[int64]gitea.User{}, collaborators: map[string]bool{"owned-repo/alice": true}}
	svc := New(st, fg, true, nil)
	return svc, st, fg
}

func TestReservedOrgNameCanonicalAndFullHash(t *testing.T) {
	a, err := ReservedOrgName("BÜCHER.Example.")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ReservedOrgName("xn--bcher-kva.example")
	if a != b {
		t.Fatalf("canonical names differ: %s %s", a, b)
	}
	c, _ := ReservedOrgName("other.xn--bcher-kva.example")
	if c == a {
		t.Fatal("exact hosts collided")
	}
	if len(a) != 40 {
		t.Fatalf("name length=%d", len(a))
	}
}

func TestConfirmedRevocationPreservesIdentityAndOwnerCollaborator(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", CanonicalIdentifier: "alice@example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, "example.com", store.TenantPolicySharedRead); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 1 {
		t.Fatal("verified member not granted")
	}
	now = now.Add(time.Minute)
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationConfirmedAbsent, VerifiedAt: now.Add(-time.Minute), CheckedAt: now, FailureClass: store.DomainFailureConfirmedAbsent}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 0 {
		t.Fatal("confirmed revocation retained team access")
	}
	if _, err := st.GetIdentityLinkByPubkey(ctx, "pub"); err != nil {
		t.Fatalf("identity link was removed: %v", err)
	}
	if !fg.collaborators["owned-repo/alice"] {
		t.Fatal("owner collaborator was removed")
	}
	ms, _ := st.ListTenantMemberships(ctx, "example.com")
	if len(ms) != 1 || !ms[0].TenantOrphaned {
		t.Fatalf("membership not orphaned: %+v", ms)
	}
}

func TestRotateSCIMTokenDoesNotActivateWhenEnforcementFails(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 1 {
		t.Fatal("legacy member not granted")
	}
	fg.removeErr = errors.New("gitea unavailable")
	_, plaintext, err := svc.RotateSCIMToken(ctx, "example.com")
	if err == nil || plaintext != "" {
		t.Fatalf("rotation token=%q err=%v", plaintext, err)
	}
	if _, err := st.GetTenantSCIMToken(ctx, "example.com"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed token activated: %v", err)
	}
	if len(fg.members) != 1 {
		t.Fatal("failed staged transition changed prior membership semantics")
	}
}

func TestSCIMDeprovisionPreservesOwnerAccessAndUsesPolicyRemoved(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", CanonicalIdentifier: "alice@example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	_, plaintext, err := svc.RotateSCIMToken(ctx, "example.com")
	if err != nil || plaintext == "" {
		t.Fatalf("rotate token=%q err=%v", plaintext, err)
	}
	stored, err := st.GetTenantSCIMToken(ctx, "example.com")
	if err != nil || string(stored.TokenHash) == plaintext {
		t.Fatalf("token stored in plaintext: %+v err=%v", stored, err)
	}
	u := store.SCIMUser{Host: "example.com", ID: "u1", UserName: "alice@example.com", ExternalID: "pub", Pubkey: "pub", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateSCIMUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	g := store.SCIMGroup{Host: "example.com", ID: "g1", DisplayName: "readers", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateSCIMGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ReplaceSCIMGroupMembers(ctx, g.Host, g.ID, []string{u.ID}, 1, now); err != nil || !ok {
		t.Fatalf("members ok=%v err=%v", ok, err)
	}
	if err := svc.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 1 {
		t.Fatal("SCIM member not granted")
	}
	now = now.Add(time.Minute)
	u.Active = false
	u.Version = 2
	u.UpdatedAt = now
	if ok, err := st.UpdateSCIMUser(ctx, u, 1); err != nil || !ok {
		t.Fatalf("deactivate ok=%v err=%v", ok, err)
	}
	if err := svc.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 0 {
		t.Fatal("SCIM deprovision retained team access")
	}
	ms, _ := st.ListTenantMemberships(ctx, "example.com")
	if len(ms) != 1 || ms[0].AccessState != store.TenantAccessPolicyRemoved || ms[0].TenantOrphaned {
		t.Fatalf("deprovision membership=%+v", ms)
	}
	if _, err := st.GetIdentityLinkByPubkey(ctx, "pub"); err != nil {
		t.Fatalf("identity removed: %v", err)
	}
	if !fg.collaborators["owned-repo/alice"] {
		t.Fatal("owner collaborator removed")
	}
}

func TestProvisioningCrashRetryRecoversOnlyMatchingMarker(t *testing.T) {
	svc, _, fg := setup(t)
	ctx := context.Background()
	approved, err := svc.Approve(ctx, "example.com", store.TenantPolicyDirectoryOnly)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate Gitea accepting both POSTs immediately before the process dies,
	// leaving the already-persisted provisioning intent but no numeric pins.
	fg.org = gitea.Organization{ID: 11, UserName: approved.OrgName, Visibility: "private", Description: approved.ProvisioningMarker}
	fg.team = gitea.Team{ID: 22, Name: ReaderTeamName, Description: approved.ProvisioningMarker, Organization: &fg.org, Permission: "none", IncludesAllRepositories: true, UnitsMap: map[string]string{"repo.code": "read"}}
	created, err := svc.Create(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if created.GiteaOrgID != 11 || created.ReaderTeamID != 22 || created.State != store.TenantStateActive {
		t.Fatalf("recovered tenant=%+v", created)
	}
}

func TestProvisioningRecoveryRejectsUnmarkedExistingOrg(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	approved, err := svc.Approve(ctx, "example.com", store.TenantPolicyDirectoryOnly)
	if err != nil {
		t.Fatal(err)
	}
	fg.org = gitea.Organization{ID: 99, UserName: approved.OrgName, Visibility: "private", Description: "someone-else"}
	if _, err := svc.Create(ctx, "example.com"); err == nil {
		t.Fatal("adopted unmarked existing organization")
	}
	stored, err := st.GetManagedTenant(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.GiteaOrgID != 0 {
		t.Fatalf("pinned arbitrary org id %d", stored.GiteaOrgID)
	}
}

func TestSuspendResumeRestoresMembershipWithoutPoisoningEvidence(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Suspend(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 0 {
		t.Fatal("suspend did not revoke")
	}
	ms, _ := st.ListTenantMemberships(ctx, "example.com")
	if len(ms) != 1 || ms[0].EvidenceStatus != store.DomainAffiliationVerified || ms[0].AccessState != store.TenantAccessPolicyRemoved || ms[0].TenantOrphaned {
		t.Fatalf("policy removal poisoned evidence: %+v", ms)
	}
	if _, err := svc.Resume(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resume(ctx, "example.com"); err != nil {
		t.Fatalf("idempotent resume: %v", err)
	}
	if len(fg.members) != 1 {
		t.Fatal("resume did not synchronously restore")
	}
	ms, _ = st.ListTenantMemberships(ctx, "example.com")
	if ms[0].AccessState != store.TenantAccessGranted || !ms[0].Granted || ms[0].EvidenceStatus != store.DomainAffiliationVerified {
		t.Fatalf("resume membership=%+v", ms[0])
	}
}

func TestDriftRevokesAndFailsReadiness(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	_, _ = svc.Create(ctx, "example.com")
	fg.org.Visibility = "public"
	fg.team.UnitsMap = map[string]string{"repo.code": "write"}
	if err := svc.ReconcileAll(ctx); err == nil {
		t.Fatal("drift reconciliation succeeded")
	}
	if len(fg.members) != 0 {
		t.Fatal("drift did not revoke all members")
	}
	if err := svc.Check(ctx); err == nil {
		t.Fatal("drift did not fail readiness")
	}
}

func TestStaleOver24HoursRevokes(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationStale, VerifiedAt: now.Add(-25 * time.Hour), CheckedAt: now, FailureClass: store.DomainFailureIndeterminate})
	if err := svc.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 0 {
		t.Fatal("24h-expired stale member retained access")
	}
}

func TestStaleGraceAndKillSwitch(t *testing.T) {
	svc, st, fg := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	_ = st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationStale, VerifiedAt: now.Add(-23 * time.Hour), CheckedAt: now})
	_, _ = svc.Approve(ctx, "example.com", store.TenantPolicySharedRead)
	if _, err := svc.Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 1 {
		t.Fatal("stale-under-24h should remain in grace")
	}
	if _, err := svc.Kill(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(fg.members) != 0 {
		t.Fatal("kill switch did not synchronously revoke")
	}
	if _, err := svc.Resume(ctx, "example.com"); err == nil {
		t.Fatal("killed tenant resumed")
	}
}

package tenant

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

func seedPackageTenant(t *testing.T, mode string) (*Service, *store.SQLiteStore, store.ManagedTenant, PackagePrincipal) {
	t.Helper()
	svc, st, _ := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "pub", Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "pub", Host: "example.com", Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, "example.com", store.TenantPolicyDirectoryOnly, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := svc.Create(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	families := []string{"docker", "npm", "generic"}
	if _, err = svc.UpdatePackagePolicy(ctx, tn.Host, PackagePolicyPatch{ExpectedVersion: 1, Enabled: &enabled, AllowedFamilies: &families, AllocationMode: &mode}); err != nil {
		t.Fatal(err)
	}
	return svc, st, tn, PackagePrincipal{Pubkey: "pub", GiteaUserID: 9, GiteaUser: "alice"}
}

func TestPackageAllocationPolicyMatrix(t *testing.T) {
	ctx := context.Background()
	svc, st, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	req := PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "docker", Name: "app", Write: true}}, Principal: &principal}
	if _, err := svc.AuthorizePackageRequest(ctx, req); !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("unallocated err=%v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "foreign", Npub: "npub2", GiteaUserID: 10, GiteaUser: "bob", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "foreign", Host: tn.Host, Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "docker", Name: "app", TargetType: "pubkey", TargetID: "foreign"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthorizePackageRequest(ctx, req); !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("foreign err=%v", err)
	}

	svc2, st2, tn2, principal2 := seedPackageTenant(t, store.TenantPackageAllocationOpen)
	req = PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn2.OrgName, Family: "docker", Name: "open/app", Write: true, Creation: true}}, Principal: &principal2}
	decision, err := svc2.AuthorizePackageRequest(ctx, req)
	if err != nil {
		t.Fatalf("open reservation: %v", err)
	}
	a, err := st2.GetTenantPackageAllocation(ctx, tn2.Host, "docker", "open/app")
	if err != nil || a.TargetID != principal2.Pubkey || !a.Pending {
		t.Fatalf("reservation=%+v err=%v", a, err)
	}
	if err = svc2.CompletePackageRequest(ctx, decision, true); err != nil {
		t.Fatal(err)
	}
	a, _ = st2.GetTenantPackageAllocation(ctx, tn2.Host, "docker", "open/app")
	if !a.Pending {
		t.Fatal("docker token exchange finalized before publish")
	}
	continuation, err := svc2.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn2.OrgName, Family: "docker", Name: "open/app", Write: true, Creation: true}}, RegistryContinuation: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = svc2.CompletePackageRequest(ctx, continuation, true); err != nil {
		t.Fatal(err)
	}
	a, _ = st2.GetTenantPackageAllocation(ctx, tn2.Host, "docker", "open/app")
	if a.Pending {
		t.Fatal("successful docker publish did not finalize reservation")
	}
}

func TestManagedPackageOwnerRejectsMixedCaseBypass(t *testing.T) {
	ctx := context.Background()
	svc, _, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	for _, family := range []string{"npm", "generic", "docker"} {
		_, err := svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: strings.ToUpper(tn.OrgName), Family: family, Name: "pkg", Write: true, Creation: true}}, Principal: &principal})
		if !errors.Is(err, ErrPackageDenied) {
			t.Fatalf("%s mixed-case err=%v", family, err)
		}
	}
}

func TestOpenAllocationReservationsFinalizeOnlyAfterSuccess(t *testing.T) {
	ctx := context.Background()
	svc, st, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationOpen)
	for _, c := range []PackageCoordinate{{Owner: tn.OrgName, Family: "npm", Name: "delete-squat", Write: true}, {Owner: tn.OrgName, Family: "npm", Name: "bad%name", Write: true, Creation: true}} {
		if _, err := svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{c}, Principal: &principal}); !errors.Is(err, ErrPackageDenied) {
			t.Fatalf("coordinate=%+v err=%v", c, err)
		}
	}
	if _, err := st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "delete-squat"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DELETE created allocation: %v", err)
	}
	creation := PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "npm", Name: "widget", Write: true, Creation: true}}, Principal: &principal}
	decision, err := svc.AuthorizePackageRequest(ctx, creation)
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "widget")
	if err != nil || !a.Pending {
		t.Fatalf("pending=%+v err=%v", a, err)
	}
	if err = svc.CompletePackageRequest(ctx, decision, false); err != nil {
		t.Fatal(err)
	}
	if _, err = st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "widget"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed publish retained reservation: %v", err)
	}
	expiring := creation
	expiring.Coordinates = []PackageCoordinate{{Owner: tn.OrgName, Family: "npm", Name: "expiring", Write: true, Creation: true}}
	expiredDecision, err := svc.AuthorizePackageRequest(ctx, expiring)
	if err != nil {
		t.Fatal(err)
	}
	oldReservation, err := st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "expiring")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return oldReservation.ReservationExpiresAt.Add(time.Second) }
	newDecision, err := svc.AuthorizePackageRequest(ctx, expiring)
	if err != nil {
		t.Fatal(err)
	}
	newReservation, err := st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "expiring")
	if err != nil || newReservation.ReservationID == oldReservation.ReservationID {
		t.Fatalf("expired reservation not replaced old=%+v new=%+v err=%v", oldReservation, newReservation, err)
	}
	if err = svc.CompletePackageRequest(ctx, expiredDecision, false); err != nil {
		t.Fatal(err)
	}
	if err = svc.CompletePackageRequest(ctx, newDecision, false); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.AuthorizePackageRequest(ctx, creation)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.CompletePackageRequest(ctx, decision, true); err != nil {
		t.Fatal(err)
	}
	a, err = st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "widget")
	if err != nil || a.Pending {
		t.Fatalf("successful publish allocation=%+v err=%v", a, err)
	}
}

func TestPackageAuthorizationLifecycleAndVisibility(t *testing.T) {
	ctx := context.Background()
	svc, st, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	if _, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "npm", Name: "widget", TargetType: "pubkey", TargetID: principal.Pubkey, Visibility: "private"}); err != nil {
		t.Fatal(err)
	}
	read := PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "npm", Name: "widget"}}}
	if _, err := svc.AuthorizePackageRequest(ctx, read); !errors.Is(err, ErrPackageAuthRequired) {
		t.Fatalf("private anonymous err=%v", err)
	}
	read.Principal = &principal
	if _, err := svc.AuthorizePackageRequest(ctx, read); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Suspend(ctx, tn.Host); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthorizePackageRequest(ctx, read); !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("suspended err=%v", err)
	}
	if _, err := svc.Resume(ctx, tn.Host); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: principal.Pubkey, Host: tn.Host, Status: store.DomainAffiliationConfirmedAbsent, CheckedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthorizePackageRequest(ctx, read); !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("revoked err=%v", err)
	}
	a, err := st.GetTenantPackageAllocation(ctx, tn.Host, "npm", "widget")
	if err != nil || !a.Orphaned {
		t.Fatalf("orphan=%+v err=%v", a, err)
	}
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: "new-owner", Npub: "npub-new", GiteaUserID: 11, GiteaUser: "carol", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: "new-owner", Host: tn.Host, Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	reassigned, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "npm", Name: "widget", TargetType: "pubkey", TargetID: "new-owner", Visibility: "private"})
	if err != nil || reassigned.Orphaned || reassigned.TargetID != "new-owner" {
		t.Fatalf("reassigned=%+v err=%v", reassigned, err)
	}
}

func TestTeamAllocationRequiresLiveSCIMMembership(t *testing.T) {
	ctx := context.Background()
	svc, st, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	now := time.Now().UTC()
	if err := st.UpsertTenantSCIMToken(ctx, store.TenantSCIMToken{Host: tn.Host, TokenHash: []byte("hash"), Generation: 1, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSCIMUser(ctx, store.SCIMUser{Host: tn.Host, ID: "u1", UserName: "alice", ExternalID: "pub", Pubkey: principal.Pubkey, Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSCIMGroup(ctx, store.SCIMGroup{Host: tn.Host, ID: "team1", DisplayName: "publishers", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ReplaceSCIMGroupMembers(ctx, tn.Host, "team1", []string{"u1"}, 1, now); err != nil || !ok {
		t.Fatalf("members ok=%v err=%v", ok, err)
	}
	if _, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "generic", Name: "team-artifact", TargetType: "team", TargetID: "team1", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	req := PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "generic", Name: "team-artifact", Write: true}}, Principal: &principal}
	if _, err := svc.AuthorizePackageRequest(ctx, req); err != nil {
		t.Fatalf("team publish: %v", err)
	}
	if _, err := svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "generic", Name: "team-artifact"}}}); err != nil {
		t.Fatalf("public team read: %v", err)
	}
	group, err := st.GetSCIMGroup(ctx, tn.Host, "team1")
	if err != nil {
		t.Fatal(err)
	}
	expected := group.Version
	group.Active = false
	group.Version++
	group.UpdatedAt = now.Add(time.Second)
	if ok, err := st.UpdateSCIMGroup(ctx, group, expected); err != nil || !ok {
		t.Fatalf("deactivate group ok=%v err=%v", ok, err)
	}
	if _, err := svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "generic", Name: "team-artifact"}}}); !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("inactive team public read err=%v", err)
	}
}

func TestPublicReadRechecksBoundedOwnerAffiliation(t *testing.T) {
	ctx := context.Background()
	svc, st, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	if _, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "generic", Name: "public-old", TargetType: "pubkey", TargetID: principal.Pubkey, Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	affiliation, err := st.GetDomainAffiliation(ctx, principal.Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	now := affiliation.CheckedAt.Add(2 * time.Hour)
	svc.now = func() time.Time { return now }
	svc.affiliationMaxAge = time.Hour
	_, err = svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "generic", Name: "public-old"}}})
	if !errors.Is(err, ErrPackageDenied) {
		t.Fatalf("stale public owner err=%v", err)
	}
	a, e := st.GetTenantPackageAllocation(ctx, tn.Host, "generic", "public-old")
	if e != nil || !a.Orphaned {
		t.Fatalf("allocation=%+v err=%v", a, e)
	}
}

func TestPublicGenericDownloadAllowsAnonymous(t *testing.T) {
	ctx := context.Background()
	svc, _, tn, principal := seedPackageTenant(t, store.TenantPackageAllocationExplicit)
	if _, err := svc.CreatePackageAllocation(ctx, tn.Host, PackageAllocationRequest{Family: "generic", Name: "artifact", TargetType: "pubkey", TargetID: principal.Pubkey, Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.AuthorizePackageRequest(ctx, PackageAuthorizationRequest{Coordinates: []PackageCoordinate{{Owner: tn.OrgName, Family: "generic", Name: "artifact"}}})
	if err != nil || !decision.Managed || !decision.PublicRead {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

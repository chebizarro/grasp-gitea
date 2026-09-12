package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
	tenantservice "github.com/sharegap/grasp-gitea/internal/tenant"
)

func seedPlacementTenant(t *testing.T, st *store.SQLiteStore, state *testGiteaServer, tenantState string, enabled bool) store.ManagedTenant {
	t.Helper()
	now := time.Now().UTC()
	tenant := store.ManagedTenant{
		Host: "example.com", Policy: store.TenantPolicyDirectoryOnly,
		PlacementEnabled: enabled, State: tenantState,
		OrgName: "grasp-t-placement", ProvisioningMarker: "grasp-tenant-provisioning:placement",
		GiteaOrgID: 77, ReaderTeamID: 88, Version: 1, ReconciledVersion: 1,
		LastReconciledAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateManagedTenant(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.orgs[tenant.OrgName] = true
	state.orgIDs[tenant.OrgName] = tenant.GiteaOrgID
	state.mu.Unlock()
	return tenant
}

func verifiedPlacement(pubkey string) nip05resolve.AffiliationVerification {
	now := time.Now().UTC()
	return nip05resolve.AffiliationVerification{
		CanonicalIdentifier: "alice@example.com", LocalPart: "alice", Host: "example.com",
		Pubkey: pubkey, VerifiedAt: now,
	}
}

func TestTenantPlacementIntentRequiresOneCanonicalHost(t *testing.T) {
	if got := tenantPlacementIntent(nostr.Tags{{"tenant", "EXAMPLE.com."}}); got != "example.com" {
		t.Fatalf("canonical intent=%q", got)
	}
	for _, tags := range []nostr.Tags{
		{{"tenant"}},
		{{"tenant", "example.com", "extra"}},
		{{"tenant", "example.com"}, {"tenant", "example.com"}},
		{{"tenant", "bad/host"}},
	} {
		if got := tenantPlacementIntent(tags); got != "" {
			t.Fatalf("ambiguous intent %v accepted as %q", tags, got)
		}
	}
}

func TestTenantPlacementDecisionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, state, intent            string
		enabled, verified, stale, scim bool
	}{
		{name: "unverified affiliation", state: store.TenantStateActive, enabled: true, intent: "example.com"},
		{name: "stale stored affiliation", state: store.TenantStateActive, enabled: true, intent: "example.com", stale: true},
		{name: "inactive tenant", state: store.TenantStatePending, enabled: true, intent: "example.com", verified: true},
		{name: "tenant opt-in off", state: store.TenantStateActive, intent: "example.com", verified: true},
		{name: "repo opt-in absent", state: store.TenantStateActive, enabled: true, verified: true},
		{name: "SCIM unauthorized", state: store.TenantStateActive, enabled: true, intent: "example.com", verified: true, scim: true},
		{name: "suspended tenant", state: store.TenantStateSuspended, enabled: true, intent: "example.com", verified: true},
		{name: "killed tenant", state: store.TenantStateKilled, enabled: true, intent: "example.com", verified: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, state, _ := newTestService(t)
			seedPlacementTenant(t, st, state, tc.state, tc.enabled)
			pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			now := time.Now().UTC()
			if err := st.UpsertIdentityLink(t.Context(), store.NostrIdentityLink{Pubkey: pubkey, Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if tc.stale {
				if err := st.UpsertDomainAffiliation(t.Context(), store.DomainAffiliation{Pubkey: pubkey, Host: "example.com", Status: store.DomainAffiliationStale, VerifiedAt: now.Add(-23 * time.Hour), CheckedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.scim {
				if err := st.UpsertTenantSCIMToken(t.Context(), store.TenantSCIMToken{Host: "example.com", TokenHash: []byte("hash"), TokenSuffix: "hash", Generation: 1, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			svc.verifyAffiliation = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
				if tc.verified {
					return verifiedPlacement(pubkey)
				}
				return nip05resolve.AffiliationVerification{Host: "example.com", Pubkey: pubkey, FailureClass: nip05resolve.FailureIndeterminate}
			}
			if tc.intent == "" {
				return
			}
			placed, placementErr := svc.tenantPlacement.WithPlacement(t.Context(), tc.intent, func(ctx context.Context, tenant store.ManagedTenant) error {
				if _, authorized := svc.authorizeTenantPlacement(ctx, pubkey, tenant, nil); !authorized {
					return errTenantPlacementDeclined
				}
				return nil
			})
			if placed && placementErr == nil {
				t.Fatal("unsafe tenant placement was selected")
			}
		})
	}
}

func TestTenantPlacementPersistsPhysicalPathAndOwnerAccess(t *testing.T) {
	svc, st, state, reposDir := newTestService(t)
	tenant := seedPlacementTenant(t, st, state, store.TenantStateActive, true)
	ev := makeSignedAnnouncementEvent(t, "dotfiles", "https://git.example.com/npub/dotfiles.git")
	ev.Tags = append(ev.Tags, []string{"tenant", "EXAMPLE.com."})
	if err := ev.Sign(mustSK(testSecretKey)); err != nil {
		t.Fatal(err)
	}
	pubkey := ev.PubKey.Hex()
	now := time.Now().UTC()
	if err := st.UpsertIdentityLink(t.Context(), store.NostrIdentityLink{Pubkey: pubkey, Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	svc.verifyAffiliation = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
		return verifiedPlacement(pubkey)
	}
	if err := svc.HandleAnnouncementEvent(t.Context(), ev, "ws://test-relay"); err != nil {
		t.Fatal(err)
	}
	mappings, err := st.ListMappings(t.Context())
	if err != nil || len(mappings) != 1 {
		t.Fatalf("mappings=%+v err=%v", mappings, err)
	}
	m := mappings[0]
	wantName := tenantRepoName("dotfiles", pubkey)
	if m.Owner != tenant.OrgName || m.RepoName != wantName || m.TenantHost != tenant.Host || m.GiteaRepoID != 1 {
		t.Fatalf("tenant mapping=%+v want host=%s owner=%s name=%s id=1", m, tenant.Host, tenant.OrgName, wantName)
	}
	state.mu.Lock()
	collaborator := state.collaborators[tenant.OrgName+"/"+wantName]
	state.mu.Unlock()
	if collaborator != "alice:write" {
		t.Fatalf("owner collaborator=%q, want alice:write", collaborator)
	}
	hookPath := filepath.Join(reposDir, tenant.OrgName, wantName+".git", "hooks", "pre-receive")
	hook, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(hook) == "" || !containsAll(string(hook), "GRASP_REPO_ID='dotfiles'", "GRASP_REPO_NPUB='") {
		t.Fatalf("unexpected tenant hook: %s", hook)
	}
}

func TestTenantPlacementUsesSharedAuthStore(t *testing.T) {
	svc, mappingStore, state, _ := newTestService(t)
	authStore, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authStore.Close() })
	svc.authStore = authStore
	svc.tenantPlacement = tenantservice.New(authStore, svc.gitea, true, svc.logger)
	tenant := seedPlacementTenant(t, authStore, state, store.TenantStateActive, true)

	ev := makeSignedAnnouncementEvent(t, "shared", "https://git.example.com/npub/shared.git")
	ev.Tags = append(ev.Tags, []string{"tenant", tenant.Host})
	if err := ev.Sign(mustSK(testSecretKey)); err != nil {
		t.Fatal(err)
	}
	pubkey := ev.PubKey.Hex()
	now := time.Now().UTC()
	if err := authStore.UpsertIdentityLink(t.Context(), store.NostrIdentityLink{Pubkey: pubkey, Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := mappingStore.GetIdentityLinkByPubkey(t.Context(), pubkey); err == nil {
		t.Fatal("test requires identity state to exist only in shared auth store")
	}
	svc.verifyAffiliation = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
		return verifiedPlacement(pubkey)
	}
	if err := svc.HandleAnnouncementEvent(t.Context(), ev, "ws://test-relay"); err != nil {
		t.Fatal(err)
	}
	mapping, err := mappingStore.GetMapping(t.Context(), nip19.EncodeNpub(ev.PubKey), "shared")
	if err != nil {
		t.Fatal(err)
	}
	if mapping.TenantHost != tenant.Host || mapping.Owner != tenant.OrgName {
		t.Fatalf("placement read wrong backend: %+v", mapping)
	}
}

func TestReconcileHooksRestoresTenantOwnerCollaborator(t *testing.T) {
	svc, st, state, reposDir := newTestService(t)
	ctx := t.Context()
	const pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const owner = "grasp-t-placement"
	const repoName = "repo-physical-suffix"
	now := time.Now().UTC()
	if err := st.UpsertIdentityLink(ctx, store.NostrIdentityLink{Pubkey: pubkey, Npub: "npub", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMapping(ctx, store.Mapping{Npub: "npub", RepoID: "repo", Pubkey: pubkey, Owner: owner, RepoName: repoName, TenantHost: "example.com", GiteaRepoID: 41, HookInstalled: false}); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.orgs[owner] = true
	state.orgIDs[owner] = 77
	state.repos[owner+"/"+repoName] = testRepo{ID: 41, Name: repoName, Org: owner}
	state.mu.Unlock()
	initBareTestRepo(t, filepath.Join(reposDir, owner, repoName+".git"))
	if err := svc.ReconcileHooks(ctx); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	collaborator := state.collaborators[owner+"/"+repoName]
	state.mu.Unlock()
	if collaborator != "alice:write" {
		t.Fatalf("reconciled collaborator=%q", collaborator)
	}
	mapping, err := st.GetMapping(ctx, "npub", "repo")
	if err != nil || !mapping.HookInstalled {
		t.Fatalf("mapping=%+v err=%v", mapping, err)
	}
}

func TestEnsureUploadPackCapabilitiesUsesPhysicalRepoName(t *testing.T) {
	svc, st, _, reposDir := newTestService(t)
	const owner = "grasp-t-placement"
	const physical = "logical-0123456789abcdef0123"
	if err := st.UpsertMapping(t.Context(), store.Mapping{Npub: "npub", RepoID: "logical", Pubkey: "pub", Owner: owner, RepoName: physical, TenantHost: "example.com", GiteaRepoID: 41, HookInstalled: true}); err != nil {
		t.Fatal(err)
	}
	initBareTestRepo(t, filepath.Join(reposDir, owner, physical+".git"))
	if err := svc.EnsureUploadPackCapabilities(t.Context()); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(reposDir, owner, physical+".git", "config"))
	if err != nil || !strings.Contains(string(config), "allowFilter = true") {
		t.Fatalf("physical repo config=%q err=%v", config, err)
	}
}

func TestTenantRepoNameSuffixIsStableAndUnconditional(t *testing.T) {
	pubkey := "ABCDEF"
	sum := sha256.Sum256([]byte("abcdef"))
	want := "repo-" + hex.EncodeToString(sum[:10])
	if got := tenantRepoName("repo", pubkey); got != want || tenantRepoName("repo", pubkey) != got {
		t.Fatalf("tenant repo name=%q want=%q", got, want)
	}
}

func containsAll(s string, values ...string) bool {
	for _, value := range values {
		if !strings.Contains(s, value) {
			return false
		}
	}
	return true
}

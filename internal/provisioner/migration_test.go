package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func seedExistingMigrationRepo(t *testing.T) (*Service, *store.SQLiteStore, *testGiteaServer, store.ManagedTenant, store.Mapping, string) {
	t.Helper()
	svc, st, state, reposDir := newTestService(t)
	tenant := seedPlacementTenant(t, st, state, store.TenantStateActive, true)
	ev := makeSignedAnnouncementEvent(t, "repo", "https://git.example.com/owner/repo.git")
	ev.Tags = append(ev.Tags, []string{"tenant", tenant.Host})
	if err := ev.Sign(mustSK(testSecretKey)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	npub := nip19.EncodeNpub(ev.PubKey)
	mapping := store.Mapping{
		Npub: npub, RepoID: "repo", Pubkey: ev.PubKey.Hex(), Owner: "owner", RepoName: "repo",
		GiteaRepoID: 41, CloneURL: "https://git.example.com/owner/repo.git", SourceEvent: ev.ID.Hex(),
		HookInstalled: true, AnnouncementEventJSON: string(raw), AnnouncementEventID: ev.ID.Hex(),
	}
	if err := st.UpsertMapping(t.Context(), mapping); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAnnouncementEvent(t.Context(), mapping.Npub, mapping.RepoID, mapping.AnnouncementEventJSON, mapping.AnnouncementEventID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.UpsertIdentityLink(t.Context(), store.NostrIdentityLink{Pubkey: mapping.Pubkey, Npub: npub, GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.orgs[mapping.Owner] = true
	state.orgIDs[mapping.Owner] = 22
	state.repos[mapping.Owner+"/"+mapping.RepoName] = testRepo{ID: mapping.GiteaRepoID, Name: mapping.RepoName, Org: mapping.Owner}
	state.mu.Unlock()
	if err := os.MkdirAll(filepath.Join(reposDir, mapping.Owner, mapping.RepoName+".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := svc.installer.InstallAt(mapping.Owner, mapping.RepoName, mapping.Npub, mapping.RepoID); err != nil {
		t.Fatal(err)
	}
	svc.verifyAffiliation = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
		return verifiedPlacement(mapping.Pubkey)
	}
	return svc, st, state, tenant, mapping, reposDir
}

func TestMigrateExistingPreflightMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *Service, *store.SQLiteStore, *testGiteaServer, store.ManagedTenant, store.Mapping, string)
	}{
		{name: "owner consent absent", mutate: func(t *testing.T, _ *Service, st *store.SQLiteStore, _ *testGiteaServer, _ store.ManagedTenant, m store.Mapping, _ string) {
			ev := makeSignedAnnouncementEvent(t, m.RepoID, m.CloneURL)
			ev.CreatedAt += 100
			if err := ev.Sign(mustSK(testSecretKey)); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(ev)
			if err := st.SetAnnouncementEvent(t.Context(), m.Npub, m.RepoID, string(raw), ev.ID.Hex()); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fresh affiliation required", mutate: func(_ *testing.T, svc *Service, _ *store.SQLiteStore, _ *testGiteaServer, _ store.ManagedTenant, m store.Mapping, _ string) {
			svc.verifyAffiliation = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
				return nip05resolve.AffiliationVerification{Pubkey: m.Pubkey, Host: "example.com", FailureClass: nip05resolve.FailureIndeterminate}
			}
		}},
		{name: "hook must be healthy", mutate: func(t *testing.T, _ *Service, st *store.SQLiteStore, _ *testGiteaServer, _ store.ManagedTenant, m store.Mapping, _ string) {
			if err := st.SetHookInstalled(t.Context(), m.Npub, m.RepoID, false); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "target name must be free", mutate: func(_ *testing.T, _ *Service, _ *store.SQLiteStore, state *testGiteaServer, tenant store.ManagedTenant, m store.Mapping, _ string) {
			name := tenantRepoName(m.RepoID, m.Pubkey)
			state.mu.Lock()
			state.repos[tenant.OrgName+"/"+name] = testRepo{ID: 99, Name: name, Org: tenant.OrgName}
			state.mu.Unlock()
		}},
		{name: "tenant placement must remain enabled", mutate: func(t *testing.T, _ *Service, st *store.SQLiteStore, _ *testGiteaServer, tenant store.ManagedTenant, _ store.Mapping, _ string) {
			tenant.PlacementEnabled = false
			tenant.Version++
			tenant.ReconciledVersion = tenant.Version
			tenant.UpdatedAt = time.Now().UTC()
			if ok, err := st.UpdateManagedTenant(t.Context(), tenant, tenant.Version-1); err != nil || !ok {
				t.Fatalf("disable placement: ok=%v err=%v", ok, err)
			}
		}},
		{name: "mid push lock refuses migration", mutate: func(t *testing.T, _ *Service, _ *store.SQLiteStore, _ *testGiteaServer, _ store.ManagedTenant, m store.Mapping, reposDir string) {
			if err := os.MkdirAll(filepath.Join(reposDir, m.Owner, m.RepoName+".git", "refs", "heads"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(reposDir, m.Owner, m.RepoName+".git", "refs", "heads", "main.lock"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, state, tenant, mapping, reposDir := seedExistingMigrationRepo(t)
			tc.mutate(t, svc, st, state, tenant, mapping, reposDir)
			if _, err := svc.MigrateExisting(t.Context(), tenant.Host, mapping.Npub, mapping.RepoID); err == nil {
				t.Fatal("unsafe migration passed preflight")
			}
		})
	}
}

func TestMigrateExistingSuccess(t *testing.T) {
	svc, st, state, tenant, original, reposDir := seedExistingMigrationRepo(t)
	got, err := svc.MigrateExisting(t.Context(), tenant.Host, original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	wantName := tenantRepoName(original.RepoID, original.Pubkey)
	if got.Owner != tenant.OrgName || got.RepoName != wantName || got.TenantHost != tenant.Host || got.GiteaRepoID != original.GiteaRepoID || got.Migrating || !got.HookInstalled {
		t.Fatalf("migrated mapping=%+v", got)
	}
	if err := svc.installer.VerifyAt(got.Owner, got.RepoName, got.Npub, got.RepoID); err != nil {
		t.Fatalf("migrated hook: %v", err)
	}
	if _, err := os.Stat(filepath.Join(reposDir, got.Owner, got.RepoName+".git", "grasp-migrating")); !os.IsNotExist(err) {
		t.Fatalf("migration marker remains: %v", err)
	}
	if err := svc.installer.VerifyMigrationAt(got.Owner, got.RepoName, got.Npub, got.RepoID); err != nil {
		t.Fatalf("inert migration reference guard missing: %v", err)
	}
	state.mu.Lock()
	collaborator := state.collaborators[got.Owner+"/"+got.RepoName]
	state.mu.Unlock()
	if collaborator != "alice:write" {
		t.Fatalf("owner collaborator=%q", collaborator)
	}
	if journals, err := st.ListRepoMigrations(t.Context()); err != nil || len(journals) != 0 {
		t.Fatalf("journals=%+v err=%v", journals, err)
	}
}

func TestMigrateExistingIDMismatchRollsBack(t *testing.T) {
	svc, st, state, tenant, original, _ := seedExistingMigrationRepo(t)
	state.mu.Lock()
	state.transferResponseID = 999
	state.mu.Unlock()
	if _, err := svc.MigrateExisting(t.Context(), tenant.Host, original.Npub, original.RepoID); err == nil {
		t.Fatal("ID-changing transfer was accepted")
	}
	assertMigrationRolledBack(t, svc, st, state, original)
}

func TestMigrateExistingCrashBoundariesRollBack(t *testing.T) {
	steps := []string{
		store.MigrationStepPrepared,
		store.MigrationStepQuiesced,
		store.MigrationStepTransferred,
		store.MigrationStepRenamed,
		store.MigrationStepMappingUpdated,
		store.MigrationStepHookVerified,
		store.MigrationStepCollaboratorReady,
	}
	for _, failStep := range steps {
		t.Run(failStep, func(t *testing.T) {
			svc, st, state, tenant, original, _ := seedExistingMigrationRepo(t)
			svc.migrationStepHook = func(step string) error {
				if step == failStep {
					return errMigrationCrashTest
				}
				return nil
			}
			if _, err := svc.MigrateExisting(t.Context(), tenant.Host, original.Npub, original.RepoID); !errors.Is(err, errMigrationCrashTest) {
				t.Fatalf("simulated crash error=%v", err)
			}
			if journals, err := st.ListRepoMigrations(t.Context()); err != nil || len(journals) != 1 {
				t.Fatalf("crash journal=%+v err=%v", journals, err)
			}
			svc.migrationStepHook = nil
			if err := svc.ReconcileMigrations(t.Context()); err != nil {
				t.Fatalf("startup recovery: %v", err)
			}
			assertMigrationRolledBack(t, svc, st, state, original)
		})
	}
}

func TestMigrationRecoveryHookFailureRemainsQuiesced(t *testing.T) {
	svc, st, state, tenant, original, reposDir := seedExistingMigrationRepo(t)
	svc.migrationStepHook = func(step string) error {
		if step == store.MigrationStepMappingUpdated {
			return errMigrationCrashTest
		}
		return nil
	}
	if _, err := svc.MigrateExisting(t.Context(), tenant.Host, original.Npub, original.RepoID); !errors.Is(err, errMigrationCrashTest) {
		t.Fatalf("simulated crash error=%v", err)
	}

	hookPath := filepath.Join(reposDir, original.Owner, original.RepoName+".git", "hooks", "pre-receive")
	state.mu.Lock()
	state.afterRename = func() {
		_ = os.Remove(hookPath)
		_ = os.Mkdir(hookPath, 0o755)
	}
	state.mu.Unlock()
	svc.migrationStepHook = nil
	if err := svc.ReconcileMigrations(t.Context()); err == nil {
		t.Fatal("recovery unexpectedly succeeded without restoring the hook")
	}

	mapping, err := st.GetMapping(t.Context(), original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Owner != original.Owner || mapping.RepoName != original.RepoName || !mapping.Migrating || mapping.HookInstalled {
		t.Fatalf("failed recovery mapping not fail-closed: %+v", mapping)
	}
	state.mu.Lock()
	repo := state.repos[original.Owner+"/"+original.RepoName]
	state.mu.Unlock()
	if repo.ID != original.GiteaRepoID || !repo.Archived {
		t.Fatalf("failed recovery repository not archived: %+v", repo)
	}
	if _, err := os.Stat(filepath.Join(reposDir, original.Owner, original.RepoName+".git", "grasp-migrating")); err != nil {
		t.Fatalf("failed recovery marker missing: %v", err)
	}
	if journals, err := st.ListRepoMigrations(t.Context()); err != nil || len(journals) != 1 {
		t.Fatalf("failed recovery journal=%+v err=%v", journals, err)
	}
}

func TestMigrationRecoveryRejectsJournaledNameIdentityMismatch(t *testing.T) {
	svc, st, state, tenant, original, _ := seedExistingMigrationRepo(t)
	svc.migrationStepHook = func(step string) error {
		if step == store.MigrationStepTransferred {
			return errMigrationCrashTest
		}
		return nil
	}
	if _, err := svc.MigrateExisting(t.Context(), tenant.Host, original.Npub, original.RepoID); !errors.Is(err, errMigrationCrashTest) {
		t.Fatalf("simulated crash error=%v", err)
	}

	state.mu.Lock()
	key := tenant.OrgName + "/" + original.RepoName
	reused := state.repos[key]
	reused.ID = 999
	state.repos[key] = reused
	state.mu.Unlock()
	svc.migrationStepHook = nil
	if err := svc.ReconcileMigrations(t.Context()); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("identity mismatch recovery error=%v", err)
	}

	state.mu.Lock()
	_, movedBack := state.repos[original.Owner+"/"+original.RepoName]
	stillAtJournaledName := state.repos[key]
	state.mu.Unlock()
	if movedBack || stillAtJournaledName.ID != 999 || !stillAtJournaledName.Archived {
		t.Fatalf("identity-mismatched repository was mutated: movedBack=%v repo=%+v", movedBack, stillAtJournaledName)
	}
	mapping, err := st.GetMapping(t.Context(), original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if !mapping.Migrating || mapping.Owner != tenant.OrgName || mapping.RepoName != original.RepoName {
		t.Fatalf("identity mismatch mapping=%+v", mapping)
	}
	if journals, err := st.ListRepoMigrations(t.Context()); err != nil || len(journals) != 1 {
		t.Fatalf("identity mismatch journal=%+v err=%v", journals, err)
	}
}

func TestMigrationDeferredRollbackIgnoresRequestCancellation(t *testing.T) {
	svc, st, state, tenant, original, _ := seedExistingMigrationRepo(t)
	ctx, cancel := context.WithCancel(t.Context())
	injected := errors.New("injected post-transfer failure")
	svc.migrationStepHook = func(step string) error {
		if step == store.MigrationStepTransferred {
			cancel()
			return injected
		}
		return nil
	}
	if _, err := svc.MigrateExisting(ctx, tenant.Host, original.Npub, original.RepoID); !errors.Is(err, injected) {
		t.Fatalf("migration error=%v", err)
	}
	assertMigrationRolledBack(t, svc, st, state, original)
}

func assertMigrationRolledBack(t *testing.T, svc *Service, st *store.SQLiteStore, state *testGiteaServer, original store.Mapping) {
	t.Helper()
	got, err := st.GetMapping(t.Context(), original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != original.Owner || got.RepoName != original.RepoName || got.TenantHost != "" || got.Migrating || !got.HookInstalled || got.GiteaRepoID != original.GiteaRepoID {
		t.Fatalf("rollback mapping=%+v", got)
	}
	if err := svc.installer.VerifyAt(original.Owner, original.RepoName, original.Npub, original.RepoID); err != nil {
		t.Fatalf("restored hook: %v", err)
	}
	state.mu.Lock()
	repo, ok := state.repos[original.Owner+"/"+original.RepoName]
	state.mu.Unlock()
	if !ok || repo.ID != original.GiteaRepoID {
		t.Fatalf("original repository not restored: %+v ok=%v", repo, ok)
	}
	journals, err := st.ListRepoMigrations(t.Context())
	if err != nil || len(journals) != 0 {
		t.Fatalf("journal not cleared after rollback: %+v err=%v", journals, err)
	}
}

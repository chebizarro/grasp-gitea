package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/store"
)

var ErrMigrationPreflight = errors.New("repository migration preflight failed")
var errMigrationCrashTest = errors.New("simulated migration process crash")

const migrationRollbackTimeout = 30 * time.Second

// MigrateExisting moves one existing per-pubkey repository into an active,
// placement-enabled tenant. The admin call is the operator opt-in; the cached,
// owner-signed announcement's exact tenant tag is the independent owner opt-in.
func (s *Service) MigrateExisting(ctx context.Context, host, npub, repoID string) (store.Mapping, error) {
	host, npub, repoID = strings.TrimSpace(host), strings.TrimSpace(npub), strings.TrimSpace(repoID)
	if host == "" || npub == "" || repoID == "" {
		return store.Mapping{}, fmt.Errorf("%w: tenant host, npub, and repo_id are required", ErrMigrationPreflight)
	}
	if s.tenantPlacement == nil || s.authStore == nil || s.gitea == nil || s.installer == nil {
		return store.Mapping{}, fmt.Errorf("%w: migration dependencies are not configured", ErrMigrationPreflight)
	}

	var result store.Mapping
	eligible, err := s.tenantPlacement.WithPlacement(ctx, host, func(lockedCtx context.Context, tenant store.ManagedTenant) error {
		var migrateErr error
		result, migrateErr = s.migrateExistingLocked(lockedCtx, tenant, npub, repoID)
		return migrateErr
	})
	if err != nil {
		return store.Mapping{}, err
	}
	if !eligible {
		return store.Mapping{}, fmt.Errorf("%w: tenant is not active, current, healthy, and placement-enabled", ErrMigrationPreflight)
	}
	return result, nil
}

func (s *Service) migrateExistingLocked(ctx context.Context, tenant store.ManagedTenant, npub, repoID string) (_ store.Mapping, retErr error) {
	mapping, err := s.store.GetMapping(ctx, npub, repoID)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("%w: mapping lookup: %v", ErrMigrationPreflight, err)
	}
	if mapping.TenantHost != "" || mapping.Migrating || !mapping.HookInstalled || mapping.Owner == "" || mapping.RepoName == "" || mapping.GiteaRepoID <= 0 {
		return store.Mapping{}, fmt.Errorf("%w: mapping is not a healthy unmigrated repository", ErrMigrationPreflight)
	}
	if err := ownerConsentedToTenant(mapping, tenant.Host); err != nil {
		return store.Mapping{}, fmt.Errorf("%w: %v", ErrMigrationPreflight, err)
	}

	relayURLs := s.cfg.RelayURLs
	if s.policy != nil {
		if snapshot := s.policy.Current(); snapshot != nil {
			relayURLs = snapshot.RelayURLs
		}
	}
	collaborator, authorized := s.authorizeTenantPlacement(ctx, mapping.Pubkey, tenant, relayURLs)
	if !authorized || collaborator == "" {
		return store.Mapping{}, fmt.Errorf("%w: owner lacks fresh exact-host affiliation, SCIM authorization, or a linked Gitea user", ErrMigrationPreflight)
	}
	live, err := s.gitea.GetRepo(ctx, mapping.Owner, mapping.RepoName)
	if err != nil || live.ID != mapping.GiteaRepoID || live.Archived {
		return store.Mapping{}, fmt.Errorf("%w: mapped repository identity is unhealthy or already archived", ErrMigrationPreflight)
	}
	if err := s.installer.VerifyAt(mapping.Owner, mapping.RepoName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("%w: pre-receive hook verification: %v", ErrMigrationPreflight, err)
	}
	newName := tenantRepoName(mapping.RepoID, mapping.Pubkey)
	if _, err := s.gitea.GetRepo(ctx, tenant.OrgName, newName); err == nil || !gitea.IsNotFound(err) {
		return store.Mapping{}, fmt.Errorf("%w: target repository name is not verifiably free", ErrMigrationPreflight)
	}

	now := time.Now().UTC()
	journal := store.RepoMigration{
		Npub: mapping.Npub, RepoID: mapping.RepoID, Pubkey: mapping.Pubkey, TenantHost: tenant.Host,
		OldOwner: mapping.Owner, OldRepoName: mapping.RepoName, NewOwner: tenant.OrgName, NewRepoName: newName,
		GiteaRepoID: mapping.GiteaRepoID, Collaborator: collaborator, Step: store.MigrationStepPrepared,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.authStore.CreateRepoMigration(ctx, journal); err != nil {
		return store.Mapping{}, fmt.Errorf("create migration journal: %w", err)
	}
	journalCreated := true
	defer func() {
		if retErr == nil || !journalCreated || errors.Is(retErr, errMigrationCrashTest) {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationRollbackTimeout)
		defer cancel()
		if rollbackErr := s.rollbackMigrationLocked(rollbackCtx, journal); rollbackErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("migration rollback failed: %w", rollbackErr))
		}
	}()
	if err := s.afterMigrationStep(store.MigrationStepPrepared); err != nil {
		return store.Mapping{}, err
	}

	if err := s.store.SetMappingMigrating(ctx, mapping.Npub, mapping.RepoID, true); err != nil {
		return store.Mapping{}, fmt.Errorf("quiesce mapping: %w", err)
	}
	// Gitea's archived state is the outer write barrier: it rejects new direct
	// and proxied pushes before we drain any receive that started earlier.
	if err := s.gitea.SetRepoArchived(ctx, mapping.Owner, mapping.RepoName, true); err != nil {
		return store.Mapping{}, fmt.Errorf("enable Gitea migration write barrier: %w", err)
	}
	if archived, err := s.gitea.GetRepo(ctx, mapping.Owner, mapping.RepoName); err != nil || !archived.Archived || archived.ID != mapping.GiteaRepoID {
		return store.Mapping{}, fmt.Errorf("verify Gitea migration write barrier: archived=%v err=%v", archived.Archived, err)
	}
	if err := s.installer.QuiesceAt(mapping.Owner, mapping.RepoName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("quiesce repository hook: %w", err)
	}
	if err := s.installer.CheckQuiescentAt(mapping.Owner, mapping.RepoName); err != nil {
		return store.Mapping{}, fmt.Errorf("repository is mid-push: %w", err)
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepQuiesced); err != nil {
		return store.Mapping{}, err
	}

	transferred, err := s.gitea.TransferRepo(ctx, mapping.Owner, mapping.RepoName, tenant.OrgName)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("transfer repository ownership: %w", err)
	}
	live, err = s.gitea.GetRepo(ctx, tenant.OrgName, mapping.RepoName)
	if err != nil || live.ID != mapping.GiteaRepoID || transferred.ID != mapping.GiteaRepoID {
		return store.Mapping{}, fmt.Errorf("transferred repository id changed: response=%d live=%d expected=%d", transferred.ID, live.ID, mapping.GiteaRepoID)
	}
	transferredCloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, tenant.OrgName, mapping.RepoName)
	if err := s.store.UpdateMappingPhysical(ctx, mapping.Npub, mapping.RepoID, tenant.OrgName, mapping.RepoName, "", transferredCloneURL, true); err != nil {
		return store.Mapping{}, fmt.Errorf("update transferred mapping path: %w", err)
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepTransferred); err != nil {
		return store.Mapping{}, err
	}

	renamed, err := s.gitea.RenameRepo(ctx, tenant.OrgName, mapping.RepoName, newName)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("rename migrated repository: %w", err)
	}
	live, err = s.gitea.GetRepo(ctx, tenant.OrgName, newName)
	if err != nil || live.ID != mapping.GiteaRepoID || renamed.ID != mapping.GiteaRepoID {
		return store.Mapping{}, fmt.Errorf("renamed repository id changed: response=%d live=%d expected=%d", renamed.ID, live.ID, mapping.GiteaRepoID)
	}

	cloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, tenant.OrgName, newName)
	if err := s.store.UpdateMappingPhysical(ctx, mapping.Npub, mapping.RepoID, tenant.OrgName, newName, tenant.Host, cloneURL, true); err != nil {
		return store.Mapping{}, fmt.Errorf("update migrated mapping: %w", err)
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepRenamed); err != nil {
		return store.Mapping{}, err
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepMappingUpdated); err != nil {
		return store.Mapping{}, err
	}
	if err := s.installer.InstallAt(tenant.OrgName, newName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("reinstall migrated hook: %w", err)
	}
	if err := s.installer.VerifyMigrationAt(tenant.OrgName, newName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("verify migrated hook: %w", err)
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepHookVerified); err != nil {
		return store.Mapping{}, err
	}
	if err := s.gitea.AddOrUpdateCollaborator(ctx, tenant.OrgName, newName, collaborator, "write"); err != nil {
		return store.Mapping{}, fmt.Errorf("grant owner collaborator write: %w", err)
	}
	permission, err := s.gitea.GetCollaboratorPermission(ctx, tenant.OrgName, newName, collaborator)
	if err != nil || (permission != "write" && permission != "admin") {
		return store.Mapping{}, fmt.Errorf("verify owner collaborator write: permission=%q err=%v", permission, err)
	}
	if err := s.advanceMigration(ctx, journal, store.MigrationStepCollaboratorReady); err != nil {
		return store.Mapping{}, err
	}
	if err := s.gitea.SetRepoArchived(ctx, tenant.OrgName, newName, false); err != nil {
		return store.Mapping{}, fmt.Errorf("disable Gitea migration write barrier: %w", err)
	}
	if ready, err := s.gitea.GetRepo(ctx, tenant.OrgName, newName); err != nil || ready.Archived || ready.ID != mapping.GiteaRepoID {
		return store.Mapping{}, fmt.Errorf("verify migrated repository writable state: archived=%v err=%v", ready.Archived, err)
	}
	if err := s.installer.UnquiesceAt(tenant.OrgName, newName); err != nil {
		return store.Mapping{}, fmt.Errorf("unquiesce migrated repository: %w", err)
	}
	if err := s.store.SetMappingMigrating(ctx, mapping.Npub, mapping.RepoID, false); err != nil {
		return store.Mapping{}, fmt.Errorf("unquiesce migrated mapping: %w", err)
	}
	if err := s.authStore.DeleteRepoMigration(ctx, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("complete migration journal: %w", err)
	}
	journalCreated = false
	return s.store.GetMapping(ctx, mapping.Npub, mapping.RepoID)
}

func ownerConsentedToTenant(mapping store.Mapping, host string) error {
	if strings.TrimSpace(mapping.AnnouncementEventJSON) == "" {
		return errors.New("owner-signed announcement with a tenant tag is required")
	}
	var event nostr.Event
	if err := json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &event); err != nil {
		return fmt.Errorf("decode owner announcement: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(&event); err != nil {
		return fmt.Errorf("verify owner announcement: %w", err)
	}
	if event.PubKey.Hex() != strings.ToLower(mapping.Pubkey) || tenantPlacementIntent(event.Tags) != host {
		return errors.New("owner announcement does not request this exact tenant")
	}
	return nil
}

func (s *Service) advanceMigration(ctx context.Context, migration store.RepoMigration, step string) error {
	if err := s.authStore.UpdateRepoMigrationStep(ctx, migration.Npub, migration.RepoID, step, time.Now().UTC()); err != nil {
		return fmt.Errorf("advance migration journal to %s: %w", step, err)
	}
	return s.afterMigrationStep(step)
}

func (s *Service) afterMigrationStep(step string) error {
	if s.migrationStepHook != nil {
		return s.migrationStepHook(step)
	}
	return nil
}

// ReconcileMigrations rolls every incomplete journal back on startup. Recovery
// remains journaled and quiesced until the immutable repository identity,
// original mapping, and restored hook have all been verified.
func (s *Service) ReconcileMigrations(ctx context.Context) error {
	journals, err := s.authStore.ListRepoMigrations(ctx)
	if err != nil {
		return fmt.Errorf("list migration journals: %w", err)
	}
	var errs []error
	for _, journal := range journals {
		err := s.authStore.WithTenantLock(ctx, journal.TenantHost, func(lockedCtx context.Context) error {
			return s.rollbackMigrationLocked(lockedCtx, journal)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("recover migration %s/%s: %w", journal.Npub, journal.RepoID, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) rollbackMigrationLocked(ctx context.Context, journal store.RepoMigration) error {
	owner, name, err := s.locateMigrationRepo(ctx, journal)
	if err != nil {
		return err
	}

	// Establish every recovery barrier before mutating repository placement. If
	// any later restore step fails, the journal and these barriers remain.
	if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
		return err
	}
	if err := s.gitea.SetRepoArchived(ctx, owner, name, true); err != nil {
		return fmt.Errorf("archive repository for recovery: %w", err)
	}
	if repo, err := s.requireMigrationRepoState(ctx, owner, name, journal.GiteaRepoID); err != nil || !repo.Archived {
		return fmt.Errorf("verify recovery archive barrier: archived=%v err=%v", repo.Archived, err)
	}
	if err := s.store.SetMappingMigrating(ctx, journal.Npub, journal.RepoID, true); err != nil {
		return fmt.Errorf("restore mapping quiesce barrier: %w", err)
	}
	if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
		return err
	}
	if err := s.installer.QuiesceAt(owner, name, journal.Npub, journal.RepoID); err != nil {
		return fmt.Errorf("restore repository hook barrier: %w", err)
	}

	if owner != journal.OldOwner {
		if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
			return err
		}
		transferred, err := s.gitea.TransferRepo(ctx, owner, name, journal.OldOwner)
		if err != nil {
			return fmt.Errorf("transfer repository back: %w", err)
		}
		if transferred.ID != journal.GiteaRepoID {
			return fmt.Errorf("transfer-back repository id mismatch: got %d want %d", transferred.ID, journal.GiteaRepoID)
		}
		owner = journal.OldOwner
		if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
			return fmt.Errorf("verify transferred-back repository: %w", err)
		}
	}
	if name != journal.OldRepoName {
		if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
			return err
		}
		renamed, err := s.gitea.RenameRepo(ctx, owner, name, journal.OldRepoName)
		if err != nil {
			return fmt.Errorf("restore original repository name: %w", err)
		}
		if renamed.ID != journal.GiteaRepoID {
			return fmt.Errorf("rename-back repository id mismatch: got %d want %d", renamed.ID, journal.GiteaRepoID)
		}
		name = journal.OldRepoName
		if err := s.requireMigrationRepo(ctx, owner, name, journal.GiteaRepoID); err != nil {
			return fmt.Errorf("verify renamed-back repository: %w", err)
		}
	}

	cloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, journal.OldOwner, journal.OldRepoName)
	if err := s.store.UpdateMappingPhysical(ctx, journal.Npub, journal.RepoID, journal.OldOwner, journal.OldRepoName, "", cloneURL, false); err != nil {
		return fmt.Errorf("restore mapping: %w", err)
	}
	if err := s.requireMigrationRepo(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil {
		return err
	}
	if err := s.installer.InstallAt(journal.OldOwner, journal.OldRepoName, journal.Npub, journal.RepoID); err != nil {
		return fmt.Errorf("restore hook: %w", err)
	}
	if err := s.installer.VerifyAt(journal.OldOwner, journal.OldRepoName, journal.Npub, journal.RepoID); err != nil {
		return fmt.Errorf("verify restored hook: %w", err)
	}
	if err := s.store.SetHookInstalled(ctx, journal.Npub, journal.RepoID, true); err != nil {
		return fmt.Errorf("record verified restored hook: %w", err)
	}
	if err := s.verifyMigrationRestore(ctx, journal); err != nil {
		return err
	}

	// Only a fully verified original repository, mapping, and hook may have its
	// recovery barriers removed. Any cleanup failure re-establishes them.
	if err := s.requireMigrationRepo(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil {
		return err
	}
	if err := s.installer.UnquiesceAt(journal.OldOwner, journal.OldRepoName); err != nil {
		return fmt.Errorf("remove migration marker: %w", err)
	}
	if err := s.requireMigrationRepo(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil {
		return s.reestablishMigrationBarriers(ctx, journal, err)
	}
	if err := s.gitea.SetRepoArchived(ctx, journal.OldOwner, journal.OldRepoName, false); err != nil {
		return s.reestablishMigrationBarriers(ctx, journal, fmt.Errorf("clear Gitea write barrier: %w", err))
	}
	if ready, err := s.requireMigrationRepoState(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil || ready.Archived {
		return s.reestablishMigrationBarriers(ctx, journal, fmt.Errorf("verify cleared Gitea write barrier: archived=%v err=%v", ready.Archived, err))
	}
	if err := s.store.SetMappingMigrating(ctx, journal.Npub, journal.RepoID, false); err != nil {
		return s.reestablishMigrationBarriers(ctx, journal, fmt.Errorf("clear mapping quiesce: %w", err))
	}
	if err := s.authStore.DeleteRepoMigration(ctx, journal.Npub, journal.RepoID); err != nil {
		return s.reestablishMigrationBarriers(ctx, journal, fmt.Errorf("complete migration journal: %w", err))
	}
	return nil
}

func (s *Service) locateMigrationRepo(ctx context.Context, journal store.RepoMigration) (string, string, error) {
	paths := [][2]string{{journal.OldOwner, journal.OldRepoName}, {journal.NewOwner, journal.OldRepoName}, {journal.NewOwner, journal.NewRepoName}, {journal.OldOwner, journal.NewRepoName}}
	seen := make(map[[2]string]bool, len(paths))
	var found [2]string
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		repo, err := s.gitea.GetRepo(ctx, path[0], path[1])
		if gitea.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", "", fmt.Errorf("locate migrating repository at %s/%s: %w", path[0], path[1], err)
		}
		if repo.ID != journal.GiteaRepoID {
			return "", "", fmt.Errorf("migration repository identity mismatch at %s/%s: got %d want %d", path[0], path[1], repo.ID, journal.GiteaRepoID)
		}
		if found != [2]string{} {
			return "", "", fmt.Errorf("migration repository id %d exists at multiple journaled paths", journal.GiteaRepoID)
		}
		found = path
	}
	if found == [2]string{} {
		return "", "", errors.New("migrating repository not found at any journaled path")
	}
	return found[0], found[1], nil
}

func (s *Service) requireMigrationRepo(ctx context.Context, owner, name string, id int64) error {
	_, err := s.requireMigrationRepoState(ctx, owner, name, id)
	return err
}

func (s *Service) requireMigrationRepoState(ctx context.Context, owner, name string, id int64) (gitea.Repository, error) {
	repo, err := s.gitea.GetRepo(ctx, owner, name)
	if err != nil {
		return gitea.Repository{}, fmt.Errorf("verify migration repository %s/%s: %w", owner, name, err)
	}
	if repo.ID != id {
		return gitea.Repository{}, fmt.Errorf("migration repository identity mismatch at %s/%s: got %d want %d", owner, name, repo.ID, id)
	}
	return repo, nil
}

func (s *Service) verifyMigrationRestore(ctx context.Context, journal store.RepoMigration) error {
	repo, err := s.requireMigrationRepoState(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID)
	if err != nil {
		return err
	}
	if !repo.Archived {
		return errors.New("restored repository lost recovery archive barrier")
	}
	mapping, err := s.store.GetMapping(ctx, journal.Npub, journal.RepoID)
	if err != nil {
		return fmt.Errorf("verify restored mapping: %w", err)
	}
	if mapping.GiteaRepoID != journal.GiteaRepoID || mapping.Owner != journal.OldOwner || mapping.RepoName != journal.OldRepoName || mapping.TenantHost != "" || !mapping.Migrating || !mapping.HookInstalled {
		return fmt.Errorf("restored mapping failed verification: %+v", mapping)
	}
	if err := s.installer.VerifyAt(journal.OldOwner, journal.OldRepoName, journal.Npub, journal.RepoID); err != nil {
		return fmt.Errorf("verify restored hook: %w", err)
	}
	return nil
}

func (s *Service) reestablishMigrationBarriers(ctx context.Context, journal store.RepoMigration, cause error) error {
	var errs []error
	errs = append(errs, cause)
	if err := s.store.SetMappingMigrating(ctx, journal.Npub, journal.RepoID, true); err != nil {
		errs = append(errs, fmt.Errorf("re-establish mapping quiesce: %w", err))
	}
	if err := s.requireMigrationRepo(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	if err := s.gitea.SetRepoArchived(ctx, journal.OldOwner, journal.OldRepoName, true); err != nil {
		errs = append(errs, fmt.Errorf("re-establish Gitea archive barrier: %w", err))
	} else if repo, err := s.requireMigrationRepoState(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil || !repo.Archived {
		errs = append(errs, fmt.Errorf("verify re-established Gitea archive barrier: archived=%v err=%v", repo.Archived, err))
	}
	if err := s.requireMigrationRepo(ctx, journal.OldOwner, journal.OldRepoName, journal.GiteaRepoID); err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	if err := s.installer.QuiesceAt(journal.OldOwner, journal.OldRepoName, journal.Npub, journal.RepoID); err != nil {
		errs = append(errs, fmt.Errorf("re-establish repository hook barrier: %w", err))
	}
	return errors.Join(errs...)
}

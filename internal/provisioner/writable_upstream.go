package provisioner

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

var ErrWritableUpstreamPreflight = errors.New("writable-upstream migration preflight failed")
var safeUpstreamRepoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// MigrateWritableUpstream converts a mapping that points directly at a Gitea
// pull mirror into the dual-repository topology: the old pull mirror remains
// untouched, while a private imported sibling is verified, hooked, activated
// atomically, and only then made public and writable.
func (s *Service) MigrateWritableUpstream(ctx context.Context, npub, repoID string, expectedMirrorID int64, targetName string) (store.Mapping, error) {
	npub, repoID, targetName = strings.TrimSpace(npub), strings.TrimSpace(repoID), strings.TrimSpace(targetName)
	if npub == "" || repoID == "" || expectedMirrorID <= 0 || !safeUpstreamRepoName.MatchString(targetName) {
		return store.Mapping{}, fmt.Errorf("%w: npub, repo_id, expected mirror id, and a safe target name are required", ErrWritableUpstreamPreflight)
	}
	if s.store == nil || s.gitea == nil || s.installer == nil {
		return store.Mapping{}, fmt.Errorf("%w: migration dependencies are not configured", ErrWritableUpstreamPreflight)
	}
	unlock := s.lockRepo(npub, repoID)
	defer unlock.Unlock()
	mapping, err := s.store.GetMapping(ctx, npub, repoID)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("%w: mapping lookup: %v", ErrWritableUpstreamPreflight, err)
	}
	prepared, preparedErr := s.store.GetWritableUpstreamMigration(ctx, npub, repoID)
	if preparedErr == nil && prepared.Active {
		if mapping.GiteaRepoID != prepared.NewGiteaRepoID || prepared.OldGiteaRepoID != expectedMirrorID || prepared.NewRepoName != targetName {
			return store.Mapping{}, fmt.Errorf("%w: active migration does not match this request", ErrWritableUpstreamPreflight)
		}
		if err := s.activateWritableRepo(ctx, mapping.Owner, mapping.RepoName, mapping.GiteaRepoID); err != nil {
			return store.Mapping{}, err
		}
		return mapping, nil
	} else if preparedErr != nil && !errors.Is(preparedErr, sql.ErrNoRows) {
		return store.Mapping{}, preparedErr
	}
	if mapping.GiteaRepoID != expectedMirrorID || mapping.Migrating || !mapping.HookInstalled || mapping.Owner == "" || mapping.RepoName == "" {
		return store.Mapping{}, fmt.Errorf("%w: mapping revision or health does not match", ErrWritableUpstreamPreflight)
	}
	if targetName == mapping.RepoName {
		return store.Mapping{}, fmt.Errorf("%w: target must be a distinct sibling repository", ErrWritableUpstreamPreflight)
	}
	source, err := s.gitea.GetRepo(ctx, mapping.Owner, mapping.RepoName)
	if err != nil || source.ID != expectedMirrorID || !source.Mirror || !source.PubliclyReadable() {
		return store.Mapping{}, fmt.Errorf("%w: source must be the exact public pull mirror: %v", ErrWritableUpstreamPreflight, err)
	}

	target, targetErr := s.gitea.GetRepo(ctx, mapping.Owner, targetName)
	if preparedErr == nil {
		if prepared.OldGiteaRepoID != expectedMirrorID || prepared.OldOwner != mapping.Owner || prepared.OldRepoName != mapping.RepoName || prepared.NewOwner != mapping.Owner || prepared.NewRepoName != targetName {
			return store.Mapping{}, fmt.Errorf("%w: prepared migration does not match this request", ErrWritableUpstreamPreflight)
		}
		if !prepared.ExpectedMappingUpdatedAt.Equal(mapping.UpdatedAt) {
			return store.Mapping{}, fmt.Errorf("%w: mapping changed after migration preparation", ErrWritableUpstreamPreflight)
		}
	} else {
		if targetErr == nil {
			return store.Mapping{}, fmt.Errorf("%w: target repository already exists without a matching preparation record", ErrWritableUpstreamPreflight)
		}
		if !gitea.IsNotFound(targetErr) {
			return store.Mapping{}, fmt.Errorf("inspect writable upstream target: %w", targetErr)
		}
		marker, err := newWritableUpstreamMarker()
		if err != nil {
			return store.Mapping{}, fmt.Errorf("create writable-upstream marker: %w", err)
		}
		preparation := store.WritableUpstreamMigration{Npub: mapping.Npub, RepoID: mapping.RepoID, OldOwner: mapping.Owner, OldRepoName: mapping.RepoName, OldGiteaRepoID: mapping.GiteaRepoID, OldCloneURL: mapping.CloneURL, NewOwner: mapping.Owner, NewRepoName: targetName, TargetMarker: marker, ExpectedMappingUpdatedAt: mapping.UpdatedAt}
		if err := s.store.PrepareWritableUpstream(ctx, preparation); err != nil {
			return store.Mapping{}, fmt.Errorf("prepare writable-upstream migration: %w", err)
		}
		prepared = preparation
	}
	if gitea.IsNotFound(targetErr) {
		target, err = s.gitea.MigrateRepo(ctx, gitea.MigrateRepoRequest{CloneAddr: source.CloneURL, Owner: mapping.Owner, Name: targetName, Description: prepared.TargetMarker})
	} else {
		err = targetErr
	}
	if err != nil {
		return store.Mapping{}, fmt.Errorf("create or inspect writable upstream: %w", err)
	}
	if target.ID <= 0 || target.Mirror || target.Owner != mapping.Owner || target.Name != targetName || target.Description != prepared.TargetMarker {
		return store.Mapping{}, fmt.Errorf("%w: target identity or repository mode mismatch", ErrWritableUpstreamPreflight)
	}
	// Every pre-activation retry re-establishes both visibility barriers.
	if err := s.gitea.SetRepoPrivate(ctx, mapping.Owner, targetName, true); err != nil {
		return store.Mapping{}, fmt.Errorf("make target private: %w", err)
	}
	if err := s.gitea.SetRepoArchived(ctx, mapping.Owner, targetName, true); err != nil {
		return store.Mapping{}, fmt.Errorf("archive target during verification: %w", err)
	}
	if err := s.afterMigrationStep("writable_target_created"); err != nil {
		return store.Mapping{}, err
	}
	sourceRefs, err := s.gitea.ListGitRefs(ctx, mapping.Owner, mapping.RepoName)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("read source refs: %w", err)
	}
	targetRefs, err := s.gitea.ListGitRefs(ctx, mapping.Owner, targetName)
	if err != nil {
		return store.Mapping{}, fmt.Errorf("read target refs: %w", err)
	}
	if !equalRefs(sourceRefs, targetRefs) {
		return store.Mapping{}, fmt.Errorf("%w: imported refs do not exactly match the source mirror", ErrWritableUpstreamPreflight)
	}
	if err := s.installer.InstallAt(mapping.Owner, targetName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("install writable-upstream hook: %w", err)
	}
	if err := s.installer.VerifyAt(mapping.Owner, targetName, mapping.Npub, mapping.RepoID); err != nil {
		return store.Mapping{}, fmt.Errorf("verify writable-upstream hook: %w", err)
	}
	if err := s.afterMigrationStep("writable_hook_verified"); err != nil {
		return store.Mapping{}, err
	}
	newCloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, mapping.Owner, targetName)
	record := store.WritableUpstreamMigration{
		Npub: mapping.Npub, RepoID: mapping.RepoID,
		OldOwner: mapping.Owner, OldRepoName: mapping.RepoName, OldGiteaRepoID: mapping.GiteaRepoID, OldCloneURL: mapping.CloneURL,
		NewOwner: mapping.Owner, NewRepoName: targetName, NewGiteaRepoID: target.ID, NewCloneURL: newCloneURL,
		TargetMarker:             prepared.TargetMarker,
		ExpectedMappingUpdatedAt: prepared.ExpectedMappingUpdatedAt,
	}
	if err := s.store.ActivateWritableUpstream(ctx, record); err != nil {
		return store.Mapping{}, fmt.Errorf("activate writable-upstream mapping: %w", err)
	}
	if err := s.afterMigrationStep("writable_mapping_activated"); err != nil {
		return store.Mapping{}, err
	}
	if err := s.activateWritableRepo(ctx, mapping.Owner, targetName, target.ID); err != nil {
		return store.Mapping{}, err
	}
	return s.store.GetMapping(ctx, npub, repoID)
}

func newWritableUpstreamMarker() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "grasp-writable-upstream:" + hex.EncodeToString(raw[:]), nil
}

func (s *Service) activateWritableRepo(ctx context.Context, owner, name string, expectedID int64) error {
	if err := s.gitea.SetRepoArchived(ctx, owner, name, false); err != nil {
		return fmt.Errorf("unarchive writable upstream: %w", err)
	}
	if err := s.gitea.SetRepoPrivate(ctx, owner, name, false); err != nil {
		return fmt.Errorf("publish writable upstream: %w", err)
	}
	repo, err := s.gitea.GetRepo(ctx, owner, name)
	if err != nil || repo.ID != expectedID || repo.Mirror || repo.Archived || !repo.PubliclyReadable() {
		return fmt.Errorf("verify writable upstream activation: %+v: %w", repo, err)
	}
	return nil
}

func equalRefs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for ref, sha := range a {
		if b[ref] != sha {
			return false
		}
	}
	return true
}

// RollbackWritableUpstream restores the preserved pull-mirror mapping and
// makes the sibling private and archived. It never deletes either repository.
func (s *Service) RollbackWritableUpstream(ctx context.Context, npub, repoID string, expectedUpstreamID int64) (store.Mapping, error) {
	npub, repoID = strings.TrimSpace(npub), strings.TrimSpace(repoID)
	unlock := s.lockRepo(npub, repoID)
	defer unlock.Unlock()
	record, err := s.store.GetWritableUpstreamMigration(ctx, npub, repoID)
	if err != nil || record.NewGiteaRepoID != expectedUpstreamID {
		return store.Mapping{}, fmt.Errorf("%w: active migration mismatch: %v", ErrWritableUpstreamPreflight, err)
	}
	oldRepo, err := s.gitea.GetRepo(ctx, record.OldOwner, record.OldRepoName)
	if err != nil || oldRepo.ID != record.OldGiteaRepoID || !oldRepo.Mirror {
		return store.Mapping{}, fmt.Errorf("%w: preserved pull mirror is unavailable: %v", ErrWritableUpstreamPreflight, err)
	}
	if record.Active {
		if err := s.store.RollbackWritableUpstream(ctx, record.Npub, record.RepoID, expectedUpstreamID); err != nil {
			return store.Mapping{}, err
		}
	} else {
		mapping, err := s.store.GetMapping(ctx, record.Npub, record.RepoID)
		if err != nil || mapping.GiteaRepoID != record.OldGiteaRepoID || mapping.Owner != record.OldOwner || mapping.RepoName != record.OldRepoName {
			return store.Mapping{}, fmt.Errorf("%w: inactive rollback does not match the preserved mapping: %v", ErrWritableUpstreamPreflight, err)
		}
	}
	if err := s.gitea.SetRepoPrivate(ctx, record.NewOwner, record.NewRepoName, true); err != nil {
		return store.Mapping{}, fmt.Errorf("quarantine rolled-back upstream: %w", err)
	}
	if err := s.gitea.SetRepoArchived(ctx, record.NewOwner, record.NewRepoName, true); err != nil {
		return store.Mapping{}, fmt.Errorf("archive rolled-back upstream: %w", err)
	}
	return s.store.GetMapping(ctx, record.Npub, record.RepoID)
}

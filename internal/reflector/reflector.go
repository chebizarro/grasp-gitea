// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package reflector mirrors verified Nostr-originated NIP-34 collaboration
// events into the provisioned Gitea repository they reference.
package reflector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/echofp"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

var (
	validEventID = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	validSHA     = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)
)

type Store interface {
	EventProcessed(ctx context.Context, eventID string) (bool, error)
	MarkEventProcessed(ctx context.Context, eventID string, pubkey string, kind int) error
	GetProvisionedMappingByRepoAddr(ctx context.Context, pubkey string, repoID string) (store.Mapping, error)
	RecordReflectedEvent(ctx context.Context, ref store.ReflectedEvent) (bool, error)
	GetReflectedEvent(ctx context.Context, nostrEventID string) (store.ReflectedEvent, error)
	RecordPendingNostrRef(ctx context.Context, ref store.PendingNostrRef) error
}

type GiteaClient interface {
	CreateIssue(ctx context.Context, owner string, repo string, title string, body string) (gitea.Issue, error)
	CreateIssueComment(ctx context.Context, owner string, repo string, index int64, body string) (gitea.IssueComment, error)
	SetIssueState(ctx context.Context, owner string, repo string, index int64, state string) (gitea.Issue, error)
	CreatePullRequest(ctx context.Context, owner string, repo string, head string, base string, title string, body string) (gitea.PullRequest, error)
}

type PatchRejectionPublisher interface {
	PublishEvent(ctx context.Context, ev *nostr.Event) error
}

// Reflector reflects verified Nostr collaboration events into Gitea.
type Reflector struct {
	store                   Store
	gitea                   GiteaClient
	repositoriesDir         string
	logger                  *slog.Logger
	statusSyncEnabled       bool
	patchRejectionPublisher PatchRejectionPublisher
}

func New(st Store, g GiteaClient, repositoriesDir string, logger *slog.Logger) *Reflector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reflector{store: st, gitea: g, repositoriesDir: repositoriesDir, logger: logger}
}

func (r *Reflector) SetStatusSyncEnabled(enabled bool) {
	if r != nil {
		r.statusSyncEnabled = enabled
	}
}

func (r *Reflector) SetPatchRejectionPublisher(pub PatchRejectionPublisher) {
	if r != nil {
		r.patchRejectionPublisher = pub
	}
}

// HandleEvent verifies, scopes, deduplicates, and reflects a Nostr event. Events
// for unknown or not-yet-provisioned repositories are ignored without marking
// them processed so they can be handled after provisioning catches up.
func (r *Reflector) HandleEvent(ctx context.Context, ev *nostr.Event, relayURL string) error {
	if ev == nil || !isCollaborationKind(int(ev.Kind)) {
		return nil
	}
	if r == nil || r.store == nil || r.gitea == nil {
		return fmt.Errorf("reflector not configured")
	}

	processed, err := r.store.EventProcessed(ctx, ev.ID.Hex())
	if err != nil {
		return fmt.Errorf("check processed event: %w", err)
	}
	if processed {
		return nil
	}

	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return fmt.Errorf("collaboration event cryptographic validation failed: %w", err)
	}

	if _, err := r.store.GetReflectedEvent(ctx, ev.ID.Hex()); err == nil {
		return r.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind))
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check reflected event: %w", err)
	}

	mapping, ok, err := r.mappingForEvent(ctx, ev)
	if err != nil {
		return err
	}
	if !ok {
		r.logger.Debug("reflector: ignoring event for unknown repo", "event", ev.ID.Hex(), "kind", int(ev.Kind), "relay", relayURL)
		return nil
	}

	success := false
	switch ev.Kind {
	case relay.KindIssue:
		success, err = r.reflectIssue(ctx, mapping, ev)
	case relay.KindNIP22Comment:
		success, err = r.reflectComment(ctx, mapping, ev)
	case relay.KindStatusOpen, relay.KindStatusApplied, relay.KindStatusClosed, relay.KindStatusDraft:
		success, err = r.reflectIssueStatus(ctx, mapping, ev)
	case relay.KindPatch, relay.KindPROpen:
		success, err = r.reflectPatch(ctx, mapping, ev)
	case relay.KindPRUpdate:
		success, err = r.reflectPRUpdate(ctx, mapping, ev)
	}
	if err != nil {
		return err
	}
	if success {
		if err := r.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind)); err != nil {
			return fmt.Errorf("mark event processed: %w", err)
		}
	}
	return nil
}

func (r *Reflector) mappingForEvent(ctx context.Context, ev *nostr.Event) (store.Mapping, bool, error) {
	addr := tagValue(ev.Tags, "a")
	pubkey, repoID, ok := parseRepoAddr(addr)
	if !ok {
		return store.Mapping{}, false, nil
	}
	mapping, err := r.store.GetProvisionedMappingByRepoAddr(ctx, pubkey, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Mapping{}, false, nil
	}
	if err != nil {
		return store.Mapping{}, false, fmt.Errorf("lookup repo mapping for %s: %w", addr, err)
	}
	return mapping, true, nil
}

func (r *Reflector) reflectIssue(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	title := strings.TrimSpace(tagValue(ev.Tags, "subject"))
	if title == "" {
		title = fallbackTitle(ev)
	}
	issue, err := r.gitea.CreateIssue(ctx, mapping.Owner, mapping.RepoName, title, ev.Content)
	if err != nil {
		return false, fmt.Errorf("create Gitea issue: %w", err)
	}
	index := issue.Index
	if index == 0 {
		index = issue.Number
	}
	if index == 0 {
		return false, fmt.Errorf("create Gitea issue returned no index")
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID:    ev.ID.Hex(),
		GiteaRepoID:     mapping.GiteaRepoID,
		GiteaIndex:      index,
		Kind:            int(ev.Kind),
		EchoFingerprint: echofp.Issue(title, ev.Content),
	}); err != nil {
		return false, fmt.Errorf("record reflected issue: %w", err)
	}
	r.logger.Info("reflector: created Gitea issue from Nostr", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", index)
	return true, nil
}

func (r *Reflector) reflectComment(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	rootID := rootEventID(ev.Tags)
	if rootID == "" {
		return false, nil
	}
	root, err := r.store.GetReflectedEvent(ctx, rootID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup reflected comment root: %w", err)
	}
	if root.GiteaRepoID != mapping.GiteaRepoID || root.GiteaIndex == 0 {
		return false, nil
	}
	if _, err := r.gitea.CreateIssueComment(ctx, mapping.Owner, mapping.RepoName, root.GiteaIndex, ev.Content); err != nil {
		return false, fmt.Errorf("create Gitea issue comment: %w", err)
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID:    ev.ID.Hex(),
		GiteaRepoID:     mapping.GiteaRepoID,
		GiteaIndex:      root.GiteaIndex,
		Kind:            int(ev.Kind),
		EchoFingerprint: echofp.Comment(ev.Content),
	}); err != nil {
		return false, fmt.Errorf("record reflected comment: %w", err)
	}
	r.logger.Info("reflector: created Gitea comment from Nostr", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", root.GiteaIndex)
	return true, nil
}

func (r *Reflector) reflectIssueStatus(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	if !r.statusSyncEnabled {
		r.logger.Debug("reflector: NIP-34 status sync disabled", "event", ev.ID.Hex(), "kind", ev.Kind)
		return false, nil
	}
	rootID := rootEventID(ev.Tags)
	if rootID == "" {
		return false, nil
	}
	root, err := r.store.GetReflectedEvent(ctx, rootID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup reflected status root: %w", err)
	}
	if root.GiteaRepoID != mapping.GiteaRepoID || root.GiteaIndex == 0 || root.Kind != relay.KindIssue {
		return false, nil
	}
	state := "open"
	if ev.Kind == relay.KindStatusClosed || ev.Kind == relay.KindStatusApplied {
		state = "closed"
	}
	if _, err := r.gitea.SetIssueState(ctx, mapping.Owner, mapping.RepoName, root.GiteaIndex, state); err != nil {
		return false, fmt.Errorf("set Gitea issue state: %w", err)
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID:    ev.ID.Hex(),
		GiteaRepoID:     mapping.GiteaRepoID,
		GiteaIndex:      root.GiteaIndex,
		Kind:            int(ev.Kind),
		EchoFingerprint: echofp.IssueStatus(state),
	}); err != nil {
		return false, fmt.Errorf("record reflected status: %w", err)
	}
	r.logger.Info("reflector: updated Gitea issue state from Nostr", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", root.GiteaIndex, "state", state)
	return true, nil
}

func (r *Reflector) reflectPatch(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	tip := tagValue(ev.Tags, "c")
	if r.repositoriesDir == "" {
		r.logger.Info("reflector: repository directory unavailable; recording patch without PR creation", "event", ev.ID.Hex(), "tip", tip)
		return r.recordPatchOnly(ctx, mapping, ev, tip)
	}
	if !validEventID.MatchString(ev.ID.Hex()) {
		r.logger.Info("reflector: patch missing usable event id; recording without PR creation", "event", ev.ID.Hex(), "tip", tip)
		return r.recordPatchOnly(ctx, mapping, ev, tip)
	}

	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	branch := patchBranchNameForRepo(ctx, repoPath, ev)
	base, err := resolveBaseBranch(ctx, repoPath)
	if err != nil {
		r.logger.Warn("reflector: failed to resolve base branch for patch PR; recording only", "event", ev.ID.Hex(), "error", err)
		return r.recordPatchRejection(ctx, mapping, ev, tip, "resolve base branch failed: "+err.Error())
	}

	if validSHA.MatchString(tip) {
		if err := r.materializeTipBranch(ctx, mapping, ev, repoPath, tip, branch); err != nil {
			r.logger.Warn("reflector: failed to materialize patch tip; rejecting patch", "event", ev.ID.Hex(), "tip", tip, "error", err)
			return r.recordPatchRejection(ctx, mapping, ev, tip, "materialize patch tip failed: "+err.Error())
		}
	} else {
		if !looksLikeFormatPatch(ev.Content) {
			r.logger.Info("reflector: patch missing usable c-tip and content is not git format-patch; rejecting patch", "event", ev.ID.Hex(), "tip", tip)
			return r.recordPatchRejection(ctx, mapping, ev, "", "patch content is not a git format-patch and no usable c tip was provided")
		}
		if err := applyPatchContentBranch(ctx, repoPath, base, branch, ev.Content); err != nil {
			r.logger.Warn("reflector: failed to apply patch content; rejecting patch", "event", ev.ID.Hex(), "error", err)
			return r.recordPatchRejection(ctx, mapping, ev, "", "apply patch content failed: "+err.Error())
		}
	}

	title := patchTitle(ev)
	body := patchBody(ev)
	pr, err := r.gitea.CreatePullRequest(ctx, mapping.Owner, mapping.RepoName, branch, base, title, body)
	if err != nil {
		r.logger.Warn("reflector: failed to create Gitea PR for patch; rejecting patch", "event", ev.ID.Hex(), "branch", branch, "base", base, "error", err)
		return r.recordPatchRejection(ctx, mapping, ev, tip, "create pull request failed: "+err.Error())
	}
	index := pr.Index
	if index == 0 {
		index = pr.Number
	}
	if index == 0 {
		r.logger.Warn("reflector: created Gitea PR returned no index; rejecting patch", "event", ev.ID.Hex())
		return r.recordPatchRejection(ctx, mapping, ev, tip, "create pull request returned no index")
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID:    ev.ID.Hex(),
		GiteaRepoID:     mapping.GiteaRepoID,
		GiteaIndex:      index,
		HeadBranch:      branch,
		Kind:            relay.KindPROpen,
		EchoFingerprint: echofp.PROpen(title, body),
	}); err != nil {
		return false, fmt.Errorf("record reflected patch PR: %w", err)
	}
	r.logger.Info("reflector: created Gitea PR from Nostr patch", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", index, "head", branch, "base", base)
	return true, nil
}

func (r *Reflector) reflectPRUpdate(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	rootID := prUpdateRootEventID(ev.Tags)
	if rootID == "" {
		r.logger.Info("reflector: PR update missing root PR event tag", "event", ev.ID.Hex())
		return false, nil
	}
	root, err := r.store.GetReflectedEvent(ctx, rootID)
	if errors.Is(err, sql.ErrNoRows) {
		r.logger.Info("reflector: PR update root is not reflected yet", "event", ev.ID.Hex(), "root", rootID)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup reflected PR update root: %w", err)
	}
	if root.GiteaRepoID != mapping.GiteaRepoID || root.GiteaIndex == 0 || root.Kind != relay.KindPROpen || root.HeadBranch == "" {
		r.logger.Info("reflector: PR update root does not reference a reflected PR for this repo", "event", ev.ID.Hex(), "root", rootID, "root_repo", root.GiteaRepoID, "root_index", root.GiteaIndex, "root_kind", root.Kind, "head_branch", root.HeadBranch)
		return false, nil
	}
	if r.repositoriesDir == "" {
		r.logger.Warn("reflector: repository directory unavailable; cannot reflect PR update", "event", ev.ID.Hex(), "root", rootID)
		return false, nil
	}

	tip := tagValue(ev.Tags, "c")
	if !validSHA.MatchString(tip) {
		r.logger.Info("reflector: PR update missing usable c-tip", "event", ev.ID.Hex(), "tip", tip)
		return false, nil
	}
	clones := tagValues(ev.Tags, "clone")
	if len(clones) == 0 {
		r.logger.Info("reflector: PR update has no clone URLs", "event", ev.ID.Hex(), "tip", tip)
		return false, nil
	}

	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	refspec := "+" + tip + ":" + refsnostr.RefPrefix + ev.ID.Hex()
	var errs []string
	for _, cloneURL := range clones {
		if err := gitFetch(ctx, repoPath, cloneURL, refspec); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		// A PR update is a new revision of the existing PR branch. Rebased PRs are
		// expected to force-move this ref; Gitea observes the changed head on its
		// next branch synchronization.
		if err := updateBareRef(ctx, repoPath, "refs/heads/"+root.HeadBranch, tip); err != nil {
			r.logger.Warn("reflector: failed to update PR head branch for PR update", "event", ev.ID.Hex(), "root", rootID, "branch", root.HeadBranch, "tip", tip, "error", err)
			return false, nil
		}
		if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
			NostrEventID:    ev.ID.Hex(),
			GiteaRepoID:     mapping.GiteaRepoID,
			GiteaIndex:      root.GiteaIndex,
			HeadBranch:      root.HeadBranch,
			Kind:            relay.KindPRUpdate,
			EchoFingerprint: echofp.PRUpdate(tip),
		}); err != nil {
			return false, fmt.Errorf("record reflected PR update: %w", err)
		}
		r.logger.Info("reflector: updated Gitea PR head from Nostr PR update", "event", ev.ID.Hex(), "root", rootID, "repo", mapping.Owner+"/"+mapping.RepoName, "index", root.GiteaIndex, "head", root.HeadBranch, "tip", tip)
		return true, nil
	}
	if len(errs) > 0 {
		r.logger.Warn("reflector: failed to fetch PR update tip from clone URLs", "event", ev.ID.Hex(), "root", rootID, "tip", tip, "error", strings.Join(errs, "; "))
	}
	return false, nil
}

func (r *Reflector) materializeTipBranch(ctx context.Context, mapping store.Mapping, ev *nostr.Event, repoPath string, tip string, branch string) error {
	clones := tagValues(ev.Tags, "clone")
	if len(clones) == 0 {
		return fmt.Errorf("patch has no clone URLs")
	}
	refspec := "+" + tip + ":" + refsnostr.RefPrefix + ev.ID.Hex()
	var errs []string
	for _, cloneURL := range clones {
		if err := gitFetch(ctx, repoPath, cloneURL, refspec); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := updateBareRef(ctx, repoPath, "refs/heads/"+branch, tip); err != nil {
			return err
		}
		if err := r.store.RecordPendingNostrRef(ctx, store.PendingNostrRef{
			EventID:     ev.ID.Hex(),
			TipSHA:      tip,
			GiteaRepoID: mapping.GiteaRepoID,
			Owner:       mapping.Owner,
			RepoName:    mapping.RepoName,
			FirstSeenAt: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("record pending refs/nostr patch tip: %w", err)
		}
		return nil
	}
	return fmt.Errorf("fetch patch tip to refs/nostr failed: %s", strings.Join(errs, "; "))
}

func (r *Reflector) recordPatchRejection(ctx context.Context, mapping store.Mapping, ev *nostr.Event, tip string, reason string) (bool, error) {
	if err := r.publishPatchRejection(ctx, mapping, ev, reason); err != nil {
		return false, err
	}
	return r.recordPatchOnly(ctx, mapping, ev, tip)
}

func (r *Reflector) publishPatchRejection(ctx context.Context, mapping store.Mapping, ev *nostr.Event, reason string) error {
	if r.patchRejectionPublisher == nil {
		r.logger.Warn("reflector: patch rejection publisher unavailable", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "reason", reason)
		return nil
	}
	aTag := tagValue(ev.Tags, "a")
	if aTag == "" {
		aTag = fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	}
	payload := map[string]any{
		"schema_version": "grasp.patch_rejection.v1",
		"event_id":       ev.ID.Hex(),
		"event_kind":     int(ev.Kind),
		"repo":           mapping.Owner + "/" + mapping.RepoName,
		"repo_id":        mapping.RepoID,
		"reason":         reason,
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal patch rejection: %w", err)
	}
	rejection := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      relay.KindStatusClosed,
		Tags: nostr.Tags{
			{"a", aTag},
			{"e", ev.ID.Hex(), "", "root"},
			{"p", ev.PubKey.Hex()},
			{"K", fmt.Sprint(int(ev.Kind))},
			{"status", "rejected"},
			{"reason", reason},
		},
		Content: string(content),
	}
	if err := r.patchRejectionPublisher.PublishEvent(ctx, rejection); err != nil {
		return fmt.Errorf("publish patch rejection: %w", err)
	}
	r.logger.Info("reflector: published NIP-34 patch rejection", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "reason", reason)
	return nil
}

func (r *Reflector) recordPatchOnly(ctx context.Context, mapping store.Mapping, ev *nostr.Event, tip string) (bool, error) {
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID: ev.ID.Hex(),
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   0,
		Kind:         int(ev.Kind),
	}); err != nil {
		return false, fmt.Errorf("record reflected patch: %w", err)
	}
	r.logger.Info("reflector: recorded patch without PR creation", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "tip", tip)
	return true, nil
}

func gitFetch(ctx context.Context, repoPath string, remote string, refspec string) error {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "fetch", remote, refspec).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("git fetch %s %s: %w: %s", remote, refspec, err, msg)
		}
		return fmt.Errorf("git fetch %s %s: %w", remote, refspec, err)
	}
	return nil
}

func updateBareRef(ctx context.Context, repoPath string, ref string, value string) error {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", ref, value).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("git update-ref %s %s: %w: %s", ref, value, err, msg)
		}
		return fmt.Errorf("git update-ref %s %s: %w", ref, value, err)
	}
	return nil
}

func resolveBaseBranch(ctx context.Context, repoPath string) (string, error) {
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "--short", "HEAD").CombinedOutput(); err == nil {
		base := strings.TrimSpace(string(out))
		base = strings.TrimPrefix(base, "refs/heads/")
		if base != "" {
			return base, nil
		}
	}
	for _, candidate := range []string{"main", "master"} {
		if err := verifyBareCommit(ctx, repoPath, "refs/heads/"+candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no symbolic HEAD, main, or master branch in %s", repoPath)
}

func verifyBareCommit(ctx context.Context, repoPath string, rev string) error {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "rev-parse", "--verify", rev+"^{commit}").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("git rev-parse %s: %w: %s", rev, err, msg)
		}
		return fmt.Errorf("git rev-parse %s: %w", rev, err)
	}
	return nil
}

func applyPatchContentBranch(ctx context.Context, repoPath string, base string, branch string, content string) error {
	baseCommit, err := bareOutput(ctx, repoPath, "rev-parse", "--verify", "refs/heads/"+base+"^{commit}")
	if err != nil {
		return err
	}
	parent, err := os.MkdirTemp("", "grasp-nip34-patch-*")
	if err != nil {
		return fmt.Errorf("create patch temp dir: %w", err)
	}
	defer os.RemoveAll(parent)
	worktree := filepath.Join(parent, "worktree")
	patchPath := filepath.Join(parent, "patch.mbox")
	if err := os.WriteFile(patchPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write patch content: %w", err)
	}

	added := false
	defer func() {
		if added {
			_, _ = exec.CommandContext(context.Background(), "git", "-C", worktree, "am", "--abort").CombinedOutput()
			_, _ = exec.CommandContext(context.Background(), "git", "--git-dir", repoPath, "worktree", "remove", "--force", worktree).CombinedOutput()
		}
	}()

	if err := bareRun(ctx, repoPath, "worktree", "add", "--detach", worktree, strings.TrimSpace(baseCommit)); err != nil {
		return err
	}
	added = true
	if err := worktreeRun(ctx, worktree, "-c", "user.name=GRASP Bridge", "-c", "user.email=grasp-bridge@example.invalid", "am", patchPath); err != nil {
		return err
	}
	head, err := worktreeOutput(ctx, worktree, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	return updateBareRef(ctx, repoPath, "refs/heads/"+branch, strings.TrimSpace(head))
}

func bareRun(ctx context.Context, repoPath string, args ...string) error {
	_, err := bareOutput(ctx, repoPath, args...)
	return err
}

func bareOutput(ctx context.Context, repoPath string, args ...string) (string, error) {
	gitArgs := append([]string{"--git-dir", repoPath}, args...)
	out, err := exec.CommandContext(ctx, "git", gitArgs...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(gitArgs, " "), err, msg)
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(gitArgs, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func worktreeRun(ctx context.Context, worktree string, args ...string) error {
	_, err := worktreeOutput(ctx, worktree, args...)
	return err
}

func worktreeOutput(ctx context.Context, worktree string, args ...string) (string, error) {
	gitArgs := append([]string{"-C", worktree}, args...)
	out, err := exec.CommandContext(ctx, "git", gitArgs...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(gitArgs, " "), err, msg)
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(gitArgs, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func patchBranchNameForRepo(ctx context.Context, repoPath string, ev *nostr.Event) string {
	fallback := patchFallbackBranchName(ev)
	branch := sanitizeBranchName(tagValue(ev.Tags, "branch-name"))
	if branch == "" {
		return fallback
	}
	// Do not let an untrusted Nostr branch-name move an existing Gitea branch
	// such as main/master. Existing requested names fall back to the event-owned
	// deterministic branch; the fallback may already exist from a prior attempt.
	if branch != fallback && bareRefExists(ctx, repoPath, "refs/heads/"+branch) {
		return fallback
	}
	return branch
}

func patchFallbackBranchName(ev *nostr.Event) string {
	if ev != nil && len(ev.ID.Hex()) >= 12 {
		return "nostr-pr-" + ev.ID.Hex()[:12]
	}
	return "nostr-pr"
}

func bareRefExists(ctx context.Context, repoPath string, ref string) bool {
	return verifyBareCommit(ctx, repoPath, ref) == nil
}

func sanitizeBranchName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var b strings.Builder
	lastSlash := false
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '/'
		if !ok {
			r = '-'
		}
		if r == '/' {
			if lastSlash {
				continue
			}
			lastSlash = true
		} else {
			lastSlash = false
		}
		b.WriteRune(r)
	}
	name = strings.Trim(b.String(), "/. ")
	for strings.Contains(name, "..") || strings.Contains(name, "@{") {
		name = strings.ReplaceAll(name, "..", ".")
		name = strings.ReplaceAll(name, "@{", "-")
	}
	parts := strings.Split(name, "/")
	out := parts[:0]
	for _, part := range parts {
		part = strings.Trim(part, ". ")
		part = strings.TrimSuffix(part, ".lock")
		if part == "" || part == "." || part == ".." {
			continue
		}
		out = append(out, part)
	}
	name = strings.Join(out, "/")
	if name == "" || name == "HEAD" || strings.HasPrefix(name, "-") {
		return ""
	}
	return name
}

func patchTitle(ev *nostr.Event) string {
	title := strings.TrimSpace(tagValue(ev.Tags, "subject"))
	if title != "" {
		return title
	}
	line := strings.TrimSpace(ev.Content)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line != "" {
		if len(line) > 80 {
			return line[:80]
		}
		return line
	}
	if ev != nil && len(ev.ID.Hex()) >= 12 {
		return "Nostr PR " + ev.ID.Hex()[:12]
	}
	return "Nostr PR"
}

func patchBody(ev *nostr.Event) string {
	body := strings.TrimSpace(ev.Content)
	footer := "Reflected from Nostr event " + ev.ID.Hex() + "."
	if body == "" {
		return footer
	}
	return body + "\n\n---\n" + footer
}

func looksLikeFormatPatch(content string) bool {
	content = strings.TrimSpace(content)
	return strings.HasPrefix(content, "From ") && strings.Contains(content, "\ndiff --git ")
}

func isCollaborationKind(kind int) bool {
	switch kind {
	case relay.KindNIP22Comment,
		relay.KindPatch,
		relay.KindPROpen,
		relay.KindPRUpdate,
		relay.KindIssue,
		relay.KindStatusOpen,
		relay.KindStatusApplied,
		relay.KindStatusClosed,
		relay.KindStatusDraft:
		return true
	default:
		return false
	}
}

func parseRepoAddr(addr string) (pubkey string, repoID string, ok bool) {
	parts := strings.SplitN(addr, ":", 3)
	if len(parts) != 3 || parts[0] != fmt.Sprint(relay.KindRepositoryAnnouncement) || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func rootEventID(tags nostr.Tags) string {
	for _, key := range []string{"E", "e"} {
		for _, tag := range tags {
			if len(tag) < 2 || tag[0] != key {
				continue
			}
			if len(tag) >= 4 && tag[3] != "" && tag[3] != "root" {
				continue
			}
			return tag[1]
		}
	}
	return ""
}

func prUpdateRootEventID(tags nostr.Tags) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "E" {
			return tag[1]
		}
	}
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "e" && (len(tag) < 4 || tag[3] == "" || tag[3] == "root") {
			return tag[1]
		}
	}
	return ""
}

func fallbackTitle(ev *nostr.Event) string {
	line := strings.TrimSpace(ev.Content)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line != "" {
		if len(line) > 80 {
			return line[:80]
		}
		return line
	}
	if ev != nil && len(ev.ID.Hex()) >= 12 {
		return "Nostr issue " + ev.ID.Hex()[:12]
	}
	return "Nostr issue"
}

func tagValue(tags nostr.Tags, key string) string {
	v := tags.Find(key)
	if v == nil || len(v) < 2 {
		return ""
	}
	return v[1]
}

func tagValues(tags nostr.Tags, key string) []string {
	out := make([]string, 0)
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key && strings.TrimSpace(tag[1]) != "" {
			out = append(out, tag[1])
		}
	}
	return out
}

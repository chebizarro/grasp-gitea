// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package reflector mirrors verified Nostr-originated NIP-34 collaboration
// events into the provisioned Gitea repository they reference.
package reflector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"

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
}

// Reflector reflects verified Nostr collaboration events into Gitea.
type Reflector struct {
	store           Store
	gitea           GiteaClient
	repositoriesDir string
	logger          *slog.Logger
}

func New(st Store, g GiteaClient, repositoriesDir string, logger *slog.Logger) *Reflector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reflector{store: st, gitea: g, repositoriesDir: repositoriesDir, logger: logger}
}

// HandleEvent verifies, scopes, deduplicates, and reflects a Nostr event. Events
// for unknown or not-yet-provisioned repositories are ignored without marking
// them processed so they can be handled after provisioning catches up.
func (r *Reflector) HandleEvent(ctx context.Context, ev *nostr.Event, relayURL string) error {
	if ev == nil || !isCollaborationKind(ev.Kind) {
		return nil
	}
	if r == nil || r.store == nil || r.gitea == nil {
		return fmt.Errorf("reflector not configured")
	}

	processed, err := r.store.EventProcessed(ctx, ev.ID)
	if err != nil {
		return fmt.Errorf("check processed event: %w", err)
	}
	if processed {
		return nil
	}

	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return fmt.Errorf("collaboration event cryptographic validation failed: %w", err)
	}

	if _, err := r.store.GetReflectedEvent(ctx, ev.ID); err == nil {
		return r.store.MarkEventProcessed(ctx, ev.ID, ev.PubKey, ev.Kind)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check reflected event: %w", err)
	}

	mapping, ok, err := r.mappingForEvent(ctx, ev)
	if err != nil {
		return err
	}
	if !ok {
		r.logger.Debug("reflector: ignoring event for unknown repo", "event", ev.ID, "kind", ev.Kind, "relay", relayURL)
		return nil
	}

	success := false
	switch ev.Kind {
	case relay.KindIssue:
		success, err = r.reflectIssue(ctx, mapping, ev)
	case relay.KindNIP22Comment:
		success, err = r.reflectComment(ctx, mapping, ev)
	case relay.KindStatusOpen, relay.KindStatusClosed:
		success, err = r.reflectIssueStatus(ctx, mapping, ev)
	case relay.KindStatusApplied, relay.KindStatusDraft:
		r.logger.Info("reflector: status kind has no Phase F Gitea state action", "event", ev.ID, "kind", ev.Kind)
		success = true
	case relay.KindPatch:
		success, err = r.reflectPatchTip(ctx, mapping, ev)
	}
	if err != nil {
		return err
	}
	if success {
		if err := r.store.MarkEventProcessed(ctx, ev.ID, ev.PubKey, ev.Kind); err != nil {
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
		NostrEventID: ev.ID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   index,
		Kind:         ev.Kind,
	}); err != nil {
		return false, fmt.Errorf("record reflected issue: %w", err)
	}
	r.logger.Info("reflector: created Gitea issue from Nostr", "event", ev.ID, "repo", mapping.Owner+"/"+mapping.RepoName, "index", index)
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
		NostrEventID: ev.ID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   root.GiteaIndex,
		Kind:         ev.Kind,
	}); err != nil {
		return false, fmt.Errorf("record reflected comment: %w", err)
	}
	r.logger.Info("reflector: created Gitea comment from Nostr", "event", ev.ID, "repo", mapping.Owner+"/"+mapping.RepoName, "index", root.GiteaIndex)
	return true, nil
}

func (r *Reflector) reflectIssueStatus(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
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
	if ev.Kind == relay.KindStatusClosed {
		state = "closed"
	}
	if _, err := r.gitea.SetIssueState(ctx, mapping.Owner, mapping.RepoName, root.GiteaIndex, state); err != nil {
		return false, fmt.Errorf("set Gitea issue state: %w", err)
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID: ev.ID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   root.GiteaIndex,
		Kind:         ev.Kind,
	}); err != nil {
		return false, fmt.Errorf("record reflected status: %w", err)
	}
	r.logger.Info("reflector: updated Gitea issue state from Nostr", "event", ev.ID, "repo", mapping.Owner+"/"+mapping.RepoName, "index", root.GiteaIndex, "state", state)
	return true, nil
}

func (r *Reflector) reflectPatchTip(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	tip := tagValue(ev.Tags, "c")
	if !validEventID.MatchString(ev.ID) || !validSHA.MatchString(tip) {
		r.logger.Info("reflector: patch missing usable event id or c-tip; full patch apply is deferred", "event", ev.ID, "tip", tip)
		return r.recordPatchOnly(ctx, mapping, ev, "")
	}

	if r.repositoriesDir == "" {
		r.logger.Info("reflector: repository directory unavailable; recording patch without refs/nostr fetch", "event", ev.ID)
		return r.recordPatchOnly(ctx, mapping, ev, tip)
	}
	clones := tagValues(ev.Tags, "clone")
	if len(clones) == 0 {
		r.logger.Info("reflector: patch has no clone URLs; recording without refs/nostr fetch", "event", ev.ID)
		return r.recordPatchOnly(ctx, mapping, ev, tip)
	}

	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	refspec := "+" + tip + ":" + refsnostr.RefPrefix + ev.ID
	var errs []string
	for _, cloneURL := range clones {
		if err := gitFetch(ctx, repoPath, cloneURL, refspec); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := r.store.RecordPendingNostrRef(ctx, store.PendingNostrRef{
			EventID:     ev.ID,
			TipSHA:      tip,
			GiteaRepoID: mapping.GiteaRepoID,
			Owner:       mapping.Owner,
			RepoName:    mapping.RepoName,
			FirstSeenAt: time.Now().UTC(),
		}); err != nil {
			return false, fmt.Errorf("record pending refs/nostr patch tip: %w", err)
		}
		return r.recordPatchOnly(ctx, mapping, ev, tip)
	}
	return false, fmt.Errorf("fetch patch tip to refs/nostr failed: %s", strings.Join(errs, "; "))
}

func (r *Reflector) recordPatchOnly(ctx context.Context, mapping store.Mapping, ev *nostr.Event, tip string) (bool, error) {
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID: ev.ID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   0,
		Kind:         ev.Kind,
	}); err != nil {
		return false, fmt.Errorf("record reflected patch: %w", err)
	}
	r.logger.Info("reflector: recorded patch tip under refs/nostr when available; full patch apply/merge is deferred", "event", ev.ID, "repo", mapping.Owner+"/"+mapping.RepoName, "tip", tip)
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

func isCollaborationKind(kind int) bool {
	switch kind {
	case relay.KindNIP22Comment,
		relay.KindPatch,
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
	if ev != nil && len(ev.ID) >= 12 {
		return "Nostr issue " + ev.ID[:12]
	}
	return "Nostr issue"
}

func tagValue(tags nostr.Tags, key string) string {
	v := tags.GetFirst([]string{key, ""})
	if v == nil || len(*v) < 2 {
		return ""
	}
	return (*v)[1]
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

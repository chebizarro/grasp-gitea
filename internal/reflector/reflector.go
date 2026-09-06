// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package reflector mirrors verified Nostr-originated NIP-34 collaboration
// events into the provisioned Gitea repository they reference.
package reflector

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/echofp"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/nostrauthz"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/safefetch"
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
	GetMappingByGiteaRepoID(ctx context.Context, giteaRepoID int64) (store.Mapping, error)
	RecordReflectedEvent(ctx context.Context, ref store.ReflectedEvent) (bool, error)
	GetReflectedEvent(ctx context.Context, nostrEventID string) (store.ReflectedEvent, error)
	RecordPendingNostrRef(ctx context.Context, ref store.PendingNostrRef) error
	UpsertThreadRoot(ctx context.Context, root store.ThreadRoot) error
	GetThreadRoot(ctx context.Context, objectType string, giteaRepoID, giteaIndex int64) (store.ThreadRoot, error)
	GetThreadRootByEventID(ctx context.Context, eventID string) (store.ThreadRoot, error)
}

type GiteaClient interface {
	CreateIssue(ctx context.Context, owner string, repo string, title string, body string) (gitea.Issue, error)
	CreateIssueComment(ctx context.Context, owner string, repo string, index int64, body string) (gitea.IssueComment, error)
	SetIssueState(ctx context.Context, owner string, repo string, index int64, state string) (gitea.Issue, error)
	AddIssueLabel(ctx context.Context, owner string, repo string, index int64, label string) error
	RemoveIssueLabel(ctx context.Context, owner string, repo string, index int64, label string) error
	CreatePullRequest(ctx context.Context, owner string, repo string, head string, base string, title string, body string) (gitea.PullRequest, error)
	FindPullRequestsByHead(ctx context.Context, owner, repo, head string) ([]gitea.PullRequest, error)
	ListIssueComments(ctx context.Context, owner, repo string, index int64) ([]gitea.IssueComment, error)
}

type PatchRejectionPublisher interface {
	PublishEvent(ctx context.Context, ev *nostr.Event) error
}

// Reflector reflects verified Nostr collaboration events into Gitea.
type Reflector struct {
	store                   Store
	proposalStore           store.ProposalStore
	gitea                   GiteaClient
	repositoriesDir         string
	logger                  *slog.Logger
	statusSyncEnabled       bool
	patchRejectionPublisher PatchRejectionPublisher
	validateGitCloneURL     func(context.Context, string) error
	ownershipDiagnoser      func(repoPath string) string
	maxProposalPatchBytes   int
	giteaCreator            string
	submitterMu             sync.Mutex
	submitterActive         map[string]int
	maxPerSubmitter         int
}

func New(st Store, g GiteaClient, repositoriesDir string, logger *slog.Logger) *Reflector {
	if logger == nil {
		logger = slog.Default()
	}
	var proposals store.ProposalStore
	if candidate, ok := st.(store.ProposalStore); ok {
		proposals = candidate
	}
	return &Reflector{
		store:                 st,
		proposalStore:         proposals,
		gitea:                 g,
		repositoriesDir:       repositoriesDir,
		logger:                logger,
		validateGitCloneURL:   safefetch.ValidateGitCloneURL,
		maxProposalPatchBytes: 8 << 20,
		submitterActive:       make(map[string]int),
		maxPerSubmitter:       2,
	}
}

// SetProposalStore selects the durable proposal backend. Postgres-backed
// deployments use this to coordinate proposal identity across replicas.
func (r *Reflector) SetProposalStore(st store.ProposalStore) {
	if r != nil {
		r.proposalStore = st
	}
}

// SetOwnershipDiagnoser attaches current refs/objects ownership details to
// proposal materialization permission failures.
func (r *Reflector) SetProposalSecurityLimits(maxPatchBytes int, maxPerSubmitter int) {
	if r == nil {
		return
	}
	if maxPatchBytes > 0 {
		r.maxProposalPatchBytes = maxPatchBytes
	}
	if maxPerSubmitter > 0 {
		r.maxPerSubmitter = maxPerSubmitter
	}
}

func (r *Reflector) SetGiteaCreator(login string) {
	if r != nil {
		r.giteaCreator = strings.TrimSpace(login)
	}
}

func (r *Reflector) acquireProposalSubmitter(pubkey string) bool {
	r.submitterMu.Lock()
	defer r.submitterMu.Unlock()
	if r.submitterActive[pubkey] >= r.maxPerSubmitter {
		return false
	}
	r.submitterActive[pubkey]++
	return true
}

func (r *Reflector) releaseProposalSubmitter(pubkey string) {
	r.submitterMu.Lock()
	defer r.submitterMu.Unlock()
	r.submitterActive[pubkey]--
	if r.submitterActive[pubkey] <= 0 {
		delete(r.submitterActive, pubkey)
	}
}

// SetOwnershipDiagnoser attaches current refs/objects ownership details to
// proposal materialization permission failures.
func (r *Reflector) SetOwnershipDiagnoser(diagnose func(repoPath string) string) {
	if r != nil {
		r.ownershipDiagnoser = diagnose
	}
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

	if ev.Kind == relay.KindPatch && r.proposalStore != nil {
		failure, failureErr := r.proposalStore.GetProposalFailure(ctx, ev.ID.Hex())
		if failureErr == nil && !proposalFailureRetryable(failure.FailureClass) {
			return nil
		}
		if failureErr != nil && !errors.Is(failureErr, sql.ErrNoRows) {
			return fmt.Errorf("check terminal proposal event state: %w", failureErr)
		}
	}

	processed, err := r.store.EventProcessed(ctx, ev.ID.Hex())
	if err != nil {
		return fmt.Errorf("check processed event: %w", err)
	}
	if processed {
		return nil
	}

	if ev.Kind == relay.KindPatch {
		if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
			return fmt.Errorf("collaboration event cryptographic validation failed: %w", err)
		}
		mapping, ok, err := r.mappingForEvent(ctx, ev)
		if err != nil {
			return err
		}
		if !ok {
			r.logger.Debug("reflector: ignoring proposal for unknown repo", "event", ev.ID.Hex(), "repo_addr", tagValue(ev.Tags, "a"), "failure_class", "missing-mapping", "relay", relayURL)
			return nil
		}
		if !r.acquireProposalSubmitter(ev.PubKey.Hex()) {
			return r.proposalFailure(ctx, mapping, proposalRepositoryAddress(mapping), proposalRootReference(ev), ev, "submitter-rate-limit", fmt.Errorf("proposal submitter concurrency limit exceeded"))
		}
		defer r.releaseProposalSubmitter(ev.PubKey.Hex())
		success, err := r.reflectProposal(ctx, mapping, ev)
		if err != nil {
			var materializationErr *MaterializationError
			if errors.As(err, &materializationErr) && !materializationErr.Retryable {
				if markErr := r.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind)); markErr != nil {
					return fmt.Errorf("%w; mark terminal proposal failure: %v", err, markErr)
				}
			}
			return err
		}
		if success {
			if err := r.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind)); err != nil {
				return fmt.Errorf("mark event processed: %w", err)
			}
		}
		return nil
	}

	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return fmt.Errorf("collaboration event cryptographic validation failed: %w", err)
	}

	if reflected, err := r.store.GetReflectedEvent(ctx, ev.ID.Hex()); err == nil {
		if reflected.GiteaIndex > 0 && (reflected.Kind == relay.KindIssue || reflected.Kind == relay.KindPROpen) {
			objectType := "issue"
			if reflected.Kind == relay.KindPROpen {
				objectType = "pr"
			}
			if _, rootErr := r.store.GetThreadRootByEventID(ctx, ev.ID.Hex()); errors.Is(rootErr, sql.ErrNoRows) {
				if rootErr := r.store.UpsertThreadRoot(ctx, store.ThreadRoot{
					ObjectType: objectType, GiteaRepoID: reflected.GiteaRepoID, GiteaIndex: reflected.GiteaIndex,
					NostrEventID: ev.ID.Hex(), Pubkey: ev.PubKey.Hex(), Kind: reflected.Kind,
				}); rootErr != nil {
					return fmt.Errorf("repair reflected thread root: %w", rootErr)
				}
			} else if rootErr != nil {
				return fmt.Errorf("check reflected thread root: %w", rootErr)
			}
		}
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
		success, err = r.reflectIssueStatus(ctx, mapping, ev, relayURL)
	case relay.KindNIP32Label:
		success, err = r.reflectLabel(ctx, mapping, ev)
	case relay.KindPROpen:
		success, err = r.reflectPatch(ctx, mapping, ev)
	case relay.KindPRUpdate:
		success, err = r.reflectPRUpdate(ctx, mapping, ev)
	}
	if errors.Is(err, nostrauthz.ErrUnauthorized) {
		r.logger.Warn("reflector: rejected unauthorized issue status", "event", ev.ID.Hex(), "pubkey", ev.PubKey.Hex())
		return r.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind))
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
		if ev.Kind != relay.KindNIP22Comment && ev.Kind != relay.KindNIP32Label {
			return store.Mapping{}, false, nil
		}
		rootID := rootEventID(ev.Tags)
		if rootID == "" {
			return store.Mapping{}, false, nil
		}
		root, err := r.store.GetThreadRootByEventID(ctx, rootID)
		if errors.Is(err, sql.ErrNoRows) {
			return store.Mapping{}, false, nil
		}
		if err != nil {
			return store.Mapping{}, false, fmt.Errorf("lookup persisted thread root %s: %w", rootID, err)
		}
		mapping, err := r.store.GetMappingByGiteaRepoID(ctx, root.GiteaRepoID)
		if errors.Is(err, sql.ErrNoRows) {
			return store.Mapping{}, false, nil
		}
		if err != nil {
			return store.Mapping{}, false, fmt.Errorf("lookup mapping for persisted thread root %s: %w", rootID, err)
		}
		return mapping, true, nil
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
	if err := r.store.UpsertThreadRoot(ctx, store.ThreadRoot{
		ObjectType:   "issue",
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   index,
		NostrEventID: ev.ID.Hex(),
		Pubkey:       ev.PubKey.Hex(),
		Kind:         relay.KindIssue,
	}); err != nil {
		return false, fmt.Errorf("persist reflected issue thread root: %w", err)
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

func (r *Reflector) reflectIssueStatus(ctx context.Context, mapping store.Mapping, ev *nostr.Event, relayURL string) (bool, error) {
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

	authorized, err := r.issueStatusAuthorized(ctx, mapping, ev, rootID, relayURL)
	if err != nil {
		return false, err
	}
	if !authorized {
		return false, fmt.Errorf("%w: signer %s cannot update issue root %s", nostrauthz.ErrUnauthorized, ev.PubKey.Hex(), rootID)
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

func (r *Reflector) issueStatusAuthorized(ctx context.Context, mapping store.Mapping, ev *nostr.Event, rootID, relayURL string) (bool, error) {
	thread, err := r.store.GetThreadRootByEventID(ctx, rootID)
	if err == nil && thread.GiteaRepoID == mapping.GiteaRepoID && thread.Kind == relay.KindIssue && thread.Pubkey == ev.PubKey.Hex() {
		return true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("lookup issue root author: %w", err)
	}

	var ownerAnnouncement nostr.Event
	if strings.TrimSpace(mapping.AnnouncementEventJSON) == "" {
		return false, fmt.Errorf("%w: cached owner announcement missing", nostrauthz.ErrAuthorityUnavailable)
	}
	if err := json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &ownerAnnouncement); err != nil {
		return false, fmt.Errorf("%w: decode cached owner announcement: %v", nostrauthz.ErrAuthorityUnavailable, err)
	}
	coord := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	pool := []nostr.Event{ownerAnnouncement}
	authorized, err := nostrauthz.NewResolver(pool).IsAuthorized(ev.PubKey.Hex(), coord)
	if err != nil {
		return false, fmt.Errorf("resolve issue status authority: %w", err)
	}
	if authorized || strings.TrimSpace(relayURL) == "" {
		return authorized, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	source, err := nostr.RelayConnect(fetchCtx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return false, fmt.Errorf("%w: query maintainer announcements: %v", nostrauthz.ErrAuthorityUnavailable, err)
	}
	defer source.Close()
	sub, err := source.Subscribe(fetchCtx, nostr.Filter{
		Kinds: []nostr.Kind{nostr.KindRepositoryAnnouncement},
		Tags:  nostr.TagMap{"d": []string{mapping.RepoID}},
		Limit: 200,
	}, nostr.SubscriptionOptions{})
	if err != nil {
		return false, fmt.Errorf("%w: subscribe maintainer announcements: %v", nostrauthz.ErrAuthorityUnavailable, err)
	}
	for {
		select {
		case announcement, ok := <-sub.Events:
			if ok {
				pool = append(pool, announcement)
			}
		case <-sub.EndOfStoredEvents:
			authorized, err := nostrauthz.NewResolver(pool).IsAuthorized(ev.PubKey.Hex(), coord)
			if err != nil {
				return false, fmt.Errorf("resolve recursive issue status authority: %w", err)
			}
			return authorized, nil
		case <-fetchCtx.Done():
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, fmt.Errorf("%w: maintainer announcement query timed out", nostrauthz.ErrAuthorityUnavailable)
		}
	}
}

func (r *Reflector) reflectLabel(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	label := nip32GiteaLabel(ev.Tags)
	if label == "" {
		return false, nil
	}
	index, ok, err := r.labelTargetIndex(ctx, mapping, ev)
	if err != nil || !ok {
		return false, err
	}
	remove := isLabelRemoval(ev.Tags)
	if remove {
		if err := r.gitea.RemoveIssueLabel(ctx, mapping.Owner, mapping.RepoName, index, label); err != nil {
			return false, fmt.Errorf("remove Gitea issue label: %w", err)
		}
	} else {
		if err := r.gitea.AddIssueLabel(ctx, mapping.Owner, mapping.RepoName, index, label); err != nil {
			return false, fmt.Errorf("add Gitea issue label: %w", err)
		}
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID:    ev.ID.Hex(),
		GiteaRepoID:     mapping.GiteaRepoID,
		GiteaIndex:      index,
		Kind:            relay.KindNIP32Label,
		EchoFingerprint: labelEchoFingerprint(label, remove),
	}); err != nil {
		return false, fmt.Errorf("record reflected label: %w", err)
	}
	r.logger.Info("reflector: updated Gitea issue label from Nostr", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", index, "label", label, "remove", remove)
	return true, nil
}

func (r *Reflector) labelTargetIndex(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (int64, bool, error) {
	if rootID := rootEventID(ev.Tags); rootID != "" {
		root, err := r.store.GetThreadRootByEventID(ctx, rootID)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, fmt.Errorf("lookup label target root: %w", err)
		}
		if root.GiteaRepoID != mapping.GiteaRepoID || root.GiteaIndex <= 0 {
			return 0, false, nil
		}
		return root.GiteaIndex, true, nil
	}
	for _, target := range tagValues(ev.Tags, "r") {
		parts := strings.Split(strings.Trim(target, "/"), "/")
		if len(parts) < 2 || (parts[len(parts)-2] != "issue" && parts[len(parts)-2] != "pull" && parts[len(parts)-2] != "pr") {
			continue
		}
		index, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
		if err == nil && index > 0 {
			return index, true, nil
		}
	}
	return 0, false, nil
}

func nip32GiteaLabel(tags nostr.Tags) string {
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "l" || strings.TrimSpace(tag[1]) == "" {
			continue
		}
		if len(tag) >= 3 && tag[2] != "" && tag[2] != "gitea/label" {
			continue
		}
		return strings.TrimSpace(tag[1])
	}
	return ""
}

func isLabelRemoval(tags nostr.Tags) bool {
	switch strings.ToLower(strings.TrimSpace(tagValue(tags, "action"))) {
	case "remove", "removed", "unlabel", "unlabeled", "delete":
		return true
	default:
		return false
	}
}

func labelEchoFingerprint(label string, remove bool) string {
	action := "apply"
	if remove {
		action = "remove"
	}
	return action + "\x00" + strings.TrimSpace(label)
}

// MaterializationError is returned for actionable proposal failures.
type MaterializationError struct {
	FailureClass      string
	Operation         string
	RepositoryAddress string
	RootEventID       string
	LatestEventID     string
	RepoPath          string
	Retryable         bool
	Cause             error
}

func (e *MaterializationError) Error() string {
	return fmt.Sprintf("NIP-34 proposal materialization failed (%s) repo=%s root=%s event=%s: %v", e.FailureClass, e.RepositoryAddress, e.RootEventID, e.LatestEventID, e.Cause)
}
func (e *MaterializationError) Unwrap() error { return e.Cause }

func proposalFailureRetryable(class string) bool {
	return class == "missing-dependency" || class == "ref-write-fail" || class == "gitea-api-fail" || class == "persistence-fail" || class == "submitter-rate-limit"
}

func (r *Reflector) proposalFailure(ctx context.Context, mapping store.Mapping, addr, rootID string, ev *nostr.Event, class string, cause error) error {
	if addr == "" && mapping.Pubkey != "" {
		addr = fmt.Sprintf("30617:%s:%s", mapping.Pubkey, mapping.RepoID)
	}
	retryable := proposalFailureRetryable(class)
	repoPath := ""
	if mapping.Owner != "" && r.repositoriesDir != "" {
		repoPath = filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	}
	failure := store.ProposalFailure{RepositoryAddress: addr, RootEventID: rootID, EventID: ev.ID.Hex(), FailureClass: class, FailureDetail: cause.Error(), UpdatedAt: time.Now().UTC()}
	if r.proposalStore != nil {
		if err := r.proposalStore.RecordProposalFailure(ctx, failure); err != nil {
			cause = fmt.Errorf("%w; persist diagnostic: %v", cause, err)
		}
	}
	r.logger.Warn("reflector: NIP-34 proposal materialization failed", "repo_addr", addr, "repo_path", repoPath, "root_event_id", rootID, "latest_event_id", ev.ID.Hex(), "failure_class", class, "retryable", retryable, "error", cause)
	return &MaterializationError{FailureClass: class, Operation: class, RepositoryAddress: addr, RootEventID: rootID, LatestEventID: ev.ID.Hex(), RepoPath: repoPath, Retryable: retryable, Cause: cause}
}

func proposalReplyReference(ev *nostr.Event) string {
	if ev == nil {
		return ""
	}
	for _, tag := range ev.Tags {
		if len(tag) >= 4 && tag[0] == "e" && tag[3] == "reply" {
			return tag[1]
		}
	}
	return ""
}

func proposalRootReference(ev *nostr.Event) string {
	if ev == nil {
		return ""
	}
	if hasTagValue(ev.Tags, "t", "root-revision") {
		return proposalReplyReference(ev)
	}
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "t" && tag[1] == "root" {
			return ev.ID.Hex()
		}
	}
	for _, marker := range []string{"reply", "root", ""} {
		for _, tag := range ev.Tags {
			if len(tag) < 2 || tag[0] != "e" {
				continue
			}
			got := ""
			if len(tag) >= 4 {
				got = tag[3]
			}
			if got == marker {
				return tag[1]
			}
		}
	}
	return ""
}

func proposalRepositoryAddress(mapping store.Mapping) string {
	return fmt.Sprintf("30617:%s:%s", mapping.Pubkey, mapping.RepoID)
}

func proposalLinks(mapping store.Mapping, ev *nostr.Event) string {
	eventLink := ev.ID.Hex()
	if encoded := nip19.EncodeNevent(ev.ID, nil, ev.PubKey); encoded != "" {
		eventLink = "nostr:" + encoded
	}
	repoLink := proposalRepositoryAddress(mapping)
	if pk, err := nostr.PubKeyFromHex(mapping.Pubkey); err == nil {
		if encoded := nip19.EncodeNaddr(pk, nostr.Kind(relay.KindRepositoryAnnouncement), mapping.RepoID, nil); encoded != "" {
			repoLink = "nostr:" + encoded
		}
	}
	return fmt.Sprintf("[Nostr event](%s) (`%s`) · [repository](%s) (`%s`)", eventLink, ev.ID.Hex(), repoLink, proposalRepositoryAddress(mapping))
}

func newProposalRecoveryNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate proposal recovery nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func proposalBody(mapping store.Mapping, ev *nostr.Event, rootID, nonce string) string {
	body := strings.TrimSpace(ev.Content)
	footer := proposalLinks(mapping, ev) + "\n\n<!-- grasp:nip34-proposal-root:" + rootID + ":" + nonce + " -->"
	if body == "" {
		return footer
	}
	return body + "\n\n---\n" + footer
}

func proposalUpdateBody(mapping store.Mapping, ev *nostr.Event, tip string) string {
	subject := strings.TrimSpace(tagValue(ev.Tags, "subject"))
	if subject == "" {
		subject = "Applied NIP-34 proposal update"
	}
	return fmt.Sprintf("%s\n\nMaterialized head: `%s`\n\n%s\n\n<!-- grasp:nip34-proposal-event:%s -->", subject, tip, proposalLinks(mapping, ev), ev.ID.Hex())
}

func (r *Reflector) reflectProposal(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	addr := proposalRepositoryAddress(mapping)
	if r.proposalStore == nil {
		return false, r.proposalFailure(ctx, mapping, addr, ev.ID.Hex(), ev, "persistence-fail", fmt.Errorf("proposal store is not configured"))
	}
	rootID := proposalRootReference(ev)
	if rootID == "" {
		if hasTagValue(ev.Tags, "t", "root-revision") {
			return false, r.proposalFailure(ctx, mapping, addr, "", ev, "missing-dependency", fmt.Errorf("root revision has no proposal reference"))
		}
		rootID = ev.ID.Hex()
	} else if rootID != ev.ID.Hex() {
		current, err := r.proposalStore.GetProposalByEventID(ctx, rootID)
		if errors.Is(err, sql.ErrNoRows) {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "missing-dependency", fmt.Errorf("referenced proposal event %s has not been materialized", rootID))
		}
		if err != nil {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", err)
		}
		rootID = current.RootEventID
	}
	opCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var success bool
	err := r.proposalStore.WithProposalLock(opCtx, addr, rootID, func(lockCtx context.Context) error {
		var err error
		success, err = r.reflectProposalLocked(lockCtx, mapping, ev)
		return err
	})
	return success, err
}

func (r *Reflector) reflectProposalLocked(ctx context.Context, mapping store.Mapping, ev *nostr.Event) (bool, error) {
	addr := proposalRepositoryAddress(mapping)
	if r.maxProposalPatchBytes > 0 && len(ev.Content) > r.maxProposalPatchBytes {
		return false, r.proposalFailure(ctx, mapping, addr, proposalRootReference(ev), ev, "patch-decode-fail", fmt.Errorf("proposal patch is %d bytes; maximum is %d", len(ev.Content), r.maxProposalPatchBytes))
	}
	if r.proposalStore == nil {
		return false, r.proposalFailure(ctx, mapping, addr, ev.ID.Hex(), ev, "persistence-fail", fmt.Errorf("proposal store is not configured"))
	}
	if existing, err := r.proposalStore.GetProposalByEventID(ctx, ev.ID.Hex()); err == nil && existing.GiteaPRNumber > 0 && existing.LatestEventID != "" {
		if ev.ID.Hex() == existing.RootEventID {
			body := proposalBody(mapping, ev, existing.RootEventID, existing.RecoveryNonce)
			if _, recordErr := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{NostrEventID: ev.ID.Hex(), GiteaRepoID: existing.GiteaRepoID, GiteaIndex: existing.GiteaPRNumber, HeadBranch: existing.HeadBranch, Kind: relay.KindPROpen, EchoFingerprint: echofp.PROpen(patchTitle(ev), body)}); recordErr != nil {
				return false, recordErr
			}
			if rootErr := r.store.UpsertThreadRoot(ctx, store.ThreadRoot{ObjectType: "pr", GiteaRepoID: existing.GiteaRepoID, GiteaIndex: existing.GiteaPRNumber, NostrEventID: existing.RootEventID, Pubkey: ev.PubKey.Hex(), Kind: relay.KindPROpen}); rootErr != nil {
				return false, rootErr
			}
		} else {
			body := proposalUpdateBody(mapping, ev, existing.HeadRefSHA)
			comments, lookupErr := r.gitea.ListIssueComments(ctx, mapping.Owner, mapping.RepoName, existing.GiteaPRNumber)
			if lookupErr != nil {
				return false, r.proposalFailure(ctx, mapping, addr, existing.RootEventID, ev, "gitea-api-fail", lookupErr)
			}
			marker := "grasp:nip34-proposal-event:" + ev.ID.Hex()
			commented := false
			for _, comment := range comments {
				if strings.Contains(comment.Body, marker) {
					commented = true
					break
				}
			}
			if !commented {
				if _, commentErr := r.gitea.CreateIssueComment(ctx, mapping.Owner, mapping.RepoName, existing.GiteaPRNumber, body); commentErr != nil {
					return false, r.proposalFailure(ctx, mapping, addr, existing.RootEventID, ev, "gitea-api-fail", commentErr)
				}
			}
			if _, recordErr := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{NostrEventID: ev.ID.Hex(), GiteaRepoID: existing.GiteaRepoID, GiteaIndex: existing.GiteaPRNumber, HeadBranch: existing.HeadBranch, Kind: relay.KindNIP22Comment, EchoFingerprint: echofp.Comment(body)}); recordErr != nil {
				return false, recordErr
			}
		}
		return true, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, r.proposalFailure(ctx, mapping, addr, ev.ID.Hex(), ev, "persistence-fail", err)
	}

	rootID := proposalRootReference(ev)
	isRoot := rootID == "" || rootID == ev.ID.Hex()
	var current store.ProposalState
	if isRoot {
		rootID = ev.ID.Hex()
		var err error
		current, err = r.proposalStore.GetProposal(ctx, addr, rootID)
		if err == nil && current.GiteaPRNumber > 0 && current.LatestEventID != "" {
			return true, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", err)
		}
	} else {
		var err error
		current, err = r.proposalStore.GetProposalByEventID(ctx, rootID)
		if errors.Is(err, sql.ErrNoRows) {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "missing-dependency", fmt.Errorf("referenced proposal event %s has not been materialized", rootID))
		}
		if err != nil {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", err)
		}
		rootID = current.RootEventID
		for _, tag := range ev.Tags {
			if len(tag) < 2 || tag[0] != "e" || !validEventID.MatchString(tag[1]) {
				continue
			}
			linked, linkErr := r.proposalStore.GetProposalByEventID(ctx, tag[1])
			if errors.Is(linkErr, sql.ErrNoRows) {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "missing-dependency", fmt.Errorf("referenced proposal event %s has not been materialized", tag[1]))
			}
			if linkErr != nil {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", linkErr)
			}
			if linked.RootEventID != rootID || linked.RepositoryAddress != addr {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "invalid-thread", fmt.Errorf("proposal references resolve to conflicting threads"))
			}
		}
		if current.RepositoryAddress != addr || current.GiteaRepoID != mapping.GiteaRepoID {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "invalid-thread", fmt.Errorf("proposal reference belongs to another repository"))
		}
		if current.RootSubmitterPubkey == "" || ev.PubKey.Hex() != current.RootSubmitterPubkey {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "unauthorized-author", fmt.Errorf("proposal revision signer does not match root submitter"))
		}
		directReply := proposalReplyReference(ev) == current.LatestEventID
		if int64(ev.CreatedAt) < current.LatestCreatedAt || (!directReply && int64(ev.CreatedAt) == current.LatestCreatedAt && ev.ID.Hex() >= current.LatestEventID) {
			r.logger.Info("reflector: ignored stale NIP-34 proposal revision", "repo_addr", addr, "root_event_id", rootID, "latest_event_id", ev.ID.Hex())
			return true, nil
		}
	}
	if r.repositoriesDir == "" {
		return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "ref-write-fail", fmt.Errorf("repository directory unavailable"))
	}
	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	base := current.BaseBranch
	branch := current.HeadBranch
	if !isRoot && !hasTagValue(ev.Tags, "t", "root-revision") {
		base = current.HeadBranch
	}
	if isRoot {
		var err error
		if current.BaseBranch == "" {
			base, err = resolveBaseBranch(ctx, repoPath)
			if err != nil {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "ref-write-fail", err)
			}
			branch = "nostr-proposal-" + rootID
			nonce, nonceErr := newProposalRecoveryNonce()
			if nonceErr != nil {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", nonceErr)
			}
			candidate := store.ProposalState{
				RepositoryAddress: addr, RootEventID: rootID, GiteaRepoID: mapping.GiteaRepoID,
				RootSubmitterPubkey: ev.PubKey.Hex(), RecoveryNonce: nonce, GiteaCreator: r.giteaCreator,
				HeadBranch: branch, BaseBranch: base, LatestCreatedAt: -1, UpdatedAt: time.Now().UTC(),
			}
			reserved, _, reserveErr := r.proposalStore.ReserveProposal(ctx, candidate)
			if reserveErr != nil {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", reserveErr)
			}
			current = reserved
		} else {
			base = current.BaseBranch
			branch = current.HeadBranch
		}
		if current.RootSubmitterPubkey != ev.PubKey.Hex() || current.RecoveryNonce == "" || current.HeadBranch != branch || current.BaseBranch != base {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "materialization-conflict", fmt.Errorf("proposal reservation metadata does not match root event"))
		}
	}
	previousTip := current.HeadRefSHA
	tip, err := r.materializeProposalHead(ctx, mapping, ev, repoPath, base, branch)
	if err != nil {
		class := "patch-decode-fail"
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "parent-commit unavailable") {
			class = "missing-dependency"
		}
		if isPermissionError(err) || strings.Contains(message, "update-ref") || strings.Contains(message, "git fetch") || strings.Contains(message, "unsafe clone") || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			class = "ref-write-fail"
		}
		return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, class, err)
	}

	if isRoot {
		body := proposalBody(mapping, ev, rootID, current.RecoveryNonce)
		var pr gitea.PullRequest
		matches, lookupErr := r.gitea.FindPullRequestsByHead(ctx, mapping.Owner, mapping.RepoName, branch)
		if lookupErr != nil {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "gitea-api-fail", lookupErr)
		}
		marker := "<!-- grasp:nip34-proposal-root:" + rootID + ":" + current.RecoveryNonce + " -->"
		matchCount := 0
		for _, candidate := range matches {
			if current.GiteaCreator != "" && strings.Contains(candidate.Body, marker) && candidate.User.Login == current.GiteaCreator && candidate.Head.Ref == branch && candidate.Head.SHA == tip && candidate.Base.Ref == base {
				pr = candidate
				matchCount++
			}
		}
		if matchCount > 1 {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "materialization-conflict", fmt.Errorf("multiple pull requests match proposal root"))
		}
		if matchCount == 0 && len(matches) > 0 {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "materialization-conflict", fmt.Errorf("proposal branch is already attached to an unrelated pull request"))
		}
		createdPR := false
		if pr.ID == 0 && pr.Index == 0 && pr.Number == 0 {
			pr, err = r.gitea.CreatePullRequest(ctx, mapping.Owner, mapping.RepoName, branch, base, patchTitle(ev), body)
			if err != nil {
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "gitea-api-fail", err)
			}
			createdPR = true
		}
		index := pr.Index
		if index == 0 {
			index = pr.Number
		}
		if index == 0 {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "gitea-api-fail", fmt.Errorf("pull request response has no index"))
		}
		current.GiteaPRID = pr.ID
		current.GiteaPRNumber = index
		current.HeadRefSHA = tip
		current.LatestEventID = ev.ID.Hex()
		current.LatestCreatedAt = int64(ev.CreatedAt)
		current.UpdatedAt = time.Now().UTC()
		advanced, err := r.proposalStore.UpsertProposal(ctx, current)
		if err != nil {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", err)
		}
		if !advanced {
			persisted, readErr := r.proposalStore.GetProposal(ctx, addr, rootID)
			if readErr != nil || persisted.LatestEventID != ev.ID.Hex() || persisted.HeadRefSHA != tip || persisted.GiteaPRNumber != index {
				if createdPR {
					_, _ = r.gitea.SetIssueState(ctx, mapping.Owner, mapping.RepoName, index, "closed")
				}
				if readErr == nil && persisted.HeadRefSHA != "" {
					_ = updateBareRef(ctx, repoPath, "refs/heads/"+branch, persisted.HeadRefSHA)
				} else {
					_ = deleteBareRef(ctx, repoPath, "refs/heads/"+branch)
				}
				return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "materialization-conflict", fmt.Errorf("proposal state CAS lost after pull request creation"))
			}
			current = persisted
		}
		if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{NostrEventID: ev.ID.Hex(), GiteaRepoID: mapping.GiteaRepoID, GiteaIndex: index, HeadBranch: branch, Kind: relay.KindPROpen, EchoFingerprint: echofp.PROpen(patchTitle(ev), body)}); err != nil {
			return false, err
		}
		if err := r.store.UpsertThreadRoot(ctx, store.ThreadRoot{ObjectType: "pr", GiteaRepoID: mapping.GiteaRepoID, GiteaIndex: index, NostrEventID: rootID, Pubkey: ev.PubKey.Hex(), Kind: relay.KindPROpen}); err != nil {
			return false, err
		}
		r.logger.Info("reflector: materialized NIP-34 proposal as Gitea PR", "repo_addr", addr, "root_event_id", rootID, "latest_event_id", ev.ID.Hex(), "index", index, "head", branch)
		return true, nil
	}

	commentBody := proposalUpdateBody(mapping, ev, tip)
	current.HeadRefSHA = tip
	current.ParentEventID = proposalReplyReference(ev)
	current.LatestEventID = ev.ID.Hex()
	current.LatestCreatedAt = int64(ev.CreatedAt)
	current.UpdatedAt = time.Now().UTC()
	advanced, err := r.proposalStore.UpsertProposal(ctx, current)
	if err != nil {
		return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "persistence-fail", err)
	}
	if !advanced {
		persisted, readErr := r.proposalStore.GetProposal(ctx, addr, rootID)
		if readErr != nil || persisted.LatestEventID != ev.ID.Hex() || persisted.HeadRefSHA != tip {
			if readErr == nil && persisted.HeadRefSHA != "" {
				_ = updateBareRef(ctx, repoPath, "refs/heads/"+branch, persisted.HeadRefSHA)
			} else if previousTip != "" {
				_ = updateBareRef(ctx, repoPath, "refs/heads/"+branch, previousTip)
			}
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "materialization-conflict", fmt.Errorf("proposal state CAS lost after revision"))
		}
		current = persisted
	}
	commented := false
	comments, lookupErr := r.gitea.ListIssueComments(ctx, mapping.Owner, mapping.RepoName, current.GiteaPRNumber)
	if lookupErr != nil {
		return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "gitea-api-fail", lookupErr)
	}
	marker := "grasp:nip34-proposal-event:" + ev.ID.Hex()
	for _, comment := range comments {
		if strings.Contains(comment.Body, marker) {
			commented = true
			break
		}
	}
	if !commented {
		if _, err := r.gitea.CreateIssueComment(ctx, mapping.Owner, mapping.RepoName, current.GiteaPRNumber, commentBody); err != nil {
			return false, r.proposalFailure(ctx, mapping, addr, rootID, ev, "gitea-api-fail", err)
		}
	}
	if _, err := r.store.RecordReflectedEvent(ctx, store.ReflectedEvent{NostrEventID: ev.ID.Hex(), GiteaRepoID: mapping.GiteaRepoID, GiteaIndex: current.GiteaPRNumber, HeadBranch: current.HeadBranch, Kind: relay.KindNIP22Comment, EchoFingerprint: echofp.Comment(commentBody)}); err != nil {
		return false, err
	}
	r.logger.Info("reflector: updated Gitea PR from NIP-34 proposal revision", "repo_addr", addr, "root_event_id", rootID, "latest_event_id", ev.ID.Hex(), "index", current.GiteaPRNumber, "head", current.HeadBranch, "tip", tip)
	return true, nil
}

func (r *Reflector) materializeProposalHead(ctx context.Context, mapping store.Mapping, ev *nostr.Event, repoPath, base, branch string) (string, error) {
	stagingRef := refsnostr.RefPrefix + ev.ID.Hex()
	declared := tagValue(ev.Tags, "commit")
	legacy := tagValue(ev.Tags, "c")
	if declared != "" && legacy != "" && declared != legacy {
		return "", fmt.Errorf("conflicting commit and c tags")
	}
	if declared == "" {
		declared = legacy
	}
	if staged, err := bareOutput(ctx, repoPath, "rev-parse", "--verify", stagingRef+"^{commit}"); err == nil {
		if declared != "" && !strings.EqualFold(staged, declared) {
			return "", fmt.Errorf("staged commit %s does not match declared commit %s", staged, declared)
		}
		if err := updateBareRef(ctx, repoPath, "refs/heads/"+branch, staged); err != nil {
			return "", err
		}
		return staged, nil
	}
	baseRef := base
	if !strings.HasPrefix(baseRef, "refs/") {
		baseRef = "refs/heads/" + baseRef
	}
	if parent := tagValue(ev.Tags, "parent-commit"); parent != "" {
		if hasTagValue(ev.Tags, "t", "root-revision") {
			parentSHA, err := bareOutput(ctx, repoPath, "rev-parse", "--verify", parent+"^{commit}")
			if err != nil {
				return "", fmt.Errorf("parent-commit unavailable: %w", err)
			}
			baseRef = parentSHA
		} else {
			baseSHA, err := bareOutput(ctx, repoPath, "rev-parse", "--verify", baseRef+"^{commit}")
			if err != nil {
				return "", err
			}
			if !strings.EqualFold(baseSHA, parent) {
				return "", fmt.Errorf("parent-commit %s does not match materialization base %s", parent, baseSHA)
			}
		}
	}
	if looksLikeFormatPatch(ev.Content) {
		head, err := applyPatchContentRef(ctx, repoPath, baseRef, stagingRef, ev.Content)
		if err != nil {
			return "", err
		}
		if declared != "" && !strings.EqualFold(head, declared) {
			return "", fmt.Errorf("applied commit %s does not match declared commit %s", head, declared)
		}
		if err := updateBareRef(ctx, repoPath, "refs/heads/"+branch, head); err != nil {
			return "", err
		}
		return head, nil
	}
	if validSHA.MatchString(declared) && len(tagValues(ev.Tags, "clone")) > 0 {
		if err := r.materializeTipBranch(ctx, mapping, ev, repoPath, declared, branch); err != nil {
			return "", err
		}
		return declared, nil
	}
	return "", fmt.Errorf("patch content is not git format-patch and no fetchable commit was provided")
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
			r.logRepositoryFailure("reflector: failed to materialize patch tip; rejecting patch", mapping, repoPath, ev.ID.Hex(), err, "tip", tip)
			return r.recordPatchRejection(ctx, mapping, ev, tip, "materialize patch tip failed: "+err.Error())
		}
	} else {
		if !looksLikeFormatPatch(ev.Content) {
			r.logger.Info("reflector: patch missing usable c-tip and content is not git format-patch; rejecting patch", "event", ev.ID.Hex(), "tip", tip)
			return r.recordPatchRejection(ctx, mapping, ev, "", "patch content is not a git format-patch and no usable c tip was provided")
		}
		if err := applyPatchContentBranch(ctx, repoPath, base, branch, ev.Content); err != nil {
			r.logRepositoryFailure("reflector: failed to apply patch content; rejecting patch", mapping, repoPath, ev.ID.Hex(), err)
			return r.recordPatchRejection(ctx, mapping, ev, "", "apply patch content failed: "+err.Error())
		}
	}

	title := patchTitle(ev)
	body := patchBody(ev)
	pr, err := r.gitea.CreatePullRequest(ctx, mapping.Owner, mapping.RepoName, branch, base, title, body)
	if err != nil {
		r.logRepositoryFailure("reflector: failed to create Gitea PR for patch; rejecting patch", mapping, repoPath, ev.ID.Hex(), err, "branch", branch, "base", base)
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
	if err := r.store.UpsertThreadRoot(ctx, store.ThreadRoot{
		ObjectType:   "pr",
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   index,
		NostrEventID: ev.ID.Hex(),
		Pubkey:       ev.PubKey.Hex(),
		Kind:         relay.KindPROpen,
	}); err != nil {
		return false, fmt.Errorf("persist reflected PR thread root: %w", err)
	}
	r.logger.Info("reflector: created Gitea PR from Nostr patch", "event", ev.ID.Hex(), "repo", mapping.Owner+"/"+mapping.RepoName, "index", index, "head", branch, "base", base)
	return true, nil
}

func (r *Reflector) logRepositoryFailure(message string, mapping store.Mapping, repoPath, eventID string, err error, extra ...any) {
	args := []any{"repo_address", fmt.Sprintf("30617:%s:%s", mapping.Pubkey, mapping.RepoID), "repo_path", repoPath, "event", eventID, "error", err}
	args = append(args, extra...)
	if isPermissionError(err) && r.ownershipDiagnoser != nil {
		if diagnosis := r.ownershipDiagnoser(repoPath); diagnosis != "" {
			args = append(args, "ownership_mismatch", diagnosis)
		}
	}
	r.logger.Warn(message, args...)
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "permission denied") || strings.Contains(message, "insufficient permission") || strings.Contains(message, "cannot lock ref")
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
		validate := r.validateGitCloneURL
		if validate == nil {
			validate = safefetch.ValidateGitCloneURL
		}
		if err := validate(ctx, cloneURL); err != nil {
			errs = append(errs, fmt.Sprintf("unsafe clone URL %q: %v", cloneURL, err))
			continue
		}
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
		validate := r.validateGitCloneURL
		if validate == nil {
			validate = safefetch.ValidateGitCloneURL
		}
		if err := validate(ctx, cloneURL); err != nil {
			errs = append(errs, fmt.Sprintf("unsafe clone URL %q: %v", cloneURL, err))
			continue
		}
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

func deleteBareRef(ctx context.Context, repoPath string, ref string) error {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", "-d", ref).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("git update-ref -d %s: %w: %s", ref, err, msg)
		}
		return fmt.Errorf("git update-ref -d %s: %w", ref, err)
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
	_, err := applyPatchContentRef(ctx, repoPath, "refs/heads/"+base, "refs/heads/"+branch, content)
	return err
}

func applyPatchContentRef(ctx context.Context, repoPath, baseRef, targetRef, content string) (string, error) {
	baseCommit, err := bareOutput(ctx, repoPath, "rev-parse", "--verify", baseRef+"^{commit}")
	if err != nil {
		return "", err
	}
	parent, err := os.MkdirTemp("", "grasp-nip34-patch-*")
	if err != nil {
		return "", fmt.Errorf("create patch temp dir: %w", err)
	}
	defer os.RemoveAll(parent)
	worktree := filepath.Join(parent, "worktree")
	patchPath := filepath.Join(parent, "patch.mbox")
	if err := os.WriteFile(patchPath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write patch content: %w", err)
	}

	added := false
	defer func() {
		if added {
			_, _ = exec.CommandContext(context.Background(), "git", "-C", worktree, "am", "--abort").CombinedOutput()
			_, _ = exec.CommandContext(context.Background(), "git", "--git-dir", repoPath, "worktree", "remove", "--force", worktree).CombinedOutput()
		}
	}()

	if err := bareRun(ctx, repoPath, "worktree", "add", "--detach", worktree, strings.TrimSpace(baseCommit)); err != nil {
		return "", err
	}
	added = true
	if err := worktreeRun(ctx, worktree, "-c", "user.name=GRASP Bridge", "-c", "user.email=grasp-bridge@example.invalid", "am", patchPath); err != nil {
		return "", err
	}
	head, err := worktreeOutput(ctx, worktree, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	head = strings.TrimSpace(head)
	if err := updateBareRef(ctx, repoPath, targetRef, head); err != nil {
		return "", err
	}
	return head, nil
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
		relay.KindStatusDraft,
		relay.KindNIP32Label:
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
	// NIP-22 defines uppercase E as the root reference; element four is the
	// root author pubkey, not a NIP-10 marker.
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "E" {
			return tag[1]
		}
	}
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "e" {
			continue
		}
		if len(tag) >= 4 && tag[3] != "" && tag[3] != "root" {
			continue
		}
		return tag[1]
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

func hasTagValue(tags nostr.Tags, key, value string) bool {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key && tag[1] == value {
			return true
		}
	}
	return false
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

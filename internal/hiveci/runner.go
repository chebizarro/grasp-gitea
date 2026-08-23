// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package hiveci runs fleet-local act-based checks for NIP-34 repository
// activity and publishes signed check-run attestations back to Nostr.
package hiveci

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/nostrauthz"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	defaultActPath       = "/usr/bin/act"
	checkResultSchema    = "hiveci.check_run.v1"
	auditSchema          = "hiveci.audit.gate_decision.v1"
	auditType            = "CAS_AUDIT"
	maxPublishedLogBytes = 8192
	defaultRunTimeout    = 15 * time.Minute
	defaultMaxConcurrent = 2
	maxStartedEntries    = 4096
	startedEntryTTL      = 24 * time.Hour
	worktreeCleanupLimit = 30 * time.Second
)

var validCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)

// Config controls the Hive-CI Tier A runner.
type Config struct {
	Enabled       bool
	ActPath       string
	TriggerRepos  []string
	RunTimeout    time.Duration
	MaxConcurrent int
}

// Store resolves NIP-34 repository coordinates to local Gitea repositories.
type Store interface {
	GetProvisionedMappingByRepoAddr(ctx context.Context, pubkey string, repoID string) (store.Mapping, error)
}

// Signer signs operator-authored check/audit events. In production this is the
// Signet-backed server signer; BRIDGE_NSEC only reaches this interface in dev.
type Signer interface {
	PublicKey() string
	SignEvent(ctx context.Context, ev *nostr.Event) error
}

// Runner executes act workflows for received NIP-34 push/PR events.
type Runner struct {
	enabled         bool
	localEnabled    bool
	actPath         string
	store           Store
	signer          Signer
	relayURLs       []string
	repositoriesDir string
	logger          *slog.Logger
	runTimeout      time.Duration
	runSlots        chan struct{}
	triggerRepos    []string
	policy          *policy.Store

	mu      sync.Mutex
	started map[string]time.Time

	publish      func(context.Context, *nostr.Event) error
	statusSink   loom.StatusSink
	statusPrefix string
	remote       RemoteDispatcher
	dispatchMode string
	authorizer   WorkflowAuthorizer
}

// SetPolicyStore makes local and remote CI dispatch consult live policy snapshots.
func (r *Runner) SetPolicyStore(store *policy.Store) {
	if r != nil {
		r.policy = store
	}
}

type WorkflowAuthorizer interface {
	IsWorkflowAuthorAuthorized(context.Context, store.Mapping, string) (bool, error)
}

type RemoteDispatcher interface {
	Enabled() bool
	Dispatch(context.Context, loom.DispatchRequest) (bool, error)
}

type branchTip struct {
	Branch string
	Commit string
}

type runRecord struct {
	SchemaVersion string `json:"schema_version"`
	Project       string `json:"project"`
	Repository    string `json:"repository"`
	RepoID        string `json:"repo_id"`
	OwnerPubkey   string `json:"owner_pubkey"`
	SourceEventID string `json:"source_event_id"`
	SourceRelay   string `json:"source_relay,omitempty"`
	Trigger       string `json:"trigger"`
	Branch        string `json:"branch,omitempty"`
	Commit        string `json:"commit"`
	Workflow      string `json:"workflow"`
	Result        string `json:"result"`
	Reason        string `json:"reason"`
	BlocksMerge   bool   `json:"blocks_merge"`
	ExitCode      int    `json:"exit_code"`
	DurationMS    int64  `json:"duration_ms"`
	OutputTail    string `json:"output_tail,omitempty"`
}

// New creates a runner. Disabled runners are safe no-ops.
func New(cfg Config, st Store, signer Signer, relayURLs []string, repositoriesDir string, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	actPath := strings.TrimSpace(cfg.ActPath)
	if actPath == "" {
		actPath = defaultActPath
	}
	runTimeout := cfg.RunTimeout
	if runTimeout <= 0 || runTimeout > time.Hour {
		runTimeout = defaultRunTimeout
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	} else if maxConcurrent > 16 {
		maxConcurrent = 16
	}
	localEnabled := cfg.Enabled && st != nil && signer != nil && repositoriesDir != "" && actPath != ""
	r := &Runner{
		enabled:         localEnabled,
		localEnabled:    localEnabled,
		actPath:         actPath,
		store:           st,
		signer:          signer,
		relayURLs:       append([]string(nil), relayURLs...),
		repositoriesDir: repositoriesDir,
		logger:          logger,
		runTimeout:      runTimeout,
		runSlots:        make(chan struct{}, maxConcurrent),
		triggerRepos:    append([]string(nil), cfg.TriggerRepos...),
		started:         make(map[string]time.Time),
	}
	r.publish = r.publishToRelays
	return r
}

// SetStatusSink routes local Tier-A results through the shared durable sink.
func (r *Runner) SetStatusSink(sink loom.StatusSink, contextPrefix string) {
	if r == nil {
		return
	}
	r.statusSink = sink
	r.statusPrefix = strings.TrimSpace(contextPrefix)
}

// SetWorkflowAuthorizer shares the validated owner/recursive-maintainer pool
// used by proactive synchronization with local and remote CI.
func (r *Runner) SetWorkflowAuthorizer(authorizer WorkflowAuthorizer) {
	if r != nil {
		r.authorizer = authorizer
	}
}

// SetRemoteDispatcher adds canonical Loom execution alongside the local act path.
func (r *Runner) SetRemoteDispatcher(dispatcher RemoteDispatcher, mode string) {
	if r == nil {
		return
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "remote" && mode != "both" {
		mode = "local"
	}
	r.remote = dispatcher
	r.dispatchMode = mode
	if dispatcher != nil && dispatcher.Enabled() && mode != "local" && r.store != nil && r.repositoriesDir != "" {
		r.enabled = true
	}
}

// Enabled reports whether the runner can execute checks and publish results.
func (r *Runner) Enabled() bool {
	return r != nil && r.enabled
}

// HandleEvent consumes NIP-34 repository state (push) and PR/patch events.
func (r *Runner) HandleEvent(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	if !r.Enabled() || ev == nil {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		r.logger.Warn("HiveCI ignored event with invalid ID or signature", "event", ev.ID.Hex(), "kind", ev.Kind, "error", err)
		return nil
	}
	switch ev.Kind {
	case relay.KindRepositoryState:
		return r.handleRepositoryState(ctx, ev, sourceRelay)
	case relay.KindPatch, relay.KindPROpen, relay.KindPRUpdate:
		return r.handlePullRequestEvent(ctx, ev, sourceRelay)
	default:
		return nil
	}
}

func (r *Runner) handleRepositoryState(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	repoID := tagValue(ev.Tags, "d")
	if repoID == "" {
		return nil
	}
	mapping, ok, err := r.mappingForState(ctx, ev, repoID)
	if err != nil || !ok {
		return err
	}
	for _, tip := range branchTips(ev.Tags) {
		if err := r.runForCommit(ctx, mapping, ev, sourceRelay, "push", tip.Branch, tip.Commit); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) handlePullRequestEvent(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	mapping, ok, err := r.mappingForAddress(ctx, ev)
	if err != nil || !ok {
		return err
	}
	commit := strings.TrimSpace(tagValue(ev.Tags, "c"))
	if !validCommitSHA.MatchString(commit) {
		r.logger.Debug("HiveCI: PR event has no usable c commit", "event", ev.ID.Hex(), "kind", ev.Kind)
		return nil
	}
	branch := firstNonEmpty(tagValue(ev.Tags, "branch-name"), tagValue(ev.Tags, "branch"), "pr")
	return r.runForCommit(ctx, mapping, ev, sourceRelay, "pull_request", branch, commit)
}

func (r *Runner) runForCommit(ctx context.Context, mapping store.Mapping, ev *nostr.Event, sourceRelay, trigger, branch, commit string) error {
	if !r.isRepoCIAllowed(mapping.Owner, mapping.RepoID) {
		return nil
	}
	authorized, authErr := r.workflowAuthorAuthorized(ctx, mapping, ev.PubKey.Hex())
	if authErr != nil || !authorized {
		r.logger.Warn("HiveCI ignored workflow from unauthorized author", "repo", mapping.RepoID,
			"event", ev.ID.Hex(), "author", ev.PubKey.Hex(), "error", authErr)
		return nil
	}
	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	workflows, err := detectWorkflows(ctx, repoPath, commit)
	if err != nil {
		return fmt.Errorf("detect HiveCI workflows for %s/%s@%s: %w", mapping.Owner, mapping.RepoName, commit, err)
	}
	if len(workflows) == 0 {
		r.logger.Debug("HiveCI: no workflows for commit", "repo", mapping.RepoID, "commit", commit)
		return nil
	}
	for _, workflow := range workflows {
		if r.remote != nil && r.remote.Enabled() && r.dispatchMode != "local" {
			handled, dispatchErr := r.remote.Dispatch(ctx, loom.DispatchRequest{
				SourceEventID: ev.ID.Hex(), OwnerPubkey: mapping.Pubkey,
				Owner: mapping.Owner, RepoName: mapping.RepoName, RepoID: mapping.RepoID,
				CloneURL:  firstNonEmpty(mapping.AnnouncedCloneURL, mapping.CloneURL),
				CommitSHA: commit, WorkflowPath: workflow,
				Branch: branch, Trigger: trigger, TriggeredBy: ev.PubKey.Hex(),
			})
			if handled {
				if dispatchErr != nil {
					r.logger.Warn("durable Loom dispatch awaits retry", "repo", mapping.RepoID, "workflow", workflow, "error", dispatchErr)
				}
				continue
			}
			if dispatchErr != nil {
				return fmt.Errorf("prepare Loom dispatch: %w", dispatchErr)
			}
			if r.dispatchMode == "remote" {
				r.logger.Warn("Loom remote-only workflow has no eligible worker", "repo", mapping.RepoID, "workflow", workflow)
				continue
			}
		}
		// Remote-only is an execution boundary, not permission to fall back to
		// local act when the dispatcher is misconfigured or unavailable.
		if r.dispatchMode == "remote" {
			continue
		}
		if !r.localEnabled {
			continue
		}
		key := runKey(ev.ID.Hex(), commit, workflow)
		if r.markStarted(key) {
			continue
		}
		ref := localStatusRef(mapping, ev, trigger, commit, workflow)
		claimed, err := r.claimCommitStatus(ctx, ref, "hive-ci: workflow queued")
		if err != nil {
			r.unmarkStarted(key)
			return fmt.Errorf("persist HiveCI execution claim: %w", err)
		}
		if !claimed {
			// A prior process already started or completed this immutable attempt.
			// Delivery retries must never acquire execution ownership.
			continue
		}
		record := r.runWorkflow(ctx, mapping, ev, sourceRelay, trigger, branch, commit, workflow)
		terminalState := store.LoomStatusFailure
		if record.Result == "success" {
			terminalState = store.LoomStatusSuccess
		}
		if err := r.setCommitStatus(ctx, ref, terminalState, "hive-ci: "+record.Reason, "terminal"); err != nil {
			// Delivery persistence is deliberately outside the execution/retry path:
			// a Gitea failure must never cause act to run again.
			r.logger.Error("HiveCI terminal status enqueue failed", "repo", mapping.RepoID, "workflow", workflow, "error", err)
		}
		if err := r.publishRun(ctx, mapping, record); err != nil {
			return err
		}
		r.logger.Info("HiveCI check run published", "repo", mapping.RepoID, "branch", branch, "workflow", workflow, "commit", commit, "result", record.Result)
	}
	return nil
}

func (r *Runner) runWorkflow(ctx context.Context, mapping store.Mapping, ev *nostr.Event, sourceRelay, trigger, branch, commit, workflow string) runRecord {
	start := time.Now()
	rec := runRecord{
		SchemaVersion: checkResultSchema,
		Project:       mapping.Owner + "/" + mapping.RepoID,
		Repository:    mapping.Owner + "/" + mapping.RepoName,
		RepoID:        mapping.RepoID,
		OwnerPubkey:   mapping.Pubkey,
		SourceEventID: ev.ID.Hex(),
		SourceRelay:   sourceRelay,
		Trigger:       trigger,
		Branch:        branch,
		Commit:        commit,
		Workflow:      workflow,
		Result:        "failure",
		Reason:        "act did not complete",
		BlocksMerge:   true,
		ExitCode:      -1,
	}

	select {
	case r.runSlots <- struct{}{}:
		defer func() { <-r.runSlots }()
	case <-ctx.Done():
		rec.Reason = "run cancelled while waiting for concurrency slot: " + ctx.Err().Error()
		rec.DurationMS = time.Since(start).Milliseconds()
		return rec
	}

	runCtx, cancel := context.WithTimeout(ctx, r.runTimeout)
	defer cancel()
	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	parent, err := os.MkdirTemp("", "hiveci-*")
	if err != nil {
		rec.Reason = "create temp dir: " + err.Error()
		rec.DurationMS = time.Since(start).Milliseconds()
		return rec
	}
	defer os.RemoveAll(parent)
	worktree := filepath.Join(parent, "worktree")
	added := false
	defer func() {
		if added {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), worktreeCleanupLimit)
			defer cleanupCancel()
			_, _ = exec.CommandContext(cleanupCtx, "git", "--git-dir", repoPath, "worktree", "remove", "--force", worktree).CombinedOutput()
		}
	}()

	if out, err := exec.CommandContext(runCtx, "git", "--git-dir", repoPath, "worktree", "add", "--detach", worktree, commit).CombinedOutput(); err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			rec.Reason = "HiveCI run timed out after " + r.runTimeout.String()
		} else {
			rec.Reason = commandError("git worktree add", err, out)
		}
		rec.OutputTail = tailString(string(out), maxPublishedLogBytes)
		rec.DurationMS = time.Since(start).Milliseconds()
		return rec
	}
	added = true

	cmd := exec.Command(r.actPath, trigger, "-W", workflow, "--rm")
	cmd.Dir = worktree
	cmd.Env = append(os.Environ(), "CI=true")
	out, err := runBoundedCommand(runCtx, cmd, maxPublishedLogBytes)
	rec.OutputTail = tailString(string(out), maxPublishedLogBytes)
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			rec.Reason = "HiveCI run timed out after " + r.runTimeout.String()
		} else {
			rec.Reason = commandError("act", err, out)
		}
		rec.ExitCode = exitCode(err)
		return rec
	}
	rec.Result = "success"
	rec.Reason = "act completed successfully"
	rec.BlocksMerge = false
	rec.ExitCode = 0
	return rec
}

func (r *Runner) publishRun(ctx context.Context, mapping store.Mapping, rec runRecord) error {
	statusEv, err := r.buildCheckResultEvent(mapping, rec)
	if err != nil {
		return err
	}
	if err := r.publish(ctx, statusEv); err != nil {
		return fmt.Errorf("publish HiveCI check result: %w", err)
	}
	auditEv, err := r.buildAuditEvent(mapping, rec)
	if err != nil {
		return err
	}
	if err := r.publish(ctx, auditEv); err != nil {
		return fmt.Errorf("publish HiveCI audit result: %w", err)
	}
	return nil
}

func (r *Runner) buildCheckResultEvent(mapping store.Mapping, rec runRecord) (*nostr.Event, error) {
	content, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	tags := commonRunTags(mapping, rec)
	tags = append(tags,
		nostr.Tag{"d", "hiveci:check:" + stableRunID(rec)},
		nostr.Tag{"status", rec.Result},
	)
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: relay.KindCheckRunResult, Tags: tags, Content: string(content)}
	return ev, r.sign(context.Background(), ev)
}

func (r *Runner) buildAuditEvent(mapping store.Mapping, rec runRecord) (*nostr.Event, error) {
	audit := map[string]any{
		"schema_version":  auditSchema,
		"project":         rec.Project,
		"repository":      rec.Repository,
		"decision":        rec.Result,
		"reason":          rec.Reason,
		"blocks_merge":    rec.BlocksMerge,
		"source_event_id": rec.SourceEventID,
		"commit":          rec.Commit,
		"branch":          rec.Branch,
		"workflow":        rec.Workflow,
		"duration_ms":     rec.DurationMS,
		"exit_code":       rec.ExitCode,
	}
	content, err := json.Marshal(audit)
	if err != nil {
		return nil, err
	}
	tags := commonRunTags(mapping, rec)
	tags = append(tags,
		nostr.Tag{"d", "hiveci:audit:" + stableRunID(rec)},
		nostr.Tag{"audit_type", auditType},
		nostr.Tag{"decision", rec.Result},
	)
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: relay.KindCASAudit, Tags: tags, Content: string(content)}
	return ev, r.sign(context.Background(), ev)
}

func commonRunTags(mapping store.Mapping, rec runRecord) nostr.Tags {
	aTag := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	tags := nostr.Tags{
		{"project", rec.Project},
		{"a", aTag},
		{"p", mapping.Pubkey},
		{"commit", rec.Commit},
		{"workflow", rec.Workflow},
		{"triggered-by", rec.Trigger},
		{"event", rec.SourceEventID},
	}
	if rec.Branch != "" {
		tags = append(tags, nostr.Tag{"branch", rec.Branch})
	}
	if rec.SourceRelay != "" {
		tags = append(tags, nostr.Tag{"relay", rec.SourceRelay})
	}
	return tags
}

func (r *Runner) sign(ctx context.Context, ev *nostr.Event) error {
	if r.signer == nil {
		return fmt.Errorf("HiveCI signer not configured")
	}
	pk, err := nostr.PubKeyFromHex(r.signer.PublicKey())
	if err != nil {
		return fmt.Errorf("invalid HiveCI signer pubkey: %w", err)
	}
	ev.PubKey = pk
	ev.ID = nostr.ID{}
	ev.Sig = [64]byte{}
	return r.signer.SignEvent(ctx, ev)
}

func (r *Runner) publishToRelays(ctx context.Context, ev *nostr.Event) error {
	if len(r.relayURLs) == 0 {
		return fmt.Errorf("no relay URLs configured")
	}
	var succeeded int
	for _, url := range r.relayURLs {
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		relayConn, err := nostr.RelayConnect(pubCtx, url, nostr.RelayOptions{})
		if err != nil {
			cancel()
			r.logger.Warn("HiveCI relay connect failed", "relay", url, "error", err)
			continue
		}
		err = relayConn.Publish(pubCtx, *ev)
		relayConn.Close()
		cancel()
		if err != nil {
			r.logger.Warn("HiveCI relay publish failed", "relay", url, "event", ev.ID.Hex(), "error", err)
			continue
		}
		succeeded++
	}
	if succeeded == 0 {
		return fmt.Errorf("event %s rejected by all %d relays", ev.ID.Hex(), len(r.relayURLs))
	}
	return nil
}

func (r *Runner) mappingForState(ctx context.Context, ev *nostr.Event, repoID string) (store.Mapping, bool, error) {
	candidates := []string{tagValue(ev.Tags, "p"), ev.PubKey.Hex()}
	seen := map[string]struct{}{}
	for _, pubkey := range candidates {
		pubkey = strings.TrimSpace(pubkey)
		if pubkey == "" {
			continue
		}
		if _, ok := seen[pubkey]; ok {
			continue
		}
		seen[pubkey] = struct{}{}
		mapping, err := r.store.GetProvisionedMappingByRepoAddr(ctx, pubkey, repoID)
		if err == nil {
			return mapping, true, nil
		}
		if err != sql.ErrNoRows {
			return store.Mapping{}, false, err
		}
	}
	return store.Mapping{}, false, nil
}

func (r *Runner) mappingForAddress(ctx context.Context, ev *nostr.Event) (store.Mapping, bool, error) {
	pubkey, repoID, ok := parseRepoAddr(tagValue(ev.Tags, "a"))
	if !ok {
		return store.Mapping{}, false, nil
	}
	mapping, err := r.store.GetProvisionedMappingByRepoAddr(ctx, pubkey, repoID)
	if err == sql.ErrNoRows {
		return store.Mapping{}, false, nil
	}
	if err != nil {
		return store.Mapping{}, false, err
	}
	return mapping, true, nil
}

func (r *Runner) isRepoCIAllowed(owner, repoID string) bool {
	target := strings.TrimSpace(owner) + "/" + strings.TrimSpace(repoID)
	triggerRepos := r.triggerRepos
	if snapshot := r.policy.Current(); snapshot != nil {
		triggerRepos = snapshot.CITriggerRepos
	}
	for _, entry := range triggerRepos {
		entry = strings.TrimSpace(entry)
		if entry == "*" || entry == target {
			return true
		}
	}
	return false
}

func (r *Runner) workflowAuthorAuthorized(ctx context.Context, mapping store.Mapping, author string) (bool, error) {
	if r.authorizer != nil {
		return r.authorizer.IsWorkflowAuthorAuthorized(ctx, mapping, author)
	}
	return workflowAuthorAuthorized(mapping, author), nil
}

func workflowAuthorAuthorized(mapping store.Mapping, author string) bool {
	author = strings.TrimSpace(author)
	if author == "" || strings.TrimSpace(mapping.AnnouncementEventJSON) == "" {
		return false
	}
	var announcement nostr.Event
	if err := json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &announcement); err != nil {
		return false
	}
	coord := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	ok, err := nostrauthz.NewResolver([]nostr.Event{announcement}).IsAuthorized(author, coord)
	return err == nil && ok
}

func branchTips(tags nostr.Tags) []branchTip {
	tips := make([]branchTip, 0)
	for _, tag := range tags {
		if len(tag) < 2 || !strings.HasPrefix(tag[0], "refs/heads/") {
			continue
		}
		commit := strings.TrimSpace(tag[1])
		if !validCommitSHA.MatchString(commit) {
			continue
		}
		branch := strings.TrimPrefix(tag[0], "refs/heads/")
		if branch == "" {
			continue
		}
		tips = append(tips, branchTip{Branch: branch, Commit: commit})
	}
	return tips
}

var workflowDirs = []string{
	".gitea/workflows",
	".github/workflows",
	".hive/workflows",
}

func detectWorkflows(ctx context.Context, repoPath string, commitSHA string) ([]string, error) {
	if !validCommitSHA.MatchString(commitSHA) {
		return nil, fmt.Errorf("invalid commit %q", commitSHA)
	}
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "cat-file", "-e", commitSHA+"^{commit}").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("commit object unavailable: %s: %w", strings.TrimSpace(string(out)), err)
	}
	var workflows []string
	for _, dir := range workflowDirs {
		found, err := listWorkflowFiles(ctx, repoPath, commitSHA, dir)
		if err != nil {
			return nil, err
		}
		workflows = append(workflows, found...)
	}
	return workflows, nil
}

func listWorkflowFiles(ctx context.Context, repoPath, commitSHA, dir string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "ls-tree", "-r", "--name-only", commitSHA, "--", dir).Output()
	if err != nil {
		return nil, err
	}
	prefix := dir + "/"
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || (!strings.HasSuffix(line, ".yml") && !strings.HasSuffix(line, ".yaml")) {
			continue
		}
		cleaned := path.Clean(line)
		if !strings.HasPrefix(cleaned, prefix) {
			continue
		}
		files = append(files, cleaned)
	}
	return files, nil
}

func (r *Runner) markStarted(key string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for existing, startedAt := range r.started {
		if now.Sub(startedAt) >= startedEntryTTL {
			delete(r.started, existing)
		}
	}
	if _, ok := r.started[key]; ok {
		return true
	}
	if len(r.started) >= maxStartedEntries {
		var oldestKey string
		var oldest time.Time
		for existing, startedAt := range r.started {
			if oldestKey == "" || startedAt.Before(oldest) {
				oldestKey = existing
				oldest = startedAt
			}
		}
		delete(r.started, oldestKey)
	}
	r.started[key] = now
	return false
}

func (r *Runner) unmarkStarted(key string) {
	r.mu.Lock()
	delete(r.started, key)
	r.mu.Unlock()
}

func runKey(eventID, commit, workflow string) string {
	return eventID + ":" + commit + ":" + workflow
}

func localStatusRef(mapping store.Mapping, ev *nostr.Event, trigger, commit, workflow string) loom.Ref {
	rec := runRecord{SourceEventID: ev.ID.Hex(), Commit: commit, Workflow: workflow, Trigger: trigger}
	return loom.Ref{
		WorkflowRunID: "local:" + stableRunID(rec), Owner: mapping.Owner,
		RepoName: mapping.RepoName, RepoID: mapping.RepoID, CommitSHA: commit,
		WorkflowPath: workflow,
	}
}

func (r *Runner) claimCommitStatus(ctx context.Context, ref loom.Ref, description string) (bool, error) {
	if r.statusSink == nil {
		return true, nil
	}
	return r.statusSink.Claim(ctx, loom.Status{
		Ref: ref, State: store.LoomStatusPending, Description: description,
		Context: loom.Context(r.statusPrefix, ref.WorkflowPath), Source: store.LoomSourceLocal,
		ProtocolEventID: ref.WorkflowRunID + ":pending",
	})
}

func (r *Runner) setCommitStatus(ctx context.Context, ref loom.Ref, state, description, phase string) error {
	if r.statusSink == nil {
		return nil
	}
	return r.statusSink.Set(ctx, loom.Status{
		Ref: ref, State: state, Description: description,
		Context: loom.Context(r.statusPrefix, ref.WorkflowPath), Source: store.LoomSourceLocal,
		ProtocolEventID: ref.WorkflowRunID + ":" + phase,
	})
}

func stableRunID(rec runRecord) string {
	sum := sha256.Sum256([]byte(rec.SourceEventID + "\x00" + rec.Commit + "\x00" + rec.Workflow + "\x00" + rec.Trigger))
	return hex.EncodeToString(sum[:12])
}

func parseRepoAddr(addr string) (pubkey string, repoID string, ok bool) {
	parts := strings.SplitN(addr, ":", 3)
	if len(parts) != 3 || parts[0] != fmt.Sprint(relay.KindRepositoryAnnouncement) || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func tagValue(tags nostr.Tags, key string) string {
	v := tags.Find(key)
	if v == nil || len(v) < 2 {
		return ""
	}
	return v[1]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type tailOutput struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (w *tailOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := len(p)
	if len(p) >= w.max {
		w.buf = append(w.buf[:0], p[len(p)-w.max:]...)
		return written, nil
	}
	w.buf = append(w.buf, p...)
	if excess := len(w.buf) - w.max; excess > 0 {
		copy(w.buf, w.buf[excess:])
		w.buf = w.buf[:w.max]
	}
	return written, nil
}

func (w *tailOutput) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf...)
}

func runBoundedCommand(ctx context.Context, cmd *exec.Cmd, maxOutput int) ([]byte, error) {
	output := &tailOutput{max: maxOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return output.Bytes(), err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return output.Bytes(), err
	case <-ctx.Done():
		// Kill the whole process group so workflow child processes do not keep
		// consuming host resources after the run deadline.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return output.Bytes(), ctx.Err()
	}
}

func commandError(prefix string, err error, output []byte) string {
	msg := strings.TrimSpace(string(output))
	if msg != "" {
		return fmt.Sprintf("%s: %v: %s", prefix, err, tailString(msg, 512))
	}
	return fmt.Sprintf("%s: %v", prefix, err)
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func tailString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

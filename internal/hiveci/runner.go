// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package hiveci runs local act-based checks for NIP-34 repository activity
// and records their outcomes as durable Gitea commit statuses.
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
	"github.com/sharegap/grasp-gitea/internal/telemetry"
)

const (
	defaultActPath       = "/usr/bin/act"
	maxRunOutputBytes    = 8192
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
	ListPendingLocalLoomJobs(context.Context) ([]store.LoomJob, error)
}

// Runner executes act workflows for received NIP-34 push/PR events.
type Runner struct {
	enabled         bool
	localEnabled    bool
	actPath         string
	store           Store
	repositoriesDir string
	logger          *slog.Logger
	runTimeout      time.Duration
	runSlots        chan struct{}
	triggerRepos    []string
	policy          *policy.Store

	mu              sync.Mutex
	started         map[string]time.Time
	terminalRetries map[string]loom.Status

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

// New creates a runner. Disabled runners are safe no-ops.
func New(cfg Config, st Store, repositoriesDir string, logger *slog.Logger) *Runner {
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
	localEnabled := cfg.Enabled && st != nil && repositoriesDir != "" && actPath != ""
	r := &Runner{
		enabled:         localEnabled,
		localEnabled:    localEnabled,
		actPath:         actPath,
		store:           st,
		repositoriesDir: repositoriesDir,
		logger:          logger,
		runTimeout:      runTimeout,
		runSlots:        make(chan struct{}, maxConcurrent),
		triggerRepos:    append([]string(nil), cfg.TriggerRepos...),
		started:         make(map[string]time.Time),
		terminalRetries: make(map[string]loom.Status),
	}
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

// Enabled reports whether the runner can execute checks.
func (r *Runner) Enabled() bool {
	return r != nil && r.enabled
}

// HandleEvent consumes NIP-34 repository state (push) and PR/patch events.
func (r *Runner) HandleEvent(ctx context.Context, ev *nostr.Event) error {
	if !r.Enabled() || ev == nil {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		r.logger.Warn("HiveCI ignored event with invalid ID or signature", "event", ev.ID.Hex(), "kind", ev.Kind, "error", err)
		return nil
	}
	ctx = telemetry.ContextWithTraceTags(ctx, tagValue(ev.Tags, "traceparent"), tagValue(ev.Tags, "tracestate"))
	switch ev.Kind {
	case relay.KindRepositoryState:
		return r.handleRepositoryState(ctx, ev)
	case relay.KindPatch, relay.KindPROpen, relay.KindPRUpdate:
		return r.handlePullRequestEvent(ctx, ev)
	default:
		return nil
	}
}

func (r *Runner) handleRepositoryState(ctx context.Context, ev *nostr.Event) error {
	repoID := tagValue(ev.Tags, "d")
	if repoID == "" {
		return nil
	}
	mapping, ok, err := r.mappingForState(ctx, ev, repoID)
	if err != nil || !ok {
		return err
	}
	for _, tip := range branchTips(ev.Tags) {
		if err := r.runForCommit(ctx, mapping, ev, "push", tip.Branch, tip.Commit); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) handlePullRequestEvent(ctx context.Context, ev *nostr.Event) error {
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
	return r.runForCommit(ctx, mapping, ev, "pull_request", branch, commit)
}

func (r *Runner) runForCommit(ctx context.Context, mapping store.Mapping, ev *nostr.Event, trigger, branch, commit string) error {
	if !r.isRepoCIAllowed(mapping) {
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
	var terminalErrors error
	for _, workflow := range workflows {
		if r.remote != nil && r.remote.Enabled() && r.dispatchMode != "local" {
			handled, dispatchErr := r.remote.Dispatch(ctx, loom.DispatchRequest{
				SourceEventID: ev.ID.Hex(), OwnerPubkey: mapping.Pubkey,
				Owner: mapping.Owner, RepoName: mapping.RepoName, RepoID: mapping.RepoID,
				CloneURL:  r.cloneURL(mapping),
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
		success, reason := r.runWorkflow(ctx, mapping, trigger, commit, workflow)
		terminalState := store.LoomStatusFailure
		if success {
			terminalState = store.LoomStatusSuccess
		}
		terminal := loom.Status{
			Ref: ref, State: terminalState, Description: "hive-ci: " + reason,
			Context: loom.Context(r.statusPrefix, ref.WorkflowPath), Source: store.LoomSourceLocal,
			ProtocolEventID: ref.WorkflowRunID + ":terminal",
		}
		r.mu.Lock()
		r.terminalRetries[ref.WorkflowRunID] = terminal
		r.mu.Unlock()
		statusCtx, statusCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		statusErr := r.statusSink.Set(statusCtx, terminal)
		statusCancel()
		if statusErr != nil {
			terminalErrors = errors.Join(terminalErrors, fmt.Errorf("persist HiveCI terminal status after local execution: %w", statusErr))
			continue
		}
		r.mu.Lock()
		delete(r.terminalRetries, ref.WorkflowRunID)
		r.mu.Unlock()
		r.logger.Info("HiveCI local workflow completed", "repo", mapping.RepoID, "branch", branch, "workflow", workflow, "commit", commit, "status", terminalState)
	}
	return terminalErrors
}

func (r *Runner) runWorkflow(ctx context.Context, mapping store.Mapping, trigger, commit, workflow string) (bool, string) {
	select {
	case r.runSlots <- struct{}{}:
		defer func() { <-r.runSlots }()
	case <-ctx.Done():
		return false, "run cancelled while waiting for concurrency slot: " + ctx.Err().Error()
	}

	runTimeout := r.runTimeout
	if snapshot := r.policy.Current(); snapshot != nil {
		runTimeout = snapshot.HiveCIJobTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	parent, err := os.MkdirTemp("", "hiveci-*")
	if err != nil {
		return false, "create temp dir: " + err.Error()
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
			return false, "HiveCI run timed out after " + runTimeout.String()
		}
		return false, commandError("git worktree add", err, out)
	}
	added = true

	cmd := exec.Command(r.actPath, trigger, "-W", workflow, "--rm")
	cmd.Dir = worktree
	cmd.Env = r.workflowEnvironment()
	out, err := runBoundedCommand(runCtx, cmd, maxRunOutputBytes)
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return false, "HiveCI run timed out after " + runTimeout.String()
		}
		return false, commandError("act", err, out)
	}
	return true, "act completed successfully"
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
	coord, err := nostrauthz.ParseRepositoryCoordinate(tagValue(ev.Tags, "a"))
	if err != nil {
		return store.Mapping{}, false, nil
	}
	mapping, err := r.store.GetProvisionedMappingByRepoAddr(ctx, coord.OwnerPubkey, coord.RepoID)
	if err == sql.ErrNoRows {
		return store.Mapping{}, false, nil
	}
	if err != nil {
		return store.Mapping{}, false, err
	}
	return mapping, true, nil
}

func (r *Runner) isRepoCIAllowed(mapping store.Mapping) bool {
	// Tenant repositories must use the immutable owner-pubkey/repo-id key:
	// their shared physical owner makes the legacy owner/repo-id form ambiguous.
	// Preserve legacy compatibility only for unmigrated per-pubkey mappings.
	immutable := strings.TrimSpace(mapping.Pubkey) + "/" + strings.TrimSpace(mapping.RepoID)
	legacy := strings.TrimSpace(mapping.Owner) + "/" + strings.TrimSpace(mapping.RepoID)
	legacyAllowed := strings.TrimSpace(mapping.TenantHost) == ""
	triggerRepos := r.triggerRepos
	if r.policy != nil {
		if snapshot := r.policy.Current(); snapshot != nil {
			triggerRepos = snapshot.CITriggerRepos
		}
	}
	for _, entry := range triggerRepos {
		entry = strings.TrimSpace(entry)
		if entry == "*" || entry == immutable || (legacyAllowed && entry == legacy) {
			return true
		}
	}
	return false
}

func (r *Runner) cloneURL(mapping store.Mapping) string {
	fallback := firstNonEmpty(mapping.AnnouncedCloneURL, mapping.CloneURL)
	snapshot := r.policy.Current()
	if snapshot == nil || strings.TrimSpace(snapshot.HiveCICloneURLTemplate) == "" {
		return fallback
	}
	return strings.NewReplacer(
		"{owner}", mapping.Owner,
		"{repo}", mapping.RepoName,
		"{repo_id}", mapping.RepoID,
		"{npub}", mapping.Npub,
		"{pubkey}", mapping.Pubkey,
	).Replace(snapshot.HiveCICloneURLTemplate)
}

func (r *Runner) workflowEnvironment() []string {
	blocked := map[string]struct{}{"NOSTR_RELAYS": {}, "CASHU_MINT_URL": {}, "BLOSSOM_URL": {}, "JOB_TIMEOUT_MINUTES": {}, "HIVECI_CLONE_URL_TEMPLATE": {}}
	env := make([]string, 0, len(os.Environ())+6)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, remove := blocked[key]; !remove {
			env = append(env, entry)
		}
	}
	env = append(env, "CI=true")
	if snapshot := r.policy.Current(); snapshot != nil {
		env = append(env,
			"NOSTR_RELAYS="+strings.Join(snapshot.HiveCINostrRelays, ","),
			"CASHU_MINT_URL="+snapshot.HiveCICashuMintURL,
			"BLOSSOM_URL="+snapshot.HiveCIBlossomURL,
			fmt.Sprintf("JOB_TIMEOUT_MINUTES=%d", int(snapshot.HiveCIJobTimeout/time.Minute)),
			"HIVECI_CLONE_URL_TEMPLATE="+snapshot.HiveCICloneURLTemplate,
		)
	}
	return env
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
	return loom.Ref{
		WorkflowRunID: "local:" + stableRunID(ev.ID.Hex(), commit, workflow, trigger), Owner: mapping.Owner,
		RepoName: mapping.RepoName, RepoID: mapping.RepoID, CommitSHA: commit,
		WorkflowPath: workflow,
	}
}

func (r *Runner) claimCommitStatus(ctx context.Context, ref loom.Ref, description string) (bool, error) {
	if r.statusSink == nil {
		return false, fmt.Errorf("HiveCI status sink not configured")
	}
	return r.statusSink.Claim(ctx, loom.Status{
		Ref: ref, State: store.LoomStatusPending, Description: description,
		Context: loom.Context(r.statusPrefix, ref.WorkflowPath), Source: store.LoomSourceLocal,
		ProtocolEventID: ref.WorkflowRunID + ":pending",
	})
}

// RecoverInterruptedLocalRuns marks prior-process pending claims with an unknown
// outcome. It must run before this process accepts CI events or starts local work.
func (r *Runner) RecoverInterruptedLocalRuns(ctx context.Context) error {
	if r == nil || r.store == nil {
		return nil
	}
	if r.statusSink == nil {
		return fmt.Errorf("HiveCI status sink not configured")
	}
	jobs, err := r.store.ListPendingLocalLoomJobs(ctx)
	if err != nil {
		return fmt.Errorf("list interrupted local HiveCI runs: %w", err)
	}
	for _, job := range jobs {
		statusContext := job.StatusContext
		if statusContext == "" {
			statusContext = loom.Context(r.statusPrefix, job.WorkflowPath)
		}
		status := loom.Status{
			Ref: loom.Ref{WorkflowRunID: job.WorkflowRunID, Owner: job.Owner, RepoName: job.RepoName,
				RepoID: job.RepoID, CommitSHA: job.CommitSHA, WorkflowPath: job.WorkflowPath, Branch: job.Branch},
			State: store.LoomStatusError, Description: "hive-ci: outcome unavailable after interrupted local execution",
			Context: statusContext, Source: store.LoomSourceLocalRecovery,
			ProtocolEventID: job.WorkflowRunID + ":recovery",
		}
		if err := r.statusSink.Set(ctx, status); err != nil {
			return fmt.Errorf("recover interrupted local HiveCI run %s: %w", job.WorkflowRunID, err)
		}
	}
	return nil
}

// RunTerminalRetries retains exact results while this process lives. It never
// re-executes a workflow; the durable sink handles Gitea delivery separately.
func (r *Runner) RunTerminalRetries(ctx context.Context) {
	if r == nil || !r.localEnabled {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.retryTerminalStatuses(ctx)
		}
	}
}

// DrainTerminalRetries gives completed local runs one final bounded chance to
// persist their exact outcome during graceful shutdown.
func (r *Runner) DrainTerminalRetries(ctx context.Context) error {
	if r == nil {
		return nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		r.retryTerminalStatuses(ctx)
		r.mu.Lock()
		remaining := len(r.terminalRetries)
		r.mu.Unlock()
		if remaining == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%d local HiveCI terminal statuses remain unpersisted: %w", remaining, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (r *Runner) retryTerminalStatuses(ctx context.Context) {
	r.mu.Lock()
	pending := make([]loom.Status, 0, len(r.terminalRetries))
	for _, status := range r.terminalRetries {
		pending = append(pending, status)
	}
	r.mu.Unlock()
	for _, status := range pending {
		if ctx.Err() != nil {
			return
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := r.statusSink.Set(attemptCtx, status)
		cancel()
		if err != nil {
			r.logger.Warn("HiveCI terminal status persistence retry failed", "run", status.Ref.WorkflowRunID, "error", err)
			continue
		}
		r.mu.Lock()
		delete(r.terminalRetries, status.Ref.WorkflowRunID)
		r.mu.Unlock()
	}
}

func stableRunID(eventID, commit, workflow, trigger string) string {
	sum := sha256.Sum256([]byte(eventID + "\x00" + commit + "\x00" + workflow + "\x00" + trigger))
	return hex.EncodeToString(sum[:12])
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

func tailString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

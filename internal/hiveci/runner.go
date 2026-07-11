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
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	defaultActPath       = "/usr/bin/act"
	checkResultSchema    = "hiveci.check_run.v1"
	auditSchema          = "hiveci.audit.gate_decision.v1"
	auditType            = "CAS_AUDIT"
	maxPublishedLogBytes = 8192
)

var validCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)

// Config controls the Hive-CI Tier A runner.
type Config struct {
	Enabled bool
	ActPath string
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
	actPath         string
	store           Store
	signer          Signer
	relayURLs       []string
	repositoriesDir string
	logger          *slog.Logger

	mu      sync.Mutex
	started map[string]struct{}

	publish func(context.Context, *nostr.Event) error
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
	r := &Runner{
		enabled:         cfg.Enabled && st != nil && signer != nil && repositoriesDir != "" && actPath != "",
		actPath:         actPath,
		store:           st,
		signer:          signer,
		relayURLs:       append([]string(nil), relayURLs...),
		repositoriesDir: repositoriesDir,
		logger:          logger,
		started:         make(map[string]struct{}),
	}
	r.publish = r.publishToRelays
	return r
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
		r.logger.Debug("HiveCI: PR event has no usable c commit", "event", ev.ID, "kind", ev.Kind)
		return nil
	}
	branch := firstNonEmpty(tagValue(ev.Tags, "branch-name"), tagValue(ev.Tags, "branch"), "pr")
	return r.runForCommit(ctx, mapping, ev, sourceRelay, "pull_request", branch, commit)
}

func (r *Runner) runForCommit(ctx context.Context, mapping store.Mapping, ev *nostr.Event, sourceRelay, trigger, branch, commit string) error {
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
		key := runKey(ev.ID, commit, workflow)
		if r.markStarted(key) {
			continue
		}
		record := r.runWorkflow(ctx, mapping, ev, sourceRelay, trigger, branch, commit, workflow)
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
		SourceEventID: ev.ID,
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
			_, _ = exec.CommandContext(context.Background(), "git", "--git-dir", repoPath, "worktree", "remove", "--force", worktree).CombinedOutput()
		}
	}()

	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "worktree", "add", "--detach", worktree, commit).CombinedOutput(); err != nil {
		rec.Reason = commandError("git worktree add", err, out)
		rec.OutputTail = tailString(string(out), maxPublishedLogBytes)
		rec.DurationMS = time.Since(start).Milliseconds()
		return rec
	}
	added = true

	cmd := exec.CommandContext(ctx, r.actPath, trigger, "-W", workflow)
	cmd.Dir = worktree
	cmd.Env = append(os.Environ(), "CI=true")
	out, err := cmd.CombinedOutput()
	rec.OutputTail = tailString(string(out), maxPublishedLogBytes)
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		rec.Reason = commandError("act", err, out)
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
	ev.PubKey = r.signer.PublicKey()
	ev.ID = ""
	ev.Sig = ""
	return r.signer.SignEvent(ctx, ev)
}

func (r *Runner) publishToRelays(ctx context.Context, ev *nostr.Event) error {
	if len(r.relayURLs) == 0 {
		return fmt.Errorf("no relay URLs configured")
	}
	var succeeded int
	for _, url := range r.relayURLs {
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		relayConn, err := nostr.RelayConnect(pubCtx, url)
		if err != nil {
			cancel()
			r.logger.Warn("HiveCI relay connect failed", "relay", url, "error", err)
			continue
		}
		err = relayConn.Publish(pubCtx, *ev)
		relayConn.Close()
		cancel()
		if err != nil {
			r.logger.Warn("HiveCI relay publish failed", "relay", url, "event", ev.ID, "error", err)
			continue
		}
		succeeded++
	}
	if succeeded == 0 {
		return fmt.Errorf("event %s rejected by all %d relays", ev.ID, len(r.relayURLs))
	}
	return nil
}

func (r *Runner) mappingForState(ctx context.Context, ev *nostr.Event, repoID string) (store.Mapping, bool, error) {
	candidates := []string{tagValue(ev.Tags, "p"), ev.PubKey}
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
	var workflows []string
	for _, dir := range workflowDirs {
		found, err := listWorkflowFiles(ctx, repoPath, commitSHA, dir)
		if err != nil {
			continue
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.started[key]; ok {
		return true
	}
	r.started[key] = struct{}{}
	return false
}

func runKey(eventID, commit, workflow string) string {
	return eventID + ":" + commit + ":" + workflow
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
	v := tags.GetFirst([]string{key, ""})
	if v == nil || len(*v) < 2 {
		return ""
	}
	return (*v)[1]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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

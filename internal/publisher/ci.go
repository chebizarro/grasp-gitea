// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip34"

	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// ---------------------------------------------------------------------------
// Dedup cache — bounded, with periodic TTL sweep
// ---------------------------------------------------------------------------

const (
	dedupMaxAge         = 10 * time.Minute
	dedupSweepThreshold = 500
)

// ciDedup tracks recently processed event IDs to prevent duplicate
// duplicate ContextVM publications when the same state event arrives from
// multiple relays. Entries are evicted after dedupMaxAge.
type ciDedup struct {
	mu   sync.Mutex
	seen map[string]int64 // eventID → unix timestamp
}

func newCIDedup() *ciDedup {
	return &ciDedup{seen: make(map[string]int64)}
}

// MarkSeen records an event ID and reports whether it was already known.
func (d *ciDedup) MarkSeen(eventID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Periodic sweep: evict stale entries.
	if len(d.seen) >= dedupSweepThreshold {
		cutoff := time.Now().Unix() - int64(dedupMaxAge.Seconds())
		for id, ts := range d.seen {
			if ts < cutoff {
				delete(d.seen, id)
			}
		}
	}

	if _, ok := d.seen[eventID]; ok {
		return true
	}
	d.seen[eventID] = time.Now().Unix()
	return false
}

// Len returns the current number of tracked entries (for testing).
func (d *ciDedup) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

// ---------------------------------------------------------------------------
// CI configuration
// ---------------------------------------------------------------------------

// SetCIConfig enables CI workflow-run publishing and configures which
// repos are allowed to trigger CI. triggerRepos entries are
// "owner/repo-id" strings; a single "*" entry means all repos.
func (s *Service) SetCIConfig(enabled bool, triggerRepos []string) {
	s.ciEnabled = enabled
	s.ciTriggerRepos = triggerRepos
	s.ciDedup = newCIDedup()
}

// CIEnabled reports whether CI workflow-run publishing is active.
func (s *Service) CIEnabled() bool {
	return s.Enabled() && s.ciEnabled
}

// ---------------------------------------------------------------------------
// State-event handler
// ---------------------------------------------------------------------------

// HandleStateEventCI inspects an incoming kind:30618 repository state
// event, detects changed branches and release tags, checks for CI workflow files, and
// publishes a canonical ContextVM ci/workflow-run request for each qualifying
// change.
//
// Call this BEFORE proactive sync so that local refs still reflect the
// previous state for change detection. The caller must serialise access
// per repo (e.g. via a per-repo mutex) to avoid races with proactive
// sync running in a concurrent goroutine.
func (s *Service) HandleStateEventCI(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	if !s.CIEnabled() {
		return nil
	}
	if ev == nil || ev.Kind != relay.KindRepositoryState {
		return nil
	}

	// Dedup: skip if we already processed this exact event (e.g. seen
	// from a second relay).
	if s.ciDedup.MarkSeen(ev.ID.Hex()) {
		return nil
	}

	repoID := evTagValue(ev.Tags, "d")
	if repoID == "" {
		return nil
	}

	mapping, err := s.resolveStateEventMapping(ctx, ev, repoID)
	if err == sql.ErrNoRows {
		return nil // not provisioned — skip silently
	}
	if err != nil {
		return fmt.Errorf("lookup mapping for CI: %w", err)
	}

	if !s.isRepoCIAllowed(mapping.Owner, repoID) {
		return nil
	}

	repoPath := filepath.Join(s.repositoriesDir, mapping.Owner, mapping.RepoName+".git")

	// Snapshot current local refs to detect what changed.
	_, localBranches, localTags, localErr := snapshotRefs(ctx, repoPath)
	if localErr != nil {
		s.logger.Debug("CI: cannot snapshot local refs, skipping",
			"repo", repoID, "error", localErr)
		return nil
	}

	// Parse the incoming state to get the branch→SHA map.
	state := nip34.ParseRepositoryState(*ev)

	var published int
	for branch, newSHA := range state.Branches {
		if err := ctx.Err(); err != nil {
			return err // honour shutdown
		}

		if localBranches[branch] == newSHA {
			continue // unchanged
		}

		workflows, wfErr := detectWorkflows(ctx, repoPath, newSHA)
		if wfErr != nil {
			s.logger.Debug("CI: workflow detection error",
				"repo", repoID, "branch", branch, "error", wfErr)
			continue
		}
		if len(workflows) == 0 {
			continue
		}

		for _, wf := range workflows {
			if err := ctx.Err(); err != nil {
				return err
			}

			wfEv, buildErr := s.buildWorkflowRunEvent(
				mapping.Pubkey, repoID, newSHA, branch, wf, sourceRelay)
			if buildErr != nil {
				s.logger.Warn("failed to build workflow run event",
					"repo", repoID, "branch", branch,
					"workflow", wf, "error", buildErr)
				continue
			}

			if pubErr := s.publishToRelays(ctx, wfEv); pubErr != nil {
				metrics.IncCIWorkflowRunsFailed()
				s.logger.Warn("failed to publish workflow run event",
					"repo", repoID, "branch", branch,
					"workflow", wf, "error", pubErr)
				continue
			}

			published++
			metrics.IncCIWorkflowRunsPublished()
			s.logger.Info("published CI workflow run event",
				"repo", repoID, "branch", branch,
				"workflow", wf, "commit", newSHA,
				"event_id", wfEv.ID)
		}
	}

	for tag, newSHA := range state.Tags {
		if err := ctx.Err(); err != nil {
			return err
		}
		if localTags[tag] == newSHA {
			continue
		}
		workflows, wfErr := detectTagWorkflows(ctx, repoPath, newSHA, tag)
		if wfErr != nil {
			s.logger.Debug("CI: workflow detection error", "repo", repoID, "tag", tag, "error", wfErr)
			continue
		}
		for _, wf := range workflows {
			wfEv, buildErr := s.buildWorkflowRunEventForRef(
				mapping.Pubkey, repoID, newSHA, "refs/tags/"+tag, wf, sourceRelay, "nip34-tag", mapping.CloneURL)
			if buildErr != nil {
				s.logger.Warn("failed to build release workflow run event", "repo", repoID, "tag", tag, "workflow", wf, "error", buildErr)
				continue
			}
			if pubErr := s.publishToRelays(ctx, wfEv); pubErr != nil {
				metrics.IncCIWorkflowRunsFailed()
				s.logger.Warn("failed to publish release workflow run event", "repo", repoID, "tag", tag, "workflow", wf, "error", pubErr)
				continue
			}
			published++
			metrics.IncCIWorkflowRunsPublished()
			s.logger.Info("published release CI workflow run event", "repo", repoID, "tag", tag, "workflow", wf, "commit", newSHA, "event_id", wfEv.ID)
		}
	}

	if published == 0 {
		s.logger.Debug("no CI workflow runs triggered", "repo", repoID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

// isRepoCIAllowed checks whether a repo is in the CI trigger allowlist.
func (s *Service) isRepoCIAllowed(owner, repoID string) bool {
	for _, entry := range s.ciTriggerRepos {
		if entry == "*" {
			return true
		}
		if entry == owner+"/"+repoID {
			return true
		}
	}
	return false
}

// HandleWebhookPushCI emits workflow-run events directly from a Gitea push
// webhook using the before/after SHA pair, which is necessary for local push
// flows where the repository refs have already advanced before a relay state
// event is observed again.
func (s *Service) HandleWebhookPushCI(ctx context.Context, giteaRepoID int64, ref, before, after, sourceRelay string) error {
	if !s.CIEnabled() {
		return nil
	}
	if !strings.HasPrefix(ref, "refs/heads/") && !strings.HasPrefix(ref, "refs/tags/") {
		return nil
	}
	if after == "" || after == before || strings.Trim(after, "0") == "" {
		return nil
	}

	mapping, err := s.store.GetMappingByGiteaRepoID(ctx, giteaRepoID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup mapping by gitea repo id %d: %w", giteaRepoID, err)
	}
	if !s.isRepoCIAllowed(mapping.Owner, mapping.RepoID) {
		return nil
	}

	refName := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
	triggeredBy := "push"
	if strings.HasPrefix(ref, "refs/tags/") {
		triggeredBy = "webhook-tag"
	}
	repoPath := filepath.Join(s.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	workflows, wfErr := detectWorkflows(ctx, repoPath, after)
	if wfErr != nil {
		s.logger.Debug("CI: workflow detection error on webhook push",
			"repo", mapping.RepoID, "ref", ref, "error", wfErr)
		return nil
	}
	if len(workflows) == 0 {
		s.logger.Debug("no CI workflow runs triggered on webhook push", "repo", mapping.RepoID, "ref", ref)
		return nil
	}

	for _, wf := range workflows {
		wfEv, buildErr := s.buildWorkflowRunEventForRef(mapping.Pubkey, mapping.RepoID, after, ref, wf, sourceRelay, triggeredBy, mapping.CloneURL)
		if buildErr != nil {
			s.logger.Warn("failed to build workflow run event from webhook push",
				"repo", mapping.RepoID, "ref", ref,
				"workflow", wf, "error", buildErr)
			continue
		}
		if pubErr := s.publishToRelays(ctx, wfEv); pubErr != nil {
			metrics.IncCIWorkflowRunsFailed()
			s.logger.Warn("failed to publish workflow run event from webhook push",
				"repo", mapping.RepoID, "ref", ref, "name", refName,
				"workflow", wf, "error", pubErr)
			continue
		}
		metrics.IncCIWorkflowRunsPublished()
		s.logger.Info("published CI workflow run event",
			"repo", mapping.RepoID, "ref", ref, "name", refName,
			"workflow", wf, "commit", after,
			"event_id", wfEv.ID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Workflow detection
// ---------------------------------------------------------------------------

// workflowDirs lists the directories scanned for CI workflow definitions.
// Each entry is checked in order; all discovered workflows are returned.
//
//   - .gitea/workflows  — Gitea / Forgejo Actions workflows
//   - .github/workflows — GitHub Actions and compatible runners
//   - .hive/workflows   — legacy Nostr / Hive CI pipelines
var workflowDirs = []string{
	".gitea/workflows",
	".github/workflows",
	".hive/workflows",
}

// detectWorkflows lists CI workflow files at the given commit SHA in a
// bare git repository. It scans every directory in workflowDirs and
// returns paths for any .yml/.yaml files found. Returns nil when no
// workflow directories exist or they contain no matching files.
func detectWorkflows(ctx context.Context, repoPath string, commitSHA string) ([]string, error) {
	var workflows []string
	for _, dir := range workflowDirs {
		found, err := listWorkflowFiles(ctx, repoPath, commitSHA, dir)
		if err != nil {
			continue // directory absent or git error — try next
		}
		workflows = append(workflows, found...)
	}
	return workflows, nil
}

// detectTagWorkflows returns only workflows whose GitHub-compatible trigger
// accepts the released tag. Merely existing under a workflow directory is not
// enough: branch-only CI must not fan out when a NIP-34 tag is published.
func detectTagWorkflows(ctx context.Context, repoPath, commitSHA, tag string) ([]string, error) {
	workflows, err := detectWorkflows(ctx, repoPath, commitSHA)
	if err != nil {
		return nil, err
	}
	var selected []string
	for _, workflow := range workflows {
		out, showErr := exec.CommandContext(ctx, "git", "--git-dir", repoPath,
			"show", commitSHA+":"+workflow).Output()
		if showErr != nil {
			continue
		}
		if workflowAcceptsTag(out, tag) {
			selected = append(selected, workflow)
		}
	}
	return selected, nil
}

func workflowAcceptsTag(data []byte, tag string) bool {
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || len(document.Content) == 0 {
		return false
	}
	on := mappingValue(document.Content[0], "on")
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == "push"
	case yaml.SequenceNode:
		for _, trigger := range on.Content {
			if trigger.Value == "push" {
				return true
			}
		}
		return false
	case yaml.MappingNode:
		push := mappingValue(on, "push")
		if push == nil {
			return false
		}
		if push.Kind == yaml.ScalarNode && (push.Tag == "!!null" || push.Value == "") {
			return true
		}
		if push.Kind != yaml.MappingNode {
			return true
		}
		tags := mappingValue(push, "tags")
		if tags == nil {
			// GitHub does not run tag refs when a push trigger restricts branches.
			return mappingValue(push, "branches") == nil && mappingValue(push, "branches-ignore") == nil
		}
		return yamlPatternsMatch(tags, tag)
	default:
		return false
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func yamlPatternsMatch(node *yaml.Node, value string) bool {
	patterns := node.Content
	if node.Kind == yaml.ScalarNode {
		patterns = []*yaml.Node{node}
	}
	matched := false
	for _, patternNode := range patterns {
		pattern := patternNode.Value
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		ok, err := path.Match(pattern, value)
		if err != nil || !ok {
			continue
		}
		matched = !negated
	}
	return matched
}

// listWorkflowFiles returns .yml/.yaml file paths under a single
// directory tree at the given commit in a bare repo. Returned paths
// are validated to reside within the expected directory.
func listWorkflowFiles(ctx context.Context, repoPath, commitSHA, dir string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath,
		"ls-tree", "-r", "--name-only", commitSHA, "--", dir).Output()
	if err != nil {
		return nil, err
	}

	prefix := dir + "/"
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, ".yml") && !strings.HasSuffix(line, ".yaml") {
			continue
		}
		// Defence-in-depth: ensure the path stays within the expected
		// directory after normalisation (git should guarantee this, but
		// we verify anyway).
		cleaned := path.Clean(line)
		if !strings.HasPrefix(cleaned, prefix) {
			continue
		}
		files = append(files, cleaned)
	}
	return files, nil
}

// ---------------------------------------------------------------------------
// Event construction
// ---------------------------------------------------------------------------

// buildWorkflowRunEvent creates the legacy Hive CI workflow-run event consumed
// by Bahia's authenticated HiveCI bridge and signs it with the bridge key. The
// JSON-RPC-shaped content remains additive metadata; routing uses the signed
// kind-5401 tags and does not require decoding the content.
func (s *Service) buildWorkflowRunEvent(ownerPubkey, repoID, commitSHA, branch, workflow, relayHint string) (*nostr.Event, error) {
	return s.buildWorkflowRunEventForRef(ownerPubkey, repoID, commitSHA, "refs/heads/"+branch, workflow, relayHint, "push", "")
}

func (s *Service) buildWorkflowRunEventForRef(ownerPubkey, repoID, commitSHA, ref, workflow, relayHint, triggeredBy, repository string) (*nostr.Event, error) {
	method, ok := cascadia.ContextVMMethods["ci/workflow-run"]
	if !ok {
		return nil, fmt.Errorf("generated binding missing ci/workflow-run")
	}
	refName := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
	payload := cascadia.HiveCiWorkflowV1Payload{
		Workflow: workflow, Commit: commitSHA, Branch: refName, TriggeredBy: triggeredBy,
	}
	if err := payload.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s payload: %w", method.Schema, err)
	}
	request := struct {
		JSONRPC string                           `json:"jsonrpc"`
		ID      string                           `json:"id"`
		Method  string                           `json:"method"`
		Params  cascadia.HiveCiWorkflowV1Payload `json:"params"`
	}{
		JSONRPC: "2.0",
		ID:      fmt.Sprintf("grasp:%s:%s:%s", repoID, commitSHA, workflow),
		Method:  method.Name,
		Params:  payload,
	}
	content, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal %s request: %w", method.Name, err)
	}
	aTag := fmt.Sprintf("%d:%s:%s",
		relay.KindRepositoryAnnouncement, ownerPubkey, repoID)

	ev := &nostr.Event{
		PubKey:    s.bridgePubKeyBytes,
		CreatedAt: nostr.Now(),
		Kind:      relay.KindHiveWorkflowRun,
		Tags: nostr.Tags{
			{"a", aTag},
			{"p", ownerPubkey},
			{"commit", commitSHA},
			{"branch", refName},
			{"ref", ref},
			{"workflow", workflow},
			{"triggered-by", triggeredBy},
			{"publisher", s.bridgePubKey},
			{"relay", relayHint},
		},
		Content: string(content),
	}
	if strings.HasPrefix(ref, "refs/tags/") {
		ev.Tags = append(ev.Tags, nostr.Tag{"tag", refName}, nostr.Tag{"release", "true"})
	}
	if strings.TrimSpace(repository) != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"repo", strings.TrimSpace(repository)})
	}

	if err := s.signOutbound(context.Background(), ev); err != nil {
		return nil, fmt.Errorf("sign workflow run event: %w", err)
	}
	return ev, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// evTagValue extracts the first value for a tag key from nostr tags.
func evTagValue(tags nostr.Tags, key string) string {
	v := tags.Find(key)
	if v == nil || len(v) < 2 {
		return ""
	}
	return v[1]
}

func (s *Service) resolveStateEventMapping(ctx context.Context, ev *nostr.Event, repoID string) (store.Mapping, error) {
	candidatePubkeys := []string{}
	if ownerPubkey := evTagValue(ev.Tags, "p"); ownerPubkey != "" {
		candidatePubkeys = append(candidatePubkeys, ownerPubkey)
	}
	if ev != nil && ev.PubKey != (nostr.PubKey{}) {
		candidatePubkeys = append(candidatePubkeys, ev.PubKey.Hex())
	}

	seen := map[string]bool{}
	for _, pubkey := range candidatePubkeys {
		if pubkey == "" || seen[pubkey] {
			continue
		}
		seen[pubkey] = true
		pk, err := nostr.PubKeyFromHex(pubkey)
		if err != nil {
			continue
		}
		npub := nip19.EncodeNpub(pk)
		mapping, err := s.store.GetMapping(ctx, npub, repoID)
		if err == nil {
			return mapping, nil
		}
		if err != sql.ErrNoRows {
			return store.Mapping{}, err
		}
	}
	return store.Mapping{}, sql.ErrNoRows
}

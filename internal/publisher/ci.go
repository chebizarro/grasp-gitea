// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/relay"
)

// ---------------------------------------------------------------------------
// Dedup cache — bounded, with periodic TTL sweep
// ---------------------------------------------------------------------------

const (
	dedupMaxAge         = 10 * time.Minute
	dedupSweepThreshold = 500
)

// ciDedup tracks recently processed event IDs to prevent duplicate
// kind:5401 publications when the same state event arrives from
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
// event, detects changed branches, checks for CI workflow files, and
// publishes a kind:5401 WorkflowRun event for each qualifying change.
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
	if s.ciDedup.MarkSeen(ev.ID) {
		return nil
	}

	repoID := evTagValue(ev.Tags, "d")
	if repoID == "" {
		return nil
	}

	npub, err := nip19.EncodePublicKey(ev.PubKey)
	if err != nil {
		return fmt.Errorf("encode pubkey to npub: %w", err)
	}

	mapping, err := s.store.GetMapping(ctx, npub, repoID)
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
	_, localBranches, _, localErr := snapshotRefs(ctx, repoPath)
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

// ---------------------------------------------------------------------------
// Workflow detection
// ---------------------------------------------------------------------------

// workflowDirs lists the directories scanned for CI workflow definitions.
// Each entry is checked in order; all discovered workflows are returned.
//
//   - .github/workflows — GitHub Actions and compatible runners
//     (Gitea Actions, Forgejo Actions, etc.)
//   - .hive/workflows   — Nostr / Hive CI pipelines
var workflowDirs = []string{
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

// buildWorkflowRunEvent creates a kind:5401 WorkflowRun event and signs
// it with the bridge key.
func (s *Service) buildWorkflowRunEvent(ownerPubkey, repoID, commitSHA, branch, workflow, relayHint string) (*nostr.Event, error) {
	aTag := fmt.Sprintf("%d:%s:%s",
		relay.KindRepositoryAnnouncement, ownerPubkey, repoID)

	ev := &nostr.Event{
		PubKey:    s.bridgePubKey,
		CreatedAt: nostr.Now(),
		Kind:      relay.KindWorkflowRun,
		Tags: nostr.Tags{
			{"a", aTag},
			{"p", ownerPubkey},
			{"commit", commitSHA},
			{"branch", branch},
			{"workflow", workflow},
			{"relay", relayHint},
		},
		Content: "",
	}

	if err := ev.Sign(s.bridgePrivKey); err != nil {
		return nil, fmt.Errorf("sign workflow run event: %w", err)
	}
	return ev, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// evTagValue extracts the first value for a tag key from nostr tags.
func evTagValue(tags nostr.Tags, key string) string {
	v := tags.GetFirst([]string{key, ""})
	if v == nil || len(*v) < 2 {
		return ""
	}
	return (*v)[1]
}

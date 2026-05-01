// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// Service republishes NIP-34 repository announcement and state events
// to Nostr relays when Gitea mirror syncs complete.
type Service struct {
	store           *store.SQLiteStore
	logger          *slog.Logger
	repositoriesDir string
	relayURLs       []string

	bridgePrivKey string
	bridgePubKey  string

	repoMu    sync.Mutex
	repoLocks map[int64]*sync.Mutex
}

// New creates a publisher service. If bridgeNsec is empty, the service
// will be a no-op (MirrorPublishEnabled should be checked first).
func New(bridgeNsec string, st *store.SQLiteStore, relayURLs []string, repositoriesDir string, logger *slog.Logger) (*Service, error) {
	s := &Service{
		store:           st,
		logger:          logger,
		repositoriesDir: repositoriesDir,
		relayURLs:       relayURLs,
		repoLocks:       make(map[int64]*sync.Mutex),
	}

	if bridgeNsec == "" {
		return s, nil
	}

	typ, v, err := nip19.Decode(bridgeNsec)
	if err != nil {
		return nil, fmt.Errorf("decode BRIDGE_NSEC: %w", err)
	}
	if typ != "nsec" {
		return nil, fmt.Errorf("BRIDGE_NSEC must be an nsec, got %s", typ)
	}
	privKey, ok := v.(string)
	if !ok || privKey == "" {
		return nil, fmt.Errorf("invalid decoded nsec value")
	}

	pubKey, err := nostr.GetPublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key from BRIDGE_NSEC: %w", err)
	}

	s.bridgePrivKey = privKey
	s.bridgePubKey = pubKey
	logger.Info("publisher initialized", "bridge_pubkey", pubKey)
	return s, nil
}

// Enabled reports whether the publisher has a signing key configured.
func (s *Service) Enabled() bool {
	return s.bridgePrivKey != ""
}

// lockRepo acquires a per-repo mutex for serializing concurrent callbacks.
func (s *Service) lockRepo(giteaRepoID int64) *sync.Mutex {
	s.repoMu.Lock()
	mu, ok := s.repoLocks[giteaRepoID]
	if !ok {
		mu = &sync.Mutex{}
		s.repoLocks[giteaRepoID] = mu
	}
	s.repoMu.Unlock()
	mu.Lock()
	return mu
}

// RepublishForGiteaRepo looks up the mapping for a Gitea repo, republishes
// the cached owner-signed announcement if new, snapshots current refs, and
// publishes a bridge-signed NIP-34 state event if the digest changed.
func (s *Service) RepublishForGiteaRepo(ctx context.Context, giteaRepoID int64) error {
	if !s.Enabled() {
		return nil
	}

	mu := s.lockRepo(giteaRepoID)
	defer mu.Unlock()

	mapping, err := s.store.GetMappingByGiteaRepoID(ctx, giteaRepoID)
	if err == sql.ErrNoRows {
		s.logger.Debug("mirror sync callback for unknown repo", "gitea_repo_id", giteaRepoID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup mapping by gitea repo id %d: %w", giteaRepoID, err)
	}

	if mapping.AnnouncementEventJSON == "" {
		s.logger.Debug("repo not eligible for republishing (no cached announcement)", "owner", mapping.Owner, "repo", mapping.RepoID)
		return nil
	}

	now := time.Now().UTC()

	// Republish the cached owner-signed announcement if not already done.
	if mapping.AnnouncementEventID != "" && mapping.AnnouncementEventID != mapping.LastRepublishedAnnouncementID {
		if err := s.republishAnnouncement(ctx, &mapping, now); err != nil {
			s.logger.Warn("failed to republish announcement", "owner", mapping.Owner, "repo", mapping.RepoID, "error", err)
			// Continue to state publishing regardless.
		}
	}

	// Snapshot current repo refs from disk.
	repoPath := filepath.Join(s.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	head, branches, tags, err := snapshotRefs(ctx, repoPath)
	if err != nil {
		return fmt.Errorf("snapshot refs for %s/%s: %w", mapping.Owner, mapping.RepoName, err)
	}

	digest := computeDigest(head, branches, tags)
	if digest == mapping.LastStateDigest {
		s.logger.Debug("state unchanged, skipping publish", "owner", mapping.Owner, "repo", mapping.RepoID, "digest", digest)
		return nil
	}

	// Build and sign a new state event.
	stateEvent, err := s.buildStateEvent(mapping.RepoID, head, branches, tags)
	if err != nil {
		return fmt.Errorf("build state event: %w", err)
	}

	if err := s.publishToRelays(ctx, stateEvent); err != nil {
		return fmt.Errorf("publish state event: %w", err)
	}

	if err := s.store.RecordStatePublished(ctx, mapping.Npub, mapping.RepoID, digest, stateEvent.ID, now); err != nil {
		s.logger.Warn("failed to record state publish", "error", err)
	}

	s.logger.Info("published NIP-34 state event",
		"owner", mapping.Owner, "repo", mapping.RepoID,
		"event_id", stateEvent.ID, "digest", digest,
		"branches", len(branches), "tags", len(tags))
	return nil
}

// republishAnnouncement publishes the cached owner-signed announcement event.
func (s *Service) republishAnnouncement(ctx context.Context, mapping *store.Mapping, now time.Time) error {
	var ev nostr.Event
	if err := json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &ev); err != nil {
		return fmt.Errorf("unmarshal cached announcement: %w", err)
	}

	if err := s.publishToRelays(ctx, &ev); err != nil {
		return err
	}

	if err := s.store.RecordAnnouncementRepublished(ctx, mapping.Npub, mapping.RepoID, ev.ID, now); err != nil {
		s.logger.Warn("failed to record announcement republish", "error", err)
	}

	s.logger.Info("republished owner-signed announcement",
		"owner", mapping.Owner, "repo", mapping.RepoID, "event_id", ev.ID)
	return nil
}

// buildStateEvent creates a new NIP-34 repository state event and signs it
// with the bridge key.
func (s *Service) buildStateEvent(repoID string, head string, branches map[string]string, tags map[string]string) (*nostr.Event, error) {
	// Build tags in deterministic order.
	eventTags := make(nostr.Tags, 0, 2+len(branches)+len(tags))
	eventTags = append(eventTags, nostr.Tag{"d", repoID})

	branchNames := sortedKeys(branches)
	for _, name := range branchNames {
		eventTags = append(eventTags, nostr.Tag{"refs/heads/" + name, branches[name]})
	}

	tagNames := sortedKeys(tags)
	for _, name := range tagNames {
		eventTags = append(eventTags, nostr.Tag{"refs/tags/" + name, tags[name]})
	}

	if head != "" {
		eventTags = append(eventTags, nostr.Tag{"HEAD", "ref: refs/heads/" + head})
	}

	ev := &nostr.Event{
		PubKey:    s.bridgePubKey,
		CreatedAt: nostr.Now(),
		Kind:      relay.KindRepositoryState,
		Tags:      eventTags,
	}
	if err := ev.Sign(s.bridgePrivKey); err != nil {
		return nil, fmt.Errorf("sign state event: %w", err)
	}
	return ev, nil
}

// publishToRelays publishes an event to all configured relays.
// Returns an error only if no relay accepted the event.
func (s *Service) publishToRelays(ctx context.Context, ev *nostr.Event) error {
	if len(s.relayURLs) == 0 {
		return fmt.Errorf("no relay URLs configured")
	}

	var succeeded int
	for _, url := range s.relayURLs {
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		r, err := nostr.RelayConnect(pubCtx, url)
		if err != nil {
			cancel()
			s.logger.Warn("relay connect failed", "relay", url, "error", err)
			continue
		}
		err = r.Publish(pubCtx, *ev)
		r.Close()
		cancel()
		if err != nil {
			s.logger.Warn("relay publish failed", "relay", url, "event", ev.ID, "error", err)
			continue
		}
		succeeded++
	}

	if succeeded == 0 {
		return fmt.Errorf("event %s rejected by all %d relays", ev.ID, len(s.relayURLs))
	}
	return nil
}

// snapshotRefs reads the current HEAD, branches, and tags from a bare git repo.
func snapshotRefs(ctx context.Context, repoPath string) (head string, branches map[string]string, tags map[string]string, err error) {
	branches = make(map[string]string)
	tags = make(map[string]string)

	// Read HEAD.
	headOut, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "--quiet", "--short", "HEAD").Output()
	if err == nil {
		head = strings.TrimSpace(string(headOut))
	}
	// Failure is OK for empty repos.

	// Read all refs.
	refsOut, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").Output()
	if err != nil {
		return "", nil, nil, fmt.Errorf("for-each-ref: %w", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(refsOut)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		refName, sha := parts[0], parts[1]
		if strings.HasSuffix(refName, "^{}") {
			continue
		}
		if strings.HasPrefix(refName, "refs/heads/") {
			branches[strings.TrimPrefix(refName, "refs/heads/")] = sha
		} else if strings.HasPrefix(refName, "refs/tags/") {
			tags[strings.TrimPrefix(refName, "refs/tags/")] = sha
		}
	}

	return head, branches, tags, nil
}

// computeDigest produces a deterministic hash from the repo's current refs.
func computeDigest(head string, branches map[string]string, tags map[string]string) string {
	var b strings.Builder
	b.WriteString("HEAD=" + head + "\n")

	branchNames := sortedKeys(branches)
	for _, name := range branchNames {
		b.WriteString("B:" + name + "=" + branches[name] + "\n")
	}

	tagNames := sortedKeys(tags)
	for _, name := range tagNames {
		b.WriteString("T:" + name + "=" + tags[name] + "\n")
	}

	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

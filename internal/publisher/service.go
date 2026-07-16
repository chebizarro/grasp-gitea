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

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
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

	bridgeSigner      ServerSigner
	bridgePrivKey     string // legacy dev/test fallback
	bridgePubKey      string
	bridgePubKeyBytes nostr.PubKey

	ownerStateSigner StateSigner
	ownerStateOutbox StateOutbox

	repoMu    sync.Mutex
	repoLocks map[int64]*sync.Mutex

	ciEnabled      bool
	ciTriggerRepos []string
	ciDedup        *ciDedup
}

// StateSigner reports whether user grant signing is available.
type StateSigner interface {
	Enabled() bool
}

// StateOutbox persists unsigned state events for asynchronous owner signing.
type StateOutbox interface {
	Enqueue(ctx context.Context, kind int, authorPubkey string, scope string, unsignedEvent *nostr.Event, dedupeKey string) error
}

// ServerSigner signs bridge/operator-authored outbound events without exposing
// the private key to the publisher. Production should provide a Signet/NIP-46
// implementation; local nsec signing is retained only as an explicit dev fallback.
type ServerSigner interface {
	PublicKey() string
	SignEvent(ctx context.Context, ev *nostr.Event) error
}

// New creates a publisher service. If bridgeNsec is empty, bridge-signed
// publishing is disabled, but owner-signed outbox publishing can still be wired
// with SetOwnerStateSigning. This legacy constructor is the dev/test fallback.
func New(bridgeNsec string, st *store.SQLiteStore, relayURLs []string, repositoriesDir string, logger *slog.Logger) (*Service, error) {
	var signer ServerSigner
	if bridgeNsec != "" {
		local, err := NewLocalServerSigner(bridgeNsec)
		if err != nil {
			return nil, err
		}
		signer = local
	}
	return NewWithServerSigner(signer, st, relayURLs, repositoriesDir, logger), nil
}

// NewWithServerSigner creates a publisher with an already-constructed bridge
// signer, typically backed by Signet/NIP-46.
func NewWithServerSigner(signer ServerSigner, st *store.SQLiteStore, relayURLs []string, repositoriesDir string, logger *slog.Logger) *Service {
	s := &Service{
		store:           st,
		logger:          logger,
		repositoriesDir: repositoriesDir,
		relayURLs:       relayURLs,
		bridgeSigner:    signer,
		repoLocks:       make(map[int64]*sync.Mutex),
	}
	if signer != nil {
		s.bridgePubKey = signer.PublicKey()
		if pk, err := nostr.PubKeyFromHex(s.bridgePubKey); err == nil {
			s.bridgePubKeyBytes = pk
		}
		if local, ok := signer.(*localServerSigner); ok {
			s.bridgePrivKey = local.privKey.Hex()
		}
		logger.Info("publisher initialized", "bridge_pubkey", s.bridgePubKey)
	}
	return s
}

// Enabled reports whether the publisher has a bridge/server signer configured.
func (s *Service) Enabled() bool {
	return s != nil && (s.bridgeSigner != nil || s.bridgePrivKey != "")
}

// SetOwnerStateSigning wires the Phase-B outbox and signer availability check
// used to enqueue owner-authored kind:30618 state events for user signing.
func (s *Service) SetOwnerStateSigning(signer StateSigner, outbox StateOutbox) {
	s.ownerStateSigner = signer
	s.ownerStateOutbox = outbox
}

func (s *Service) ownerStateSigningConfigured() bool {
	return s.ownerStateSigner != nil && s.ownerStateSigner.Enabled() && s.ownerStateOutbox != nil && s.store != nil
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
// publishes a NIP-34 state event if the digest changed. State events prefer the
// owner's signer grant via the outbox and fall back to bridge signing when the
// signer path is unavailable or no owner grant exists yet.
func (s *Service) RepublishForGiteaRepo(ctx context.Context, giteaRepoID int64) error {
	if !s.Enabled() && !s.ownerStateSigningConfigured() {
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

	now := time.Now().UTC()

	if mapping.AnnouncementEventJSON == "" {
		s.logger.Debug("continuing state publish without cached announcement", "owner", mapping.Owner, "repo", mapping.RepoID)
	}

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

	// Build a new unsigned owner-authored state event.
	stateEvent, err := s.buildStateEvent(mapping.Pubkey, mapping.RepoID, head, branches, tags)
	if err != nil {
		return fmt.Errorf("build state event: %w", err)
	}

	enqueued, err := s.enqueueOwnerSignedState(ctx, &mapping, stateEvent, digest)
	if err != nil {
		return fmt.Errorf("enqueue owner-signed state event: %w", err)
	}
	if enqueued {
		s.logger.Info("enqueued owner-signed NIP-34 state event",
			"owner", mapping.Owner, "repo", mapping.RepoID,
			"author_pubkey", mapping.Pubkey, "digest", digest,
			"branches", len(branches), "tags", len(tags))
		return nil
	}

	return s.publishBridgeSignedState(ctx, &mapping, stateEvent, digest, now, branches, tags)
}

func (s *Service) enqueueOwnerSignedState(ctx context.Context, mapping *store.Mapping, ev *nostr.Event, digest string) (bool, error) {
	if mapping == nil || ev == nil {
		return false, fmt.Errorf("state event and mapping are required")
	}
	if !s.ownerStateSigningConfigured() {
		return false, nil
	}
	grant, err := s.store.GetSignerGrant(ctx, mapping.Pubkey)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup owner signer grant: %w", err)
	}
	if grant.Status != "active" || grant.RevokedAt != nil {
		return false, nil
	}

	dedupeKey := fmt.Sprintf("repo-state:%d:%s:%s", mapping.GiteaRepoID, mapping.RepoID, digest)
	scope := fmt.Sprintf("repo:%s/%s", mapping.Owner, mapping.RepoName)
	if err := s.ownerStateOutbox.Enqueue(ctx, relay.KindRepositoryState, mapping.Pubkey, scope, ev, dedupeKey); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) publishBridgeSignedState(ctx context.Context, mapping *store.Mapping, unsigned *nostr.Event, digest string, now time.Time, branches map[string]string, tags map[string]string) error {
	if !s.Enabled() {
		s.logger.Warn("skipping NIP-34 state fallback because bridge signing is disabled", "owner", mapping.Owner, "repo", mapping.RepoID, "digest", digest)
		return nil
	}

	stateEvent := cloneStateEvent(unsigned)
	stateEvent.PubKey = s.bridgePubKeyBytes
	stateEvent.ID = nostr.ID{}
	stateEvent.Sig = [64]byte{}
	if err := s.signOutbound(ctx, stateEvent); err != nil {
		return fmt.Errorf("sign state event with bridge signer: %w", err)
	}

	metrics.IncBridgeSignedFallback()
	s.logger.Warn("bridge-signed fallback for NIP-34 state event", "owner", mapping.Owner, "repo", mapping.RepoID, "digest", digest)

	if err := s.publishToRelays(ctx, stateEvent); err != nil {
		return fmt.Errorf("publish state event: %w", err)
	}

	if err := s.store.RecordStatePublished(ctx, mapping.Npub, mapping.RepoID, digest, stateEvent.ID.Hex(), now); err != nil {
		s.logger.Warn("failed to record state publish", "error", err)
	}

	s.logger.Info("published bridge-signed NIP-34 state event",
		"owner", mapping.Owner, "repo", mapping.RepoID,
		"event_id", stateEvent.ID.Hex(), "digest", digest,
		"branches", len(branches), "tags", len(tags))
	return nil
}

func cloneStateEvent(ev *nostr.Event) *nostr.Event {
	if ev == nil {
		return nil
	}
	clone := *ev
	clone.Tags = make(nostr.Tags, len(ev.Tags))
	for i, tag := range ev.Tags {
		clone.Tags[i] = append(nostr.Tag(nil), tag...)
	}
	return &clone
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

	if err := s.store.RecordAnnouncementRepublished(ctx, mapping.Npub, mapping.RepoID, ev.ID.Hex(), now); err != nil {
		s.logger.Warn("failed to record announcement republish", "error", err)
	}

	s.logger.Info("republished owner-signed announcement",
		"owner", mapping.Owner, "repo", mapping.RepoID, "event_id", ev.ID.Hex())
	return nil
}

// buildStateEvent creates a new unsigned owner-authored NIP-34 repository state event.
func (s *Service) buildStateEvent(ownerPubkey string, repoID string, head string, branches map[string]string, tags map[string]string) (*nostr.Event, error) {
	var ownerPK nostr.PubKey
	if ownerPubkey != "" {
		pk, err := nostr.PubKeyFromHex(ownerPubkey)
		if err != nil {
			return nil, fmt.Errorf("invalid owner pubkey %q: %w", ownerPubkey, err)
		}
		ownerPK = pk
	}

	// Build tags in deterministic order.
	eventTags := make(nostr.Tags, 0, 3+len(branches)+len(tags))
	eventTags = append(eventTags, nostr.Tag{"d", repoID})
	if ownerPubkey != "" {
		eventTags = append(eventTags, nostr.Tag{"p", ownerPubkey})
	}

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

	return &nostr.Event{
		PubKey:    ownerPK,
		CreatedAt: nostr.Now(),
		Kind:      relay.KindRepositoryState,
		Tags:      eventTags,
	}, nil
}

// PublishEvent signs and publishes an arbitrary event to all configured relays.
// Used by the webhook handler to publish NIP-34 events (PRs, issues, patches, labels).
func (s *Service) PublishEvent(ctx context.Context, ev *nostr.Event) error {
	if !s.Enabled() {
		return fmt.Errorf("publisher not enabled")
	}

	// Set pubkey and sign with the configured server signer.
	ev.PubKey = s.bridgePubKeyBytes
	if err := s.signOutbound(ctx, ev); err != nil {
		return fmt.Errorf("sign event: %w", err)
	}

	return s.publishToRelays(ctx, ev)
}

func (s *Service) signOutbound(ctx context.Context, ev *nostr.Event) error {
	if !s.Enabled() {
		return fmt.Errorf("publisher not enabled")
	}
	ev.PubKey = s.bridgePubKeyBytes
	ev.ID = nostr.ID{}
	ev.Sig = [64]byte{}
	if s.bridgeSigner != nil {
		return s.bridgeSigner.SignEvent(ctx, ev)
	}
	sk, err := nostr.SecretKeyFromHex(s.bridgePrivKey)
	if err != nil {
		return fmt.Errorf("invalid bridge private key: %w", err)
	}
	return ev.Sign(sk)
}

// PublishSigned publishes an already-signed event to all configured relays.
// It intentionally does not sign or mutate the event; Phase-B outbox rows are
// signed by the user's NIP-46 grant before reaching this method.
func (s *Service) PublishSigned(ctx context.Context, ev *nostr.Event) error {
	if ev == nil {
		return fmt.Errorf("event is required")
	}
	return s.publishToRelays(ctx, ev)
}

// FetchEvent retrieves a single event by ID from the configured relays.
// It queries relays in order and returns the first match. It returns
// (nil, nil) when the event is not found on any relay (a normal condition,
// not an error), and a non-nil error only when no relay could be queried.
func (s *Service) FetchEvent(ctx context.Context, id string) (*nostr.Event, error) {
	if len(s.relayURLs) == 0 {
		return nil, fmt.Errorf("no relay URLs configured")
	}

	eid, err := nostr.IDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid event id %q: %w", id, err)
	}

	var queried int
	for _, url := range s.relayURLs {
		qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		r, err := nostr.RelayConnect(qCtx, url, nostr.RelayOptions{})
		if err != nil {
			cancel()
			s.logger.Warn("relay connect failed for fetch", "relay", url, "error", err)
			continue
		}
		queried++
		var found *nostr.Event
		for ev := range r.QueryEvents(nostr.Filter{IDs: []nostr.ID{eid}, Limit: 1}) {
			e := ev
			found = &e
			break
		}
		r.Close()
		cancel()
		if found != nil {
			return found, nil
		}
	}

	if queried == 0 {
		return nil, fmt.Errorf("event %s: all %d relays unreachable", id, len(s.relayURLs))
	}
	return nil, nil // queried successfully but not found
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
		r, err := nostr.RelayConnect(pubCtx, url, nostr.RelayOptions{})
		if err != nil {
			cancel()
			s.logger.Warn("relay connect failed", "relay", url, "error", err)
			continue
		}
		err = r.Publish(pubCtx, *ev)
		r.Close()
		cancel()
		if err != nil {
			s.logger.Warn("relay publish failed", "relay", url, "event", ev.ID.Hex(), "error", err)
			continue
		}
		succeeded++
	}

	if succeeded == 0 {
		return fmt.Errorf("event %s rejected by all %d relays", ev.ID.Hex(), len(s.relayURLs))
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

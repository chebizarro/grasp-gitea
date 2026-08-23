//go:build full

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/nostrauthz"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/purgatory"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type hostedRepoChecker interface {
	MappingExists(ctx context.Context, npub string, repoID string) (bool, error)
}

type storedEventLookup func(ctx context.Context, eventID string) (*nostr.Event, error)

type mappingLister interface {
	ListMappings(ctx context.Context) ([]store.Mapping, error)
}

type announcementLookup func(ctx context.Context, repoID string) ([]nostr.Event, error)
type stateEventResolver func(ctx context.Context, ev *nostr.Event) (store.Mapping, error)

func makeStateEventResolver(mappings mappingLister, lookup announcementLookup, trustedBridgePubkey string) stateEventResolver {
	return func(ctx context.Context, ev *nostr.Event) (store.Mapping, error) {
		if ev == nil || ev.Kind != nostr.KindRepositoryState {
			return store.Mapping{}, fmt.Errorf("repository state event is required")
		}
		if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
			return store.Mapping{}, err
		}
		repoID := ""
		if d := ev.Tags.Find("d"); d != nil && len(d) >= 2 {
			repoID = strings.TrimSpace(d[1])
		}
		if repoID == "" {
			return store.Mapping{}, fmt.Errorf("repository state event missing d tag")
		}
		if mappings == nil {
			return store.Mapping{}, fmt.Errorf("%w: mapping store unavailable", nostrauthz.ErrAuthorityUnavailable)
		}

		allMappings, err := mappings.ListMappings(ctx)
		if err != nil {
			return store.Mapping{}, fmt.Errorf("list repository mappings: %w", err)
		}
		hints := relayStateOwnerHints(ev, repoID)
		signer := ev.PubKey.Hex()
		trustedBridge := trustedBridgePubkey != "" && signer == trustedBridgePubkey

		var authorized []store.Mapping
		var resolvedAuthority bool
		for _, mapping := range allMappings {
			if mapping.RepoID != repoID || mapping.Pubkey == "" {
				continue
			}
			ownerPK, err := nostr.PubKeyFromHex(mapping.Pubkey)
			if err != nil {
				continue
			}
			mapping.Pubkey = ownerPK.Hex()
			coord := nostrauthz.RepositoryCoordinate{OwnerPubkey: mapping.Pubkey, RepoID: mapping.RepoID}.String()

			events := make([]nostr.Event, 0)
			if lookup != nil {
				lookedUp, lookupErr := lookup(ctx, mapping.RepoID)
				if lookupErr != nil {
					continue
				}
				events = append(events, lookedUp...)
			}
			if strings.TrimSpace(mapping.AnnouncementEventJSON) != "" {
				var cached nostr.Event
				if json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &cached) == nil {
					events = append(events, cached)
				}
			}

			authority, err := nostrauthz.NewResolver(events).Resolve(coord)
			if err != nil {
				continue
			}
			resolvedAuthority = true
			if authority.IsAuthorized(signer) {
				authorized = append(authorized, mapping)
				continue
			}
			// Bridge trust is explicit and state-only. The signed owner hint
			// must select this already-resolved provisioned coordinate.
			if trustedBridge {
				if _, hinted := hints[mapping.Pubkey]; hinted {
					authorized = append(authorized, mapping)
				}
			}
		}
		if len(authorized) == 0 {
			if !resolvedAuthority {
				return store.Mapping{}, fmt.Errorf("%w: no valid owner announcement for %q", nostrauthz.ErrAuthorityUnavailable, repoID)
			}
			return store.Mapping{}, fmt.Errorf("%w: signer %s for repository id %q", nostrauthz.ErrUnauthorized, signer, repoID)
		}
		if len(authorized) == 1 {
			return authorized[0], nil
		}
		var hinted []store.Mapping
		for _, mapping := range authorized {
			if _, ok := hints[mapping.Pubkey]; ok {
				hinted = append(hinted, mapping)
			}
		}
		if len(hinted) == 1 {
			return hinted[0], nil
		}
		return store.Mapping{}, fmt.Errorf("%w: signer %s and repository id %q", nostrauthz.ErrAmbiguousRepository, signer, repoID)
	}
}

func configuredBridgePubkey(cfg config.Config) (string, error) {
	// The bunker authority in a NIP-46 URL is the exact public key returned by
	// the durable Signet-backed ServerSigner, so it can be known before the
	// signer session is connected later in startup.
	if strings.TrimSpace(cfg.SignetBunkerURL) != "" {
		u, err := url.Parse(cfg.SignetBunkerURL)
		if err != nil || !strings.EqualFold(u.Scheme, "bunker") {
			return "", fmt.Errorf("invalid Signet bunker URL")
		}
		pk, err := nostr.PubKeyFromHex(u.Hostname())
		if err != nil {
			return "", fmt.Errorf("invalid Signet bunker pubkey: %w", err)
		}
		return pk.Hex(), nil
	}
	if strings.TrimSpace(cfg.BridgeNsec) != "" {
		bridgeSigner, err := publisher.NewLocalServerSigner(cfg.BridgeNsec)
		if err != nil {
			return "", err
		}
		return bridgeSigner.PublicKey(), nil
	}
	return "", nil
}

func relayStateOwnerHints(ev *nostr.Event, repoID string) map[string]struct{} {
	hints := map[string]struct{}{}
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			if pk, err := nostr.PubKeyFromHex(tag[1]); err == nil {
				hints[pk.Hex()] = struct{}{}
			}
		case "a":
			if coord, err := nostrauthz.ParseRepositoryCoordinate(tag[1]); err == nil && coord.RepoID == repoID {
				hints[coord.OwnerPubkey] = struct{}{}
			}
		}
	}
	return hints
}

func startEmbeddedRelay(ctx context.Context, cfg config.Config, policies *policy.Store, logger *slog.Logger) (string, http.Handler, func(context.Context) error, error) {
	if !cfg.EmbeddedRelay {
		return "", nil, func(context.Context) error { return nil }, nil
	}

	r := khatru.NewRelay()
	db := &lmdb.LMDBBackend{Path: cfg.EmbeddedRelayDB}
	if err := db.Init(); err != nil {
		return "", nil, nil, fmt.Errorf("init embedded relay db: %w", err)
	}

	repoStore, err := store.Open(cfg.DBPath)
	if err != nil {
		db.Close()
		return "", nil, nil, fmt.Errorf("open embedded relay mapping store: %w", err)
	}

	r.UseEventstore(db, 500)

	lookupStoredEvent := func(ctx context.Context, eventID string) (*nostr.Event, error) {
		id, err := nostr.IDFromHex(eventID)
		if err != nil {
			return nil, err
		}
		for ev := range db.QueryEvents(nostr.Filter{IDs: []nostr.ID{id}, Limit: 1}, 1) {
			e := ev
			return &e, nil
		}
		return nil, nil
	}

	announcementLookup := func(_ context.Context, repoID string) ([]nostr.Event, error) {
		filter := nostr.Filter{
			Kinds: []nostr.Kind{nostr.KindRepositoryAnnouncement},
			Tags:  nostr.TagMap{"d": []string{repoID}},
			Limit: 500,
		}
		events := make([]nostr.Event, 0)
		for ev := range db.QueryEvents(filter, 500) {
			events = append(events, ev)
		}
		return events, nil
	}
	trustedBridgePubkey, bridgeKeyErr := configuredBridgePubkey(cfg)
	if bridgeKeyErr != nil {
		logger.Warn("embedded relay cannot derive configured bridge pubkey", "error", bridgeKeyErr)
	}
	resolveStateEvent := makeStateEventResolver(repoStore, announcementLookup, trustedBridgePubkey)

	policy := makeEmbeddedRelayRejectPolicy(repoStore, lookupStoredEvent, resolveStateEvent)
	r.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
		return policy(ctx, &event)
	}

	// GRASP-01 durable purgatory: accepted repo events whose git objects have
	// not arrived are acknowledged and durably retained, but kept out of the
	// eventstore (and therefore out of normal queries) until released.
	storeEvent, replaceEvent := r.StoreEvent, r.ReplaceEvent
	releaseEvent := func(ctx context.Context, ev nostr.Event) error {
		var err error
		if ev.Kind.IsRegular() {
			err = storeEvent(ctx, ev)
		} else {
			err = replaceEvent(ctx, ev)
		}
		if err == eventstore.ErrDupEvent {
			return nil
		}
		return err
	}
	purgatorySvc := purgatory.New(repoStore, releaseEvent, logger)
	repoPathForEvent := makeRepoPathResolver(cfg, repoStore, resolveStateEvent)
	holdIfAwaitingGitData := func(ctx context.Context, ev nostr.Event) (bool, error) {
		repoPath := ""
		if ev.Kind == nostr.KindRepositoryState {
			// Admission already authorized this event, but storage happens in a
			// separate callback. Fail storage closed if authority changes or the
			// owner mapping cannot be resolved a second time; never bypass
			// purgatory by treating a resolution failure as "no repository".
			mapping, err := resolveStateEvent(ctx, &ev)
			if err != nil {
				return false, fmt.Errorf("re-resolve repository state for purgatory: %w", err)
			}
			repoName := mapping.RepoName
			if repoName == "" {
				repoName = mapping.RepoID
			}
			if mapping.Owner == "" || repoName == "" {
				return false, fmt.Errorf("resolved repository path is incomplete")
			}
			repoPath = filepath.Join(cfg.GiteaRepositoriesDir, mapping.Owner, repoName+".git")
		} else {
			repoPath = repoPathForEvent(ctx, &ev)
		}
		if repoPath == "" {
			return false, nil
		}
		return purgatorySvc.Hold(ctx, &ev, repoPath)
	}
	r.StoreEvent = func(ctx context.Context, ev nostr.Event) error {
		if held, err := holdIfAwaitingGitData(ctx, ev); err != nil {
			return err
		} else if held {
			return eventstore.ErrDupEvent // OK-acked, not stored, not broadcast
		}
		return storeEvent(ctx, ev)
	}
	r.ReplaceEvent = func(ctx context.Context, ev nostr.Event) error {
		if held, err := holdIfAwaitingGitData(ctx, ev); err != nil {
			return err
		} else if held {
			return eventstore.ErrDupEvent
		}
		return replaceEvent(ctx, ev)
	}
	go purgatorySvc.Run(ctx, 30*time.Second)

	relayRootHandler := graspNIP11Handler(r, cfg, policies)
	addr := fmt.Sprintf(":%d", cfg.EmbeddedRelayPort)
	httpServer := &http.Server{Addr: addr, Handler: relayRootHandler}
	go func() {
		logger.Info("embedded relay listening", "addr", addr, "db", cfg.EmbeddedRelayDB)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("embedded relay failed", "error", err)
		}
	}()

	shutdown := func(shutdownCtx context.Context) error {
		httpErr := httpServer.Shutdown(shutdownCtx)
		db.Close()
		if err := repoStore.Close(); err != nil && httpErr == nil {
			return err
		}
		return httpErr
	}

	localURL := fmt.Sprintf("ws://localhost:%d", cfg.EmbeddedRelayPort)
	return localURL, relayRootHandler, shutdown, nil
}

func makeEmbeddedRelayRejectPolicy(repoChecker hostedRepoChecker, lookup storedEventLookup, stateResolvers ...stateEventResolver) func(context.Context, *nostr.Event) (bool, string) {
	var resolveState stateEventResolver
	if len(stateResolvers) > 0 {
		resolveState = stateResolvers[0]
	}
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event == nil {
			return true, "nil event"
		}
		if event.Kind == relay.KindRepositoryAnnouncement {
			return false, ""
		}
		if event.Kind == relay.KindRepositoryState {
			if resolveState == nil {
				return true, "repository state authority resolver unavailable"
			}
			if _, err := resolveState(ctx, event); err != nil {
				return true, "repository state signer is not authorized for a hosted repository"
			}
			return false, ""
		}
		if !isEmbeddedRelayCollaborationKind(int(event.Kind)) {
			return true, "only GRASP repository and collaboration events are accepted"
		}
		if referencesHostedRepo(ctx, event, repoChecker) {
			return false, ""
		}
		if referencesStoredCollaboration(ctx, event, lookup) {
			return false, ""
		}
		return true, "collaboration events must reference a hosted repository or accepted issue/patch/PR"
	}
}

func isEmbeddedRelayCollaborationKind(kind int) bool {
	switch kind {
	case relay.KindPatch,
		relay.KindPROpen,
		relay.KindPRUpdate,
		relay.KindIssue,
		relay.KindStatusOpen,
		relay.KindStatusApplied,
		relay.KindStatusClosed,
		relay.KindStatusDraft,
		relay.KindNIP22Comment:
		return true
	default:
		return false
	}
}

func isStoredCollaborationAnchorKind(kind int) bool {
	switch kind {
	case relay.KindPatch, relay.KindPROpen, relay.KindPRUpdate, relay.KindIssue:
		return true
	default:
		return false
	}
}

func referencesHostedRepo(ctx context.Context, event *nostr.Event, repoChecker hostedRepoChecker) bool {
	if repoChecker == nil {
		return false
	}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "a" {
			continue
		}
		parts := strings.SplitN(tag[1], ":", 3)
		if len(parts) != 3 || parts[0] != fmt.Sprint(relay.KindRepositoryAnnouncement) || parts[1] == "" || parts[2] == "" {
			continue
		}
		pk, err := nostr.PubKeyFromHex(parts[1])
		if err != nil {
			continue
		}
		npub := nip19.EncodeNpub(pk)
		exists, err := repoChecker.MappingExists(ctx, npub, parts[2])
		if err == nil && exists {
			return true
		}
	}
	return false
}

func referencesStoredCollaboration(ctx context.Context, event *nostr.Event, lookup storedEventLookup) bool {
	if lookup == nil {
		return false
	}
	for _, tag := range event.Tags {
		if len(tag) < 2 || (tag[0] != "e" && tag[0] != "E") || tag[1] == "" {
			continue
		}
		stored, err := lookup(ctx, tag[1])
		if err == nil && stored != nil && isStoredCollaborationAnchorKind(int(stored.Kind)) {
			return true
		}
	}
	return false
}

// makeRepoPathResolver maps a repo-scoped event to its validated owner
// repository path. State signers may be owners, recursive maintainers, or an
// explicitly trusted bridge; their p/a tags are hints only.
func makeRepoPathResolver(cfg config.Config, mappings *store.SQLiteStore, stateResolvers ...stateEventResolver) func(ctx context.Context, ev *nostr.Event) string {
	var resolveState stateEventResolver
	if len(stateResolvers) > 0 {
		resolveState = stateResolvers[0]
	}
	return func(ctx context.Context, ev *nostr.Event) string {
		var mapping store.Mapping
		switch int(ev.Kind) {
		case relay.KindRepositoryState:
			if resolveState == nil {
				return ""
			}
			resolved, err := resolveState(ctx, ev)
			if err != nil {
				return ""
			}
			mapping = resolved
		case relay.KindPROpen, relay.KindPRUpdate:
			var ownerPubkey, repoID string
			if a := ev.Tags.Find("a"); a != nil && len(a) >= 2 {
				coord, err := nostrauthz.ParseRepositoryCoordinate(a[1])
				if err == nil {
					ownerPubkey, repoID = coord.OwnerPubkey, coord.RepoID
				}
			}
			if ownerPubkey == "" || repoID == "" {
				return ""
			}
			pk, err := nostr.PubKeyFromHex(ownerPubkey)
			if err != nil {
				return ""
			}
			resolved, err := mappings.GetMapping(ctx, nip19.EncodeNpub(pk), repoID)
			if err != nil {
				return ""
			}
			mapping = resolved
		default:
			return ""
		}
		repoName := mapping.RepoName
		if repoName == "" {
			repoName = mapping.RepoID
		}
		if mapping.Owner == "" || repoName == "" {
			return ""
		}
		return filepath.Join(cfg.GiteaRepositoriesDir, mapping.Owner, repoName+".git")
	}
}

func graspNIP11Handler(relayHandler *khatru.Relay, cfg config.Config, policies *policy.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
			writeGRASPNIP11(w, relayHandler, cfg, policies)
			return
		}
		relayHandler.ServeHTTP(w, r)
	})
}

func writeGRASPNIP11(w http.ResponseWriter, relayHandler *khatru.Relay, cfg config.Config, policies *policy.Store) {
	w.Header().Set("Content-Type", "application/nostr+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	info := *relayHandler.Info
	if relayHandler.DeleteEvent != nil {
		info.AddSupportedNIP(9)
	}
	if relayHandler.Count != nil {
		info.AddSupportedNIP(45)
	}
	if relayHandler.Negentropy {
		info.AddSupportedNIP(77)
	}

	raw, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc := map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// GRASP-02 is intentionally not advertised until its complete behavior
	// passes validation (beads phase1-t7j).
	doc["supported_grasps"] = []string{"GRASP-01"}
	doc["repo_acceptance_criteria"] = "Repository announcements must list this service in clone and relays tags; collaboration events must reference a hosted repository or accepted issue, patch, or pull request."
	allowlistEnabled := cfg.AllowlistEnabled()
	if snapshot := policies.Current(); snapshot != nil {
		allowlistEnabled = len(snapshot.PubkeyAllowlist) > 0
	}
	if allowlistEnabled {
		doc["curation"] = "Repository announcements are limited to the configured pubkey allowlist."
	}
	_ = json.NewEncoder(w).Encode(doc)
}

//go:build full

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/purgatory"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type hostedRepoChecker interface {
	MappingExists(ctx context.Context, npub string, repoID string) (bool, error)
}

type storedEventLookup func(ctx context.Context, eventID string) (*nostr.Event, error)

func startEmbeddedRelay(ctx context.Context, cfg config.Config, logger *slog.Logger) (string, http.Handler, func(context.Context) error, error) {
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

	policy := makeEmbeddedRelayRejectPolicy(repoStore, lookupStoredEvent)
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
	repoPathForEvent := makeRepoPathResolver(cfg, repoStore)
	holdIfAwaitingGitData := func(ctx context.Context, ev nostr.Event) (bool, error) {
		repoPath := repoPathForEvent(ctx, &ev)
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

	relayRootHandler := graspNIP11Handler(r, cfg)
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

func makeEmbeddedRelayRejectPolicy(repoChecker hostedRepoChecker, lookup storedEventLookup) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event == nil {
			return true, "nil event"
		}
		if event.Kind == relay.KindRepositoryAnnouncement || event.Kind == relay.KindRepositoryState {
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

// makeRepoPathResolver maps a repo-scoped event to its bare repository path.
// State events (30618) are keyed by their own pubkey+d; PR events (1618/1619)
// carry the repository coordinate in their a tag.
func makeRepoPathResolver(cfg config.Config, mappings *store.SQLiteStore) func(ctx context.Context, ev *nostr.Event) string {
	return func(ctx context.Context, ev *nostr.Event) string {
		var ownerPubkey, repoID string
		switch int(ev.Kind) {
		case relay.KindRepositoryState:
			ownerPubkey = ev.PubKey.Hex()
			if d := ev.Tags.Find("d"); d != nil && len(d) >= 2 {
				repoID = d[1]
			}
		case relay.KindPROpen, relay.KindPRUpdate:
			if a := ev.Tags.Find("a"); a != nil && len(a) >= 2 {
				parts := strings.SplitN(a[1], ":", 3)
				if len(parts) == 3 && parts[0] == fmt.Sprint(relay.KindRepositoryAnnouncement) {
					ownerPubkey, repoID = parts[1], parts[2]
				}
			}
		default:
			return ""
		}
		if ownerPubkey == "" || repoID == "" {
			return ""
		}
		pk, err := nostr.PubKeyFromHex(ownerPubkey)
		if err != nil {
			return ""
		}
		mapping, err := mappings.GetMapping(ctx, nip19.EncodeNpub(pk), repoID)
		if err != nil {
			return ""
		}
		return filepath.Join(cfg.GiteaRepositoriesDir, mapping.Owner, mapping.RepoID+".git")
	}
}

func graspNIP11Handler(relayHandler *khatru.Relay, cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
			writeGRASPNIP11(w, relayHandler, cfg)
			return
		}
		relayHandler.ServeHTTP(w, r)
	})
}

func writeGRASPNIP11(w http.ResponseWriter, relayHandler *khatru.Relay, cfg config.Config) {
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
	if cfg.AllowlistEnabled() {
		doc["curation"] = "Repository announcements are limited to the configured pubkey allowlist."
	}
	_ = json.NewEncoder(w).Encode(doc)
}

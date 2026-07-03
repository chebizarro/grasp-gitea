//go:build full

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fiatjaf/eventstore/lmdb"
	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type hostedRepoChecker interface {
	MappingExists(ctx context.Context, npub string, repoID string) (bool, error)
}

type storedEventLookup func(ctx context.Context, eventID string) (*nostr.Event, error)

func startEmbeddedRelay(ctx context.Context, cfg config.Config, logger *slog.Logger) (string, func(context.Context) error, error) {
	_ = ctx
	if !cfg.EmbeddedRelay {
		return "", func(context.Context) error { return nil }, nil
	}

	r := khatru.NewRelay()
	db := lmdb.LMDBBackend{Path: cfg.EmbeddedRelayDB}
	if err := db.Init(); err != nil {
		return "", nil, fmt.Errorf("init embedded relay db: %w", err)
	}

	repoStore, err := store.Open(cfg.DBPath)
	if err != nil {
		db.Close()
		return "", nil, fmt.Errorf("open embedded relay mapping store: %w", err)
	}

	r.StoreEvent = append(r.StoreEvent, db.SaveEvent)
	r.QueryEvents = append(r.QueryEvents, db.QueryEvents)
	r.CountEvents = append(r.CountEvents, db.CountEvents)
	r.DeleteEvent = append(r.DeleteEvent, db.DeleteEvent)
	r.ReplaceEvent = append(r.ReplaceEvent, db.ReplaceEvent)

	lookupStoredEvent := func(ctx context.Context, eventID string) (*nostr.Event, error) {
		ch, err := db.QueryEvents(ctx, nostr.Filter{IDs: []string{eventID}, Limit: 1})
		if err != nil {
			return nil, err
		}
		for ev := range ch {
			return ev, nil
		}
		return nil, nil
	}

	r.RejectEvent = append(r.RejectEvent, makeEmbeddedRelayRejectPolicy(repoStore, lookupStoredEvent))

	addr := fmt.Sprintf(":%d", cfg.EmbeddedRelayPort)
	httpServer := &http.Server{Addr: addr, Handler: graspNIP11Handler(r, cfg)}
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
	return localURL, shutdown, nil
}

func makeEmbeddedRelayRejectPolicy(repoChecker hostedRepoChecker, lookup storedEventLookup) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event == nil {
			return true, "nil event"
		}
		if event.Kind == relay.KindRepositoryAnnouncement || event.Kind == relay.KindRepositoryState {
			return false, ""
		}
		if !isEmbeddedRelayCollaborationKind(event.Kind) {
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
		npub, err := nip19.EncodePublicKey(parts[1])
		if err != nil {
			continue
		}
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
		if err == nil && stored != nil && isStoredCollaborationAnchorKind(stored.Kind) {
			return true
		}
	}
	return false
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
	if len(relayHandler.DeleteEvent) > 0 {
		info.AddSupportedNIP(9)
	}
	if len(relayHandler.CountEvents) > 0 {
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
	doc["supported_grasps"] = []string{"GRASP-01", "GRASP-02"}
	doc["repo_acceptance_criteria"] = "Repository announcements must list this service in clone and relays tags; collaboration events must reference a hosted repository or accepted issue, patch, or pull request."
	if cfg.AllowlistEnabled() {
		doc["curation"] = "Repository announcements are limited to the configured pubkey allowlist."
	}
	_ = json.NewEncoder(w).Encode(doc)
}

//go:build full

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/fiatjaf/eventstore/lmdb"
	"github.com/fiatjaf/khatru"
	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/relay"
)

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

	r.StoreEvent = append(r.StoreEvent, db.SaveEvent)
	r.QueryEvents = append(r.QueryEvents, db.QueryEvents)
	r.CountEvents = append(r.CountEvents, db.CountEvents)
	r.DeleteEvent = append(r.DeleteEvent, db.DeleteEvent)
	r.ReplaceEvent = append(r.ReplaceEvent, db.ReplaceEvent)

	// Only accept NIP-34 repository announcements and state events.
	r.RejectEvent = append(r.RejectEvent, func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != relay.KindRepositoryAnnouncement && event.Kind != relay.KindRepositoryState {
			return true, "only NIP-34 repository events (kinds 30617, 30618) are accepted"
		}
		return false, ""
	})

	addr := fmt.Sprintf(":%d", cfg.EmbeddedRelayPort)
	httpServer := &http.Server{Addr: addr, Handler: r}
	go func() {
		logger.Info("embedded relay listening", "addr", addr, "db", cfg.EmbeddedRelayDB)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("embedded relay failed", "error", err)
		}
	}()

	shutdown := func(shutdownCtx context.Context) error {
		httpErr := httpServer.Shutdown(shutdownCtx)
		db.Close()
		return httpErr
	}

	localURL := fmt.Sprintf("ws://localhost:%d", cfg.EmbeddedRelayPort)
	return localURL, shutdown, nil
}

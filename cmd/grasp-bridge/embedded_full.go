//go:build full

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/fiatjaf/eventstore/lmdb"
	"github.com/fiatjaf/khatru"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func startEmbeddedRelay(ctx context.Context, cfg config.Config, logger *slog.Logger) (string, func(context.Context) error, error) {
	_ = ctx
	if !cfg.EmbeddedRelay {
		return "", func(context.Context) error { return nil }, nil
	}

	relay := khatru.NewRelay()
	db := lmdb.LMDBBackend{Path: cfg.EmbeddedRelayDB}
	if err := db.Init(); err != nil {
		return "", nil, fmt.Errorf("init embedded relay db: %w", err)
	}

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)

	addr := fmt.Sprintf(":%d", cfg.EmbeddedRelayPort)
	httpServer := &http.Server{Addr: addr, Handler: relay}
	go func() {
		logger.Info("embedded relay listening", "addr", addr, "db", cfg.EmbeddedRelayDB)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("embedded relay failed", "error", err)
		}
	}()

	shutdown := func(shutdownCtx context.Context) error {
		return httpServer.Shutdown(shutdownCtx)
	}

	localURL := fmt.Sprintf("ws://localhost:%d", cfg.EmbeddedRelayPort)
	return localURL, shutdown, nil
}

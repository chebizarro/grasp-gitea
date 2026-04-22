package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/api"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/proactivesync"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// mergeRelayURLs combines configured relay URLs with the embedded relay URL,
// deduplicating if the embedded URL is already in the list.
func mergeRelayURLs(configured []string, embeddedURL string) []string {
	result := append([]string{}, configured...)
	if embeddedURL != "" && !slices.Contains(result, embeddedURL) {
		result = append(result, embeddedURL)
	}
	return result
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("failed to open sqlite", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	giteaClient := gitea.NewClient(cfg.GiteaURL, cfg.GiteaAdminToken)
	hookInstaller := hooks.NewInstaller(cfg.GiteaRepositoriesDir, cfg.HookBinaryPath, cfg.HookRelayURL)
	nip05Resolver := nip05resolve.NewResolver(5 * time.Minute)
	provisionerSvc := provisioner.New(cfg, st, giteaClient, hookInstaller, nip05Resolver, logger)

	// Reconcile any provisioning that was interrupted by a previous crash.
	// This re-installs hooks for mappings saved with hook_installed=false.
	if err := provisionerSvc.ReconcileHooks(context.Background()); err != nil {
		logger.Warn("hook reconciliation had errors", "error", err)
	}

	proactiveSyncSvc := proactivesync.New(cfg.GiteaRepositoriesDir, st, logger)
	apiServer := api.New(cfg, provisionerSvc, st, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	embeddedRelayURL, shutdownEmbedded, err := startEmbeddedRelay(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to start embedded relay", "error", err)
		os.Exit(1)
	}
	defer shutdownEmbedded(context.Background())

	relayURLs := mergeRelayURLs(cfg.RelayURLs, embeddedRelayURL)

	handler := func(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
		err := provisionerSvc.HandleAnnouncementEvent(ctx, ev, sourceRelay)
		if err != nil {
			return err
		}
		if embeddedRelayURL != "" && sourceRelay != embeddedRelayURL {
			if ev.Kind == relay.KindRepositoryAnnouncement || ev.Kind == relay.KindRepositoryState {
				if forwardErr := forwardEventToRelay(ctx, embeddedRelayURL, ev); forwardErr != nil {
					logger.Warn("failed to forward event to embedded relay", "event", ev.ID, "error", forwardErr)
				}
			}
		}
		if ev.Kind == relay.KindRepositoryState {
			if syncErr := proactiveSyncSvc.HandleStateEvent(ctx, ev); syncErr != nil {
				logger.Warn("proactive sync failed", "event", ev.ID, "error", syncErr)
			}
		}
		return nil
	}

	subscriber := relay.New(relayURLs, handler, logger)
	subscriber.Run(ctx)

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("admin API listening", "listen", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin server failed", "error", err)
			cancel()
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	subscriber.Wait()
	logger.Info("grasp-bridge stopped")
}

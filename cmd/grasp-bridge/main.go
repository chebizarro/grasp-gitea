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

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/api"
	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/oauth2"
	"github.com/sharegap/grasp-gitea/internal/proactivesync"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/webhook"
)

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
	provisionerSvc := provisioner.New(cfg, st, giteaClient, hookInstaller, logger)
	proactiveSyncSvc := proactivesync.New(cfg.GiteaRepositoriesDir, logger)
	apiServer := api.New(provisionerSvc, st, logger)

	// Outbound NIP-34 publishing — optional, activated by GRASP_SERVER_NSEC.
	pub, err := publisher.New(cfg.ServerNsec, cfg.RelayURLs, logger)
	if err != nil {
		logger.Error("failed to initialise publisher", "error", err)
		os.Exit(1)
	}
	if pub != nil {
		webhookHandler := webhook.New(pub, st, cfg.GiteaWebhookSecret, cfg.RelayHint, logger)
		apiServer.SetWebhookHandler(webhookHandler)
		provisionerSvc.SetAnnouncer(webhookHandler)
		logger.Info("NIP-34 outbound publishing enabled", "pubkey", pub.PubKey())
	} else {
		logger.Info("NIP-34 outbound publishing disabled (set GRASP_SERVER_NSEC to enable)")
	}

	if cfg.NIP07AuthEnabled {
		nonceTTL := time.Duration(cfg.NonceTTLSeconds) * time.Second
		authSvc := auth.NewService(st, nonceTTL)
		oauth2Cfg := oauth2.Config{
			ClientID:        cfg.OAuth2ClientID,
			ClientSecret:    cfg.OAuth2ClientSecret,
			BridgePublicURL: cfg.BridgePublicURL,
			RelayURL:        firstRelay(cfg.RelayURLs),
		}
		oauth2Provider := oauth2.New(oauth2Cfg, authSvc, st, giteaClient, logger)
		apiServer.SetOAuth2Provider(oauth2Provider)
		logger.Info("NIP-07 web auth enabled", "bridge_public_url", cfg.BridgePublicURL)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	embeddedRelayURL, shutdownEmbedded, err := startEmbeddedRelay(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to start embedded relay", "error", err)
		os.Exit(1)
	}
	defer shutdownEmbedded(context.Background())

	relayURLs := append([]string{}, cfg.RelayURLs...)
	if embeddedRelayURL != "" && !slices.Contains(relayURLs, embeddedRelayURL) {
		relayURLs = append(relayURLs, embeddedRelayURL)
	}

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
	logger.Info("grasp-bridge stopped")
}

func firstRelay(relays []string) string {
	if len(relays) > 0 {
		return relays[0]
	}
	return ""
}

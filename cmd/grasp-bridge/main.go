package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/api"
	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hiveci"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/outbox"
	"github.com/sharegap/grasp-gitea/internal/proactivesync"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/reflector"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/signer"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/webhook"
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

func newServerSigner(ctx context.Context, cfg config.Config, logger *slog.Logger) (publisher.ServerSigner, error) {
	if cfg.SignetBunkerURL != "" {
		signer, err := publisher.NewSignetBunkerServerSigner(ctx, cfg.SignetBunkerURL, cfg.RelayURLs...)
		if err != nil {
			return nil, err
		}
		logger.Info("Signet NIP-46 server signer ready", "server_pubkey", signer.PublicKey())
		return signer, nil
	}
	if cfg.BridgeNsec == "" {
		return nil, nil
	}
	if cfg.Production() {
		return nil, errors.New("SIGNET_BUNKER_URL is required in production; BRIDGE_NSEC is dev fallback only")
	}
	logger.Warn("using BRIDGE_NSEC development fallback for server signing; configure SIGNET_BUNKER_URL for production")
	return publisher.NewLocalServerSigner(cfg.BridgeNsec)
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

	// Migrate every served repository to the required GRASP-01 upload-pack
	// capability configuration (allowFilter, allowTipSHA1InWant,
	// allowReachableSHA1InWant).
	if err := provisionerSvc.EnsureUploadPackCapabilities(context.Background()); err != nil {
		logger.Warn("upload-pack capability migration had errors", "error", err)
	}

	proactiveSyncSvc := proactivesync.New(cfg.GiteaRepositoriesDir, st, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	embeddedRelayURL, shutdownEmbedded, err := startEmbeddedRelay(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to start embedded relay", "error", err)
		os.Exit(1)
	}
	defer shutdownEmbedded(context.Background())

	relayURLs := mergeRelayURLs(cfg.RelayURLs, embeddedRelayURL)

	var signerSvc *signer.Service
	if cfg.SignerEnabled() {
		signerSvc, err = signer.NewService(st, cfg.SignerMasterKey, signer.WithTrustedMultiplexedBunkerURI(cfg.SignetBunkerURL))
		if err != nil {
			logger.Error("failed to create signer service", "error", err)
			os.Exit(1)
		}
		logger.Info("persistent NIP-46 signer service enabled")
	} else {
		logger.Info("persistent NIP-46 signer service disabled", "reason", "SIGNER_MASTER_KEY not configured")
	}

	proactiveSyncDone := make(chan struct{})
	go func() {
		defer close(proactiveSyncDone)
		proactiveSyncSvc.Run(ctx, cfg.ProactiveSyncInterval)
	}()
	logger.Info("GRASP-02 proactive sync scheduler started", "interval", cfg.ProactiveSyncInterval.String())

	refsNostrReaper := refsnostr.NewReaper(
		st,
		refsnostr.NewRelayChecker(relayURLs, logger),
		refsnostr.NewGitRefDeleter(cfg.GiteaRepositoriesDir),
		logger,
	)
	refsNostrReaperDone := make(chan struct{})
	go func() {
		defer close(refsNostrReaperDone)
		refsNostrReaper.Run(ctx)
	}()
	logger.Info("refs/nostr lifecycle reaper started", "ttl", refsnostr.DefaultAcceptanceTTL.String(), "interval", refsnostr.DefaultSweepInterval.String())

	// Create the publisher. Server/operator signing prefers Signet over NIP-46
	// so the bridge does not hold an nsec. BRIDGE_NSEC remains only as an
	// explicit dev fallback and is rejected when GRASP_ENV/APP_ENV/ENVIRONMENT
	// is production.
	serverSigner, err := newServerSigner(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to create server signer", "error", err)
		os.Exit(1)
	}
	publisherSvc := publisher.NewWithServerSigner(serverSigner, st, relayURLs, cfg.GiteaRepositoriesDir, logger)
	if cfg.CIEnabled && publisherSvc.Enabled() {
		publisherSvc.SetCIConfig(true, cfg.CITriggerRepos)
		logger.Info("CI workflow-run publishing enabled", "trigger_repos", cfg.CITriggerRepos)
	}
	hiveRunner := hiveci.New(hiveci.Config{Enabled: cfg.HiveCIEnabled, ActPath: cfg.HiveCIActPath}, st, serverSigner, relayURLs, cfg.GiteaRepositoriesDir, logger)
	if cfg.HiveCIEnabled && !hiveRunner.Enabled() {
		logger.Warn("Hive-CI requested but disabled; check server signer, repositories path, and act path")
	} else if hiveRunner.Enabled() {
		logger.Info("Hive-CI Tier A runner enabled", "act_path", cfg.HiveCIActPath)
	}

	var outboxDone chan struct{}
	var outboxWorker *outbox.Worker
	var actorBackfiller *webhook.ActorBackfiller
	if signerSvc != nil && signerSvc.Enabled() && publisherSvc != nil {
		outboxWorker = outbox.New(st, signerSvc, publisherSvc, logger)
		publisherSvc.SetOwnerStateSigning(signerSvc, outboxWorker)
		outboxDone = make(chan struct{})
		go func() {
			defer close(outboxDone)
			outboxWorker.Run(ctx)
		}()
		actorBackfiller = webhook.NewActorBackfiller(st, outboxWorker, logger)
		logger.Info("outbound signing queue worker started")
	}

	apiServer := api.New(cfg, provisionerSvc, publisherSvc, st, logger)
	if signerSvc != nil {
		apiServer.SetSignerAuthorizer(signerSvc)
	}

	if cfg.AuthEnabled {
		authSvc := auth.NewService(cfg, st, logger)
		identitySvc := auth.NewIdentityService(st, giteaClient, nip05Resolver, logger)
		nip07Handler := auth.NewNIP07Handler(authSvc, identitySvc, relayURLs, logger)
		nip46Handler := auth.NewNIP46Handler(st, identitySvc, relayURLs, cfg.BridgePublicURL, signerSvc, logger)
		if actorBackfiller != nil {
			nip46Handler.SetActorEventBackfiller(actorBackfiller)
		}
		nip55Handler := auth.NewNIP55Handler(authSvc, identitySvc, relayURLs, logger)
		apiServer.AddRouteRegistrar(func(mux *http.ServeMux) {
			nip07Handler.RegisterRoutes(mux)
			nip46Handler.RegisterRoutes(mux)
			nip55Handler.RegisterRoutes(mux)
		})
		logger.Info("Nostr auth routes enabled", "bridge_public_url", cfg.BridgePublicURL)
	}

	// Wire webhook handler for NIP-34 events (PRs, issues, patches, labels)
	if (publisherSvc.Enabled() || (signerSvc != nil && signerSvc.Enabled())) && cfg.GiteaWebhookSecret != "" {
		webhookHandler := webhook.New(publisherSvc, st, cfg.GiteaWebhookSecret, logger)
		webhookHandler.SetRepositoriesDir(cfg.GiteaRepositoriesDir)
		if signerSvc != nil && signerSvc.Enabled() {
			webhookHandler.SetActorSigning(signerSvc, outboxWorker, st)
		}
		apiServer.SetWebhookHandler(webhookHandler)
		logger.Info("Gitea webhook handler enabled for NIP-34 events")
	}

	reflectorSvc := reflector.New(st, giteaClient, cfg.GiteaRepositoriesDir, logger)
	reflectorSvc.SetStatusSyncEnabled(cfg.NIP34StatusSyncEnabled)
	if publisherSvc != nil && publisherSvc.Enabled() {
		reflectorSvc.SetPatchRejectionPublisher(publisherSvc)
	}

	// Per-repo lock serialises state-event processing (CI + proactive
	// sync) across relay goroutines so ref reads in the CI handler
	// cannot race with ref writes from proactive sync.
	var repoStateMu sync.Mutex
	repoStateLocks := make(map[string]*sync.Mutex)
	lockRepoState := func(key string) func() {
		repoStateMu.Lock()
		mu, ok := repoStateLocks[key]
		if !ok {
			mu = &sync.Mutex{}
			repoStateLocks[key] = mu
		}
		repoStateMu.Unlock()
		mu.Lock()
		return mu.Unlock
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
		if ev.Kind == relay.KindUserGraspList {
			if err := publisherSvc.HandleUserGraspListEvent(ctx, ev, sourceRelay); err != nil {
				return err
			}
			return nil
		}
		if reflectErr := reflectorSvc.HandleEvent(ctx, ev, sourceRelay); reflectErr != nil {
			return reflectErr
		}
		if ev.Kind == relay.KindRepositoryState {
			// Derive a stable repo key from the event to serialise
			// CI + proactive-sync per repo.
			dTag := ""
			if t := ev.Tags.Find("d"); t != nil && len(t) >= 2 {
				dTag = t[1]
			}
			unlock := lockRepoState(ev.PubKey.Hex() + "/" + dTag)

			// CI trigger runs before proactive sync so local refs
			// still reflect the previous state for change detection.
			if publisherSvc != nil {
				if ciErr := publisherSvc.HandleStateEventCI(ctx, ev, sourceRelay); ciErr != nil {
					logger.Warn("CI workflow-run trigger failed", "event", ev.ID, "error", ciErr)
				}
			}
			if syncErr := proactiveSyncSvc.HandleStateEvent(ctx, ev); syncErr != nil {
				logger.Warn("proactive sync failed", "event", ev.ID, "error", syncErr)
			}

			unlock()
		}
		if hiveRunner != nil {
			if hiveErr := hiveRunner.HandleEvent(ctx, ev, sourceRelay); hiveErr != nil {
				logger.Warn("Hive-CI runner failed", "event", ev.ID, "kind", ev.Kind, "error", hiveErr)
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
	select {
	case <-proactiveSyncDone:
	case <-shutdownCtx.Done():
		logger.Warn("proactive sync scheduler did not stop before shutdown timeout")
	}
	select {
	case <-refsNostrReaperDone:
	case <-shutdownCtx.Done():
		logger.Warn("refs/nostr lifecycle reaper did not stop before shutdown timeout")
	}
	if outboxDone != nil {
		select {
		case <-outboxDone:
		case <-shutdownCtx.Done():
			logger.Warn("outbound signing queue worker did not stop before shutdown timeout")
		}
	}
	logger.Info("grasp-bridge stopped")
}

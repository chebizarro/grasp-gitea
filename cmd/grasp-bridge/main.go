package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/api"
	"github.com/sharegap/grasp-gitea/internal/auth"
	cashuwallet "github.com/sharegap/grasp-gitea/internal/cashu"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/giteaproxy"
	"github.com/sharegap/grasp-gitea/internal/hiveci"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/outbox"
	"github.com/sharegap/grasp-gitea/internal/proactivesync"
	"github.com/sharegap/grasp-gitea/internal/profilesync"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/reflector"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/safefetch"
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

// relaySubscriptionURLs avoids subscribing to an embedded relay through both
// its local and public addresses. Treating those as separate upstream relays
// creates a reflection loop because externally received repository events are
// forwarded into the embedded relay.
func relaySubscriptionURLs(configured []string, embeddedURL string, publicEmbeddedURL string) []string {
	filtered := make([]string, 0, len(configured))
	publicEmbeddedURL = strings.TrimRight(strings.TrimSpace(publicEmbeddedURL), "/")
	for _, relayURL := range configured {
		if embeddedURL != "" && publicEmbeddedURL != "" &&
			strings.TrimRight(strings.TrimSpace(relayURL), "/") == publicEmbeddedURL {
			continue
		}
		filtered = append(filtered, relayURL)
	}
	return mergeRelayURLs(filtered, embeddedURL)
}

func loomSubscriptionKinds(includeActions bool) []nostr.Kind {
	kinds := []nostr.Kind{
		relay.KindLoomWorkerAd, relay.KindLoomJobStatus,
		relay.KindLoomJobResult, relay.KindHiveWorkflowResult,
	}
	if includeActions {
		kinds = append(kinds, relay.KindHiveWorkflowRun)
	}
	return kinds
}

func newServerSigner(ctx context.Context, cfg config.Config, st *store.SQLiteStore, relayURLs []string, logger *slog.Logger) (publisher.ServerSigner, error) {
	if cfg.SignetBunkerURL != "" {
		if cfg.Production() && len(cfg.SignerMasterKey) != 32 {
			return nil, errors.New("SIGNER_MASTER_KEY is required for production durable signing")
		}
		// Restart-durable session: Signet authorization is one-time, so the
		// authorized NIP-46 client key is persisted and reused across restarts.
		serverSigner, err := signer.ConnectDurableSignetSigner(ctx, st, cfg.SignerMasterKey, cfg.SignetBunkerURL, relayURLs, logger)
		if err != nil {
			return nil, err
		}
		logger.Info("Signet NIP-46 server signer ready", "server_pubkey", serverSigner.PublicKey())
		return serverSigner, nil
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

	giteaClient := gitea.NewClient(cfg.GiteaURL, cfg.GiteaAdminToken).WithAdminUser(cfg.GiteaAdminUser)
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

	embeddedRelayURL, relayRootHandler, shutdownEmbedded, err := startEmbeddedRelay(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to start embedded relay", "error", err)
		os.Exit(1)
	}
	defer shutdownEmbedded(context.Background())

	relayURLs := relaySubscriptionURLs(cfg.RelayURLs, embeddedRelayURL, cfg.GraspRelayURL)
	loomRelayURLs := append([]string(nil), cfg.LoomRelayURLs...)
	if len(loomRelayURLs) == 0 {
		loomRelayURLs = append(loomRelayURLs, cfg.RelayURLs...)
	}

	var signerSvc *signer.Service
	if cfg.SignerEnabled() {
		signerSvc, err = signer.NewService(st, cfg.SignerMasterKey, signer.WithTrustedMultiplexedBunkerURI(cfg.SignetBunkerURL))
		if err != nil {
			logger.Error("failed to create signer service", "error", err)
			os.Exit(1)
		}
		defer signerSvc.Close()
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
	serverSigner, err := newServerSigner(ctx, cfg, st, relayURLs, logger)
	if err != nil {
		logger.Error("failed to create server signer", "error", err)
		os.Exit(1)
	}
	if closer, ok := serverSigner.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	publisherSvc := publisher.NewWithServerSigner(serverSigner, st, relayURLs, cfg.GiteaRepositoriesDir, logger)
	if cfg.CIEnabled && cfg.CIProtocol == "cascadia" && publisherSvc.Enabled() {
		publisherSvc.SetCIConfig(true, cfg.CITriggerRepos)
		logger.Warn("legacy Cascadia CI workflow-run publishing enabled", "trigger_repos", cfg.CITriggerRepos)
	} else if cfg.CIEnabled && cfg.CIProtocol == "canonical" {
		logger.Info("canonical CI uses the Loom dispatcher; legacy CI_ENABLED publisher remains disabled")
	}
	statusSink := loom.NewDurableStatusSink(st, giteaClient, cfg.LoomJobTTL, cfg.LoomMaxJobs, logger)
	if cfg.LoomEnabled || cfg.HiveCIEnabled {
		go statusSink.Run(ctx)
	}

	workerPool := loom.NewWorkerPool(loom.WorkerPoolConfig{
		Allowlist: cfg.LoomWorkerPubkeys, RequiredSoftware: []string{"act"},
		FutureSkew: cfg.LoomFutureSkew,
	})
	var dispatchSigner loom.DispatchSigner
	if candidate, ok := serverSigner.(loom.DispatchSigner); ok {
		dispatchSigner = candidate
	}
	remoteRequested := cfg.LoomEnabled && cfg.CIProtocol == "canonical" &&
		(cfg.LoomDispatchMode == "remote" || cfg.LoomDispatchMode == "both")
	var loomWallet cashuwallet.Wallet
	if remoteRequested && cfg.LoomPaymentMode == "cashu" {
		walletErr := safefetch.ValidateHTTPSURL(ctx, cfg.LoomMintURL)
		var wallet *cashuwallet.GonutsWallet
		if walletErr == nil {
			wallet, walletErr = cashuwallet.New(cashuwallet.Config{
				MintURL: cfg.LoomMintURL, Path: cfg.LoomCashuWalletPath,
			})
		}
		if walletErr != nil {
			logger.Error("Cashu wallet unavailable; refusing to strand paid-job settlement", "error", walletErr)
			os.Exit(1)
		} else {
			loomWallet = wallet
			defer loomWallet.Close()
		}
	}
	loomDispatcher := loom.NewDispatcher(loom.DispatcherConfig{
		Enabled: remoteRequested, MaxDuration: cfg.LoomJobMaxDuration,
		CommandTemplate: cfg.LoomJobCmdTemplate, StaticPaymentToken: cfg.LoomStaticPaymentToken,
		PaymentMode: cfg.LoomPaymentMode, MintURL: cfg.LoomMintURL, MaxPayment: cfg.LoomCashuMaxPayment,
		ContextPrefix: cfg.LoomStatusContextPrefix, RelayURLs: loomRelayURLs,
		JobTTL: cfg.LoomJobTTL, MaxJobs: cfg.LoomMaxJobs,
	}, workerPool, st, dispatchSigner, logger, loomWallet)
	if remoteRequested && !loomDispatcher.Enabled() {
		if cfg.LoomDispatchMode == "remote" {
			logger.Error("remote-only Loom dispatch unavailable; check signer NIP-44 support, worker allowlist, and relay URLs")
			os.Exit(1)
		}
		logger.Warn("preferred Loom dispatch unavailable; both mode will use local Hive-CI")
	}
	go loomDispatcher.Run(ctx)

	hiveRunner := hiveci.New(hiveci.Config{
		Enabled:       cfg.HiveCIEnabled,
		ActPath:       cfg.HiveCIActPath,
		TriggerRepos:  cfg.CITriggerRepos,
		RunTimeout:    cfg.HiveCIRunTimeout,
		MaxConcurrent: cfg.HiveCIMaxConcurrent,
	}, st, serverSigner, relayURLs, cfg.GiteaRepositoriesDir, logger)
	hiveRunner.SetStatusSink(statusSink, cfg.LoomStatusContextPrefix)
	hiveRunner.SetWorkflowAuthorizer(proactiveSyncSvc)
	hiveRunner.SetRemoteDispatcher(loomDispatcher, cfg.LoomDispatchMode)
	var loomActionIngestor *hiveci.LoomActionIngestor
	if cfg.LoomActions.Enabled {
		policies := make([]hiveci.LoomActionPolicy, 0, len(cfg.LoomActions.Policies))
		for _, policy := range cfg.LoomActions.Policies {
			policies = append(policies, hiveci.LoomActionPolicy{
				RepoAddress: policy.RepoAddress, Actors: policy.Actors, Branches: policy.Branches,
				Workflows: policy.Workflows, AllowDirectDispatch: policy.AllowDirectDispatch, Version: policy.Version,
			})
		}
		localPubkey := ""
		if serverSigner != nil {
			localPubkey = serverSigner.PublicKey()
		}
		loomActionIngestor, err = hiveci.NewLoomActionIngestor(hiveci.LoomActionConfig{
			Enabled: true, LocalPubkey: localPubkey, RepositoriesDir: cfg.GiteaRepositoriesDir,
			MaxEventAge: cfg.LoomActions.MaxAge, FutureSkew: cfg.LoomActions.FutureSkew, Policies: policies,
		}, st, hiveRunner, logger)
		if err != nil {
			logger.Error("failed to configure Loom action ingress", "error", err)
			os.Exit(1)
		}
		logger.Info("signed Loom action ingress enabled", "policies", len(policies))
	}
	go func() {
		if err := hiveRunner.RecoverPendingMergeStatuses(ctx); err != nil {
			logger.Error("recover pending HiveCI merge statuses", "error", err)
		}
	}()
	loomSvc := loom.New(loom.Config{
		Enabled: cfg.LoomEnabled, ContextPrefix: cfg.LoomStatusContextPrefix,
		FutureSkew: cfg.LoomFutureSkew, ResultGrace: cfg.LoomResultGrace,
		LogFetcher: loom.NewBlossomFetcher(cfg.LoomLogMaxBytes), Wallet: loomWallet,
	}, st, statusSink, logger)
	loomSvc.Run(ctx)

	if cfg.HiveCIEnabled {
		logger.Info("Hive-CI Tier A runner configured", "act_path", cfg.HiveCIActPath)
	}
	if loomDispatcher.Enabled() {
		logger.Info("canonical Loom outbound dispatcher enabled", "mode", cfg.LoomDispatchMode, "relays", loomRelayURLs)
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
	if cfg.GitHubActions.Enabled {
		policies := make([]hiveci.GitHubActionPolicy, 0, len(cfg.GitHubActions.Policies))
		for _, policy := range cfg.GitHubActions.Policies {
			policies = append(policies, hiveci.GitHubActionPolicy{
				Repository: policy.Repository, RepositoryID: policy.RepositoryID,
				RepoAddress: policy.RepoAddress, Actors: policy.Actors, ActorIDs: policy.ActorIDs, Events: policy.Events,
				ProtectedBranches: policy.ProtectedBranches, Workflows: policy.Workflows,
				RepositoryDispatchActions: policy.RepositoryDispatchActions, Version: policy.Version,
			})
		}
		githubActions, err := hiveci.NewGitHubActionHandler(hiveci.GitHubActionConfig{
			Secret: cfg.GitHubActions.WebhookSecret, RepositoriesDir: cfg.GiteaRepositoriesDir, Policies: policies,
		}, st, hiveRunner, logger)
		if err != nil {
			logger.Error("failed to configure GitHub action ingress", "error", err)
			os.Exit(1)
		}
		apiServer.AddRouteRegistrar(githubActions.RegisterRoutes)
		logger.Info("GitHub action ingress enabled", "route", hiveci.GitHubActionsRoute, "policies", len(policies))
	}
	var bridgeTokenSvc *auth.TokenService
	var proxyNostrVerifier *auth.ProxyNIP98Verifier
	if relayRootHandler != nil {
		// GRASP-01: serve the Nostr relay (WebSocket) and NIP-11 negotiation
		// at the canonical service root on the public listener.
		apiServer.SetRootRelayHandler(relayRootHandler)
	}
	if signerSvc != nil {
		apiServer.SetSignerAuthorizer(signerSvc)
	}

	// Profile sync runs independently of interactive auth: it keeps already
	// linked users' Gitea profiles current from their kind:0. Constructed
	// here so the auth block can attach it as an identity notifier.
	var profileSyncSvc *profilesync.Service
	profileSyncDone := make(chan struct{})
	if cfg.ProfileSyncEnabled {
		profileSyncSvc = profilesync.New(profilesync.Config{
			Interval: cfg.ProfileSyncInterval,
			Workers:  cfg.ProfileSyncWorkers,
		}, st, giteaClient, relayURLs, logger)
		go func() {
			defer close(profileSyncDone)
			profileSyncSvc.Run(ctx)
		}()
		logger.Info("Nostr kind:0 profile sync enabled", "interval", cfg.ProfileSyncInterval.String(), "workers", cfg.ProfileSyncWorkers)
	} else {
		close(profileSyncDone)
	}

	if cfg.AuthEnabled {
		authSvc := auth.NewService(cfg, st, logger)
		identitySvc := auth.NewIdentityService(st, giteaClient, nip05Resolver, logger)
		if profileSyncSvc != nil {
			identitySvc.SetProfileSyncNotifier(profileSyncSvc)
		}
		nip07Handler := auth.NewNIP07Handler(authSvc, identitySvc, relayURLs, logger)
		nip46Handler := auth.NewNIP46Handler(st, identitySvc, relayURLs, cfg.BridgePublicURL, signerSvc, logger)
		nip46Handler.SetTrustedProxyCIDRs(cfg.NIP46TrustedProxyCIDRs)
		go nip46Handler.RunCleanup(ctx)
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

		if cfg.BridgeTokensEnabled {
			tokenSvc, err := auth.NewTokenService(cfg, st, identitySvc, giteaClient, logger)
			if err != nil {
				logger.Error("failed to initialize bridge token service", "error", err)
				os.Exit(1)
			}
			tokenHandler := auth.NewTokenHandler(authSvc, tokenSvc, logger)
			apiServer.AddRouteRegistrar(tokenHandler.RegisterRoutes)
			go tokenSvc.RunMaintenance(ctx)
			bridgeTokenSvc = tokenSvc
			proxyNostrVerifier = auth.NewProxyNIP98Verifier(authSvc, tokenSvc)
			logger.Info("bridge token service enabled", "scopes", tokenSvc.EnabledScopes())
		}
	}

	// The streaming proxy is the sole path to Gitea. It authenticates bridge
	// tokens, injects hidden per-user PATs, and checks live repository
	// visibility before serving anonymous mapped-npub traffic.
	// Assign through the interface variable: a typed nil *TokenService would
	// box into a non-nil interface and defeat the proxy's disabled check.
	var proxyAuthenticator giteaproxy.Authenticator
	if bridgeTokenSvc != nil {
		proxyAuthenticator = bridgeTokenSvc
	}
	giteaProxy, err := giteaproxy.New(giteaproxy.Config{
		GiteaURL:           cfg.GiteaURL,
		PublicURL:          cfg.BridgePublicURL,
		EdgeSharedSecret:   cfg.EdgeSharedSecret,
		GitBackendUser:     cfg.GitBackendUser,
		GitBackendPassword: cfg.GitBackendPassword,
		FullProxy:          cfg.FullProxyEnabled,
	}, proxyAuthenticator, giteaClient, st, logger)
	if err != nil {
		logger.Error("failed to initialize Gitea proxy", "error", err)
		os.Exit(1)
	}
	if proxyNostrVerifier != nil {
		giteaProxy.WithNostrVerifier(proxyNostrVerifier)
		logger.Info("direct NIP-98 authentication enabled on proxied endpoints")
	}
	apiServer.SetGiteaProxy(giteaProxy)
	if cfg.FullProxyEnabled {
		// The bridge is now the only path to Gitea, so its readiness must
		// include upstream reachability.
		apiServer.AddReadinessProbe(giteaProxy.UpstreamProbe())
		logger.Info("full Gitea reverse proxy enabled; all unmatched traffic is proxied to Gitea")
	}

	// Wire webhook handler for NIP-34 events (PRs, issues, patches, labels)
	if (publisherSvc.Enabled() || (signerSvc != nil && signerSvc.Enabled())) && cfg.GiteaWebhookSecret != "" {
		webhookHandler := webhook.New(publisherSvc, st, cfg.GiteaWebhookSecret, logger)
		webhookHandler.SetGraspPublicURL(cfg.GraspPublicURL)
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

	// A fixed set of striped locks serialises state-event processing (CI +
	// proactive sync) without retaining attacker-controlled repository keys.
	// Hash collisions only add harmless cross-repository serialization.
	var repoStateLocks [256]sync.Mutex
	lockRepoState := func(key string) func() {
		sum := sha256.Sum256([]byte(key))
		mu := &repoStateLocks[int(sum[0])]
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

			if authErr := proactiveSyncSvc.AuthorizeStateEvent(ctx, ev); authErr != nil {
				unlock()
				logger.Warn("repository state event authorization failed", "event", ev.ID, "error", authErr)
				return nil
			}

			// CI trigger runs before proactive sync so local refs
			// still reflect the previous state for change detection.
			if publisherSvc != nil && cfg.CIProtocol == "cascadia" {
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

	// Loom rides a dedicated subscriber: the embedded repository relay rejects
	// these canonical kinds, so an empty LOOM_RELAY_URLS falls back only to the
	// configured external relay set rather than the merged embedded set.
	var loomSubscriber *relay.Subscriber
	if loomSvc.Enabled() || (loomActionIngestor != nil && loomActionIngestor.Enabled()) {
		if len(loomRelayURLs) == 0 {
			logger.Warn("Loom enabled without an external LOOM_RELAY_URLS/RELAY_URLS subscriber")
		} else {
			loomHandler := func(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
				if loomActionIngestor != nil {
					handled, err := loomActionIngestor.HandleEvent(ctx, ev, sourceRelay)
					if handled || err != nil {
						return err
					}
				}
				if ev != nil && ev.Kind == relay.KindLoomWorkerAd {
					return workerPool.HandleEvent(ev, time.Now().UTC())
				}
				return loomSvc.HandleEvent(ctx, ev, sourceRelay)
			}
			loomSubscriber = relay.NewWithKinds(loomRelayURLs, loomSubscriptionKinds(cfg.LoomActions.Enabled), loomHandler, logger)
			loomSubscriber.Run(ctx)
			logger.Info("canonical Loom inbound subscriber enabled", "relays", loomRelayURLs)
		}
	}

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	subscriber.Wait()
	if loomSubscriber != nil {
		loomSubscriber.Wait()
	}
	select {
	case <-proactiveSyncDone:
	case <-shutdownCtx.Done():
		logger.Warn("proactive sync scheduler did not stop before shutdown timeout")
	}
	select {
	case <-profileSyncDone:
	case <-shutdownCtx.Done():
		logger.Warn("profile sync service did not stop before shutdown timeout")
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

package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

type Config struct {
	// PolicyPath is the immutable boot coordinate for the persisted mutable
	// policy projection. Legacy policy env values only seed this file once.
	PolicyPath             string
	ConfigTrustedAuthors   []string
	ConfigScope            string
	GiteaURL               string
	GiteaAdminToken        string
	ClonePrefix            string
	RelayURLs              []string
	Listen                 string
	DBPath                 string
	PubkeyAllowlist        map[string]struct{}
	ProvisionRateLimit     int
	HookRelayURL           string
	HookBinaryPath         string
	GiteaRepositoriesDir   string
	EmbeddedRelay          bool
	EmbeddedRelayPort      int
	EmbeddedRelayDB        string
	ArchiveMode            bool
	AdminAPIToken          string
	AuthEnabled            bool
	BridgePublicURL        string
	ChallengeTTL           time.Duration
	NIP46TrustedProxyCIDRs []string
	ProactiveSyncInterval  time.Duration

	// SignerMasterKey enables the persistent NIP-46 signer subsystem when set.
	// It is decoded from SIGNER_MASTER_KEY (base64 or hex) and must be 32 bytes.
	SignerMasterKey []byte

	// Server/operator signing. SIGNET_BUNKER_URL is the production path;
	// BridgeNsec is retained only as an explicit development fallback.
	SignetBunkerURL     string
	BridgeNsec          string
	Environment         string
	MirrorCallbackToken string

	// Gitea webhook handler for NIP-34 events (PRs, issues, patches, labels)
	GiteaWebhookSecret string

	// GraspPublicURL is the canonical GRASP-01 service origin
	// (e.g. https://grasp.sharegap.net). When set, announcement acceptance
	// requires the canonical npub clone URL and bridge-emitted events
	// advertise it. GraspRelayURL is the matching wss:// relay origin.
	GraspPublicURL string
	GraspRelayURL  string

	// GRASP-01 public git smart-HTTP backend identity. The public npub proxy is
	// unauthenticated; the bridge authenticates to Gitea itself using this
	// narrowly scoped service account so callers never need Gitea credentials.
	GitBackendUser     string
	GitBackendPassword string

	// CI workflow run publishing: emit ContextVM ci/workflow-run requests when state events arrive
	// for repos that have CI workflows configured.
	CIEnabled      bool
	CITriggerRepos []string // ["*"] or ["owner/repo-id", ...]

	// Hive-CI Tier A runs act locally and publishes signed check/audit results.
	HiveCIEnabled           bool
	HiveCIActPath           string
	HiveCIRunTimeout        time.Duration
	HiveCIMaxConcurrent     int
	HiveCINostrRelays       []string
	HiveCICashuMintURL      string
	HiveCIBlossomURL        string
	HiveCIJobTimeoutMinutes int
	HiveCICloneURLTemplate  string

	// Loom consumes canonical ads/results and dispatches trusted-fleet Hive-CI jobs.
	LoomEnabled             bool
	LoomDispatchMode        string
	LoomWorkerPubkeys       []string
	LoomRelayURLs           []string
	LoomJobMaxDuration      time.Duration
	LoomJobCmdTemplate      string
	LoomStatusContextPrefix string
	LoomMintURL             string
	LoomStaticPaymentToken  string
	LoomPaymentMode         string
	LoomCashuWalletPath     string
	LoomCashuMaxPayment     uint64
	LoomLogMaxBytes         int64
	LoomJobTTL              time.Duration
	LoomMaxJobs             int
	LoomFutureSkew          time.Duration
	LoomResultGrace         time.Duration
	CIProtocol              string

	// NIP34StatusSyncEnabled updates Gitea issue state from inbound NIP-34 status events.
	NIP34StatusSyncEnabled bool

	// Bridge token service: nostr-authenticated opaque tokens (grasp_v1_...)
	// exchanged at the proxy edge for hidden per-user Gitea PATs.
	BridgeTokensEnabled bool
	// GiteaAdminUser is the login of the administrator that owns
	// GITEA_ADMIN_TOKEN. The user-token lifecycle endpoints
	// (/api/v1/users/{username}/tokens) are gated by Gitea's
	// reqBasicOrRevProxyAuth, so PAT administration must authenticate with
	// HTTP Basic (admin login + admin PAT) rather than the token header.
	GiteaAdminUser string
	// CredentialKeys is the versioned AES-256-GCM key ring protecting hidden
	// Gitea PATs at rest. First entry encrypts; the rest only decrypt.
	// Deliberately separate from SignerMasterKey.
	CredentialKeys []CredentialKey
	// EdgeSharedSecret authenticates trusted nginx-originated headers
	// (session-handoff continuation) once the bridge fronts all Gitea traffic.
	EdgeSharedSecret string
	// FullProxyEnabled routes ALL unmatched HTTP traffic through the bridge to
	// Gitea (full reverse proxy mode) instead of only canonical npub paths.
	FullProxyEnabled        bool
	TokenTTLDefault         time.Duration
	TokenTTLMin             time.Duration
	TokenTTLMax             time.Duration
	AuthAuditRetention      time.Duration
	RegistryTokenMaxTTL     time.Duration
	RegistryTokenProbeEvery time.Duration
	// ShutdownGrace bounds graceful HTTP shutdown; long enough for active
	// streaming git/package uploads to complete.
	ShutdownGrace time.Duration

	// ProfileSyncEnabled turns on live kind:0 -> Gitea user profile sync
	// (display name, bio, website, avatar). Independent of bridge tokens.
	ProfileSyncEnabled  bool
	ProfileSyncInterval time.Duration
	ProfileSyncWorkers  int
}

// CredentialKey is one entry of the credential-encryption key ring.
type CredentialKey struct {
	ID  string
	Key []byte
}

// minEdgeSecretLength is the shortest accepted GRASP_EDGE_SHARED_SECRET. It
// corresponds to 32 random bytes in base64/hex form.
const minEdgeSecretLength = 43

func Load() (Config, error) {
	cfg := Config{
		GiteaURL:                envOrDefault("GITEA_URL", "http://gitea:3000"),
		PolicyPath:              envOrDefault("GRASP_CONFIG_PATH", "/data/config.json"),
		ConfigTrustedAuthors:    csvEnv("GRASP_CONFIG_TRUSTED_AUTHORS"),
		ConfigScope:             strings.TrimSpace(envOrDefault("GRASP_CONFIG_SCOPE", "prod")),
		GiteaAdminToken:         strings.TrimSpace(os.Getenv("GITEA_ADMIN_TOKEN")),
		ClonePrefix:             strings.TrimRight(strings.TrimSpace(os.Getenv("CLONE_PREFIX")), "/"),
		RelayURLs:               csvEnv("RELAY_URLS"),
		Listen:                  envOrDefault("LISTEN", ":8090"),
		DBPath:                  envOrDefault("DB_PATH", "./mappings.db"),
		PubkeyAllowlist:         parseAllowlist(os.Getenv("PUBKEY_ALLOWLIST")),
		ProvisionRateLimit:      intEnv("PROVISION_RATE_LIMIT", 0),
		HookRelayURL:            envOrDefault("HOOK_RELAY_URL", "ws://localhost:3334"),
		HookBinaryPath:          envOrDefault("HOOK_BINARY_PATH", "/usr/local/bin/grasp-pre-receive"),
		GiteaRepositoriesDir:    envOrDefault("GITEA_REPOSITORIES_PATH", "/gitea-data/git/repositories"),
		EmbeddedRelay:           boolEnv("EMBEDDED_RELAY", false),
		EmbeddedRelayPort:       intEnv("EMBEDDED_RELAY_PORT", 3334),
		EmbeddedRelayDB:         envOrDefault("EMBEDDED_RELAY_DB", "/data/relay-db"),
		ArchiveMode:             boolEnv("GRASP05_ARCHIVE_MODE", false),
		AdminAPIToken:           strings.TrimSpace(os.Getenv("ADMIN_API_TOKEN")),
		AuthEnabled:             boolEnv("AUTH_ENABLED", false),
		BridgePublicURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("BRIDGE_PUBLIC_URL")), "/"),
		ChallengeTTL:            durationEnv("CHALLENGE_TTL", 5*time.Minute),
		NIP46TrustedProxyCIDRs:  csvEnv("NIP46_TRUSTED_PROXY_CIDRS"),
		ProactiveSyncInterval:   normalizeProactiveSyncInterval(durationEnv("PROACTIVE_SYNC_INTERVAL", time.Hour)),
		ProfileSyncEnabled:      boolEnv("PROFILE_SYNC_ENABLED", false),
		ProfileSyncInterval:     durationEnv("PROFILE_SYNC_INTERVAL", 10*time.Minute),
		ProfileSyncWorkers:      intEnv("PROFILE_SYNC_WORKERS", 4),
		SignerMasterKey:         nil,
		SignetBunkerURL:         strings.TrimSpace(os.Getenv("SIGNET_BUNKER_URL")),
		BridgeNsec:              strings.TrimSpace(os.Getenv("BRIDGE_NSEC")),
		Environment:             firstEnv("GRASP_ENV", "APP_ENV", "ENVIRONMENT"),
		MirrorCallbackToken:     strings.TrimSpace(os.Getenv("MIRROR_CALLBACK_TOKEN")),
		GiteaWebhookSecret:      strings.TrimSpace(os.Getenv("GITEA_WEBHOOK_SECRET")),
		GraspPublicURL:          strings.TrimRight(strings.TrimSpace(os.Getenv("GRASP_PUBLIC_URL")), "/"),
		GraspRelayURL:           strings.TrimRight(strings.TrimSpace(os.Getenv("GRASP_RELAY_URL")), "/"),
		GitBackendUser:          strings.TrimSpace(os.Getenv("GIT_BACKEND_USER")),
		GitBackendPassword:      strings.TrimSpace(os.Getenv("GIT_BACKEND_PASSWORD")),
		CIEnabled:               boolEnv("CI_ENABLED", false),
		CITriggerRepos:          csvEnv("CI_TRIGGER_REPOS"),
		HiveCIEnabled:           boolEnv("HIVE_CI_ENABLED", false),
		HiveCIActPath:           envOrDefault("HIVE_CI_ACT_PATH", "/usr/bin/act"),
		HiveCIRunTimeout:        boundedDurationEnv("HIVE_CI_RUN_TIMEOUT", 15*time.Minute, time.Second, time.Hour),
		HiveCIMaxConcurrent:     boundedIntEnv("HIVE_CI_MAX_CONCURRENT", 2, 1, 16),
		HiveCINostrRelays:       csvEnv("NOSTR_RELAYS"),
		HiveCICashuMintURL:      strings.TrimSpace(os.Getenv("CASHU_MINT_URL")),
		HiveCIBlossomURL:        strings.TrimSpace(os.Getenv("BLOSSOM_URL")),
		HiveCIJobTimeoutMinutes: boundedIntEnv("JOB_TIMEOUT_MINUTES", 15, 1, 60),
		HiveCICloneURLTemplate:  strings.TrimSpace(os.Getenv("HIVECI_CLONE_URL_TEMPLATE")),
		LoomEnabled:             boolEnv("LOOM_ENABLED", false),
		LoomDispatchMode:        strings.ToLower(envOrDefault("LOOM_DISPATCH_MODE", "local")),
		LoomWorkerPubkeys:       csvEnv("LOOM_WORKER_PUBKEYS"),
		LoomRelayURLs:           csvEnv("LOOM_RELAY_URLS"),
		LoomJobMaxDuration:      boundedDurationEnv("LOOM_JOB_MAX_DURATION", 15*time.Minute, time.Second, time.Hour),
		LoomJobCmdTemplate:      strings.TrimSpace(os.Getenv("LOOM_JOB_CMD_TEMPLATE")),
		LoomStatusContextPrefix: envOrDefault("LOOM_STATUS_CONTEXT_PREFIX", "hive-ci"),
		LoomMintURL:             strings.TrimSpace(os.Getenv("LOOM_MINT_URL")),
		LoomStaticPaymentToken:  strings.TrimSpace(os.Getenv("LOOM_STATIC_PAYMENT_TOKEN")),
		LoomPaymentMode:         strings.ToLower(envOrDefault("LOOM_PAYMENT_MODE", "trusted")),
		LoomCashuWalletPath:     strings.TrimSpace(os.Getenv("LOOM_CASHU_WALLET_PATH")),
		LoomCashuMaxPayment:     uint64Env("LOOM_CASHU_MAX_PAYMENT", 0),
		LoomLogMaxBytes:         int64(boundedIntEnv("LOOM_LOG_MAX_BYTES", 1<<20, 1024, 10<<20)),
		LoomJobTTL:              boundedDurationEnv("LOOM_JOB_TTL", 7*24*time.Hour, time.Hour, 30*24*time.Hour),
		LoomMaxJobs:             boundedIntEnv("LOOM_MAX_JOBS", 4096, 1, 100000),
		LoomFutureSkew:          boundedDurationEnv("LOOM_FUTURE_SKEW", 5*time.Minute, time.Second, time.Hour),
		LoomResultGrace:         boundedDurationEnv("LOOM_RESULT_GRACE", 30*time.Second, time.Second, 10*time.Minute),
		CIProtocol:              strings.ToLower(envOrDefault("CI_PROTOCOL", "canonical")),
		NIP34StatusSyncEnabled:  boolEnv("NIP34_STATUS_SYNC_ENABLED", false),
		BridgeTokensEnabled:     boolEnv("BRIDGE_TOKENS_ENABLED", false),
		GiteaAdminUser:          strings.TrimSpace(os.Getenv("GITEA_ADMIN_USER")),
		EdgeSharedSecret:        strings.TrimSpace(os.Getenv("GRASP_EDGE_SHARED_SECRET")),
		FullProxyEnabled:        boolEnv("GITEA_FULL_PROXY_ENABLED", false),
		TokenTTLDefault:         durationEnv("BRIDGE_TOKEN_TTL_DEFAULT", 30*24*time.Hour),
		TokenTTLMin:             durationEnv("BRIDGE_TOKEN_TTL_MIN", time.Hour),
		TokenTTLMax:             durationEnv("BRIDGE_TOKEN_TTL_MAX", 90*24*time.Hour),
		AuthAuditRetention:      boundedDurationEnv("AUTH_AUDIT_RETENTION", 90*24*time.Hour, 24*time.Hour, 365*24*time.Hour),
		RegistryTokenMaxTTL:     durationEnv("REGISTRY_TOKEN_MAX_LIFETIME", 24*time.Hour),
		RegistryTokenProbeEvery: durationEnv("REGISTRY_TOKEN_PROBE_INTERVAL", 5*time.Minute),
		ShutdownGrace:           boundedDurationEnv("SHUTDOWN_GRACE", 5*time.Minute, time.Second, 30*time.Minute),
	}
	_, policyStatErr := os.Stat(cfg.PolicyPath)
	hasPersistedPolicy := policyStatErr == nil
	if policyStatErr != nil && !errors.Is(policyStatErr, os.ErrNotExist) {
		return Config{}, fmt.Errorf("stat GRASP_CONFIG_PATH: %w", policyStatErr)
	}

	signerMasterKey, err := parseSignerMasterKey(os.Getenv("SIGNER_MASTER_KEY"))
	if err != nil {
		return Config{}, err
	}
	cfg.SignerMasterKey = signerMasterKey
	if cfg.LoomCashuWalletPath == "" {
		cfg.LoomCashuWalletPath = cfg.DBPath + ".cashu-wallet"
	}
	if filepath.Clean(cfg.LoomCashuWalletPath) == filepath.Clean(cfg.DBPath) {
		return Config{}, fmt.Errorf("LOOM_CASHU_WALLET_PATH must not equal DB_PATH")
	}

	if cfg.GiteaAdminToken == "" {
		return Config{}, fmt.Errorf("GITEA_ADMIN_TOKEN is required")
	}

	if cfg.ClonePrefix == "" {
		return Config{}, fmt.Errorf("CLONE_PREFIX is required (e.g. https://git.example.com)")
	}

	if !hasPersistedPolicy && len(cfg.RelayURLs) == 0 && !cfg.EmbeddedRelay {
		return Config{}, fmt.Errorf("RELAY_URLS is required (or set EMBEDDED_RELAY=true for embedded-only mode)")
	}

	if !hasPersistedPolicy && cfg.LoomEnabled && len(cfg.LoomRelayURLs) == 0 && len(cfg.RelayURLs) == 0 {
		return Config{}, fmt.Errorf("LOOM_RELAY_URLS or external RELAY_URLS is required when LOOM_ENABLED=true; the embedded relay rejects Loom kinds")
	}
	if cfg.LoomDispatchMode != "local" && cfg.LoomDispatchMode != "remote" && cfg.LoomDispatchMode != "both" {
		return Config{}, fmt.Errorf("LOOM_DISPATCH_MODE must be local, remote, or both")
	}
	if cfg.LoomPaymentMode != "trusted" && cfg.LoomPaymentMode != "cashu" {
		return Config{}, fmt.Errorf("LOOM_PAYMENT_MODE must be trusted or cashu")
	}
	if cfg.LoomMintURL != "" {
		u, err := url.Parse(cfg.LoomMintURL)
		if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return Config{}, fmt.Errorf("LOOM_MINT_URL must be an absolute HTTPS URL without credentials, query, or fragment")
		}
	}
	if cfg.LoomPaymentMode == "cashu" {
		if cfg.LoomMintURL == "" {
			return Config{}, fmt.Errorf("LOOM_MINT_URL is required when LOOM_PAYMENT_MODE=cashu")
		}
		if cfg.LoomStaticPaymentToken != "" {
			return Config{}, fmt.Errorf("LOOM_STATIC_PAYMENT_TOKEN cannot be combined with LOOM_PAYMENT_MODE=cashu")
		}
		if cfg.LoomCashuMaxPayment == 0 {
			return Config{}, fmt.Errorf("LOOM_CASHU_MAX_PAYMENT is required when LOOM_PAYMENT_MODE=cashu")
		}
	}
	if !cfg.LoomEnabled && cfg.LoomDispatchMode != "local" {
		return Config{}, fmt.Errorf("LOOM_ENABLED=true is required for non-local LOOM_DISPATCH_MODE")
	}
	if !hasPersistedPolicy && cfg.HiveCIEnabled && len(cfg.CITriggerRepos) == 0 {
		return Config{}, fmt.Errorf("CI_TRIGGER_REPOS is required when HIVE_CI_ENABLED=true")
	}
	if cfg.LoomEnabled && cfg.LoomDispatchMode != "local" {
		if cfg.CIProtocol != "canonical" {
			return Config{}, fmt.Errorf("remote Loom dispatch requires CI_PROTOCOL=canonical")
		}
		if !hasPersistedPolicy && len(cfg.CITriggerRepos) == 0 {
			return Config{}, fmt.Errorf("CI_TRIGGER_REPOS is required for remote Loom dispatch")
		}
		if len(cfg.LoomWorkerPubkeys) == 0 {
			return Config{}, fmt.Errorf("LOOM_WORKER_PUBKEYS is required for trusted-fleet remote dispatch")
		}
		for i, raw := range cfg.LoomWorkerPubkeys {
			pk, err := nostr.PubKeyFromHex(raw)
			if err != nil {
				return Config{}, fmt.Errorf("invalid LOOM_WORKER_PUBKEYS entry %q: %w", raw, err)
			}
			cfg.LoomWorkerPubkeys[i] = pk.Hex()
		}
	}
	if cfg.CIProtocol != "canonical" && cfg.CIProtocol != "cascadia" {
		return Config{}, fmt.Errorf("CI_PROTOCOL must be canonical or cascadia")
	}

	if cfg.AuthEnabled && cfg.BridgePublicURL == "" {
		return Config{}, fmt.Errorf("BRIDGE_PUBLIC_URL is required when AUTH_ENABLED=true")
	}
	for _, cidr := range cfg.NIP46TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return Config{}, fmt.Errorf("invalid NIP46_TRUSTED_PROXY_CIDRS entry %q: %w", cidr, err)
		}
	}

	credentialKeys, err := parseCredentialKeys(os.Getenv("GRASP_CREDENTIAL_KEYS"))
	if err != nil {
		return Config{}, err
	}
	cfg.CredentialKeys = credentialKeys

	if cfg.TokenTTLMin <= 0 || cfg.TokenTTLMin > cfg.TokenTTLMax {
		return Config{}, fmt.Errorf("BRIDGE_TOKEN_TTL_MIN must be positive and not exceed BRIDGE_TOKEN_TTL_MAX")
	}
	if cfg.TokenTTLDefault < cfg.TokenTTLMin || cfg.TokenTTLDefault > cfg.TokenTTLMax {
		return Config{}, fmt.Errorf("BRIDGE_TOKEN_TTL_DEFAULT must be within [BRIDGE_TOKEN_TTL_MIN, BRIDGE_TOKEN_TTL_MAX]")
	}
	if cfg.BridgeTokensEnabled {
		if cfg.RegistryTokenMaxTTL <= 0 {
			return Config{}, fmt.Errorf("REGISTRY_TOKEN_MAX_LIFETIME must be positive")
		}
		if cfg.RegistryTokenProbeEvery <= 0 {
			return Config{}, fmt.Errorf("REGISTRY_TOKEN_PROBE_INTERVAL must be positive")
		}
		if !cfg.AuthEnabled {
			return Config{}, fmt.Errorf("AUTH_ENABLED=true is required when BRIDGE_TOKENS_ENABLED=true; token minting is NIP-98 authenticated")
		}
		if len(cfg.CredentialKeys) == 0 {
			return Config{}, fmt.Errorf("GRASP_CREDENTIAL_KEYS is required when BRIDGE_TOKENS_ENABLED=true")
		}
		if cfg.GiteaAdminUser == "" {
			return Config{}, fmt.Errorf("GITEA_ADMIN_USER is required when BRIDGE_TOKENS_ENABLED=true (PAT administration uses Basic auth)")
		}
		if cfg.BridgePublicURL == "" {
			return Config{}, fmt.Errorf("BRIDGE_PUBLIC_URL is required when BRIDGE_TOKENS_ENABLED=true")
		}
		if !hasPersistedPolicy && !cfg.FullProxyEnabled {
			return Config{}, fmt.Errorf("GITEA_FULL_PROXY_ENABLED=true is required when BRIDGE_TOKENS_ENABLED=true; minting tokens without downstream Gitea isolation would allow scope bypass")
		}
	}
	// The edge secret authorizes arbitrary X-Grasp-Auth-User impersonation, so
	// a guessable value is equivalent to an authentication bypass.
	if cfg.EdgeSharedSecret != "" && len(cfg.EdgeSharedSecret) < minEdgeSecretLength {
		return Config{}, fmt.Errorf("GRASP_EDGE_SHARED_SECRET must be at least %d characters of high-entropy random data", minEdgeSecretLength)
	}
	if !hasPersistedPolicy && cfg.FullProxyEnabled && cfg.AuthEnabled && cfg.EdgeSharedSecret == "" {
		return Config{}, fmt.Errorf("GRASP_EDGE_SHARED_SECRET is required when GITEA_FULL_PROXY_ENABLED=true and AUTH_ENABLED=true; browser session handoff cannot be authenticated without it")
	}
	if !hasPersistedPolicy && cfg.Production() && cfg.FullProxyEnabled && cfg.EdgeSharedSecret == "" {
		return Config{}, fmt.Errorf("GRASP_EDGE_SHARED_SECRET is required in production when GITEA_FULL_PROXY_ENABLED=true")
	}

	if cfg.Production() && cfg.AdminAPIToken == "" {
		return Config{}, fmt.Errorf("ADMIN_API_TOKEN is required in production")
	}
	if cfg.Production() && (cfg.SignetBunkerURL != "" || cfg.AuthEnabled) && !cfg.SignerEnabled() {
		return Config{}, fmt.Errorf("SIGNER_MASTER_KEY is required for production durable signing")
	}

	if !hasPersistedPolicy && cfg.ProfileSyncEnabled {
		// Profile sync mints admin PATs and edits users via the admin API,
		// which Gitea gates behind Basic admin auth.
		if cfg.GiteaAdminUser == "" {
			return Config{}, fmt.Errorf("GITEA_ADMIN_USER is required when PROFILE_SYNC_ENABLED=true")
		}
		if cfg.ProfileSyncInterval < time.Minute || cfg.ProfileSyncInterval > 24*time.Hour {
			return Config{}, fmt.Errorf("PROFILE_SYNC_INTERVAL must be between 1m and 24h, got %s", cfg.ProfileSyncInterval)
		}
		if cfg.ProfileSyncWorkers < 1 || cfg.ProfileSyncWorkers > 32 {
			return Config{}, fmt.Errorf("PROFILE_SYNC_WORKERS must be between 1 and 32, got %d", cfg.ProfileSyncWorkers)
		}
	}

	return cfg, nil
}

func (c Config) AllowlistEnabled() bool {
	return len(c.PubkeyAllowlist) > 0
}

// MirrorPublishEnabled reports whether the bridge is configured to republish
// NIP-34 events on mirror sync callbacks.
func (c Config) MirrorPublishEnabled() bool {
	return c.SignetBunkerURL != "" || c.BridgeNsec != ""
}

func (c Config) Production() bool {
	env := strings.ToLower(strings.TrimSpace(c.Environment))
	return env == "prod" || env == "production"
}

// SignerEnabled reports whether persistent NIP-46 signer grants can be used.
func (c Config) SignerEnabled() bool {
	return len(c.SignerMasterKey) == 32
}

func envOrDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func boolEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func intEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func uint64Env(key string, fallback uint64) uint64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func boundedIntEnv(key string, fallback, min, max int) int {
	n := intEnv(key, fallback)
	if n < min || n > max {
		return fallback
	}
	return n
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func csvEnv(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

// parseCredentialKeys parses GRASP_CREDENTIAL_KEYS, a comma-separated list of
// id:key entries where key is base64 (std or raw) or hex encoded 32 bytes.
// The first entry is the active encryption key; the rest are decrypt-only.
func parseCredentialKeys(raw string) ([]CredentialKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var keys []CredentialKey
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, encoded, ok := strings.Cut(entry, ":")
		id = strings.TrimSpace(id)
		encoded = strings.TrimSpace(encoded)
		if !ok || id == "" || encoded == "" {
			return nil, fmt.Errorf("GRASP_CREDENTIAL_KEYS entries must be id:base64-or-hex-32-bytes")
		}
		if !validCredentialKeyID(id) {
			return nil, fmt.Errorf("GRASP_CREDENTIAL_KEYS key id %q must be 1-32 chars of [A-Za-z0-9_-]", id)
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("GRASP_CREDENTIAL_KEYS key id %q is duplicated", id)
		}
		decoded, err := decodeKeyMaterial(encoded)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("GRASP_CREDENTIAL_KEYS key %q must decode to 32 bytes (base64 or hex)", id)
		}
		seen[id] = struct{}{}
		keys = append(keys, CredentialKey{ID: id, Key: decoded})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("GRASP_CREDENTIAL_KEYS is set but contains no key entries")
	}
	return keys, nil
}

func validCredentialKeyID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func decodeKeyMaterial(raw string) ([]byte, error) {
	decodeAttempts := []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decodeAttempts {
		if b, err := decode(raw); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("undecodable key material")
}

func parseSignerMasterKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	decodeAttempts := []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
	}
	var decoded []byte
	for _, decode := range decodeAttempts {
		b, err := decode(raw)
		if err == nil {
			decoded = b
			break
		}
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("SIGNER_MASTER_KEY must decode to 32 bytes (base64 or hex)")
	}
	return decoded, nil
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func boundedDurationEnv(key string, fallback, min, max time.Duration) time.Duration {
	d := durationEnv(key, fallback)
	if d < min || d > max {
		return fallback
	}
	return d
}

func normalizeProactiveSyncInterval(interval time.Duration) time.Duration {
	if interval <= 0 || interval > time.Hour {
		return time.Hour
	}
	return interval
}

func parseAllowlist(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			out[entry] = struct{}{}
		}
	}
	return out
}

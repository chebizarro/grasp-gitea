package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

type Config struct {
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
	HiveCIEnabled       bool
	HiveCIActPath       string
	HiveCIRunTimeout    time.Duration
	HiveCIMaxConcurrent int

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
	LoomJobTTL              time.Duration
	LoomMaxJobs             int
	LoomFutureSkew          time.Duration
	LoomResultGrace         time.Duration
	CIProtocol              string

	// NIP34StatusSyncEnabled updates Gitea issue state from inbound NIP-34 status events.
	NIP34StatusSyncEnabled bool
}

func Load() (Config, error) {
	cfg := Config{
		GiteaURL:                envOrDefault("GITEA_URL", "http://gitea:3000"),
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
		LoomEnabled:             boolEnv("LOOM_ENABLED", false),
		LoomDispatchMode:        strings.ToLower(envOrDefault("LOOM_DISPATCH_MODE", "local")),
		LoomWorkerPubkeys:       csvEnv("LOOM_WORKER_PUBKEYS"),
		LoomRelayURLs:           csvEnv("LOOM_RELAY_URLS"),
		LoomJobMaxDuration:      boundedDurationEnv("LOOM_JOB_MAX_DURATION", 15*time.Minute, time.Second, time.Hour),
		LoomJobCmdTemplate:      strings.TrimSpace(os.Getenv("LOOM_JOB_CMD_TEMPLATE")),
		LoomStatusContextPrefix: envOrDefault("LOOM_STATUS_CONTEXT_PREFIX", "hive-ci"),
		LoomMintURL:             strings.TrimSpace(os.Getenv("LOOM_MINT_URL")),
		LoomStaticPaymentToken:  strings.TrimSpace(os.Getenv("LOOM_STATIC_PAYMENT_TOKEN")),
		LoomJobTTL:              boundedDurationEnv("LOOM_JOB_TTL", 7*24*time.Hour, time.Hour, 30*24*time.Hour),
		LoomMaxJobs:             boundedIntEnv("LOOM_MAX_JOBS", 4096, 1, 100000),
		LoomFutureSkew:          boundedDurationEnv("LOOM_FUTURE_SKEW", 5*time.Minute, time.Second, time.Hour),
		LoomResultGrace:         boundedDurationEnv("LOOM_RESULT_GRACE", 30*time.Second, time.Second, 10*time.Minute),
		CIProtocol:              strings.ToLower(envOrDefault("CI_PROTOCOL", "canonical")),
		NIP34StatusSyncEnabled:  boolEnv("NIP34_STATUS_SYNC_ENABLED", false),
	}

	signerMasterKey, err := parseSignerMasterKey(os.Getenv("SIGNER_MASTER_KEY"))
	if err != nil {
		return Config{}, err
	}
	cfg.SignerMasterKey = signerMasterKey

	if cfg.GiteaAdminToken == "" {
		return Config{}, fmt.Errorf("GITEA_ADMIN_TOKEN is required")
	}

	if cfg.ClonePrefix == "" {
		return Config{}, fmt.Errorf("CLONE_PREFIX is required (e.g. https://git.example.com)")
	}

	if len(cfg.RelayURLs) == 0 && !cfg.EmbeddedRelay {
		return Config{}, fmt.Errorf("RELAY_URLS is required (or set EMBEDDED_RELAY=true for embedded-only mode)")
	}

	if cfg.LoomEnabled && len(cfg.LoomRelayURLs) == 0 && len(cfg.RelayURLs) == 0 {
		return Config{}, fmt.Errorf("LOOM_RELAY_URLS or external RELAY_URLS is required when LOOM_ENABLED=true; the embedded relay rejects Loom kinds")
	}
	if cfg.LoomDispatchMode != "local" && cfg.LoomDispatchMode != "remote" && cfg.LoomDispatchMode != "both" {
		return Config{}, fmt.Errorf("LOOM_DISPATCH_MODE must be local, remote, or both")
	}
	if !cfg.LoomEnabled && cfg.LoomDispatchMode != "local" {
		return Config{}, fmt.Errorf("LOOM_ENABLED=true is required for non-local LOOM_DISPATCH_MODE")
	}
	if cfg.HiveCIEnabled && len(cfg.CITriggerRepos) == 0 {
		return Config{}, fmt.Errorf("CI_TRIGGER_REPOS is required when HIVE_CI_ENABLED=true")
	}
	if cfg.LoomEnabled && cfg.LoomDispatchMode != "local" {
		if cfg.CIProtocol != "canonical" {
			return Config{}, fmt.Errorf("remote Loom dispatch requires CI_PROTOCOL=canonical")
		}
		if len(cfg.CITriggerRepos) == 0 {
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

	if cfg.Production() && cfg.AdminAPIToken == "" {
		return Config{}, fmt.Errorf("ADMIN_API_TOKEN is required in production")
	}
	if cfg.Production() && (cfg.SignetBunkerURL != "" || cfg.AuthEnabled) && !cfg.SignerEnabled() {
		return Config{}, fmt.Errorf("SIGNER_MASTER_KEY is required for production durable signing")
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

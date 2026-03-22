package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	GiteaURL           string
	GiteaAdminToken    string
	ClonePrefix        string
	RelayURLs          []string
	Listen             string
	DBPath             string
	PubkeyAllowlist      map[string]struct{}
	ProvisionRateLimit   int
	HookRelayURL         string
	HookBinaryPath       string
	GiteaRepositoriesDir string
	EmbeddedRelay        bool
	EmbeddedRelayPort    int
	EmbeddedRelayDB      string

	// NIP-07 web auth
	NIP07AuthEnabled   bool   // NIP07_AUTH_ENABLED
	OAuth2ClientID     string // OAUTH2_CLIENT_ID
	OAuth2ClientSecret string // OAUTH2_CLIENT_SECRET
	BridgePublicURL    string // BRIDGE_PUBLIC_URL (public base URL of grasp-bridge)
	NonceTTLSeconds    int    // NONCE_TTL_SECONDS, default 300
}

func Load() (Config, error) {
	cfg := Config{
		GiteaURL:           envOrDefault("GITEA_URL", "http://gitea:3000"),
		GiteaAdminToken:    strings.TrimSpace(os.Getenv("GITEA_ADMIN_TOKEN")),
		ClonePrefix:        strings.TrimRight(envOrDefault("CLONE_PREFIX", "https://git.sharegap.net"), "/"),
		RelayURLs:          csvEnv("RELAY_URLS"),
		Listen:             envOrDefault("LISTEN", ":8090"),
		DBPath:             envOrDefault("DB_PATH", "./mappings.db"),
		PubkeyAllowlist:      parseAllowlist(os.Getenv("PUBKEY_ALLOWLIST")),
		ProvisionRateLimit:   intEnv("PROVISION_RATE_LIMIT", 0),
		HookRelayURL:         envOrDefault("HOOK_RELAY_URL", "ws://localhost:3334"),
		HookBinaryPath:       envOrDefault("HOOK_BINARY_PATH", "/usr/local/bin/grasp-pre-receive"),
		GiteaRepositoriesDir: envOrDefault("GITEA_REPOSITORIES_PATH", "/gitea-data/git/repositories"),
		EmbeddedRelay:        boolEnv("EMBEDDED_RELAY", false),
		EmbeddedRelayPort:    intEnv("EMBEDDED_RELAY_PORT", 3334),
		EmbeddedRelayDB:      envOrDefault("EMBEDDED_RELAY_DB", "/data/relay-db"),

		NIP07AuthEnabled:   boolEnv("NIP07_AUTH_ENABLED", false),
		OAuth2ClientID:     strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_ID")),
		OAuth2ClientSecret: strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_SECRET")),
		BridgePublicURL:    strings.TrimRight(strings.TrimSpace(os.Getenv("BRIDGE_PUBLIC_URL")), "/"),
		NonceTTLSeconds:    intEnv("NONCE_TTL_SECONDS", 300),
	}

	if cfg.GiteaAdminToken == "" {
		return Config{}, fmt.Errorf("GITEA_ADMIN_TOKEN is required")
	}

	if len(cfg.RelayURLs) == 0 {
		return Config{}, fmt.Errorf("RELAY_URLS is required for Phase 1")
	}

	if cfg.NIP07AuthEnabled {
		if cfg.OAuth2ClientID == "" {
			return Config{}, fmt.Errorf("OAUTH2_CLIENT_ID is required when NIP07_AUTH_ENABLED=true")
		}
		if cfg.OAuth2ClientSecret == "" {
			return Config{}, fmt.Errorf("OAUTH2_CLIENT_SECRET is required when NIP07_AUTH_ENABLED=true")
		}
		if cfg.BridgePublicURL == "" {
			return Config{}, fmt.Errorf("BRIDGE_PUBLIC_URL is required when NIP07_AUTH_ENABLED=true")
		}
	}

	return cfg, nil
}

func (c Config) AllowlistEnabled() bool {
	return len(c.PubkeyAllowlist) > 0
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

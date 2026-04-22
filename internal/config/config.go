package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	GiteaURL             string
	GiteaAdminToken      string
	ClonePrefix          string
	RelayURLs            []string
	Listen               string
	DBPath               string
	PubkeyAllowlist      map[string]struct{}
	ProvisionRateLimit   int
	HookRelayURL         string
	HookBinaryPath       string
	GiteaRepositoriesDir string
	EmbeddedRelay        bool
	EmbeddedRelayPort    int
	EmbeddedRelayDB      string
	AdminAPIToken        string
}

func Load() (Config, error) {
	cfg := Config{
		GiteaURL:             envOrDefault("GITEA_URL", "http://gitea:3000"),
		GiteaAdminToken:      strings.TrimSpace(os.Getenv("GITEA_ADMIN_TOKEN")),
		ClonePrefix:          strings.TrimRight(strings.TrimSpace(os.Getenv("CLONE_PREFIX")), "/"),
		RelayURLs:            csvEnv("RELAY_URLS"),
		Listen:               envOrDefault("LISTEN", ":8090"),
		DBPath:               envOrDefault("DB_PATH", "./mappings.db"),
		PubkeyAllowlist:      parseAllowlist(os.Getenv("PUBKEY_ALLOWLIST")),
		ProvisionRateLimit:   intEnv("PROVISION_RATE_LIMIT", 0),
		HookRelayURL:         envOrDefault("HOOK_RELAY_URL", "ws://localhost:3334"),
		HookBinaryPath:       envOrDefault("HOOK_BINARY_PATH", "/usr/local/bin/grasp-pre-receive"),
		GiteaRepositoriesDir: envOrDefault("GITEA_REPOSITORIES_PATH", "/gitea-data/git/repositories"),
		EmbeddedRelay:        boolEnv("EMBEDDED_RELAY", false),
		EmbeddedRelayPort:    intEnv("EMBEDDED_RELAY_PORT", 3334),
		EmbeddedRelayDB:      envOrDefault("EMBEDDED_RELAY_DB", "/data/relay-db"),
		AdminAPIToken:        strings.TrimSpace(os.Getenv("ADMIN_API_TOKEN")),
	}

	if cfg.GiteaAdminToken == "" {
		return Config{}, fmt.Errorf("GITEA_ADMIN_TOKEN is required")
	}

	if cfg.ClonePrefix == "" {
		return Config{}, fmt.Errorf("CLONE_PREFIX is required (e.g. https://git.example.com)")
	}

	if len(cfg.RelayURLs) == 0 {
		return Config{}, fmt.Errorf("RELAY_URLS is required for Phase 1")
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

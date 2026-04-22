// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package config

import (
	"os"
	"testing"
	"time"
)

// setEnvs sets multiple environment variables and returns a cleanup function.
func setEnvs(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func TestLoadMinimalValid(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://relay.example.com",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GiteaAdminToken != "tok123" {
		t.Errorf("expected token 'tok123', got %q", cfg.GiteaAdminToken)
	}
	if len(cfg.RelayURLs) != 1 || cfg.RelayURLs[0] != "wss://relay.example.com" {
		t.Errorf("expected 1 relay URL, got %v", cfg.RelayURLs)
	}
}

func TestLoadMissingToken(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "",
		"RELAY_URLS":        "wss://relay.example.com",
	})
	os.Unsetenv("GITEA_ADMIN_TOKEN")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing GITEA_ADMIN_TOKEN")
	}
}

func TestLoadMissingClonePrefix(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "",
		"RELAY_URLS":        "wss://relay.example.com",
	})
	os.Unsetenv("CLONE_PREFIX")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing CLONE_PREFIX")
	}
}

func TestLoadMissingRelayURLs(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "",
	})
	os.Unsetenv("RELAY_URLS")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing RELAY_URLS")
	}
}

func TestLoadEmbeddedOnlyAllowsEmptyRelayURLs(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "",
		"EMBEDDED_RELAY":    "true",
	})
	os.Unsetenv("RELAY_URLS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should succeed with EMBEDDED_RELAY=true and no RELAY_URLS, got: %v", err)
	}
	if !cfg.EmbeddedRelay {
		t.Error("EmbeddedRelay should be true")
	}
	if len(cfg.RelayURLs) != 0 {
		t.Errorf("RelayURLs should be empty, got %v", cfg.RelayURLs)
	}
}

func TestLoadSidecarStillRequiresRelayURLs(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "",
		"EMBEDDED_RELAY":    "false",
	})
	os.Unsetenv("RELAY_URLS")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: sidecar mode with no RELAY_URLS should fail")
	}
}

func TestEmbeddedRelayConfigMatrix(t *testing.T) {
	tests := []struct {
		name        string
		embedded    string
		relayURLs   string
		unsetRelays bool
		wantErr     bool
		wantRelays  int
		wantEmbed   bool
	}{
		{
			name:       "sidecar with relays",
			embedded:   "false",
			relayURLs:  "wss://relay1",
			wantErr:    false,
			wantRelays: 1,
			wantEmbed:  false,
		},
		{
			name:        "sidecar without relays fails",
			embedded:    "false",
			relayURLs:   "",
			unsetRelays: true,
			wantErr:     true,
		},
		{
			name:       "embedded with external relays",
			embedded:   "true",
			relayURLs:  "wss://external-relay",
			wantErr:    false,
			wantRelays: 1,
			wantEmbed:  true,
		},
		{
			name:        "embedded without relays succeeds",
			embedded:    "true",
			relayURLs:   "",
			unsetRelays: true,
			wantErr:     false,
			wantRelays:  0,
			wantEmbed:   true,
		},
		{
			name:       "embedded with multiple relays",
			embedded:   "true",
			relayURLs:  "wss://r1,wss://r2",
			wantErr:    false,
			wantRelays: 2,
			wantEmbed:  true,
		},
		{
			name:        "unset embedded defaults to sidecar",
			relayURLs:   "",
			unsetRelays: true,
			wantErr:     true,
		},
		{
			name:        "embedded with custom port and db",
			embedded:    "true",
			relayURLs:   "",
			unsetRelays: true,
			wantErr:     false,
			wantRelays:  0,
			wantEmbed:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envs := map[string]string{
				"GITEA_ADMIN_TOKEN": "tok",
				"CLONE_PREFIX":      "https://git.example.com",
				"RELAY_URLS":        tt.relayURLs,
			}
			if tt.embedded != "" {
				envs["EMBEDDED_RELAY"] = tt.embedded
			}
			setEnvs(t, envs)
			if tt.unsetRelays {
				os.Unsetenv("RELAY_URLS")
			}
			if tt.embedded == "" {
				os.Unsetenv("EMBEDDED_RELAY")
			}

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.RelayURLs) != tt.wantRelays {
				t.Errorf("expected %d relay URLs, got %d: %v", tt.wantRelays, len(cfg.RelayURLs), cfg.RelayURLs)
			}
			if cfg.EmbeddedRelay != tt.wantEmbed {
				t.Errorf("expected EmbeddedRelay=%v, got %v", tt.wantEmbed, cfg.EmbeddedRelay)
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://r1",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GiteaURL != "http://gitea:3000" {
		t.Errorf("default GiteaURL: got %q", cfg.GiteaURL)
	}
	if cfg.Listen != ":8090" {
		t.Errorf("default Listen: got %q", cfg.Listen)
	}
	if cfg.DBPath != "./mappings.db" {
		t.Errorf("default DBPath: got %q", cfg.DBPath)
	}
	if cfg.EmbeddedRelay != false {
		t.Error("default EmbeddedRelay should be false")
	}
	if cfg.EmbeddedRelayPort != 3334 {
		t.Errorf("default EmbeddedRelayPort: got %d", cfg.EmbeddedRelayPort)
	}
}

func TestLoadOverridesAllFields(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN":       "my-token",
		"GITEA_URL":               "http://localhost:3001",
		"CLONE_PREFIX":            "https://custom.domain/",
		"RELAY_URLS":              "wss://r1.test, wss://r2.test",
		"LISTEN":                  ":9090",
		"DB_PATH":                 "/tmp/test.db",
		"PUBKEY_ALLOWLIST":        "pk1,pk2",
		"PROVISION_RATE_LIMIT":    "10",
		"HOOK_RELAY_URL":          "ws://hook:1234",
		"HOOK_BINARY_PATH":        "/opt/bin/hook",
		"GITEA_REPOSITORIES_PATH": "/repos",
		"EMBEDDED_RELAY":          "true",
		"EMBEDDED_RELAY_PORT":     "4000",
		"EMBEDDED_RELAY_DB":       "/tmp/relay-db",
		"ADMIN_API_TOKEN":         "admin-secret",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GiteaURL != "http://localhost:3001" {
		t.Errorf("GiteaURL: got %q", cfg.GiteaURL)
	}
	// ClonePrefix should have trailing slash stripped.
	if cfg.ClonePrefix != "https://custom.domain" {
		t.Errorf("ClonePrefix: got %q", cfg.ClonePrefix)
	}
	if len(cfg.RelayURLs) != 2 {
		t.Fatalf("RelayURLs: expected 2, got %d: %v", len(cfg.RelayURLs), cfg.RelayURLs)
	}
	if cfg.RelayURLs[1] != "wss://r2.test" {
		t.Errorf("RelayURLs[1]: got %q", cfg.RelayURLs[1])
	}
	if cfg.ProvisionRateLimit != 10 {
		t.Errorf("ProvisionRateLimit: got %d", cfg.ProvisionRateLimit)
	}
	if cfg.EmbeddedRelay != true {
		t.Error("EmbeddedRelay should be true")
	}
	if cfg.EmbeddedRelayPort != 4000 {
		t.Errorf("EmbeddedRelayPort: got %d", cfg.EmbeddedRelayPort)
	}
	if cfg.AdminAPIToken != "admin-secret" {
		t.Errorf("AdminAPIToken: got %q", cfg.AdminAPIToken)
	}
}

func TestAllowlistEnabled(t *testing.T) {
	empty := Config{PubkeyAllowlist: map[string]struct{}{}}
	if empty.AllowlistEnabled() {
		t.Error("empty allowlist should not be enabled")
	}

	populated := Config{PubkeyAllowlist: map[string]struct{}{"pk1": {}}}
	if !populated.AllowlistEnabled() {
		t.Error("non-empty allowlist should be enabled")
	}
}

func TestCsvEnvParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"a", 1},
		{"a,b,c", 3},
		{" a , b , ", 2},
		{",,,", 0},
	}
	for _, tt := range tests {
		result := csvEnv("__TEST_CSV")
		os.Setenv("__TEST_CSV", tt.input)
		result = csvEnv("__TEST_CSV")
		os.Unsetenv("__TEST_CSV")
		if len(result) != tt.expected {
			t.Errorf("csvEnv(%q): expected %d elements, got %d: %v", tt.input, tt.expected, len(result), result)
		}
	}
}

func TestBoolEnvParsing(t *testing.T) {
	tests := []struct {
		input    string
		fallback bool
		expected bool
	}{
		{"", false, false},
		{"", true, true},
		{"true", false, true},
		{"false", true, false},
		{"1", false, true},
		{"0", true, false},
		{"invalid", true, true},
	}
	for _, tt := range tests {
		os.Setenv("__TEST_BOOL", tt.input)
		if tt.input == "" {
			os.Unsetenv("__TEST_BOOL")
		}
		result := boolEnv("__TEST_BOOL", tt.fallback)
		os.Unsetenv("__TEST_BOOL")
		if result != tt.expected {
			t.Errorf("boolEnv(%q, %v): expected %v, got %v", tt.input, tt.fallback, tt.expected, result)
		}
	}
}

func TestIntEnvParsing(t *testing.T) {
	tests := []struct {
		input    string
		fallback int
		expected int
	}{
		{"", 42, 42},
		{"10", 0, 10},
		{"invalid", 5, 5},
	}
	for _, tt := range tests {
		os.Setenv("__TEST_INT", tt.input)
		if tt.input == "" {
			os.Unsetenv("__TEST_INT")
		}
		result := intEnv("__TEST_INT", tt.fallback)
		os.Unsetenv("__TEST_INT")
		if result != tt.expected {
			t.Errorf("intEnv(%q, %d): expected %d, got %d", tt.input, tt.fallback, tt.expected, result)
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	result := parseAllowlist("pk1, pk2, pk3")
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}
	if _, ok := result["pk2"]; !ok {
		t.Error("expected pk2 in allowlist")
	}

	empty := parseAllowlist("")
	if len(empty) != 0 {
		t.Errorf("empty input should produce empty allowlist, got %d entries", len(empty))
	}
}

func TestAuthEnabledRequiresBridgePublicURL(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN":  "tok",
		"CLONE_PREFIX":       "https://git.example.com",
		"RELAY_URLS":         "wss://relay",
		"AUTH_ENABLED":       "true",
		"BRIDGE_PUBLIC_URL":  "",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when AUTH_ENABLED=true without BRIDGE_PUBLIC_URL")
	}
}

func TestAuthEnabledWithPublicURL(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN":  "tok",
		"CLONE_PREFIX":       "https://git.example.com",
		"RELAY_URLS":         "wss://relay",
		"AUTH_ENABLED":       "true",
		"BRIDGE_PUBLIC_URL":  "https://bridge.example.com/",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AuthEnabled {
		t.Error("expected AuthEnabled=true")
	}
	if cfg.BridgePublicURL != "https://bridge.example.com" {
		t.Errorf("expected trailing slash stripped, got %q", cfg.BridgePublicURL)
	}
}

func TestAuthDisabledByDefault(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://relay",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuthEnabled {
		t.Error("expected AuthEnabled=false by default")
	}
}

func TestChallengeTTLDefault(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://relay",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ChallengeTTL != 5*time.Minute {
		t.Errorf("expected default ChallengeTTL=5m, got %v", cfg.ChallengeTTL)
	}
}

func TestChallengeTTLCustom(t *testing.T) {
	setEnvs(t, map[string]string{
		"GITEA_ADMIN_TOKEN": "tok",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://relay",
		"CHALLENGE_TTL":     "2m30s",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ChallengeTTL != 2*time.Minute+30*time.Second {
		t.Errorf("expected ChallengeTTL=2m30s, got %v", cfg.ChallengeTTL)
	}
}

func TestDurationEnvParsing(t *testing.T) {
	tests := []struct {
		input    string
		fallback time.Duration
		expected time.Duration
	}{
		{"", 5 * time.Minute, 5 * time.Minute},
		{"10s", 5 * time.Minute, 10 * time.Second},
		{"1h", 0, 1 * time.Hour},
		{"invalid", 3 * time.Minute, 3 * time.Minute},
	}
	for _, tt := range tests {
		os.Setenv("__TEST_DUR", tt.input)
		if tt.input == "" {
			os.Unsetenv("__TEST_DUR")
		}
		result := durationEnv("__TEST_DUR", tt.fallback)
		os.Unsetenv("__TEST_DUR")
		if result != tt.expected {
			t.Errorf("durationEnv(%q, %v): expected %v, got %v", tt.input, tt.fallback, tt.expected, result)
		}
	}
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package config

import (
	"os"
	"testing"
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setBridgeBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITEA_ADMIN_TOKEN", "admin-token")
	t.Setenv("CLONE_PREFIX", "https://git.example.com")
	t.Setenv("RELAY_URLS", "wss://relay.example.com")
	// Ensure ambient credentials from the host environment never leak in.
	t.Setenv("GRASP_CREDENTIAL_KEYS", "")
	t.Setenv("BRIDGE_TOKENS_ENABLED", "")
	t.Setenv("GITEA_FULL_PROXY_ENABLED", "")
	t.Setenv("GITEA_ADMIN_USER", "")
	t.Setenv("GRASP_EDGE_SHARED_SECRET", "")
	t.Setenv("BRIDGE_PUBLIC_URL", "")
	t.Setenv("BRIDGE_TOKEN_TTL_DEFAULT", "")
	t.Setenv("BRIDGE_TOKEN_TTL_MIN", "")
	t.Setenv("BRIDGE_TOKEN_TTL_MAX", "")
	t.Setenv("REGISTRY_TOKEN_MAX_LIFETIME", "")
	t.Setenv("REGISTRY_TOKEN_PROBE_INTERVAL", "")
	t.Setenv("REGISTRY_TOKEN_MONITOR_MODE", "")
	t.Setenv("REGISTRY_TOKEN_PROBE_URL", "")
	t.Setenv("REGISTRY_TOKEN_PROBE_USER", "")
	t.Setenv("REGISTRY_TOKEN_PROBE_TOKEN_FILE", "")
	t.Setenv("GRASP_ENV", "")
	t.Setenv("AUTH_ENABLED", "")
	t.Setenv("ADMIN_API_TOKEN", "")
	t.Setenv("SIGNER_MASTER_KEY", "")
	t.Setenv("SIGNET_BUNKER_URL", "")
}

func b64Key(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return base64.StdEncoding.EncodeToString(key)
}

// testEdgeSecret is a 32-byte-equivalent secret satisfying the strength rule.
var testEdgeSecret = strings.Repeat("e", minEdgeSecretLength)

func TestParseCredentialKeysRing(t *testing.T) {
	keys, err := parseCredentialKeys("current:" + b64Key(1) + ", older:" + b64Key(2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 || keys[0].ID != "current" || keys[1].ID != "older" {
		t.Fatalf("keys = %+v", keys)
	}
	if len(keys[0].Key) != 32 {
		t.Fatalf("key length = %d", len(keys[0].Key))
	}

	if _, err := parseCredentialKeys(""); err != nil {
		t.Fatalf("empty is not an error (feature disabled): %v", err)
	}
	for _, bad := range []string{
		"missing-separator",
		"id:short",
		"a:" + b64Key(1) + ",a:" + b64Key(2), // duplicate id
		"bad id!:" + b64Key(1),
		":" + b64Key(1),
		" , ",
	} {
		if _, err := parseCredentialKeys(bad); err == nil {
			t.Errorf("parseCredentialKeys(%q) accepted", bad)
		}
	}
}

func TestBridgeTokensConfigValidation(t *testing.T) {
	setBridgeBaseEnv(t)
	t.Setenv("BRIDGE_TOKENS_ENABLED", "true")

	// Token minting is NIP-98 authenticated, so the auth service must exist.
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_ENABLED") {
		t.Fatalf("bridge tokens without auth service accepted: %v", err)
	}

	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("BRIDGE_PUBLIC_URL", "https://git.example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GRASP_CREDENTIAL_KEYS") {
		t.Fatalf("missing credential keys accepted: %v", err)
	}

	t.Setenv("GRASP_CREDENTIAL_KEYS", "current:"+b64Key(3))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GITEA_ADMIN_USER") {
		t.Fatalf("missing admin user accepted: %v", err)
	}

	t.Setenv("GITEA_ADMIN_USER", "grasp-admin")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GITEA_FULL_PROXY_ENABLED") {
		t.Fatalf("token minting without full proxy accepted (scope bypass): %v", err)
	}

	t.Setenv("GITEA_FULL_PROXY_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GRASP_EDGE_SHARED_SECRET") {
		t.Fatalf("full proxy with browser auth and no edge secret accepted: %v", err)
	}

	t.Setenv("GRASP_EDGE_SHARED_SECRET", testEdgeSecret)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid bridge-token config rejected: %v", err)
	}
	if !cfg.BridgeTokensEnabled || !cfg.FullProxyEnabled || cfg.GiteaAdminUser != "grasp-admin" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.CredentialKeys) != 1 || cfg.CredentialKeys[0].ID != "current" {
		t.Fatalf("credential keys = %+v", cfg.CredentialKeys)
	}
	if cfg.RegistryTokenMaxTTL != 24*time.Hour || cfg.RegistryTokenProbeEvery != 5*time.Minute {
		t.Fatalf("registry monitor defaults = (%s, %s)", cfg.RegistryTokenMaxTTL, cfg.RegistryTokenProbeEvery)
	}
	if cfg.RegistryTokenMonitorMode != "warn" || cfg.RegistryTokenProbeURL != "http://gitea:3000/v2/token?service=container_registry" {
		t.Fatalf("registry probe defaults = (%q, %q)", cfg.RegistryTokenMonitorMode, cfg.RegistryTokenProbeURL)
	}
	if cfg.RegistryTokenProbeUser != "grasp-admin" || cfg.RegistryTokenProbeToken != "admin-token" {
		t.Fatalf("registry probe default credentials = (%q, %q)", cfg.RegistryTokenProbeUser, cfg.RegistryTokenProbeToken)
	}
}

func TestRegistryTokenMonitorConfigValidation(t *testing.T) {
	setBridgeBaseEnv(t)
	t.Setenv("BRIDGE_TOKENS_ENABLED", "true")
	t.Setenv("REGISTRY_TOKEN_MAX_LIFETIME", "0s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REGISTRY_TOKEN_MAX_LIFETIME") {
		t.Fatalf("non-positive maximum lifetime accepted: %v", err)
	}

	t.Setenv("REGISTRY_TOKEN_MAX_LIFETIME", "10m")
	t.Setenv("REGISTRY_TOKEN_PROBE_INTERVAL", "-1s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REGISTRY_TOKEN_PROBE_INTERVAL") {
		t.Fatalf("non-positive probe interval accepted: %v", err)
	}
}

func TestRegistryTokenProbeOverridesAndValidation(t *testing.T) {
	setBridgeBaseEnv(t)

	t.Setenv("REGISTRY_TOKEN_MONITOR_MODE", "optional")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REGISTRY_TOKEN_MONITOR_MODE") {
		t.Fatalf("invalid monitor mode accepted: %v", err)
	}

	t.Setenv("REGISTRY_TOKEN_MONITOR_MODE", "disabled")
	t.Setenv("REGISTRY_TOKEN_PROBE_URL", "/v2/token")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REGISTRY_TOKEN_PROBE_URL") {
		t.Fatalf("relative probe URL accepted: %v", err)
	}

	t.Setenv("REGISTRY_TOKEN_PROBE_URL", "http://registry.internal:3000/custom/token?service=container_registry")
	missing := filepath.Join(t.TempDir(), "missing-token")
	t.Setenv("REGISTRY_TOKEN_PROBE_TOKEN_FILE", missing)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REGISTRY_TOKEN_PROBE_TOKEN_FILE") {
		t.Fatalf("missing probe token file accepted: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "registry-token")
	if err := os.WriteFile(tokenFile, []byte("probe-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_TOKEN_PROBE_TOKEN_FILE", tokenFile)
	t.Setenv("REGISTRY_TOKEN_PROBE_USER", "probe-user")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid registry probe overrides rejected: %v", err)
	}
	if cfg.RegistryTokenMonitorMode != "disabled" || cfg.RegistryTokenProbeURL != "http://registry.internal:3000/custom/token?service=container_registry" {
		t.Fatalf("registry probe override = (%q, %q)", cfg.RegistryTokenMonitorMode, cfg.RegistryTokenProbeURL)
	}
	if cfg.RegistryTokenProbeUser != "probe-user" || cfg.RegistryTokenProbeToken != "probe-secret" || cfg.RegistryTokenProbeTokenFile != tokenFile {
		t.Fatalf("registry probe override credentials = (%q, %q, %q)", cfg.RegistryTokenProbeUser, cfg.RegistryTokenProbeToken, cfg.RegistryTokenProbeTokenFile)
	}
}

func TestFullProxyRequiresEdgeSecretInProduction(t *testing.T) {
	setBridgeBaseEnv(t)
	t.Setenv("GITEA_FULL_PROXY_ENABLED", "true")
	t.Setenv("GRASP_ENV", "production")
	t.Setenv("ADMIN_API_TOKEN", "admin-api")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GRASP_EDGE_SHARED_SECRET") {
		t.Fatalf("production full proxy without edge secret accepted: %v", err)
	}

	// A short, guessable secret is rejected: it authorizes arbitrary
	// X-Grasp-Auth-User impersonation.
	t.Setenv("GRASP_EDGE_SHARED_SECRET", "edge-secret")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("weak edge secret accepted: %v", err)
	}

	t.Setenv("GRASP_EDGE_SHARED_SECRET", testEdgeSecret)
	if _, err := Load(); err != nil {
		t.Fatalf("valid production full-proxy config rejected: %v", err)
	}
}

func TestTokenTTLBoundsValidation(t *testing.T) {
	setBridgeBaseEnv(t)

	t.Setenv("BRIDGE_TOKEN_TTL_MIN", "48h")
	t.Setenv("BRIDGE_TOKEN_TTL_MAX", "24h")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "BRIDGE_TOKEN_TTL_MIN") {
		t.Fatalf("inverted TTL bounds accepted: %v", err)
	}

	t.Setenv("BRIDGE_TOKEN_TTL_MIN", "1h")
	t.Setenv("BRIDGE_TOKEN_TTL_MAX", "24h")
	t.Setenv("BRIDGE_TOKEN_TTL_DEFAULT", "48h")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "BRIDGE_TOKEN_TTL_DEFAULT") {
		t.Fatalf("default outside bounds accepted: %v", err)
	}

	t.Setenv("BRIDGE_TOKEN_TTL_DEFAULT", "12h")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid TTL config rejected: %v", err)
	}
	if cfg.TokenTTLDefault.Hours() != 12 {
		t.Fatalf("TokenTTLDefault = %v", cfg.TokenTTLDefault)
	}
}

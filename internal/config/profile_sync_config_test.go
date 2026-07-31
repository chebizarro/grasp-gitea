// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package config

import (
	"testing"
	"time"
)

func baseProfileSyncEnv(t *testing.T, extra map[string]string) {
	vars := map[string]string{
		"GITEA_ADMIN_TOKEN": "tok123",
		"CLONE_PREFIX":      "https://git.example.com",
		"RELAY_URLS":        "wss://relay.example.com",
	}
	for k, v := range extra {
		vars[k] = v
	}
	setEnvs(t, vars)
}

func TestProfileSyncDisabledByDefault(t *testing.T) {
	baseProfileSyncEnv(t, nil)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProfileSyncEnabled {
		t.Fatal("profile sync should default off")
	}
}

func TestProfileSyncEnabledIndependentOfBridgeTokens(t *testing.T) {
	baseProfileSyncEnv(t, map[string]string{
		"PROFILE_SYNC_ENABLED": "true",
		"GITEA_ADMIN_USER":     "admin",
		// deliberately no BRIDGE_TOKENS_ENABLED / credential keys
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ProfileSyncEnabled || cfg.ProfileSyncInterval != 10*time.Minute || cfg.ProfileSyncWorkers != 4 {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
}

func TestProfileSyncRequiresAdminUser(t *testing.T) {
	baseProfileSyncEnv(t, map[string]string{"PROFILE_SYNC_ENABLED": "true"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error without GITEA_ADMIN_USER")
	}
}

func TestProfileSyncRejectsOutOfRange(t *testing.T) {
	for _, tc := range []map[string]string{
		{"PROFILE_SYNC_INTERVAL": "10s"},
		{"PROFILE_SYNC_INTERVAL": "48h"},
		{"PROFILE_SYNC_WORKERS": "0"},
		{"PROFILE_SYNC_WORKERS": "64"},
	} {
		extra := map[string]string{"PROFILE_SYNC_ENABLED": "true", "GITEA_ADMIN_USER": "admin"}
		for k, v := range tc {
			extra[k] = v
		}
		baseProfileSyncEnv(t, extra)
		if _, err := Load(); err == nil {
			t.Errorf("expected error for %v", tc)
		}
	}
}

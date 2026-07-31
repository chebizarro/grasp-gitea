// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Configuration that is not documented is configuration nobody can safely
// deploy. This test fails when a new environment variable is read by
// config.go but not documented in .env.example.
//
// undocumentedLegacyVars records the drift that already existed when this
// guard was added. Entries may be REMOVED as they get documented; adding to
// the list requires a deliberate decision and should be rare.
var undocumentedLegacyVars = map[string]bool{
	// Environment detection aliases.
	"APP_ENV": true, "ENVIRONMENT": true, "GRASP_ENV": true,
	// Canonical GRASP origins (documented in deploy/grasp-canonical.env.example).
	"GRASP_PUBLIC_URL": true, "GRASP_RELAY_URL": true,
	// Embedded relay.
	"EMBEDDED_RELAY": true, "EMBEDDED_RELAY_DB": true, "EMBEDDED_RELAY_PORT": true,
	// Legacy CI trigger path.
	"CI_ENABLED": true, "CI_PROTOCOL": true, "CI_TRIGGER_REPOS": true,
	"HIVE_CI_MAX_CONCURRENT": true, "HIVE_CI_RUN_TIMEOUT": true,
	// Loom dispatch subsystem.
	"LOOM_CASHU_MAX_PAYMENT": true, "LOOM_CASHU_WALLET_PATH": true,
	"LOOM_DISPATCH_MODE": true, "LOOM_ENABLED": true, "LOOM_FUTURE_SKEW": true,
	"LOOM_JOB_CMD_TEMPLATE": true, "LOOM_JOB_MAX_DURATION": true,
	"LOOM_JOB_TTL": true, "LOOM_LOG_MAX_BYTES": true, "LOOM_MAX_JOBS": true,
	"LOOM_MINT_URL": true, "LOOM_PAYMENT_MODE": true, "LOOM_RELAY_URLS": true,
	"LOOM_RESULT_GRACE": true, "LOOM_STATIC_PAYMENT_TOKEN": true,
	"LOOM_STATUS_CONTEXT_PREFIX": true, "LOOM_WORKER_PUBKEYS": true,
	// Misc.
	"MIRROR_CALLBACK_TOKEN": true, "NIP34_STATUS_SYNC_ENABLED": true,
	"NIP46_TRUSTED_PROXY_CIDRS": true,
}

func TestEveryConfigEnvVarIsDocumented(t *testing.T) {
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	envExample, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}

	// Every env var this package reads appears as a SHOUTY_CASE string
	// literal in config.go.
	literal := regexp.MustCompile(`"([A-Z][A-Z0-9_]{2,})"`)
	seen := map[string]bool{}
	var names []string
	for _, m := range literal.FindAllStringSubmatch(string(source), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	if len(names) < 20 {
		t.Fatalf("only %d env vars discovered; the extraction regex is probably broken", len(names))
	}

	documented := func(name string) bool {
		for _, line := range strings.Split(string(envExample), "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
			if strings.HasPrefix(line, name+"=") {
				return true
			}
		}
		return false
	}

	for _, name := range names {
		switch {
		case documented(name):
			if undocumentedLegacyVars[name] {
				t.Errorf("%s is now documented; remove it from undocumentedLegacyVars", name)
			}
		case undocumentedLegacyVars[name]:
			// Known pre-existing gap.
		default:
			t.Errorf("%s is read by config.go but not documented in .env.example", name)
		}
	}
}

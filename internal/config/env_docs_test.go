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
	// Environment detection aliases (ENVIRONMENT itself is documented).
	"APP_ENV": true, "GRASP_ENV": true,
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

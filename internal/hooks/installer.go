// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// safeShellValue matches values that are safe to embed in single-quoted
// shell strings (no single quotes, backslashes, or control characters).
var safeShellValue = regexp.MustCompile(`^[a-zA-Z0-9:/_.\-]+$`)

type Installer struct {
	repositoriesPath string
	hookBinaryPath   string
	hookRelayURL     string
}

func NewInstaller(repositoriesPath string, hookBinaryPath string, hookRelayURL string) *Installer {
	return &Installer{
		repositoriesPath: repositoriesPath,
		hookBinaryPath:   hookBinaryPath,
		hookRelayURL:     hookRelayURL,
	}
}

// Install writes the pre-receive hook for a repository.
// orgName is the Gitea org (may be a NIP-05 local-part or hex prefix).
// npub is the canonical Nostr identity passed to the hook for state lookups.
func (i *Installer) Install(orgName string, npub string, repoID string) error {
	// Validate all values that will be embedded in the shell script to
	// prevent injection. Values should only contain alphanumeric, colon,
	// slash, underscore, period, and hyphen characters.
	for name, val := range map[string]string{
		"hookRelayURL":   i.hookRelayURL,
		"npub":           npub,
		"repoID":         repoID,
		"hookBinaryPath": i.hookBinaryPath,
	} {
		if !safeShellValue.MatchString(val) {
			return fmt.Errorf("unsafe characters in %s: %q", name, val)
		}
	}

	repoGitDir := filepath.Join(i.repositoriesPath, orgName, repoID+".git")
	if st, err := os.Stat(repoGitDir); err != nil || !st.IsDir() {
		return fmt.Errorf("repository path not found: %s", repoGitDir)
	}

	hooksDir := filepath.Join(repoGitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-receive")
	script := fmt.Sprintf("#!/bin/sh\nexport GRASP_HOOK_RELAY_URL='%s'\nexport GRASP_REPO_NPUB='%s'\nexport GRASP_REPO_ID='%s'\nexec '%s' \"$@\"\n",
		i.hookRelayURL, npub, repoID, i.hookBinaryPath)

	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("write pre-receive hook: %w", err)
	}
	return nil
}

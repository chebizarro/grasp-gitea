package hooks

import (
	"fmt"
	"os"
	"path/filepath"
)

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

func (i *Installer) Install(npub string, repoID string) error {
	repoGitDir := filepath.Join(i.repositoriesPath, npub, repoID+".git")
	if st, err := os.Stat(repoGitDir); err != nil || !st.IsDir() {
		return fmt.Errorf("repository path not found: %s", repoGitDir)
	}

	hooksDir := filepath.Join(repoGitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-receive")
	script := fmt.Sprintf(`#!/bin/sh
export GRASP_HOOK_RELAY_URL=%q
export GRASP_REPO_NPUB=%q
export GRASP_REPO_ID=%q
exec %q "$@"
`, i.hookRelayURL, npub, repoID, i.hookBinaryPath)

	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("write pre-receive hook: %w", err)
	}
	return nil
}

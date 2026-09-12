// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/policy"
)

// uploadPackCapabilities are the per-repository git settings GRASP-01 servers
// must advertise so clients can use partial clone and request advertised tips
// (e.g. PR tips under refs/nostr/*) directly by SHA.
var uploadPackCapabilities = [][2]string{
	{"uploadpack.allowFilter", "true"},
	{"uploadpack.allowTipSHA1InWant", "true"},
	{"uploadpack.allowReachableSHA1InWant", "true"},
	{"uploadpack.allowAnySHA1InWant", "true"},
}

// safeShellValue matches values that are safe to embed in single-quoted
// shell strings (no single quotes, backslashes, or control characters).
var safeShellValue = regexp.MustCompile(`^[a-zA-Z0-9:/_.\-]+$`)

const migrationMarker = "grasp-migrating"

type Installer struct {
	repositoriesPath string
	hookBinaryPath   string
	hookRelayURL     string
	policy           *policy.Store
}

func (i *Installer) SetPolicyStore(store *policy.Store) { i.policy = store }

func (i *Installer) relayURL() string {
	if snapshot := i.policy.Current(); snapshot != nil && snapshot.HookRelayURL != "" {
		return snapshot.HookRelayURL
	}
	return i.hookRelayURL
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
	return i.InstallAt(orgName, repoID, npub, repoID)
}

// InstallAt installs a hook at the physical Gitea repository name while
// preserving the canonical NIP-34 repository identifier in the hook environment.
func (i *Installer) InstallAt(orgName, repoName, npub, repoID string) error {
	script, err := i.renderHook(npub, repoID, true)
	if err != nil {
		return err
	}
	repoGitDir := filepath.Join(i.repositoriesPath, orgName, repoName+".git")
	if st, err := os.Stat(repoGitDir); err != nil || !st.IsDir() {
		return fmt.Errorf("repository path not found: %s", repoGitDir)
	}
	hooksDir := filepath.Join(repoGitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}
	if err := atomicWriteExecutable(hooksDir, "pre-receive", []byte(script)); err != nil {
		return fmt.Errorf("write pre-receive hook: %w", err)
	}
	if err := configureUploadPack(repoGitDir); err != nil {
		return fmt.Errorf("configure upload-pack capabilities: %w", err)
	}
	return nil
}

func (i *Installer) renderHook(npub, repoID string, migrationAware bool) (string, error) {
	hookRelayURL := i.relayURL()
	for name, val := range map[string]string{"hookRelayURL": hookRelayURL, "npub": npub, "repoID": repoID, "hookBinaryPath": i.hookBinaryPath} {
		if !safeShellValue.MatchString(val) {
			return "", fmt.Errorf("unsafe characters in %s: %q", name, val)
		}
	}
	guard := ""
	if migrationAware {
		guard = fmt.Sprintf("if [ -e \"$(git rev-parse --git-dir)/%s\" ]; then\n  echo 'repository migration in progress; pushes are temporarily disabled' >&2\n  exit 1\nfi\n", migrationMarker)
	}
	return fmt.Sprintf("#!/bin/sh\n%sexport GRASP_HOOK_RELAY_URL='%s'\nexport GRASP_REPO_NPUB='%s'\nexport GRASP_REPO_ID='%s'\nexec '%s' \"$@\"\n", guard, hookRelayURL, npub, repoID, i.hookBinaryPath), nil
}

func renderReferenceTransactionHook() string {
	return fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = 'prepared' ] && [ -e \"$(git rev-parse --git-dir)/%s\" ]; then\n  echo 'repository migration in progress; reference updates are temporarily disabled' >&2\n  exit 1\nfi\nexit 0\n", migrationMarker)
}

func atomicWriteExecutable(dir, name string, content []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

// atomicCreateExecutable installs content only when the target is absent. A
// fully written and synced same-directory inode is linked into place, so a
// concurrently created operator hook is never overwritten.
func atomicCreateExecutable(dir, name string, content []byte) error {
	path := filepath.Join(dir, name)
	if body, err := os.ReadFile(path); err == nil {
		if string(body) == string(content) {
			return nil
		}
		return fmt.Errorf("unmanaged %s hook already exists", name)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+"-new-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if body, readErr := os.ReadFile(path); readErr == nil && string(body) == string(content) {
			return nil
		}
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// QuiesceAt upgrades the hook to the migration-aware form, then creates a
// marker inside the bare repository. Direct Gitea pushes and canonical pushes
// both execute this hook and fail with a clear message while the marker exists.
func (i *Installer) QuiesceAt(orgName, repoName, npub, repoID string) error {
	root := filepath.Join(i.repositoriesPath, orgName, repoName+".git")
	guardPath := filepath.Join(root, "hooks", "reference-transaction")
	if err := i.InstallAt(orgName, repoName, npub, repoID); err != nil {
		return err
	}
	if err := atomicCreateExecutable(filepath.Dir(guardPath), filepath.Base(guardPath), []byte(renderReferenceTransactionHook())); err != nil {
		return fmt.Errorf("install migration reference guard: %w", err)
	}
	marker := filepath.Join(root, migrationMarker)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.WriteString("migration in progress\n"); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return syncDir(root)
}

func (i *Installer) UnquiesceAt(orgName, repoName string) error {
	root := filepath.Join(i.repositoriesPath, orgName, repoName+".git")
	err := os.Remove(filepath.Join(root, migrationMarker))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(root)
}

// VerifyAt accepts the exact current hook or the exact pre-migration legacy
// hook. QuiesceAt atomically upgrades the latter before setting the barrier.
func (i *Installer) VerifyAt(orgName, repoName, npub, repoID string) error {
	current, err := i.renderHook(npub, repoID, true)
	if err != nil {
		return err
	}
	legacy, err := i.renderHook(npub, repoID, false)
	if err != nil {
		return err
	}
	return i.verifyHookContent(orgName, repoName, "pre-receive", current, legacy)
}

func (i *Installer) VerifyMigrationAt(orgName, repoName, npub, repoID string) error {
	current, err := i.renderHook(npub, repoID, true)
	if err != nil {
		return err
	}
	if err := i.verifyHookContent(orgName, repoName, "pre-receive", current); err != nil {
		return err
	}
	return i.verifyHookContent(orgName, repoName, "reference-transaction", renderReferenceTransactionHook())
}

func (i *Installer) verifyHookContent(orgName, repoName, hookName string, expected ...string) error {
	path := filepath.Join(i.repositoriesPath, orgName, repoName+".git", "hooks", hookName)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("pre-receive hook is not executable")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, candidate := range expected {
		if string(body) == candidate {
			return nil
		}
	}
	return fmt.Errorf("pre-receive hook content verification failed")
}

// CheckQuiescentAt refuses transfer while Git advertises an in-flight ref or
// object transaction. The migration-aware hook prevents any new transaction
// from passing pre-receive after the marker was created.
func (i *Installer) CheckQuiescentAt(orgName, repoName string) error {
	root := filepath.Join(i.repositoriesPath, orgName, repoName+".git")
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		incomingObjectDir := entry.IsDir() && filepath.Dir(rel) == "objects" && strings.HasPrefix(name, "incoming-")
		if strings.HasSuffix(name, ".lock") || incomingObjectDir {
			return fmt.Errorf("repository has an in-flight Git transaction at %s", path)
		}
		return nil
	})
}

// ConfigureUploadPack applies the required GRASP-01 upload-pack capabilities
// to an already-provisioned repository.
func (i *Installer) ConfigureUploadPack(orgName string, repoID string) error {
	repoGitDir := filepath.Join(i.repositoriesPath, orgName, repoID+".git")
	if st, err := os.Stat(repoGitDir); err != nil || !st.IsDir() {
		return fmt.Errorf("repository path not found: %s", repoGitDir)
	}
	return configureUploadPack(repoGitDir)
}

func configureUploadPack(repoGitDir string) error {
	for _, kv := range uploadPackCapabilities {
		cmd := exec.Command("git", "--git-dir="+repoGitDir, "config", "--local", kv[0], kv[1])
		// Installation runs outside a receive process. Ignore any inherited Git
		// repository context so an empty GIT_DIR/GIT_WORK_TREE cannot redirect or
		// invalidate configuration of the explicit target file.
		cmd.Env = gitConfigEnvironment()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git config %s: %s", kv[0], strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func gitConfigEnvironment() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, item := range env {
		if strings.HasPrefix(item, "GIT_DIR=") || strings.HasPrefix(item, "GIT_WORK_TREE=") || strings.HasPrefix(item, "GIT_COMMON_DIR=") {
			continue
		}
		out = append(out, item)
	}
	return out
}

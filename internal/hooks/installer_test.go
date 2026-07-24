// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesHookScript(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "myorg", "myrepo.git", "hooks")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	installer := NewInstaller(dir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")
	if err := installer.Install("myorg", "npub1abc123", "myrepo"); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	hookPath := filepath.Join(repoDir, "pre-receive")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}

	script := string(content)
	if !strings.Contains(script, "GRASP_HOOK_RELAY_URL='ws://localhost:3334'") {
		t.Errorf("missing relay URL in hook script")
	}
	if !strings.Contains(script, "GRASP_REPO_NPUB='npub1abc123'") {
		t.Errorf("missing npub in hook script")
	}
	if !strings.Contains(script, "GRASP_REPO_ID='myrepo'") {
		t.Errorf("missing repo ID in hook script")
	}
}

func TestInstallRejectsUnsafeValues(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "myorg", "myrepo.git")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	installer := NewInstaller(dir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")

	// repoID with shell metacharacter should be rejected.
	err := installer.Install("myorg", "npub1abc", "repo$(evil)")
	if err == nil {
		t.Fatal("expected error for unsafe repoID")
	}
	if !strings.Contains(err.Error(), "unsafe characters") {
		t.Fatalf("expected 'unsafe characters' error, got: %v", err)
	}

	// npub with backtick should be rejected.
	err = installer.Install("myorg", "npub`whoami`", "myrepo")
	if err == nil {
		t.Fatal("expected error for unsafe npub")
	}

	// npub with spaces should be rejected.
	err = installer.Install("myorg", "npub with spaces", "myrepo")
	if err == nil {
		t.Fatal("expected error for npub with spaces")
	}
}

func TestInstallRejectsNonexistentRepoPath(t *testing.T) {
	dir := t.TempDir()
	installer := NewInstaller(dir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")

	err := installer.Install("nonexistent-org", "npub1abc", "nonexistent-repo")
	if err == nil {
		t.Fatal("expected error for nonexistent repo path")
	}
	if !strings.Contains(err.Error(), "repository path not found") {
		t.Fatalf("expected 'repository path not found' error, got: %v", err)
	}
}

func TestInstallConfiguresUploadPackCapabilities(t *testing.T) {
	reposDir := t.TempDir()
	repoDir := filepath.Join(reposDir, "org1", "repo1.git")
	if err := os.MkdirAll(filepath.Join(repoDir, "hooks"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	installer := NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://relay:3334")
	if err := installer.Install("org1", "npub1abc", "repo1"); err != nil {
		t.Fatalf("install: %v", err)
	}

	for _, key := range []string{"uploadpack.allowFilter", "uploadpack.allowTipSHA1InWant", "uploadpack.allowReachableSHA1InWant"} {
		out, err := exec.Command("git", "config", "--file", filepath.Join(repoDir, "config"), "--get", key).Output()
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if got := strings.TrimSpace(string(out)); got != "true" {
			t.Fatalf("expected %s=true, got %q", key, got)
		}
	}
}

func TestConfigureUploadPackMigratesExistingRepo(t *testing.T) {
	reposDir := t.TempDir()
	repoDir := filepath.Join(reposDir, "org1", "existing.git")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	installer := NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://relay:3334")
	if err := installer.ConfigureUploadPack("org1", "existing"); err != nil {
		t.Fatalf("configure: %v", err)
	}
	out, err := exec.Command("git", "config", "--file", filepath.Join(repoDir, "config"), "--get", "uploadpack.allowReachableSHA1InWant").Output()
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("expected capability set, got %q err %v", out, err)
	}

	if err := installer.ConfigureUploadPack("org1", "missing"); err == nil {
		t.Fatalf("expected error for missing repository")
	}
}

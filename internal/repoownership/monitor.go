// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package repoownership detects ownership and writability drift in managed
// Gitea repositories.
package repoownership

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// MappingLister supplies the repositories managed by this bridge.
type MappingLister interface {
	ListMappings(context.Context) ([]store.Mapping, error)
}

// Mismatch describes one managed repository path that is unsafe for writes.
type Mismatch struct {
	Path   string
	UID    uint32
	GID    uint32
	Reason string
}

// Monitor caches the latest ownership preflight result for readiness checks.
type Monitor struct {
	repositoriesDir string
	mappings        MappingLister
	logger          *slog.Logger
	uid             uint32
	gid             uint32

	scanMu  sync.Mutex
	mu      sync.RWMutex
	count   int64
	scanErr error
}

// New creates a monitor expecting repository files to match the bridge process,
// which the container entrypoint runs as the same uid/gid as Gitea's git user.
func New(repositoriesDir string, mappings MappingLister, logger *slog.Logger) *Monitor {
	return newMonitor(repositoriesDir, mappings, logger, uint32(os.Geteuid()), uint32(os.Getegid()))
}

func newMonitor(repositoriesDir string, mappings MappingLister, logger *slog.Logger, uid, gid uint32) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{repositoriesDir: repositoriesDir, mappings: mappings, logger: logger, uid: uid, gid: gid}
}

func (m *Monitor) Name() string { return "repository_ownership" }

// Scan checks every path in each managed bare repository without following
// symlinks. Drift is reported per path with an explicit operator repair command.
// Any mismatch is returned as an error so callers can fail closed before writes.
func (m *Monitor) Scan(ctx context.Context) error {
	m.scanMu.Lock()
	defer m.scanMu.Unlock()
	if m.mappings == nil {
		return m.storeResult(0, nil)
	}
	mappings, err := m.mappings.ListMappings(ctx)
	if err != nil {
		return m.storeResult(0, fmt.Errorf("list managed repositories: %w", err))
	}

	var total int64
	var scanErrors []error
	for _, mapping := range mappings {
		if err := ctx.Err(); err != nil {
			return m.storeResult(total, err)
		}
		repoPath := repositoryPath(m.repositoriesDir, mapping)
		mismatches, scanErr := findMismatches(repoPath, m.uid, m.gid)
		if scanErr != nil {
			total++
			scanErrors = append(scanErrors, fmt.Errorf("%s (%s): %w", repositoryAddress(mapping), repoPath, scanErr))
			m.logger.Error("repository ownership preflight failed", "repo_address", repositoryAddress(mapping), "repo_path", repoPath, "error", scanErr, "repair_command", RepairCommand(repoPath, m.uid, m.gid))
			continue
		}
		if len(mismatches) == 0 {
			continue
		}
		total += int64(len(mismatches))
		for _, mismatch := range mismatches {
			m.logger.Error("managed repository ownership or writability mismatch",
				"repo_address", repositoryAddress(mapping),
				"repo_path", repoPath,
				"offending_path", mismatch.Path,
				"actual_uid", mismatch.UID,
				"actual_gid", mismatch.GID,
				"expected_uid", m.uid,
				"expected_gid", m.gid,
				"reason", mismatch.Reason,
			)
		}
		m.logger.Error("managed repository is not safely writable by Gitea git user",
			"repo_address", repositoryAddress(mapping),
			"repo_path", repoPath,
			"ownership_mismatch_count", len(mismatches),
			"repair_command", RepairCommand(repoPath, m.uid, m.gid),
		)
	}
	if total != 0 {
		scanErrors = append(scanErrors, fmt.Errorf("%d unsafe managed repository paths detected; see bridge logs for repo paths and repair commands", total))
	}
	return m.storeResult(total, errors.Join(scanErrors...))
}

// Run periodically refreshes the readiness result. Each scan is delayed by the
// interval plus up to 20 percent jitter to avoid synchronized fleet scans.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	for {
		jitterMax := interval / 5
		jitter := time.Duration(0)
		if jitterMax > 0 {
			jitter = time.Duration(rand.Int64N(int64(jitterMax)))
		}
		timer := time.NewTimer(interval + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := m.Scan(ctx); err != nil && ctx.Err() == nil {
				m.logger.Error("periodic repository ownership preflight failed", "error", err)
			}
		}
	}
}

func (m *Monitor) storeResult(count int64, err error) error {
	m.mu.Lock()
	m.count, m.scanErr = count, err
	m.mu.Unlock()
	metrics.SetRepositoryOwnershipDrift(count)
	return err
}

// Check implements api.ReadinessProbe using the latest preflight scan.
func (m *Monitor) Check(context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.scanErr != nil {
		return m.scanErr
	}
	if m.count != 0 {
		return fmt.Errorf("%d unsafe managed repository paths detected; see bridge logs for repair commands", m.count)
	}
	return nil
}

// Diagnose returns ownership details suitable for attaching to a Git permission
// failure log. An empty string means no mismatch was detected.
func (m *Monitor) Diagnose(repoPath string) string {
	mismatches, err := findMismatches(repoPath, m.uid, m.gid)
	if err != nil {
		return fmt.Sprintf("ownership scan failed: %v; repair: %s", err, RepairCommand(repoPath, m.uid, m.gid))
	}
	if len(mismatches) == 0 {
		return ""
	}
	first := mismatches[0]
	return fmt.Sprintf("%d unsafe repository paths; first=%s uid=%d gid=%d reason=%s expected_uid=%d expected_gid=%d; repair: %s", len(mismatches), first.Path, first.UID, first.GID, first.Reason, m.uid, m.gid, RepairCommand(repoPath, m.uid, m.gid))
}

// RepairCommand returns the explicit operator-only repair path. The symlink
// guard must pass before ownership or modes are changed; Git alternate object
// directories are referenced by file and are never traversed or changed.
func RepairCommand(repoPath string, uid, gid uint32) string {
	quoted := shellQuote(repoPath)
	return fmt.Sprintf("test -z \"$(find %s -type l -print -quit)\" && chown -R %d:%d %s && chmod -R u+rwX %s", quoted, uid, gid, quoted, quoted)
}

func repositoryAddress(mapping store.Mapping) string {
	return fmt.Sprintf("30617:%s:%s", mapping.Pubkey, mapping.RepoID)
}

func repositoryPath(root string, mapping store.Mapping) string {
	name := mapping.RepoName
	if name == "" {
		name = mapping.RepoID
	}
	return filepath.Join(root, mapping.Owner, name+".git")
}

func findMismatches(repoPath string, uid, gid uint32) ([]Mismatch, error) {
	var mismatches []Mismatch
	rootInfo, err := os.Lstat(repoPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("managed repository path is a symlink: %s", repoPath)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("managed repository path is not a directory: %s", repoPath)
	}

	err = filepath.WalkDir(repoPath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in managed repository write path: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("ownership metadata unavailable for %s", path)
		}
		reasons := make([]string, 0, 2)
		if stat.Uid != uid || stat.Gid != gid {
			reasons = append(reasons, "uid/gid mismatch")
		}
		if info.IsDir() {
			if info.Mode().Perm()&0o300 != 0o300 {
				reasons = append(reasons, "directory lacks owner write/execute permission")
			}
		} else if info.Mode().IsRegular() {
			if info.Mode().Perm()&0o200 == 0 {
				reasons = append(reasons, "file lacks owner write permission")
			}
		} else {
			reasons = append(reasons, "unsupported filesystem node")
		}
		if len(reasons) > 0 {
			mismatches = append(mismatches, Mismatch{Path: path, UID: stat.Uid, GID: stat.Gid, Reason: strings.Join(reasons, "; ")})
		}
		if path == filepath.Join(repoPath, "objects", "info", "alternates") {
			if err := validateAlternates(repoPath, path); err != nil {
				return err
			}
		}
		return nil
	})
	return mismatches, err
}

func validateAlternates(repoPath, alternatesPath string) error {
	f, err := os.Open(alternatesPath)
	if err != nil {
		return fmt.Errorf("open git alternates file %s: %w", alternatesPath, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		target := value
		if !filepath.IsAbs(target) {
			target = filepath.Join(repoPath, "objects", target)
		}
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("git alternate %q from %s is unavailable: %w", value, alternatesPath, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("git alternate %q from %s is not a directory", value, alternatesPath)
		}
		dir, err := os.Open(target)
		if err != nil {
			return fmt.Errorf("git alternate %q from %s is unreadable: %w", value, alternatesPath, err)
		}
		_, readErr := dir.Readdirnames(1)
		_ = dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("git alternate %q from %s is unreadable: %w", value, alternatesPath, readErr)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read git alternates file %s: %w", alternatesPath, err)
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

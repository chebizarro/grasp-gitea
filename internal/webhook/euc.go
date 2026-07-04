// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// EarliestUniqueCommit returns the first root commit reachable from the given
// default branch in a bare repository. NIP-34 uses this value as the repository
// identity r tag for collaboration events.
func EarliestUniqueCommit(ctx context.Context, gitDir string, defaultBranch string) (string, error) {
	if gitDir == "" {
		return "", fmt.Errorf("git dir is required")
	}
	if defaultBranch == "" {
		defaultBranch = "HEAD"
	}

	candidates := []string{defaultBranch}
	if defaultBranch != "HEAD" && !strings.HasPrefix(defaultBranch, "refs/") {
		candidates = append(candidates, "refs/heads/"+defaultBranch)
	}
	if defaultBranch != "HEAD" {
		candidates = append(candidates, "HEAD")
	}

	var lastErr error
	for _, ref := range uniqueStrings(candidates) {
		out, err := exec.CommandContext(ctx, "git", "--git-dir", gitDir, "rev-list", "--max-parents=0", ref).Output()
		if err != nil {
			lastErr = err
			continue
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 {
			lastErr = fmt.Errorf("no root commits found for %s", ref)
			continue
		}
		return fields[0], nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no refs tried")
	}
	return "", fmt.Errorf("compute earliest unique commit for %s: %w", gitDir, lastErr)
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

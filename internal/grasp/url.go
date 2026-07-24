// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package grasp holds helpers for the canonical GRASP-01 service surface.
package grasp

import (
	"net/url"
	"strings"
)

// CanonicalCloneURL returns the canonical GRASP-01 clone URL
// <publicURL>/<npub>/<percent-encoded-identifier>.git for a repository.
// Returns "" when no canonical public URL is configured.
func CanonicalCloneURL(publicURL string, npub string, repoID string) string {
	publicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if publicURL == "" || npub == "" || repoID == "" {
		return ""
	}
	return publicURL + "/" + url.PathEscape(npub) + "/" + url.PathEscape(repoID) + ".git"
}

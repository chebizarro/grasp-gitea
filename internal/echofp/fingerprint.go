// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package echofp defines deterministic fingerprints for bridge-reflected Gitea
// writes. Both the Nostr reflector and Gitea webhook guard use these helpers so
// duplicate webhooks are suppressed only when their content still matches what
// the bridge wrote.
package echofp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Issue returns the fingerprint for a reflected issue create/edit payload.
func Issue(title, body string) string {
	return hashParts("issue", normalize(title), normalize(body))
}

// Comment returns the fingerprint for a reflected issue or PR comment payload.
func Comment(body string) string {
	return hashParts("comment", normalize(body))
}

// IssueStatus returns the fingerprint for a reflected issue state transition.
func IssueStatus(state string) string {
	return strings.ToLower(normalize(state))
}

// PROpen returns the fingerprint for a reflected PR open payload.
func PROpen(title, body string) string {
	return hashParts("pr-open", normalize(title), normalize(body))
}

// PRUpdate returns the fingerprint for a reflected PR head-tip update.
func PRUpdate(headTipSHA string) string {
	return strings.ToLower(normalize(headTipSHA))
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

func hashParts(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

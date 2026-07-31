// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

// Git smart-HTTP service names.
const (
	gitUploadPack  = "git-upload-pack"
	gitReceivePack = "git-receive-pack"
)

// classifyGit recognizes Git smart and dumb HTTP requests under a *.git path
// and maps them to the bridge scope they require. Unknown or unsupported
// service values are rejected (ok=false) rather than guessed.
func classifyGit(r *http.Request) (Action, string, bool) {
	path := r.URL.Path
	idx := strings.Index(path, ".git/")
	if idx < 0 {
		return "", "", false
	}
	subpath := path[idx+len(".git/"):]

	switch {
	case subpath == "info/refs":
		// The advertised service decides read vs write; a missing or unknown
		// service parameter is not a valid smart-HTTP request.
		switch r.URL.Query().Get("service") {
		case gitUploadPack:
			return ActionRead, auth.ScopeGitRead, true
		case gitReceivePack:
			return ActionWrite, auth.ScopeGitWrite, true
		default:
			return "", "", false
		}
	case subpath == gitUploadPack:
		if r.Method != http.MethodPost {
			return "", "", false
		}
		return ActionRead, auth.ScopeGitRead, true
	case subpath == gitReceivePack:
		if r.Method != http.MethodPost {
			return "", "", false
		}
		return ActionWrite, auth.ScopeGitWrite, true
	case subpath == "HEAD",
		strings.HasPrefix(subpath, "objects/"),
		strings.HasPrefix(subpath, "refs/"):
		// Dumb HTTP object/ref fetches are reads.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return "", "", false
		}
		return ActionRead, auth.ScopeGitRead, true
	}
	return "", "", false
}

// IsGitSmartHTTPSubpath reports whether a mapped-npub subpath is one of the
// three canonical smart-HTTP endpoints.
func IsGitSmartHTTPSubpath(subpath string) bool {
	switch subpath {
	case "info/refs", gitUploadPack, gitReceivePack:
		return true
	default:
		return false
	}
}

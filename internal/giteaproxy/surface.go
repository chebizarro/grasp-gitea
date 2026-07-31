// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package giteaproxy is the bridge's single reverse proxy toward Gitea. It
// streams every request (git packs, package artifacts, LFS objects) without
// buffering, classifies the target surface, and translates bridge-issued
// credentials into the downstream credential shape Gitea expects.
package giteaproxy

import (
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

// Surface is the closed set of Gitea HTTP surfaces the classifier recognizes.
type Surface string

const (
	SurfaceGit       Surface = "git"
	SurfacePackages  Surface = "packages"
	SurfaceContainer Surface = "container"
	SurfaceAPI       Surface = "api"
	SurfaceLFS       Surface = "lfs"
	SurfaceWeb       Surface = "web"
	SurfaceUnknown   Surface = "unknown"
)

// Action is the access class a request needs on its surface.
type Action string

const (
	ActionRead          Action = "read"
	ActionWrite         Action = "write"
	ActionTokenExchange Action = "token_exchange"
	ActionSession       Action = "session"
)

// Classification is the result of inspecting a request's path, method, and
// bounded protocol metadata. Scope is the bridge scope required to use a
// bridge token here; an empty Scope means bridge tokens are not yet supported
// on this surface and must be rejected rather than forwarded.
type Classification struct {
	Surface Surface
	Action  Action
	Scope   string
}

// BridgeTokensSupported reports whether a bridge token may be exchanged for a
// hidden PAT on this classification.
func (c Classification) BridgeTokensSupported() bool {
	return c.Scope != ""
}

// Classify determines the surface and action for a request. It runs before
// authentication so scope requirements are deterministic and never depend on
// who is calling.
//
// Git smart HTTP and the /api/packages/ registry family carry bridge scopes.
// Container (/v2), REST API, and LFS paths are classified so bridge tokens
// fail closed there with a clear error until their adapters land, rather
// than being forwarded verbatim.
func Classify(r *http.Request) Classification {
	path := r.URL.Path

	switch {
	case isLFSPath(path):
		return Classification{Surface: SurfaceLFS, Action: lfsAction(r)}
	case strings.HasPrefix(path, "/v2/"), path == "/v2":
		class := Classification{Surface: SurfaceContainer, Action: containerAction(r)}
		if class.Action == ActionTokenExchange {
			// The docker token exchange is the only container endpoint where a
			// bridge token may appear (as Basic auth). Everything after it
			// carries Gitea's short-lived registry JWT, which passes through.
			class.Scope = dockerTokenScope(r)
		}
		return class
	case strings.HasPrefix(path, "/api/packages/"):
		return Classification{Surface: SurfacePackages, Action: methodAction(r), Scope: packagesScope(r)}
	case strings.HasPrefix(path, "/api/v1/"):
		return Classification{Surface: SurfaceAPI, Action: methodAction(r)}
	}

	if action, scope, ok := classifyGit(r); ok {
		return Classification{Surface: SurfaceGit, Action: action, Scope: scope}
	}
	return Classification{Surface: SurfaceWeb, Action: methodAction(r)}
}

func methodAction(r *http.Request) Action {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return ActionRead
	}
	return ActionWrite
}

// packagesScope maps a package-registry request to the bridge scope it
// requires. Reads (download, metadata) need packages:read; anything mutating
// (publish, delete, and any unrecognized method) needs packages:write, so an
// unknown verb fails toward the stronger requirement rather than the weaker.
func packagesScope(r *http.Request) string {
	if methodAction(r) == ActionRead {
		return auth.ScopePackagesRead
	}
	return auth.ScopePackagesWrite
}

func containerAction(r *http.Request) Action {
	// Docker's login exchange trades Basic credentials for a registry token.
	// Only the exact token endpoint and the version probe are the exchange:
	// a suffix match would misclassify a manifest legitimately named "token"
	// (e.g. PUT /v2/o/img/manifests/token) and let a read-only bridge token
	// reach a write endpoint with the hidden PAT's full authority.
	switch r.URL.Path {
	case "/v2/token":
		return ActionTokenExchange
	case "/v2", "/v2/":
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return ActionTokenExchange
		}
	}
	return methodAction(r)
}

// dockerTokenScope maps the docker-requested access (the repeated `scope`
// query parameter, `resource:name:action[,action...]`) to the bridge scope
// the exchange requires. Pull-only needs packages:read; push or delete needs
// packages:write. No requested scope (a bare `docker login` probe) is an
// authentication check and needs packages:read. Any malformed scope or
// unknown action returns "" so the exchange fails closed rather than
// guessing at authority.
func dockerTokenScope(r *http.Request) string {
	requested := r.URL.Query()["scope"]
	if len(requested) == 0 {
		return auth.ScopePackagesRead
	}
	write := false
	for _, s := range requested {
		// Strictly resource:name:actions with non-empty components and a
		// recognized resource type. Anything looser risks the bridge and
		// Gitea interpreting the same scope differently.
		parts := strings.SplitN(s, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return ""
		}
		switch parts[0] {
		case "repository", "registry":
		default:
			return ""
		}
		for _, action := range strings.Split(parts[2], ",") {
			switch action {
			case "pull":
			case "push", "delete", "*":
				write = true
			default:
				return ""
			}
		}
	}
	if write {
		return auth.ScopePackagesWrite
	}
	return auth.ScopePackagesRead
}

func isLFSPath(path string) bool {
	return strings.Contains(path, "/info/lfs/") || strings.HasSuffix(path, "/info/lfs")
}

func lfsAction(r *http.Request) Action {
	return methodAction(r)
}

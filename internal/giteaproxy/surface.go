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
		return Classification{Surface: SurfaceContainer, Action: containerAction(r)}
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
	if strings.HasSuffix(r.URL.Path, "/token") || strings.HasSuffix(r.URL.Path, "/v2/") || r.URL.Path == "/v2" {
		return ActionTokenExchange
	}
	return methodAction(r)
}

func isLFSPath(path string) bool {
	return strings.Contains(path, "/info/lfs/") || strings.HasSuffix(path, "/info/lfs")
}

func lfsAction(r *http.Request) Action {
	return methodAction(r)
}

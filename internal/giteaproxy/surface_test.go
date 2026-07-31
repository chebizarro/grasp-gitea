// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

func TestClassifyGitSmartHTTP(t *testing.T) {
	cases := []struct {
		method     string
		target     string
		wantAction Action
		wantScope  string
	}{
		{http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", ActionRead, auth.ScopeGitRead},
		{http.MethodGet, "/owner/repo.git/info/refs?service=git-receive-pack", ActionWrite, auth.ScopeGitWrite},
		{http.MethodPost, "/owner/repo.git/git-upload-pack", ActionRead, auth.ScopeGitRead},
		{http.MethodPost, "/owner/repo.git/git-receive-pack", ActionWrite, auth.ScopeGitWrite},
		{http.MethodGet, "/owner/repo.git/HEAD", ActionRead, auth.ScopeGitRead},
		{http.MethodGet, "/owner/repo.git/objects/info/packs", ActionRead, auth.ScopeGitRead},
		{http.MethodGet, "/npub1x/repo.git/info/refs?service=git-upload-pack", ActionRead, auth.ScopeGitRead},
	}
	for _, tc := range cases {
		class := Classify(httptest.NewRequest(tc.method, tc.target, nil))
		if class.Surface != SurfaceGit {
			t.Errorf("%s %s surface = %q, want git", tc.method, tc.target, class.Surface)
			continue
		}
		if class.Action != tc.wantAction || class.Scope != tc.wantScope {
			t.Errorf("%s %s = (%s, %s), want (%s, %s)",
				tc.method, tc.target, class.Action, class.Scope, tc.wantAction, tc.wantScope)
		}
	}
}

func TestClassifyRejectsAmbiguousGitService(t *testing.T) {
	// A missing or unknown service parameter is not a valid smart-HTTP
	// request; guessing could turn a push into a read classification.
	for _, target := range []string{
		"/owner/repo.git/info/refs",
		"/owner/repo.git/info/refs?service=git-evil-pack",
		"/owner/repo.git/info/refs?service=",
	} {
		class := Classify(httptest.NewRequest(http.MethodGet, target, nil))
		if class.Surface == SurfaceGit {
			t.Errorf("Classify(%q) surface = git, want non-git", target)
		}
	}

	// Pack endpoints are POST-only.
	class := Classify(httptest.NewRequest(http.MethodGet, "/owner/repo.git/git-receive-pack", nil))
	if class.Surface == SurfaceGit {
		t.Error("GET git-receive-pack classified as git")
	}
}

func TestClassifyNonGitSurfaces(t *testing.T) {
	cases := []struct {
		method      string
		target      string
		wantSurface Surface
		wantAction  Action
		wantScope   string
	}{
		{http.MethodGet, "/api/packages/owner/npm/pkg", SurfacePackages, ActionRead, auth.ScopePackagesRead},
		{http.MethodHead, "/api/packages/owner/pypi/simple/pkg/", SurfacePackages, ActionRead, auth.ScopePackagesRead},
		{http.MethodPut, "/api/packages/owner/npm/pkg", SurfacePackages, ActionWrite, auth.ScopePackagesWrite},
		{http.MethodPost, "/api/packages/owner/pypi", SurfacePackages, ActionWrite, auth.ScopePackagesWrite},
		{http.MethodDelete, "/api/packages/owner/cargo/pkg/1.0.0", SurfacePackages, ActionWrite, auth.ScopePackagesWrite},
		{http.MethodGet, "/api/v1/user", SurfaceAPI, ActionRead, ""},
		{http.MethodPost, "/api/v1/repos/o/r/issues", SurfaceAPI, ActionWrite, ""},
		{http.MethodGet, "/v2/", SurfaceContainer, ActionTokenExchange, ""},
		{http.MethodGet, "/v2/token", SurfaceContainer, ActionTokenExchange, ""},
		{http.MethodPatch, "/v2/owner/img/blobs/uploads/abc", SurfaceContainer, ActionWrite, ""},
		{http.MethodPost, "/owner/repo.git/info/lfs/objects/batch", SurfaceLFS, ActionWrite, ""},
		{http.MethodGet, "/explore/repos", SurfaceWeb, ActionRead, ""},
		{http.MethodGet, "/", SurfaceWeb, ActionRead, ""},
	}
	for _, tc := range cases {
		class := Classify(httptest.NewRequest(tc.method, tc.target, nil))
		if class.Surface != tc.wantSurface || class.Action != tc.wantAction {
			t.Errorf("%s %s = (%s, %s), want (%s, %s)",
				tc.method, tc.target, class.Surface, class.Action, tc.wantSurface, tc.wantAction)
		}
		// Bridge tokens are accepted on git and packages; every other surface
		// must fail closed until its adapter lands.
		if class.Scope != tc.wantScope {
			t.Errorf("%s %s scope = %q, want %q", tc.method, tc.target, class.Scope, tc.wantScope)
		}
	}
}

func TestLFSClassifiedBeforeGit(t *testing.T) {
	// An LFS path also contains ".git/"; LFS must win so bridge tokens do not
	// gain git scope over LFS object transfers.
	class := Classify(httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/lfs/objects/abc", nil))
	if class.Surface != SurfaceLFS {
		t.Fatalf("surface = %q, want lfs", class.Surface)
	}
}

func TestIsGitSmartHTTPSubpath(t *testing.T) {
	for _, good := range []string{"info/refs", "git-upload-pack", "git-receive-pack"} {
		if !IsGitSmartHTTPSubpath(good) {
			t.Errorf("IsGitSmartHTTPSubpath(%q) = false", good)
		}
	}
	for _, bad := range []string{"", "HEAD", "objects/info/packs", "../../etc/passwd", "info/lfs/objects/batch"} {
		if IsGitSmartHTTPSubpath(bad) {
			t.Errorf("IsGitSmartHTTPSubpath(%q) = true", bad)
		}
	}
}

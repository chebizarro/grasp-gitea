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
		{http.MethodGet, "/api/v1/user", SurfaceAPI, ActionRead, auth.ScopeAPIRead},
		{http.MethodPost, "/api/v1/repos/o/r/issues", SurfaceAPI, ActionWrite, auth.ScopeAPIWrite},
		{http.MethodDelete, "/api/v1/repos/o/r", SurfaceAPI, ActionWrite, auth.ScopeAPIWrite},
		// Admin endpoints never accept a bridge credential.
		{http.MethodGet, "/api/v1/admin/users", SurfaceAPI, ActionRead, ""},
		{http.MethodPost, "/api/v1/admin/users", SurfaceAPI, ActionWrite, ""},
		{http.MethodGet, "/api/v1/admin", SurfaceAPI, ActionRead, ""},
		// A non-admin path that merely shares the prefix string is not admin.
		{http.MethodGet, "/api/v1/adminrepo/x", SurfaceAPI, ActionRead, auth.ScopeAPIRead},
		{http.MethodGet, "/v2/", SurfaceContainer, ActionTokenExchange, auth.ScopePackagesRead},
		{http.MethodGet, "/v2/token", SurfaceContainer, ActionTokenExchange, auth.ScopePackagesRead},
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

// TestRestrictedAPIPathsRefuseBridgeCredentials: endpoints that can mint or
// manage durable credentials (or reveal the hidden PAT) never accept a
// bridge credential, and non-canonical path spellings fail closed.
func TestRestrictedAPIPathsRefuseBridgeCredentials(t *testing.T) {
	denied := []string{
		"/api/v1/admin",
		"/api/v1/admin/users",
		"/api/v1/users/alice/tokens",
		"/api/v1/users/alice/tokens/42",
		"/api/v1/user/keys",
		"/api/v1/user/keys/7",
		"/api/v1/user/gpg_keys",
		"/api/v1/user/applications/oauth2",
		"/api/v1/user/emails",
		"/api/v1/repos/o/r/keys",
		"/api/v1/repos/o/r/keys/3",
	}
	for _, path := range denied {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			class := Classify(httptest.NewRequest(method, path, nil))
			if class.Scope != "" {
				t.Errorf("%s %s scope = %q, want refused", method, path, class.Scope)
			}
		}
	}

	// Non-canonical spellings whose interpretation could diverge between
	// the classifier and Gitea's router fail closed.
	nonCanonical := []string{
		"/api/v1/../v1/admin/users",
		"/api/v1/./admin/users",
		"/api/v1//admin/users",
		"/api/v1/%2e%2e/v1/admin/users",
		"/api/v1/x%2Fadmin",
		"/api/v1/x%5Cadmin",
	}
	for _, target := range nonCanonical {
		class := Classify(httptest.NewRequest(http.MethodGet, target, nil))
		if class.Surface == SurfaceAPI && class.Scope != "" {
			t.Errorf("GET %s scope = %q, want refused (non-canonical)", target, class.Scope)
		}
	}

	// Similar-looking but legitimate paths keep their scopes.
	allowed := map[string]string{
		"/api/v1/adminrepo/x":        auth.ScopeAPIRead,
		"/api/v1/users/alice/repos":  auth.ScopeAPIRead,
		"/api/v1/user/repos":         auth.ScopeAPIRead,
		"/api/v1/repos/o/r/issues":   auth.ScopeAPIRead,
		"/api/v1/repos/o/r/branches": auth.ScopeAPIRead,
	}
	for path, want := range allowed {
		class := Classify(httptest.NewRequest(http.MethodGet, path, nil))
		if class.Scope != want {
			t.Errorf("GET %s scope = %q, want %q", path, class.Scope, want)
		}
	}
}

func TestDockerTokenScopeMapping(t *testing.T) {
	cases := []struct {
		target    string
		wantScope string
	}{
		// A bare login probe is an authentication check.
		{"/v2/token", auth.ScopePackagesRead},
		{"/v2/token?service=container_registry&scope=repository:o/img:pull", auth.ScopePackagesRead},
		{"/v2/token?scope=repository:o/img:pull,push", auth.ScopePackagesWrite},
		{"/v2/token?scope=repository:o/img:push", auth.ScopePackagesWrite},
		{"/v2/token?scope=repository:o/img:delete", auth.ScopePackagesWrite},
		{"/v2/token?scope=registry:catalog:*", auth.ScopePackagesWrite},
		// Two scope params: the union decides.
		{"/v2/token?scope=repository:a/x:pull&scope=repository:b/y:push", auth.ScopePackagesWrite},
		// Unknown actions and malformed scopes fail closed.
		{"/v2/token?scope=repository:o/img:admin", ""},
		{"/v2/token?scope=garbage", ""},
		{"/v2/token?scope=repository:o/img:", ""},
		{"/v2/token?scope=repository::pull", ""},
		{"/v2/token?scope=admin:anything:pull", ""},
		{"/v2/token?scope=:o/img:pull", ""},
		// The /v2/ probe is also a token-exchange surface.
		{"/v2/", auth.ScopePackagesRead},
	}
	for _, tc := range cases {
		class := Classify(httptest.NewRequest(http.MethodGet, tc.target, nil))
		if class.Surface != SurfaceContainer || class.Action != ActionTokenExchange {
			t.Errorf("%s = (%s, %s), want container token_exchange", tc.target, class.Surface, class.Action)
		}
		if class.Scope != tc.wantScope {
			t.Errorf("%s scope = %q, want %q", tc.target, class.Scope, tc.wantScope)
		}
	}

	// Non-exchange container paths never carry a bridge scope: they run on
	// Gitea's short-lived registry JWT.
	blob := Classify(httptest.NewRequest(http.MethodGet, "/v2/o/img/blobs/sha256:abc", nil))
	if blob.Scope != "" || blob.Action != ActionRead {
		t.Errorf("blob pull = (%s, %q), want (read, no scope)", blob.Action, blob.Scope)
	}

	// A manifest legitimately named "token" is NOT the exchange: a suffix
	// match here would let a read-only token reach a write endpoint.
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		class := Classify(httptest.NewRequest(method, "/v2/o/img/manifests/token", nil))
		if class.Action != ActionWrite || class.Scope != "" {
			t.Errorf("%s manifests/token = (%s, %q), want (write, no scope)", method, class.Action, class.Scope)
		}
	}
	// A write-method probe is not an exchange either.
	if class := Classify(httptest.NewRequest(http.MethodPost, "/v2/", nil)); class.Action != ActionWrite || class.Scope != "" {
		t.Errorf("POST /v2/ = (%s, %q), want (write, no scope)", class.Action, class.Scope)
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

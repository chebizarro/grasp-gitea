// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/gitea"
)

const testBridgeToken = auth.BridgeTokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// stubAuthenticator is a controllable bridge-token authenticator.
type stubAuthenticator struct {
	enabled   bool
	principal auth.TokenPrincipal
	authErr   error
	patErr    error
	patLogin  string
	patSecret string
}

func (s *stubAuthenticator) Enabled() bool { return s.enabled }

func (s *stubAuthenticator) Authenticate(_ context.Context, token string) (auth.TokenPrincipal, error) {
	if s.authErr != nil {
		return auth.TokenPrincipal{}, s.authErr
	}
	if token != testBridgeToken {
		return auth.TokenPrincipal{}, auth.ErrTokenUnauthorized
	}
	return s.principal, nil
}

func (s *stubAuthenticator) DownstreamPAT(_ context.Context, _ int64, _ string) (string, string, error) {
	if s.patErr != nil {
		return "", "", s.patErr
	}
	return s.patLogin, s.patSecret, nil
}

type stubInspector struct {
	id       int64
	private  bool
	internal bool
	err      error
}

func (s stubInspector) GetRepo(_ context.Context, org, repo string) (gitea.Repository, error) {
	if s.err != nil {
		return gitea.Repository{}, s.err
	}
	return gitea.Repository{
		ID: s.id, Owner: org, Name: repo,
		Private: s.private, Internal: s.internal,
	}, nil
}

// mapped is the canonical mapping used by the npub tests.
func mapped(id int64) MappedRepo {
	return MappedRepo{Owner: "org", Name: "repo", ExpectedID: id}
}

// backendRequest is what the fake Gitea backend saw, copied out under lock.
type backendRequest struct {
	hit           bool
	path          string
	rawQuery      string
	authorization string
	cookie        string
	proxyAuth     string
	authUser      string
	sessionProxy  string
	edgeSecret    string
	nugetAPIKey   string
	body          string
}

// observed guards a backendRequest shared with the backend handler goroutine.
type observed struct {
	mu   sync.Mutex
	last backendRequest
}

func (o *observed) snapshot() backendRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

type proxyEnv struct {
	proxy   *Proxy
	backend *httptest.Server
	seen    *observed
	auth    *stubAuthenticator
}

func newProxyEnv(t *testing.T, cfg Config, tokens *stubAuthenticator, repos RepositoryInspector) *proxyEnv {
	t.Helper()
	seen := &observed{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.last = backendRequest{
			hit:           true,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			cookie:        r.Header.Get("Cookie"),
			proxyAuth:     r.Header.Get("Proxy-Authorization"),
			authUser:      r.Header.Get("X-Grasp-Auth-User"),
			sessionProxy:  r.Header.Get("X-Grasp-Session-Proxy"),
			edgeSecret:    r.Header.Get("X-Grasp-Edge-Secret"),
			nugetAPIKey:   r.Header.Get("X-NuGet-ApiKey"),
			body:          string(body),
		}
		seen.mu.Unlock()
		_, _ = w.Write([]byte("backend ok"))
	}))
	t.Cleanup(backend.Close)

	cfg.GiteaURL = backend.URL
	var authenticator Authenticator
	if tokens != nil {
		authenticator = tokens
	}
	p, err := New(cfg, authenticator, repos, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &proxyEnv{proxy: p, backend: backend, seen: seen, auth: tokens}
}

func basicHeader(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func linkedPrincipal() auth.TokenPrincipal {
	return auth.TokenPrincipal{
		TokenID: "tok1", Pubkey: "pk", Npub: "npub1owner",
		GiteaUserID: 42, GiteaUser: "npub1owner-login",
		Scopes: []string{auth.ScopeGitRead, auth.ScopeGitWrite},
	}
}

// --- Mapped npub (public GRASP) surface -------------------------------------

func TestMappedGitAnonymousPublicRepoUsesServiceIdentity(t *testing.T) {
	env := newProxyEnv(t, Config{
		GitBackendUser: "grasp-bridge", GitBackendPassword: "service-secret",
	}, nil, stubInspector{id: 7, private: false})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("caller", "caller-secret"))
	r.Header.Set("Cookie", "i_like_gitea=session")
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	seen := env.seen.snapshot()
	if seen.path != "/org/repo.git/info/refs" || seen.rawQuery != "service=git-upload-pack" {
		t.Fatalf("backend saw %q?%q", seen.path, seen.rawQuery)
	}
	if seen.authorization != basicHeader("grasp-bridge", "service-secret") {
		t.Fatalf("authorization = %q, want service identity", seen.authorization)
	}
	if seen.cookie != "" {
		t.Fatalf("caller cookie leaked: %q", seen.cookie)
	}
}

func TestMappedGitAnonymousPrivateRepoFailsClosed(t *testing.T) {
	env := newProxyEnv(t, Config{
		GitBackendUser: "grasp-bridge", GitBackendPassword: "service-secret",
	}, nil, stubInspector{id: 7, private: true})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for anonymous access to a private repo", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("private repository was proxied anonymously")
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("WWW-Authenticate = %q, want a Basic challenge so git retries with credentials", got)
	}
}

// TestMappedGitInternalRepoIsNotPublic covers Gitea's "internal" visibility:
// a repository with private=false owned by a private organization still
// requires an authenticated user, so anonymous GRASP access must be refused.
func TestMappedGitInternalRepoIsNotPublic(t *testing.T) {
	env := newProxyEnv(t, Config{
		GitBackendUser: "grasp-bridge", GitBackendPassword: "service-secret",
	}, nil, stubInspector{id: 7, private: false, internal: true})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an internal repository", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("internal repository served anonymously")
	}
}

// TestMappedGitRejectsRepositoryIdentityChange covers deletion and same-path
// recreation: the new repository has no grasp-pre-receive hook, so serving it
// under the original NIP-34 coordinate would bypass Nostr authority.
func TestMappedGitRejectsRepositoryIdentityChange(t *testing.T) {
	env := newProxyEnv(t, Config{
		GitBackendUser: "grasp-bridge", GitBackendPassword: "service-secret",
	}, nil, stubInspector{id: 999})

	r := httptest.NewRequest(http.MethodPost, "/npub1owner/repo.git/git-receive-pack", strings.NewReader("pack"))
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "git-receive-pack")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the mapped repository id changed", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("push forwarded to a repository that is not the mapped one")
	}
}

// TestMappedGitTokenPathAlsoVerifiesIdentity: the identity check applies to
// authenticated requests too, not just anonymous ones.
func TestMappedGitTokenPathAlsoVerifiesIdentity(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{}, tokens, stubInspector{id: 999})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("authenticated request reached the wrong repository")
	}
}

func TestMappedGitVisibilityLookupFailureFailsClosed(t *testing.T) {
	env := newProxyEnv(t, Config{}, nil, stubInspector{err: fmt.Errorf("gitea down")})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when visibility is unknown", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("request proxied despite unknown visibility")
	}
}

func TestMappedGitWithBridgeTokenUsesHiddenPAT(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "npub1owner-login", patSecret: "hidden-pat",
	}
	// Private repository: only the token holder's own access can serve it.
	env := newProxyEnv(t, Config{
		GitBackendUser: "grasp-bridge", GitBackendPassword: "service-secret",
	}, tokens, stubInspector{id: 7, private: true})

	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	seen := env.seen.snapshot()
	if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
		t.Fatalf("authorization = %q, want hidden PAT", seen.authorization)
	}
	if strings.Contains(seen.authorization, testBridgeToken) {
		t.Fatal("bridge token forwarded to Gitea")
	}
}

func TestMappedGitNeverSurfacesBackendChallenge(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Gitea"`)
		w.Header().Set("Set-Cookie", "i_like_gitea=abc")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL}, nil, stubInspector{id: 7}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	p.ServeMappedGit(w, r, mapped(7), "info/refs")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("backend auth state leaked: %+v", w.Header())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("CORS missing on public GRASP error response")
	}
}

// --- Ordinary Gitea surface -------------------------------------------------

func TestServeHTTPPassesThroughOrdinaryCredentials(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true}, nil, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("alice", "alice-gitea-pat"))
	r.Header.Set("Cookie", "i_like_gitea=session")
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	seen := env.seen.snapshot()
	if seen.authorization != basicHeader("alice", "alice-gitea-pat") {
		t.Fatalf("ordinary credential altered: %q", seen.authorization)
	}
	if seen.cookie != "i_like_gitea=session" {
		t.Fatalf("ordinary cookie altered: %q", seen.cookie)
	}
}

func TestServeHTTPBridgeTokenInjectsPATAndStripsCallerCredentials(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "npub1owner-login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodPost, "/owner/repo.git/git-receive-pack", strings.NewReader("packdata"))
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	seen := env.seen.snapshot()
	if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
		t.Fatalf("authorization = %q", seen.authorization)
	}
	if seen.body != "packdata" {
		t.Fatalf("body = %q, want it streamed through", seen.body)
	}
}

func TestServeHTTPBearerBridgeToken(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", "Bearer "+testBridgeToken)
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := env.seen.snapshot().authorization; got != basicHeader("login", "hidden-pat") {
		t.Fatalf("authorization = %q", got)
	}
}

func TestServeHTTPRejectsUsernameMismatch(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("someone-else", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (username must identify the token subject)", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("request forwarded despite username mismatch")
	}
}

func TestServeHTTPRejectsMissingScope(t *testing.T) {
	readOnly := linkedPrincipal()
	readOnly.Scopes = []string{auth.ScopeGitRead}
	tokens := &stubAuthenticator{
		enabled: true, principal: readOnly, patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodPost, "/owner/repo.git/git-receive-pack", strings.NewReader("x"))
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a read-only token pushing", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("push forwarded without git:write")
	}
}

func TestServeHTTPMalformedBridgeCredentialNeverFallsThrough(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true}, &stubAuthenticator{enabled: true}, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", basicHeader("npub1owner", auth.BridgeTokenPrefix+"tooshort"))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("malformed bridge credential was forwarded to Gitea")
	}
}

func TestServeHTTPBridgeTokenOnUnsupportedSurfaceFailsClosed(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	// Container object paths remain the one surface without a bridge-token
	// adapter (only the /v2 token exchange is supported); a bridge token
	// must not be silently exchanged for the hidden PAT's full authority.
	// The principal deliberately holds every enabled scope so the rejection
	// can only come from the surface, not from a missing scope.
	tokens.principal.Scopes = []string{
		auth.ScopeGitRead, auth.ScopeGitWrite,
		auth.ScopePackagesRead, auth.ScopePackagesWrite,
		auth.ScopeAPIRead, auth.ScopeAPIWrite,
		auth.ScopeLFSRead, auth.ScopeLFSWrite,
	}
	for _, path := range []string{
		"/v2/owner/image/blobs/uploads/",
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", path, w.Code)
		}
	}
	if env.seen.snapshot().hit {
		t.Fatal("bridge token reached Gitea on an unsupported surface")
	}
}

// TestPackageRegistryCredentialFamilies exercises the credential shapes the
// package clients actually send: npm (Bearer), PyPI/Maven/Composer/Generic
// (Basic, token as password), Cargo (raw token, no scheme), and token-in-
// username Basic. Every family must exchange the bridge token for the hidden
// PAT as downstream Basic auth.
func TestPackageRegistryCredentialFamilies(t *testing.T) {
	pkgPrincipal := linkedPrincipal()
	pkgPrincipal.Scopes = []string{auth.ScopePackagesRead, auth.ScopePackagesWrite}

	cases := []struct {
		name   string
		method string
		path   string
		header string
	}{
		{"npm bearer download", http.MethodGet, "/api/packages/owner/npm/@scope%2Fpkg", "Bearer " + testBridgeToken},
		{"npm bearer publish", http.MethodPut, "/api/packages/owner/npm/@scope%2Fpkg", "Bearer " + testBridgeToken},
		{"pypi basic upload", http.MethodPost, "/api/packages/owner/pypi", basicHeader("npub1owner", testBridgeToken)},
		{"pypi basic download", http.MethodGet, "/api/packages/owner/pypi/simple/pkg/", basicHeader("npub1owner", testBridgeToken)},
		{"cargo raw token", http.MethodPut, "/api/packages/owner/cargo/api/v1/crates/new", testBridgeToken},
		{"generic basic upload", http.MethodPut, "/api/packages/owner/generic/pkg/1.0/file.bin", basicHeader("npub1owner", testBridgeToken)},
		{"maven token in username", http.MethodPut, "/api/packages/owner/maven/g/a/1.0/a-1.0.jar", basicHeader(testBridgeToken, "")},
		{"nuget delete", http.MethodDelete, "/api/packages/owner/nuget/pkg/1.0.0", basicHeader("npub1owner", testBridgeToken)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokens := &stubAuthenticator{
				enabled: true, principal: pkgPrincipal,
				patLogin: "npub1owner-login", patSecret: "hidden-pat",
			}
			env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader("artifact"))
			r.Header.Set("Authorization", tc.header)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			seen := env.seen.snapshot()
			if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
				t.Fatalf("downstream authorization = %q, want hidden PAT Basic", seen.authorization)
			}
			if strings.Contains(seen.authorization, testBridgeToken) {
				t.Fatal("bridge token leaked downstream")
			}
		})
	}
}

// TestNuGetAPIKeyHeaderCarriesBridgeToken covers the NuGet client shape:
// the credential arrives in X-NuGet-ApiKey, not Authorization. A bridge
// token there must be exchanged locally and the header must never reach
// Gitea; ambiguous dual credentials are rejected; an ordinary API key
// passes through untouched.
func TestNuGetAPIKeyHeaderCarriesBridgeToken(t *testing.T) {
	pkgPrincipal := linkedPrincipal()
	pkgPrincipal.Scopes = []string{auth.ScopePackagesRead, auth.ScopePackagesWrite}
	newEnv := func() *proxyEnv {
		return newProxyEnv(t, Config{FullProxy: true}, &stubAuthenticator{
			enabled: true, principal: pkgPrincipal,
			patLogin: "npub1owner-login", patSecret: "hidden-pat",
		}, stubInspector{})
	}

	t.Run("bridge token in api key header", func(t *testing.T) {
		env := newEnv()
		r := httptest.NewRequest(http.MethodPut, "/api/packages/owner/nuget", strings.NewReader("nupkg"))
		r.Header.Set("X-NuGet-ApiKey", testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		seen := env.seen.snapshot()
		if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
			t.Fatalf("downstream authorization = %q, want hidden PAT Basic", seen.authorization)
		}
		if seen.nugetAPIKey != "" {
			t.Fatalf("X-NuGet-ApiKey reached Gitea: %q", seen.nugetAPIKey)
		}
	})

	t.Run("malformed bridge api key fails locally", func(t *testing.T) {
		env := newEnv()
		r := httptest.NewRequest(http.MethodPut, "/api/packages/owner/nuget", strings.NewReader("x"))
		r.Header.Set("X-NuGet-ApiKey", auth.BridgeTokenPrefix+"tooshort")
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("malformed bridge api key was forwarded")
		}
	})

	t.Run("dual credentials are ambiguous", func(t *testing.T) {
		env := newEnv()
		r := httptest.NewRequest(http.MethodPut, "/api/packages/owner/nuget", strings.NewReader("x"))
		r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
		r.Header.Set("X-NuGet-ApiKey", testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for ambiguous dual credentials", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("ambiguous dual credentials were forwarded")
		}
	})

	t.Run("ordinary api key passes through", func(t *testing.T) {
		env := newEnv()
		r := httptest.NewRequest(http.MethodPut, "/api/packages/owner/nuget", strings.NewReader("x"))
		r.Header.Set("X-NuGet-ApiKey", "ordinary-gitea-pat")
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		if got := env.seen.snapshot().nugetAPIKey; got != "ordinary-gitea-pat" {
			t.Fatalf("ordinary api key altered: %q", got)
		}
	})
}

// TestDockerTokenExchangeTranslatesBridgeToken covers the docker login flow:
// Basic npub:bridge-token on the /v2 token endpoint is exchanged for the
// hidden PAT, gated by the docker-requested scope.
func TestDockerTokenExchangeTranslatesBridgeToken(t *testing.T) {
	pkgPrincipal := linkedPrincipal()
	pkgPrincipal.Scopes = []string{auth.ScopePackagesRead, auth.ScopePackagesWrite}
	tokens := &stubAuthenticator{
		enabled: true, principal: pkgPrincipal,
		patLogin: "npub1owner-login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	for _, target := range []string{
		"/v2/", // login probe
		"/v2/token?service=container_registry&scope=repository:owner/img:pull,push",
	} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", target, w.Code, w.Body.String())
		}
		if got := env.seen.snapshot().authorization; got != basicHeader("npub1owner-login", "hidden-pat") {
			t.Fatalf("%s downstream authorization = %q, want hidden PAT Basic", target, got)
		}
	}
}

// TestDockerTokenExchangeScopeEnforcement: push requires packages:write;
// unknown docker actions fail closed even with every scope.
func TestDockerTokenExchangeScopeEnforcement(t *testing.T) {
	readOnly := linkedPrincipal()
	readOnly.Scopes = []string{auth.ScopePackagesRead}
	tokens := &stubAuthenticator{
		enabled: true, principal: readOnly, patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/v2/token?scope=repository:o/img:pull,push", nil)
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("push exchange with read-only token = %d, want 403", w.Code)
	}

	full := linkedPrincipal()
	full.Scopes = []string{auth.ScopePackagesRead, auth.ScopePackagesWrite}
	tokens.principal = full
	r = httptest.NewRequest(http.MethodGet, "/v2/token?scope=repository:o/img:admin", nil)
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w = httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown docker action = %d, want 403 (fail closed)", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("denied docker exchange reached Gitea")
	}

	// A manifest named "token" is not the exchange endpoint: a bridge token
	// there hits the scopeless container surface and fails closed, never
	// trading a read-only token for the hidden PAT on a write endpoint.
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		r = httptest.NewRequest(method, "/v2/o/img/manifests/token", strings.NewReader("m"))
		r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
		w = httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s manifests/token = %d, want 403", method, w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("bridge token reached Gitea via manifests/token")
		}
	}
}

// TestRegistryJWTPassesThrough: after the exchange, docker presents Gitea's
// registry token as Bearer; it has no bridge prefix and must pass through.
func TestRegistryJWTPassesThrough(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true}, &stubAuthenticator{enabled: true}, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/v2/owner/img/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.registry.jwt")
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := env.seen.snapshot().authorization; got != "Bearer eyJhbGciOiJIUzI1NiJ9.registry.jwt" {
		t.Fatalf("registry JWT altered: %q", got)
	}
}

// TestBearerChallengeRealmRewrite: the docker token-endpoint discovery realm
// must point at the public origin, and only an exact backend-origin realm is
// rewritten.
func TestBearerChallengeRealmRewrite(t *testing.T) {
	seen := &observed{}
	var challenge string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.last = backendRequest{hit: true}
		seen.mu.Unlock()
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(backend.Close)

	p, err := New(Config{
		GiteaURL:  backend.URL,
		PublicURL: "https://git.example.com",
		FullProxy: true,
	}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Backend-origin realm is rewritten, other attributes preserved.
	challenge = `Bearer realm="` + backend.URL + `/v2/token",service="container_registry"`
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	want := `Bearer realm="https://git.example.com/v2/token",service="container_registry"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}

	// A foreign-origin realm must not be vouched for.
	challenge = `Bearer realm="https://evil.example/v2/token",service="x"`
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if got := w.Header().Get("WWW-Authenticate"); got != challenge {
		t.Fatalf("foreign realm altered: %q", got)
	}

	// A Basic challenge is left alone.
	challenge = `Basic realm="Gitea"`
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if got := w.Header().Get("WWW-Authenticate"); got != challenge {
		t.Fatalf("basic challenge altered: %q", got)
	}

	// Scheme and parameter names are case-insensitive per RFC 9110.
	challenge = `bearer REALM="` + backend.URL + `/v2/token",service="x"`
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	wantLower := `bearer REALM="https://git.example.com/v2/token",service="x"`
	if got := w.Header().Get("WWW-Authenticate"); got != wantLower {
		t.Fatalf("case-variant challenge = %q, want %q", got, wantLower)
	}
}

// TestPackageWriteRequiresWriteScope ensures a read-only package token cannot
// publish or delete.
func TestPackageWriteRequiresWriteScope(t *testing.T) {
	readOnly := linkedPrincipal()
	readOnly.Scopes = []string{auth.ScopePackagesRead}
	tokens := &stubAuthenticator{
		enabled: true, principal: readOnly, patLogin: "login", patSecret: "hidden-pat",
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/packages/owner/npm/pkg"},
		{http.MethodDelete, "/api/packages/owner/cargo/pkg/1.0.0"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403", tc.method, tc.path, w.Code)
		}
	}
	if env.seen.snapshot().hit {
		t.Fatal("package write forwarded without packages:write")
	}
}

// TestCredentialEndpointsRefuseBridgeAuthority: an api:write bridge token
// (or signature) must not reach endpoints that can mint durable credentials
// — a hidden PAT creating an ordinary Gitea PAT would escape bridge scope,
// expiry, and revocation entirely.
func TestCredentialEndpointsRefuseBridgeAuthority(t *testing.T) {
	full := linkedPrincipal()
	full.Scopes = []string{
		auth.ScopeGitRead, auth.ScopeGitWrite,
		auth.ScopePackagesRead, auth.ScopePackagesWrite,
		auth.ScopeAPIRead, auth.ScopeAPIWrite,
	}
	tokens := &stubAuthenticator{enabled: true, principal: full, patLogin: "login", patSecret: "hidden-pat"}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
	env.proxy.WithNostrVerifier(&stubNostrVerifier{principal: full})

	targets := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/users/npub1owner-login/tokens"},
		{http.MethodGet, "/api/v1/users/npub1owner-login/tokens"},
		{http.MethodPost, "/api/v1/user/keys"},
		{http.MethodPost, "/api/v1/repos/o/r/keys"},
		{http.MethodPost, "/api/v1/user/applications/oauth2"},
	}
	for _, tc := range targets {
		for _, cred := range []string{"Bearer " + testBridgeToken, "Nostr proof"} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			r.Header.Set("Authorization", cred)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with %q = %d, want 403", tc.method, tc.path, cred[:6], w.Code)
			}
		}
	}
	if env.seen.snapshot().hit {
		t.Fatal("credential-management endpoint reached Gitea with bridge authority")
	}

	// Ordinary Gitea credentials still pass through: the restriction gates
	// bridge-injected authority, not the user's own credentials.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/tokens", nil)
	r.Header.Set("Authorization", basicHeader("alice", "her-own-pat"))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !env.seen.snapshot().hit {
		t.Fatalf("ordinary credential on tokens endpoint = %d, want passthrough", w.Code)
	}
}

// stubNostrVerifier records what it was asked to verify.
type stubNostrVerifier struct {
	principal auth.TokenPrincipal
	err       error
	gotBody   []byte
	calls     int
}

func (s *stubNostrVerifier) VerifyProxyNIP98(_ context.Context, _ *http.Request, body []byte) (auth.TokenPrincipal, error) {
	s.calls++
	s.gotBody = append([]byte(nil), body...)
	if s.err != nil {
		return auth.TokenPrincipal{}, s.err
	}
	return s.principal, nil
}

func apiPrincipal() auth.TokenPrincipal {
	p := linkedPrincipal()
	p.Scopes = []string{auth.ScopeAPIRead, auth.ScopeAPIWrite}
	return p
}

func TestDirectNIP98OnAPIEndpoints(t *testing.T) {
	verifier := &stubNostrVerifier{principal: apiPrincipal()}
	tokens := &stubAuthenticator{enabled: true, patLogin: "login", patSecret: "hidden-pat"}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
	env.proxy.WithNostrVerifier(verifier)

	// GET with no body.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
	r.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString([]byte(`{}`)))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", w.Code, w.Body.String())
	}
	seen := env.seen.snapshot()
	if seen.authorization != basicHeader("login", "hidden-pat") {
		t.Fatalf("downstream authorization = %q, want hidden PAT", seen.authorization)
	}

	// POST with a bounded body: the verifier sees the exact bytes and the
	// backend receives them intact.
	body := `{"title":"hi"}`
	r = httptest.NewRequest(http.MethodPost, "/api/v1/repos/o/r/issues", strings.NewReader(body))
	r.Header.Set("Authorization", "Nostr proof")
	w = httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST status = %d: %s", w.Code, w.Body.String())
	}
	if string(verifier.gotBody) != body {
		t.Fatalf("verifier saw body %q, want %q", verifier.gotBody, body)
	}
	if got := env.seen.snapshot().body; got != body {
		t.Fatalf("backend saw body %q, want %q", got, body)
	}
}

func TestDirectNIP98RejectsUnverifiableShapes(t *testing.T) {
	verifier := &stubNostrVerifier{principal: apiPrincipal()}
	tokens := &stubAuthenticator{enabled: true, patLogin: "login", patSecret: "hidden-pat"}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
	env.proxy.WithNostrVerifier(verifier)

	send := func(mutate func(r *http.Request)) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/repos/o/r/issues", strings.NewReader("{}"))
		r.Header.Set("Authorization", "Nostr proof")
		mutate(r)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		return w.Code
	}

	if code := send(func(r *http.Request) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = -1 }); code != http.StatusUnauthorized {
		t.Errorf("chunked = %d, want 401", code)
	}
	if code := send(func(r *http.Request) { r.Header.Set("Expect", "100-continue") }); code != http.StatusUnauthorized {
		t.Errorf("100-continue = %d, want 401", code)
	}
	if code := send(func(r *http.Request) { r.ContentLength = -1 }); code != http.StatusUnauthorized {
		t.Errorf("unknown length = %d, want 401", code)
	}
	if code := send(func(r *http.Request) { r.ContentLength = maxNIP98ProxyBody + 1 }); code != http.StatusUnauthorized {
		t.Errorf("oversized = %d, want 401", code)
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier consulted %d times for unverifiable shapes", verifier.calls)
	}
	if env.seen.snapshot().hit {
		t.Fatal("unverifiable NIP-98 request reached Gitea")
	}
}

func TestDirectNIP98FailuresAndBoundaries(t *testing.T) {
	tokens := &stubAuthenticator{enabled: true, patLogin: "login", patSecret: "hidden-pat"}

	t.Run("invalid proof", func(t *testing.T) {
		env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
		env.proxy.WithNostrVerifier(&stubNostrVerifier{err: auth.ErrTokenUnauthorized})
		r := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
		r.Header.Set("Authorization", "Nostr bad")
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "Nostr" {
			t.Fatalf("challenge = %q, want Nostr", got)
		}
		if env.seen.snapshot().hit {
			t.Fatal("invalid proof forwarded")
		}
	})

	t.Run("admin endpoints refuse signatures", func(t *testing.T) {
		env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
		env.proxy.WithNostrVerifier(&stubNostrVerifier{principal: apiPrincipal()})
		r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
		r.Header.Set("Authorization", "Nostr proof")
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("admin = %d, want 403", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("admin request with signature reached Gitea")
		}
	})

	t.Run("no verifier configured", func(t *testing.T) {
		env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})
		r := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
		r.Header.Set("Authorization", "Nostr proof")
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("Nostr proof forwarded without a verifier")
		}
	})

	t.Run("mapped surface refuses signatures", func(t *testing.T) {
		env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{id: 7})
		env.proxy.WithNostrVerifier(&stubNostrVerifier{principal: apiPrincipal()})
		r := httptest.NewRequest(http.MethodGet, "/npub1x/repo.git/info/refs?service=git-upload-pack", nil)
		r.Header.Set("Authorization", "Nostr proof")
		w := httptest.NewRecorder()
		env.proxy.ServeMappedGit(w, r, mapped(7), "info/refs")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("mapped = %d, want 401", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("Nostr proof on mapped surface reached Gitea")
		}
	})
}

// TestBridgeCredentialsNeverReachGitea enumerates the credential shapes that
// claim the bridge prefix. Every one must be resolved locally: forwarding any
// of them would leak a bridge token to Gitea and could serve the request with
// unintended authority.
func TestBridgeCredentialsNeverReachGitea(t *testing.T) {
	cases := []struct {
		name   string
		apply  func(*http.Request)
		status int
	}{
		{"basic password malformed", func(r *http.Request) {
			r.Header.Set("Authorization", basicHeader("u", auth.BridgeTokenPrefix+"short"))
		}, http.StatusUnauthorized},
		{"basic username carries token", func(r *http.Request) {
			r.Header.Set("Authorization", basicHeader(auth.BridgeTokenPrefix+"short", ""))
		}, http.StatusUnauthorized},
		{"raw value without scheme", func(r *http.Request) {
			r.Header.Set("Authorization", auth.BridgeTokenPrefix+"short")
		}, http.StatusUnauthorized},
		{"unknown scheme carries token", func(r *http.Request) {
			r.Header.Set("Authorization", "Weird "+auth.BridgeTokenPrefix+"short")
		}, http.StatusUnauthorized},
		{"nostr scheme is not supported yet", func(r *http.Request) {
			r.Header.Set("Authorization", "Nostr eyJraW5kIjoyNzIzNX0=")
		}, http.StatusUnauthorized},
		{"multiple authorization headers", func(r *http.Request) {
			r.Header.Add("Authorization", basicHeader("alice", "gitea-pat"))
			r.Header.Add("Authorization", "Bearer "+testBridgeToken)
		}, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newProxyEnv(t, Config{FullProxy: true}, &stubAuthenticator{enabled: true}, stubInspector{})
			r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
			tc.apply(r)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if seen := env.seen.snapshot(); seen.hit {
				t.Fatalf("request reached Gitea carrying %q", seen.authorization)
			}
		})
	}
}

func TestServeHTTPDownstreamCredentialFailure(t *testing.T) {
	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(), patErr: auth.ErrPATProvisioning,
	}
	env := newProxyEnv(t, Config{FullProxy: true}, tokens, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", "Bearer "+testBridgeToken)
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("request forwarded without a downstream credential")
	}
}

func TestInjectedCredentialRejectionBecomes502(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Gitea"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer backend.Close()

	tokens := &stubAuthenticator{
		enabled: true, principal: linkedPrincipal(),
		patLogin: "login", patSecret: "stale-pat",
	}
	p, err := New(Config{GiteaURL: backend.URL, FullProxy: true}, tokens, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", "Bearer "+testBridgeToken)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: a rejected bridge credential is a bridge fault", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("relayed a challenge the caller cannot satisfy")
	}
}

// --- Header hygiene and session handoff -------------------------------------

func TestInternalHeadersAreStrippedFromClientRequests(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true}, nil, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/explore/repos", nil)
	for _, header := range InternalHeaders {
		r.Header.Set(header, "forged")
	}
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	seen := env.seen.snapshot()
	if seen.authUser != "" || seen.sessionProxy != "" || seen.edgeSecret != "" || seen.proxyAuth != "" {
		t.Fatalf("forged internal headers reached Gitea: %+v", seen)
	}
}

func TestSessionProxyRequiresEdgeSecret(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true, EdgeSharedSecret: "edge-secret"}, nil, stubInspector{})

	// Correct secret: the trusted login is forwarded.
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("X-Grasp-Session-Proxy", "1")
	r.Header.Set("X-Grasp-Edge-Secret", "edge-secret")
	r.Header.Set("X-Grasp-Auth-User", "alice")
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if got := env.seen.snapshot().authUser; got != "alice" {
		t.Fatalf("X-Grasp-Auth-User = %q, want alice", got)
	}

	// Wrong secret: the marker is ignored and no identity is forwarded.
	r = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("X-Grasp-Session-Proxy", "1")
	r.Header.Set("X-Grasp-Edge-Secret", "wrong")
	r.Header.Set("X-Grasp-Auth-User", "attacker")
	w = httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if got := env.seen.snapshot().authUser; got != "" {
		t.Fatalf("forged session identity accepted: %q", got)
	}
}

func TestSessionProxyIgnoredWithoutConfiguredSecret(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true}, nil, stubInspector{})

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("X-Grasp-Session-Proxy", "1")
	r.Header.Set("X-Grasp-Auth-User", "attacker")
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)

	if got := env.seen.snapshot().authUser; got != "" {
		t.Fatalf("session identity honored without a configured edge secret: %q", got)
	}
}

func TestSessionProxyPersistsInSignedBrowserCookie(t *testing.T) {
	env := newProxyEnv(t, Config{FullProxy: true, EdgeSharedSecret: "edge-secret"}, nil, stubInspector{})

	handoff := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	handoff.Header.Set("X-Grasp-Session-Proxy", "1")
	handoff.Header.Set("X-Grasp-Edge-Secret", "edge-secret")
	handoff.Header.Set("X-Grasp-Auth-User", "alice")
	handoffResponse := httptest.NewRecorder()
	env.proxy.ServeHTTP(handoffResponse, handoff)

	var session *http.Cookie
	for _, cookie := range handoffResponse.Result().Cookies() {
		if cookie.Name == browserSessionCookie {
			session = cookie
			break
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("session handoff did not mint a browser session cookie")
	}

	next := httptest.NewRequest(http.MethodGet, "/cascadia", nil)
	next.AddCookie(session)
	nextResponse := httptest.NewRecorder()
	env.proxy.ServeHTTP(nextResponse, next)
	if got := env.seen.snapshot().authUser; got != "alice" {
		t.Fatalf("browser session identity = %q, want alice", got)
	}

	session.Value += "tampered"
	tampered := httptest.NewRequest(http.MethodGet, "/cascadia", nil)
	tampered.AddCookie(session)
	env.proxy.ServeHTTP(httptest.NewRecorder(), tampered)
	if got := env.seen.snapshot().authUser; got != "" {
		t.Fatalf("tampered browser session accepted as %q", got)
	}
}

func TestBackendOriginRewriteRequiresExactHostMatch(t *testing.T) {
	lookalike := "http://gitea-lookalike.evil.example/owner/repo"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", lookalike)
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()

	p, err := New(Config{
		GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
	}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if got := w.Header().Get("Location"); got != lookalike {
		t.Fatalf("Location = %q, want it left alone (only the exact backend origin is rewritten)", got)
	}
}

// TestForwardedForPreservesClientChain pins behaviour the cutover depends on:
// nginx sets X-Forwarded-For to the real client, and the proxy must append
// itself rather than replace it, or Gitea's audit log and any IP-based
// controls would only ever see the bridge.
func TestForwardedForPreservesClientChain(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p, err := New(Config{
		GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
	}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	req, err := http.NewRequest(http.MethodGet, front.URL+"/explore", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// As nginx would set it for a real client.
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if !strings.HasPrefix(gotXFF, "203.0.113.7") {
		t.Fatalf("X-Forwarded-For = %q, want the client chain preserved with the bridge appended", gotXFF)
	}
	if gotXFF == "203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q, want the bridge hop appended too", gotXFF)
	}
}

func TestForwardedHeadersUseCanonicalOrigin(t *testing.T) {
	var gotHost, gotFwdHost, gotFwdProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotFwdHost = r.Header.Get("X-Forwarded-Host")
		gotFwdProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p, err := New(Config{
		GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
	}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/explore", nil)
	r.Host = "attacker.example.org"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if gotHost != "git.example.com" {
		t.Fatalf("Host = %q, want the canonical public host (not the client's)", gotHost)
	}
	if gotFwdHost != "git.example.com" || gotFwdProto != "https" {
		t.Fatalf("forwarded host/proto = %q/%q", gotFwdHost, gotFwdProto)
	}
}

func TestBackendOriginRewrittenInRedirects(t *testing.T) {
	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", backendURL+"/owner/repo")
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()
	backendURL = backend.URL

	p, err := New(Config{
		GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
	}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if got := w.Header().Get("Location"); got != "https://git.example.com/owner/repo" {
		t.Fatalf("Location = %q, want the public origin", got)
	}
}

func TestNewRejectsInvalidUpstream(t *testing.T) {
	for _, raw := range []string{"", "://nope", "ftp://gitea:3000", "http://"} {
		if _, err := New(Config{GiteaURL: raw}, nil, nil, nil, discardLogger()); err == nil {
			t.Errorf("New(%q) accepted an invalid upstream", raw)
		}
	}
}

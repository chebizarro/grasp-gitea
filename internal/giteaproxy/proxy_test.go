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

func (s *stubAuthenticator) DownstreamPAT(_ context.Context, _ int64) (string, string, error) {
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

	// Package/API/container/LFS adapters land in later phases; a bridge token
	// must not be silently exchanged for the hidden PAT's full authority.
	for _, path := range []string{
		"/api/packages/owner/npm/pkg",
		"/api/v1/user",
		"/v2/owner/image/blobs/uploads/",
		"/owner/repo.git/info/lfs/objects/batch",
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
	for _, header := range internalHeaders {
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

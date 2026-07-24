package api

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type observedGitBackendRequest struct {
	method   string
	path     string
	rawQuery string
}

func TestGitHTTPNpubProxyRewritesToMappedGiteaRepo(t *testing.T) {
	ctx := context.Background()
	backendRequests := make(chan observedGitBackendRequest, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests <- observedGitBackendRequest{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery}
		_, _ = w.Write([]byte("backend git response"))
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub:        "npub1owner",
		RepoID:      "repo one",
		Pubkey:      "pubkey",
		Owner:       "nip05-org",
		RepoName:    "gitea-repo",
		GiteaRepoID: 101,
		CloneURL:    backend.URL + "/nip05-org/gitea-repo.git",
		SourceEvent: "event1",
	})

	srv := New(config.Config{GiteaURL: backend.URL}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/npub1owner/repo%20one.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "backend git response" {
		t.Fatalf("expected backend body, got %q", got)
	}
	assertGitHTTPCORS(t, w.Result().Header)

	seen := <-backendRequests
	if seen.method != http.MethodGet {
		t.Fatalf("expected backend GET, got %s", seen.method)
	}
	if seen.path != "/nip05-org/gitea-repo.git/info/refs" {
		t.Fatalf("expected rewritten backend path, got %q", seen.path)
	}
	if seen.rawQuery != "service=git-upload-pack" {
		t.Fatalf("expected query to be preserved, got %q", seen.rawQuery)
	}
}

func TestGitHTTPNpubProxyUnknownMappingReturns404(t *testing.T) {
	backendHit := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit <- struct{}{}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	srv := New(config.Config{GiteaURL: backend.URL}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/npub1missing/unknown.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	assertGitHTTPCORS(t, w.Result().Header)

	select {
	case <-backendHit:
		t.Fatal("backend should not be called for unknown mapping")
	default:
	}
}

func TestGitHTTPNpubProxyOptionsReturns204WithCORS(t *testing.T) {
	st := openGitHTTPProxyTestStore(t)
	srv := New(config.Config{GiteaURL: "http://gitea.invalid"}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodOptions, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 204, got %d: %s", w.Code, string(body))
	}
	assertGitHTTPCORS(t, w.Result().Header)
}

func TestGitHTTPNpubProxyDecodesPercentEncodedIdentifier(t *testing.T) {
	ctx := context.Background()
	backendRequests := make(chan observedGitBackendRequest, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests <- observedGitBackendRequest{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery}
		_, _ = w.Write([]byte("decoded"))
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub:        "npub1owner",
		RepoID:      "repo/with space",
		Pubkey:      "pubkey",
		Owner:       "resolved-org",
		RepoName:    "decoded-repo",
		GiteaRepoID: 102,
		CloneURL:    backend.URL + "/resolved-org/decoded-repo.git",
		SourceEvent: "event2",
	})

	srv := New(config.Config{GiteaURL: backend.URL}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/npub1owner/repo%2Fwith%20space.git/git-upload-pack", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "decoded" {
		t.Fatalf("expected backend body, got %q", got)
	}
	assertGitHTTPCORS(t, w.Result().Header)

	seen := <-backendRequests
	if seen.path != "/resolved-org/decoded-repo.git/git-upload-pack" {
		t.Fatalf("expected decoded mapping to rewrite backend path, got %q", seen.path)
	}
}

func openGitHTTPProxyTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mappings.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedGitHTTPProxyMapping(t *testing.T, ctx context.Context, st *store.SQLiteStore, mapping store.Mapping) {
	t.Helper()
	mapping.HookInstalled = true
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
}

func assertGitHTTPCORS(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin *, got %q", got)
	}
	if got := h.Get("Access-Control-Allow-Methods"); got != "GET, POST" {
		t.Fatalf("expected Access-Control-Allow-Methods GET, POST, got %q", got)
	}
	if got := h.Get("Access-Control-Allow-Headers"); got != "Content-Type" {
		t.Fatalf("expected Access-Control-Allow-Headers Content-Type, got %q", got)
	}
}

func TestGitHTTPNpubProxyStripsCallerCredentialsAndInjectsServiceIdentity(t *testing.T) {
	ctx := context.Background()
	type observedAuth struct {
		authorization string
		cookie        string
		proxyAuth     string
	}
	backendAuth := make(chan observedAuth, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendAuth <- observedAuth{
			authorization: r.Header.Get("Authorization"),
			cookie:        r.Header.Get("Cookie"),
			proxyAuth:     r.Header.Get("Proxy-Authorization"),
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub: "npub1owner", RepoID: "repo", Pubkey: "pubkey",
		Owner: "org", RepoName: "repo", GiteaRepoID: 1,
		CloneURL: backend.URL + "/org/repo.git", SourceEvent: "event1",
	})

	srv := New(config.Config{
		GiteaURL:           backend.URL,
		GitBackendUser:     "grasp-bridge",
		GitBackendPassword: "service-secret",
	}, nil, nil, st, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Basic Y2FsbGVyOnNlY3JldA==")
	req.Header.Set("Proxy-Authorization", "Basic cHJveHk6c2VjcmV0")
	req.Header.Set("Cookie", "i_like_gitea=session-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	seen := <-backendAuth
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("grasp-bridge:service-secret"))
	if seen.authorization != wantAuth {
		t.Fatalf("expected service identity auth %q, got %q", wantAuth, seen.authorization)
	}
	if seen.cookie != "" {
		t.Fatalf("expected caller cookie to be stripped, got %q", seen.cookie)
	}
	if seen.proxyAuth != "" {
		t.Fatalf("expected caller proxy auth to be stripped, got %q", seen.proxyAuth)
	}
}

func TestGitHTTPNpubProxyForwardsNoCredentialsWhenUnconfigured(t *testing.T) {
	ctx := context.Background()
	backendAuth := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendAuth <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub: "npub1owner", RepoID: "repo", Pubkey: "pubkey",
		Owner: "org", RepoName: "repo", GiteaRepoID: 1,
		CloneURL: backend.URL + "/org/repo.git", SourceEvent: "event1",
	})

	srv := New(config.Config{GiteaURL: backend.URL}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Basic Y2FsbGVyOnNlY3JldA==")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if got := <-backendAuth; got != "" {
		t.Fatalf("expected no credentials forwarded to backend, got %q", got)
	}
}

func TestGitHTTPNpubProxyNeverSurfacesGiteaBasicChallenge(t *testing.T) {
	ctx := context.Background()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Gitea"`)
		w.Header().Set("Set-Cookie", "i_like_gitea=abc; Path=/")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer backend.Close()

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub: "npub1owner", RepoID: "repo", Pubkey: "pubkey",
		Owner: "org", RepoName: "repo", GiteaRepoID: 1,
		CloneURL: backend.URL + "/org/repo.git", SourceEvent: "event1",
	})

	srv := New(config.Config{GiteaURL: backend.URL}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/npub1owner/repo.git/info/refs?service=git-receive-pack", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected backend 401 to surface as 502, got %d", w.Code)
	}
	if got := w.Result().Header.Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no WWW-Authenticate on public response, got %q", got)
	}
	if got := w.Result().Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("expected no Set-Cookie on public response, got %q", got)
	}
	assertGitHTTPCORS(t, w.Result().Header)
}

func TestGitHTTPNpubLandingPageForKnownAndUnknownRepos(t *testing.T) {
	ctx := context.Background()
	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, ctx, st, store.Mapping{
		Npub: "npub1owner", RepoID: "repo one", Pubkey: "pubkey",
		Owner: "org", RepoName: "repo", GiteaRepoID: 1,
		CloneURL: "http://gitea/org/repo.git", SourceEvent: "event1",
	})
	srv := New(config.Config{GiteaURL: "http://gitea:3000"}, nil, nil, st, testLogger())

	// Known repository: human-facing landing page at the bare .git path.
	req := httptest.NewRequest(http.MethodGet, "/npub1owner/repo%20one.git", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 landing page, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "git clone") || !strings.Contains(body, "/npub1owner/repo%20one.git") {
		t.Fatalf("expected clone instructions in landing page, got %q", body)
	}

	// Unknown repository: useful 404.
	req = httptest.NewRequest(http.MethodGet, "/npub1owner/unknown.git", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown repo, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "kind 30617") {
		t.Fatalf("expected explanatory 404 body, got %q", w.Body.String())
	}
}

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

func lfsPrincipal(scopes ...string) auth.TokenPrincipal {
	p := linkedPrincipal()
	p.Scopes = scopes
	return p
}

func lfsEnv(t *testing.T, principal auth.TokenPrincipal) *proxyEnv {
	t.Helper()
	tokens := &stubAuthenticator{
		enabled: true, principal: principal,
		patLogin: "npub1owner-login", patSecret: "hidden-pat",
	}
	return newProxyEnv(t, Config{FullProxy: true, PublicURL: "https://git.example.com"}, tokens, stubInspector{})
}

func TestLFSScopeClassification(t *testing.T) {
	cases := []struct {
		method    string
		target    string
		wantScope string
	}{
		{http.MethodGet, "/o/r.git/info/lfs/objects/abc123", auth.ScopeLFSRead},
		{http.MethodPut, "/o/r.git/info/lfs/objects/abc123", auth.ScopeLFSWrite},
		{http.MethodPost, "/o/r.git/info/lfs/objects/abc123/verify", auth.ScopeLFSWrite},
		{http.MethodGet, "/o/r.git/info/lfs/locks", auth.ScopeLFSRead},
		{http.MethodPost, "/o/r.git/info/lfs/locks", auth.ScopeLFSWrite},
		{http.MethodPost, "/o/r.git/info/lfs/locks/1/unlock", auth.ScopeLFSWrite},
		// The batch endpoint carries no static scope: it is resolved from
		// the request body when a bridge credential is present.
		{http.MethodPost, "/o/r.git/info/lfs/objects/batch", ""},
	}
	for _, tc := range cases {
		class := Classify(httptest.NewRequest(tc.method, tc.target, nil))
		if class.Surface != SurfaceLFS {
			t.Errorf("%s %s surface = %s, want lfs", tc.method, tc.target, class.Surface)
		}
		if class.Scope != tc.wantScope {
			t.Errorf("%s %s scope = %q, want %q", tc.method, tc.target, class.Scope, tc.wantScope)
		}
	}
}

func TestLFSBatchScopeFromOperation(t *testing.T) {
	t.Run("download with lfs:read succeeds", func(t *testing.T) {
		env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead))
		body := `{"operation":"download","objects":[{"oid":"abc","size":1}]}`
		r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		seen := env.seen.snapshot()
		if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
			t.Fatalf("downstream authorization = %q", seen.authorization)
		}
		if seen.body != body {
			t.Fatalf("sniffed body not forwarded intact: %q", seen.body)
		}
	})

	t.Run("upload with lfs:read only is denied", func(t *testing.T) {
		env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead))
		r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch",
			strings.NewReader(`{"operation":"upload","objects":[]}`))
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if env.seen.snapshot().hit {
			t.Fatal("denied upload batch reached Gitea")
		}
	})

	t.Run("unknown operation fails closed", func(t *testing.T) {
		env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead, auth.ScopeLFSWrite))
		for _, body := range []string{
			`{"operation":"admin"}`,
			`{}`,
			`not json`,
		} {
			r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+testBridgeToken)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("body %q status = %d, want 401", body, w.Code)
			}
		}
		if env.seen.snapshot().hit {
			t.Fatal("unresolvable batch reached Gitea")
		}
	})

	t.Run("chunked and oversized batches fail closed", func(t *testing.T) {
		env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead, auth.ScopeLFSWrite))
		r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader(`{"operation":"download"}`))
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		r.TransferEncoding = []string{"chunked"}
		r.ContentLength = -1
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("chunked = %d, want 401", w.Code)
		}

		r = httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer "+testBridgeToken)
		r.ContentLength = maxLFSBatchBody + 1
		w = httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("oversized = %d, want 401", w.Code)
		}
	})

	t.Run("anonymous batch passes through unsniffed", func(t *testing.T) {
		env := lfsEnv(t, lfsPrincipal())
		body := `{"operation":"download"}`
		r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch", strings.NewReader(body))
		w := httptest.NewRecorder()
		env.proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		if got := env.seen.snapshot().body; got != body {
			t.Fatalf("anonymous batch body = %q", got)
		}
	})
}

func TestLFSObjectTransferStreamsWithBridgeToken(t *testing.T) {
	env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead, auth.ScopeLFSWrite))

	// Upload: PUT object content with the bridge token as Basic password.
	content := strings.Repeat("blob", 1024)
	r := httptest.NewRequest(http.MethodPut, "/o/r.git/info/lfs/objects/abc123", strings.NewReader(content))
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("upload status = %d", w.Code)
	}
	seen := env.seen.snapshot()
	if seen.authorization != basicHeader("npub1owner-login", "hidden-pat") {
		t.Fatalf("downstream authorization = %q", seen.authorization)
	}
	if seen.body != content {
		t.Fatal("object content not forwarded intact")
	}

	// Read-only token cannot upload.
	readOnly := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead))
	r = httptest.NewRequest(http.MethodPut, "/o/r.git/info/lfs/objects/abc123", strings.NewReader("x"))
	r.Header.Set("Authorization", basicHeader("npub1owner", testBridgeToken))
	w = httptest.NewRecorder()
	readOnly.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only upload = %d, want 403", w.Code)
	}
}

// TestMappedLFSAnonymousWritesDenied: on the canonical npub surface, LFS
// mutations (upload batch, object PUT, lock POST/DELETE) must never reach
// Gitea via the write-capable service identity — unlike git push, they are
// not guarded by the pre-receive hook. Reads on a public repo still work.
func TestMappedLFSAnonymousWritesDenied(t *testing.T) {
	newEnv := func() *proxyEnv {
		tokens := &stubAuthenticator{enabled: true}
		return newProxyEnv(t, Config{
			FullProxy: true, PublicURL: "https://git.example.com",
			GitBackendUser: "svc", GitBackendPassword: "svc-pw",
		}, tokens, stubInspector{id: 7})
	}

	writes := []struct {
		name, method, subpath, body string
	}{
		{"upload batch", http.MethodPost, "info/lfs/objects/batch", `{"operation":"upload"}`},
		{"object put", http.MethodPut, "info/lfs/objects/abc123", "blob"},
		{"lock create", http.MethodPost, "info/lfs/locks", `{"path":"x"}`},
		{"lock unlock", http.MethodPost, "info/lfs/locks/1/unlock", `{}`},
	}
	for _, tc := range writes {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv()
			r := httptest.NewRequest(tc.method, "/npub1x/repo.git/"+tc.subpath, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			env.proxy.ServeMappedGit(w, r, mapped(7), tc.subpath)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s status = %d, want 401", tc.name, w.Code)
			}
			if env.seen.snapshot().hit {
				t.Fatalf("anonymous LFS %s reached Gitea", tc.name)
			}
		})
	}

	// A download batch (read) on a public repo is served via the service id.
	env := newEnv()
	r := httptest.NewRequest(http.MethodPost, "/npub1x/repo.git/info/lfs/objects/batch",
		strings.NewReader(`{"operation":"download"}`))
	w := httptest.NewRecorder()
	env.proxy.ServeMappedGit(w, r, mapped(7), "info/lfs/objects/batch")
	if w.Code != http.StatusOK {
		t.Fatalf("anonymous download batch status = %d, want 200", w.Code)
	}
	if !env.seen.snapshot().hit {
		t.Fatal("anonymous download batch did not reach Gitea")
	}
}

func TestLFSRejectsDirectNIP98(t *testing.T) {
	env := lfsEnv(t, lfsPrincipal(auth.ScopeLFSRead, auth.ScopeLFSWrite))
	env.proxy.WithNostrVerifier(&stubNostrVerifier{principal: lfsPrincipal(auth.ScopeLFSRead, auth.ScopeLFSWrite)})

	r := httptest.NewRequest(http.MethodGet, "/o/r.git/info/lfs/objects/abc123", nil)
	r.Header.Set("Authorization", "Nostr proof")
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("NIP-98 on LFS = %d, want 403", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("NIP-98 LFS request reached Gitea")
	}
}

func TestLFSBatchUnsafeResponsesFailClosed(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
		body            string
	}{
		{
			name:            "compressed body",
			contentEncoding: "gzip",
			body:            `{"objects":[{"actions":{"download":{"href":"https://git.example.com/o/r.git/info/lfs/objects/abc","header":{"Authorization":"Basic hidden-pat"}}}}]}`,
		},
		{
			name: "oversized body",
			body: strings.Repeat("x", maxLFSBatchResponseBody+1),
		},
		{
			name: "invalid JSON",
			body: `{"objects":[{"header":{"Authorization":"Basic hidden-pat"}}]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Accept-Encoding"); got != "identity" {
					t.Errorf("upstream Accept-Encoding = %q, want identity", got)
				}
				w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
				if tc.contentEncoding != "" {
					w.Header().Set("Content-Encoding", tc.contentEncoding)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(backend.Close)

			p, err := New(Config{
				GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
			}, &stubAuthenticator{
				enabled: true, principal: lfsPrincipal(auth.ScopeLFSRead),
				patLogin: "l", patSecret: "hidden-pat",
			}, stubInspector{}, nil, discardLogger())
			if err != nil {
				t.Fatal(err)
			}

			r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch",
				strings.NewReader(`{"operation":"download"}`))
			r.Header.Set("Authorization", "Bearer "+testBridgeToken)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "hidden-pat") {
				t.Fatalf("raw unsafe response forwarded: %s", w.Body.String())
			}
			if got := w.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("502 retained Content-Encoding %q", got)
			}
		})
	}
}

func TestMappedLFSAnonymousBatchStripsAuthorization(t *testing.T) {
	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		fmt.Fprintf(w, `{"objects":[{"oid":"abc","actions":{"download":{"href":"%s/org/repo.git/info/lfs/objects/abc","header":{"Authorization":"Basic hidden-service-credential","X-Keep":"yes"}}}}]}`, backendURL)
	}))
	t.Cleanup(backend.Close)
	backendURL = backend.URL

	p, err := New(Config{
		GiteaURL: backend.URL, PublicURL: "https://git.example.com", FullProxy: true,
		GitBackendUser: "svc", GitBackendPassword: "svc-pw",
	}, &stubAuthenticator{enabled: true}, stubInspector{id: 7}, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/npub1x/repo.git/info/lfs/objects/batch",
		strings.NewReader(`{"operation":"download"}`))
	w := httptest.NewRecorder()
	p.ServeMappedGit(w, r, mapped(7), "info/lfs/objects/batch")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "authorization") {
		t.Fatalf("anonymous action retained authorization: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"X-Keep":"yes"`) {
		t.Fatalf("unrelated action header was removed: %s", w.Body.String())
	}
}

func TestLFSBatchResponseOriginRewrite(t *testing.T) {
	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		fmt.Fprintf(w, `{"objects":[{"oid":"abc","actions":{"download":{"href":"%s/o/r.git/info/lfs/objects/abc","header":{"Authorization":"Basic hidden-pat","X-Keep":"yes"}},"upload":{"href":"https://objects.example.com/presigned","header":{"Authorization":"AWS4-HMAC-SHA256 external-signature"}},"verify":{"href":"https://objects.example.com/verify","header":{"Authorization":%q}}}}],"other":"https://elsewhere.example/x"}`, backendURL, basicHeader("l", "p"))
	}))
	t.Cleanup(backend.Close)
	backendURL = backend.URL

	p, err := New(Config{
		GiteaURL:  backend.URL,
		PublicURL: "https://git.example.com",
		FullProxy: true,
	}, &stubAuthenticator{enabled: true, principal: lfsPrincipal(auth.ScopeLFSRead), patLogin: "l", patSecret: "p"}, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/o/r.git/info/lfs/objects/batch",
		strings.NewReader(`{"operation":"download"}`))
	r.Header.Set("Authorization", "Bearer "+testBridgeToken)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if strings.Contains(string(body), backend.URL) {
		t.Fatalf("backend origin leaked in batch response: %s", body)
	}
	if !strings.Contains(string(body), "https://git.example.com/o/r.git/info/lfs/objects/abc") {
		t.Fatalf("transfer href not rewritten to public origin: %s", body)
	}
	if !strings.Contains(string(body), "https://elsewhere.example/x") {
		t.Fatalf("foreign origin altered: %s", body)
	}
	if strings.Contains(string(body), "hidden-pat") {
		t.Fatalf("hidden PAT leaked in batch action: %s", body)
	}
	var envelope struct {
		Objects []struct {
			Actions map[string]struct {
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	actions := envelope.Objects[0].Actions
	if got := actions["download"].Header["Authorization"]; got != "Bearer "+testBridgeToken {
		t.Fatalf("internal action authorization = %q", got)
	}
	if got := actions["download"].Header["X-Keep"]; got != "yes" {
		t.Fatalf("internal action X-Keep = %q", got)
	}
	if got := actions["upload"].Header["Authorization"]; got != "AWS4-HMAC-SHA256 external-signature" {
		t.Fatalf("external action authorization = %q", got)
	}
	if got := actions["verify"].Header["Authorization"]; got != "" {
		t.Fatalf("bridge-injected credential retained on external action: %q", got)
	}
	if got := w.Header().Get("Content-Length"); got != fmt.Sprint(len(body)) {
		t.Fatalf("Content-Length %s != body %d", got, len(body))
	}
}

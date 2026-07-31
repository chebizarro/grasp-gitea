// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"

	"github.com/sharegap/grasp-gitea/internal/store"
)

const tokenTestPublicURL = "https://bridge.example.com"

type tokenHandlerEnv struct {
	server *httptest.Server
	svc    *TokenService
}

func newTokenHandlerEnv(t *testing.T) *tokenHandlerEnv {
	t.Helper()
	env := newTokenTestEnv(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	authSvc := &Service{
		store:     env.store,
		publicURL: tokenTestPublicURL,
		logger:    logger,
		nip98:     sharednip98.NewVerifier(time.Minute),
	}
	handler := NewTokenHandler(authSvc, env.svc, logger)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &tokenHandlerEnv{server: server, svc: env.svc}
}

// doNIP98 sends a request whose NIP-98 proof is signed over the canonical
// public URL (not the httptest origin), mirroring the nginx-fronted topology.
func (e *tokenHandlerEnv) doNIP98(t *testing.T, method, path string, body []byte) *http.Response {
	t.Helper()
	header := makeNIP98AuthHeader(t, tokenTestPublicURL+path, method, body)
	return e.doWithHeader(t, method, path, body, header)
}

func (e *tokenHandlerEnv) doWithHeader(t *testing.T, method, path string, body []byte, header string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", header)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func TestTokenHandlerMintListRevokeFlow(t *testing.T) {
	env := newTokenHandlerEnv(t)

	body := []byte(`{"name":"laptop","scopes":["git:read","git:write"]}`)
	resp := env.doNIP98(t, http.MethodPost, "/auth/token", body)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("mint status = %d body=%s", resp.StatusCode, raw)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	minted := decodeJSON[MintResult](t, resp)
	if !ValidBridgeTokenFormat(minted.Token) || minted.ID == "" {
		t.Fatalf("minted = %+v", minted)
	}

	// List with a fresh proof: metadata only, no plaintext anywhere.
	resp = env.doNIP98(t, http.MethodGet, "/auth/tokens", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), minted.Token) {
		t.Fatal("token plaintext leaked in listing")
	}
	var listing struct {
		Tokens []TokenMetadata `json:"tokens"`
		Limit  int             `json:"limit"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	if len(listing.Tokens) != 1 || listing.Tokens[0].ID != minted.ID || listing.Tokens[0].State != store.BridgeTokenStateActive {
		t.Fatalf("listing = %+v", listing)
	}
	if listing.Limit != tokenListDefaultLimit {
		t.Fatalf("limit = %d, want %d", listing.Limit, tokenListDefaultLimit)
	}

	// Revoke, then the token no longer authenticates.
	resp = env.doNIP98(t, http.MethodDelete, "/auth/tokens/"+minted.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	if _, err := env.svc.Authenticate(t.Context(), minted.Token); err == nil {
		t.Fatal("revoked token still authenticates")
	}

	// Second revoke 404s.
	resp = env.doNIP98(t, http.MethodDelete, "/auth/tokens/"+minted.ID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("double revoke status = %d, want 404", resp.StatusCode)
	}
}

func TestTokenHandlerRejectsReplayedProof(t *testing.T) {
	env := newTokenHandlerEnv(t)
	body := []byte(`{"name":"laptop"}`)
	header := makeNIP98AuthHeader(t, tokenTestPublicURL+"/auth/token", http.MethodPost, body)

	resp := env.doWithHeader(t, http.MethodPost, "/auth/token", body, header)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first mint status = %d", resp.StatusCode)
	}
	resp = env.doWithHeader(t, http.MethodPost, "/auth/token", body, header)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed mint status = %d, want 401", resp.StatusCode)
	}
}

func TestTokenHandlerRejectsMismatchedProof(t *testing.T) {
	env := newTokenHandlerEnv(t)
	body := []byte(`{"name":"laptop"}`)

	// Signed over a different body.
	header := makeNIP98AuthHeader(t, tokenTestPublicURL+"/auth/token", http.MethodPost, []byte(`{"name":"other"}`))
	resp := env.doWithHeader(t, http.MethodPost, "/auth/token", body, header)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("payload mismatch status = %d, want 401", resp.StatusCode)
	}

	// Signed over a different path.
	header = makeNIP98AuthHeader(t, tokenTestPublicURL+"/auth/tokens", http.MethodPost, body)
	resp = env.doWithHeader(t, http.MethodPost, "/auth/token", body, header)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("URL mismatch status = %d, want 401", resp.StatusCode)
	}

	// No Authorization header at all.
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/token", bytes.NewReader(body))
	plain, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("plain request: %v", err)
	}
	defer plain.Body.Close()
	if plain.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing header status = %d, want 401", plain.StatusCode)
	}
}

func TestTokenHandlerValidationAndLimits(t *testing.T) {
	env := newTokenHandlerEnv(t)

	// Unknown scope → 400.
	body := []byte(`{"name":"laptop","scopes":["api:write"]}`)
	resp := env.doNIP98(t, http.MethodPost, "/auth/token", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled scope status = %d, want 400", resp.StatusCode)
	}

	// Oversized body → 413.
	big := []byte(`{"name":"` + strings.Repeat("x", maxTokenBodyBytes) + `"}`)
	resp = env.doNIP98(t, http.MethodPost, "/auth/token", big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", resp.StatusCode)
	}

	// Rotate flow: mint then rotate; old id rotates only once.
	resp = env.doNIP98(t, http.MethodPost, "/auth/token", []byte(`{"name":"laptop"}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint status = %d", resp.StatusCode)
	}
	minted := decodeJSON[MintResult](t, resp)

	resp = env.doNIP98(t, http.MethodPost, "/auth/tokens/"+minted.ID+"/rotate", []byte(`{"name":"laptop-rotated"}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("rotate status = %d", resp.StatusCode)
	}
	rotated := decodeJSON[MintResult](t, resp)
	if rotated.Token == minted.Token {
		t.Fatal("rotation returned the same token")
	}

	resp = env.doNIP98(t, http.MethodPost, "/auth/tokens/"+minted.ID+"/rotate", []byte(`{"name":"again"}`))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second rotate status = %d, want 404", resp.StatusCode)
	}
}

// TestSessionHandoffRouteRegisteredWithAuth proves the nginx auth_request
// target stays reachable through the NIP-07 handler registration used by
// main.go — the full-proxy cutover depends on this route existing. Without
// the internal marker the handler intentionally masquerades as 404 (with a
// JSON body, unlike the mux's text 404); with the marker but no binding it
// answers 401.
func TestSessionHandoffRouteRegisteredWithAuth(t *testing.T) {
	env := newTestNIP07Env(t)

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/auth/session/handoff/consume", nil)
	req.Header.Set("X-Grasp-Internal-Handoff", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET consume: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("consume with marker status = %d, want 401 (route must be registered)", resp.StatusCode)
	}

	plain, err := http.Get(env.server.URL + "/auth/session/handoff/consume")
	if err != nil {
		t.Fatalf("GET consume without marker: %v", err)
	}
	defer plain.Body.Close()
	if ct := plain.Header.Get("Content-Type"); plain.StatusCode != http.StatusNotFound || !strings.Contains(ct, "application/json") {
		t.Fatalf("masked consume = %d %q, want handler-served JSON 404", plain.StatusCode, ct)
	}
}

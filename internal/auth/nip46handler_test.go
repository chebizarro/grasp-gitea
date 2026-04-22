// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// mockBunkerConnector simulates a NIP-46 bunker for testing.
type mockBunkerConnector struct {
	signerPubkey string
	err          error
	delay        time.Duration
}

func (m *mockBunkerConnector) Connect(ctx context.Context, bunkerURI string) (string, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return m.signerPubkey, m.err
}

type testNIP46Env struct {
	handler *NIP46Handler
	store   *store.SQLiteStore
	mux     *http.ServeMux
	server  *httptest.Server
	mock    *mockBunkerConnector
}

func newTestNIP46Env(t *testing.T, connector *mockBunkerConnector) *testNIP46Env {
	t.Helper()

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Set up a fake Gitea user API.
	fakeAPI := newFakeUserAPI()
	giteaServer := httptest.NewServer(fakeAPI)
	t.Cleanup(giteaServer.Close)

	gc := gitea.NewClient(giteaServer.URL, "test-token")
	resolver := &stubOrgResolver{names: map[string]string{}}
	identitySvc := NewIdentityService(st, gc, resolver, logger)

	handler := NewNIP46Handler(st, identitySvc, nil, "https://bridge.example.com", connector, logger)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &testNIP46Env{
		handler: handler,
		store:   st,
		mux:     mux,
		server:  server,
		mock:    connector,
	}
}

const testBunkerPubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
const testBunkerURI = "bunker://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef?relay=wss://relay.example.com"

func TestNIP46InitSuccess(t *testing.T) {
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey, delay: 50 * time.Millisecond}
	env := newTestNIP46Env(t, mock)

	body := fmt.Sprintf(`{"bunker_uri":"%s","redirect_uri":"/dashboard"}`, testBunkerURI)
	resp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST init: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result nip46InitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.SessionToken == "" {
		t.Error("expected non-empty session token")
	}
	if result.PollURL == "" {
		t.Error("expected non-empty poll URL")
	}
	if result.ExpiresAt == "" {
		t.Error("expected non-empty expires_at")
	}
}

func TestNIP46InitMissingBunkerURI(t *testing.T) {
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey}
	env := newTestNIP46Env(t, mock)

	resp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestNIP46InitInvalidBunkerURI(t *testing.T) {
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey}
	env := newTestNIP46Env(t, mock)

	resp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(`{"bunker_uri":"not-a-bunker-uri"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestNIP46StatusPending(t *testing.T) {
	// Use a long delay so the session stays pending.
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey, delay: 10 * time.Second}
	env := newTestNIP46Env(t, mock)

	// Init a session.
	body := fmt.Sprintf(`{"bunker_uri":"%s"}`, testBunkerURI)
	initResp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	var initResult nip46InitResponse
	json.NewDecoder(initResp.Body).Decode(&initResult)
	initResp.Body.Close()

	// Poll immediately — should be pending.
	statusResp, err := http.Get(env.server.URL + "/auth/nip46/status?session=" + initResult.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()

	var status nip46StatusResponse
	json.NewDecoder(statusResp.Body).Decode(&status)
	if status.Status != "pending" {
		t.Errorf("expected 'pending', got %q", status.Status)
	}
}

func TestNIP46StatusComplete(t *testing.T) {
	// Use a very short delay so the session completes quickly.
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey, delay: 10 * time.Millisecond}
	env := newTestNIP46Env(t, mock)

	body := fmt.Sprintf(`{"bunker_uri":"%s","redirect_uri":"/repos"}`, testBunkerURI)
	initResp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	var initResult nip46InitResponse
	json.NewDecoder(initResp.Body).Decode(&initResult)
	initResp.Body.Close()

	// Wait for the async flow to complete.
	time.Sleep(100 * time.Millisecond)

	statusResp, err := http.Get(env.server.URL + "/auth/nip46/status?session=" + initResult.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()

	var status nip46StatusResponse
	json.NewDecoder(statusResp.Body).Decode(&status)
	if status.Status != "complete" {
		t.Errorf("expected 'complete', got %q (error: %s)", status.Status, status.Error)
	}
	if status.Identity == nil {
		t.Error("expected non-nil identity")
	}
	if status.RedirectURI != "/repos" {
		t.Errorf("expected redirect_uri='/repos', got %q", status.RedirectURI)
	}
}

func TestNIP46StatusError(t *testing.T) {
	// Connector returns an error.
	mock := &mockBunkerConnector{err: fmt.Errorf("bunker connection refused"), delay: 10 * time.Millisecond}
	env := newTestNIP46Env(t, mock)

	body := fmt.Sprintf(`{"bunker_uri":"%s"}`, testBunkerURI)
	initResp, err := http.Post(env.server.URL+"/auth/nip46/init", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	var initResult nip46InitResponse
	json.NewDecoder(initResp.Body).Decode(&initResult)
	initResp.Body.Close()

	// Wait for the async flow to fail.
	time.Sleep(100 * time.Millisecond)

	statusResp, err := http.Get(env.server.URL + "/auth/nip46/status?session=" + initResult.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()

	var status nip46StatusResponse
	json.NewDecoder(statusResp.Body).Decode(&status)
	if status.Status != "error" {
		t.Errorf("expected 'error', got %q", status.Status)
	}
	if status.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestNIP46StatusNotFound(t *testing.T) {
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey}
	env := newTestNIP46Env(t, mock)

	resp, err := http.Get(env.server.URL + "/auth/nip46/status?session=nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestNIP46StatusMissingParam(t *testing.T) {
	mock := &mockBunkerConnector{signerPubkey: testBunkerPubkey}
	env := newTestNIP46Env(t, mock)

	resp, err := http.Get(env.server.URL + "/auth/nip46/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestParseBunkerURI(t *testing.T) {
	tests := []struct {
		uri     string
		wantPK  string
		wantErr bool
	}{
		{testBunkerURI, testBunkerPubkey, false},
		{"bunker://aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", false},
		{"not-bunker://foo", "", true},
		{"bunker://tooshort", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		pk, err := parseBunkerURI(tt.uri)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseBunkerURI(%q): err=%v, wantErr=%v", tt.uri, err, tt.wantErr)
		}
		if pk != tt.wantPK {
			t.Errorf("parseBunkerURI(%q): got %q, want %q", tt.uri, pk, tt.wantPK)
		}
	}
}

func TestGenerateSessionToken(t *testing.T) {
	t1, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Error("expected different tokens")
	}
	if len(t1) != 64 {
		t.Errorf("expected 64-char token, got %d", len(t1))
	}
}

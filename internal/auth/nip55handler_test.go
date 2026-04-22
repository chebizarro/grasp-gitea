// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type testNIP55Env struct {
	handler     *NIP55Handler
	authService *Service
	mux         *http.ServeMux
	server      *httptest.Server
}

func newTestNIP55Env(t *testing.T) *testNIP55Env {
	t.Helper()

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Config{
		AuthEnabled:     true,
		BridgePublicURL: "https://bridge.example.com",
		ChallengeTTL:    5 * time.Minute,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	authSvc := NewService(cfg, st, logger)

	fakeAPI := newFakeUserAPI()
	giteaServer := httptest.NewServer(fakeAPI)
	t.Cleanup(giteaServer.Close)

	gc := gitea.NewClient(giteaServer.URL, "test-token")
	resolver := &stubOrgResolver{names: map[string]string{}}
	identitySvc := NewIdentityService(st, gc, resolver, logger)

	handler := NewNIP55Handler(authSvc, identitySvc, nil, logger)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &testNIP55Env{
		handler:     handler,
		authService: authSvc,
		mux:         mux,
		server:      server,
	}
}

func TestNIP55ChallengeEndpoint(t *testing.T) {
	env := newTestNIP55Env(t)

	resp, err := http.Get(env.server.URL + "/auth/nip55/challenge?redirect_uri=/dashboard")
	if err != nil {
		t.Fatalf("GET challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result nip55ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
	if !strings.HasPrefix(result.NostrSignerURI, "nostrsigner:") {
		t.Errorf("expected nostrsigner: URI, got %q", result.NostrSignerURI)
	}
	if result.CallbackURL != "https://bridge.example.com/auth/nip55/callback" {
		t.Errorf("unexpected callback URL: %s", result.CallbackURL)
	}
	if result.ExpiresAt == "" {
		t.Error("expected non-empty expires_at")
	}
}

func TestNIP55ChallengeWrongMethod(t *testing.T) {
	env := newTestNIP55Env(t)

	resp, err := http.Post(env.server.URL+"/auth/nip55/challenge", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestNIP55CallbackFullFlow(t *testing.T) {
	env := newTestNIP55Env(t)
	ctx := context.Background()

	// 1. Issue a challenge.
	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{RedirectURI: "/repos"})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// 2. Create a signed NIP-98 event (simulating the Android signer).
	ev := makeNIP98Event(t, challenge.Nonce, challenge.URL, "POST")

	// 3. Submit to callback endpoint.
	reqBody, _ := json.Marshal(nip55CallbackRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errResp)
	}

	var result nip55CallbackResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.OK {
		t.Error("expected OK=true")
	}
	if result.Identity.GiteaUser == "" {
		t.Error("expected non-empty GiteaUser")
	}
	if result.RedirectURI != "/repos" {
		t.Errorf("expected redirect_uri='/repos', got %q", result.RedirectURI)
	}
}

func TestNIP55CallbackReplayRejected(t *testing.T) {
	env := newTestNIP55Env(t)
	ctx := context.Background()

	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatal(err)
	}

	ev := makeNIP98Event(t, challenge.Nonce, challenge.URL, "POST")
	reqBody, _ := json.Marshal(nip55CallbackRequest{SignedEvent: ev})

	// First callback succeeds.
	resp1, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewReader(reqBody))
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first callback expected 200, got %d", resp1.StatusCode)
	}

	// Second callback (replay) should fail.
	resp2, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewReader(reqBody))
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("expected replay to be rejected")
	}
}

func TestNIP55CallbackMissingEvent(t *testing.T) {
	env := newTestNIP55Env(t)

	resp, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewBufferString(`{}`))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestNIP55CallbackWrongKind(t *testing.T) {
	env := newTestNIP55Env(t)
	ctx := context.Background()

	challenge, _ := env.authService.IssueChallenge(ctx, ChallengeRequest{})

	ev := &nostr.Event{
		Kind:      1,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", challenge.URL},
			{"method", "POST"},
			{"nonce", challenge.Nonce},
		},
	}
	ev.Sign(testSecretKey)

	reqBody, _ := json.Marshal(nip55CallbackRequest{SignedEvent: ev})
	resp, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewReader(reqBody))
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for wrong kind")
	}
}

func TestNIP55CallbackExpiredTimestamp(t *testing.T) {
	env := newTestNIP55Env(t)
	ctx := context.Background()

	challenge, _ := env.authService.IssueChallenge(ctx, ChallengeRequest{})

	ev := &nostr.Event{
		Kind:      27235,
		CreatedAt: nostr.Timestamp(time.Now().Add(-5 * time.Minute).Unix()),
		Tags: nostr.Tags{
			{"u", challenge.URL},
			{"method", "POST"},
			{"nonce", challenge.Nonce},
		},
	}
	ev.Sign(testSecretKey)

	reqBody, _ := json.Marshal(nip55CallbackRequest{SignedEvent: ev})
	resp, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewReader(reqBody))
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for expired timestamp")
	}
}

func TestNIP55CallbackInvalidJSON(t *testing.T) {
	env := newTestNIP55Env(t)

	resp, _ := http.Post(env.server.URL+"/auth/nip55/callback", "application/json", bytes.NewBufferString("broken"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

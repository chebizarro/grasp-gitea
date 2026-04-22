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
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// testSecretKey is a fixed key for generating properly signed test events.
const testSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testPubkeyFromSecret derives the pubkey from the test secret key.
func testPubkeyFromSecret(t *testing.T) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(testSecretKey)
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	return pk
}

type testNIP07Env struct {
	handler     *NIP07Handler
	authService *Service
	mux         *http.ServeMux
	server      *httptest.Server
}

func newTestNIP07Env(t *testing.T) *testNIP07Env {
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

	// Set up a fake Gitea user API.
	fakeAPI := newFakeUserAPI()
	giteaServer := httptest.NewServer(fakeAPI)
	t.Cleanup(giteaServer.Close)

	gc := gitea.NewClient(giteaServer.URL, "test-token")
	resolver := &stubOrgResolver{names: map[string]string{}}
	identitySvc := NewIdentityService(st, gc, resolver, logger)

	handler := NewNIP07Handler(authSvc, identitySvc, nil, logger)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &testNIP07Env{
		handler:     handler,
		authService: authSvc,
		mux:         mux,
		server:      server,
	}
}

// makeNIP98Event creates a properly signed NIP-98 event for testing.
func makeNIP98Event(t *testing.T, nonce string, url string, method string) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{
		Kind:      27235,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", url},
			{"method", method},
			{"nonce", nonce},
		},
		Content: "",
	}
	if err := ev.Sign(testSecretKey); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

func TestChallengeEndpoint(t *testing.T) {
	env := newTestNIP07Env(t)

	body := `{"redirect_uri":"/dashboard"}`
	resp, err := http.Post(env.server.URL+"/auth/nip07/challenge", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
	if result.URL != "https://bridge.example.com/auth/nip07/verify" {
		t.Errorf("unexpected URL: %s", result.URL)
	}
	if result.Method != "POST" {
		t.Errorf("unexpected method: %s", result.Method)
	}
}

func TestChallengeEndpointEmptyBody(t *testing.T) {
	env := newTestNIP07Env(t)

	resp, err := http.Post(env.server.URL+"/auth/nip07/challenge", "application/json", nil)
	if err != nil {
		t.Fatalf("POST challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestChallengeEndpointWrongMethod(t *testing.T) {
	env := newTestNIP07Env(t)

	resp, err := http.Get(env.server.URL + "/auth/nip07/challenge")
	if err != nil {
		t.Fatalf("GET challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestVerifyEndpointFullFlow(t *testing.T) {
	env := newTestNIP07Env(t)
	ctx := context.Background()

	// 1. Issue a challenge.
	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{RedirectURI: "/repos"})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// 2. Create a signed NIP-98 event.
	ev := makeNIP98Event(t, challenge.Nonce, challenge.URL, "POST")

	// 3. Submit to verify endpoint.
	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST verify: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, errResp)
	}

	var result verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.OK {
		t.Error("expected OK=true")
	}
	if result.Identity.Pubkey != ev.PubKey {
		t.Errorf("expected pubkey %s, got %s", ev.PubKey, result.Identity.Pubkey)
	}
	if result.Identity.GiteaUser == "" {
		t.Error("expected non-empty GiteaUser")
	}
	if result.RedirectURI != "/repos" {
		t.Errorf("expected redirect_uri='/repos', got %q", result.RedirectURI)
	}
}

func TestVerifyEndpointReplayRejected(t *testing.T) {
	env := newTestNIP07Env(t)
	ctx := context.Background()

	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	ev := makeNIP98Event(t, challenge.Nonce, challenge.URL, "POST")
	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})

	// First verify should succeed.
	resp1, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("first POST verify: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected first verify to succeed, got %d", resp1.StatusCode)
	}

	// Second verify (replay) should fail.
	resp2, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("second POST verify: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("expected replay to be rejected")
	}
}

func TestVerifyEndpointMissingEvent(t *testing.T) {
	env := newTestNIP07Env(t)

	reqBody := `{"signed_event":null}`
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("POST verify: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestVerifyEndpointWrongKind(t *testing.T) {
	env := newTestNIP07Env(t)
	ctx := context.Background()

	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// Create event with wrong kind.
	ev := &nostr.Event{
		Kind:      1, // not 27235
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", challenge.URL},
			{"method", "POST"},
			{"nonce", challenge.Nonce},
		},
	}
	ev.Sign(testSecretKey)

	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for wrong kind")
	}
}

func TestVerifyEndpointWrongURL(t *testing.T) {
	env := newTestNIP07Env(t)
	ctx := context.Background()

	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// Sign with wrong URL.
	ev := makeNIP98Event(t, challenge.Nonce, "https://evil.example.com/verify", "POST")

	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for URL mismatch")
	}
}

func TestVerifyEndpointExpiredTimestamp(t *testing.T) {
	env := newTestNIP07Env(t)
	ctx := context.Background()

	challenge, err := env.authService.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// Create event with old timestamp.
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

	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for expired timestamp")
	}
}

func TestVerifyEndpointMissingNonce(t *testing.T) {
	env := newTestNIP07Env(t)

	// Sign event without nonce tag.
	ev := &nostr.Event{
		Kind:      27235,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", "https://bridge.example.com/auth/nip07/verify"},
			{"method", "POST"},
		},
	}
	ev.Sign(testSecretKey)

	reqBody, _ := json.Marshal(verifyRequest{SignedEvent: ev})
	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected rejection for missing nonce")
	}
}

func TestVerifyEndpointInvalidJSON(t *testing.T) {
	env := newTestNIP07Env(t)

	resp, err := http.Post(env.server.URL+"/auth/nip07/verify", "application/json", bytes.NewBufferString("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestTagValue(t *testing.T) {
	tags := nostr.Tags{
		{"u", "https://example.com"},
		{"method", "POST"},
		{"nonce", "abc123"},
	}
	if got := tagValue(tags, "u"); got != "https://example.com" {
		t.Errorf("tagValue('u'): got %q", got)
	}
	if got := tagValue(tags, "nonce"); got != "abc123" {
		t.Errorf("tagValue('nonce'): got %q", got)
	}
	if got := tagValue(tags, "missing"); got != "" {
		t.Errorf("tagValue('missing'): got %q", got)
	}
}

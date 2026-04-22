// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func newTestService(t *testing.T, ttl time.Duration) *Service {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Config{
		AuthEnabled:     true,
		BridgePublicURL: "https://bridge.example.com",
		ChallengeTTL:    ttl,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewService(cfg, st, logger)
	if svc == nil {
		t.Fatal("expected non-nil service when auth is enabled")
	}
	return svc
}

func TestNewServiceReturnsNilWhenDisabled(t *testing.T) {
	cfg := config.Config{AuthEnabled: false}
	svc := NewService(cfg, nil, slog.Default())
	if svc != nil {
		t.Error("expected nil service when auth is disabled")
	}
	if svc.Enabled() {
		t.Error("expected Enabled() to return false for nil service")
	}
}

func TestIssueChallengeSuccess(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	ctx := context.Background()

	resp, err := svc.IssueChallenge(ctx, ChallengeRequest{RedirectURI: "/dashboard"})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	if len(resp.Nonce) != NonceLength*2 { // hex-encoded
		t.Errorf("expected nonce length %d, got %d", NonceLength*2, len(resp.Nonce))
	}
	if resp.URL != "https://bridge.example.com/auth/nip07/verify" {
		t.Errorf("unexpected URL: %s", resp.URL)
	}
	if resp.Method != "POST" {
		t.Errorf("unexpected method: %s", resp.Method)
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestValidateChallengeSuccess(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	ctx := context.Background()

	resp, err := svc.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	challenge, err := svc.ValidateChallenge(ctx, resp.Nonce)
	if err != nil {
		t.Fatalf("ValidateChallenge: %v", err)
	}
	if challenge.Nonce != resp.Nonce {
		t.Errorf("nonce mismatch: got %s, want %s", challenge.Nonce, resp.Nonce)
	}
	if challenge.Consumed {
		t.Error("expected challenge to not be consumed yet")
	}
}

func TestValidateChallengeExpired(t *testing.T) {
	svc := newTestService(t, 1*time.Millisecond)
	ctx := context.Background()

	resp, err := svc.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	_, err = svc.ValidateChallenge(ctx, resp.Nonce)
	if err == nil {
		t.Fatal("expected error for expired challenge")
	}
}

func TestValidateChallengeReplay(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	ctx := context.Background()

	resp, err := svc.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// Consume it.
	if err := svc.ConsumeChallenge(ctx, resp.Nonce); err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}

	// Attempt replay.
	_, err = svc.ValidateChallenge(ctx, resp.Nonce)
	if err == nil {
		t.Fatal("expected error for replayed challenge")
	}
}

func TestConsumeChallengeTwiceFails(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	ctx := context.Background()

	resp, err := svc.IssueChallenge(ctx, ChallengeRequest{})
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	if err := svc.ConsumeChallenge(ctx, resp.Nonce); err != nil {
		t.Fatalf("first ConsumeChallenge: %v", err)
	}
	if err := svc.ConsumeChallenge(ctx, resp.Nonce); err == nil {
		t.Fatal("expected error on second consume")
	}
}

func TestValidateChallengeNotFound(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	ctx := context.Background()

	_, err := svc.ValidateChallenge(ctx, "nonexistent-nonce")
	if err == nil {
		t.Fatal("expected error for nonexistent challenge")
	}
}

func TestCleanupExpired(t *testing.T) {
	// Use a TTL that's short enough to expire but long enough for RFC3339
	// second-precision timestamps to register as past.
	svc := newTestService(t, 1*time.Second)
	ctx := context.Background()

	// Issue 3 challenges that will expire after 1 second.
	for i := 0; i < 3; i++ {
		if _, err := svc.IssueChallenge(ctx, ChallengeRequest{}); err != nil {
			t.Fatalf("IssueChallenge %d: %v", i, err)
		}
	}

	// Sleep long enough to ensure RFC3339 second-precision timestamps
	// show expires_at strictly before the current second.
	time.Sleep(2100 * time.Millisecond)

	n, err := svc.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 cleaned up, got %d", n)
	}

	// Second cleanup should find nothing.
	n, err = svc.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 cleaned up, got %d", n)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	nonce2, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	if nonce1 == nonce2 {
		t.Error("expected different nonces")
	}
	if len(nonce1) != NonceLength*2 {
		t.Errorf("expected nonce hex length %d, got %d", NonceLength*2, len(nonce1))
	}
}

func TestServiceEnabled(t *testing.T) {
	svc := newTestService(t, 5*time.Minute)
	if !svc.Enabled() {
		t.Error("expected Enabled() to return true")
	}
}

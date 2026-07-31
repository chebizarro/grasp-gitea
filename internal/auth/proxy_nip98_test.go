// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"
)

// TestProxyNIP98VerifierEndToEnd verifies a real signed proof against the
// same canonical-URL + payload + replay pipeline the token API uses, and
// checks the identity mapping and implicit scope grant.
func TestProxyNIP98VerifierEndToEnd(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()
	pubkey := mustSK(testSecretKey).Public().Hex()

	// Link the identity (and provision the hidden PAT) the way a real user
	// does: by minting a bridge token first.
	if _, err := env.svc.Mint(ctx, pubkey, "ev-link", MintRequest{Name: "seed"}); err != nil {
		t.Fatalf("seed mint: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authSvc := &Service{
		store:     env.store,
		publicURL: "https://bridge.example.com",
		logger:    logger,
		nip98:     sharednip98.NewVerifier(time.Minute),
	}
	verifier := NewProxyNIP98Verifier(authSvc, env.svc)

	body := []byte(`{"title":"hello"}`)
	target := "https://bridge.example.com/api/v1/repos/o/r/issues"
	header := makeNIP98AuthHeader(t, target, "POST", body)

	r := httptest.NewRequest("POST", target, strings.NewReader(string(body)))
	r.Header.Set("Authorization", header)
	principal, err := verifier.VerifyProxyNIP98(ctx, r, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if principal.Pubkey != pubkey || principal.GiteaUserID == 0 || principal.GiteaUser == "" {
		t.Fatalf("principal = %+v", principal)
	}
	if !principal.HasScope(ScopeAPIWrite) || !principal.HasScope(ScopeGitWrite) {
		t.Fatalf("signature principal missing implicit scopes: %v", principal.Scopes)
	}

	// The hidden PAT must be servable for this principal.
	if _, _, err := env.svc.DownstreamPAT(ctx, principal.GiteaUserID, ScopeGitRead); err != nil {
		t.Fatalf("downstream PAT after NIP-98: %v", err)
	}

	// Replay of the same proof is refused.
	r2 := httptest.NewRequest("POST", target, strings.NewReader(string(body)))
	r2.Header.Set("Authorization", header)
	if _, err := verifier.VerifyProxyNIP98(ctx, r2, body); err == nil {
		t.Fatal("replayed proof accepted")
	}

	// A tampered body fails payload verification.
	header3 := makeNIP98AuthHeader(t, target, "POST", body)
	r3 := httptest.NewRequest("POST", target, strings.NewReader("{}"))
	r3.Header.Set("Authorization", header3)
	if _, err := verifier.VerifyProxyNIP98(ctx, r3, []byte("{}")); err == nil {
		t.Fatal("payload mismatch accepted")
	}
}

// TestProxyNIP98VerifierQuarantinesRecreatedAccount: if the linked Gitea
// login was deleted and recreated with a different user ID, a direct
// signature must not adopt the replacement account — it quarantines, mints
// no PAT, and revokes existing bridge tokens, exactly as Mint does.
func TestProxyNIP98VerifierQuarantinesRecreatedAccount(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()
	pubkey := mustSK(testSecretKey).Public().Hex()

	first, err := env.svc.Mint(ctx, pubkey, "ev-link", MintRequest{Name: "seed"})
	if err != nil {
		t.Fatalf("seed mint: %v", err)
	}
	createsBefore := env.fake.tokenCreates

	// Simulate delete-and-recreate: same login, different Gitea user ID.
	env.fake.mu.Lock()
	for login, user := range env.fake.users {
		user.ID += 1000
		env.fake.users[login] = user
	}
	env.fake.mu.Unlock()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authSvc := &Service{
		store:     env.store,
		publicURL: "https://bridge.example.com",
		logger:    logger,
		nip98:     sharednip98.NewVerifier(time.Minute),
	}
	verifier := NewProxyNIP98Verifier(authSvc, env.svc)

	target := "https://bridge.example.com/api/v1/user"
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Authorization", makeNIP98AuthHeader(t, target, "GET", nil))
	if _, err := verifier.VerifyProxyNIP98(ctx, r, nil); err == nil {
		t.Fatal("recreated account adopted by direct NIP-98")
	}
	if env.fake.tokenCreates != createsBefore {
		t.Fatal("PAT provisioned for the replacement account")
	}
	// The pre-existing bridge token was revoked by the quarantine.
	if _, err := env.svc.Authenticate(ctx, first.Token); err == nil {
		t.Fatal("bridge token survived identity quarantine")
	}
}

// TestProxyNIP98VerifierRejectsUnlinkedPubkey: proxied endpoints must never
// provision accounts as a side effect of a drive-by signature.
func TestProxyNIP98VerifierRejectsUnlinkedPubkey(t *testing.T) {
	env := newTokenTestEnv(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authSvc := &Service{
		store:     env.store,
		publicURL: "https://bridge.example.com",
		logger:    logger,
		nip98:     sharednip98.NewVerifier(time.Minute),
	}
	verifier := NewProxyNIP98Verifier(authSvc, env.svc)

	target := "https://bridge.example.com/api/v1/user"
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Authorization", makeNIP98AuthHeader(t, target, "GET", nil))
	if _, err := verifier.VerifyProxyNIP98(context.Background(), r, nil); err == nil {
		t.Fatal("unlinked pubkey accepted")
	}
	// No Gitea user was created as a side effect.
	if creates := env.fake.tokenCreates; creates != 0 {
		t.Fatalf("side-effect PAT provisioning: %d", creates)
	}
}

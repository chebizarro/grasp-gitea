// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// stubOrgResolver returns a fixed org name for a given pubkey.
type stubOrgResolver struct {
	names map[string]string // pubkey -> org name
}

func (r *stubOrgResolver) ResolveOrgName(_ context.Context, pubkey string, _ []string) string {
	if name, ok := r.names[pubkey]; ok {
		return name
	}
	// Hex fallback.
	if len(pubkey) > 39 {
		return pubkey[:39]
	}
	return pubkey
}

// fakeUserAPI is a minimal Gitea user API mock.
type fakeUserAPI struct {
	mu     sync.Mutex
	users  map[string]gitea.User
	nextID int64
}

func newFakeUserAPI() *fakeUserAPI {
	return &fakeUserAPI{
		users:  make(map[string]gitea.User),
		nextID: 100,
	}
}

func (f *fakeUserAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := r.URL.Path

	// GET /api/v1/users/:login
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") {
		login := strings.TrimPrefix(path, "/api/v1/users/")
		user, ok := f.users[login]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"message":"user not found"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		return
	}

	// POST /api/v1/admin/users
	if r.Method == http.MethodPost && path == "/api/v1/admin/users" {
		var req struct {
			Login    string `json:"login"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if _, exists := f.users[req.Login]; exists {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, `{"message":"user already exists"}`)
			return
		}

		user := gitea.User{
			ID:    f.nextID,
			Login: req.Login,
			Email: req.Email,
		}
		f.nextID++
		f.users[req.Login] = user

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

const testPubkey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func newTestIdentityService(t *testing.T, resolver OrgNameResolver) (*IdentityService, *store.SQLiteStore, *fakeUserAPI) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	fakeAPI := newFakeUserAPI()
	ts := httptest.NewServer(fakeAPI)
	t.Cleanup(ts.Close)

	gc := gitea.NewClient(ts.URL, "test-token")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc := NewIdentityService(st, gc, resolver, logger)
	return svc, st, fakeAPI
}

func TestResolveOrCreateNewUser(t *testing.T) {
	resolver := &stubOrgResolver{names: map[string]string{
		testPubkey: "alice",
	}}
	svc, _, _ := newTestIdentityService(t, resolver)
	ctx := context.Background()

	result, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("ResolveOrCreate: %v", err)
	}
	if !result.Created {
		t.Error("expected Created=true for new user")
	}
	if result.GiteaUser != "alice" {
		t.Errorf("expected GiteaUser='alice', got %q", result.GiteaUser)
	}
	if result.GiteaUserID == 0 {
		t.Error("expected non-zero GiteaUserID")
	}
	if result.Npub == "" {
		t.Error("expected non-empty npub")
	}
	if !strings.HasPrefix(result.Npub, "npub1") {
		t.Errorf("expected npub to start with 'npub1', got %q", result.Npub)
	}
}

func TestResolveOrCreateExistingLink(t *testing.T) {
	resolver := &stubOrgResolver{names: map[string]string{
		testPubkey: "alice",
	}}
	svc, _, _ := newTestIdentityService(t, resolver)
	ctx := context.Background()

	// First call creates.
	first, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("first ResolveOrCreate: %v", err)
	}
	if !first.Created {
		t.Error("expected first call to create user")
	}

	// Second call resolves existing.
	second, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("second ResolveOrCreate: %v", err)
	}
	if second.Created {
		t.Error("expected second call to NOT create user")
	}
	if second.GiteaUserID != first.GiteaUserID {
		t.Errorf("expected same user ID %d, got %d", first.GiteaUserID, second.GiteaUserID)
	}
	if second.GiteaUser != first.GiteaUser {
		t.Errorf("expected same user %q, got %q", first.GiteaUser, second.GiteaUser)
	}
}

func TestResolveOrCreateHexFallback(t *testing.T) {
	// No NIP-05 mapping — should use hex fallback.
	resolver := &stubOrgResolver{names: map[string]string{}}
	svc, _, _ := newTestIdentityService(t, resolver)
	ctx := context.Background()

	result, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("ResolveOrCreate: %v", err)
	}
	if !result.Created {
		t.Error("expected Created=true")
	}
	// Hex fallback should be first 39 chars.
	expectedUser := testPubkey[:39]
	if result.GiteaUser != expectedUser {
		t.Errorf("expected hex fallback user %q, got %q", expectedUser, result.GiteaUser)
	}
}

func TestResolveOrCreateNilResolver(t *testing.T) {
	svc, _, _ := newTestIdentityService(t, nil)
	ctx := context.Background()

	result, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("ResolveOrCreate: %v", err)
	}
	if !result.Created {
		t.Error("expected Created=true")
	}
	// With nil resolver, should use raw hex fallback.
	if len(result.GiteaUser) != 39 {
		t.Errorf("expected 39-char username, got %d chars: %q", len(result.GiteaUser), result.GiteaUser)
	}
}

func TestResolveOrCreateNIP05Detection(t *testing.T) {
	resolver := &stubOrgResolver{names: map[string]string{
		testPubkey: "alice",
	}}
	svc, st, _ := newTestIdentityService(t, resolver)
	ctx := context.Background()

	result, err := svc.ResolveOrCreate(ctx, testPubkey, nil)
	if err != nil {
		t.Fatalf("ResolveOrCreate: %v", err)
	}
	if result.NIP05 != "alice" {
		t.Errorf("expected NIP05='alice' (non-hex resolved name), got %q", result.NIP05)
	}

	// Verify persisted in store.
	link, err := st.GetIdentityLinkByPubkey(ctx, testPubkey)
	if err != nil {
		t.Fatalf("GetIdentityLinkByPubkey: %v", err)
	}
	if link.NIP05 != "alice" {
		t.Errorf("expected stored NIP05='alice', got %q", link.NIP05)
	}
}

func TestIsHexPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"deadbeef", true},
		{"0123456789abcdef", true},
		{"ABCDEF", true},
		{"alice", false},
		{"dead-beef", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isHexPrefix(tt.input)
		if got != tt.want {
			t.Errorf("isHexPrefix(%q): got %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	p1, err := generateRandomPassword()
	if err != nil {
		t.Fatalf("generateRandomPassword: %v", err)
	}
	p2, err := generateRandomPassword()
	if err != nil {
		t.Fatalf("generateRandomPassword: %v", err)
	}
	if p1 == p2 {
		t.Error("expected different passwords")
	}
	if len(p1) != 64 { // 32 bytes hex-encoded
		t.Errorf("expected 64-char password, got %d", len(p1))
	}
}

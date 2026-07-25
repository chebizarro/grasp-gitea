// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestProposedRepositoryStateReturnsAuthenticatedHeldEvent(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := nostr.Generate()
	event := nostr.Event{
		Kind:      nostr.KindRepositoryState,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"d", "demo"}},
	}
	if err := event.Sign(key); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPurgatoryEvent(t.Context(), store.PurgatoryEvent{
		EventID: event.ID.Hex(), Pubkey: key.Public().Hex(), Kind: int(event.Kind),
		DTag: "demo", EventJSON: string(raw), AcceptedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	handler := New(config.Config{AdminAPIToken: "secret"}, nil, nil, st, nil).Handler()
	req := httptest.NewRequest(http.MethodGet, "/repository-state/proposed?pubkey="+key.Public().Hex()+"&repo_id=demo", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), event.ID.Hex()) {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
}

func TestHealthEndpointNoAuth(t *testing.T) {
	cfg := config.Config{AdminAPIToken: "secret"}
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(cfg, nil, nil, st, nil)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthRequiredWhenTokenConfigured(t *testing.T) {
	cfg := config.Config{AdminAPIToken: "my-secret-token"}
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(cfg, nil, nil, st, nil)
	handler := srv.Handler()

	// Request without auth header should be rejected.
	req := httptest.NewRequest(http.MethodGet, "/mappings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}

	// Request with wrong token should be rejected.
	req = httptest.NewRequest(http.MethodGet, "/mappings", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with wrong token, got %d", w.Code)
	}

	// Request with correct token should succeed.
	req = httptest.NewRequest(http.MethodGet, "/mappings", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/repository-state/propose", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected proposed-state endpoint to require auth, got %d", w.Code)
	}
}

func TestNoAuthRequiredWhenTokenEmpty(t *testing.T) {
	cfg := config.Config{AdminAPIToken: ""}
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(cfg, nil, nil, st, nil)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mappings", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with no token configured, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/repository-state/propose", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected proposed-state endpoint to fail closed without configured auth, got %d", w.Code)
	}
}

func TestProvisionBodySizeLimit(t *testing.T) {
	cfg := config.Config{AdminAPIToken: ""}
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(cfg, nil, nil, st, nil)
	handler := srv.Handler()

	// Send a body larger than maxRequestBodySize (1MB).
	bigBody := strings.Repeat("x", maxRequestBodySize+1)
	req := httptest.NewRequest(http.MethodPost, "/provision", strings.NewReader(bigBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
}

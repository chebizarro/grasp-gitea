// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

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

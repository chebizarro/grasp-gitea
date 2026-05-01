// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"log/slog"
	"os"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestMirrorSyncNoToken(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: ""}
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/internal/mirror-sync", strings.NewReader(`{"repo_id":1}`))
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMirrorSyncWrongToken(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: "secret123"}
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/internal/mirror-sync", strings.NewReader(`{"repo_id":1}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMirrorSyncInvalidBody(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: "secret123"}
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/internal/mirror-sync", strings.NewReader(`not-json`))
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMirrorSyncMissingRepoID(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: "secret123"}
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/internal/mirror-sync", strings.NewReader(`{"repo_id":0}`))
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMirrorSyncPublisherDisabled(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: "secret123"}
	// publisher is nil → publish_disabled
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/internal/mirror-sync", strings.NewReader(`{"repo_id":42}`))
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMirrorSyncMethodNotAllowed(t *testing.T) {
	cfg := config.Config{MirrorCallbackToken: "secret123"}
	srv := New(cfg, nil, nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/internal/mirror-sync", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", w.Code, w.Body.String())
	}
}

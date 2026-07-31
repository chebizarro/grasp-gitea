// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type stubProbe struct {
	name string
	err  error
}

func (s stubProbe) Name() string                  { return s.name }
func (s stubProbe) Check(_ context.Context) error { return s.err }

func readyResponse(t *testing.T, srv *Server) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /ready body %q: %v", w.Body.String(), err)
	}
	return w.Code, body
}

func TestReadyReportsHealthyDependencies(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	srv := New(config.Config{}, nil, nil, st, testLogger())
	srv.AddReadinessProbe(stubProbe{name: "gitea"})

	code, body := readyResponse(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", code, body)
	}
	if body["status"] != "ready" {
		t.Fatalf("status = %v", body["status"])
	}
	checks, _ := body["checks"].(map[string]any)
	if checks["store"] != "ok" || checks["gitea"] != "ok" {
		t.Fatalf("checks = %v", checks)
	}
}

// TestReadyFailsWhenUpstreamIsDown is what makes the cutover safe to operate:
// in full-proxy mode an unreachable Gitea means the bridge cannot serve any
// traffic, so it must report itself unready rather than erroring per request.
func TestReadyFailsWhenUpstreamIsDown(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	srv := New(config.Config{}, nil, nil, st, testLogger())
	srv.AddReadinessProbe(stubProbe{name: "gitea", err: fmt.Errorf("connection refused")})

	code, body := readyResponse(t, srv)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %v", code, body)
	}
	if body["status"] != "not ready" {
		t.Fatalf("status = %v", body["status"])
	}
	checks, _ := body["checks"].(map[string]any)
	if got, _ := checks["gitea"].(string); got == "ok" || got == "" {
		t.Fatalf("gitea check = %q, want an error", got)
	}
}

func TestReadyFailsWhenStoreIsClosed(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ready.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := New(config.Config{}, nil, nil, st, testLogger())
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	code, _ := readyResponse(t, srv)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the store is unusable", code)
	}
}

func TestReadyRequiresNoAuth(t *testing.T) {
	// Load balancers and container healthchecks poll this without credentials.
	srv := New(config.Config{AdminAPIToken: "secret"}, nil, nil, nil, testLogger())
	code, _ := readyResponse(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without credentials", code)
	}
}

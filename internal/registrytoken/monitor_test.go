// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package registrytoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/metrics"
)

func testJWT(t *testing.T, issuedAt, expires int64) string {
	t.Helper()
	payload, err := json.Marshal(map[string]int64{"iat": issuedAt, "exp": expires})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func newTestMonitor(t *testing.T, handler http.HandlerFunc, maxLifetime, interval time.Duration) (*Monitor, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	monitor, err := New(server.URL+"/v2/token?service=container_registry", "admin", "pat", ModeRequire, maxLifetime, interval, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		server.Close()
		t.Fatalf("New: %v", err)
	}
	return monitor, server
}

func TestProbeRecordsAcceptedLifetime(t *testing.T) {
	monitor, server := newTestMonitor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/token" || r.URL.Query().Get("service") != "container_registry" {
			t.Errorf("request target = %s", r.URL.String())
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "admin" || password != "pat" {
			t.Errorf("Basic auth = (%q, %q, %v)", user, password, ok)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": testJWT(t, 100, 400)})
	}, 10*time.Minute, time.Hour)
	defer server.Close()

	monitor.probeAndRecord(context.Background())
	if err := monitor.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	snapshot := metrics.Snapshot()
	if got := snapshot["registry_token_lifetime_seconds"]; got != 300 {
		t.Fatalf("lifetime metric = %d, want 300", got)
	}
	if got := snapshot["registry_token_bound_exceeded"]; got != 0 {
		t.Fatalf("bound metric = %d, want 0", got)
	}
}

func TestProbeSignalsExceededBound(t *testing.T) {
	monitor, server := newTestMonitor(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": testJWT(t, 100, 3701)})
	}, 10*time.Minute, time.Hour)
	defer server.Close()

	monitor.probeAndRecord(context.Background())
	if err := monitor.Check(context.Background()); err == nil {
		t.Fatal("Check succeeded for excessive registry token lifetime")
	}
	snapshot := metrics.Snapshot()
	if got := snapshot["registry_token_lifetime_seconds"]; got != 3601 {
		t.Fatalf("lifetime metric = %d, want 3601", got)
	}
	if got := snapshot["registry_token_bound_exceeded"]; got != 1 {
		t.Fatalf("bound metric = %d, want 1", got)
	}
}

func TestProbeLogsNon2XXContext(t *testing.T) {
	const (
		challenge  = `Basic realm="registry"`
		apiVersion = "registry/2.0"
		body       = `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		w.Header().Set("Docker-Distribution-Api-Version", apiVersion)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	endpoint := server.URL + "/v2/token?service=container_registry"
	monitor, err := New(endpoint, "admin", "pat", ModeRequire, 10*time.Minute, time.Hour, server.Client(), logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	monitor.probeAndRecord(context.Background())

	checkErr := monitor.Check(context.Background())
	if checkErr == nil {
		t.Fatal("Check succeeded for 401 response")
	}
	if !strings.Contains(checkErr.Error(), endpoint) || !strings.Contains(checkErr.Error(), challenge) {
		t.Fatalf("readiness error lacks URL or challenge: %v", checkErr)
	}
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log: %v\n%s", err, logs.String())
	}
	for field, want := range map[string]string{
		"request_url":                     endpoint,
		"http_status":                     "401 Unauthorized",
		"www_authenticate":                challenge,
		"docker_distribution_api_version": apiVersion,
		"response_body":                   body,
	} {
		if got := entry[field]; got != want {
			t.Errorf("log field %s = %#v, want %q", field, got, want)
		}
	}
}

func TestWarnModeDoesNotFailReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	monitor, err := New(server.URL+"/v2/token?service=container_registry", "admin", "pat", ModeWarn, 10*time.Minute, time.Hour, server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	monitor.probeAndRecord(context.Background())
	if err := monitor.Check(context.Background()); err != nil {
		t.Fatalf("warn-mode readiness failed: %v", err)
	}
	if got := metrics.Snapshot()["registry_token_bound_exceeded"]; got != 1 {
		t.Fatalf("bound metric = %d, want 1", got)
	}
}

func TestRedactedURL(t *testing.T) {
	got := RedactedURL("https://admin:secret@gitea.example/v2/token?service=container_registry")
	if strings.Contains(got, "admin") || strings.Contains(got, "secret") || !strings.Contains(got, "REDACTED") {
		t.Fatalf("RedactedURL leaked credentials: %q", got)
	}
}

func TestProbeRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"status", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusUnauthorized) }},
		{"malformed jwt", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"token":"not-a-jwt"}`) }},
		{"invalid claims", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": testJWT(t, 400, 100)})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			monitor, server := newTestMonitor(t, tc.handler, 10*time.Minute, time.Hour)
			defer server.Close()
			monitor.probeAndRecord(context.Background())
			if err := monitor.Check(context.Background()); err == nil {
				t.Fatal("Check succeeded for invalid response")
			}
		})
	}
}

func TestRunProbesPeriodicallyAndStops(t *testing.T) {
	var requests atomic.Int64
	monitor, server := newTestMonitor(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": testJWT(t, 100, 400)})
	}, 10*time.Minute, 5*time.Millisecond)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		monitor.Run(ctx)
	}()
	deadline := time.Now().Add(time.Second)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
	if got := requests.Load(); got < 2 {
		t.Fatalf("requests = %d, want at least 2", got)
	}
}

func TestJWTLifetimeOverflow(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1,"exp":9223372036854775807}`))
	if _, err := jwtLifetime(header + "." + payload + ".sig"); err == nil {
		t.Fatal("overflowing exp-iat accepted")
	}
}

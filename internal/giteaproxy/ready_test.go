// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpstreamProbeReachable(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass"}`))
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL}, nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.UpstreamProbe().Check(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if gotPath != "/api/healthz" {
		t.Fatalf("probe path = %q", gotPath)
	}
}

func TestUpstreamProbeUnreachable(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := backend.URL
	backend.Close() // nothing is listening now

	p, err := New(Config{GiteaURL: url}, nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.UpstreamProbe().Check(context.Background()); err == nil {
		t.Fatal("probe reported a dead upstream as reachable")
	}
}

// A 404 means the health endpoint is not where the configuration says it is,
// which usually means a wrong base path. Reporting ready in that state would
// hide a misconfiguration that breaks every real request.
func TestUpstreamProbeRejectsUnexpectedStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL}, nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.UpstreamProbe().Check(context.Background()); err == nil {
		t.Fatal("probe accepted a 404 health endpoint as ready")
	}
}

// A base path in GiteaURL must be preserved: probing the wrong path would
// report ready while every real request 404s.
func TestUpstreamProbeHonoursBasePath(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL + "/gitea"}, nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.UpstreamProbe().Check(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if gotPath != "/gitea/api/healthz" {
		t.Fatalf("probe path = %q, want the configured base path preserved", gotPath)
	}
}

// A 5xx means Gitea is up but unhealthy; the bridge cannot serve traffic.
func TestUpstreamProbeReportsServerErrors(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL}, nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.UpstreamProbe().Check(context.Background()); err == nil {
		t.Fatal("probe accepted a 502 upstream")
	}
}

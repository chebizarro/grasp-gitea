// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/api"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type stubAuthStateInspector struct {
	hasState       bool
	hasTenantState bool
	err            error
	tenantErr      error
	calls          int
}

func (s *stubAuthStateInspector) HasAuthState(context.Context) (bool, error) {
	s.calls++
	return s.hasState, s.err
}
func (s *stubAuthStateInspector) HasTenantState(context.Context) (bool, error) {
	return s.hasTenantState, s.tenantErr
}

func TestProductionServerInstallsSCIMProvider(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/scim-wiring.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	managed := store.ManagedTenant{Host: "example.com", Policy: store.TenantPolicySharedRead, State: store.TenantStateActive, OrgName: "org-example", ProvisioningMarker: "marker-example", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateManagedTenant(context.Background(), managed); err != nil {
		t.Fatal(err)
	}
	token := "production-scim-token"
	digest := sha256.Sum256([]byte(token))
	if err := st.UpsertTenantSCIMToken(context.Background(), store.TenantSCIMToken{Host: managed.Host, TokenHash: digest[:], TokenSuffix: "im-token", Generation: 1, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	server := api.New(config.Config{}, nil, nil, st, nil)
	installSCIMProvider(server, st, nil)
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("production handler SCIM status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGuardPostgresTakeover(t *testing.T) {
	tests := []struct {
		name       string
		sqlite     stubAuthStateInspector
		postgres   stubAuthStateInspector
		allowEmpty bool
		wantErr    string
	}{
		{name: "both empty"},
		{name: "postgres populated", sqlite: stubAuthStateInspector{hasState: true}, postgres: stubAuthStateInspector{hasState: true}},
		{name: "refuses empty takeover", sqlite: stubAuthStateInspector{hasState: true}, wantErr: "POSTGRES_ALLOW_EMPTY_TAKEOVER=true"},
		{name: "tenant state migrated", sqlite: stubAuthStateInspector{hasTenantState: true}, postgres: stubAuthStateInspector{hasTenantState: true}},
		{name: "refuses missing tenant state", sqlite: stubAuthStateInspector{hasTenantState: true}, postgres: stubAuthStateInspector{hasState: true}, wantErr: "tenant or affiliation state"},
		{name: "explicit override", sqlite: stubAuthStateInspector{hasState: true, hasTenantState: true}, allowEmpty: true},
		{name: "sqlite inspection fails closed", sqlite: stubAuthStateInspector{err: errors.New("read failed")}, wantErr: "inspect SQLite auth state"},
		{name: "postgres inspection fails closed", sqlite: stubAuthStateInspector{hasState: true}, postgres: stubAuthStateInspector{err: errors.New("read failed")}, wantErr: "inspect Postgres auth state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := guardPostgresTakeover(context.Background(), &tt.sqlite, &tt.postgres, tt.allowEmpty)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("guardPostgresTakeover() error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("guardPostgresTakeover() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMergeRelayURLsEmpty(t *testing.T) {
	result := mergeRelayURLs(nil, "")
	if len(result) != 0 {
		t.Errorf("expected 0 URLs, got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsNoEmbedded(t *testing.T) {
	configured := []string{"wss://r1", "wss://r2"}
	result := mergeRelayURLs(configured, "")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[0] != "wss://r1" || result[1] != "wss://r2" {
		t.Errorf("unexpected URLs: %v", result)
	}
}

func TestMergeRelayURLsAppendsEmbedded(t *testing.T) {
	configured := []string{"wss://external"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[1] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL appended, got %v", result)
	}
}

func TestMergeRelayURLsDeduplicates(t *testing.T) {
	configured := []string{"ws://localhost:3334", "wss://other"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Errorf("expected 2 URLs (no duplicate), got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsEmbeddedOnly(t *testing.T) {
	result := mergeRelayURLs(nil, "ws://localhost:3334")
	if len(result) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(result), result)
	}
	if result[0] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL, got %v", result)
	}
}

func TestMergeRelayURLsDoesNotMutateInput(t *testing.T) {
	configured := []string{"wss://r1"}
	original := make([]string, len(configured))
	copy(original, configured)

	_ = mergeRelayURLs(configured, "ws://localhost:3334")

	if len(configured) != len(original) {
		t.Error("mergeRelayURLs mutated the input slice")
	}
	if configured[0] != original[0] {
		t.Error("mergeRelayURLs mutated the input slice content")
	}
}

func TestRelaySubscriptionURLsSkipsPublicEmbeddedRelay(t *testing.T) {
	configured := []string{
		"wss://external.example",
		"wss://grasp.example/",
	}
	result := relaySubscriptionURLs(configured, "ws://localhost:3334", "wss://grasp.example")
	if len(result) != 2 {
		t.Fatalf("expected external and local embedded relay, got %v", result)
	}
	if result[0] != "wss://external.example" || result[1] != "ws://localhost:3334" {
		t.Fatalf("unexpected relay subscriptions: %v", result)
	}
}

func TestRelaySubscriptionURLsKeepsPublicRelayWithoutEmbedded(t *testing.T) {
	result := relaySubscriptionURLs(
		[]string{"wss://grasp.example"},
		"",
		"wss://grasp.example",
	)
	if len(result) != 1 || result[0] != "wss://grasp.example" {
		t.Fatalf("expected public relay without embedded relay, got %v", result)
	}
}

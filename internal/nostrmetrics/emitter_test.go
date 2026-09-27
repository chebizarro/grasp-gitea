// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nostrmetrics

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fiatjaf.com/nostr"
)

// testSigner is a deterministic signer for unit tests.
type testSigner struct {
	privKey nostr.SecretKey
	pubKey  string
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	sk := nostr.Generate()
	return &testSigner{
		privKey: sk,
		pubKey:  sk.Public().Hex(),
	}
}

func (s *testSigner) PublicKey() string { return s.pubKey }

func (s *testSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	return ev.Sign(s.privKey)
}

func TestNewReturnsNilWithoutSigner(t *testing.T) {
	e := New(Config{
		Signer:    nil,
		RelayURLs: []string{"wss://relay.example.com"},
	})
	if e != nil {
		t.Fatal("expected nil emitter without signer")
	}
	if e.Enabled() {
		t.Fatal("nil emitter should not be enabled")
	}
}

func TestNewReturnsNilWithoutRelays(t *testing.T) {
	signer := newTestSigner(t)
	e := New(Config{
		Signer:    signer,
		RelayURLs: nil,
	})
	if e != nil {
		t.Fatal("expected nil emitter without relays")
	}
}

func TestNewSetsDefaults(t *testing.T) {
	signer := newTestSigner(t)
	e := New(Config{
		Signer:    signer,
		RelayURLs: []string{"wss://relay.example.com"},
	})
	if e == nil {
		t.Fatal("expected non-nil emitter")
	}
	if !e.Enabled() {
		t.Fatal("emitter should be enabled")
	}
	if e.service != "grasp-bridge" {
		t.Errorf("service = %q, want %q", e.service, "grasp-bridge")
	}
	if e.instanceID != signer.PublicKey() {
		t.Errorf("instanceID = %q, want signer pubkey", e.instanceID)
	}
	if e.scope != "grasp-bridge" {
		t.Errorf("scope = %q, want %q", e.scope, "grasp-bridge")
	}
}

func TestNewAppliesCustomConfig(t *testing.T) {
	signer := newTestSigner(t)
	e := New(Config{
		Signer:      signer,
		RelayURLs:   []string{"wss://relay.example.com"},
		ServiceName: "my-service",
		InstanceID:  "instance-42",
		Scope:       "custom-scope",
	})
	if e.service != "my-service" {
		t.Errorf("service = %q, want %q", e.service, "my-service")
	}
	if e.instanceID != "instance-42" {
		t.Errorf("instanceID = %q, want %q", e.instanceID, "instance-42")
	}
	if e.scope != "custom-scope" {
		t.Errorf("scope = %q, want %q", e.scope, "custom-scope")
	}
}

func TestNilEmitterMethodsAreNoOps(t *testing.T) {
	var e *Emitter
	ctx := context.Background()

	// None of these should panic.
	e.Emit(ctx, DataPoint{Name: "test", Type: Gauge, Value: 1.0})
	e.EmitBatch(ctx, []DataPoint{{Name: "test", Type: Gauge, Value: 1.0}})
	e.EmitGauge(ctx, "test", 1.0, "s", nil)

	if e.Enabled() {
		t.Fatal("nil emitter should not be enabled")
	}
	if e.String() != "nostrmetrics.Emitter(disabled)" {
		t.Errorf("String() = %q", e.String())
	}
}

func TestEmitterString(t *testing.T) {
	signer := newTestSigner(t)
	e := New(Config{
		Signer:    signer,
		RelayURLs: []string{"wss://relay1.example.com", "wss://relay2.example.com"},
	})
	s := e.String()
	if !strings.Contains(s, "grasp-bridge") {
		t.Errorf("String() missing service name: %q", s)
	}
	if !strings.Contains(s, "relays=2") {
		t.Errorf("String() missing relay count: %q", s)
	}
}

func TestDataPointJSON(t *testing.T) {
	dp := DataPoint{
		Name:              "registry.token.lifetime",
		Description:       "JWT lifetime in seconds",
		Unit:              "s",
		Type:              Gauge,
		Value:             86400,
		TimestampUnixNano: 1695000000000000000,
		Attributes: map[string]string{
			"accepted_bound": "129600",
		},
	}
	raw, err := json.Marshal(dp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DataPoint
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Name != dp.Name {
		t.Errorf("name = %q, want %q", decoded.Name, dp.Name)
	}
	if decoded.Value != dp.Value {
		t.Errorf("value = %f, want %f", decoded.Value, dp.Value)
	}
	if decoded.Type != Gauge {
		t.Errorf("type = %q, want %q", decoded.Type, Gauge)
	}
	if decoded.Attributes["accepted_bound"] != "129600" {
		t.Errorf("attributes mismatch")
	}
}

// TestEmitBuildsCorrectEvent verifies the event structure without a real relay.
// We intercept at the sign step to inspect the event.
type captureSigner struct {
	privKey nostr.SecretKey
	pubKey  string
	mu      sync.Mutex
	events  []nostr.Event
}

func newCaptureSigner(t *testing.T) *captureSigner {
	t.Helper()
	sk := nostr.Generate()
	return &captureSigner{
		privKey: sk,
		pubKey:  sk.Public().Hex(),
	}
}

func (s *captureSigner) PublicKey() string { return s.pubKey }

func (s *captureSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ev.Sign(s.privKey); err != nil {
		return err
	}
	s.events = append(s.events, *ev)
	return nil
}

func TestEmitEventStructure(t *testing.T) {
	signer := newCaptureSigner(t)

	// Start a fake HTTP server that will reject connections (we just want to
	// verify the event is built and signed correctly; publish failures are
	// expected and logged).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	// Use a ws:// URL that will fail connection — we only care about sign.
	e := New(Config{
		Signer:      signer,
		RelayURLs:   []string{"ws://127.0.0.1:1"}, // unreachable, publish will fail
		ServiceName: "test-service",
		InstanceID:  "test-instance",
		Scope:       "test-scope",
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	dp := DataPoint{
		Name:              "registry.token.lifetime",
		Description:       "JWT exp-iat in seconds",
		Unit:              "s",
		Type:              Gauge,
		Value:             86400,
		TimestampUnixNano: 1695000000000000000,
		Attributes:        map[string]string{"endpoint": "v2-token"},
	}

	e.Emit(context.Background(), dp)

	signer.mu.Lock()
	defer signer.mu.Unlock()

	if len(signer.events) != 1 {
		t.Fatalf("expected 1 signed event, got %d", len(signer.events))
	}

	ev := signer.events[0]

	// Verify kind.
	if ev.Kind != Kind {
		t.Errorf("kind = %d, want %d", ev.Kind, Kind)
	}

	// Verify d tag.
	dTag := ev.Tags.GetD()
	if dTag != "test-scope/registry.token.lifetime" {
		t.Errorf("d tag = %q, want %q", dTag, "test-scope/registry.token.lifetime")
	}

	// Verify service tags.
	assertTag := func(key, want string) {
		t.Helper()
		for _, tag := range ev.Tags {
			if len(tag) >= 2 && tag[0] == key {
				if tag[1] != want {
					t.Errorf("tag %q = %q, want %q", key, tag[1], want)
				}
				return
			}
		}
		t.Errorf("tag %q not found", key)
	}
	assertTag("service.name", "test-service")
	assertTag("service.instance_id", "test-instance")
	assertTag("metric.type", "gauge")
	assertTag("metric.unit", "s")

	// Verify attribute tag.
	var foundAttr bool
	for _, tag := range ev.Tags {
		if len(tag) >= 3 && tag[0] == "t" && tag[1] == "endpoint" {
			if tag[2] != "v2-token" {
				t.Errorf("attribute tag endpoint = %q, want %q", tag[2], "v2-token")
			}
			foundAttr = true
		}
	}
	if !foundAttr {
		t.Error("attribute tag 'endpoint' not found")
	}

	// Verify content is valid JSON with the data point.
	var decoded DataPoint
	if err := json.Unmarshal([]byte(ev.Content), &decoded); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if decoded.Value != 86400 {
		t.Errorf("content value = %f, want 86400", decoded.Value)
	}

	// Verify pubkey matches signer.
	if ev.PubKey.Hex() != signer.PublicKey() {
		t.Errorf("pubkey = %s, want %s", ev.PubKey.Hex(), signer.PublicKey())
	}

	// Verify the event has a valid signature.
	if !ev.VerifySignature() {
		t.Error("event signature is invalid")
	}
}

func TestEmitGaugeConvenience(t *testing.T) {
	signer := newCaptureSigner(t)
	e := New(Config{
		Signer:    signer,
		RelayURLs: []string{"ws://127.0.0.1:1"},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	e.EmitGauge(context.Background(), "test.metric", 42.5, "ms", map[string]string{"host": "node1"})

	signer.mu.Lock()
	defer signer.mu.Unlock()

	if len(signer.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(signer.events))
	}

	var dp DataPoint
	if err := json.Unmarshal([]byte(signer.events[0].Content), &dp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dp.Name != "test.metric" {
		t.Errorf("name = %q", dp.Name)
	}
	if dp.Value != 42.5 {
		t.Errorf("value = %f", dp.Value)
	}
	if dp.Type != Gauge {
		t.Errorf("type = %q", dp.Type)
	}
}

func TestEmitBatch(t *testing.T) {
	signer := newCaptureSigner(t)
	e := New(Config{
		Signer:    signer,
		RelayURLs: []string{"ws://127.0.0.1:1"},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	points := []DataPoint{
		{Name: "metric.a", Type: Gauge, Value: 1},
		{Name: "metric.b", Type: Counter, Value: 2},
		{Name: "metric.c", Type: Gauge, Value: 3},
	}

	e.EmitBatch(context.Background(), points)

	signer.mu.Lock()
	defer signer.mu.Unlock()

	if len(signer.events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(signer.events))
	}

	// Verify each event has a unique d tag.
	dTags := make(map[string]bool)
	for _, ev := range signer.events {
		dTags[ev.Tags.GetD()] = true
	}
	if len(dTags) != 3 {
		t.Errorf("expected 3 unique d tags, got %d", len(dTags))
	}
}



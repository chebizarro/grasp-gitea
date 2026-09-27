// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package nostrmetrics publishes OTEL-compatible metric data points as signed
// Nostr events. Each metric becomes a kind-31420 parametric replaceable event
// so relay consumers always see the latest value for a given metric name.
//
// Event structure:
//
//	Kind:    31420 (parametric replaceable — telemetry)
//	Tags:
//	  ["d", "<scope>/<metric.name>"]          — replacement key
//	  ["service.name", "<service>"]           — OTEL resource attribute
//	  ["service.instance_id", "<instance>"]   — OTEL resource attribute
//	  ["metric.type", "gauge"|"counter"]      — OTEL instrument kind
//	  ["metric.unit", "s"|"1"|"By"|…]         — OTEL unit string
//	  ["t", "<key>", "<value>"]               — per-data-point attributes
//	Content: JSON-encoded DataPoint (value + timestamp)
//
// The kind 31420 is application-defined and does not conflict with any
// registered NIP kind as of 2026-09. A future NIP for Nostr-native telemetry
// could supersede it.
package nostrmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"fiatjaf.com/nostr"
)

// Kind is the Nostr event kind for OTEL-compatible metric data points.
// Parametric replaceable (30000–39999 range) so the latest value per metric
// replaces prior values on the relay.
const Kind = 31420

// MetricType mirrors OTEL instrument kinds relevant to infrastructure metrics.
type MetricType string

const (
	Gauge   MetricType = "gauge"
	Counter MetricType = "counter"
)

// DataPoint is a single OTEL-compatible metric observation.
type DataPoint struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Unit        string            `json:"unit,omitempty"`
	Type        MetricType        `json:"type"`
	Value       float64           `json:"value"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	// TimestampUnixNano follows the OTEL data model; set automatically if zero.
	TimestampUnixNano int64 `json:"timestamp_unix_nano,omitempty"`
}

// EventSigner signs Nostr events. Compatible with publisher.ServerSigner.
type EventSigner interface {
	PublicKey() string
	SignEvent(ctx context.Context, ev *nostr.Event) error
}

// Emitter publishes OTEL-compatible metrics as signed Nostr events to
// configured relays. It is safe for concurrent use.
type Emitter struct {
	signer     EventSigner
	relayURLs  []string
	service    string
	instanceID string
	scope      string
	logger     *slog.Logger
}

// Config configures a metrics emitter.
type Config struct {
	// Signer signs outbound metric events with the bridge identity.
	Signer EventSigner
	// RelayURLs are the Nostr relays to publish metric events to.
	RelayURLs []string
	// ServiceName is the OTEL service.name resource attribute.
	ServiceName string
	// InstanceID is the OTEL service.instance_id resource attribute.
	// Defaults to the signer's public key if empty.
	InstanceID string
	// Scope is the OTEL instrumentation scope name prefix for the `d` tag.
	// Defaults to "grasp-bridge".
	Scope string
	// Logger for publish diagnostics.
	Logger *slog.Logger
}

// New creates a metrics emitter. Returns nil (no-op) if signer is nil or
// no relay URLs are configured — callers can safely call Emit on a nil Emitter.
func New(cfg Config) *Emitter {
	if cfg.Signer == nil || len(cfg.RelayURLs) == 0 {
		return nil
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "grasp-bridge"
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = cfg.Signer.PublicKey()
	}
	if cfg.Scope == "" {
		cfg.Scope = "grasp-bridge"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Emitter{
		signer:     cfg.Signer,
		relayURLs:  cfg.RelayURLs,
		service:    cfg.ServiceName,
		instanceID: cfg.InstanceID,
		scope:      cfg.Scope,
		logger:     cfg.Logger.With("component", "nostrmetrics"),
	}
}

// Emit publishes a single data point as a signed kind-31420 event. It is
// best-effort: relay failures are logged but do not return errors, matching
// the OTEL exporter contract where metric export failures are non-fatal.
//
// Safe to call on a nil receiver (no-op).
func (e *Emitter) Emit(ctx context.Context, dp DataPoint) {
	if e == nil {
		return
	}
	if dp.TimestampUnixNano == 0 {
		dp.TimestampUnixNano = time.Now().UnixNano()
	}

	content, err := json.Marshal(dp)
	if err != nil {
		e.logger.Error("marshal metric data point", "metric", dp.Name, "error", err)
		return
	}

	dTag := e.scope + "/" + dp.Name

	tags := nostr.Tags{
		{"d", dTag},
		{"service.name", e.service},
		{"service.instance_id", e.instanceID},
		{"metric.type", string(dp.Type)},
	}
	if dp.Unit != "" {
		tags = append(tags, nostr.Tag{"metric.unit", dp.Unit})
	}
	for k, v := range dp.Attributes {
		tags = append(tags, nostr.Tag{"t", k, v})
	}

	ev := nostr.Event{
		Kind:      Kind,
		Tags:      tags,
		Content:   string(content),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}

	pk, pkErr := nostr.PubKeyFromHex(e.signer.PublicKey())
	if pkErr != nil {
		e.logger.Error("invalid signer pubkey", "error", pkErr)
		return
	}
	ev.PubKey = pk

	if err := e.signer.SignEvent(ctx, &ev); err != nil {
		e.logger.Error("sign metric event", "metric", dp.Name, "error", err)
		return
	}

	e.publishToRelays(ctx, &ev, dp.Name)
}

// EmitBatch publishes multiple data points. Each becomes a separate event.
// Safe to call on a nil receiver.
func (e *Emitter) EmitBatch(ctx context.Context, points []DataPoint) {
	if e == nil {
		return
	}
	for i := range points {
		e.Emit(ctx, points[i])
	}
}

// EmitGauge is a convenience for emitting a single gauge data point.
// Safe to call on a nil receiver.
func (e *Emitter) EmitGauge(ctx context.Context, name string, value float64, unit string, attrs map[string]string) {
	e.Emit(ctx, DataPoint{
		Name:       name,
		Type:       Gauge,
		Value:      value,
		Unit:       unit,
		Attributes: attrs,
	})
}

func (e *Emitter) publishToRelays(ctx context.Context, ev *nostr.Event, metricName string) {
	var succeeded int
	for _, relayURL := range e.relayURLs {
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, connErr := nostr.RelayConnect(pubCtx, relayURL, nostr.RelayOptions{})
		if connErr != nil {
			cancel()
			e.logger.Warn("metric relay connect failed", "relay", relayURL, "metric", metricName, "error", connErr)
			continue
		}
		pubErr := conn.Publish(pubCtx, *ev)
		conn.Close()
		cancel()
		if pubErr != nil {
			e.logger.Warn("metric relay publish failed", "relay", relayURL, "metric", metricName, "event", ev.ID.Hex(), "error", pubErr)
			continue
		}
		succeeded++
	}
	if succeeded > 0 {
		e.logger.Debug("metric published", "metric", metricName, "relays_ok", succeeded, "relays_total", len(e.relayURLs))
	} else {
		e.logger.Warn("metric publish failed on all relays", "metric", metricName, "relays_total", len(e.relayURLs))
	}
}

// Enabled reports whether the emitter is configured and will publish events.
func (e *Emitter) Enabled() bool {
	return e != nil
}

// String returns a human-readable description for logging.
func (e *Emitter) String() string {
	if e == nil {
		return "nostrmetrics.Emitter(disabled)"
	}
	return fmt.Sprintf("nostrmetrics.Emitter(service=%s, relays=%d, scope=%s)", e.service, len(e.relayURLs), e.scope)
}

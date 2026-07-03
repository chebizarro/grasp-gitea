// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestOutboundEventsEndpointReturnsCountsAndEntries(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "api-outbound.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	seedOutboundEvent(t, st, store.OutboundEvent{
		DedupeKey:    "pending-key",
		Kind:         30617,
		AuthorPubkey: "pending-author",
		Scope:        "repo:pending",
		UnsignedJSON: `{"content":"pending"}`,
		State:        store.OutboundStatePending,
	}, now)
	seedOutboundEvent(t, st, store.OutboundEvent{
		DedupeKey:        "published-key",
		Kind:             30617,
		AuthorPubkey:     "published-author",
		Scope:            "repo:published",
		UnsignedJSON:     `{"content":"published"}`,
		State:            store.OutboundStatePublished,
		PublishedEventID: "published-event-id",
	}, now.Add(time.Second))
	seedOutboundEvent(t, st, store.OutboundEvent{
		DedupeKey:    "dead-key",
		Kind:         30617,
		AuthorPubkey: "dead-author",
		Scope:        "repo:dead",
		UnsignedJSON: `{"content":"dead"}`,
		State:        store.OutboundStateDead,
		Attempts:     3,
		LastError:    "signer offline",
	}, now.Add(2*time.Second))

	srv := New(config.Config{AdminAPIToken: "admin-token"}, nil, nil, st, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/outbound-events?limit=2", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		Counts store.OutboundQueueCounts `json:"counts"`
		Recent []store.OutboundEvent     `json:"recent"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Counts.Pending != 1 || got.Counts.Published != 1 || got.Counts.Dead != 1 {
		t.Fatalf("counts = %+v, want 1 pending / 1 published / 1 dead", got.Counts)
	}
	if len(got.Recent) != 2 {
		t.Fatalf("recent length = %d, want 2", len(got.Recent))
	}
	if got.Recent[0].DedupeKey != "dead-key" || got.Recent[1].DedupeKey != "published-key" {
		t.Fatalf("recent entries ordered unexpectedly: %+v", got.Recent)
	}
	if got.Recent[1].PublishedEventID != "published-event-id" {
		t.Fatalf("published entry event id = %q", got.Recent[1].PublishedEventID)
	}
}

func seedOutboundEvent(t *testing.T, st *store.SQLiteStore, ev store.OutboundEvent, now time.Time) {
	t.Helper()
	inserted, err := st.EnqueueOutboundEvent(context.Background(), ev, now)
	if err != nil {
		t.Fatalf("seed outbound event %q: %v", ev.DedupeKey, err)
	}
	if !inserted {
		t.Fatalf("seed outbound event %q was deduped unexpectedly", ev.DedupeKey)
	}
}

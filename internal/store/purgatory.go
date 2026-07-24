// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func marshalStringSlice(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	raw, err := json.Marshal(values)
	return string(raw), err
}

func unmarshalStringSlice(raw string) ([]string, error) {
	var out []string
	if raw == "" {
		return nil, nil
	}
	err := json.Unmarshal([]byte(raw), &out)
	return out, err
}

// PurgatoryEvent is an accepted Nostr event retained durably but not served
// until its referenced Git data arrives (GRASP-01 purgatory).
type PurgatoryEvent struct {
	EventID      string
	Pubkey       string
	Kind         int
	DTag         string
	EventJSON    string
	RequiredSHAs []string
	RepoPath     string
	AcceptedAt   time.Time
}

// UpsertPurgatoryEvent records an event awaiting Git data. Re-acceptance of
// the same event refreshes nothing: the original accepted_at is preserved so
// expiry cannot be extended by replays.
func (s *SQLiteStore) UpsertPurgatoryEvent(ctx context.Context, ev PurgatoryEvent) error {
	shas, err := marshalStringSlice(ev.RequiredSHAs)
	if err != nil {
		return fmt.Errorf("marshal required shas: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO purgatory_events (event_id, pubkey, kind, d_tag, event_json, required_shas, repo_path, accepted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_id) DO NOTHING`,
		ev.EventID, ev.Pubkey, ev.Kind, ev.DTag, ev.EventJSON, shas, ev.RepoPath, ev.AcceptedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert purgatory event: %w", err)
	}
	return nil
}

// ListPurgatoryEvents returns all events currently held in purgatory.
func (s *SQLiteStore) ListPurgatoryEvents(ctx context.Context) ([]PurgatoryEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, pubkey, kind, d_tag, event_json, required_shas, repo_path, accepted_at
		FROM purgatory_events ORDER BY accepted_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list purgatory events: %w", err)
	}
	defer rows.Close()
	var out []PurgatoryEvent
	for rows.Next() {
		var ev PurgatoryEvent
		var shas string
		if err := rows.Scan(&ev.EventID, &ev.Pubkey, &ev.Kind, &ev.DTag, &ev.EventJSON, &shas, &ev.RepoPath, &ev.AcceptedAt); err != nil {
			return nil, fmt.Errorf("scan purgatory event: %w", err)
		}
		ev.RequiredSHAs, err = unmarshalStringSlice(shas)
		if err != nil {
			return nil, fmt.Errorf("decode required shas: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// DeletePurgatoryEvent removes an event from purgatory (after release or expiry).
func (s *SQLiteStore) DeletePurgatoryEvent(ctx context.Context, eventID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM purgatory_events WHERE event_id = ?`, eventID)
	if err != nil {
		return fmt.Errorf("delete purgatory event: %w", err)
	}
	return nil
}

// PurgatoryContains reports whether an event is currently held in purgatory.
func (s *SQLiteStore) PurgatoryContains(ctx context.Context, eventID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM purgatory_events WHERE event_id = ?`, eventID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

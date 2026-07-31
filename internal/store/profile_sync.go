// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ProfileSyncCursor is the last kind:0 event applied to a user's Gitea
// profile. CreatedAt is the event's created_at; a strictly greater value is
// required to apply a new event (replaceable-event semantics).
type ProfileSyncCursor struct {
	Pubkey         string
	GiteaUserID    int64
	EventCreatedAt int64
	EventID        string
	SyncedAt       time.Time
}

// GetProfileSyncCursor returns the applied kind:0 cursor for a pubkey scoped
// to a Gitea user id. A cursor recorded against a DIFFERENT user id (the
// account was repaired/recreated) is treated as zero, so the current kind:0
// is re-applied to the new account. Never-synced returns a zero cursor.
func (s *SQLiteStore) GetProfileSyncCursor(ctx context.Context, pubkey string, giteaUserID int64) (ProfileSyncCursor, error) {
	cur := ProfileSyncCursor{Pubkey: pubkey, GiteaUserID: giteaUserID}
	var storedUserID, createdAt int64
	var eventID, syncedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT gitea_user_id, event_created_at, event_id, synced_at FROM profile_sync_state WHERE pubkey = ?
	`, pubkey).Scan(&storedUserID, &createdAt, &eventID, &syncedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSyncCursor{Pubkey: pubkey, GiteaUserID: giteaUserID}, nil
		}
		return ProfileSyncCursor{}, err
	}
	if storedUserID != giteaUserID {
		// Identity repaired: the old cursor does not describe this account.
		return ProfileSyncCursor{Pubkey: pubkey, GiteaUserID: giteaUserID}, nil
	}
	cur.EventCreatedAt = createdAt
	cur.EventID = eventID
	if syncedAt != "" {
		cur.SyncedAt, _ = time.Parse(time.RFC3339, syncedAt)
	}
	return cur, nil
}

// MarkNostrProfileSynced advances the cursor, but only if the candidate
// event_created_at is strictly newer than the stored one. Returns whether it
// updated; a false with nil error means a newer event was already applied.
func (s *SQLiteStore) MarkNostrProfileSynced(ctx context.Context, pubkey string, giteaUserID int64, eventID string, eventCreatedAt int64, syncedAt time.Time) (bool, error) {
	// Advance when strictly newer, OR whenever the stored cursor belongs to a
	// different Gitea user id (identity repair resets the cursor).
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO profile_sync_state(pubkey, gitea_user_id, event_created_at, event_id, synced_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			gitea_user_id = excluded.gitea_user_id,
			event_created_at = excluded.event_created_at,
			event_id = excluded.event_id,
			synced_at = excluded.synced_at
		WHERE excluded.gitea_user_id != profile_sync_state.gitea_user_id
		   OR excluded.event_created_at > profile_sync_state.event_created_at
	`, pubkey, giteaUserID, eventCreatedAt, eventID, syncedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListIdentityLinksAfter keyset-pages identity links ordered by pubkey, for
// the profile-sync sweep. Pass "" to start; pass the last returned pubkey to
// continue. A link inserted before the cursor is picked up next sweep.
func (s *SQLiteStore) ListIdentityLinksAfter(ctx context.Context, afterPubkey string, limit int) ([]NostrIdentityLink, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT pubkey, npub, gitea_user_id, gitea_user, nip05, created_at, updated_at, last_login_at
		FROM nostr_identity_links WHERE pubkey > ? ORDER BY pubkey ASC LIMIT ?
	`, afterPubkey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []NostrIdentityLink
	for rows.Next() {
		var link NostrIdentityLink
		var createdAt, updatedAt, lastLoginAt string
		if err := rows.Scan(&link.Pubkey, &link.Npub, &link.GiteaUserID, &link.GiteaUser,
			&link.NIP05, &createdAt, &updatedAt, &lastLoginAt); err != nil {
			return nil, err
		}
		link.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		link.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		if lastLoginAt != "" {
			link.LastLoginAt, _ = time.Parse(time.RFC3339, lastLoginAt)
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// ProfileSyncPATCleanup is a durable record of an ephemeral write:user PAT
// minted to set a user's avatar. Its existence means a PAT may be live in
// Gitea; the row is removed only once deletion is confirmed.
type ProfileSyncPATCleanup struct {
	PATName        string
	GiteaUserID    int64
	GiteaUser      string
	GiteaTokenID   int64
	CreatedAt      time.Time
	DeleteAttempts int
	LastError      string
}

// ReserveProfileSyncPATCleanup records the intent to mint an ephemeral PAT
// BEFORE it is created, so a crash mid-mint still leaves a cleanup record.
func (s *SQLiteStore) ReserveProfileSyncPATCleanup(ctx context.Context, rec ProfileSyncPATCleanup, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO profile_sync_pat_cleanup(pat_name, gitea_user_id, gitea_user, gitea_token_id, created_at)
		VALUES(?, ?, ?, 0, ?)
	`, rec.PATName, rec.GiteaUserID, rec.GiteaUser, now.UTC().Format(time.RFC3339))
	return err
}

// SetProfileSyncPATTokenID records Gitea's numeric token id once created, so
// cleanup can delete by id (reliable across a rename).
func (s *SQLiteStore) SetProfileSyncPATTokenID(ctx context.Context, patName string, tokenID int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE profile_sync_pat_cleanup SET gitea_token_id = ? WHERE pat_name = ?
	`, tokenID, patName)
	return err
}

// GetProfileSyncPATCleanupForUser returns any outstanding cleanup record for a
// user, or ok=false if none. A user may hold at most one at a time.
func (s *SQLiteStore) GetProfileSyncPATCleanupForUser(ctx context.Context, giteaUserID int64) (ProfileSyncPATCleanup, bool, error) {
	rec, err := s.scanProfileSyncPATCleanup(s.db.QueryRowContext(ctx, `
		SELECT pat_name, gitea_user_id, gitea_user, gitea_token_id, created_at, delete_attempts, last_error
		FROM profile_sync_pat_cleanup WHERE gitea_user_id = ? LIMIT 1
	`, giteaUserID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSyncPATCleanup{}, false, nil
		}
		return ProfileSyncPATCleanup{}, false, err
	}
	return rec, true, nil
}

// ListStaleProfileSyncPATCleanup returns outstanding cleanup rows ordered by
// delete_attempts (fair retry: a permanently-failing row never starves fresh
// ones) then created_at.
func (s *SQLiteStore) ListStaleProfileSyncPATCleanup(ctx context.Context, limit int) ([]ProfileSyncPATCleanup, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT pat_name, gitea_user_id, gitea_user, gitea_token_id, created_at, delete_attempts, last_error
		FROM profile_sync_pat_cleanup ORDER BY delete_attempts ASC, created_at ASC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileSyncPATCleanup
	for rows.Next() {
		rec, err := s.scanProfileSyncPATCleanup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// RecordProfileSyncPATDeleteFailure bumps delete_attempts and records the
// error, keeping the row for fair-ordered retry.
func (s *SQLiteStore) RecordProfileSyncPATDeleteFailure(ctx context.Context, patName, lastError string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE profile_sync_pat_cleanup SET delete_attempts = delete_attempts + 1, last_error = ?
		WHERE pat_name = ?
	`, lastError, patName)
	return err
}

// DeleteProfileSyncPATCleanup removes a cleanup row once its Gitea PAT is
// confirmed gone.
func (s *SQLiteStore) DeleteProfileSyncPATCleanup(ctx context.Context, patName string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM profile_sync_pat_cleanup WHERE pat_name = ?`, patName)
	return err
}

func (s *SQLiteStore) scanProfileSyncPATCleanup(row rowScanner) (ProfileSyncPATCleanup, error) {
	var rec ProfileSyncPATCleanup
	var createdAt string
	if err := row.Scan(&rec.PATName, &rec.GiteaUserID, &rec.GiteaUser, &rec.GiteaTokenID,
		&createdAt, &rec.DeleteAttempts, &rec.LastError); err != nil {
		return ProfileSyncPATCleanup{}, err
	}
	if createdAt != "" {
		var err error
		rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return ProfileSyncPATCleanup{}, fmt.Errorf("parse profile-sync cleanup created_at for %s: %w", rec.PATName, err)
		}
	}
	return rec, nil
}

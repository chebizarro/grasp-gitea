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

// BridgeSignerSession persists the bridge's own NIP-46 client identity for a
// bunker so restarts reconnect with the already-authorized client key instead
// of generating a fresh one (Signet authorization is one-time).
type BridgeSignerSession struct {
	BunkerURI       string // secret-stripped bunker URI (primary key)
	ClientSeckeyEnc []byte // encrypted client secret key
	ClientPubkey    string
	SignerPubkey    string
	CreatedAt       time.Time
	LastOKAt        *time.Time
}

// GetBridgeSignerSession loads the persisted session for a bunker URI.
func (s *SQLiteStore) GetBridgeSignerSession(ctx context.Context, bunkerURI string) (BridgeSignerSession, error) {
	var sess BridgeSignerSession
	var lastOK sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT bunker_uri, client_seckey_enc, client_pubkey, signer_pubkey, created_at, last_ok_at
		FROM bridge_signer_sessions WHERE bunker_uri = ?`, bunkerURI).
		Scan(&sess.BunkerURI, &sess.ClientSeckeyEnc, &sess.ClientPubkey, &sess.SignerPubkey, &sess.CreatedAt, &lastOK)
	if err != nil {
		return BridgeSignerSession{}, err
	}
	if lastOK.Valid {
		t := lastOK.Time
		sess.LastOKAt = &t
	}
	return sess, nil
}

// UpsertBridgeSignerSession stores or replaces the bridge session for a bunker.
func (s *SQLiteStore) UpsertBridgeSignerSession(ctx context.Context, sess BridgeSignerSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bridge_signer_sessions (bunker_uri, client_seckey_enc, client_pubkey, signer_pubkey, created_at, last_ok_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(bunker_uri) DO UPDATE SET
			client_seckey_enc = excluded.client_seckey_enc,
			client_pubkey = excluded.client_pubkey,
			signer_pubkey = excluded.signer_pubkey,
			last_ok_at = excluded.last_ok_at`,
		sess.BunkerURI, sess.ClientSeckeyEnc, sess.ClientPubkey, sess.SignerPubkey, sess.CreatedAt.UTC(), sess.LastOKAt)
	if err != nil {
		return fmt.Errorf("upsert bridge signer session: %w", err)
	}
	return nil
}

// TouchBridgeSignerSession records a successful use of the session.
func (s *SQLiteStore) TouchBridgeSignerSession(ctx context.Context, bunkerURI string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE bridge_signer_sessions SET last_ok_at = ? WHERE bunker_uri = ?`, at.UTC(), bunkerURI)
	return err
}

// ErrNoBridgeSignerSession reports a missing persisted session.
var ErrNoBridgeSignerSession = errors.New("no bridge signer session")

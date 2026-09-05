// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"time"
)

// AuthStore is the persistence contract for the bridge's authentication
// state: bridge tokens, hidden PAT credentials, NIP-98 replay claims,
// challenges, NIP-46 sessions, identity links, and the auth audit ledger.
//
// This is the exact state active-active deployment must share across nodes
// (docs/designs/phase6-active-active.md). *SQLiteStore implements it today;
// a shared transactional backend (Postgres) implements it next. Every method
// an auth-layer consumer calls belongs here — consumers hold this interface,
// never *SQLiteStore, so the backend can be swapped without touching them.
//
// Contract notes a second implementation must honor:
//   - ClaimNIP98Event is single-use ACROSS NODES: the same event id must be
//     claimable exactly once (unique-constraint semantics, not read-check).
//   - InsertBridgeToken enforces maxActive atomically (conditional insert).
//   - ActivatePATCredential atomically demotes the previously active
//     generation (create-before-retire under one transaction).
//   - ResealPATCredential is compare-and-swap on the ciphertext and reports
//     rows affected.
//   - "Not found" is sql.ErrNoRows (or a wrapper satisfying errors.Is).
type AuthStore interface {
	// WithUserLock runs fn while holding an exclusive lock for one Gitea
	// user, honored ACROSS EVERY NODE sharing the store. It serializes the
	// PAT lifecycle (provision, scope upgrade, retirement, reconciliation)
	// against itself; fn may perform external calls, so implementations
	// must not hold a database transaction while fn runs.
	WithUserLock(ctx context.Context, giteaUserID int64, fn func(ctx context.Context) error) error

	// TryMaintenanceLease attempts to become the maintenance leader for a
	// single sweep. acquired=false means another node holds it right now, so
	// the caller should skip this tick (leadership is an efficiency
	// guarantee: sweeps stay idempotent, so skipping only avoids redundant
	// work). Always call release() when acquired is true. A single-node
	// backend is always the leader.
	TryMaintenanceLease(ctx context.Context) (acquired bool, release func(), err error)

	// NIP-98 replay ledger.
	ClaimNIP98Event(ctx context.Context, eventID, pubkey, method string, targetHash []byte, now, expiresAt time.Time) (bool, error)
	CleanupExpiredReplayClaims(ctx context.Context, now time.Time) (int64, error)

	// Login challenges.
	CreateChallenge(ctx context.Context, c AuthChallenge) error
	GetChallenge(ctx context.Context, nonce string) (AuthChallenge, error)
	ConsumeChallenge(ctx context.Context, nonce string) error
	DeleteExpiredChallenges(ctx context.Context) (int64, error)

	// NIP-46 sessions and signer grants.
	CreateNIP46Session(ctx context.Context, sess NIP46Session) error
	GetNIP46Session(ctx context.Context, token string) (NIP46Session, error)
	UpdateNIP46SessionState(ctx context.Context, token string, state string, resultPubkey string, errMsg string) error
	DeleteExpiredNIP46Sessions(ctx context.Context) (int64, error)
	GetSignerGrant(ctx context.Context, pubkey string) (SignerGrant, error)
	UpsertSignerGrant(ctx context.Context, grant SignerGrant) error
	RevokeSignerGrant(ctx context.Context, pubkey string, at time.Time) error
	RecordSignerGrantOK(ctx context.Context, pubkey string, at time.Time) error
	GetBridgeSignerSession(ctx context.Context, bunkerURI string) (BridgeSignerSession, error)
	UpsertBridgeSignerSession(ctx context.Context, sess BridgeSignerSession) error
	TouchBridgeSignerSession(ctx context.Context, bunkerURI string, at time.Time) error

	// Identity links.
	GetIdentityLinkByPubkey(ctx context.Context, pubkey string) (NostrIdentityLink, error)
	GetIdentityLinkByGiteaUserID(ctx context.Context, userID int64) (NostrIdentityLink, error)
	ListIdentityLinksAfter(ctx context.Context, afterPubkey string, limit int) ([]NostrIdentityLink, error)
	UpsertIdentityLink(ctx context.Context, link NostrIdentityLink) error
	UpdateLastLogin(ctx context.Context, pubkey string) error

	// Verified NIP-05 domain affiliation. This state is shared across nodes and
	// remains separate from identity-link naming metadata.
	UpsertDomainAffiliation(ctx context.Context, affiliation DomainAffiliation) error
	GetDomainAffiliation(ctx context.Context, pubkey string) (DomainAffiliation, error)
	ListVerifiedDomainAffiliations(ctx context.Context, host string, checkedAfter time.Time, limit int) ([]DomainAffiliation, error)

	// Bridge tokens.
	InsertBridgeToken(ctx context.Context, t BridgeToken, maxActive int) error
	GetBridgeTokenByHash(ctx context.Context, hash []byte) (BridgeToken, error)
	ListBridgeTokens(ctx context.Context, pubkey string, limit, offset int) ([]BridgeToken, error)
	RevokeBridgeToken(ctx context.Context, pubkey, id string, now time.Time) error
	RevokeBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error)
	RotateBridgeToken(ctx context.Context, pubkey, oldID string, replacement BridgeToken, now time.Time) error
	TouchBridgeTokenUsage(ctx context.Context, id string, now, cutoff time.Time) error
	CountActiveBridgeTokensForGiteaUser(ctx context.Context, giteaUserID int64, now time.Time) (int64, error)

	// Hidden PAT credential lifecycle.
	ReservePATCredential(ctx context.Context, giteaUserID int64, giteaUser, namePrefix string, giteaScopes []string, now time.Time) (generation int64, patName string, err error)
	FinalizePATCredential(ctx context.Context, giteaUserID, generation, giteaTokenID int64, ciphertext []byte, keyID string) error
	ActivatePATCredential(ctx context.Context, giteaUserID, generation int64, now time.Time) error
	GetActivePATCredential(ctx context.Context, giteaUserID int64) (GiteaPATCredential, error)
	ResealPATCredential(ctx context.Context, giteaUserID, generation int64, expectedCiphertext, ciphertext []byte, keyID string) (int64, error)
	SetPATCredentialState(ctx context.Context, giteaUserID, generation int64, state, lastError string) error
	RetireActivePATCredential(ctx context.Context, giteaUserID int64) (int64, error)
	MarkPATCredentialRetired(ctx context.Context, giteaUserID, generation int64, now time.Time) error
	RecordPATDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error
	RecordTerminalDeleteFailure(ctx context.Context, giteaUserID, generation int64, lastError string) error
	DeletePATCredential(ctx context.Context, giteaUserID, generation int64) error
	ListGiteaUsersWithoutActiveTokens(ctx context.Context, now time.Time, limit int) (map[int64]time.Time, error)
	ListPATCredentialsPendingDeletion(ctx context.Context, limit int) ([]GiteaPATCredential, error)
	ListPATCredentialsByState(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error)
	ListPATCredentialsUnderStaleKey(ctx context.Context, activeKeyID string, limit int) ([]GiteaPATCredential, error)
	ListStalePATCredentialsInState(ctx context.Context, state string, before time.Time, limit int) ([]GiteaPATCredential, error)
	ListTerminalPATCredentials(ctx context.Context, state string, limit int) ([]GiteaPATCredential, error)

	// Auth audit ledger.
	InsertAuthAuditEvent(ctx context.Context, ev AuthAuditEvent) error
	ListAuthAuditEvents(ctx context.Context, eventType string, limit int) ([]AuthAuditEvent, error)
	CleanupAuthAuditEvents(ctx context.Context, before time.Time) (int64, error)
}

// The SQLite store is the reference AuthStore implementation.
var _ AuthStore = (*SQLiteStore)(nil)

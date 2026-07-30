// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openAuthTokenTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "auth-tokens.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testBridgeToken(id, pubkey string, giteaUserID int64, issued time.Time, ttl time.Duration) BridgeToken {
	hash := sha256.Sum256([]byte("plaintext-" + id))
	return BridgeToken{
		ID:             id,
		TokenHash:      hash[:],
		TokenSuffix:    "abcdef",
		Pubkey:         pubkey,
		GiteaUserID:    giteaUserID,
		Name:           "test " + id,
		Scopes:         []string{"git:read", "git:write"},
		IssuedAt:       issued,
		ExpiresAt:      issued.Add(ttl),
		CreatedEventID: "event-" + id,
	}
}

func TestSchemaMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotent.db")
	st1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("second open (migrations must be idempotent): %v", err)
	}
	_ = st2.Close()
}

func TestBridgeTokenInsertGetAndState(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	tok := testBridgeToken("tok1", "pk1", 11, now, time.Hour)
	if err := st.InsertBridgeToken(ctx, tok, 50); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := st.GetBridgeTokenByHash(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "tok1" || got.Pubkey != "pk1" || got.GiteaUserID != 11 {
		t.Fatalf("unexpected token: %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "git:read" {
		t.Fatalf("scopes = %v", got.Scopes)
	}
	if got.State(now) != BridgeTokenStateActive {
		t.Fatalf("state = %q, want active", got.State(now))
	}
	if got.State(now.Add(2*time.Hour)) != BridgeTokenStateExpired {
		t.Fatal("expired token not reported expired")
	}

	if _, err := st.GetBridgeTokenByHash(ctx, []byte("nope")); !errors.Is(err, ErrBridgeTokenNotFound) {
		t.Fatalf("unknown hash error = %v, want ErrBridgeTokenNotFound", err)
	}

	// Duplicate hash must be rejected by the unique index.
	dup := testBridgeToken("tok2", "pk1", 11, now, time.Hour)
	dup.TokenHash = tok.TokenHash
	if err := st.InsertBridgeToken(ctx, dup, 50); err == nil {
		t.Fatal("duplicate token hash accepted")
	}
}

func TestBridgeTokenActiveLimit(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.InsertBridgeToken(ctx, testBridgeToken("a", "pk", 1, now, time.Hour), 2); err != nil {
		t.Fatalf("insert a: %v", err)
	}
	if err := st.InsertBridgeToken(ctx, testBridgeToken("b", "pk", 1, now, time.Hour), 2); err != nil {
		t.Fatalf("insert b: %v", err)
	}
	if err := st.InsertBridgeToken(ctx, testBridgeToken("c", "pk", 1, now, time.Hour), 2); !errors.Is(err, ErrBridgeTokenLimit) {
		t.Fatalf("third insert error = %v, want ErrBridgeTokenLimit", err)
	}

	// Revoked tokens free capacity; other pubkeys are unaffected.
	if err := st.RevokeBridgeToken(ctx, "pk", "a", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := st.InsertBridgeToken(ctx, testBridgeToken("c", "pk", 1, now, time.Hour), 2); err != nil {
		t.Fatalf("insert after revoke: %v", err)
	}
	if err := st.InsertBridgeToken(ctx, testBridgeToken("d", "other", 2, now, time.Hour), 2); err != nil {
		t.Fatalf("other pubkey blocked: %v", err)
	}
}

func TestBridgeTokenRevokeOwnershipAndDoubleRevoke(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.InsertBridgeToken(ctx, testBridgeToken("tok", "owner", 1, now, time.Hour), 0); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.RevokeBridgeToken(ctx, "intruder", "tok", now); !errors.Is(err, ErrBridgeTokenNotFound) {
		t.Fatalf("cross-owner revoke error = %v, want ErrBridgeTokenNotFound", err)
	}
	if err := st.RevokeBridgeToken(ctx, "owner", "tok", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := st.RevokeBridgeToken(ctx, "owner", "tok", now); !errors.Is(err, ErrBridgeTokenNotFound) {
		t.Fatalf("double revoke error = %v, want ErrBridgeTokenNotFound", err)
	}
}

func TestBridgeTokenRotation(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	orig := testBridgeToken("orig", "pk", 5, now, time.Hour)
	if err := st.InsertBridgeToken(ctx, orig, 0); err != nil {
		t.Fatalf("insert: %v", err)
	}

	replacement := testBridgeToken("next", "pk", 5, now, 2*time.Hour)
	if err := st.RotateBridgeToken(ctx, "pk", "orig", replacement, now); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	old, err := st.GetBridgeTokenByHash(ctx, orig.TokenHash)
	if err != nil {
		t.Fatalf("get old: %v", err)
	}
	if old.State(now) != BridgeTokenStateRevoked {
		t.Fatalf("old state = %q, want revoked", old.State(now))
	}
	if _, err := st.GetBridgeTokenByHash(ctx, replacement.TokenHash); err != nil {
		t.Fatalf("replacement missing: %v", err)
	}

	// Rotating an already-revoked token fails and must not insert anything.
	again := testBridgeToken("again", "pk", 5, now, time.Hour)
	if err := st.RotateBridgeToken(ctx, "pk", "orig", again, now); !errors.Is(err, ErrBridgeTokenNotFound) {
		t.Fatalf("rotate revoked error = %v, want ErrBridgeTokenNotFound", err)
	}
	if _, err := st.GetBridgeTokenByHash(ctx, again.TokenHash); !errors.Is(err, ErrBridgeTokenNotFound) {
		t.Fatal("failed rotation leaked replacement row")
	}
}

func TestRotateBridgeTokenPinsSubject(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	orig := testBridgeToken("orig", "pk", 5, now, time.Hour)
	if err := st.InsertBridgeToken(ctx, orig, 0); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// A buggy handler passes a replacement claiming a different subject.
	hijack := testBridgeToken("hijack", "other-pubkey", 999, now, time.Hour)
	if err := st.RotateBridgeToken(ctx, "pk", "orig", hijack, now); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	stored, err := st.GetBridgeTokenByHash(ctx, hijack.TokenHash)
	if err != nil {
		t.Fatalf("get replacement: %v", err)
	}
	if stored.Pubkey != "pk" || stored.GiteaUserID != 5 {
		t.Fatalf("replacement subject = %s/%d, want pk/5 (subject must be copied from revoked row)", stored.Pubkey, stored.GiteaUserID)
	}
}

func TestBridgeTokenLimitConcurrentMints(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const limit = 5
	const attempts = 20
	var wg sync.WaitGroup
	errs := make([]error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = st.InsertBridgeToken(ctx, testBridgeToken(fmt.Sprintf("c%d", i), "pk", 1, now, time.Hour), limit)
		}(i)
	}
	wg.Wait()

	inserted := 0
	for i, err := range errs {
		switch {
		case err == nil:
			inserted++
		case errors.Is(err, ErrBridgeTokenLimit):
		default:
			t.Fatalf("attempt %d unexpected error: %v", i, err)
		}
	}
	if inserted != limit {
		t.Fatalf("inserted = %d, want exactly %d (conditional INSERT must serialize the limit)", inserted, limit)
	}
}

func TestBridgeTokenListAndGiteaUserOperations(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	for i, id := range []string{"t1", "t2", "t3"} {
		tok := testBridgeToken(id, "pk", 9, now.Add(time.Duration(i)*time.Minute), time.Hour)
		if err := st.InsertBridgeToken(ctx, tok, 0); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	page, err := st.ListBridgeTokens(ctx, "pk", 2, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 2 || page[0].ID != "t3" {
		t.Fatalf("page = %+v, want newest first", page)
	}

	count, err := st.CountActiveBridgeTokensForGiteaUser(ctx, 9, now)
	if err != nil || count != 3 {
		t.Fatalf("count = %d err=%v, want 3", count, err)
	}

	revoked, err := st.RevokeBridgeTokensForGiteaUser(ctx, 9, now)
	if err != nil || revoked != 3 {
		t.Fatalf("bulk revoke = %d err=%v, want 3", revoked, err)
	}
	count, err = st.CountActiveBridgeTokensForGiteaUser(ctx, 9, now)
	if err != nil || count != 0 {
		t.Fatalf("count after bulk revoke = %d err=%v", count, err)
	}
}

func TestPATCredentialLifecycle(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	gen1, name1, err := st.ReservePATCredential(ctx, 100, "npub1user", "grasp-bridge", []string{"write:repository"}, now)
	if err != nil {
		t.Fatalf("reserve gen1: %v", err)
	}
	if gen1 != 1 || name1 != "grasp-bridge-100-1" {
		t.Fatalf("reservation = (%d, %q), want (1, grasp-bridge-100-1)", gen1, name1)
	}

	if _, err := st.GetActivePATCredential(ctx, 100); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("provisioning PAT visible as active: %v", err)
	}
	// Activation before finalization must fail: the row has no ciphertext yet.
	if err := st.ActivatePATCredential(ctx, 100, gen1, now); err == nil {
		t.Fatal("unfinalized PAT activated")
	}
	if err := st.FinalizePATCredential(ctx, 100, gen1, 4242, []byte{1, 2, 3}, "k1"); err != nil {
		t.Fatalf("finalize gen1: %v", err)
	}
	if err := st.ActivatePATCredential(ctx, 100, gen1, now); err != nil {
		t.Fatalf("activate gen1: %v", err)
	}
	active, err := st.GetActivePATCredential(ctx, 100)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.Generation != 1 || active.State != PATStateActive || active.PATName != "grasp-bridge-100-1" || active.GiteaTokenID != 4242 {
		t.Fatalf("active = %+v", active)
	}

	// Create-before-retire rotation: generation 2 becomes active, 1 retiring.
	gen2, name2, err := st.ReservePATCredential(ctx, 100, "npub1user", "grasp-bridge", []string{"write:repository"}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("reserve gen2: %v", err)
	}
	if gen2 != 2 || name2 != "grasp-bridge-100-2" {
		t.Fatalf("reservation = (%d, %q), want (2, grasp-bridge-100-2)", gen2, name2)
	}
	if err := st.FinalizePATCredential(ctx, 100, gen2, 4243, []byte{4, 5, 6}, "k1"); err != nil {
		t.Fatalf("finalize gen2: %v", err)
	}
	if err := st.ActivatePATCredential(ctx, 100, gen2, now.Add(time.Minute)); err != nil {
		t.Fatalf("activate gen2: %v", err)
	}
	active, err = st.GetActivePATCredential(ctx, 100)
	if err != nil || active.Generation != 2 {
		t.Fatalf("active after rotation = %+v err=%v", active, err)
	}
	retiring, err := st.ListPATCredentialsByState(ctx, PATStateRetiring, 10)
	if err != nil || len(retiring) != 1 || retiring[0].Generation != 1 {
		t.Fatalf("retiring = %+v err=%v", retiring, err)
	}
	pending, err := st.ListPATCredentialsPendingDeletion(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Generation != 1 || pending[0].GiteaTokenID != 4242 {
		t.Fatalf("pending deletion = %+v err=%v", pending, err)
	}

	if err := st.RecordPATDeleteFailure(ctx, 100, 1, "gitea unavailable"); err != nil {
		t.Fatalf("record delete failure: %v", err)
	}
	if err := st.MarkPATCredentialRetired(ctx, 100, 1, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("mark retired: %v", err)
	}
	// A completed retirement leaves the pending-deletion queue.
	pending, err = st.ListPATCredentialsPendingDeletion(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after retirement = %+v err=%v (reconciliation would re-delete)", pending, err)
	}
	retired, err := st.ListPATCredentialsByState(ctx, PATStateRetiring, 10)
	if err != nil || len(retired) != 1 {
		t.Fatalf("retired list = %+v err=%v", retired, err)
	}
	if retired[0].RetiredAt.IsZero() || retired[0].DeleteAttempts != 1 {
		t.Fatalf("retired row = %+v", retired[0])
	}

	if err := st.SetPATCredentialState(ctx, 100, 2, PATStateOrphaned, "user deleted"); err != nil {
		t.Fatalf("orphan: %v", err)
	}
	if _, err := st.GetActivePATCredential(ctx, 100); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("orphaned PAT still active")
	}
}

func TestPATSingleActiveEnforced(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 1; i <= 2; i++ {
		gen, _, err := st.ReservePATCredential(ctx, 7, "u7", "pat", []string{"write:repository"}, now)
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		if err := st.FinalizePATCredential(ctx, 7, gen, int64(i), []byte{byte(i)}, "k1"); err != nil {
			t.Fatalf("finalize %d: %v", i, err)
		}
	}
	if err := st.ActivatePATCredential(ctx, 7, 1, now); err != nil {
		t.Fatalf("activate 1: %v", err)
	}
	// Forcing a second concurrent active row must violate the partial index.
	if err := st.SetPATCredentialState(ctx, 7, 2, PATStateActive, ""); err == nil {
		t.Fatal("two active PATs accepted for one user")
	}
}

func TestReservePATCredentialConcurrentGenerations(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const workers = 8
	var wg sync.WaitGroup
	gens := make([]int64, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			gens[i], _, errs[i] = st.ReservePATCredential(ctx, 55, "u55", "pat", []string{"write:repository"}, now)
		}(i)
	}
	wg.Wait()

	seen := map[int64]bool{}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if seen[gens[i]] {
			t.Fatalf("generation %d assigned twice", gens[i])
		}
		seen[gens[i]] = true
	}
}

func TestClaimNIP98EventReplay(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	hash := sha256.Sum256([]byte("GET|https://example.com/auth/tokens"))

	ok, err := st.ClaimNIP98Event(ctx, "ev1", "pk", "GET", hash[:], now, now.Add(5*time.Minute))
	if err != nil || !ok {
		t.Fatalf("first claim ok=%v err=%v", ok, err)
	}
	ok, err = st.ClaimNIP98Event(ctx, "ev1", "pk", "GET", hash[:], now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("replay claim err: %v", err)
	}
	if ok {
		t.Fatal("replayed event id claimed twice")
	}

	deleted, err := st.CleanupExpiredReplayClaims(ctx, now.Add(10*time.Minute))
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup = %d err=%v, want 1", deleted, err)
	}
	ok, err = st.ClaimNIP98Event(ctx, "ev1", "pk", "GET", hash[:], now, now.Add(5*time.Minute))
	if err != nil || !ok {
		t.Fatalf("reclaim after cleanup ok=%v err=%v (freshness window guards replay)", ok, err)
	}
}

func TestAuthAuditEvents(t *testing.T) {
	st := openAuthTokenTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := st.InsertAuthAuditEvent(ctx, AuthAuditEvent{
		OccurredAt:  now.Add(-100 * 24 * time.Hour),
		EventType:   "token_mint",
		Pubkey:      "pk",
		TokenID:     "tok",
		GiteaUserID: 3,
		Surface:     "git",
		Action:      "write",
		Outcome:     "success",
	}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := st.InsertAuthAuditEvent(ctx, AuthAuditEvent{
		OccurredAt: now,
		EventType:  "token_revoke",
		Pubkey:     "pk",
		Outcome:    "success",
	}); err != nil {
		t.Fatalf("insert new: %v", err)
	}

	deleted, err := st.CleanupAuthAuditEvents(ctx, now.Add(-90*24*time.Hour))
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup = %d err=%v, want 1", deleted, err)
	}
}

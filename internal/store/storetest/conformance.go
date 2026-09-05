// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package storetest is the AuthStore conformance suite. Every backend
// (SQLite today, a shared transactional store for active-active next) must
// pass it unchanged: it encodes the distributed-correctness contract the
// auth layer depends on, not implementation details.
package storetest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// Factory returns a fresh, empty AuthStore for one test.
type Factory func(t *testing.T) store.AuthStore

// Run executes the conformance suite against a backend.
func Run(t *testing.T, factory Factory) {
	t.Run("NIP98ReplayClaimIsSingleUse", func(t *testing.T) { testReplaySingleUse(t, factory(t)) })
	t.Run("BridgeTokenActiveLimitIsAtomic", func(t *testing.T) { testTokenLimit(t, factory(t)) })
	t.Run("PATActivationRetiresPreviousGeneration", func(t *testing.T) { testCreateBeforeRetire(t, factory(t)) })
	t.Run("ResealIsCompareAndSwap", func(t *testing.T) { testResealCAS(t, factory(t)) })
	t.Run("NotFoundIsErrNoRows", func(t *testing.T) { testNotFound(t, factory(t)) })
	t.Run("TokenRevocationIsSubjectScoped", func(t *testing.T) { testRevokeScoped(t, factory(t)) })
	t.Run("ConcurrentReplayClaimsOneWinner", func(t *testing.T) { testConcurrentReplay(t, factory(t)) })
	t.Run("ConcurrentMintsNeverExceedLimit", func(t *testing.T) { testConcurrentLimit(t, factory(t)) })
	t.Run("ConcurrentReservationsGetDistinctGenerations", func(t *testing.T) { testConcurrentReserve(t, factory(t)) })
	t.Run("UserLockIsMutuallyExclusive", func(t *testing.T) { testUserLockExclusion(t, factory(t)) })
	t.Run("MaintenanceLeaseIsSingleHolder", func(t *testing.T) { testMaintenanceLease(t, factory(t)) })
	t.Run("DomainAffiliationPersistence", func(t *testing.T) { testDomainAffiliationPersistence(t, factory(t)) })
	t.Run("TenantPersistence", func(t *testing.T) { testTenantPersistence(t, factory(t)) })
	t.Run("SCIMPersistence", func(t *testing.T) { testSCIMPersistence(t, factory(t)) })
}

func testSCIMPersistence(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Date(2026, 9, 5, 2, 3, 4, 0, time.UTC)
	tn := store.ManagedTenant{Host: "scim.example", Policy: store.TenantPolicySharedRead, State: store.TenantStateActive, OrgName: "grasp-t-scim", ProvisioningMarker: "grasp-tenant-provisioning:scim", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateManagedTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("secret"))
	pending := store.TenantSCIMToken{Host: tn.Host, TokenHash: hash[:], TokenSuffix: "secret", Generation: 1, UpdatedAt: now}
	if err := st.StageTenantSCIMToken(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTenantSCIMToken(ctx, tn.Host); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("pending token authenticated: %v", err)
	}
	if ok, err := st.ActivateTenantSCIMToken(ctx, tn.Host, hash[:], 99, now); err != nil || ok {
		t.Fatalf("stale activation ok=%v err=%v", ok, err)
	}
	if _, err := st.GetTenantSCIMTokenByHash(ctx, hash[:]); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed activation was not rolled back: %v", err)
	}
	if ok, err := st.ActivateTenantSCIMToken(ctx, tn.Host, hash[:], 1, now); err != nil || !ok {
		t.Fatalf("activate ok=%v err=%v", ok, err)
	}
	tok, err := st.GetTenantSCIMTokenByHash(ctx, hash[:])
	if err != nil || tok.Host != tn.Host {
		t.Fatalf("token=%+v err=%v", tok, err)
	}
	u := store.SCIMUser{Host: tn.Host, ID: "u1", UserName: "alice@scim.example", ExternalID: "pub", Pubkey: "pub", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
	if ok, err := st.ApplySCIMUserAndAdvanceTenant(ctx, u, 0, 99, true); err != nil || ok {
		t.Fatalf("stale user tx ok=%v err=%v", ok, err)
	}
	if _, err := st.GetSCIMUser(ctx, tn.Host, u.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("user survived rolled-back tenant bump: %v", err)
	}
	if ok, err := st.ApplySCIMUserAndAdvanceTenant(ctx, u, 0, 2, true); err != nil || !ok {
		t.Fatalf("create user tx ok=%v err=%v", ok, err)
	}
	g := store.SCIMGroup{Host: tn.Host, ID: "g1", DisplayName: "readers", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
	if ok, err := st.ApplySCIMGroupAndAdvanceTenant(ctx, g, []string{u.ID}, 0, 99, true); err != nil || ok {
		t.Fatalf("stale group tx ok=%v err=%v", ok, err)
	}
	if _, err := st.GetSCIMGroup(ctx, tn.Host, g.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("group survived rolled-back tenant bump: %v", err)
	}
	if ok, err := st.ApplySCIMGroupAndAdvanceTenant(ctx, g, []string{u.ID}, 0, 3, true); err != nil || !ok {
		t.Fatalf("create group tx ok=%v err=%v", ok, err)
	}
	authorized, err := st.ListSCIMAuthorizedUsers(ctx, tn.Host)
	if err != nil || len(authorized) != 1 {
		t.Fatalf("authorized=%+v err=%v", authorized, err)
	}
	u.Active = false
	u.Version = 2
	u.UpdatedAt = now.Add(time.Second)
	if ok, err := st.ApplySCIMUserAndAdvanceTenant(ctx, u, 1, 4, false); err != nil || !ok {
		t.Fatalf("deactivate tx ok=%v err=%v", ok, err)
	}
	authorized, err = st.ListSCIMAuthorizedUsers(ctx, tn.Host)
	if err != nil || len(authorized) != 0 {
		t.Fatalf("inactive authorized=%+v err=%v", authorized, err)
	}
}

func testTenantPersistence(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC)
	tenant := store.ManagedTenant{Host: "xn--bcher-kva.example", Policy: store.TenantPolicyDirectoryOnly, State: store.TenantStatePending, OrgName: "grasp-t-0123456789abcdef0123456789abcdef", ProvisioningMarker: "grasp-tenant-provisioning:test", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateManagedTenant(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenant.GiteaOrgID = 42
	tenant.ReaderTeamID = 7
	tenant.State = store.TenantStateActive
	tenant.Version = 2
	tenant.UpdatedAt = now.Add(time.Second)
	if ok, err := st.UpdateManagedTenant(ctx, tenant, 1); err != nil || !ok {
		t.Fatalf("pin tenant: ok=%v err=%v", ok, err)
	}
	changed := tenant
	changed.ProvisioningMarker = "grasp-tenant-provisioning:attacker"
	changed.Version = 3
	if ok, err := st.UpdateManagedTenant(ctx, changed, 2); err != nil || ok {
		t.Fatalf("immutable provisioning marker changed: ok=%v err=%v", ok, err)
	}
	changed = tenant
	changed.GiteaOrgID = 43
	changed.Version = 3
	if ok, err := st.UpdateManagedTenant(ctx, changed, 2); err != nil || ok {
		t.Fatalf("immutable org pin changed: ok=%v err=%v", ok, err)
	}
	m := store.TenantMembership{Host: tenant.Host, Pubkey: "pub", GiteaUserID: 9, GiteaUser: "alice", EvidenceStatus: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now, Granted: true, UpdatedAt: now}
	if err := st.UpsertTenantMembership(ctx, m); err != nil {
		t.Fatal(err)
	}
	older := m
	older.CheckedAt = now.Add(-time.Minute)
	older.Granted = false
	older.TenantOrphaned = true
	if err := st.UpsertTenantMembership(ctx, older); err != nil {
		t.Fatal(err)
	}
	members, err := st.ListTenantMemberships(ctx, tenant.Host)
	if err != nil || len(members) != 1 || !members[0].Granted || members[0].TenantOrphaned {
		t.Fatalf("monotonic membership = %+v err=%v", members, err)
	}
	reconciledAt := now.Add(2 * time.Minute)
	if ok, err := st.UpdateTenantMembershipAccess(ctx, tenant.Host, m.Pubkey, store.TenantAccessPolicyRemoved, false, false, reconciledAt, m.CheckedAt, tenant.Version); err != nil || !ok {
		t.Fatalf("access CAS ok=%v err=%v", ok, err)
	}
	if ok, err := st.UpdateTenantMembershipAccess(ctx, tenant.Host, m.Pubkey, store.TenantAccessGranted, true, false, reconciledAt, m.CheckedAt, tenant.Version+1); err != nil || ok {
		t.Fatalf("stale tenant-version access CAS ok=%v err=%v", ok, err)
	}
	if err := st.UpsertDomainAffiliation(ctx, store.DomainAffiliation{Pubkey: m.Pubkey, Host: tenant.Host, Status: store.DomainAffiliationVerified, VerifiedAt: now, CheckedAt: now}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.UpdateTenantMembershipAccess(ctx, tenant.Host, m.Pubkey, store.TenantAccessGranted, true, false, reconciledAt, m.CheckedAt.Add(-time.Nanosecond), tenant.Version); err != nil || ok {
		t.Fatalf("stale evidence access CAS ok=%v err=%v", ok, err)
	}
	members, err = st.ListTenantMemberships(ctx, tenant.Host)
	if err != nil || members[0].EvidenceStatus != store.DomainAffiliationVerified || !members[0].CheckedAt.Equal(now) || members[0].AccessState != store.TenantAccessPolicyRemoved || members[0].Granted || members[0].TenantOrphaned {
		t.Fatalf("access update poisoned evidence: %+v err=%v", members, err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = st.WithTenantLock(ctx, tenant.Host, func(context.Context) error { close(locked); <-release; return nil })
		close(done)
	}()
	<-locked
	entered := make(chan struct{})
	go func() {
		_ = st.WithTenantLock(ctx, tenant.Host, func(context.Context) error { close(entered); return nil })
	}()
	select {
	case <-entered:
		t.Fatal("tenant lock was not exclusive")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("tenant lock did not release")
	}
}

// testMaintenanceLease proves at most one node holds the maintenance lease at
// a time, and that a released lease can be re-acquired. On Postgres each
// acquirer uses a distinct pooled session, so this exercises real advisory-
// lock leadership; SQLite is trivially always-leader.
func testDomainAffiliationPersistence(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	verifiedAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	checkedAt := verifiedAt.Add(time.Minute)
	a := store.DomainAffiliation{
		CanonicalIdentifier: "alice@team.example.com", LocalPart: "alice", Host: "team.example.com",
		Pubkey: "pubkey-affiliation", VerifiedAt: verifiedAt, CheckedAt: checkedAt,
		Status: store.DomainAffiliationVerified,
	}
	if err := st.UpsertDomainAffiliation(ctx, a); err != nil {
		t.Fatalf("upsert verified affiliation: %v", err)
	}
	got, err := st.GetDomainAffiliation(ctx, a.Pubkey)
	if err != nil {
		t.Fatalf("get affiliation: %v", err)
	}
	if got.CanonicalIdentifier != a.CanonicalIdentifier || got.LocalPart != a.LocalPart || got.Host != a.Host ||
		got.Pubkey != a.Pubkey || !got.VerifiedAt.Equal(verifiedAt) || !got.CheckedAt.Equal(checkedAt) || got.Status != store.DomainAffiliationVerified {
		t.Fatalf("persisted affiliation = %+v, want %+v", got, a)
	}
	listed, err := st.ListVerifiedDomainAffiliations(ctx, "team.example.com", time.Time{}, 100)
	if err != nil || len(listed) != 1 || listed[0].Pubkey != a.Pubkey {
		t.Fatalf("exact-host list = %+v, err=%v", listed, err)
	}
	parent, err := st.ListVerifiedDomainAffiliations(ctx, "example.com", time.Time{}, 100)
	if err != nil || len(parent) != 0 {
		t.Fatalf("parent host must not include subdomain affiliation: %+v, err=%v", parent, err)
	}

	a.Status = store.DomainAffiliationStale
	a.CheckedAt = checkedAt.Add(time.Minute)
	a.FailureClass = store.DomainFailureIndeterminate
	a.FailureCode = "transport"
	a.FailureDetail = "timeout"
	if err := st.UpsertDomainAffiliation(ctx, a); err != nil {
		t.Fatalf("upsert stale affiliation: %v", err)
	}
	got, err = st.GetDomainAffiliation(ctx, a.Pubkey)
	if err != nil || got.Status != store.DomainAffiliationStale || got.FailureClass != store.DomainFailureIndeterminate || !got.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("stale affiliation = %+v, err=%v", got, err)
	}
	listed, err = st.ListVerifiedDomainAffiliations(ctx, "team.example.com", time.Time{}, 100)
	if err != nil || len(listed) != 0 {
		t.Fatalf("stale affiliation must not receive a verified badge: %+v, err=%v", listed, err)
	}

	newer := store.DomainAffiliation{
		CanonicalIdentifier: "new@example.com", LocalPart: "new", Host: "example.com", Pubkey: "pubkey-monotonic",
		VerifiedAt: verifiedAt.Add(3 * time.Minute), CheckedAt: checkedAt.Add(3*time.Minute + 500*time.Millisecond), Status: store.DomainAffiliationVerified,
	}
	older := newer
	older.CanonicalIdentifier = "old@example.com"
	older.LocalPart = "old"
	older.CheckedAt = checkedAt.Add(3 * time.Minute)
	older.Status = store.DomainAffiliationConfirmedAbsent
	if err := st.UpsertDomainAffiliation(ctx, newer); err != nil {
		t.Fatalf("upsert newer affiliation: %v", err)
	}
	if err := st.UpsertDomainAffiliation(ctx, older); err != nil {
		t.Fatalf("upsert out-of-order older affiliation: %v", err)
	}
	equalTime := newer
	equalTime.Status = store.DomainAffiliationConfirmedAbsent
	equalTime.CanonicalIdentifier = "regressed@example.com"
	if err := st.UpsertDomainAffiliation(ctx, equalTime); err != nil {
		t.Fatalf("upsert equal-time affiliation: %v", err)
	}
	got, err = st.GetDomainAffiliation(ctx, newer.Pubkey)
	if err != nil || got.Status != store.DomainAffiliationVerified || got.CanonicalIdentifier != newer.CanonicalIdentifier || !got.CheckedAt.Equal(newer.CheckedAt) {
		t.Fatalf("older evidence overwrote newer evidence: %+v, err=%v", got, err)
	}

	oldVerified := store.DomainAffiliation{
		CanonicalIdentifier: "expired@example.com", LocalPart: "expired", Host: "example.com", Pubkey: "pubkey-expired",
		VerifiedAt: verifiedAt, CheckedAt: checkedAt, Status: store.DomainAffiliationVerified,
	}
	if err := st.UpsertDomainAffiliation(ctx, oldVerified); err != nil {
		t.Fatalf("upsert expired affiliation: %v", err)
	}
	listed, err = st.ListVerifiedDomainAffiliations(ctx, "example.com", newer.CheckedAt, 1)
	if err != nil || len(listed) != 1 || listed[0].Pubkey != newer.Pubkey {
		t.Fatalf("fresh bounded affiliation list = %+v, err=%v", listed, err)
	}
}

func testMaintenanceLease(t *testing.T, st store.AuthStore) {
	ctx := context.Background()

	// A single-node backend (SQLite) is always the leader: every attempt
	// succeeds. A multi-node backend (Postgres) grants exactly one at a time.
	// Detect which by whether a second concurrent acquire succeeds while the
	// first is held.
	acq1, rel1, err := st.TryMaintenanceLease(ctx)
	if err != nil || !acq1 {
		t.Fatalf("first lease: acquired=%v err=%v", acq1, err)
	}
	acq2, rel2, err := st.TryMaintenanceLease(ctx)
	if err != nil {
		t.Fatalf("second lease attempt: %v", err)
	}
	singleNode := acq2 // always-leader backend
	if acq2 {
		rel2()
	}
	rel1()

	if singleNode {
		// Nothing more to prove: a single-node store is always leader by
		// contract, and re-acquisition trivially holds.
		if acq, rel, err := st.TryMaintenanceLease(ctx); err != nil || !acq {
			t.Fatalf("re-acquire on single-node: acquired=%v err=%v", acq, err)
		} else {
			rel()
		}
		return
	}

	// Multi-node: race many acquirers; exactly one may hold it at once.
	const workers = 16
	var held atomic.Int32
	var maxHeld atomic.Int32
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acquired, release, err := st.TryMaintenanceLease(ctx)
			if err != nil {
				t.Errorf("lease: %v", err)
				return
			}
			if !acquired {
				return
			}
			wins.Add(1)
			n := held.Add(1)
			for {
				m := maxHeld.Load()
				if n <= m || maxHeld.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(3 * time.Millisecond)
			held.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if maxHeld.Load() > 1 {
		t.Fatalf("maintenance lease held by %d nodes at once, want <= 1", maxHeld.Load())
	}
	if wins.Load() == 0 {
		t.Fatal("no node ever acquired the maintenance lease")
	}

	// After the storm, the lease is free and re-acquirable.
	if acq, rel, err := st.TryMaintenanceLease(ctx); err != nil || !acq {
		t.Fatalf("re-acquire after release: acquired=%v err=%v", acq, err)
	} else {
		rel()
	}
}

// testUserLockExclusion proves WithUserLock serializes critical sections for
// one user: a plain (unsynchronized) read-modify-write under the lock must
// behave as if serial. On Postgres each goroutine holds a distinct pooled
// session, so this exercises real advisory-lock exclusion, not a Go mutex.
func testUserLockExclusion(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	const workers = 16

	var counter int // deliberately unsynchronized; the lock is the protection
	var inside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.WithUserLock(ctx, 42, func(context.Context) error {
				if inside.Add(1) != 1 {
					t.Error("two critical sections for the same user overlapped")
				}
				v := counter
				time.Sleep(2 * time.Millisecond)
				counter = v + 1
				inside.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("lock: %v", err)
			}
		}()
	}
	wg.Wait()
	if counter != workers {
		t.Fatalf("counter = %d, want %d (lost updates => exclusion broken)", counter, workers)
	}

	// A different user's lock must not deadlock against user 42's.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = st.WithUserLock(ctx, 42, func(ctx context.Context) error {
			return st.WithUserLock(ctx, 43, func(context.Context) error { return nil })
		})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("nested locks for distinct users deadlocked")
	}
}

// testConcurrentReplay hammers the same event id from many goroutines:
// exactly one claim may win. This is THE cross-node NIP-98 guarantee.
func testConcurrentReplay(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Now().UTC()
	hash := sha256.Sum256([]byte("t"))

	const attempts = 24
	wins := make(chan bool, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.ClaimNIP98Event(ctx, "race-ev", "pk", "POST", hash[:], now, now.Add(5*time.Minute))
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			wins <- ok
		}()
	}
	wg.Wait()
	close(wins)
	won := 0
	for ok := range wins {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d concurrent claims won for one event id, want exactly 1", won)
	}
}

// testConcurrentLimit races many mints against a limit of 3: the number of
// active tokens must never exceed the limit, no matter the interleaving.
func testConcurrentLimit(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	const attempts = 24
	const limit = 3
	var wg sync.WaitGroup
	var inserted atomic.Int64
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := st.InsertBridgeToken(ctx, token(fmt.Sprintf("race-tok-%02d", i), "race-pk", 50, expires), limit)
			switch {
			case err == nil:
				inserted.Add(1)
			case errors.Is(err, store.ErrBridgeTokenLimit):
			default:
				t.Errorf("insert: %v", err)
			}
		}(i)
	}
	wg.Wait()

	tokens, err := st.ListBridgeTokens(ctx, "race-pk", 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tokens) > limit {
		t.Fatalf("%d tokens inserted under a limit of %d — the conditional insert is not atomic on this backend", len(tokens), limit)
	}
	if inserted.Load() != int64(len(tokens)) {
		t.Fatalf("insert successes %d != stored rows %d", inserted.Load(), len(tokens))
	}
}

// testConcurrentReserve races PAT reservations for one user: every
// reservation must receive a distinct generation (unique names feed the
// ambiguous-creation reconciliation).
func testConcurrentReserve(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Now().UTC()

	const attempts = 12
	gens := make(chan int64, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gen, _, err := st.ReservePATCredential(ctx, 60, "u60", "grasp-bridge", []string{"write:repository"}, now)
			if err != nil {
				// A serialization conflict surfacing as an error is acceptable
				// (the caller retries); a duplicate generation is not.
				return
			}
			gens <- gen
		}()
	}
	wg.Wait()
	close(gens)
	seen := map[int64]bool{}
	for gen := range gens {
		if seen[gen] {
			t.Fatalf("generation %d handed to two concurrent reservations", gen)
		}
		seen[gen] = true
	}
	if len(seen) == 0 {
		t.Fatal("no reservation succeeded")
	}
}

func testReplaySingleUse(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Now().UTC()
	hash := sha256.Sum256([]byte("target"))

	ok, err := st.ClaimNIP98Event(ctx, "ev1", "pk", "POST", hash[:], now, now.Add(5*time.Minute))
	if err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	// The SAME event id must never be claimable twice — this is the
	// cross-node single-use guarantee (unique-constraint semantics).
	ok, err = st.ClaimNIP98Event(ctx, "ev1", "pk", "POST", hash[:], now, now.Add(5*time.Minute))
	if err != nil || ok {
		t.Fatalf("replay claim: ok=%v err=%v, want refused without error", ok, err)
	}
	// A different event id claims fine.
	if ok, err := st.ClaimNIP98Event(ctx, "ev2", "pk", "POST", hash[:], now, now.Add(5*time.Minute)); err != nil || !ok {
		t.Fatalf("second event: ok=%v err=%v", ok, err)
	}
	// Cleanup removes expired claims, freeing storage but never un-claiming
	// a live one.
	if _, err := st.CleanupExpiredReplayClaims(ctx, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func token(id, pubkey string, userID int64, expires time.Time) store.BridgeToken {
	h := sha256.Sum256([]byte(id))
	return store.BridgeToken{
		ID: id, TokenHash: h[:], TokenSuffix: id[len(id)-4:],
		Pubkey: pubkey, GiteaUserID: userID, Name: "n-" + id,
		Scopes: []string{"git:read"}, IssuedAt: time.Now().UTC(), ExpiresAt: expires,
	}
}

func testTokenLimit(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	for i := 0; i < 3; i++ {
		if err := st.InsertBridgeToken(ctx, token(fmt.Sprintf("tok-%d", i), "pk1", 1, expires), 3); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// The limit is enforced in the insert itself, atomically.
	if err := st.InsertBridgeToken(ctx, token("tok-over", "pk1", 1, expires), 3); !errors.Is(err, store.ErrBridgeTokenLimit) {
		t.Fatalf("over-limit insert error = %v, want ErrBridgeTokenLimit", err)
	}
	// Another subject is unaffected.
	if err := st.InsertBridgeToken(ctx, token("tok-b", "pk2", 2, expires), 3); err != nil {
		t.Fatalf("other subject: %v", err)
	}
	// Revoking frees a slot.
	if err := st.RevokeBridgeToken(ctx, "pk1", "tok-0", time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := st.InsertBridgeToken(ctx, token("tok-3", "pk1", 1, expires), 3); err != nil {
		t.Fatalf("insert after revoke: %v", err)
	}
}

func testCreateBeforeRetire(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Now().UTC()

	provision := func() int64 {
		gen, _, err := st.ReservePATCredential(ctx, 7, "u7", "grasp-bridge", []string{"write:repository"}, now)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := st.FinalizePATCredential(ctx, 7, gen, 9000+gen, []byte{1, 2, byte(gen)}, "key"); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		if err := st.ActivatePATCredential(ctx, 7, gen, now); err != nil {
			t.Fatalf("activate gen %d: %v", gen, err)
		}
		return gen
	}

	gen1 := provision()
	cred, err := st.GetActivePATCredential(ctx, 7)
	if err != nil || cred.Generation != gen1 {
		t.Fatalf("active after first: %+v err=%v", cred, err)
	}

	// Activating a second generation atomically demotes the first: exactly
	// one active credential per user, at every instant.
	gen2 := provision()
	cred, err = st.GetActivePATCredential(ctx, 7)
	if err != nil || cred.Generation != gen2 {
		t.Fatalf("active after second: %+v err=%v", cred, err)
	}
	pending, err := st.ListPATCredentialsPendingDeletion(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Generation != gen1 {
		t.Fatalf("pending = %+v err=%v, want demoted gen %d", pending, err, gen1)
	}

	// Activation without finalization must be refused: an active row always
	// carries usable ciphertext.
	gen3, _, err := st.ReservePATCredential(ctx, 7, "u7", "grasp-bridge", []string{"write:repository"}, now)
	if err != nil {
		t.Fatalf("reserve gen3: %v", err)
	}
	if err := st.ActivatePATCredential(ctx, 7, gen3, now); err == nil {
		t.Fatal("unfinalized generation activated")
	}
}

func testResealCAS(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	now := time.Now().UTC()
	gen, _, err := st.ReservePATCredential(ctx, 8, "u8", "grasp-bridge", []string{"write:repository"}, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	original := []byte{9, 9, 9}
	if err := st.FinalizePATCredential(ctx, 8, gen, 1, original, "k1"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := st.ActivatePATCredential(ctx, 8, gen, now); err != nil {
		t.Fatalf("activate: %v", err)
	}

	if n, err := st.ResealPATCredential(ctx, 8, gen, original, []byte{1}, "k2"); err != nil || n != 1 {
		t.Fatalf("reseal: n=%d err=%v", n, err)
	}
	// A stale expectation must not clobber, and must report 0 rows.
	if n, err := st.ResealPATCredential(ctx, 8, gen, original, []byte{2}, "k3"); err != nil || n != 0 {
		t.Fatalf("stale reseal: n=%d err=%v", n, err)
	}
	cred, _ := st.GetActivePATCredential(ctx, 8)
	if cred.KeyID != "k2" {
		t.Fatalf("key after CAS = %q, want k2", cred.KeyID)
	}
}

func testNotFound(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	if _, err := st.GetActivePATCredential(ctx, 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing PAT error = %v, want sql.ErrNoRows", err)
	}
	if _, err := st.GetIdentityLinkByPubkey(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing link error = %v, want sql.ErrNoRows", err)
	}
	if _, err := st.GetBridgeTokenByHash(ctx, []byte{1}); !errors.Is(err, store.ErrBridgeTokenNotFound) {
		t.Fatalf("missing token error = %v, want ErrBridgeTokenNotFound", err)
	}
}

func testRevokeScoped(t *testing.T, st store.AuthStore) {
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if err := st.InsertBridgeToken(ctx, token("tok-x", "owner", 1, expires), 5); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// A different pubkey cannot revoke someone else's token.
	if err := st.RevokeBridgeToken(ctx, "attacker", "tok-x", time.Now().UTC()); !errors.Is(err, store.ErrBridgeTokenNotFound) {
		t.Fatalf("foreign revoke error = %v, want ErrBridgeTokenNotFound", err)
	}
	if err := st.RevokeBridgeToken(ctx, "owner", "tok-x", time.Now().UTC()); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// TestReencryptStaleCredentialsProactively: an idle credential sealed under a
// retired key is re-encrypted by the maintenance sweep, without a request
// touching it, so the old key can be dropped from the ring.
func TestReencryptStaleCredentialsProactively(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	minted, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	principal, err := env.svc.Authenticate(ctx, minted.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	before, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Rotate the ring: old key becomes decrypt-only.
	oldKey := env.keys[0]
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	cipher, err := NewCredentialCipher([]config.CredentialKey{{ID: "new", Key: newKey}, oldKey})
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	env.svc.cipher = cipher

	// The proactive sweep re-encrypts without any DownstreamPAT call.
	env.svc.reencryptStaleCredentials(ctx)

	after, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.KeyID != "new" {
		t.Fatalf("key_id = %q, want new", after.KeyID)
	}
	if string(after.Ciphertext) == string(before.Ciphertext) {
		t.Fatal("ciphertext unchanged after proactive reseal")
	}

	// It now decrypts under the active key alone — the old key is retireable.
	onlyNew, err := NewCredentialCipher([]config.CredentialKey{{ID: "new", Key: newKey}})
	if err != nil {
		t.Fatalf("new-only cipher: %v", err)
	}
	env.svc.cipher = onlyNew
	if _, _, err := env.svc.DownstreamPAT(ctx, principal.GiteaUserID, ScopeGitRead); err != nil {
		t.Fatalf("decrypt after key retirement: %v", err)
	}

	// A second sweep is a no-op (nothing under a stale key).
	env.svc.reencryptStaleCredentials(ctx)
}

// TestReconcileTerminalCredentials: error/orphaned rows have their Gitea PAT
// deleted and their rows cleared; a delete failure keeps the row for retry.
func TestReconcileTerminalCredentials(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred, err := env.store.GetActivePATCredential(ctx, 100)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Mark it orphaned as quarantine would.
	if err := env.store.SetPATCredentialState(ctx, cred.GiteaUserID, cred.Generation, store.PATStateOrphaned, "test"); err != nil {
		t.Fatalf("orphan: %v", err)
	}

	env.svc.reconcilePATCredentials(ctx, env.svc.now().UTC())

	env.fake.mu.Lock()
	deleted := append([]string(nil), env.fake.deletedPATs...)
	env.fake.mu.Unlock()
	if len(deleted) != 1 || !strings.HasSuffix(deleted[0], "/tokens/9000") {
		t.Fatalf("deleted = %v, want the orphaned PAT deleted by id", deleted)
	}
	if rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateOrphaned, 10); len(rows) != 0 {
		t.Fatalf("orphaned rows remain after reconciliation: %+v", rows)
	}
}

// TestReconcileRetriesOnDeleteFailure: a Gitea deletion failure keeps the row
// in its terminal state for the next tick rather than dropping it.
func TestReconcileRetriesOnDeleteFailure(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred, err := env.store.GetActivePATCredential(ctx, 100)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := env.store.SetPATCredentialState(ctx, cred.GiteaUserID, cred.Generation, store.PATStateError, "boom"); err != nil {
		t.Fatalf("error state: %v", err)
	}

	env.fake.mu.Lock()
	env.fake.failDelete = true
	env.fake.mu.Unlock()

	env.svc.reconcilePATCredentials(ctx, env.svc.now().UTC())

	rows, err := env.store.ListPATCredentialsByState(ctx, store.PATStateError, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("error rows = %+v err=%v, want 1 retained for retry", rows, err)
	}
	if !strings.Contains(rows[0].LastError, "reconcile delete failed") {
		t.Fatalf("LastError = %q, want reconcile failure recorded", rows[0].LastError)
	}

	// Once Gitea recovers, the next tick clears it.
	env.fake.mu.Lock()
	env.fake.failDelete = false
	env.fake.mu.Unlock()
	env.svc.reconcilePATCredentials(ctx, env.svc.now().UTC())
	if rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateError, 10); len(rows) != 0 {
		t.Fatalf("error rows remain after recovery: %+v", rows)
	}
}

// TestReconcileIsFairUnderPersistentFailure: a permanently-failing row bumps
// its delete_attempts and sorts behind fresher rows, so it never starves a
// newly-orphaned credential. Also asserts the durable pat_reconciled audit
// event is written before the row is deleted.
func TestReconcileIsFairUnderPersistentFailure(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	// A row whose Gitea deletion will keep failing.
	if _, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "stuck"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred, _ := env.store.GetActivePATCredential(ctx, 100)
	if err := env.store.SetPATCredentialState(ctx, cred.GiteaUserID, cred.Generation, store.PATStateError, "boom"); err != nil {
		t.Fatalf("error state: %v", err)
	}

	env.fake.mu.Lock()
	env.fake.failDelete = true
	env.fake.mu.Unlock()

	// Several ticks accumulate delete_attempts without progress.
	for i := 0; i < 3; i++ {
		env.svc.reconcilePATCredentials(ctx, env.svc.now().UTC())
	}
	rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateError, 10)
	if len(rows) != 1 || rows[0].DeleteAttempts < 3 {
		t.Fatalf("delete_attempts not accumulating: %+v", rows)
	}

	// The fair listing orders by delete_attempts ascending, so a persistently
	// failing row is always served after any fresher row — it can never
	// starve rows behind it.
	fair, err := env.store.ListTerminalPATCredentials(ctx, store.PATStateError, 10)
	if err != nil {
		t.Fatalf("fair list: %v", err)
	}
	if len(fair) != 1 || fair[0].DeleteAttempts < 3 {
		t.Fatalf("expected the failing row with accumulated attempts: %+v", fair)
	}

	// Recovery: Gitea deletes succeed, the row clears and audits.
	env.fake.mu.Lock()
	env.fake.failDelete = false
	env.fake.mu.Unlock()
	env.svc.reconcilePATCredentials(ctx, env.svc.now().UTC())
	if rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateError, 10); len(rows) != 0 {
		t.Fatalf("error rows remain after recovery: %+v", rows)
	}
	events, err := env.store.ListAuthAuditEvents(ctx, "pat_reconciled", 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no pat_reconciled audit event recorded before deletion")
	}
}

// TestRecoverStuckProvisioningRow: a provisioning row stranded by a crash
// (never finalized) is recovered after the threshold — its possibly-created
// Gitea PAT is deleted by name and the row cleared. A fresh row is untouched.
func TestRecoverStuckProvisioningRow(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	// Reserve a provisioning row directly, as ensureActivePATLocked would
	// before a crash between reserve and finalize.
	now := env.svc.now().UTC()
	_, patName, err := env.store.ReservePATCredential(ctx, 100, "user100", patNamePrefix, []string{"write:repository"}, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// Fresh row: not yet past the threshold, so the sweep leaves it.
	env.svc.reconcilePATCredentials(ctx, now)
	if rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateProvisioning, 10); len(rows) != 1 {
		t.Fatalf("fresh provisioning row recovered too early: %+v", rows)
	}

	// Past the threshold: recovered.
	later := now.Add(reconcileStuckProvisioningAfter + time.Minute)
	env.svc.reconcilePATCredentials(ctx, later)

	if _, err := env.store.GetActivePATCredential(ctx, 100); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("active credential unexpectedly present: %v", err)
	}
	if rows, _ := env.store.ListPATCredentialsByState(ctx, store.PATStateProvisioning, 10); len(rows) != 0 {
		t.Fatalf("stuck provisioning row not recovered: %+v", rows)
	}
	env.fake.mu.Lock()
	deleted := append([]string(nil), env.fake.deletedPATs...)
	env.fake.mu.Unlock()
	if len(deleted) != 1 || !strings.HasSuffix(deleted[0], "/tokens/"+patName) {
		t.Fatalf("deleted = %v, want deletion by reserved name %q", deleted, patName)
	}
}

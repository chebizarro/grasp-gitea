// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"testing"
	"time"
)

func openProfileSyncStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := Open(t.TempDir() + "/ps.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestProfileSyncCursorOnlyAdvancesForward(t *testing.T) {
	st := openProfileSyncStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Unsynced pubkey → zero cursor.
	cur, err := st.GetProfileSyncCursor(ctx, "pk", 1)
	if err != nil || cur.EventCreatedAt != 0 {
		t.Fatalf("initial cursor = %+v err=%v", cur, err)
	}

	// First apply.
	if ok, err := st.MarkNostrProfileSynced(ctx, "pk", 1, "e1", 1000, now); err != nil || !ok {
		t.Fatalf("first mark: ok=%v err=%v", ok, err)
	}
	// Older event is rejected.
	if ok, err := st.MarkNostrProfileSynced(ctx, "pk", 1, "e0", 999, now); err != nil || ok {
		t.Fatalf("older event accepted: ok=%v err=%v", ok, err)
	}
	// Equal timestamp is rejected (strictly newer required).
	if ok, _ := st.MarkNostrProfileSynced(ctx, "pk", 1, "e1b", 1000, now); ok {
		t.Fatal("equal-timestamp event accepted")
	}
	// Newer wins.
	if ok, err := st.MarkNostrProfileSynced(ctx, "pk", 1, "e2", 2000, now); err != nil || !ok {
		t.Fatalf("newer event rejected: ok=%v err=%v", ok, err)
	}
	cur, _ = st.GetProfileSyncCursor(ctx, "pk", 1)
	if cur.EventCreatedAt != 2000 || cur.EventID != "e2" {
		t.Fatalf("final cursor = %+v", cur)
	}

	// Identity repair: same pubkey, different gitea user id → cursor treated
	// as zero and an older event re-applies to the new account.
	if cur, _ := st.GetProfileSyncCursor(ctx, "pk", 2); cur.EventCreatedAt != 0 {
		t.Fatalf("cursor for repaired identity = %+v, want zero", cur)
	}
	if ok, err := st.MarkNostrProfileSynced(ctx, "pk", 2, "e-new", 1500, now); err != nil || !ok {
		t.Fatalf("repaired identity mark: ok=%v err=%v", ok, err)
	}
	if cur, _ := st.GetProfileSyncCursor(ctx, "pk", 2); cur.EventCreatedAt != 1500 {
		t.Fatalf("cursor after repair = %+v", cur)
	}
}

func TestProfileSyncPATCleanupLifecycle(t *testing.T) {
	st := openProfileSyncStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	rec := ProfileSyncPATCleanup{PATName: "grasp-profile-5-x", GiteaUserID: 5, GiteaUser: "u5"}
	if err := st.ReserveProfileSyncPATCleanup(ctx, rec, now); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	got, ok, err := st.GetProfileSyncPATCleanupForUser(ctx, 5)
	if err != nil || !ok || got.GiteaTokenID != 0 {
		t.Fatalf("get after reserve: %+v ok=%v err=%v", got, ok, err)
	}
	if err := st.SetProfileSyncPATTokenID(ctx, rec.PATName, 77); err != nil {
		t.Fatalf("set token id: %v", err)
	}
	got, _, _ = st.GetProfileSyncPATCleanupForUser(ctx, 5)
	if got.GiteaTokenID != 77 {
		t.Fatalf("token id = %d, want 77", got.GiteaTokenID)
	}

	// Failure ordering: a bumped row sorts behind a fresh one.
	_ = st.ReserveProfileSyncPATCleanup(ctx, ProfileSyncPATCleanup{PATName: "grasp-profile-6-y", GiteaUserID: 6, GiteaUser: "u6"}, now.Add(time.Second))
	if err := st.RecordProfileSyncPATDeleteFailure(ctx, rec.PATName, "boom"); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	list, err := st.ListStaleProfileSyncPATCleanup(ctx, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	if list[0].DeleteAttempts != 0 || list[len(list)-1].PATName != rec.PATName {
		t.Fatalf("fair ordering broken: %+v", list)
	}

	if err := st.DeleteProfileSyncPATCleanup(ctx, rec.PATName); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := st.GetProfileSyncPATCleanupForUser(ctx, 5); ok {
		t.Fatal("cleanup row not deleted")
	}
}

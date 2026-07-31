// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package profilesync

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// fakeStore implements Store with an in-memory model.
type fakeStore struct {
	mu       sync.Mutex
	links    map[string]store.NostrIdentityLink
	cursors  map[string]store.ProfileSyncCursor
	cleanups map[int64]store.ProfileSyncPATCleanup // by user id
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		links:    map[string]store.NostrIdentityLink{},
		cursors:  map[string]store.ProfileSyncCursor{},
		cleanups: map[int64]store.ProfileSyncPATCleanup{},
	}
}

func (f *fakeStore) GetIdentityLinkByPubkey(_ context.Context, pubkey string) (store.NostrIdentityLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[pubkey]
	if !ok {
		return store.NostrIdentityLink{}, sql.ErrNoRows
	}
	return l, nil
}

func (f *fakeStore) ListIdentityLinksAfter(_ context.Context, after string, limit int) ([]store.NostrIdentityLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.NostrIdentityLink
	for _, l := range f.links {
		if l.Pubkey > after {
			out = append(out, l)
		}
	}
	return out, nil
}

func (f *fakeStore) GetProfileSyncCursor(_ context.Context, pubkey string, giteaUserID int64) (store.ProfileSyncCursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.cursors[pubkey]
	if cur.GiteaUserID != giteaUserID {
		return store.ProfileSyncCursor{Pubkey: pubkey, GiteaUserID: giteaUserID}, nil
	}
	return cur, nil
}

func (f *fakeStore) MarkNostrProfileSynced(_ context.Context, pubkey string, giteaUserID int64, eventID string, createdAt int64, syncedAt time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.cursors[pubkey]
	if cur.GiteaUserID == giteaUserID && cur.EventCreatedAt >= createdAt {
		return false, nil
	}
	f.cursors[pubkey] = store.ProfileSyncCursor{Pubkey: pubkey, GiteaUserID: giteaUserID, EventCreatedAt: createdAt, EventID: eventID, SyncedAt: syncedAt}
	return true, nil
}

func (f *fakeStore) ReserveProfileSyncPATCleanup(_ context.Context, rec store.ProfileSyncPATCleanup, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec.CreatedAt = now
	f.cleanups[rec.GiteaUserID] = rec
	return nil
}

func (f *fakeStore) SetProfileSyncPATTokenID(_ context.Context, patName string, tokenID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, rec := range f.cleanups {
		if rec.PATName == patName {
			rec.GiteaTokenID = tokenID
			f.cleanups[id] = rec
		}
	}
	return nil
}

func (f *fakeStore) GetProfileSyncPATCleanupForUser(_ context.Context, id int64) (store.ProfileSyncPATCleanup, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.cleanups[id]
	return rec, ok, nil
}

func (f *fakeStore) ListStaleProfileSyncPATCleanup(_ context.Context, limit int) ([]store.ProfileSyncPATCleanup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.ProfileSyncPATCleanup
	for _, rec := range f.cleanups {
		out = append(out, rec)
	}
	return out, nil
}

func (f *fakeStore) RecordProfileSyncPATDeleteFailure(_ context.Context, patName, lastErr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, rec := range f.cleanups {
		if rec.PATName == patName {
			rec.DeleteAttempts++
			rec.LastError = lastErr
			f.cleanups[id] = rec
		}
	}
	return nil
}

func (f *fakeStore) DeleteProfileSyncPATCleanup(_ context.Context, patName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, rec := range f.cleanups {
		if rec.PATName == patName {
			delete(f.cleanups, id)
		}
	}
	return nil
}

func (f *fakeStore) cleanupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cleanups)
}

// fakeGitea implements Gitea.
type fakeGitea struct {
	mu            sync.Mutex
	userID        int64
	fields        gitea.UserProfileFields
	fieldsCalls   int
	created       []string // token names
	deletedTokens []string
	avatarSet     int
	avatarDeleted int
	failCreate    bool
	failDelete    bool
	patSubjectID  int64 // what GetAuthenticatedUserBasic reports
	nextTokenID   int64
}

func newFakeGitea(userID int64) *fakeGitea {
	return &fakeGitea{userID: userID, patSubjectID: userID, nextTokenID: 5000}
}

func (g *fakeGitea) GetUser(_ context.Context, login string) (gitea.User, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return gitea.User{ID: g.userID, Login: login}, nil
}

func (g *fakeGitea) UpdateUserProfileFields(_ context.Context, _ string, f gitea.UserProfileFields) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fields = f
	g.fieldsCalls++
	return nil
}

func (g *fakeGitea) CreateUserAccessToken(_ context.Context, _, name string, _ []string) (gitea.AccessToken, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failCreate {
		return gitea.AccessToken{}, errors.New("mint failed")
	}
	g.created = append(g.created, name)
	id := g.nextTokenID
	g.nextTokenID++
	return gitea.AccessToken{ID: id, Name: name, Token: "eph-pat"}, nil
}

func (g *fakeGitea) DeleteUserAccessToken(_ context.Context, _, ref string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failDelete {
		return errors.New("delete failed")
	}
	g.deletedTokens = append(g.deletedTokens, ref)
	return nil
}

func (g *fakeGitea) GetAuthenticatedUserBasic(_ context.Context, login, _ string) (gitea.User, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return gitea.User{ID: g.patSubjectID, Login: login}, nil
}

func (g *fakeGitea) SetUserAvatarBasic(_ context.Context, _, _ string, _ []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.avatarSet++
	return nil
}

func (g *fakeGitea) DeleteUserAvatarBasic(_ context.Context, _, _ string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.avatarDeleted++
	return nil
}

func testService(st Store, gc Gitea) *Service {
	return New(Config{Interval: time.Minute, Workers: 1}, st, gc, []string{"wss://relay.example"}, nil)
}

func link(pubkey string, id int64) store.NostrIdentityLink {
	return store.NostrIdentityLink{Pubkey: pubkey, GiteaUserID: id, GiteaUser: "u" + pubkey[:4]}
}

// stubProfile installs a fetch stub returning a fixed snapshot.
func stubFetch(s *Service, createdAt int64, picture string, err error) {
	s.fetch = func(_ context.Context, _ string) (snapshot, error) {
		if err != nil {
			return snapshot{}, err
		}
		return snapshot{
			displayName: "Alice", about: "bio", website: "https://a.example",
			picture: picture, eventID: "evid", createdAt: createdAt,
		}, nil
	}
}

func TestSyncAppliesTextAndDedups(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef01"] = link("deadbeef01", 42)
	gc := newFakeGitea(42)
	svc := testService(st, gc)
	stubFetch(svc, 1000, "", nil)

	if err := svc.SyncPubkey(context.Background(), "deadbeef01"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gc.fieldsCalls != 1 || gc.fields.FullName != "Alice" || gc.fields.Website != "https://a.example" {
		t.Fatalf("fields not applied: %+v (calls %d)", gc.fields, gc.fieldsCalls)
	}
	// Empty picture => avatar deleted.
	if gc.avatarDeleted != 1 {
		t.Fatalf("avatar deleted = %d, want 1", gc.avatarDeleted)
	}

	// A second sync with the same created_at is a no-op (dedup).
	if err := svc.SyncPubkey(context.Background(), "deadbeef01"); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if gc.fieldsCalls != 1 {
		t.Fatalf("dedup failed: fields applied %d times", gc.fieldsCalls)
	}

	// A newer event re-applies.
	stubFetch(svc, 2000, "", nil)
	if err := svc.SyncPubkey(context.Background(), "deadbeef01"); err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if gc.fieldsCalls != 2 {
		t.Fatalf("newer event not applied: calls %d", gc.fieldsCalls)
	}
}

func TestSyncAvatarEphemeralPATLifecycle(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef02"] = link("deadbeef02", 7)
	gc := newFakeGitea(7)
	svc := testService(st, gc)
	svc.fetch = func(_ context.Context, _ string) (snapshot, error) {
		return snapshot{displayName: "Bob", picture: "https://img.example/a.png", eventID: "e", createdAt: 100}, nil
	}
	svc.prepareImage = func(_ context.Context, _ string) ([]byte, error) { return []byte("PNGDATA"), nil }

	if err := svc.SyncPubkey(context.Background(), "deadbeef02"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gc.avatarSet != 1 {
		t.Fatalf("avatar set = %d, want 1", gc.avatarSet)
	}
	if len(gc.created) != 1 {
		t.Fatalf("ephemeral PAT mints = %d, want 1", len(gc.created))
	}
	if len(gc.deletedTokens) != 1 {
		t.Fatalf("ephemeral PAT deletes = %d, want 1 (delete-after-use)", len(gc.deletedTokens))
	}
	if st.cleanupCount() != 0 {
		t.Fatalf("cleanup row remained after successful delete: %d", st.cleanupCount())
	}
}

func TestSyncRejectsPATSubjectMismatch(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef03"] = link("deadbeef03", 9)
	gc := newFakeGitea(9)
	gc.patSubjectID = 999 // minted PAT authenticates as the wrong user
	svc := testService(st, gc)
	svc.fetch = func(_ context.Context, _ string) (snapshot, error) {
		return snapshot{displayName: "C", picture: "https://img.example/a.png", createdAt: 1}, nil
	}
	svc.prepareImage = func(_ context.Context, _ string) ([]byte, error) { return []byte("x"), nil }

	err := svc.SyncPubkey(context.Background(), "deadbeef03")
	if err == nil {
		t.Fatal("expected error on PAT subject mismatch")
	}
	if gc.avatarSet != 0 {
		t.Fatal("avatar set despite PAT subject mismatch")
	}
	if len(gc.deletedTokens) != 1 {
		t.Fatal("mismatched PAT not deleted")
	}
	// Cursor must NOT advance on failure.
	if st.cursors["deadbeef03"].EventCreatedAt != 0 {
		t.Fatal("cursor advanced despite avatar failure")
	}
}

func TestSyncInvalidImageSyncsTextAndAdvances(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef04"] = link("deadbeef04", 11)
	gc := newFakeGitea(11)
	svc := testService(st, gc)
	svc.fetch = func(_ context.Context, _ string) (snapshot, error) {
		return snapshot{displayName: "D", picture: "https://img.example/bad", createdAt: 5}, nil
	}
	svc.prepareImage = func(_ context.Context, _ string) ([]byte, error) {
		return nil, gitea.ErrImageInvalid
	}

	if err := svc.SyncPubkey(context.Background(), "deadbeef04"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gc.fieldsCalls != 1 {
		t.Fatal("text not synced on invalid image")
	}
	if len(gc.created) != 0 {
		t.Fatal("ephemeral PAT minted for an invalid image")
	}
	if st.cursors["deadbeef04"].EventCreatedAt != 5 {
		t.Fatal("cursor did not advance past a permanently-invalid image")
	}
}

func TestSyncTransientImageDoesNotAdvance(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef05"] = link("deadbeef05", 13)
	gc := newFakeGitea(13)
	svc := testService(st, gc)
	svc.fetch = func(_ context.Context, _ string) (snapshot, error) {
		return snapshot{displayName: "E", picture: "https://img.example/x", createdAt: 5}, nil
	}
	svc.prepareImage = func(_ context.Context, _ string) ([]byte, error) {
		return nil, gitea.ErrImageTransient
	}

	if err := svc.SyncPubkey(context.Background(), "deadbeef05"); err == nil {
		t.Fatal("expected transient error")
	}
	if st.cursors["deadbeef05"].EventCreatedAt != 0 {
		t.Fatal("cursor advanced on transient image failure")
	}
}

func TestSyncFutureDatedIgnored(t *testing.T) {
	st := newFakeStore()
	st.links["deadbeef06"] = link("deadbeef06", 15)
	gc := newFakeGitea(15)
	svc := testService(st, gc)
	future := time.Now().Add(time.Hour).Unix()
	stubFetch(svc, future, "", nil)

	if err := svc.SyncPubkey(context.Background(), "deadbeef06"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if gc.fieldsCalls != 0 || st.cursors["deadbeef06"].EventCreatedAt != 0 {
		t.Fatal("future-dated event was applied")
	}
}

func TestReconcilePATRetries(t *testing.T) {
	st := newFakeStore()
	gc := newFakeGitea(20)
	gc.failDelete = true
	svc := testService(st, gc)

	// A stranded cleanup row.
	_ = st.ReserveProfileSyncPATCleanup(context.Background(),
		store.ProfileSyncPATCleanup{PATName: "grasp-profile-20-abc", GiteaUserID: 20, GiteaUser: "u", GiteaTokenID: 42}, time.Now())

	svc.reconcilePATs(context.Background())
	if st.cleanupCount() != 1 {
		t.Fatal("cleanup row cleared despite delete failure")
	}

	gc.mu.Lock()
	gc.failDelete = false
	gc.mu.Unlock()
	svc.reconcilePATs(context.Background())
	if st.cleanupCount() != 0 {
		t.Fatal("cleanup row not cleared after Gitea recovered")
	}
}

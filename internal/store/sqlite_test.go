// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestOpenAndClose(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestUpsertAndGetMapping(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := Mapping{
		Npub:              "npub1test",
		RepoID:            "repo1",
		Pubkey:            "deadbeef",
		Owner:             "testorg",
		RepoName:          "repo1",
		GiteaRepoID:       42,
		CloneURL:          "https://example.com/testorg/repo1.git",
		AnnouncedCloneURL: "https://example.com/npub1test/repo1.git",
		SourceEvent:       "event123",
		HookInstalled:     true,
	}

	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := st.GetMapping(ctx, "npub1test", "repo1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Owner != "testorg" {
		t.Errorf("expected owner 'testorg', got %q", got.Owner)
	}
	if got.GiteaRepoID != 42 {
		t.Errorf("expected gitea repo id 42, got %d", got.GiteaRepoID)
	}
	if got.CloneURL != "https://example.com/testorg/repo1.git" {
		t.Errorf("expected gitea clone URL, got %q", got.CloneURL)
	}
	if got.AnnouncedCloneURL != "https://example.com/npub1test/repo1.git" {
		t.Errorf("expected announced clone URL, got %q", got.AnnouncedCloneURL)
	}
	if !got.HookInstalled {
		t.Error("expected hook_installed to be true")
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected non-zero created_at")
	}
}

func TestMappingExists(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	exists, err := st.MappingExists(ctx, "npub1none", "repo1")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected mapping to not exist")
	}

	m := Mapping{
		Npub:        "npub1test",
		RepoID:      "repo1",
		Pubkey:      "deadbeef",
		Owner:       "testorg",
		RepoName:    "repo1",
		GiteaRepoID: 1,
		CloneURL:    "https://example.com/testorg/repo1.git",
		SourceEvent: "ev1",
	}
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatal(err)
	}

	exists, err = st.MappingExists(ctx, "npub1test", "repo1")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("expected mapping to exist")
	}
}

func TestEventProcessed(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	processed, err := st.EventProcessed(ctx, "event1")
	if err != nil {
		t.Fatal(err)
	}
	if processed {
		t.Error("expected event to not be processed")
	}

	if err := st.MarkEventProcessed(ctx, "event1", "pubkey1", 30617); err != nil {
		t.Fatal(err)
	}

	processed, err = st.EventProcessed(ctx, "event1")
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Error("expected event to be processed")
	}
}

func TestProvisionCountSince(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	m := Mapping{
		Npub:        "npub1test",
		RepoID:      "repo1",
		Pubkey:      "pk1",
		Owner:       "org1",
		RepoName:    "repo1",
		GiteaRepoID: 1,
		CloneURL:    "url",
		SourceEvent: "ev1",
	}
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatal(err)
	}

	count, err := st.ProvisionCountSince(ctx, "pk1", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	count, err = st.ProvisionCountSince(ctx, "pk-other", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected count 0 for different pubkey, got %d", count)
	}
}

func TestListMappings(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for i, id := range []string{"repo1", "repo2"} {
		m := Mapping{
			Npub:          "npub1test",
			RepoID:        id,
			Pubkey:        "pk1",
			Owner:         "org1",
			RepoName:      id,
			GiteaRepoID:   int64(i + 1),
			CloneURL:      "url",
			SourceEvent:   "ev",
			HookInstalled: true,
		}
		if err := st.UpsertMapping(ctx, m); err != nil {
			t.Fatal(err)
		}
	}

	mappings, err := st.ListMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
}

func TestHookInstalledTracking(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Insert a mapping with hook_installed=false (simulates interrupted provisioning).
	m := Mapping{
		Npub:          "npub1test",
		RepoID:        "repo1",
		Pubkey:        "pk1",
		Owner:         "org1",
		RepoName:      "repo1",
		GiteaRepoID:   1,
		CloneURL:      "url",
		SourceEvent:   "ev1",
		HookInstalled: false,
	}
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatal(err)
	}

	// Also insert a fully provisioned mapping.
	m2 := Mapping{
		Npub:          "npub1test",
		RepoID:        "repo2",
		Pubkey:        "pk1",
		Owner:         "org1",
		RepoName:      "repo2",
		GiteaRepoID:   2,
		CloneURL:      "url2",
		SourceEvent:   "ev2",
		HookInstalled: true,
	}
	if err := st.UpsertMapping(ctx, m2); err != nil {
		t.Fatal(err)
	}

	// ListUnhookedMappings should only return the incomplete one.
	unhooked, err := st.ListUnhookedMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhooked) != 1 {
		t.Fatalf("expected 1 unhooked mapping, got %d", len(unhooked))
	}
	if unhooked[0].RepoID != "repo1" {
		t.Errorf("expected repo1, got %s", unhooked[0].RepoID)
	}
	if unhooked[0].HookInstalled {
		t.Error("expected hook_installed=false for unhooked mapping")
	}

	// GetMapping should reflect hook_installed=false.
	got, err := st.GetMapping(ctx, "npub1test", "repo1")
	if err != nil {
		t.Fatal(err)
	}
	if got.HookInstalled {
		t.Error("expected hook_installed=false")
	}

	// SetHookInstalled should mark it as complete.
	if err := st.SetHookInstalled(ctx, "npub1test", "repo1", true); err != nil {
		t.Fatal(err)
	}

	got, err = st.GetMapping(ctx, "npub1test", "repo1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HookInstalled {
		t.Error("expected hook_installed=true after SetHookInstalled")
	}

	// No more unhooked mappings.
	unhooked, err = st.ListUnhookedMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unhooked) != 0 {
		t.Fatalf("expected 0 unhooked mappings after reconciliation, got %d", len(unhooked))
	}
}

// --- Auth challenge tests ---

func TestCreateAndGetChallenge(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	c := AuthChallenge{
		Nonce:       "test-nonce-001",
		URL:         "https://bridge.example.com/auth/nip07/verify",
		Method:      "POST",
		RedirectURI: "/dashboard",
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	if err := st.CreateChallenge(ctx, c); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	got, err := st.GetChallenge(ctx, "test-nonce-001")
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	if got.Nonce != c.Nonce {
		t.Errorf("nonce: got %q, want %q", got.Nonce, c.Nonce)
	}
	if got.URL != c.URL {
		t.Errorf("url: got %q, want %q", got.URL, c.URL)
	}
	if got.RedirectURI != c.RedirectURI {
		t.Errorf("redirect_uri: got %q, want %q", got.RedirectURI, c.RedirectURI)
	}
	if got.Consumed {
		t.Error("expected consumed=false")
	}
}

func TestGetChallengeNotFound(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.GetChallenge(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent challenge")
	}
}

func TestConsumeChallenge(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	c := AuthChallenge{
		Nonce:     "consume-test",
		URL:       "https://example.com/verify",
		Method:    "POST",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := st.CreateChallenge(ctx, c); err != nil {
		t.Fatal(err)
	}

	// First consume should succeed.
	if err := st.ConsumeChallenge(ctx, "consume-test"); err != nil {
		t.Fatalf("first ConsumeChallenge: %v", err)
	}

	// Verify it's marked consumed.
	got, err := st.GetChallenge(ctx, "consume-test")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Consumed {
		t.Error("expected consumed=true after ConsumeChallenge")
	}

	// Second consume should fail.
	if err := st.ConsumeChallenge(ctx, "consume-test"); err == nil {
		t.Fatal("expected error on double consume")
	}
}

func TestDeleteExpiredChallenges(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	past := time.Now().UTC().Add(-10 * time.Minute)
	for i, nonce := range []string{"expired-1", "expired-2"} {
		c := AuthChallenge{
			Nonce:     nonce,
			URL:       "https://example.com/verify",
			Method:    "POST",
			CreatedAt: past.Add(time.Duration(i) * time.Second),
			ExpiresAt: past.Add(5 * time.Minute),
		}
		if err := st.CreateChallenge(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.DeleteExpiredChallenges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 deleted, got %d", n)
	}
}

// --- Identity link tests ---

func TestUpsertAndGetIdentityLink(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	link := NostrIdentityLink{
		Pubkey:      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Npub:        "npub1test",
		GiteaUserID: 42,
		GiteaUser:   "alice",
		NIP05:       "alice@example.com",
		LastLoginAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatalf("UpsertIdentityLink: %v", err)
	}

	got, err := st.GetIdentityLinkByPubkey(ctx, link.Pubkey)
	if err != nil {
		t.Fatalf("GetIdentityLinkByPubkey: %v", err)
	}
	if got.GiteaUserID != 42 {
		t.Errorf("gitea_user_id: got %d, want 42", got.GiteaUserID)
	}
	if got.GiteaUser != "alice" {
		t.Errorf("gitea_user: got %q, want 'alice'", got.GiteaUser)
	}
	if got.NIP05 != "alice@example.com" {
		t.Errorf("nip05: got %q, want 'alice@example.com'", got.NIP05)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected non-zero created_at")
	}
}

func TestGetIdentityLinkByGiteaUserID(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	link := NostrIdentityLink{
		Pubkey:      "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd",
		Npub:        "npub1user2",
		GiteaUserID: 99,
		GiteaUser:   "bob",
		LastLoginAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetIdentityLinkByGiteaUserID(ctx, 99)
	if err != nil {
		t.Fatalf("GetIdentityLinkByGiteaUserID: %v", err)
	}
	if got.Pubkey != link.Pubkey {
		t.Errorf("pubkey: got %q, want %q", got.Pubkey, link.Pubkey)
	}
}

func TestGetIdentityLinkNotFound(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.GetIdentityLinkByPubkey(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}

	_, err = st.GetIdentityLinkByGiteaUserID(ctx, 999)
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	link := NostrIdentityLink{
		Pubkey:      "1111111111111111111111111111111111111111111111111111111111111111",
		Npub:        "npub1login",
		GiteaUserID: 10,
		GiteaUser:   "loginuser",
	}
	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	if err := st.UpdateLastLogin(ctx, link.Pubkey); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}

	got, err := st.GetIdentityLinkByPubkey(ctx, link.Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastLoginAt.IsZero() {
		t.Error("expected non-zero last_login_at after UpdateLastLogin")
	}
}

func TestListIdentityLinks(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for i, pk := range []string{"aaaa", "bbbb"} {
		link := NostrIdentityLink{
			Pubkey:      pk,
			Npub:        "npub1" + pk,
			GiteaUserID: int64(i + 1),
			GiteaUser:   "user" + pk,
		}
		if err := st.UpsertIdentityLink(ctx, link); err != nil {
			t.Fatal(err)
		}
	}

	links, err := st.ListIdentityLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Errorf("expected 2 links, got %d", len(links))
	}
}

func TestUpsertIdentityLinkUpdatesExisting(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	link := NostrIdentityLink{
		Pubkey:      "2222222222222222222222222222222222222222222222222222222222222222",
		Npub:        "npub1first",
		GiteaUserID: 50,
		GiteaUser:   "firstuser",
		NIP05:       "old@example.com",
	}
	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	// Update with new NIP-05 and user.
	link.NIP05 = "new@example.com"
	link.GiteaUser = "updateduser"
	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetIdentityLinkByPubkey(ctx, link.Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	if got.NIP05 != "new@example.com" {
		t.Errorf("nip05: got %q, want 'new@example.com'", got.NIP05)
	}
	if got.GiteaUser != "updateduser" {
		t.Errorf("gitea_user: got %q, want 'updateduser'", got.GiteaUser)
	}

	// Should still be only one link.
	links, err := st.ListIdentityLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Errorf("expected 1 link after upsert, got %d", len(links))
	}
}

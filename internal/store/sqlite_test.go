// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"database/sql"
	"fmt"
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

func TestOpenMigratesLegacyIdentityLinks(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	created := time.Now().UTC().Truncate(time.Second)
	_, err = db.Exec(`
		CREATE TABLE nostr_identity_links (
			pubkey TEXT PRIMARY KEY,
			npub TEXT NOT NULL,
			nip05 TEXT NOT NULL DEFAULT '',
			gitea_user_id INTEGER NOT NULL,
			gitea_username TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			last_login_at DATETIME
		);
		INSERT INTO nostr_identity_links(pubkey, npub, nip05, gitea_user_id, gitea_username, created_at, last_login_at)
		VALUES('legacy-pubkey', 'legacy-npub', '', 42, 'legacy-user', ?, ?)
	`, created.Format(time.RFC3339), created.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seed legacy database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer st.Close()

	link, err := st.GetIdentityLinkByPubkey(context.Background(), "legacy-pubkey")
	if err != nil {
		t.Fatalf("get migrated identity link: %v", err)
	}
	if link.GiteaUser != "legacy-user" {
		t.Fatalf("migrated gitea user = %q, want legacy-user", link.GiteaUser)
	}
	if link.UpdatedAt.IsZero() {
		t.Fatal("migrated updated_at is zero")
	}
}

func TestOpenMigratesLegacyNIP46Sessions(t *testing.T) {
	path := t.TempDir() + "/legacy-nip46.db"
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, err = db.Exec(`
		CREATE TABLE nip46_sessions (
			session_token TEXT PRIMARY KEY,
			bunker_pubkey TEXT NOT NULL,
			client_pubkey TEXT NOT NULL,
			oauth2_state TEXT NOT NULL DEFAULT '',
			redirect_uri TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			auth_code TEXT NOT NULL DEFAULT '',
			error_msg TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		);
		INSERT INTO nip46_sessions(session_token, bunker_pubkey, client_pubkey, redirect_uri, status, auth_code, error_msg, created_at, expires_at)
		VALUES('legacy-session', 'bunker-pubkey', 'client-pubkey', '/', 'complete', 'result-pubkey', '', ?, ?)
	`, now.Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seed legacy database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer st.Close()

	sess, err := st.GetNIP46Session(context.Background(), "legacy-session")
	if err != nil {
		t.Fatalf("get migrated NIP-46 session: %v", err)
	}
	if sess.State != "complete" || sess.ResultPubkey != "result-pubkey" {
		t.Fatalf("migrated session = state %q result %q", sess.State, sess.ResultPubkey)
	}

	newSession := NIP46Session{
		SessionToken: "new-session", BunkerPubkey: "new-bunker", ClientPubkey: "new-client",
		State: "pending", RedirectURI: "/new", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := st.CreateNIP46Session(context.Background(), newSession); err != nil {
		t.Fatalf("create session in migrated legacy table: %v", err)
	}
	if _, err := st.GetNIP46Session(context.Background(), "new-session"); err != nil {
		t.Fatalf("get new session from migrated legacy table: %v", err)
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

func TestGetProvisionedMappingByRepoAddr(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.UpsertMapping(ctx, Mapping{
		Npub:          "npub1pending",
		RepoID:        "repo1",
		Pubkey:        "pub1",
		Owner:         "org1",
		RepoName:      "repo1",
		GiteaRepoID:   1,
		CloneURL:      "url",
		SourceEvent:   "ev",
		HookInstalled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetProvisionedMappingByRepoAddr(ctx, "pub1", "repo1"); err != sql.ErrNoRows {
		t.Fatalf("expected unhooked mapping to be ignored, got %v", err)
	}

	if err := st.SetHookInstalled(ctx, "npub1pending", "repo1", true); err != nil {
		t.Fatal(err)
	}
	m, err := st.GetProvisionedMappingByRepoAddr(ctx, "pub1", "repo1")
	if err != nil {
		t.Fatalf("get provisioned mapping: %v", err)
	}
	if m.Owner != "org1" || !m.HookInstalled {
		t.Fatalf("unexpected mapping: %+v", m)
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

func TestReflectedEvents(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	armedAt := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	inserted, err := st.RecordReflectedEvent(ctx, ReflectedEvent{
		NostrEventID:    "ev1",
		GiteaRepoID:     42,
		GiteaIndex:      7,
		HeadBranch:      "feature/tip",
		Kind:            1621,
		EchoArmedAt:     armedAt,
		EchoFingerprint: "fp1",
	})
	if err != nil {
		t.Fatalf("record reflected event: %v", err)
	}
	if !inserted {
		t.Fatal("expected first insert to report inserted")
	}
	inserted, err = st.RecordReflectedEvent(ctx, ReflectedEvent{
		NostrEventID: "ev1",
		GiteaRepoID:  42,
		GiteaIndex:   7,
		Kind:         1621,
	})
	if err != nil {
		t.Fatalf("record duplicate reflected event: %v", err)
	}
	if inserted {
		t.Fatal("expected duplicate insert to report false")
	}

	ref, err := st.GetReflectedEvent(ctx, "ev1")
	if err != nil {
		t.Fatalf("get reflected event: %v", err)
	}
	if ref.GiteaRepoID != 42 || ref.GiteaIndex != 7 || ref.HeadBranch != "feature/tip" || ref.Kind != 1621 || ref.EchoFingerprint != "fp1" || !ref.EchoArmedAt.Equal(armedAt) {
		t.Fatalf("unexpected reflected event: %+v", ref)
	}
	ok, err := st.WasReflectedGiteaObject(ctx, 42, 7, 1621)
	if err != nil {
		t.Fatalf("was reflected: %v", err)
	}
	if !ok {
		t.Fatal("expected reflected object lookup to match")
	}
	ok, err = st.WasReflectedGiteaObject(ctx, 42, 7, 1111)
	if err != nil {
		t.Fatalf("was reflected other kind: %v", err)
	}
	if ok {
		t.Fatal("did not expect other kind to match")
	}

	matched, err := st.CheckReflectedGiteaEcho(ctx, 42, 7, 1621, "fp1", armedAt.Add(time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check echo: %v", err)
	}
	if !matched {
		t.Fatal("expected first echo check to match")
	}
	matched, err = st.CheckReflectedGiteaEcho(ctx, 42, 7, 1621, "fp1", armedAt.Add(2*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check echo again: %v", err)
	}
	if !matched {
		t.Fatal("duplicate echo should still match inside the window")
	}
	matched, err = st.CheckReflectedGiteaEcho(ctx, 42, 7, 1621, "different", armedAt.Add(3*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check echo mismatch: %v", err)
	}
	if matched {
		t.Fatal("different fingerprint must not match inside the window")
	}
	matched, err = st.CheckReflectedGiteaEcho(ctx, 42, 7, 1621, "fp1", armedAt.Add(6*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check expired echo: %v", err)
	}
	if matched {
		t.Fatal("expired guard must not match")
	}
}

func TestNostrObjectMappingDoesNotArmEchoGuard(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	inserted, err := st.RecordNostrObjectMapping(ctx, ReflectedEvent{
		NostrEventID: "gitea-origin-event",
		GiteaRepoID:  42,
		GiteaIndex:   9,
		Kind:         1621,
	})
	if err != nil {
		t.Fatalf("record nostr object mapping: %v", err)
	}
	if !inserted {
		t.Fatal("expected mapping insert")
	}
	ref, err := st.GetReflectedEvent(ctx, "gitea-origin-event")
	if err != nil {
		t.Fatalf("get mapping: %v", err)
	}
	if ref.GiteaIndex != 9 {
		t.Fatalf("unexpected mapping: %+v", ref)
	}
	matched, err := st.CheckReflectedGiteaEcho(ctx, 42, 9, 1621, "", time.Now().UTC(), 5*time.Minute)
	if err != nil {
		t.Fatalf("check echo: %v", err)
	}
	if matched {
		t.Fatal("Gitea-origin mapping must not arm echo guard")
	}
}

func TestDisarmExpiredEchoGuards(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	armedAt := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if _, err := st.RecordReflectedEvent(ctx, ReflectedEvent{
		NostrEventID:    "old",
		GiteaRepoID:     42,
		GiteaIndex:      7,
		Kind:            1621,
		EchoArmedAt:     armedAt,
		EchoFingerprint: "fp",
	}); err != nil {
		t.Fatalf("record old guard: %v", err)
	}
	if _, err := st.RecordReflectedEvent(ctx, ReflectedEvent{
		NostrEventID:    "fresh",
		GiteaRepoID:     42,
		GiteaIndex:      8,
		Kind:            1621,
		EchoArmedAt:     armedAt.Add(4 * time.Minute),
		EchoFingerprint: "fp2",
	}); err != nil {
		t.Fatalf("record fresh guard: %v", err)
	}

	disarmed, err := st.DisarmExpiredEchoGuards(ctx, armedAt.Add(6*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("disarm expired guards: %v", err)
	}
	if disarmed != 1 {
		t.Fatalf("disarmed = %d, want 1", disarmed)
	}
	matched, err := st.CheckReflectedGiteaEcho(ctx, 42, 7, 1621, "fp", armedAt.Add(6*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check old guard: %v", err)
	}
	if matched {
		t.Fatal("old guard should be disarmed")
	}
	matched, err = st.CheckReflectedGiteaEcho(ctx, 42, 8, 1621, "fp2", armedAt.Add(6*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatalf("check fresh guard: %v", err)
	}
	if !matched {
		t.Fatal("fresh guard should remain armed")
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

// --- NIP-46 session tests ---

func TestCreateAndGetNIP46Session(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	sess := NIP46Session{
		SessionToken: "test-token-001",
		BunkerPubkey: "deadbeef",
		ClientPubkey: "clientpk",
		State:        "pending",
		RedirectURI:  "/dashboard",
		CreatedAt:    now,
		ExpiresAt:    now.Add(2 * time.Minute),
	}

	if err := st.CreateNIP46Session(ctx, sess); err != nil {
		t.Fatalf("CreateNIP46Session: %v", err)
	}

	got, err := st.GetNIP46Session(ctx, "test-token-001")
	if err != nil {
		t.Fatalf("GetNIP46Session: %v", err)
	}
	if got.State != "pending" {
		t.Errorf("state: got %q, want 'pending'", got.State)
	}
	if got.BunkerPubkey != "deadbeef" {
		t.Errorf("bunker_pubkey: got %q", got.BunkerPubkey)
	}
	if got.RedirectURI != "/dashboard" {
		t.Errorf("redirect_uri: got %q", got.RedirectURI)
	}
}

func TestGetNIP46SessionNotFound(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.GetNIP46Session(ctx, "nonexistent")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUpdateNIP46SessionState(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	sess := NIP46Session{
		SessionToken: "update-test",
		BunkerPubkey: "bpk",
		ClientPubkey: "cpk",
		State:        "pending",
		CreatedAt:    now,
		ExpiresAt:    now.Add(2 * time.Minute),
	}
	if err := st.CreateNIP46Session(ctx, sess); err != nil {
		t.Fatal(err)
	}

	// Update to complete.
	if err := st.UpdateNIP46SessionState(ctx, "update-test", "complete", "signer-pk", ""); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetNIP46Session(ctx, "update-test")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "complete" {
		t.Errorf("state: got %q, want 'complete'", got.State)
	}
	if got.ResultPubkey != "signer-pk" {
		t.Errorf("result_pubkey: got %q", got.ResultPubkey)
	}
}

func TestDeleteExpiredNIP46Sessions(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	past := time.Now().UTC().Add(-10 * time.Minute)
	sess := NIP46Session{
		SessionToken: "expired-sess",
		BunkerPubkey: "bpk",
		ClientPubkey: "cpk",
		State:        "pending",
		CreatedAt:    past,
		ExpiresAt:    past.Add(2 * time.Minute),
	}
	if err := st.CreateNIP46Session(ctx, sess); err != nil {
		t.Fatal(err)
	}

	n, err := st.DeleteExpiredNIP46Sessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}
}

func TestUserGraspListCacheReplaceableSemantics(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	owner, err := st.HasProvisionedOwnerPubkey(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if owner {
		t.Fatal("owner pubkey should not be provisioned before mapping exists")
	}

	if err := st.UpsertMapping(ctx, Mapping{
		Npub:          "npub1owner",
		RepoID:        "repo1",
		Pubkey:        "owner-pubkey",
		Owner:         "owner",
		RepoName:      "repo1",
		GiteaRepoID:   1,
		CloneURL:      "https://example.com/owner/repo1.git",
		SourceEvent:   "seed",
		HookInstalled: false,
	}); err != nil {
		t.Fatal(err)
	}
	owner, err = st.HasProvisionedOwnerPubkey(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if owner {
		t.Fatal("unhooked mapping should not count as provisioned owner")
	}
	if err := st.SetHookInstalled(ctx, "npub1owner", "repo1", true); err != nil {
		t.Fatal(err)
	}
	owner, err = st.HasProvisionedOwnerPubkey(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if !owner {
		t.Fatal("hooked mapping should count as provisioned owner")
	}

	inserted, err := st.UpsertUserGraspListEvent(ctx, UserGraspList{
		Pubkey:    "owner-pubkey",
		EventJSON: `{"id":"old"}`,
		EventID:   "old",
		CreatedAt: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first user GRASP list insert returned false")
	}
	if err := st.RecordUserGraspListRepublished(ctx, "owner-pubkey", "old"); err != nil {
		t.Fatal(err)
	}

	replaced, err := st.UpsertUserGraspListEvent(ctx, UserGraspList{
		Pubkey:    "owner-pubkey",
		EventJSON: `{"id":"new"}`,
		EventID:   "new",
		CreatedAt: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("newer user GRASP list did not replace cached row")
	}
	got, err := st.GetUserGraspList(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if got.EventID != "new" || got.CreatedAt != 200 || got.EventJSON != `{"id":"new"}` {
		t.Fatalf("cached newer row mismatch: %+v", got)
	}
	if got.LastRepublishedID != "old" {
		t.Fatalf("last republished id should remain old until rebroadcast, got %q", got.LastRepublishedID)
	}

	ignored, err := st.UpsertUserGraspListEvent(ctx, UserGraspList{
		Pubkey:    "owner-pubkey",
		EventJSON: `{"id":"older"}`,
		EventID:   "older",
		CreatedAt: 150,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ignored {
		t.Fatal("older user GRASP list unexpectedly replaced cached row")
	}
	got, err = st.GetUserGraspList(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if got.EventID != "new" || got.CreatedAt != 200 {
		t.Fatalf("older event changed cache: %+v", got)
	}
	if err := st.RecordUserGraspListRepublished(ctx, "owner-pubkey", "new"); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetUserGraspList(ctx, "owner-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRepublishedID != "new" {
		t.Fatalf("last republished id = %q, want new", got.LastRepublishedID)
	}
}

func TestPendingActorEventsSaveListDeleteAndTrim(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		inserted, trimmed, err := st.SavePendingActorEvent(ctx, PendingActorEvent{
			GiteaUserID:       77,
			Kind:              1618,
			UnsignedEventJSON: fmt.Sprintf(`{"content":"event-%d"}`, i),
			Scope:             "repo:42:pr",
			DedupeKey:         fmt.Sprintf("pending-%d", i),
		}, base.Add(time.Duration(i)*time.Minute), 2, 30*24*time.Hour)
		if err != nil {
			t.Fatalf("SavePendingActorEvent %d: %v", i, err)
		}
		if !inserted {
			t.Fatalf("SavePendingActorEvent %d inserted=false", i)
		}
		if i < 2 && trimmed != 0 {
			t.Fatalf("SavePendingActorEvent %d trimmed=%d, want 0", i, trimmed)
		}
		if i == 2 && trimmed != 1 {
			t.Fatalf("SavePendingActorEvent final trimmed=%d, want 1", trimmed)
		}
	}

	rows, err := st.ListPendingActorEvents(ctx, 77, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("pending rows = %d, want 2", len(rows))
	}
	if rows[0].DedupeKey != "pending-1" || rows[1].DedupeKey != "pending-2" {
		t.Fatalf("trim should keep newest rows in old-to-new order, got %#v", rows)
	}

	inserted, trimmed, err := st.SavePendingActorEvent(ctx, PendingActorEvent{
		GiteaUserID:       77,
		Kind:              1618,
		UnsignedEventJSON: `{"content":"dup"}`,
		Scope:             "repo:42:pr",
		DedupeKey:         "pending-2",
	}, base.Add(10*time.Minute), 2, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if inserted || trimmed != 0 {
		t.Fatalf("duplicate inserted=%v trimmed=%d, want false/0", inserted, trimmed)
	}

	if err := st.DeletePendingActorEvent(ctx, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	rows, err = st.ListPendingActorEvents(ctx, 77, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DedupeKey != "pending-2" {
		t.Fatalf("after delete rows = %#v", rows)
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

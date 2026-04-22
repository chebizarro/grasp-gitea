// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
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

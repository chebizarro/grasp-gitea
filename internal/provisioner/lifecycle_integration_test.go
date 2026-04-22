// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package provisioner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// testGiteaServer creates a mock Gitea API that tracks orgs, repos, and archive state.
type testGiteaServer struct {
	mu       sync.Mutex
	orgs     map[string]bool
	repos    map[string]testRepo
	nextID   int64
	reposDir string
}

type testRepo struct {
	ID       int64
	Name     string
	Org      string
	Archived bool
}

func newTestGiteaServer(t *testing.T, reposDir string) (*httptest.Server, *testGiteaServer) {
	t.Helper()
	state := &testGiteaServer{
		orgs:     map[string]bool{},
		repos:    map[string]testRepo{},
		nextID:   1,
		reposDir: reposDir,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		path := r.URL.Path
		switch {
		// GET org
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/orgs/") && !strings.Contains(path[len("/api/v1/orgs/"):], "/"):
			org := strings.TrimPrefix(path, "/api/v1/orgs/")
			if !state.orgs[org] {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"username": org})

		// POST org
		case r.Method == http.MethodPost && path == "/api/v1/orgs":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			org, _ := body["username"].(string)
			state.orgs[org] = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"username": org})

		// GET repo
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/repos/"):
			parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
			if len(parts) != 2 {
				http.NotFound(w, r)
				return
			}
			key := parts[0] + "/" + parts[1]
			repo, ok := state.repos[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": repo.ID, "name": repo.Name, "archived": repo.Archived,
				"owner": map[string]any{"username": repo.Org},
			})

		// POST repo (create)
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/orgs/") && strings.HasSuffix(path, "/repos"):
			org := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/orgs/"), "/repos")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			name, _ := body["name"].(string)
			key := org + "/" + name
			state.repos[key] = testRepo{ID: state.nextID, Name: name, Org: org}
			state.nextID++
			repoPath := filepath.Join(state.reposDir, org, name+".git", "hooks")
			_ = os.MkdirAll(repoPath, 0o755)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": state.repos[key].ID, "name": name,
				"owner": map[string]any{"username": org},
			})

		// PATCH repo (archive)
		case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/repos/"):
			parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
			if len(parts) != 2 {
				http.NotFound(w, r)
				return
			}
			key := parts[0] + "/" + parts[1]
			repo, ok := state.repos[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if archived, ok := body["archived"].(bool); ok {
				repo.Archived = archived
				state.repos[key] = repo
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": repo.ID, "name": repo.Name, "archived": repo.Archived,
				"owner": map[string]any{"username": repo.Org},
			})

		default:
			http.NotFound(w, r)
		}
	}))

	return srv, state
}

// newTestService creates a provisioner service with test infrastructure.
func newTestService(t *testing.T) (*Service, *store.SQLiteStore, *testGiteaServer, string) {
	t.Helper()
	tempDir := t.TempDir()
	reposDir := filepath.Join(tempDir, "git", "repositories")
	if err := os.MkdirAll(reposDir, 0o755); err != nil {
		t.Fatalf("mkdir repos: %v", err)
	}

	srv, state := newTestGiteaServer(t, reposDir)
	t.Cleanup(srv.Close)

	st, err := store.Open(filepath.Join(tempDir, "mappings.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Config{
		ClonePrefix: "https://git.example.com",
	}
	giteaClient := gitea.NewClient(srv.URL, "test-token")
	hookInstaller := hooks.NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	nip05Resolver := nip05resolve.NewResolver(0) // disable cache for test isolation

	svc := New(cfg, st, giteaClient, hookInstaller, nip05Resolver, logger)
	return svc, st, state, reposDir
}

// testSecretKey is a fixed test-only secret key for generating signed events.
// This is NOT a real key and must never be used outside tests.
const testSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// makeSignedAnnouncementEvent creates a properly signed kind:30617 event.
func makeSignedAnnouncementEvent(t *testing.T, repoID, cloneURL string) *nostr.Event {
	t.Helper()
	tags := nostr.Tags{
		{"d", repoID},
	}
	if cloneURL != "" {
		tags = append(tags, nostr.Tag{"clone", cloneURL})
	}
	ev := &nostr.Event{
		Kind:      relay.KindRepositoryAnnouncement,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
		Content:   "",
	}
	if err := ev.Sign(testSecretKey); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

func TestAnnouncementProvisionsNewRepo(t *testing.T) {
	svc, st, state, reposDir := newTestService(t)
	ctx := context.Background()

	// Reset metrics for clean assertions.
	_ = metrics.Snapshot()

	ev := makeSignedAnnouncementEvent(t, "myrepo", "https://git.example.com/whatever/myrepo.git")

	err := svc.HandleAnnouncementEvent(ctx, ev, "ws://test-relay")
	if err != nil {
		t.Fatalf("HandleAnnouncementEvent: %v", err)
	}

	// Verify mapping exists in store (check via listing since npub is derived).
	mappingsCheck, _ := st.ListMappings(ctx)
	if len(mappingsCheck) == 0 {
		t.Fatal("expected at least 1 mapping after provisioning")
	}

	// Verify event is marked as processed (deduplication).
	processed, err := st.EventProcessed(ctx, ev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Error("expected event to be marked as processed")
	}

	// Verify repo was created in mock Gitea.
	state.mu.Lock()
	repoCount := len(state.repos)
	state.mu.Unlock()
	if repoCount != 1 {
		t.Errorf("expected 1 repo in Gitea, got %d", repoCount)
	}

	// Verify hook file exists on disk.
	mappings, _ := st.ListMappings(ctx)
	if len(mappings) > 0 {
		hookPath := filepath.Join(reposDir, mappings[0].Owner, "myrepo.git", "hooks", "pre-receive")
		if _, err := os.Stat(hookPath); os.IsNotExist(err) {
			t.Errorf("expected hook at %s", hookPath)
		}
		if !mappings[0].HookInstalled {
			t.Error("expected hook_installed=true in mapping")
		}
	}
}

func TestDuplicateEventIsIgnored(t *testing.T) {
	svc, st, state, _ := newTestService(t)
	ctx := context.Background()

	ev := makeSignedAnnouncementEvent(t, "myrepo", "https://git.example.com/whatever/myrepo.git")

	// First call provisions.
	if err := svc.HandleAnnouncementEvent(ctx, ev, "ws://relay"); err != nil {
		t.Fatal(err)
	}

	state.mu.Lock()
	repoCountBefore := len(state.repos)
	state.mu.Unlock()

	// Second call with same event ID should be a no-op.
	if err := svc.HandleAnnouncementEvent(ctx, ev, "ws://relay"); err != nil {
		t.Fatal(err)
	}

	state.mu.Lock()
	repoCountAfter := len(state.repos)
	state.mu.Unlock()

	if repoCountAfter != repoCountBefore {
		t.Errorf("expected no new repos on duplicate event, before=%d after=%d", repoCountBefore, repoCountAfter)
	}

	// Verify store still has exactly 1 mapping.
	mappings, _ := st.ListMappings(ctx)
	if len(mappings) != 1 {
		t.Errorf("expected 1 mapping after duplicate event, got %d", len(mappings))
	}
}

func TestAnnouncementArchivesRemovedClone(t *testing.T) {
	svc, st, state, _ := newTestService(t)
	ctx := context.Background()

	// First: provision with matching clone URL.
	ev1 := makeSignedAnnouncementEvent(t, "archiveme", "https://git.example.com/whatever/archiveme.git")
	if err := svc.HandleAnnouncementEvent(ctx, ev1, "ws://relay"); err != nil {
		t.Fatal(err)
	}

	// Verify repo exists and is not archived.
	mappings, _ := st.ListMappings(ctx)
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	orgName := mappings[0].Owner
	state.mu.Lock()
	repo := state.repos[orgName+"/archiveme"]
	if repo.Archived {
		t.Error("repo should not be archived yet")
	}
	state.mu.Unlock()

	// Second: new announcement for the same (npub, repo_id) WITHOUT clone URL.
	ev2 := makeSignedAnnouncementEvent(t, "archiveme", "")
	if err := svc.HandleAnnouncementEvent(ctx, ev2, "ws://relay"); err != nil {
		t.Fatal(err)
	}

	// Verify repo is now archived in mock Gitea.
	state.mu.Lock()
	repo = state.repos[orgName+"/archiveme"]
	state.mu.Unlock()
	if !repo.Archived {
		t.Error("expected repo to be archived after clone tag removal")
	}
}

func TestReconcileHooksReinstallsIncomplete(t *testing.T) {
	svc, st, _, reposDir := newTestService(t)
	ctx := context.Background()

	orgName := "testorg"
	repoID := "reconcile-test"

	// Pre-create the repo directory so the hook installer has somewhere to write.
	repoPath := filepath.Join(reposDir, orgName, repoID+".git", "hooks")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatal(err)
	}

	// Insert a mapping with hook_installed=false, simulating interrupted provisioning.
	m := store.Mapping{
		Npub:          "npub1testreconcile",
		RepoID:        repoID,
		Pubkey:        "pk-reconcile",
		Owner:         orgName,
		RepoName:      repoID,
		GiteaRepoID:   99,
		CloneURL:      fmt.Sprintf("https://git.example.com/%s/%s.git", orgName, repoID),
		SourceEvent:   "ev-reconcile",
		HookInstalled: false,
	}
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatal(err)
	}

	// Verify it's in the unhooked list.
	unhooked, _ := st.ListUnhookedMappings(ctx)
	if len(unhooked) != 1 {
		t.Fatalf("expected 1 unhooked mapping, got %d", len(unhooked))
	}

	// Run reconciliation.
	if err := svc.ReconcileHooks(ctx); err != nil {
		t.Fatalf("ReconcileHooks: %v", err)
	}

	// Verify hook is now installed on disk.
	hookPath := filepath.Join(reposDir, orgName, repoID+".git", "hooks", "pre-receive")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("expected hook file at %s: %v", hookPath, err)
	}
	if !strings.Contains(string(content), "GRASP_REPO_ID='"+repoID+"'") {
		t.Errorf("hook content missing repo id: %s", string(content))
	}

	// Verify mapping is now marked as hook_installed=true.
	got, err := st.GetMapping(ctx, "npub1testreconcile", repoID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HookInstalled {
		t.Error("expected hook_installed=true after reconciliation")
	}

	// Verify no more unhooked mappings.
	unhooked, _ = st.ListUnhookedMappings(ctx)
	if len(unhooked) != 0 {
		t.Errorf("expected 0 unhooked mappings, got %d", len(unhooked))
	}
}

func TestNilAndWrongKindEventsRejected(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	// Nil event.
	if err := svc.HandleAnnouncementEvent(ctx, nil, "ws://relay"); err == nil {
		t.Error("expected error for nil event")
	}

	// Wrong kind (30618 instead of 30617).
	wrongKind := &nostr.Event{
		ID:     "event-wrong-kind",
		PubKey: "pubkey",
		Kind:   relay.KindRepositoryState,
		Tags:   nostr.Tags{{"d", "repo"}},
		Sig:    "fakesig",
	}
	if err := svc.HandleAnnouncementEvent(ctx, wrongKind, "ws://relay"); err != nil {
		t.Errorf("non-30617 event should be silently ignored, got: %v", err)
	}
}

func TestAllowlistBlocksUnauthorized(t *testing.T) {
	tempDir := t.TempDir()
	reposDir := filepath.Join(tempDir, "git", "repositories")
	_ = os.MkdirAll(reposDir, 0o755)

	srv, _ := newTestGiteaServer(t, reposDir)
	defer srv.Close()

	st, err := store.Open(filepath.Join(tempDir, "mappings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Config{
		ClonePrefix:     "https://git.example.com",
		PubkeyAllowlist: map[string]struct{}{"allowed-pubkey": {}},
	}
	giteaClient := gitea.NewClient(srv.URL, "test-token")
	hookInstaller := hooks.NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	nip05Resolver := nip05resolve.NewResolver(0)

	svc := New(cfg, st, giteaClient, hookInstaller, nip05Resolver, logger)

	ev := makeSignedAnnouncementEvent(t, "blockedrepo", "https://git.example.com/whatever/blockedrepo.git")

	err = svc.HandleAnnouncementEvent(context.Background(), ev, "ws://relay")
	if err == nil {
		t.Fatal("expected error for non-allowlisted pubkey")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("expected allowlist error, got: %v", err)
	}
}

func TestRateLimitBlocksExcessive(t *testing.T) {
	tempDir := t.TempDir()
	reposDir := filepath.Join(tempDir, "git", "repositories")
	_ = os.MkdirAll(reposDir, 0o755)

	srv, _ := newTestGiteaServer(t, reposDir)
	defer srv.Close()

	st, err := store.Open(filepath.Join(tempDir, "mappings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Config{
		ClonePrefix:        "https://git.example.com",
		ProvisionRateLimit: 1, // allow only 1 provision per hour
	}
	giteaClient := gitea.NewClient(srv.URL, "test-token")
	hookInstaller := hooks.NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	nip05Resolver := nip05resolve.NewResolver(0)

	svc := New(cfg, st, giteaClient, hookInstaller, nip05Resolver, logger)

	// First provision should succeed.
	ev1 := makeSignedAnnouncementEvent(t, "repo1", "https://git.example.com/whatever/repo1.git")
	if err := svc.HandleAnnouncementEvent(context.Background(), ev1, "ws://relay"); err != nil {
		t.Fatalf("first provision should succeed: %v", err)
	}

	// Second provision should be rate-limited.
	ev2 := makeSignedAnnouncementEvent(t, "repo2", "https://git.example.com/whatever/repo2.git")
	err = svc.HandleAnnouncementEvent(context.Background(), ev2, "ws://relay")
	if err == nil {
		t.Fatal("expected error for rate-limited pubkey")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}

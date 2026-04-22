// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package gitea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGitea is a minimal Gitea API simulator for tests.
type fakeGitea struct {
	mu    sync.Mutex
	orgs  map[string]bool
	repos map[string]int64
	next  int64
}

func newFakeGitea() *fakeGitea {
	return &fakeGitea{orgs: map[string]bool{}, repos: map[string]int64{}, next: 1}
}

func (f *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := r.URL.Path

	// GET /api/v1/orgs/:org
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/orgs/") && !strings.Contains(strings.TrimPrefix(path, "/api/v1/orgs/"), "/") {
		org := strings.TrimPrefix(path, "/api/v1/orgs/")
		if !f.orgs[org] {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"username": org})
		return
	}

	// POST /api/v1/orgs
	if r.Method == http.MethodPost && path == "/api/v1/orgs" {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		org, _ := body["username"].(string)
		if f.orgs[org] {
			http.Error(w, `{"message":"conflict"}`, http.StatusConflict)
			return
		}
		f.orgs[org] = true
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"username": org})
		return
	}

	// GET /api/v1/repos/:owner/:repo
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/repos/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
		if len(parts) == 2 {
			key := parts[0] + "/" + parts[1]
			id, ok := f.repos[key]
			if !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id": id, "name": parts[1],
				"owner": map[string]any{"username": parts[0]},
			})
			return
		}
	}

	// POST /api/v1/orgs/:org/repos
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/orgs/") && strings.HasSuffix(path, "/repos") {
		org := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/orgs/"), "/repos")
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		name, _ := body["name"].(string)
		key := org + "/" + name
		if _, exists := f.repos[key]; exists {
			http.Error(w, `{"message":"conflict"}`, http.StatusConflict)
			return
		}
		id := f.next
		f.next++
		f.repos[key] = id
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id": id, "name": name,
			"owner": map[string]any{"username": org},
		})
		return
	}

	// PATCH /api/v1/repos/:owner/:repo (archive)
	if r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/repos/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
		if len(parts) == 2 {
			key := parts[0] + "/" + parts[1]
			if _, ok := f.repos[key]; !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"id": f.repos[key], "archived": true})
			return
		}
	}

	http.NotFound(w, r)
}

func TestEnsureOrgCreatesNew(t *testing.T) {
	fake := newFakeGitea()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	ctx := context.Background()

	if err := c.EnsureOrg(ctx, "myorg"); err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if !fake.orgs["myorg"] {
		t.Error("org should have been created")
	}
}

func TestEnsureOrgIdempotent(t *testing.T) {
	fake := newFakeGitea()
	fake.orgs["existing"] = true
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	if err := c.EnsureOrg(context.Background(), "existing"); err != nil {
		t.Fatalf("EnsureOrg existing: %v", err)
	}
}

func TestEnsureOrgConflictHandled(t *testing.T) {
	// Simulate race: org doesn't exist on GET but conflicts on POST.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		callCount++
		http.Error(w, `{"message":"conflict"}`, http.StatusConflict)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	if err := c.EnsureOrg(context.Background(), "raceorg"); err != nil {
		t.Fatalf("EnsureOrg with conflict: %v", err)
	}
}

func TestEnsureRepoCreatesNew(t *testing.T) {
	fake := newFakeGitea()
	fake.orgs["org1"] = true
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	repo, err := c.EnsureRepo(context.Background(), "org1", "myrepo")
	if err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if repo.ID != 1 {
		t.Errorf("expected repo ID 1, got %d", repo.ID)
	}
	if repo.Name != "myrepo" {
		t.Errorf("expected name 'myrepo', got %q", repo.Name)
	}
	if repo.Owner != "org1" {
		t.Errorf("expected owner 'org1', got %q", repo.Owner)
	}
}

func TestEnsureRepoIdempotent(t *testing.T) {
	fake := newFakeGitea()
	fake.orgs["org1"] = true
	fake.repos["org1/existing"] = 42
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	repo, err := c.EnsureRepo(context.Background(), "org1", "existing")
	if err != nil {
		t.Fatalf("EnsureRepo existing: %v", err)
	}
	if repo.ID != 42 {
		t.Errorf("expected repo ID 42, got %d", repo.ID)
	}
}

func TestEnsureRepoConflictRecovers(t *testing.T) {
	// First GET returns 404, POST returns conflict, second GET returns repo.
	callNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callNum++
		if r.Method == http.MethodGet && callNum == 1 {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			http.Error(w, `{"message":"conflict"}`, http.StatusConflict)
			return
		}
		// Second GET
		json.NewEncoder(w).Encode(map[string]any{
			"id": 99, "name": "racerepo",
			"owner": map[string]any{"username": "org1"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	repo, err := c.EnsureRepo(context.Background(), "org1", "racerepo")
	if err != nil {
		t.Fatalf("EnsureRepo conflict recovery: %v", err)
	}
	if repo.ID != 99 {
		t.Errorf("expected repo ID 99, got %d", repo.ID)
	}
}

func TestArchiveRepo(t *testing.T) {
	fake := newFakeGitea()
	fake.repos["org1/repo1"] = 10
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	if err := c.ArchiveRepo(context.Background(), "org1", "repo1"); err != nil {
		t.Fatalf("ArchiveRepo: %v", err)
	}
}

func TestArchiveRepoNotFound(t *testing.T) {
	fake := newFakeGitea()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	err := c.ArchiveRepo(context.Background(), "org1", "missing")
	if err == nil {
		t.Fatal("expected error archiving non-existent repo")
	}
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", httpErr.StatusCode)
	}
}

func TestGetRepoNotFound(t *testing.T) {
	fake := newFakeGitea()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.GetRepo(context.Background(), "org1", "nope")
	if err == nil {
		t.Fatal("expected error for missing repo")
	}
	if !isNotFound(err) {
		t.Errorf("expected isNotFound=true, got false for %v", err)
	}
}

func TestHTTPErrorString(t *testing.T) {
	e := &HTTPError{StatusCode: 500, Body: "internal error"}
	s := e.Error()
	if !strings.Contains(s, "500") || !strings.Contains(s, "internal error") {
		t.Errorf("unexpected error string: %s", s)
	}
}

func TestIsConflict(t *testing.T) {
	if isConflict(nil) {
		t.Error("nil should not be conflict")
	}
	if isConflict(&HTTPError{StatusCode: 404}) {
		t.Error("404 should not be conflict")
	}
	if !isConflict(&HTTPError{StatusCode: 409}) {
		t.Error("409 should be conflict")
	}
}

func TestClientTrimsBaseURL(t *testing.T) {
	c := NewClient("http://example.com/", "tok")
	if c.baseURL != "http://example.com" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

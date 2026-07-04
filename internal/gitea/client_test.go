// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package gitea

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

// fakeGitea is a minimal Gitea API simulator for tests.
type fakeGitea struct {
	mu       sync.Mutex
	orgs     map[string]bool
	repos    map[string]int64
	users    map[string]fakeUser
	issues   map[string]map[int64]Issue
	pulls    map[string]map[int64]PullRequest
	comments map[string]map[int64][]IssueComment
	next     int64
}

func newFakeGitea() *fakeGitea {
	return &fakeGitea{
		orgs:     map[string]bool{},
		repos:    map[string]int64{},
		users:    map[string]fakeUser{},
		issues:   map[string]map[int64]Issue{},
		pulls:    map[string]map[int64]PullRequest{},
		comments: map[string]map[int64][]IssueComment{},
		next:     1,
	}
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

	// POST /api/v1/repos/:owner/:repo/issues
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/repos/") && strings.HasSuffix(path, "/issues") {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/repos/"), "/issues"), "/")
		if len(parts) == 2 {
			key := parts[0] + "/" + parts[1]
			if _, ok := f.repos[key]; !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			idx := f.next
			f.next++
			if f.issues[key] == nil {
				f.issues[key] = map[int64]Issue{}
			}
			issue := Issue{ID: idx, Index: idx, Number: idx, Title: body["title"].(string), Body: body["body"].(string), State: "open"}
			f.issues[key][idx] = issue
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(issue)
			return
		}
	}

	// POST /api/v1/repos/:owner/:repo/pulls
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/repos/") && strings.HasSuffix(path, "/pulls") {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/repos/"), "/pulls"), "/")
		if len(parts) == 2 {
			key := parts[0] + "/" + parts[1]
			if _, ok := f.repos[key]; !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			idx := f.next
			f.next++
			if f.pulls[key] == nil {
				f.pulls[key] = map[int64]PullRequest{}
			}
			pr := PullRequest{ID: idx, Index: idx, Number: idx, Title: body["title"].(string), State: "open", HTMLURL: "https://git.example/" + key + "/pulls/" + fmt.Sprint(idx)}
			f.pulls[key][idx] = pr
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(pr)
			return
		}
	}

	// POST /api/v1/repos/:owner/:repo/issues/:index/comments
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/repos/") && strings.HasSuffix(path, "/comments") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
		if len(parts) == 5 && parts[2] == "issues" && parts[4] == "comments" {
			key := parts[0] + "/" + parts[1]
			idx := int64(0)
			fmt.Sscan(parts[3], &idx)
			if _, ok := f.issues[key][idx]; !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			comment := IssueComment{ID: int64(len(f.comments[key][idx]) + 1), Body: body["body"].(string)}
			if f.comments[key] == nil {
				f.comments[key] = map[int64][]IssueComment{}
			}
			f.comments[key][idx] = append(f.comments[key][idx], comment)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(comment)
			return
		}
	}

	// PATCH /api/v1/repos/:owner/:repo/issues/:index
	if r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/repos/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
		if len(parts) == 4 && parts[2] == "issues" {
			key := parts[0] + "/" + parts[1]
			idx := int64(0)
			fmt.Sscan(parts[3], &idx)
			issue, ok := f.issues[key][idx]
			if !ok {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			issue.State, _ = body["state"].(string)
			f.issues[key][idx] = issue
			json.NewEncoder(w).Encode(issue)
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

	// GET /api/v1/users/:login
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/") {
		login := strings.TrimPrefix(path, "/api/v1/users/")
		user, ok := f.users[login]
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(user)
		return
	}

	// POST /api/v1/admin/users
	if r.Method == http.MethodPost && path == "/api/v1/admin/users" {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		login, _ := body["login"].(string)
		if _, exists := f.users[login]; exists {
			http.Error(w, `{"message":"user already exists"}`, http.StatusUnprocessableEntity)
			return
		}
		email, _ := body["email"].(string)
		id := f.next
		f.next++
		f.users[login] = fakeUser{ID: id, Login: login, Email: email}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(f.users[login])
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

func TestGetUserFound(t *testing.T) {
	g := newFakeGitea()
	g.users = map[string]fakeUser{"alice": {ID: 42, Login: "alice", Email: "alice@example.com"}}
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	user, err := c.GetUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.ID != 42 {
		t.Errorf("expected ID=42, got %d", user.ID)
	}
	if user.Login != "alice" {
		t.Errorf("expected Login='alice', got %q", user.Login)
	}
}

func TestGetUserNotFound(t *testing.T) {
	g := newFakeGitea()
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	_, err := c.GetUser(context.Background(), "nobody")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !IsNotFound(err) {
		t.Errorf("expected IsNotFound=true, got false for %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	g := newFakeGitea()
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	user, err := c.CreateUser(context.Background(), "bob", "bob@example.com", "secret123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Login != "bob" {
		t.Errorf("expected Login='bob', got %q", user.Login)
	}
	if user.ID == 0 {
		t.Error("expected non-zero user ID")
	}
}

func TestCreateUserConflict(t *testing.T) {
	g := newFakeGitea()
	g.users = map[string]fakeUser{"bob": {ID: 10, Login: "bob", Email: "bob@example.com"}}
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	_, err := c.CreateUser(context.Background(), "bob", "bob2@example.com", "secret123")
	if err == nil {
		t.Fatal("expected error for duplicate user")
	}
}

func TestIsNotFoundExported(t *testing.T) {
	if IsNotFound(nil) {
		t.Error("nil should not be not-found")
	}
	if !IsNotFound(&HTTPError{StatusCode: 404}) {
		t.Error("404 should be not-found")
	}
	if IsNotFound(&HTTPError{StatusCode: 500}) {
		t.Error("500 should not be not-found")
	}
}

func TestCreatePullRequest(t *testing.T) {
	g := newFakeGitea()
	g.repos["org1/repo1"] = 10
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	pr, err := c.CreatePullRequest(context.Background(), "org1", "repo1", "nostr-pr", "main", "from nostr", "body")
	if err != nil {
		t.Fatalf("CreatePullRequest: %v", err)
	}
	if pr.Index == 0 || pr.Number != pr.Index || pr.Title != "from nostr" || pr.State != "open" || pr.HTMLURL == "" {
		t.Fatalf("unexpected pull request: %+v", pr)
	}
}

func TestIssueAPIs(t *testing.T) {
	g := newFakeGitea()
	g.repos["org1/repo1"] = 10
	ts := httptest.NewServer(g)
	defer ts.Close()

	c := NewClient(ts.URL, "tok")
	ctx := context.Background()
	issue, err := c.CreateIssue(ctx, "org1", "repo1", "from nostr", "body")
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Index == 0 || issue.Title != "from nostr" || issue.State != "open" {
		t.Fatalf("unexpected issue: %+v", issue)
	}

	comment, err := c.CreateIssueComment(ctx, "org1", "repo1", issue.Index, "comment body")
	if err != nil {
		t.Fatalf("CreateIssueComment: %v", err)
	}
	if comment.Body != "comment body" {
		t.Fatalf("comment body = %q", comment.Body)
	}

	updated, err := c.SetIssueState(ctx, "org1", "repo1", issue.Index, "closed")
	if err != nil {
		t.Fatalf("SetIssueState: %v", err)
	}
	if updated.State != "closed" {
		t.Fatalf("state = %q", updated.State)
	}
}

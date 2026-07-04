// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package reflector

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/echofp"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type reflectorFakeGitea struct {
	mu       sync.Mutex
	next     int64
	issues   map[int64]gitea.Issue
	pulls    map[int64]reflectorPR
	comments map[int64][]string
}

type reflectorPR struct {
	gitea.PullRequest
	Head string
	Base string
	Body string
}

func newReflectorFakeGitea() *reflectorFakeGitea {
	return &reflectorFakeGitea{next: 1, issues: map[int64]gitea.Issue{}, pulls: map[int64]reflectorPR{}, comments: map[int64][]string{}}
}

func (f *reflectorFakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/repos/"), "/")
	if len(parts) < 3 || parts[0] != "org1" || parts[1] != "repo1" {
		http.NotFound(w, r)
		return
	}

	if parts[2] == "pulls" && r.Method == http.MethodPost && len(parts) == 3 {
		var body struct {
			Head  string `json:"head"`
			Base  string `json:"base"`
			Title string `json:"title"`
			Body  string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		idx := f.next
		f.next++
		pr := reflectorPR{
			PullRequest: gitea.PullRequest{ID: idx, Index: idx, Number: idx, Title: body.Title, State: "open", HTMLURL: "https://git.example/org1/repo1/pulls/" + strconv.FormatInt(idx, 10)},
			Head:        body.Head,
			Base:        body.Base,
			Body:        body.Body,
		}
		f.pulls[idx] = pr
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pr.PullRequest)
		return
	}

	if parts[2] != "issues" {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodPost && len(parts) == 3 {
		var body struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		idx := f.next
		f.next++
		issue := gitea.Issue{ID: idx, Index: idx, Number: idx, Title: body.Title, Body: body.Body, State: "open"}
		f.issues[idx] = issue
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(issue)
		return
	}

	if len(parts) >= 4 {
		idx, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		issue, ok := f.issues[idx]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 5 && parts[4] == "comments" {
			var body struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.comments[idx] = append(f.comments[idx], body.Body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(gitea.IssueComment{ID: int64(len(f.comments[idx])), Body: body.Body})
			return
		}
		if r.Method == http.MethodPatch && len(parts) == 4 {
			var body struct {
				State string `json:"state"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			issue.State = body.State
			f.issues[idx] = issue
			_ = json.NewEncoder(w).Encode(issue)
			return
		}
	}

	http.NotFound(w, r)
}

func TestReflectorReflectsIssueCommentStatusAndDedupes(t *testing.T) {
	ctx := context.Background()
	st, mapping, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	actorPriv := nostr.GeneratePrivateKey()

	issueEv := signedEvent(t, actorPriv, relay.KindIssue, nostr.Tags{
		{"a", coord},
		{"subject", "Nostr issue title"},
	}, "issue body")
	if err := r.HandleEvent(ctx, issueEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect issue: %v", err)
	}

	fake.mu.Lock()
	if len(fake.issues) != 1 {
		t.Fatalf("expected 1 Gitea issue, got %d", len(fake.issues))
	}
	if got := fake.issues[1].Title; got != "Nostr issue title" {
		t.Fatalf("issue title = %q", got)
	}
	fake.mu.Unlock()

	ref, err := st.GetReflectedEvent(ctx, issueEv.ID)
	if err != nil {
		t.Fatalf("get reflected issue row: %v", err)
	}
	if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 1 || ref.Kind != relay.KindIssue || ref.EchoFingerprint != echofp.Issue("Nostr issue title", "issue body") {
		t.Fatalf("unexpected reflected issue row: %+v", ref)
	}

	commentEv := signedEvent(t, actorPriv, relay.KindNIP22Comment, nostr.Tags{
		{"a", coord},
		{"E", issueEv.ID, "", "root"},
		{"K", strconv.Itoa(relay.KindIssue)},
	}, "comment body")
	if err := r.HandleEvent(ctx, commentEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect comment: %v", err)
	}
	fake.mu.Lock()
	if got := fake.comments[1]; len(got) != 1 || got[0] != "comment body" {
		t.Fatalf("comments = %#v", got)
	}
	fake.mu.Unlock()

	statusEv := signedEvent(t, actorPriv, relay.KindStatusClosed, nostr.Tags{
		{"a", coord},
		{"e", issueEv.ID, "", "root"},
	}, "")
	if err := r.HandleEvent(ctx, statusEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect status: %v", err)
	}
	fake.mu.Lock()
	if got := fake.issues[1].State; got != "closed" {
		t.Fatalf("issue state = %q", got)
	}
	fake.mu.Unlock()

	if _, err := st.RecordNostrObjectMapping(ctx, store.ReflectedEvent{
		NostrEventID: "gitea-origin-root",
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   1,
		Kind:         relay.KindIssue,
	}); err != nil {
		t.Fatalf("record gitea-origin root mapping: %v", err)
	}
	giteaRootComment := signedEvent(t, actorPriv, relay.KindNIP22Comment, nostr.Tags{
		{"a", coord},
		{"E", "gitea-origin-root", "", "root"},
	}, "comment on gitea-origin root")
	if err := r.HandleEvent(ctx, giteaRootComment, "wss://relay.test"); err != nil {
		t.Fatalf("reflect comment on gitea-origin root: %v", err)
	}
	fake.mu.Lock()
	if got := fake.comments[1]; len(got) != 2 || got[1] != "comment on gitea-origin root" {
		t.Fatalf("comments after gitea-origin root comment = %#v", got)
	}
	fake.mu.Unlock()

	unknownEv := signedEvent(t, actorPriv, relay.KindIssue, nostr.Tags{
		{"a", "30617:" + mapping.Pubkey + ":unknown"},
		{"subject", "ignored"},
	}, "ignored")
	if err := r.HandleEvent(ctx, unknownEv, "wss://relay.test"); err != nil {
		t.Fatalf("unknown repo event should be ignored: %v", err)
	}
	fake.mu.Lock()
	if len(fake.issues) != 1 {
		t.Fatalf("unknown repo should not create an issue, got %d issues", len(fake.issues))
	}
	fake.mu.Unlock()

	if err := r.HandleEvent(ctx, issueEv, "wss://relay.test"); err != nil {
		t.Fatalf("duplicate issue event should be ignored: %v", err)
	}
	fake.mu.Lock()
	if len(fake.issues) != 1 {
		t.Fatalf("duplicate issue should not create another issue, got %d", len(fake.issues))
	}
	fake.mu.Unlock()
}

func TestReflectorTipPatchCreatesPullRequest(t *testing.T) {
	for _, kind := range []int{relay.KindPatch, relay.KindPROpen} {
		t.Run(strconv.Itoa(kind), func(t *testing.T) {
			ctx := context.Background()
			st, mapping, coord := newReflectorTestStore(t)
			repo := setupReflectorGitRepo(t)
			fake := newReflectorFakeGitea()
			ts := httptest.NewServer(fake)
			defer ts.Close()

			r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
			actorPriv := nostr.GeneratePrivateKey()
			ev := signedEvent(t, actorPriv, kind, nostr.Tags{
				{"a", coord},
				{"subject", "Tip PR"},
				{"c", repo.tip},
				{"clone", repo.workDir},
				{"branch-name", "feature/tip"},
			}, "tip body")

			if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
				t.Fatalf("reflect tip patch: %v", err)
			}
			fake.mu.Lock()
			if len(fake.pulls) != 1 {
				fake.mu.Unlock()
				t.Fatalf("expected 1 PR, got %d", len(fake.pulls))
			}
			pr := fake.pulls[1]
			fake.mu.Unlock()
			if pr.Head != "feature/tip" || pr.Base != "main" || pr.Title != "Tip PR" {
				t.Fatalf("unexpected PR request: %+v", pr)
			}
			if !strings.Contains(pr.Body, ev.ID) {
				t.Fatalf("PR body missing source event id: %q", pr.Body)
			}

			gotTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/feature/tip"))
			if gotTip != repo.tip {
				t.Fatalf("head branch tip = %s, want %s", gotTip, repo.tip)
			}
			ref, err := st.GetReflectedEvent(ctx, ev.ID)
			if err != nil {
				t.Fatalf("get reflected PR row: %v", err)
			}
			if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 1 || ref.HeadBranch != "feature/tip" || ref.Kind != relay.KindPROpen {
				t.Fatalf("unexpected reflected row: %+v", ref)
			}
		})
	}
}

func TestReflectorPRUpdateMovesExistingHeadBranchAndRecordsEchoGuard(t *testing.T) {
	ctx := context.Background()
	st, mapping, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rootID := "reflected-pr-root"
	headBranch := "feature/tip"
	if err := gitFetch(ctx, repo.repoPath, repo.workDir, "+"+repo.tip+":refs/heads/"+headBranch); err != nil {
		t.Fatalf("seed PR head branch: %v", err)
	}
	if _, err := st.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID: rootID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   7,
		HeadBranch:   headBranch,
		Kind:         relay.KindPROpen,
	}); err != nil {
		t.Fatalf("record reflected root PR: %v", err)
	}

	if err := os.WriteFile(filepath.Join(repo.workDir, "README.md"), []byte("root\nfeature\nrevision\n"), 0o644); err != nil {
		t.Fatalf("write revised README: %v", err)
	}
	reflectorGit(t, repo.workDir, "add", "README.md")
	reflectorGit(t, repo.workDir, "commit", "-m", "revision")
	newTip := strings.TrimSpace(reflectorGitOutput(t, repo.workDir, "rev-parse", "HEAD"))

	actorPriv := nostr.GeneratePrivateKey()
	updateEv := signedEvent(t, actorPriv, relay.KindPRUpdate, nostr.Tags{
		{"a", coord},
		{"E", rootID},
		{"P", mapping.Pubkey},
		{"c", newTip},
		{"clone", repo.workDir},
	}, "")

	if err := r.HandleEvent(ctx, updateEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect PR update: %v", err)
	}
	gotTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/"+headBranch))
	if gotTip != newTip {
		t.Fatalf("head branch tip = %s, want %s", gotTip, newTip)
	}
	ref, err := st.GetReflectedEvent(ctx, updateEv.ID)
	if err != nil {
		t.Fatalf("get reflected PR update row: %v", err)
	}
	if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 7 || ref.HeadBranch != headBranch || ref.Kind != relay.KindPRUpdate || ref.EchoFingerprint != echofp.PRUpdate(newTip) {
		t.Fatalf("unexpected reflected PR update row: %+v", ref)
	}
	matched, err := st.CheckReflectedGiteaEcho(ctx, mapping.GiteaRepoID, 7, relay.KindPRUpdate, echofp.PRUpdate(newTip), time.Now().UTC(), store.DefaultEchoGuardWindow)
	if err != nil {
		t.Fatalf("check reflected PR-update echo: %v", err)
	}
	if !matched {
		t.Fatal("expected PR-update reflected row to arm echo guard")
	}
}

func TestReflectorPRUpdateUnknownRootIsIgnored(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	headBranch := "feature/tip"
	if err := gitFetch(ctx, repo.repoPath, repo.workDir, "+"+repo.tip+":refs/heads/"+headBranch); err != nil {
		t.Fatalf("seed PR head branch: %v", err)
	}
	actorPriv := nostr.GeneratePrivateKey()
	updateEv := signedEvent(t, actorPriv, relay.KindPRUpdate, nostr.Tags{
		{"a", coord},
		{"E", "unknown-root"},
		{"c", repo.tip},
		{"clone", repo.workDir},
	}, "")

	if err := r.HandleEvent(ctx, updateEv, "wss://relay.test"); err != nil {
		t.Fatalf("unknown-root PR update should be ignored: %v", err)
	}
	gotTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/"+headBranch))
	if gotTip != repo.tip {
		t.Fatalf("head branch changed to %s, want unchanged %s", gotTip, repo.tip)
	}
	if _, err := st.GetReflectedEvent(ctx, updateEv.ID); err != sql.ErrNoRows {
		t.Fatalf("unexpected reflected row for ignored PR update: %v", err)
	}
	processed, err := st.EventProcessed(ctx, updateEv.ID)
	if err != nil {
		t.Fatalf("check processed: %v", err)
	}
	if processed {
		t.Fatal("ignored unknown-root PR update should not be marked processed")
	}
}

func TestReflectorExistingBranchNameFallsBackToEventBranch(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	actorPriv := nostr.GeneratePrivateKey()
	ev := signedEvent(t, actorPriv, relay.KindPROpen, nostr.Tags{
		{"a", coord},
		{"subject", "Do not overwrite main"},
		{"c", repo.tip},
		{"clone", repo.workDir},
		{"branch-name", "main"},
	}, "tip body")

	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
		t.Fatalf("reflect protected branch patch: %v", err)
	}
	wantHead := "nostr-pr-" + ev.ID[:12]
	fake.mu.Lock()
	pr := fake.pulls[1]
	fake.mu.Unlock()
	if pr.Head != wantHead || pr.Base != "main" {
		t.Fatalf("PR head/base = %q/%q, want %q/main", pr.Head, pr.Base, wantHead)
	}
	mainTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/main"))
	if mainTip != repo.base {
		t.Fatalf("main was moved to %s, want base %s", mainTip, repo.base)
	}
	fallbackTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/"+wantHead))
	if fallbackTip != repo.tip {
		t.Fatalf("fallback branch tip = %s, want %s", fallbackTip, repo.tip)
	}
}

func TestReflectorContentPatchAppliesAndCreatesPullRequest(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	patch := reflectorGitOutput(t, repo.workDir, "format-patch", "-1", "--stdout", "HEAD")
	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	actorPriv := nostr.GeneratePrivateKey()
	ev := signedEvent(t, actorPriv, relay.KindPatch, nostr.Tags{
		{"a", coord},
		{"subject", "Content patch"},
		{"branch-name", "content patch"},
	}, patch)

	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
		t.Fatalf("reflect content patch: %v", err)
	}
	fake.mu.Lock()
	if len(fake.pulls) != 1 {
		fake.mu.Unlock()
		t.Fatalf("expected 1 PR, got %d", len(fake.pulls))
	}
	pr := fake.pulls[1]
	fake.mu.Unlock()
	if pr.Head != "content-patch" || pr.Base != "main" || pr.Title != "Content patch" {
		t.Fatalf("unexpected PR request: %+v", pr)
	}
	readme := reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "show", "refs/heads/content-patch:README.md")
	if !strings.Contains(readme, "feature") {
		t.Fatalf("applied branch README = %q, want feature change", readme)
	}
	ref, err := st.GetReflectedEvent(ctx, ev.ID)
	if err != nil {
		t.Fatalf("get reflected content PR row: %v", err)
	}
	if ref.GiteaIndex != 1 || ref.Kind != relay.KindPROpen {
		t.Fatalf("unexpected reflected content row: %+v", ref)
	}
}

func TestReflectorGarbagePatchFallsBackAndCleansWorktree(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	actorPriv := nostr.GeneratePrivateKey()
	garbage := "From bad patch\n\ndiff --git a/README.md b/README.md\nthis is not a valid patch\n"
	ev := signedEvent(t, actorPriv, relay.KindPatch, nostr.Tags{
		{"a", coord},
		{"subject", "Bad patch"},
		{"branch-name", "bad-patch"},
	}, garbage)

	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
		t.Fatalf("garbage patch should fall back without crashing: %v", err)
	}
	fake.mu.Lock()
	if len(fake.pulls) != 0 {
		fake.mu.Unlock()
		t.Fatalf("garbage patch created PRs: %#v", fake.pulls)
	}
	fake.mu.Unlock()
	ref, err := st.GetReflectedEvent(ctx, ev.ID)
	if err != nil {
		t.Fatalf("get reflected fallback row: %v", err)
	}
	if ref.GiteaIndex != 0 || ref.Kind != relay.KindPatch {
		t.Fatalf("unexpected fallback reflected row: %+v", ref)
	}
	worktrees := reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "worktree", "list", "--porcelain")
	if got := strings.Count(worktrees, "worktree "); got != 1 {
		t.Fatalf("dangling worktrees after failed patch: count=%d output=%s", got, worktrees)
	}
}

func TestReflectorRejectsUnverifiedEvent(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	priv := nostr.GeneratePrivateKey()
	ev := signedEvent(t, priv, relay.KindIssue, nostr.Tags{{"a", coord}, {"subject", "tampered"}}, "before")
	ev.Content = "after"
	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err == nil {
		t.Fatal("expected invalid signature error")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.issues) != 0 {
		t.Fatalf("unverified event created %d issues", len(fake.issues))
	}
}

func newReflectorTestStore(t *testing.T) (*store.SQLiteStore, store.Mapping, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ownerPriv := nostr.GeneratePrivateKey()
	ownerPub, err := nostr.GetPublicKey(ownerPriv)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	mapping := store.Mapping{
		Npub:          "npub1owner",
		RepoID:        "repo1",
		Pubkey:        ownerPub,
		Owner:         "org1",
		RepoName:      "repo1",
		GiteaRepoID:   42,
		CloneURL:      "https://git.example/org1/repo1.git",
		SourceEvent:   "seed",
		HookInstalled: true,
	}
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	coord := "30617:" + ownerPub + ":" + mapping.RepoID
	return st, mapping, coord
}

type reflectorGitRepo struct {
	repositoriesDir string
	repoPath        string
	workDir         string
	base            string
	tip             string
}

func setupReflectorGitRepo(t *testing.T) reflectorGitRepo {
	t.Helper()
	tmp := t.TempDir()
	work := filepath.Join(tmp, "work")
	repositoriesDir := filepath.Join(tmp, "git", "repositories")
	repoPath := filepath.Join(repositoriesDir, "org1", "repo1.git")
	reflectorGit(t, tmp, "init", "-b", "main", work)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("root\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	reflectorGit(t, work, "add", "README.md")
	reflectorGit(t, work, "commit", "-m", "root")
	base := strings.TrimSpace(reflectorGitOutput(t, work, "rev-parse", "HEAD"))
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("mkdir repo parent: %v", err)
	}
	reflectorGit(t, tmp, "clone", "--bare", work, repoPath)

	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("root\nfeature\n"), 0o644); err != nil {
		t.Fatalf("write feature README: %v", err)
	}
	reflectorGit(t, work, "add", "README.md")
	reflectorGit(t, work, "commit", "-m", "feature")
	tip := strings.TrimSpace(reflectorGitOutput(t, work, "rev-parse", "HEAD"))
	return reflectorGitRepo{repositoriesDir: repositoriesDir, repoPath: repoPath, workDir: work, base: base, tip: tip}
}

func reflectorGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = reflectorGitOutput(t, dir, args...)
}

func reflectorGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.com",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed in %s: %v\n%s", strings.Join(args, " "), dir, err, string(out))
	}
	return string(out)
}

func signedEvent(t *testing.T, priv string, kind int, tags nostr.Tags, content string) *nostr.Event {
	t.Helper()
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	ev := &nostr.Event{
		PubKey:    pub,
		Kind:      kind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
		Content:   content,
	}
	if err := ev.Sign(priv); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

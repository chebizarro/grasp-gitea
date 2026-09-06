// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package reflector

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	"fiatjaf.com/nostr"

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
	labels   map[int64][]gitea.Label
}

type reflectorPR struct {
	gitea.PullRequest
	Head    string
	HeadSHA string
	Base    string
	Body    string
	Creator string
}

type alwaysUnprocessedStore struct {
	Store
}

func (s alwaysUnprocessedStore) EventProcessed(context.Context, string) (bool, error) {
	return false, nil
}

type losingProposalStore struct {
	store.ProposalStore
}

func (s losingProposalStore) UpsertProposal(context.Context, store.ProposalState) (bool, error) {
	return false, nil
}

type reflectorFakePublisher struct {
	mu     sync.Mutex
	events []*nostr.Event
}

func (p *reflectorFakePublisher) PublishEvent(ctx context.Context, ev *nostr.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	clone := *ev
	clone.Tags = append(nostr.Tags(nil), ev.Tags...)
	p.events = append(p.events, &clone)
	return nil
}

func (p *reflectorFakePublisher) published() []*nostr.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*nostr.Event, len(p.events))
	copy(out, p.events)
	return out
}

func newReflectorFakeGitea() *reflectorFakeGitea {
	return &reflectorFakeGitea{
		next: 1, issues: map[int64]gitea.Issue{}, pulls: map[int64]reflectorPR{},
		comments: map[int64][]string{}, labels: map[int64][]gitea.Label{},
	}
}

func (f *reflectorFakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/repos/"), "/")
	if len(parts) < 3 || parts[0] != "org1" || parts[1] != "repo1" {
		http.NotFound(w, r)
		return
	}

	if parts[2] == "pulls" && r.Method == http.MethodGet && len(parts) == 3 {
		var rows []map[string]any
		for _, pr := range f.pulls {
			rows = append(rows, map[string]any{"id": pr.ID, "index": pr.Index, "number": pr.Number, "title": pr.Title, "body": pr.Body, "state": pr.State, "html_url": pr.HTMLURL, "user": map[string]any{"login": pr.Creator}, "head": map[string]any{"ref": pr.Head, "sha": pr.HeadSHA}, "base": map[string]any{"ref": pr.Base}})
		}
		_ = json.NewEncoder(w).Encode(rows)
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
			Creator:     "admin",
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
			if pr, exists := f.pulls[idx]; exists {
				issue = gitea.Issue{ID: pr.ID, Index: pr.Index, Number: pr.Number, Title: pr.Title, Body: pr.Body, State: pr.State}
				ok = true
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 5 && parts[4] == "labels" {
			switch r.Method {
			case http.MethodPost:
				var body struct {
					Labels []string `json:"labels"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				for _, name := range body.Labels {
					f.labels[idx] = append(f.labels[idx], gitea.Label{ID: int64(len(f.labels[idx]) + 1), Name: name})
				}
				_ = json.NewEncoder(w).Encode(f.labels[idx])
				return
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(f.labels[idx])
				return
			}
		}
		if r.Method == http.MethodDelete && len(parts) == 6 && parts[4] == "labels" {
			labelID, _ := strconv.ParseInt(parts[5], 10, 64)
			labels := f.labels[idx]
			for i, label := range labels {
				if label.ID == labelID {
					f.labels[idx] = append(labels[:i], labels[i+1:]...)
					break
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 5 && parts[4] == "comments" {
			rows := make([]gitea.IssueComment, 0, len(f.comments[idx]))
			for i, body := range f.comments[idx] {
				rows = append(rows, gitea.IssueComment{ID: int64(i + 1), Body: body})
			}
			_ = json.NewEncoder(w).Encode(rows)
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
			if pr, exists := f.pulls[idx]; exists {
				pr.State = body.State
				f.pulls[idx] = pr
			} else {
				f.issues[idx] = issue
			}
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
	r.SetStatusSyncEnabled(true)
	actorPriv := nostr.Generate().Hex()

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

	ref, err := st.GetReflectedEvent(ctx, issueEv.ID.Hex())
	if err != nil {
		t.Fatalf("get reflected issue row: %v", err)
	}
	if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 1 || ref.Kind != relay.KindIssue || ref.EchoFingerprint != echofp.Issue("Nostr issue title", "issue body") {
		t.Fatalf("unexpected reflected issue row: %+v", ref)
	}

	// Recreate the reflector to prove the root-only NIP-22 comment resolves from
	// durable state rather than the old process-local thread map.
	restarted := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	commentEv := signedEvent(t, actorPriv, relay.KindNIP22Comment, nostr.Tags{
		{"E", issueEv.ID.Hex(), "", issueEv.PubKey.Hex()},
		{"K", strconv.Itoa(relay.KindIssue)},
	}, "comment body")
	if err := restarted.HandleEvent(ctx, commentEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect comment: %v", err)
	}
	fake.mu.Lock()
	if got := fake.comments[1]; len(got) != 1 || got[0] != "comment body" {
		t.Fatalf("comments = %#v", got)
	}
	fake.mu.Unlock()

	statusEv := signedEvent(t, actorPriv, relay.KindStatusClosed, nostr.Tags{
		{"a", coord},
		{"e", issueEv.ID.Hex(), "", "root"},
	}, "")
	if err := r.HandleEvent(ctx, statusEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect status: %v", err)
	}
	fake.mu.Lock()
	if got := fake.issues[1].State; got != "closed" {
		t.Fatalf("issue state = %q", got)
	}
	fake.mu.Unlock()

	openEv := signedEvent(t, actorPriv, relay.KindStatusOpen, nostr.Tags{{"a", coord}, {"e", issueEv.ID.Hex(), "", "root"}}, "")
	if err := r.HandleEvent(ctx, openEv, "wss://relay.test"); err != nil {
		t.Fatalf("reflect open status: %v", err)
	}
	fake.mu.Lock()
	if got := fake.issues[1].State; got != "open" {
		t.Fatalf("issue state after open = %q", got)
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

func TestReflectorRejectsUnauthorizedIssueClose(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetStatusSyncEnabled(true)
	authorPriv := nostr.Generate().Hex()
	issueEv := signedEvent(t, authorPriv, relay.KindIssue, nostr.Tags{
		{"a", coord},
		{"subject", "authorization regression"},
	}, "must remain open")
	if err := r.HandleEvent(ctx, issueEv, ""); err != nil {
		t.Fatalf("reflect issue: %v", err)
	}

	attackerPriv := nostr.Generate().Hex()
	closeEv := signedEvent(t, attackerPriv, relay.KindStatusClosed, nostr.Tags{
		{"a", coord},
		{"e", issueEv.ID.Hex(), "", "root"},
	}, "")
	if err := r.HandleEvent(ctx, closeEv, ""); err != nil {
		t.Fatalf("unauthorized status should be rejected without poisoning subscriber: %v", err)
	}

	fake.mu.Lock()
	state := fake.issues[1].State
	fake.mu.Unlock()
	if state != "open" {
		t.Fatalf("unauthorized close changed issue state to %q", state)
	}
	processed, err := st.EventProcessed(ctx, closeEv.ID.Hex())
	if err != nil {
		t.Fatalf("check rejected event dedupe: %v", err)
	}
	if !processed {
		t.Fatal("rejected unauthorized status was not durably deduplicated")
	}
}

func TestReflectorAppliesAndRemovesInboundNIP32Label(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	actorPriv := nostr.Generate().Hex()
	issueEv := signedEvent(t, actorPriv, relay.KindIssue, nostr.Tags{
		{"a", coord},
		{"subject", "label target"},
	}, "")
	if err := r.HandleEvent(ctx, issueEv, ""); err != nil {
		t.Fatalf("reflect issue: %v", err)
	}

	addEv := signedEvent(t, actorPriv, relay.KindNIP32Label, nostr.Tags{
		{"a", coord},
		{"e", issueEv.ID.Hex(), "", "root"},
		{"L", "gitea/label"},
		{"l", "bug", "gitea/label"},
		{"action", "apply"},
	}, "")
	if err := r.HandleEvent(ctx, addEv, ""); err != nil {
		t.Fatalf("reflect label apply: %v", err)
	}
	fake.mu.Lock()
	if got := fake.labels[1]; len(got) != 1 || got[0].Name != "bug" {
		fake.mu.Unlock()
		t.Fatalf("labels after apply = %#v", got)
	}
	fake.mu.Unlock()

	removeEv := signedEvent(t, actorPriv, relay.KindNIP32Label, nostr.Tags{
		{"a", coord},
		{"e", issueEv.ID.Hex(), "", "root"},
		{"L", "gitea/label"},
		{"l", "bug", "gitea/label"},
		{"action", "remove"},
	}, "")
	if err := r.HandleEvent(ctx, removeEv, ""); err != nil {
		t.Fatalf("reflect label removal: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.labels[1]; len(got) != 0 {
		t.Fatalf("labels after removal = %#v", got)
	}
}

func TestProposalPermissionLogIncludesRepositoryOwnershipDiagnosis(t *testing.T) {
	var logs bytes.Buffer
	r := &Reflector{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	r.SetOwnershipDiagnoser(func(string) string { return "root-owned objects path uid=0 gid=0 expected_uid=1000 expected_gid=1000" })
	mapping := store.Mapping{Pubkey: strings.Repeat("a", 64), RepoID: "project", Owner: "org", RepoName: "hosted"}
	r.logRepositoryFailure("proposal failed", mapping, "/repos/org/hosted.git", strings.Repeat("b", 64), errors.New("insufficient permission for adding an object"))
	for _, want := range []string{"repo_address=30617:" + mapping.Pubkey + ":project", "repo_path=/repos/org/hosted.git", "ownership_mismatch=\"root-owned objects", "insufficient permission"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("permission log missing %q:\n%s", want, logs.String())
		}
	}
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
			r.validateGitCloneURL = func(context.Context, string) error { return nil }
			actorPriv := nostr.Generate().Hex()
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
			wantHead := "feature/tip"
			if kind == relay.KindPatch {
				wantHead = "nostr-proposal-" + ev.ID.Hex()
			}
			if pr.Head != wantHead || pr.Base != "main" || pr.Title != "Tip PR" {
				t.Fatalf("unexpected PR request: %+v", pr)
			}
			if !strings.Contains(pr.Body, ev.ID.Hex()) {
				t.Fatalf("PR body missing source event id: %q", pr.Body)
			}

			gotTip := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/"+wantHead))
			if gotTip != repo.tip {
				t.Fatalf("head branch tip = %s, want %s", gotTip, repo.tip)
			}
			ref, err := st.GetReflectedEvent(ctx, ev.ID.Hex())
			if err != nil {
				t.Fatalf("get reflected PR row: %v", err)
			}
			if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 1 || ref.HeadBranch != wantHead || ref.Kind != relay.KindPROpen {
				t.Fatalf("unexpected reflected row: %+v", ref)
			}
		})
	}
}

func TestReflectorKind1617ProposalIsIdempotentAndRevisionUpdatesPR(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	actorPriv := nostr.Generate().Hex()
	root := signedEvent(t, actorPriv, relay.KindPatch, nostr.Tags{
		{"a", coord}, {"t", "root"}, {"subject", "Astillero-style proposal"},
		{"commit", repo.tip}, {"clone", repo.workDir}, {"branch-name", "proposal/fix"},
	}, "proposal body")
	if err := r.HandleEvent(ctx, root, "wss://relay.test"); err != nil {
		t.Fatalf("root proposal: %v", err)
	}
	if err := r.HandleEvent(ctx, root, "wss://relay.test"); err != nil {
		t.Fatalf("root replay: %v", err)
	}
	fake.mu.Lock()
	if len(fake.pulls) != 1 {
		t.Fatalf("root replay created %d PRs", len(fake.pulls))
	}
	body := fake.pulls[1].Body
	fake.mu.Unlock()
	for _, want := range []string{"nostr:nevent1", "nostr:naddr1", root.ID.Hex(), coord} {
		if !strings.Contains(body, want) {
			t.Errorf("PR body missing %q: %s", want, body)
		}
	}

	_ = os.WriteFile(filepath.Join(repo.workDir, "revision.txt"), []byte("revision\n"), 0o644)
	reflectorGitOutput(t, repo.workDir, "add", "revision.txt")
	reflectorGitOutput(t, repo.workDir, "commit", "-m", "proposal revision")
	tip2 := strings.TrimSpace(reflectorGitOutput(t, repo.workDir, "rev-parse", "HEAD"))
	update := signedEvent(t, actorPriv, relay.KindPatch, nostr.Tags{
		{"a", coord}, {"e", root.ID.Hex(), "", "reply"}, {"t", "root-revision"},
		{"commit", tip2}, {"clone", repo.workDir},
	}, "")
	update.CreatedAt = root.CreatedAt + 1
	if err := update.Sign(mustSK(actorPriv)); err != nil {
		t.Fatal(err)
	}
	if err := r.HandleEvent(ctx, update, "wss://relay.test"); err != nil {
		t.Fatalf("proposal revision: %v", err)
	}
	if err := r.HandleEvent(ctx, update, "wss://relay.test"); err != nil {
		t.Fatalf("revision replay: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.pulls) != 1 {
		t.Fatalf("revision created %d PRs", len(fake.pulls))
	}
	if got := fake.comments[1]; len(got) != 1 || !strings.Contains(got[0], update.ID.Hex()) {
		t.Fatalf("revision comments = %#v", got)
	}
	if got := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/nostr-proposal-"+root.ID.Hex())); got != tip2 {
		t.Fatalf("proposal head=%s want %s", got, tip2)
	}
	state, err := st.GetProposal(ctx, coord, root.ID.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if state.LatestEventID != update.ID.Hex() || state.HeadRefSHA != tip2 || state.GiteaPRNumber != 1 {
		t.Fatalf("proposal state = %+v", state)
	}
}

func TestReflectorRejectsForeignSignerProposalRevisionWithoutMovingHead(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.validateGitCloneURL = func(context.Context, string) error { return nil }

	submitter := nostr.Generate().Hex()
	root := signedEvent(t, submitter, relay.KindPatch, nostr.Tags{{"a", coord}, {"commit", repo.tip}, {"clone", repo.workDir}}, "root")
	if err := r.HandleEvent(ctx, root, "wss://relay.test"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(repo.workDir, "attack.txt"), []byte("attack\n"), 0o644)
	reflectorGitOutput(t, repo.workDir, "add", "attack.txt")
	reflectorGitOutput(t, repo.workDir, "commit", "-m", "attacker revision")
	attackTip := strings.TrimSpace(reflectorGitOutput(t, repo.workDir, "rev-parse", "HEAD"))
	attacker := nostr.Generate().Hex()
	revision := signedEvent(t, attacker, relay.KindPatch, nostr.Tags{{"a", coord}, {"e", root.ID.Hex(), "", "reply"}, {"t", "root"}, {"t", "root-revision"}, {"commit", attackTip}, {"clone", repo.workDir}}, "")
	revision.CreatedAt = root.CreatedAt + 1
	if err := revision.Sign(mustSK(attacker)); err != nil {
		t.Fatal(err)
	}
	err := r.HandleEvent(ctx, revision, "wss://relay.test")
	var materializationErr *MaterializationError
	if !errors.As(err, &materializationErr) || materializationErr.FailureClass != "unauthorized-author" {
		t.Fatalf("foreign revision error = %v", err)
	}
	got := strings.TrimSpace(reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "rev-parse", "refs/heads/nostr-proposal-"+root.ID.Hex()))
	if got != repo.tip {
		t.Fatalf("foreign revision moved head to %s, want %s", got, repo.tip)
	}
	state, err := st.GetProposal(ctx, coord, root.ID.Hex())
	if err != nil || state.LatestEventID != root.ID.Hex() || state.RootSubmitterPubkey != root.PubKey.Hex() {
		t.Fatalf("proposal state changed after attack: %+v err=%v", state, err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.comments[1]) != 0 {
		t.Fatalf("foreign revision created comments: %#v", fake.comments[1])
	}
}

func TestReflectorRefusesForgedProposalRecoveryMarkerWithoutNonce(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetGiteaCreator("admin")
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	priv := nostr.Generate().Hex()
	root := signedEvent(t, priv, relay.KindPatch, nostr.Tags{{"a", coord}, {"commit", repo.tip}, {"clone", repo.workDir}}, "root")
	branch := "nostr-proposal-" + root.ID.Hex()
	fake.pulls[99] = reflectorPR{PullRequest: gitea.PullRequest{ID: 99, Index: 99, Number: 99, State: "open"}, Head: branch, HeadSHA: repo.tip, Base: "main", Body: "<!-- grasp:nip34-proposal-root:" + root.ID.Hex() + " -->", Creator: "admin"}

	err := r.HandleEvent(ctx, root, "wss://relay.test")
	var materializationErr *MaterializationError
	if !errors.As(err, &materializationErr) || materializationErr.FailureClass != "materialization-conflict" {
		t.Fatalf("forged recovery error = %v", err)
	}
	state, err := st.GetProposal(ctx, coord, root.ID.Hex())
	if err != nil || state.GiteaPRNumber != 0 || state.RecoveryNonce == "" {
		t.Fatalf("forged PR was adopted or nonce missing: %+v err=%v", state, err)
	}
}

func TestReflectorAbortsWhenProposalCASLoses(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetProposalStore(losingProposalStore{ProposalStore: st})
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	ev := signedEvent(t, nostr.Generate().Hex(), relay.KindPatch, nostr.Tags{{"a", coord}, {"commit", repo.tip}, {"clone", repo.workDir}}, "root")
	err := r.HandleEvent(ctx, ev, "wss://relay.test")
	var materializationErr *MaterializationError
	if !errors.As(err, &materializationErr) || materializationErr.FailureClass != "materialization-conflict" {
		t.Fatalf("losing CAS error = %v", err)
	}
	if _, err := st.GetReflectedEvent(ctx, ev.ID.Hex()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("losing CAS recorded completed reflection: %v", err)
	}
	state, err := st.GetProposal(ctx, coord, ev.ID.Hex())
	if err != nil || state.GiteaPRNumber != 0 || state.LatestEventID != "" {
		t.Fatalf("losing CAS advanced proposal: %+v err=%v", state, err)
	}
	if _, err := exec.Command("git", "--git-dir", repo.repoPath, "rev-parse", "--verify", "refs/heads/nostr-proposal-"+ev.ID.Hex()).CombinedOutput(); err == nil {
		t.Fatal("losing CAS left proposal branch behind")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.pulls[1].State != "closed" {
		t.Fatalf("losing CAS left PR open: %+v", fake.pulls[1])
	}
}

func TestProposalSubmitterConcurrencyLimit(t *testing.T) {
	r := New(nil, nil, "", nil)
	r.SetProposalSecurityLimits(1024, 1)
	if !r.acquireProposalSubmitter("submitter") {
		t.Fatal("first proposal slot rejected")
	}
	if r.acquireProposalSubmitter("submitter") {
		t.Fatal("second concurrent proposal slot accepted")
	}
	r.releaseProposalSubmitter("submitter")
	if !r.acquireProposalSubmitter("submitter") {
		t.Fatal("proposal slot not released")
	}
	r.releaseProposalSubmitter("submitter")
}

func TestReflectorPRUpdateMovesExistingHeadBranchAndRecordsEchoGuard(t *testing.T) {
	ctx := context.Background()
	st, mapping, coord := newReflectorTestStore(t)
	repo := setupReflectorGitRepo(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
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

	actorPriv := nostr.Generate().Hex()
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
	ref, err := st.GetReflectedEvent(ctx, updateEv.ID.Hex())
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
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	headBranch := "feature/tip"
	if err := gitFetch(ctx, repo.repoPath, repo.workDir, "+"+repo.tip+":refs/heads/"+headBranch); err != nil {
		t.Fatalf("seed PR head branch: %v", err)
	}
	actorPriv := nostr.Generate().Hex()
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
	if _, err := st.GetReflectedEvent(ctx, updateEv.ID.Hex()); err != sql.ErrNoRows {
		t.Fatalf("unexpected reflected row for ignored PR update: %v", err)
	}
	processed, err := st.EventProcessed(ctx, updateEv.ID.Hex())
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
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	actorPriv := nostr.Generate().Hex()
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
	wantHead := "nostr-pr-" + ev.ID.Hex()[:12]
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
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	actorPriv := nostr.Generate().Hex()
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
	wantHead := "nostr-proposal-" + ev.ID.Hex()
	if pr.Head != wantHead || pr.Base != "main" || pr.Title != "Content patch" {
		t.Fatalf("unexpected PR request: %+v", pr)
	}
	readme := reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "show", "refs/heads/"+wantHead+":README.md")
	if !strings.Contains(readme, "feature") {
		t.Fatalf("applied branch README = %q, want feature change", readme)
	}
	ref, err := st.GetReflectedEvent(ctx, ev.ID.Hex())
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
	r.validateGitCloneURL = func(context.Context, string) error { return nil }
	rejectionPub := &reflectorFakePublisher{}
	r.SetPatchRejectionPublisher(rejectionPub)
	actorPriv := nostr.Generate().Hex()
	garbage := "From bad patch\n\ndiff --git a/README.md b/README.md\nthis is not a valid patch\n"
	ev := signedEvent(t, actorPriv, relay.KindPatch, nostr.Tags{
		{"a", coord},
		{"subject", "Bad patch"},
		{"branch-name", "bad-patch"},
	}, garbage)

	err := r.HandleEvent(ctx, ev, "wss://relay.test")
	var materializationErr *MaterializationError
	if !errors.As(err, &materializationErr) || materializationErr.FailureClass != "patch-decode-fail" {
		t.Fatalf("garbage patch error = %v", err)
	}
	fake.mu.Lock()
	if len(fake.pulls) != 0 {
		fake.mu.Unlock()
		t.Fatalf("garbage patch created PRs: %#v", fake.pulls)
	}
	fake.mu.Unlock()
	if _, err := st.GetReflectedEvent(ctx, ev.ID.Hex()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed proposal reflected as complete: %v", err)
	}
	failure, err := st.GetProposalFailure(ctx, ev.ID.Hex())
	if err != nil {
		t.Fatalf("get proposal failure: %v", err)
	}
	if failure.FailureClass != "patch-decode-fail" || failure.RootEventID != ev.ID.Hex() {
		t.Fatalf("unexpected proposal diagnostic: %+v", failure)
	}
	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
		t.Fatalf("terminal failure replay was not deduplicated: %v", err)
	}
	replayedFailure, err := st.GetProposalFailure(ctx, ev.ID.Hex())
	if err != nil || !replayedFailure.UpdatedAt.Equal(failure.UpdatedAt) {
		t.Fatalf("terminal replay repeated proposal work: before=%+v after=%+v err=%v", failure, replayedFailure, err)
	}
	if rejections := rejectionPub.published(); len(rejections) != 0 {
		t.Fatalf("kind 1617 failure published terminal rejection: %+v", rejections)
	}
	worktrees := reflectorGitOutput(t, "", "--git-dir", repo.repoPath, "worktree", "list", "--porcelain")
	if got := strings.Count(worktrees, "worktree "); got != 1 {
		t.Fatalf("dangling worktrees after failed patch: count=%d output=%s", got, worktrees)
	}
}

func TestReflectorSharedTerminalFailureDeduplicatesAcrossProcessedLedgers(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	ev := signedEvent(t, nostr.Generate().Hex(), relay.KindPatch, nostr.Tags{{"a", coord}}, "invalid")
	if err := st.RecordProposalFailure(ctx, store.ProposalFailure{RepositoryAddress: coord, RootEventID: ev.ID.Hex(), EventID: ev.ID.Hex(), FailureClass: "patch-decode-fail", FailureDetail: "terminal", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	r := New(alwaysUnprocessedStore{Store: st}, gitea.NewClient(ts.URL, "tok"), t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetProposalStore(st)
	if err := r.HandleEvent(ctx, ev, "wss://relay.test"); err != nil {
		t.Fatalf("shared terminal failure replay: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.pulls) != 0 {
		t.Fatalf("shared terminal replay did work: %#v", fake.pulls)
	}
}

func TestReflectorRejectsOversizedProposalBeforeMaterialization(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()
	r := New(st, gitea.NewClient(ts.URL, "tok"), t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetProposalSecurityLimits(16, 2)
	ev := signedEvent(t, nostr.Generate().Hex(), relay.KindPatch, nostr.Tags{{"a", coord}}, strings.Repeat("x", 17))
	err := r.HandleEvent(ctx, ev, "wss://relay.test")
	var materializationErr *MaterializationError
	if !errors.As(err, &materializationErr) || materializationErr.FailureClass != "patch-decode-fail" {
		t.Fatalf("oversized proposal error = %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.pulls) != 0 {
		t.Fatalf("oversized proposal created PRs: %#v", fake.pulls)
	}
}

func TestReflectorRejectsUnverifiedEvent(t *testing.T) {
	ctx := context.Background()
	st, _, coord := newReflectorTestStore(t)
	fake := newReflectorFakeGitea()
	ts := httptest.NewServer(fake)
	defer ts.Close()

	r := New(st, gitea.NewClient(ts.URL, "tok"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	priv := nostr.Generate().Hex()
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

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
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
	announcement := signedEvent(t, ownerPriv, relay.KindRepositoryAnnouncement, nostr.Tags{
		{"d", mapping.RepoID},
	}, "")
	rawAnnouncement, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal owner announcement: %v", err)
	}
	if err := st.SetAnnouncementEvent(ctx, mapping.Npub, mapping.RepoID, string(rawAnnouncement), announcement.ID.Hex()); err != nil {
		t.Fatalf("cache owner announcement: %v", err)
	}
	mapping.AnnouncementEventJSON = string(rawAnnouncement)
	mapping.AnnouncementEventID = announcement.ID.Hex()
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
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	ev := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex(pub),
		Kind:      nostr.Kind(kind),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
		Content:   content,
	}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

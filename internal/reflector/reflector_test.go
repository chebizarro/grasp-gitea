// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package reflector

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type reflectorFakeGitea struct {
	mu       sync.Mutex
	next     int64
	issues   map[int64]gitea.Issue
	comments map[int64][]string
}

func newReflectorFakeGitea() *reflectorFakeGitea {
	return &reflectorFakeGitea{next: 1, issues: map[int64]gitea.Issue{}, comments: map[int64][]string{}}
}

func (f *reflectorFakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/repos/"), "/")
	if len(parts) < 3 || parts[0] != "org1" || parts[1] != "repo1" || parts[2] != "issues" {
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
	if ref.GiteaRepoID != mapping.GiteaRepoID || ref.GiteaIndex != 1 || ref.Kind != relay.KindIssue {
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

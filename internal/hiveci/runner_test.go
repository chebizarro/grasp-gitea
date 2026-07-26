// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type recordingStatusSink struct{ statuses []loom.Status }

func (s *recordingStatusSink) Claim(_ context.Context, status loom.Status) (bool, error) {
	s.statuses = append(s.statuses, status)
	return true, nil
}

func (s *recordingStatusSink) Set(_ context.Context, status loom.Status) error {
	s.statuses = append(s.statuses, status)
	return nil
}

type fakeSigner struct {
	priv string
	pub  string
}

func newFakeSigner(t *testing.T) fakeSigner {
	t.Helper()
	priv := nostr.Generate().Hex()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return fakeSigner{priv: priv, pub: pub}
}

func (s fakeSigner) PublicKey() string { return s.pub }
func (s fakeSigner) SignEvent(ctx context.Context, ev *nostr.Event) error {
	pk, err := nostr.PubKeyFromHex(s.pub)
	if err != nil {
		return err
	}
	ev.PubKey = pk
	return ev.Sign(mustSK(s.priv))
}

func TestRunnerRunsActForRepositoryStateAndPublishesCheckAndAudit(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, argsPath := fakeAct(t, 0)
	signer := newFakeSigner(t)

	var published []*nostr.Event
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, signer, []string{"wss://relay.invalid"}, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	statusSink := &recordingStatusSink{}
	r.SetStatusSink(statusSink, "hive-ci")
	r.publish = func(ctx context.Context, ev *nostr.Event) error {
		clone := *ev
		clone.Tags = append(nostr.Tags(nil), ev.Tags...)
		published = append(published, &clone)
		return nil
	}

	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID},
		{"p", mapping.Pubkey},
		{"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev, "wss://fleet-relay.test"); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}

	if len(published) != 2 {
		t.Fatalf("published events = %d, want 2", len(published))
	}
	if len(statusSink.statuses) != 2 || statusSink.statuses[0].State != store.LoomStatusPending ||
		statusSink.statuses[1].State != store.LoomStatusSuccess {
		t.Fatalf("commit statuses = %#v, want pending -> success", statusSink.statuses)
	}
	for _, status := range statusSink.statuses {
		if status.Ref.CommitSHA != repo.commit || status.Ref.Owner != mapping.Owner || status.Ref.RepoName != mapping.RepoName {
			t.Fatalf("status not anchored to local dispatch record: %#v", status)
		}
	}
	if published[0].Kind != relay.KindCheckRunResult || published[1].Kind != relay.KindCASAudit {
		t.Fatalf("published kinds = %d/%d", published[0].Kind, published[1].Kind)
	}
	for _, ev := range published {
		if ev.PubKey.Hex() != signer.pub || ev.ID == (nostr.ID{}) || ev.Sig == [64]byte{} {
			t.Fatalf("event not signed by HiveCI signer: %+v", ev)
		}
	}
	var rec runRecord
	if err := json.Unmarshal([]byte(published[0].Content), &rec); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if rec.SchemaVersion != checkResultSchema || rec.Result != "success" || rec.Workflow != ".gitea/workflows/ci.yml" || rec.Commit != repo.commit || rec.Trigger != "push" || rec.BlocksMerge {
		t.Fatalf("unexpected check record: %+v", rec)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read act args: %v", err)
	}
	if got := string(args); !strings.Contains(got, "push -W .gitea/workflows/ci.yml") {
		t.Fatalf("act args = %q", got)
	}
}

func TestRunnerPublishesFailureResultWhenActFails(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".github/workflows/ci.yml")
	actPath, _ := fakeAct(t, 7)
	signer := newFakeSigner(t)

	var published []*nostr.Event
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, signer, nil, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.publish = func(ctx context.Context, ev *nostr.Event) error {
		clone := *ev
		published = append(published, &clone)
		return nil
	}

	ev := signedHiveEvent(t, ownerPriv, relay.KindPROpen, nostr.Tags{
		{"a", "30617:" + mapping.Pubkey + ":" + mapping.RepoID},
		{"c", repo.commit},
		{"branch-name", "feature"},
	}, "")
	if err := r.HandleEvent(ctx, ev, ""); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(published) != 2 {
		t.Fatalf("published events = %d, want 2", len(published))
	}
	var rec runRecord
	if err := json.Unmarshal([]byte(published[0].Content), &rec); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if rec.Result != "failure" || !rec.BlocksMerge || rec.ExitCode != 7 || rec.Trigger != "pull_request" {
		t.Fatalf("unexpected failure record: %+v", rec)
	}
	if tagValue(published[1].Tags, "decision") != "failure" || tagValue(published[1].Tags, "audit_type") != auditType {
		t.Fatalf("unexpected audit tags: %#v", published[1].Tags)
	}
}

type recordingRemoteDispatcher struct {
	requests []loom.DispatchRequest
	enabled  bool
}

func (d *recordingRemoteDispatcher) Enabled() bool { return d.enabled }
func (d *recordingRemoteDispatcher) Dispatch(_ context.Context, req loom.DispatchRequest) (bool, error) {
	d.requests = append(d.requests, req)
	return true, nil
}

func TestRunnerRemoteDispatchRequiresResolverAuthorization(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".github/workflows/ci.yml")
	mapping.AnnouncedCloneURL = "https://grasp.example/" + mapping.Npub + "/" + mapping.RepoID + ".git"
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatal(err)
	}
	remote := &recordingRemoteDispatcher{enabled: true}
	r := New(Config{Enabled: false, TriggerRepos: []string{"*"}}, st, nil, nil, repo.repositoriesDir,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetRemoteDispatcher(remote, "remote")

	authorized := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, authorized, ""); err != nil {
		t.Fatal(err)
	}
	if len(remote.requests) != 1 {
		t.Fatalf("authorized dispatches = %d, want 1", len(remote.requests))
	}
	if remote.requests[0].CloneURL != mapping.AnnouncedCloneURL {
		t.Fatalf("remote clone URL = %q, want public %q", remote.requests[0].CloneURL, mapping.AnnouncedCloneURL)
	}

	attacker := nostr.Generate()
	unauthorized := signedHiveEvent(t, attacker.Hex(), relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, unauthorized, ""); err != nil {
		t.Fatal(err)
	}
	if len(remote.requests) != 1 {
		t.Fatal("unauthorized author caused a remote dispatch")
	}
}

func TestRunnerRemoteOnlyNeverFallsBackToLocal(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, argsPath := fakeAct(t, 0)
	signer := newFakeSigner(t)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}},
		st, signer, nil, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetRemoteDispatcher(&recordingRemoteDispatcher{enabled: false}, "remote")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
		t.Fatal("remote-only mode executed local act with an unavailable dispatcher")
	}
}

func newHiveTestStore(t *testing.T) (*store.SQLiteStore, store.Mapping, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
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
	announcement := signedHiveEvent(t, ownerPriv, relay.KindRepositoryAnnouncement,
		nostr.Tags{{"d", mapping.RepoID}}, "")
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal announcement: %v", err)
	}
	mapping.AnnouncementEventJSON = string(announcementJSON)
	if err := st.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatalf("seed mapping: %v", err)
	}
	if err := st.SetAnnouncementEvent(context.Background(), mapping.Npub, mapping.RepoID,
		string(announcementJSON), announcement.ID.Hex()); err != nil {
		t.Fatalf("seed announcement: %v", err)
	}
	return st, mapping, ownerPriv
}

type hiveRepo struct {
	repositoriesDir string
	repoPath        string
	workDir         string
	commit          string
}

func setupHiveRepo(t *testing.T, mapping store.Mapping, workflowPath string) hiveRepo {
	t.Helper()
	tmp := t.TempDir()
	work := filepath.Join(tmp, "work")
	repositoriesDir := filepath.Join(tmp, "git", "repositories")
	repoPath := filepath.Join(repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	hiveGit(t, tmp, "init", "-b", "main", work)
	if err := os.MkdirAll(filepath.Join(work, filepath.Dir(workflowPath)), 0o755); err != nil {
		t.Fatalf("mkdir workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, workflowPath), []byte("name: ci\non: [push, pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("root\n"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	hiveGit(t, work, "add", ".")
	hiveGit(t, work, "commit", "-m", "root")
	commit := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("mkdir repo parent: %v", err)
	}
	hiveGit(t, tmp, "clone", "--bare", work, repoPath)
	return hiveRepo{repositoriesDir: repositoriesDir, repoPath: repoPath, workDir: work, commit: commit}
}

func fakeAct(t *testing.T, exitCode int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	actPath := filepath.Join(dir, "act")
	argsPath := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\nprintf '%s' \"$*\" > " + shellQuote(argsPath) + "\necho hive act\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(actPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake act: %v", err)
	}
	return actPath, argsPath
}

func hiveGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = hiveGitOutput(t, dir, args...)
}

func hiveGitOutput(t *testing.T, dir string, args ...string) string {
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

func signedHiveEvent(t *testing.T, priv string, kind int, tags nostr.Tags, content string) *nostr.Event {
	t.Helper()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	ev := &nostr.Event{PubKey: nostr.MustPubKeyFromHex(pub), Kind: nostr.Kind(kind), CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: tags, Content: content}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

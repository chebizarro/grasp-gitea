// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/json"
	"errors"
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
	"go.opentelemetry.io/otel/trace"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/telemetry"
)

type recordingStatusSink struct {
	statuses      []loom.Status
	cancelOnClaim context.CancelFunc
}

func (s *recordingStatusSink) Claim(_ context.Context, status loom.Status) (bool, error) {
	s.statuses = append(s.statuses, status)
	if s.cancelOnClaim != nil {
		s.cancelOnClaim()
	}
	return true, nil
}

func (s *recordingStatusSink) Set(ctx context.Context, status loom.Status) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.statuses = append(s.statuses, status)
	return nil
}

type failOnceApplyStore struct {
	*store.SQLiteStore
	failed          bool
	failAfterCommit bool
}

func (s *failOnceApplyStore) ApplyLoomStatus(ctx context.Context, id string, update store.LoomStatusUpdate, now time.Time) (bool, error) {
	if update.Source == store.LoomSourceLocal && !s.failed {
		s.failed = true
		if s.failAfterCommit {
			if _, err := s.SQLiteStore.ApplyLoomStatus(ctx, id, update, now); err != nil {
				return false, err
			}
		}
		return false, errors.New("transient status store failure")
	}
	return s.SQLiteStore.ApplyLoomStatus(ctx, id, update, now)
}

func TestRunnerRetriesTerminalStatusWithoutReexecutingAct(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, countPath := countingAct(t)
	sink := loom.NewDurableStatusSink(&failOnceApplyStore{SQLiteStore: st}, nil, time.Hour, 10, nil)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	r.SetStatusSink(sink, "hive-ci")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err == nil || !strings.Contains(err.Error(), "transient status store failure") {
		t.Fatalf("first HandleEvent error = %v", err)
	}
	ref := localStatusRef(mapping, ev, "push", repo.commit, ".gitea/workflows/ci.yml")
	job, err := st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
	if err != nil || job.Status != store.LoomStatusPending {
		t.Fatalf("status before retry = %+v, %v", job, err)
	}
	r.retryTerminalStatuses(ctx)
	job, err = st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
	if err != nil || job.Status != store.LoomStatusSuccess {
		t.Fatalf("status after retry = %+v, %v", job, err)
	}
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("replay: %v", err)
	}
	assertActCount(t, countPath, 1)
}

func TestRunnerRetriesAmbiguousCommittedTerminalWithoutReexecution(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, countPath := countingAct(t)
	sink := loom.NewDurableStatusSink(&failOnceApplyStore{SQLiteStore: st, failAfterCommit: true}, nil, time.Hour, 10, nil)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	r.SetStatusSink(sink, "hive-ci")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err == nil {
		t.Fatal("expected ambiguous terminal persistence error")
	}
	ref := localStatusRef(mapping, ev, "push", repo.commit, ".gitea/workflows/ci.yml")
	job, err := st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
	if err != nil || job.Status != store.LoomStatusSuccess {
		t.Fatalf("committed terminal status = %+v, %v", job, err)
	}
	if err := r.DrainTerminalRetries(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	assertActCount(t, countPath, 1)
}

func TestRunnerContinuesOtherWorkflowsAfterTerminalPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	secondWorkflow := ".gitea/workflows/other.yml"
	if err := os.WriteFile(filepath.Join(repo.workDir, secondWorkflow), []byte("name: other\non: push\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, repo.workDir, "add", secondWorkflow)
	hiveGit(t, repo.workDir, "commit", "-m", "second workflow")
	commit := strings.TrimSpace(hiveGitOutput(t, repo.workDir, "rev-parse", "HEAD"))
	hiveGit(t, repo.repoPath, "fetch", repo.workDir, "main:main")
	actPath, countPath := countingAct(t)
	sink := loom.NewDurableStatusSink(&failOnceApplyStore{SQLiteStore: st}, nil, time.Hour, 10, nil)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	r.SetStatusSink(sink, "hive-ci")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err == nil {
		t.Fatal("expected first terminal persistence failure")
	}
	assertActCount(t, countPath, 2)
	r.retryTerminalStatuses(ctx)
	for _, workflow := range []string{".gitea/workflows/ci.yml", secondWorkflow} {
		ref := localStatusRef(mapping, ev, "push", commit, workflow)
		job, err := st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
		if err != nil || job.Status != store.LoomStatusSuccess {
			t.Fatalf("workflow %s status = %+v, %v", workflow, job, err)
		}
	}
}

func TestRunnerRestartRecoversUnknownOutcomeWithoutReexecution(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, countPath := countingAct(t)
	sink := loom.NewDurableStatusSink(&failOnceApplyStore{SQLiteStore: st}, nil, time.Hour, 10, nil)
	first := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	first.SetStatusSink(sink, "original-prefix")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := first.HandleEvent(ctx, ev); err == nil {
		t.Fatal("expected terminal persistence failure")
	}
	ref := localStatusRef(mapping, ev, "push", repo.commit, ".gitea/workflows/ci.yml")
	job, err := st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
	if err != nil || job.Status != store.LoomStatusPending {
		t.Fatalf("pending claim = %+v, %v", job, err)
	}
	if err := st.MarkLoomStatusDelivered(ctx, ref.WorkflowRunID, ref.WorkflowRunID+":pending", time.Now()); err != nil {
		t.Fatal(err)
	}
	// The first runner is gone; its exact result never became durable, and
	// Gitea's pending delivery has already been removed from the outbox.
	second := New(Config{Enabled: false, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	second.SetStatusSink(loom.NewDurableStatusSink(st, nil, time.Hour, 10, nil), "changed-prefix")
	if err := second.RecoverInterruptedLocalRuns(ctx); err != nil {
		t.Fatal(err)
	}
	job, err = st.GetLoomJobByWorkflowRunID(ctx, ref.WorkflowRunID)
	if err != nil || job.Status != store.LoomStatusError || job.TerminalSource != store.LoomSourceLocalRecovery {
		t.Fatalf("recovered job = %+v, %v", job, err)
	}
	deliveries, err := st.ListDueLoomStatusDeliveries(ctx, time.Now().Add(time.Second), 10)
	if err != nil || len(deliveries) != 1 || deliveries[0].Context != "original-prefix/.gitea/workflows/ci.yml" || deliveries[0].State != store.LoomStatusError {
		t.Fatalf("recovered status delivery = %+v, %v", deliveries, err)
	}
	third := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	third.SetStatusSink(loom.NewDurableStatusSink(st, nil, time.Hour, 10, nil), "changed-prefix")
	if err := third.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("replay after restart: %v", err)
	}
	assertActCount(t, countPath, 1)
}

func countingAct(t *testing.T) (string, string) {
	t.Helper()
	actPath, _ := fakeAct(t, 0)
	countPath := filepath.Join(t.TempDir(), "runs")
	wrapper := filepath.Join(t.TempDir(), "counting-act")
	script := "#!/bin/sh\necho run >> " + shellQuote(countPath) + "\nexec " + shellQuote(actPath) + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return wrapper, countPath
}

func assertActCount(t *testing.T, countPath string, want int) {
	t.Helper()
	b, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "run\n"); got != want {
		t.Fatalf("act executions = %d, want %d", got, want)
	}
}

func TestRunnerRunsActForRepositoryStateAndRecordsCommitStatus(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, argsPath := fakeAct(t, 0)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	statusSink := &recordingStatusSink{}
	r.SetStatusSink(statusSink, "hive-ci")

	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID},
		{"p", mapping.Pubkey},
		{"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("HandleEvent: %v", err)
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
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read act args: %v", err)
	}
	if got := string(args); !strings.Contains(got, "push -W .gitea/workflows/ci.yml") {
		t.Fatalf("act args = %q", got)
	}
}

func TestRunnerRecordsFailureStatusWhenActFails(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".github/workflows/ci.yml")
	actPath, _ := fakeAct(t, 7)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	statusSink := &recordingStatusSink{}
	r.SetStatusSink(statusSink, "hive-ci")

	ev := signedHiveEvent(t, ownerPriv, relay.KindPROpen, nostr.Tags{
		{"a", "30617:" + mapping.Pubkey + ":" + mapping.RepoID},
		{"c", repo.commit},
		{"branch-name", "feature"},
	}, "")
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(statusSink.statuses) != 2 || statusSink.statuses[0].State != store.LoomStatusPending ||
		statusSink.statuses[1].State != store.LoomStatusFailure ||
		!strings.Contains(statusSink.statuses[1].Description, "act") {
		t.Fatalf("commit statuses = %#v, want pending -> act failure", statusSink.statuses)
	}
}

func TestRunnerWithoutStatusSinkDoesNotExecuteLocalWorkflow(t *testing.T) {
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, argsPath := fakeAct(t, 0)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "status sink not configured") {
		t.Fatalf("HandleEvent error = %v, want missing status sink", err)
	}
	if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
		t.Fatal("local workflow ran without a durable status sink")
	}
}

func TestRunnerPersistsTerminalStatusAfterInputCancellation(t *testing.T) {
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".gitea/workflows/ci.yml")
	actPath, argsPath := fakeAct(t, 0)
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statusSink := &recordingStatusSink{cancelOnClaim: cancel}
	r.SetStatusSink(statusSink, "hive-ci")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("HandleEvent after cancellation: %v", err)
	}
	if len(statusSink.statuses) != 2 || statusSink.statuses[1].State != store.LoomStatusFailure ||
		!strings.Contains(statusSink.statuses[1].Description, "cancel") {
		t.Fatalf("commit statuses = %#v, want pending -> cancelled failure", statusSink.statuses)
	}
	if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
		t.Fatal("local workflow ran after input context cancellation")
	}
}

type recordingRemoteDispatcher struct {
	requests []loom.DispatchRequest
	contexts []trace.SpanContext
	enabled  bool
}

func (d *recordingRemoteDispatcher) Enabled() bool { return d.enabled }
func (d *recordingRemoteDispatcher) Dispatch(ctx context.Context, req loom.DispatchRequest) (bool, error) {
	d.requests = append(d.requests, req)
	d.contexts = append(d.contexts, trace.SpanContextFromContext(ctx))
	return true, nil
}

func TestSinglePushProducesExactlyOneRemoteWorkflowDispatch(t *testing.T) {
	ctx := context.Background()
	st, mapping, ownerPriv := newHiveTestStore(t)
	repo := setupHiveRepo(t, mapping, ".github/workflows/ci.yml")
	mapping.AnnouncedCloneURL = "https://grasp.example/" + mapping.Npub + "/" + mapping.RepoID + ".git"
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatal(err)
	}
	remote := &recordingRemoteDispatcher{enabled: true}
	r := New(Config{Enabled: false, TriggerRepos: []string{"*"}}, st, repo.repositoriesDir,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetRemoteDispatcher(remote, "remote")

	upstream := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	traceparent, tracestate := telemetry.TraceTags(trace.ContextWithRemoteSpanContext(context.Background(), upstream))
	authorized := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
		{"traceparent", traceparent}, {"tracestate", tracestate},
	}, "")
	if err := r.HandleEvent(ctx, authorized); err != nil {
		t.Fatal(err)
	}
	if len(remote.requests) != 1 {
		t.Fatalf("authorized dispatches = %d, want 1", len(remote.requests))
	}
	if got := remote.requests[0]; got.Trigger != "push" || got.Branch != "main" ||
		got.WorkflowPath != ".github/workflows/ci.yml" || got.CommitSHA != repo.commit {
		t.Fatalf("canonical push dispatch = %#v", got)
	}
	if remote.requests[0].CloneURL != mapping.AnnouncedCloneURL {
		t.Fatalf("remote clone URL = %q, want public %q", remote.requests[0].CloneURL, mapping.AnnouncedCloneURL)
	}
	if len(remote.contexts) != 1 || remote.contexts[0].TraceID() != upstream.TraceID() || remote.contexts[0].SpanID() != upstream.SpanID() || !remote.contexts[0].IsRemote() {
		t.Fatalf("dispatch trace context = %#v, want upstream %#v", remote.contexts, upstream)
	}

	attacker := nostr.Generate()
	unauthorized := signedHiveEvent(t, attacker.Hex(), relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, unauthorized); err != nil {
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
	r := New(Config{Enabled: true, ActPath: actPath, TriggerRepos: []string{"*"}},
		st, repo.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetRemoteDispatcher(&recordingRemoteDispatcher{enabled: false}, "remote")
	ev := signedHiveEvent(t, ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", mapping.RepoID}, {"p", mapping.Pubkey}, {"refs/heads/main", repo.commit},
	}, "")
	if err := r.HandleEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
		t.Fatal("remote-only mode executed local act with an unavailable dispatcher")
	}
}

func TestRunnerUsesLivePersistedHivePolicy(t *testing.T) {
	t.Setenv("NOSTR_RELAYS", "wss://ambient.invalid")
	policies := policy.New(config.Config{
		RelayURLs: []string{"wss://bridge.example"}, ProfileSyncInterval: 10 * time.Minute, ProfileSyncWorkers: 4,
		HiveCINostrRelays: []string{"wss://hive.example"}, HiveCICashuMintURL: "https://mint.example",
		HiveCIBlossomURL: "https://blossom.example", HiveCIJobTimeoutMinutes: 23,
		HiveCICloneURLTemplate: "https://git.example/{owner}/{repo_id}.git",
	})
	runner := New(Config{}, nil, "", nil)
	runner.SetPolicyStore(policies)
	mapping := store.Mapping{Owner: "alice", RepoName: "repository", RepoID: "stable-id", AnnouncedCloneURL: "https://old.invalid/repo.git"}
	if got := runner.cloneURL(mapping); got != "https://git.example/alice/stable-id.git" {
		t.Fatalf("clone URL = %q", got)
	}
	env := runner.workflowEnvironment()
	want := map[string]string{"NOSTR_RELAYS": "wss://hive.example", "CASHU_MINT_URL": "https://mint.example", "BLOSSOM_URL": "https://blossom.example", "JOB_TIMEOUT_MINUTES": "23"}
	for key, value := range want {
		found := false
		for _, entry := range env {
			if entry == key+"="+value {
				found = true
			}
		}
		if !found {
			t.Errorf("missing persisted %s in workflow environment", key)
		}
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

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestLoomJobsTTLEvictionAndRowCap(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "loom.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0).UTC()
	job := func(id string) LoomJob {
		return LoomJob{WorkflowRunID: id, Owner: "alice", RepoName: "repo", RepoID: "r",
			CommitSHA: "abc", WorkflowPath: ".gitea/workflows/ci.yml"}
	}
	if err := st.SaveLoomJob(ctx, job("expired"), base.Add(-2*time.Hour), time.Hour, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveLoomJob(ctx, job("one"), base, time.Hour, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetLoomJobByWorkflowRunID(ctx, "expired"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired job error = %v, want sql.ErrNoRows", err)
	}
	if err := st.SaveLoomJob(ctx, job("two"), base.Add(time.Second), time.Hour, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveLoomJob(ctx, job("three"), base.Add(2*time.Second), time.Hour, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetLoomJobByWorkflowRunID(ctx, "one"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oldest capped job error = %v, want sql.ErrNoRows", err)
	}
	if _, err := st.GetLoomJobByWorkflowRunID(ctx, "two"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetLoomJobByWorkflowRunID(ctx, "three"); err != nil {
		t.Fatal(err)
	}
}

func TestClaimLoomJobStatusIsDurableAndExclusive(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "claim.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	job := LoomJob{WorkflowRunID: "local:claim", Owner: "alice", RepoName: "repo", RepoID: "r",
		CommitSHA: "abc", WorkflowPath: "ci.yml"}
	update := LoomStatusUpdate{State: LoomStatusPending, Description: "queued", Context: "hive-ci/ci.yml",
		Source: LoomSourceLocal, ProtocolEventID: "local:claim:pending"}
	claimed, err := st.ClaimLoomJobStatus(ctx, job, update, now, time.Hour, 10)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v", claimed, err)
	}
	claimed, err = st.ClaimLoomJobStatus(ctx, job, update, now.Add(time.Second), time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("duplicate claim acquired execution ownership")
	}
	deliveries, err := st.ListDueLoomStatusDeliveries(ctx, now.Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].CommitSHA != "abc" {
		t.Fatalf("atomic pending outbox = %#v", deliveries)
	}
}

func TestApplyLoomStatusOrderingAndTerminalPrecedence(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "loom.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	job := LoomJob{WorkflowRunID: "run", JobRequestID: "request", PublisherPub: "publisher",
		WorkerPub: "worker", Owner: "alice", RepoName: "repo", RepoID: "r",
		CommitSHA: "abc", WorkflowPath: "ci.yml"}
	if err := st.SaveLoomJob(ctx, job, now, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	apply := func(update LoomStatusUpdate) bool {
		t.Helper()
		ok, err := st.ApplyLoomStatus(ctx, "run", update, now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !apply(LoomStatusUpdate{State: LoomStatusPending, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobStatus, ProtocolEventID: "bbbb", EventCreatedAt: 10}) {
		t.Fatal("first status ignored")
	}
	if apply(LoomStatusUpdate{State: LoomStatusPending, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobStatus, ProtocolEventID: "cccc", EventCreatedAt: 10}) {
		t.Fatal("higher-id tie should lose")
	}
	if !apply(LoomStatusUpdate{State: LoomStatusError, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobStatus, ProtocolEventID: "aaaa", EventCreatedAt: 10}) {
		t.Fatal("lower-id tie should win")
	}
	if apply(LoomStatusUpdate{State: LoomStatusPending, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobStatus, ProtocolEventID: "dddd", EventCreatedAt: 11}) {
		t.Fatal("late pending overwrote terminal")
	}
	if !apply(LoomStatusUpdate{State: LoomStatusFailure, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobResult, ProtocolEventID: "job-result"}) {
		t.Fatal("authoritative job result did not beat advisory 30100")
	}
	if !apply(LoomStatusUpdate{State: LoomStatusSuccess, Context: "hive-ci/ci.yml",
		Source: LoomSourceWorkflowResult, ProtocolEventID: "workflow-result"}) {
		t.Fatal("5402 did not take precedence")
	}
	if apply(LoomStatusUpdate{State: LoomStatusFailure, Context: "hive-ci/ci.yml",
		Source: LoomSourceJobResult, ProtocolEventID: "late-job-result"}) {
		t.Fatal("5101 overwrote 5402")
	}
	got, err := st.GetLoomJobByWorkflowRunID(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != LoomStatusSuccess || got.TerminalSource != LoomSourceWorkflowResult {
		t.Fatalf("job = %#v", got)
	}
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureLoomTablesMigratesPhaseOneSchema(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "phase1.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.db.Exec(`CREATE TABLE loom_jobs (
		workflow_run_id TEXT PRIMARY KEY, job_request_id TEXT NOT NULL DEFAULT '',
		publisher_pub TEXT NOT NULL DEFAULT '', worker_pub TEXT NOT NULL DEFAULT '',
		owner TEXT NOT NULL, repo_name TEXT NOT NULL, repo_id TEXT NOT NULL,
		commit_sha TEXT NOT NULL, workflow_path TEXT NOT NULL,
		workflow_run_event TEXT NOT NULL DEFAULT '', job_request_event TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending', terminal_source TEXT NOT NULL DEFAULT '',
		last_protocol_event_id TEXT NOT NULL DEFAULT '', status_event_created_at INTEGER NOT NULL DEFAULT 0,
		status_event_id TEXT NOT NULL DEFAULT '', delivery_state TEXT NOT NULL DEFAULT 'pending',
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureLoomTables(context.Background()); err != nil {
		t.Fatalf("migrate Phase 1 Loom table: %v", err)
	}
	columns := map[string]bool{}
	rows, err := st.db.Query(`PRAGMA table_info(loom_jobs)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	for _, name := range []string{"dispatch_key", "dispatch_state", "dispatch_attempts",
		"dispatch_next_attempt_at", "dispatch_last_error", "published_at", "branch",
		"cancel_event", "cancel_state", "cancel_next_attempt_at"} {
		if !columns[name] {
			t.Fatalf("migration did not add %s", name)
		}
	}
}

func TestLoomCashuSpendAndChangeAreIdempotent(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cashu.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	intent := LoomCashuSpend{DispatchKey: "dispatch", WorkerPub: "worker", WorkerAdID: "ad", MintURL: "https://mint.example",
		Amount: 600, PricePerSecond: 2, DurationSeconds: 300}
	reserved, claimed, err := st.ReserveLoomCashuSpend(ctx, intent, now)
	if err != nil || !claimed || reserved.State != "reserved" {
		t.Fatalf("reserve = %+v, %v, %v", reserved, claimed, err)
	}
	if _, claimed, err := st.ReserveLoomCashuSpend(ctx, intent, now); err != nil || claimed {
		t.Fatalf("duplicate reserve = %v, %v", claimed, err)
	}
	ready, err := st.CompleteLoomCashuSpend(ctx, "dispatch", "quote", "token", now)
	if err != nil || ready.State != "ready" || ready.Token != "token" {
		t.Fatalf("complete = %+v, %v", ready, err)
	}
	if err := st.AttachLoomCashuSpend(ctx, "dispatch", "run", now); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.ClaimLoomCashuChange(ctx, "dispatch", "result", "change", now)
	if err != nil || !claimed {
		t.Fatalf("claim change = %v, %v", claimed, err)
	}
	if claimed, err = st.ClaimLoomCashuChange(ctx, "dispatch", "result", "change", now); err != nil || claimed {
		t.Fatalf("duplicate change = %v, %v", claimed, err)
	}
	if _, err := st.ClaimLoomCashuChange(ctx, "dispatch", "other", "change", now); err == nil {
		t.Fatal("different result replaced claimed change")
	}
	if err := st.MarkLoomCashuChangeRedeemed(ctx, "dispatch", "result", 500, now); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetLoomCashuSpend(ctx, "dispatch")
	if err != nil || got.ChangeState != "redeemed" || got.ChangeAmount != 500 {
		t.Fatalf("redeemed spend = %+v, %v", got, err)
	}
}

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

func TestClaimLoomDispatchReservationIsDurableAndExclusive(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reservation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	claimed, err := st.ClaimLoomDispatchReservation(ctx, "envelope", "ci.yml", "dispatch-a", now)
	if err != nil || !claimed {
		t.Fatalf("first reservation = %v, %v", claimed, err)
	}
	claimed, err = st.ClaimLoomDispatchReservation(ctx, "envelope", "ci.yml", "dispatch-a", now)
	if err != nil || claimed {
		t.Fatalf("identical reservation replay = %v, %v", claimed, err)
	}
	if claimed, err = st.ClaimLoomDispatchReservation(ctx, "envelope", "ci.yml", "dispatch-b", now); claimed ||
		!errors.Is(err, ErrTriggerConflict) {
		t.Fatalf("conflicting reservation = %v, %v", claimed, err)
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMergeTriggerEnvelopeClaimIsImmutableAndRecoverable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "merge-trigger.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	envelope := MergeTriggerEnvelope{
		IdempotencyKey: TriggerEnvelopeKey(TriggerSourceNIP34MergeStatus, "status"), Source: TriggerSourceNIP34MergeStatus,
		TriggerID: "status", Actor: "owner", Action: "push", EvidenceJSON: `{"id":"status"}`,
		PREventID: "pr", StatusEventID: "status",
		SourceCommit:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceTree:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PatchDigest:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		AcceptedCommit: "dddddddddddddddddddddddddddddddddddddddd",
		RepoAddress:    "30617:owner:repo", PolicyVersion: "policy-v1", Branch: "main",
		CreatedAt: time.Unix(100, 0).UTC(),
	}
	stored, claimed, err := st.ClaimMergeTriggerEnvelope(ctx, envelope)
	if err != nil || !claimed || stored.StatusEventID != envelope.StatusEventID {
		t.Fatalf("first claim = %#v, %v, %v", stored, claimed, err)
	}
	if _, claimed, err := st.ClaimMergeTriggerEnvelope(ctx, envelope); err != nil || claimed {
		t.Fatalf("replay claim = %v, %v", claimed, err)
	}
	conflict := envelope
	conflict.SourceTree = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if _, _, err := st.ClaimMergeTriggerEnvelope(ctx, conflict); err == nil {
		t.Fatal("immutable envelope mismatch was accepted")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetMergeTriggerEnvelopeByStatusID(ctx, envelope.StatusEventID)
	if err != nil || !sameMergeTriggerEnvelope(got, envelope) {
		t.Fatalf("reopened envelope = %#v, %v", got, err)
	}
}

func TestTriggerEnvelopeGenericReplayAndTypedConflict(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "trigger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	envelope := TriggerEnvelope{
		IdempotencyKey: TriggerEnvelopeKey("github", "delivery/action"), Source: "github", TriggerID: "delivery/action",
		Actor: "octocat", Action: "workflow_dispatch", WorkflowPath: ".github/workflows/deploy.yml",
		EvidenceJSON:   `{"delivery":"delivery","action":"workflow_dispatch"}`,
		SourceCommit:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceTree:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PatchDigest:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		AcceptedCommit: "dddddddddddddddddddddddddddddddddddddddd",
		RepoAddress:    "30617:owner:repo", PolicyVersion: "github.v1", Branch: "main",
	}
	stored, claimed, err := st.ClaimTriggerEnvelope(ctx, envelope)
	if err != nil || !claimed || stored.TriggerID != envelope.TriggerID {
		t.Fatalf("first claim = %#v, %v, %v", stored, claimed, err)
	}
	observed, claimed, err := st.ClaimTriggerEnvelope(ctx, envelope)
	if err != nil || claimed || !sameMergeTriggerEnvelope(observed, envelope) {
		t.Fatalf("exact replay = %#v, %v, %v", observed, claimed, err)
	}
	conflict := envelope
	conflict.Actor = "mallory"
	_, _, err = st.ClaimTriggerEnvelope(ctx, conflict)
	var typed *TriggerConflictError
	if !errors.Is(err, ErrTriggerConflict) || !errors.As(err, &typed) || !typed.NonRetryable() {
		t.Fatalf("conflict = %T %v, want typed non-retryable", err, err)
	}
	malformed := envelope
	malformed.EvidenceJSON = "{"
	if _, _, err := st.ClaimTriggerEnvelope(ctx, malformed); !errors.Is(err, ErrTriggerConflict) {
		t.Fatalf("malformed known replay = %v, want typed conflict", err)
	}
	wrongKey := envelope
	wrongKey.IdempotencyKey = strings.Repeat("f", 64)
	if _, _, err := st.ClaimTriggerEnvelope(ctx, wrongKey); !errors.Is(err, ErrTriggerConflict) {
		t.Fatalf("changed replay key = %v, want typed conflict", err)
	}
	got, err := st.GetTriggerEnvelopeByIdentity(ctx, envelope.Source, envelope.TriggerID)
	if err != nil || !sameMergeTriggerEnvelope(got, envelope) {
		t.Fatalf("identity lookup = %#v, %v", got, err)
	}
}

func TestLegacyMergeTriggerMigrationPreservesReplayIdentity(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "legacy-trigger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.EnsureMergeTriggerTables(ctx); err != nil {
		t.Fatal(err)
	}
	statusID := strings.Repeat("2", 64)
	key := TriggerEnvelopeKey(TriggerSourceNIP34MergeStatus, statusID)
	_, err = st.db.ExecContext(ctx, `INSERT INTO hiveci_merge_trigger_envelopes(
		idempotency_key, pr_event_id, status_event_id, source_commit, source_tree,
		patch_digest, accepted_commit, repo_address, policy_version, branch, created_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, key, strings.Repeat("1", 64), statusID,
		strings.Repeat("3", 40), strings.Repeat("4", 40), strings.Repeat("5", 64),
		strings.Repeat("6", 40), "30617:owner:repo", "policy-v1", "main", 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureMergeTriggerTables(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetMergeTriggerEnvelopeByStatusID(ctx, statusID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != TriggerSourceNIP34MergeStatus || got.TriggerID != statusID ||
		got.Action != "push" || got.Actor != "" || got.EvidenceJSON != "" {
		t.Fatalf("legacy migration = %#v", got)
	}
}

func TestAcceptedRepositoryStateUsesNIP01LatestOrdering(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	state := func(id string, created int64) AcceptedRepositoryState {
		return AcceptedRepositoryState{RepoAddress: "30617:owner:repo", EventID: id,
			AuthorPubkey: "owner", EventCreatedAt: created, EventJSON: "{" + id + "}"}
	}
	for _, candidate := range []AcceptedRepositoryState{
		state("c", 100), state("z", 101), state("a", 101), state("0", 99),
	} {
		if err := st.SaveAcceptedRepositoryState(ctx, candidate); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.GetAcceptedRepositoryState(ctx, "30617:owner:repo")
	if err != nil {
		t.Fatal(err)
	}
	if got.EventID != "a" || got.EventCreatedAt != 101 {
		t.Fatalf("latest state = %#v, want lower event ID at newest timestamp", got)
	}
}

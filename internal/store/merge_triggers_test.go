// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"path/filepath"
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
		IdempotencyKey: "key", PREventID: "pr", StatusEventID: "status",
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

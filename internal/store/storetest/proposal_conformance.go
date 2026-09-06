// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package storetest

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type ProposalFactory func(t *testing.T) store.ProposalStore

func RunProposal(t *testing.T, factory ProposalFactory) {
	t.Run("ProposalLockSerializesSideEffects", func(t *testing.T) {
		ctx := context.Background()
		st := factory(t)
		var inside atomic.Int64
		var maximum atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := st.WithProposalLock(ctx, "30617:owner:repo", "root", func(context.Context) error {
					n := inside.Add(1)
					if n > maximum.Load() {
						maximum.Store(n)
					}
					time.Sleep(5 * time.Millisecond)
					inside.Add(-1)
					return nil
				}); err != nil {
					t.Errorf("proposal lock: %v", err)
				}
			}()
		}
		wg.Wait()
		if maximum.Load() != 1 {
			t.Fatalf("maximum concurrent proposal side effects=%d", maximum.Load())
		}
	})
	t.Run("ProposalReservationIsOpaqueAndFirstWriterWins", func(t *testing.T) {
		ctx := context.Background()
		st := factory(t)
		first := store.ProposalState{RepositoryAddress: "30617:owner:reserved", RootEventID: "root-reserved", GiteaRepoID: 7, RootSubmitterPubkey: "submitter-a", RecoveryNonce: "nonce-a", GiteaCreator: "admin", HeadBranch: "nostr-proposal-root-reserved", BaseBranch: "main", LatestCreatedAt: -1, UpdatedAt: time.Now().UTC()}
		got, created, err := st.ReserveProposal(ctx, first)
		if err != nil || !created || got.RecoveryNonce != "nonce-a" {
			t.Fatalf("first reservation created=%v got=%+v err=%v", created, got, err)
		}
		second := first
		second.RootSubmitterPubkey = "submitter-b"
		second.RecoveryNonce = "nonce-b"
		got, created, err = st.ReserveProposal(ctx, second)
		if err != nil || created || got.RootSubmitterPubkey != "submitter-a" || got.RecoveryNonce != "nonce-a" {
			t.Fatalf("losing reservation created=%v got=%+v err=%v", created, got, err)
		}
	})

	t.Run("ProposalCreateReplayAndUpdate", func(t *testing.T) {
		ctx := context.Background()
		st := factory(t)
		if _, err := st.GetProposal(ctx, "30617:owner:repo", "root"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("missing proposal error=%v", err)
		}
		root := store.ProposalState{RepositoryAddress: "30617:owner:repo", RootEventID: "root", GiteaRepoID: 7, GiteaPRID: 8, GiteaPRNumber: 9, HeadBranch: "nostr-proposal-root", HeadRefSHA: "aaa", BaseBranch: "main", LatestEventID: "root", LatestCreatedAt: 10, UpdatedAt: time.Now().UTC()}
		advanced, err := st.UpsertProposal(ctx, root)
		if err != nil || !advanced {
			t.Fatalf("root upsert advanced=%v err=%v", advanced, err)
		}
		advanced, err = st.UpsertProposal(ctx, root)
		if err != nil || advanced {
			t.Fatalf("replay advanced=%v err=%v", advanced, err)
		}
		got, err := st.GetProposalByEventID(ctx, "root")
		if err != nil || got.GiteaPRNumber != 9 {
			t.Fatalf("root lookup=%+v err=%v", got, err)
		}
		update := root
		update.LatestEventID = "update"
		update.ParentEventID = "root"
		update.LatestCreatedAt = 10
		update.HeadRefSHA = "bbb"
		advanced, err = st.UpsertProposal(ctx, update)
		if err != nil || !advanced {
			t.Fatalf("update advanced=%v err=%v", advanced, err)
		}
		got, err = st.GetProposalByEventID(ctx, "update")
		if err != nil || got.LatestEventID != "update" || got.HeadRefSHA != "bbb" {
			t.Fatalf("update lookup=%+v err=%v", got, err)
		}
		stale := root
		stale.LatestEventID = "stale"
		stale.LatestCreatedAt = 9
		advanced, err = st.UpsertProposal(ctx, stale)
		if err != nil || advanced {
			t.Fatalf("stale advanced=%v err=%v", advanced, err)
		}
		if _, err = st.GetProposalByEventID(ctx, "stale"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("losing stale event unexpectedly materialized: %v", err)
		}
		oldReply := update
		oldReply.LatestEventID = "old-reply"
		oldReply.ParentEventID = "update"
		oldReply.LatestCreatedAt = 9
		oldReply.HeadRefSHA = "ccc"
		advanced, err = st.UpsertProposal(ctx, oldReply)
		if err != nil || advanced {
			t.Fatalf("old direct reply advanced=%v err=%v", advanced, err)
		}
		got, err = st.GetProposal(ctx, root.RepositoryAddress, root.RootEventID)
		if err != nil || got.LatestEventID != "update" || got.HeadRefSHA != "bbb" || got.LatestCreatedAt != 10 {
			t.Fatalf("old direct reply regressed cursor: %+v err=%v", got, err)
		}
	})

	t.Run("ProposalFailureDiagnostics", func(t *testing.T) {
		ctx := context.Background()
		st := factory(t)
		detail := strings.Repeat("x", 5000)
		want := store.ProposalFailure{RepositoryAddress: "30617:owner:repo", RootEventID: "root", EventID: "bad", FailureClass: "patch-decode-fail", FailureDetail: detail, UpdatedAt: time.Now().UTC()}
		if err := st.RecordProposalFailure(ctx, want); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetProposalFailure(ctx, "bad")
		if err != nil {
			t.Fatal(err)
		}
		if got.FailureClass != want.FailureClass || len(got.FailureDetail) != 4096 {
			t.Fatalf("failure=%+v detail_len=%d", got, len(got.FailureDetail))
		}
	})

	t.Run("DeleteProposalFailureIsIdempotent", func(t *testing.T) {
		ctx := context.Background()
		st := factory(t)
		// No row — delete is a no-op returning deleted=false.
		if deleted, err := st.DeleteProposalFailure(ctx, "missing"); err != nil || deleted {
			t.Fatalf("missing delete: deleted=%v err=%v", deleted, err)
		}
		// Record then delete: deleted=true, subsequent Get returns ErrNoRows,
		// second delete is a no-op.
		f := store.ProposalFailure{RepositoryAddress: "30617:owner:repo", RootEventID: "root", EventID: "retry-event", FailureClass: "patch-decode-fail", FailureDetail: "boom", UpdatedAt: time.Now().UTC()}
		if err := st.RecordProposalFailure(ctx, f); err != nil {
			t.Fatal(err)
		}
		if deleted, err := st.DeleteProposalFailure(ctx, "retry-event"); err != nil || !deleted {
			t.Fatalf("first delete: deleted=%v err=%v", deleted, err)
		}
		if _, err := st.GetProposalFailure(ctx, "retry-event"); err == nil {
			t.Fatalf("failure row was not removed")
		}
		if deleted, err := st.DeleteProposalFailure(ctx, "retry-event"); err != nil || deleted {
			t.Fatalf("second delete: deleted=%v err=%v", deleted, err)
		}
	})
}

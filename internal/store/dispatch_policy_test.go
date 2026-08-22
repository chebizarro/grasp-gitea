// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDispatchPolicyEvidenceIsImmutableAndDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dispatch-policy.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	review := DispatchReviewEvidence{
		EventID: strings.Repeat("1", 64), ReviewerPubkey: strings.Repeat("2", 64),
		RepoAddress: "30617:" + strings.Repeat("3", 64) + ":repo", RootEventID: strings.Repeat("4", 64),
		PatchEventID: strings.Repeat("5", 64), BaseCommit: strings.Repeat("6", 40),
		TipCommit: strings.Repeat("7", 40), DiffSHA256: strings.Repeat("8", 64),
		EventCreatedAt: 100, EventJSON: `{"id":"review"}`, ObservedAt: time.Unix(101, 0),
	}
	if err := st.SaveDispatchReviewEvidence(ctx, review); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDispatchReviewEvidence(ctx, review); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	mutated := review
	mutated.TipCommit = strings.Repeat("9", 40)
	if err := st.SaveDispatchReviewEvidence(ctx, mutated); err == nil {
		t.Fatal("mutated review identity was accepted")
	}
	audit := DispatchReviewAudit{
		EventID: strings.Repeat("a", 64), ReviewerPubkey: review.ReviewerPubkey,
		ReviewEventID: review.EventID, RepoAddress: review.RepoAddress, Commit: review.TipCommit,
		Outcome: "approved", EventCreatedAt: 102, EventJSON: `{"id":"audit"}`,
	}
	if err := st.SaveDispatchReviewAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	gotReview, err := reopened.GetDispatchReviewEvidence(ctx, review.EventID)
	if err != nil || !sameDispatchReviewEvidence(gotReview, review) {
		t.Fatalf("durable review = %#v, %v", gotReview, err)
	}
	audits, err := reopened.ListDispatchReviewAuditsForSource(ctx, review.RepoAddress, review.TipCommit)
	if err != nil || len(audits) != 1 || !sameDispatchReviewAudit(audits[0], audit) {
		t.Fatalf("durable audits = %#v, %v", audits, err)
	}
}

func TestRepositoryAuthorityUsesCanonicalLatestOrdering(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	base := RepositoryAuthorityEvent{AuthorPubkey: strings.Repeat("1", 64), RepoID: "repo", EventJSON: `{}`}
	for _, candidate := range []RepositoryAuthorityEvent{
		{AuthorPubkey: base.AuthorPubkey, RepoID: base.RepoID, EventID: "c", EventCreatedAt: 100, EventJSON: `{"id":"c"}`},
		{AuthorPubkey: base.AuthorPubkey, RepoID: base.RepoID, EventID: "z", EventCreatedAt: 101, EventJSON: `{"id":"z"}`},
		{AuthorPubkey: base.AuthorPubkey, RepoID: base.RepoID, EventID: "a", EventCreatedAt: 101, EventJSON: `{"id":"a"}`},
		{AuthorPubkey: base.AuthorPubkey, RepoID: base.RepoID, EventID: "0", EventCreatedAt: 99, EventJSON: `{"id":"0"}`},
	} {
		if err := st.SaveRepositoryAuthorityEvent(ctx, candidate); err != nil {
			t.Fatal(err)
		}
	}
	events, err := st.ListRepositoryAuthorityEvents(ctx, "repo")
	if err != nil || len(events) != 1 || events[0].EventID != "a" || events[0].EventCreatedAt != 101 {
		t.Fatalf("latest authority = %#v, %v", events, err)
	}
}

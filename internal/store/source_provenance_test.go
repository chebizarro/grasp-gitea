// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func provenanceFixture(t *testing.T) SourceProvenanceEvidence {
	t.Helper()
	accepted := strings.Repeat("4", 40)
	acceptedTree := strings.Repeat("5", 40)
	repo := "HTTPS://GitHub.COM/sharegap/grasp-gitea.git/"
	ref, err := SourceProvenanceReference(repo, accepted, acceptedTree)
	if err != nil {
		t.Fatal(err)
	}
	return SourceProvenanceEvidence{
		EvidenceRef: ref, SchemaVersion: SourceProvenanceSchemaV1,
		RepoIdentity: repo, ReviewBaseCommit: strings.Repeat("1", 40),
		SourceCommit: strings.Repeat("2", 40), SourceTree: strings.Repeat("3", 40),
		AcceptedCommit: accepted, AcceptedTree: acceptedTree,
		CanonicalCommit: accepted, CanonicalTree: acceptedTree,
		MirrorCommit: accepted, MirrorTree: acceptedTree,
		SignedReviewPatchSHA256: strings.Repeat("6", 64),
		SourceDiffSHA256:        strings.Repeat("7", 64), MergeResultDiffSHA256: strings.Repeat("8", 64),
		VerifiedAt: time.Unix(100, 0).UTC(),
	}
}

func TestSourceProvenanceReferenceIsStableAndDomainSeparated(t *testing.T) {
	repo := "https://github.com/sharegap/grasp-gitea.git"
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	got, err := SourceProvenanceReference(" HTTPS://GitHub.COM/sharegap/grasp-gitea.git/ ", commit, tree)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(SourceProvenanceSchemaV1 + "\x00" + repo + "\x00" + commit + "\x00" + tree))
	want := SourceProvenanceReferencePrefix + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("reference = %q, want %q", got, want)
	}
	changedTree, err := SourceProvenanceReference(repo, commit, strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if changedTree == got {
		t.Fatal("changed accepted tree retained the same evidence reference")
	}
}

func TestSourceProvenanceEvidenceIsImmutableAddressableAndDurable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "source-provenance.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	evidence := provenanceFixture(t)
	if err := st.SaveSourceProvenanceEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	replay := evidence
	replay.VerifiedAt = time.Unix(999, 0).UTC()
	if err := st.SaveSourceProvenanceEvidence(ctx, replay); err != nil {
		t.Fatalf("exact evidence replay: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetSourceProvenanceEvidence(ctx, evidence.EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	if got.RepoIdentity != "https://github.com/sharegap/grasp-gitea.git" {
		t.Fatalf("stored repository identity = %q", got.RepoIdentity)
	}
	evidence.RepoIdentity = got.RepoIdentity
	if !sameSourceProvenanceEvidence(got, evidence) || !got.VerifiedAt.Equal(evidence.VerifiedAt) {
		t.Fatalf("durable evidence = %#v, want %#v", got, evidence)
	}
}

func TestSourceProvenanceConflictingReplayIsTerminal(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "source-provenance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	evidence := provenanceFixture(t)
	if err := st.SaveSourceProvenanceEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	conflict := evidence
	conflict.SourceDiffSHA256 = strings.Repeat("9", 64)
	err = st.SaveSourceProvenanceEvidence(ctx, conflict)
	if !errors.Is(err, ErrSourceProvenanceConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	var terminal interface{ NonRetryable() bool }
	if !errors.As(err, &terminal) || !terminal.NonRetryable() {
		t.Fatalf("conflicting replay is not marked non-retryable: %v", err)
	}
}

func TestSourceProvenanceRejectsIncompleteMutableOrUnequalEvidence(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "source-provenance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	valid := provenanceFixture(t)

	tests := []struct {
		name   string
		mutate func(*SourceProvenanceEvidence)
	}{
		{"missing review base", func(e *SourceProvenanceEvidence) { e.ReviewBaseCommit = "" }},
		{"missing signed review patch", func(e *SourceProvenanceEvidence) { e.SignedReviewPatchSHA256 = "" }},
		{"short source diff", func(e *SourceProvenanceEvidence) { e.SourceDiffSHA256 = strings.Repeat("a", 40) }},
		{"branch only", func(e *SourceProvenanceEvidence) { e.RepoIdentity = "refs/heads/main"; e.EvidenceRef = "" }},
		{"tag only", func(e *SourceProvenanceEvidence) { e.RepoIdentity = "refs/tags/v1"; e.EvidenceRef = "" }},
		{"credential userinfo", func(e *SourceProvenanceEvidence) {
			e.RepoIdentity = "https://token@github.com/sharegap/grasp-gitea.git"
			e.EvidenceRef = ""
		}},
		{"credential query", func(e *SourceProvenanceEvidence) {
			e.RepoIdentity = "https://github.com/sharegap/grasp-gitea.git?token=secret"
			e.EvidenceRef = ""
		}},
		{"changed canonical tree", func(e *SourceProvenanceEvidence) { e.CanonicalTree = strings.Repeat("a", 40) }},
		{"mismatched mirror commit", func(e *SourceProvenanceEvidence) { e.MirrorCommit = strings.Repeat("b", 40) }},
		{"forged reference", func(e *SourceProvenanceEvidence) {
			e.EvidenceRef = SourceProvenanceReferencePrefix + strings.Repeat("c", 64)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			tt.mutate(&candidate)
			if err := st.SaveSourceProvenanceEvidence(ctx, candidate); err == nil {
				t.Fatal("invalid provenance evidence was accepted")
			}
		})
	}
}

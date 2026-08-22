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

func releaseStoreRecord(identityDigit, contentDigit, eventDigit string) ReleaseProvenanceRecord {
	return ReleaseProvenanceRecord{
		ReleaseIdentity:    ReleaseIdentityPrefix + strings.Repeat(identityDigit, 64),
		SchemaVersion:      ReleaseProvenanceSchemaV1,
		ContentDigest:      "sha256:" + strings.Repeat(contentDigit, 64),
		RegistryRepository: "sap/application",
		ManifestDigest:     "sha256:" + strings.Repeat("3", 64),
		SBOMDigest:         "sha256:" + strings.Repeat("4", 64),
		ProvenanceDigest:   "sha256:" + strings.Repeat("5", 64),
		SignedEventID:      strings.Repeat(eventDigit, 64),
		SignedEventJSON:    `{"terminal":"release"}`,
		CreatedAt:          time.Unix(100, 0).UTC(),
	}
}

func TestReleaseProvenanceExactReplayAndConflictQuarantine(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "release-store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.EnsureReleaseProvenanceTables(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureReleaseProvenanceTables(ctx); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}

	candidate := releaseStoreRecord("1", "2", "6")
	first, err := st.CommitReleaseProvenance(ctx, candidate)
	if err != nil || first.Replay {
		t.Fatalf("first commit=(%+v, %v)", first, err)
	}
	replayCandidate := candidate
	replayCandidate.SignedEventID = strings.Repeat("7", 64)
	replayCandidate.SignedEventJSON = `{"kind":5402,"different_signature":true}`
	replay, err := st.CommitReleaseProvenance(ctx, replayCandidate)
	if err != nil || !replay.Replay || replay.Record.SignedEventID != candidate.SignedEventID {
		t.Fatalf("exact replay did not return authoritative event: (%+v, %v)", replay, err)
	}

	conflict := candidate
	conflict.ContentDigest = "sha256:" + strings.Repeat("8", 64)
	conflict.SignedEventID = strings.Repeat("9", 64)
	conflict.SignedEventJSON = `{"kind":5402,"conflict":true}`
	if _, err := st.CommitReleaseProvenance(ctx, conflict); !errors.Is(err, ErrReleaseProvenanceConflict) {
		t.Fatalf("error=%v, want conflict", err)
	}
	// Re-delivery of the same conflict is idempotently quarantined.
	if _, err := st.CommitReleaseProvenance(ctx, conflict); !errors.Is(err, ErrReleaseProvenanceConflict) {
		t.Fatalf("second error=%v, want conflict", err)
	}
	stored, err := st.GetReleaseProvenance(ctx, candidate.ReleaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ContentDigest != candidate.ContentDigest || stored.SignedEventID != candidate.SignedEventID {
		t.Fatal("conflict rebound successful release")
	}
	quarantine, err := st.ListReleaseQuarantine(ctx, candidate.ReleaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantine) != 1 || quarantine[0].ConflictingContentDigest != conflict.ContentDigest {
		t.Fatalf("quarantine=%+v, want one conflict", quarantine)
	}
}

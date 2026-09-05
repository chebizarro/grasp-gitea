// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05affiliation

import (
	"context"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestRefreshMakesIndeterminateStaleAndConfirmedAbsenceRevoked(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/affiliation.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	verifiedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	original := store.DomainAffiliation{
		CanonicalIdentifier: "alice@example.com", LocalPart: "alice", Host: "example.com", Pubkey: "pubkey",
		VerifiedAt: verifiedAt, CheckedAt: verifiedAt, Status: store.DomainAffiliationVerified,
	}
	if err := st.UpsertDomainAffiliation(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	svc := New(st, func() []string { return nil }, nil)
	svc.verify = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
		return nip05resolve.AffiliationVerification{Pubkey: "pubkey", FailureClass: nip05resolve.FailureIndeterminate, FailureCode: "transport"}
	}
	svc.refresh(t.Context(), "pubkey")
	got, err := st.GetDomainAffiliation(t.Context(), "pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.DomainAffiliationStale || got.Host != "example.com" || !got.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("indeterminate refresh = %+v", got)
	}

	svc.verify = func(context.Context, string, []string) nip05resolve.AffiliationVerification {
		return nip05resolve.AffiliationVerification{
			CanonicalIdentifier: "alice@example.com", LocalPart: "alice", Host: "example.com", Pubkey: "pubkey",
			FailureClass: nip05resolve.FailureConfirmedAbsent, FailureCode: "name_absent",
		}
	}
	svc.refresh(t.Context(), "pubkey")
	got, err = st.GetDomainAffiliation(t.Context(), "pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.DomainAffiliationConfirmedAbsent || got.FailureClass != store.DomainFailureConfirmedAbsent {
		t.Fatalf("confirmed-absence refresh = %+v", got)
	}
}

func TestJitteredIntervalStaysNearFifteenMinutes(t *testing.T) {
	svc := &Service{interval: DefaultInterval, randFloat: func() float64 { return 0 }}
	if got := svc.jitteredInterval(); got != 12*time.Minute {
		t.Fatalf("low jitter = %v", got)
	}
	svc.randFloat = func() float64 { return 1 }
	if got := svc.jitteredInterval(); got != 18*time.Minute {
		t.Fatalf("high jitter = %v", got)
	}
}

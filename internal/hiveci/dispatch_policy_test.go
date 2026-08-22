// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type dispatchPolicyFixture struct {
	ctx        context.Context
	store      *store.SQLiteStore
	resolver   *DispatchPolicyResolver
	now        time.Time
	ownerPriv  string
	reviewPriv string
	ownerPub   string
	reviewPub  string
	repo       string
	root       string
	patch      string
	base       string
	tip        string
	tree       string
	diff       string
}

func newDispatchPolicyFixture(t *testing.T) *dispatchPolicyFixture {
	t.Helper()
	ownerPriv, reviewPriv := nostr.Generate().Hex(), nostr.Generate().Hex()
	ownerPub, _ := derivePubHex(ownerPriv)
	reviewPub, _ := derivePubHex(reviewPriv)
	fx := &dispatchPolicyFixture{
		ctx: context.Background(), now: time.Unix(10_000, 0).UTC(), ownerPriv: ownerPriv, reviewPriv: reviewPriv,
		ownerPub: ownerPub, reviewPub: reviewPub, repo: "30617:" + ownerPub + ":project",
		root: strings.Repeat("1", 64), patch: strings.Repeat("2", 64), base: strings.Repeat("3", 40),
		tip: strings.Repeat("4", 40), tree: strings.Repeat("5", 40), diff: strings.Repeat("6", 64),
	}
	var err error
	fx.store, err = store.Open(filepath.Join(t.TempDir(), "dispatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fx.store.Close() })
	fx.resolver, err = NewDispatchPolicyResolver(DispatchPolicyConfig{
		Policies:       []DispatchReviewPolicy{{RepoAddress: fx.repo, Reviewers: []string{reviewPub}, Version: "review-policy-v1"}},
		ApprovalMaxAge: time.Hour, FutureSkew: time.Minute,
	}, fx.store)
	if err != nil {
		t.Fatal(err)
	}
	fx.resolver.now = func() time.Time { return fx.now }
	fx.ingest(t, fx.authorityEvent(t, true, fx.now.Add(-10*time.Minute)))
	return fx
}

func (fx *dispatchPolicyFixture) authorityEvent(t *testing.T, authorize bool, at time.Time) *nostr.Event {
	t.Helper()
	tags := nostr.Tags{{"d", "project"}}
	if authorize {
		tags = append(tags, nostr.Tag{"maintainers", fx.reviewPub})
	}
	return signMergeEventAt(t, fx.ownerPriv, int(nostr.KindRepositoryAnnouncement), tags, "", at.Unix())
}

func (fx *dispatchPolicyFixture) reviewEvent(t *testing.T, priv string, at time.Time) *nostr.Event {
	t.Helper()
	return signMergeEventAt(t, priv, int(nostr.KindComment), nostr.Tags{
		{"E", fx.root, "", fx.ownerPub}, {"K", "1618"},
		{"e", fx.patch, "", fx.ownerPub}, {"k", "1619"}, {"A", fx.repo},
		{"base_commit", fx.base}, {"tip_commit", fx.tip}, {"diff_sha256", fx.diff},
	}, "review summary\nrepo-id: project", at.Unix())
}

func (fx *dispatchPolicyFixture) auditEvent(t *testing.T, priv, reviewID, outcome string, at time.Time) *nostr.Event {
	t.Helper()
	payload, err := json.Marshal(cascadia.CascadiaAuditReviewV1Payload{
		ReviewId: reviewID, Repository: fx.repo, Commit: fx.tip, Outcome: outcome,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signMergeEventAt(t, priv, cascadia.CAS_AUDIT, nostr.Tags{
		{"domain", canonicalReviewAuditDomain}, {"type", canonicalReviewAuditType},
		{"schema", canonicalReviewAuditSchema}, {"e", reviewID},
	}, string(payload), at.Unix())
}

func (fx *dispatchPolicyFixture) envelope() store.TriggerEnvelope {
	return store.TriggerEnvelope{
		PREventID: fx.patch, SourceCommit: fx.tip, SourceTree: fx.tree,
		AcceptedCommit: strings.Repeat("7", 40), RepoAddress: fx.repo,
		CreatedAt: fx.now.Add(-time.Minute),
	}
}

func (fx *dispatchPolicyFixture) ingest(t *testing.T, ev *nostr.Event) {
	t.Helper()
	handled, err := fx.resolver.HandleEvent(fx.ctx, ev)
	if err != nil || !handled {
		t.Fatalf("ingest kind %d = %v, %v", ev.Kind, handled, err)
	}
}

func TestDispatchPolicyResolvesExactCurrentApproval(t *testing.T) {
	fx := newDispatchPolicyFixture(t)
	review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute))
	fx.ingest(t, review)
	audit := fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-4*time.Minute))
	fx.ingest(t, audit)
	approval, err := fx.resolver.Resolve(fx.ctx, fx.envelope())
	if err != nil {
		t.Fatal(err)
	}
	if approval.ReviewEventID != review.ID.Hex() || approval.AuditEventID != audit.ID.Hex() ||
		approval.ReviewerPubkey != fx.reviewPub || approval.PatchEventID != fx.patch ||
		approval.SourceCommit != fx.tip || approval.SourceTree != fx.tree ||
		approval.PolicyVersion != "review-policy-v1" || len(approval.PolicySHA256) != 64 {
		t.Fatalf("incomplete approval: %#v", approval)
	}
}

func TestDispatchPolicyFailsClosedOnRejectedEvidence(t *testing.T) {
	t.Run("missing review and audit", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("missing evidence = %v", err)
		}
	})
	t.Run("missing audit", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		fx.ingest(t, fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute)))
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("missing audit = %v", err)
		}
	})
	t.Run("missing signed review", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, strings.Repeat("9", 64), "approved", fx.now.Add(-4*time.Minute)))
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("missing review = %v", err)
		}
	})
	t.Run("wrong commit", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute))
		fx.ingest(t, review)
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-4*time.Minute)))
		envelope := fx.envelope()
		envelope.SourceCommit = strings.Repeat("8", 40)
		if _, err := fx.resolver.Resolve(fx.ctx, envelope); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("wrong commit = %v", err)
		}
	})
	t.Run("stale approval", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-2*time.Hour))
		fx.ingest(t, review)
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-2*time.Hour+time.Minute)))
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("stale approval = %v", err)
		}
	})
	t.Run("reviewer revoked by current owner policy", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute))
		fx.ingest(t, review)
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-4*time.Minute)))
		fx.ingest(t, fx.authorityEvent(t, false, fx.now.Add(-time.Minute)))
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("revoked reviewer = %v", err)
		}
	})
	t.Run("conflicting attestation", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute))
		fx.ingest(t, review)
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-4*time.Minute)))
		fx.ingest(t, fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "revoked", fx.now.Add(-3*time.Minute)))
		if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("conflicting audit = %v", err)
		}
	})
	t.Run("malformed tree", func(t *testing.T) {
		fx := newDispatchPolicyFixture(t)
		envelope := fx.envelope()
		envelope.SourceTree = "not-a-tree"
		if _, err := fx.resolver.Resolve(fx.ctx, envelope); !errors.Is(err, ErrDispatchPolicyDenied) {
			t.Fatalf("malformed tree = %v", err)
		}
	})
}

func TestDispatchPolicyRejectsUnauthorizedAndLegacyIngest(t *testing.T) {
	fx := newDispatchPolicyFixture(t)
	stranger := nostr.Generate().Hex()
	if handled, err := fx.resolver.HandleEvent(fx.ctx, fx.reviewEvent(t, stranger, fx.now.Add(-time.Minute))); !handled || !errors.Is(err, ErrDispatchPolicyDenied) {
		t.Fatalf("unauthorized review = %v, %v", handled, err)
	}
	legacy := signMergeEventAt(t, fx.reviewPriv, cascadia.CAS_AUDIT, nostr.Tags{
		{"domain", "drydock"}, {"type", "review-published"}, {"schema", "cascadia.audit.v1"},
	}, `{"action":"review-published"}`, fx.now.Unix())
	if handled, err := fx.resolver.HandleEvent(fx.ctx, legacy); handled || err != nil {
		t.Fatalf("legacy review-published audit participated: %v, %v", handled, err)
	}
	tampered := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-time.Minute))
	tampered.Content += " tampered"
	if handled, err := fx.resolver.HandleEvent(fx.ctx, tampered); !handled || !errors.Is(err, ErrDispatchPolicyDenied) {
		t.Fatalf("tampered review = %v, %v", handled, err)
	}
}

func TestDispatchPolicyRequiresOneCanonicalReviewAudit(t *testing.T) {
	fx := newDispatchPolicyFixture(t)
	review := fx.reviewEvent(t, fx.reviewPriv, fx.now.Add(-5*time.Minute))
	fx.ingest(t, review)
	audit := fx.auditEvent(t, fx.reviewPriv, review.ID.Hex(), "approved", fx.now.Add(-4*time.Minute))
	// Point the canonical attestation at a review that was never observed.
	var payload cascadia.CascadiaAuditReviewV1Payload
	if err := json.Unmarshal([]byte(audit.Content), &payload); err != nil {
		t.Fatal(err)
	}
	payload.ReviewId = strings.Repeat("f", 64)
	content, _ := json.Marshal(payload)
	audit.Content = string(content)
	resignMergeEvent(t, audit, fx.reviewPriv)
	if handled, err := fx.resolver.HandleEvent(fx.ctx, audit); !handled || err != nil {
		t.Fatalf("canonical audit ingest = %v, %v", handled, err)
	}
	if _, err := fx.resolver.Resolve(fx.ctx, fx.envelope()); !errors.Is(err, ErrDispatchPolicyDenied) {
		t.Fatalf("missing canonical audit = %v", err)
	}
}

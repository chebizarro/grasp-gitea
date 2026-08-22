// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type integrationDispatchSigner struct {
	key    nostr.SecretKey
	signed []nostr.Kind
}

func (s *integrationDispatchSigner) PublicKey() string { return s.key.Public().Hex() }
func (s *integrationDispatchSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	if err := ev.Sign(s.key); err != nil {
		return err
	}
	s.signed = append(s.signed, ev.Kind)
	return nil
}
func (s *integrationDispatchSigner) NIP44Encrypt(_ context.Context, target nostr.PubKey, plaintext string) (string, error) {
	key, err := nip44.GenerateConversationKey(target, s.key)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, key)
}

type dispatchIntegrationFixture struct {
	merge      *mergeFixture
	resolver   *DispatchPolicyResolver
	validator  *Runner
	dispatcher *loom.Dispatcher
	req        loom.DispatchRequest
	envelope   store.TriggerEnvelope
	reviewPriv string
	reviewPub  string
	worker     nostr.SecretKey
	pool       *loom.WorkerPool
	signer     *integrationDispatchSigner
	published  []nostr.Event
	attempted  []nostr.Event
	publishErr error
	now        time.Time
}

func newDispatchIntegrationFixture(t *testing.T) *dispatchIntegrationFixture {
	t.Helper()
	fx := newMergeFixture(t, true)
	remote := &mergeRemoteDispatcher{}
	status := fx.statusEvent(t, fx.ownerPriv, true, fx.acceptedCommit, fx.stateCreatedAt+1)
	if err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatal(err)
	}
	var req loom.DispatchRequest
	for _, candidate := range remote.unique {
		req = candidate
	}
	envelope, err := fx.store.GetTriggerEnvelope(fx.ctx, req.TriggerEnvelopeID)
	if err != nil {
		t.Fatal(err)
	}
	reviewPriv := nostr.Generate().Hex()
	reviewPub, _ := derivePubHex(reviewPriv)
	resolver, err := NewDispatchPolicyResolver(DispatchPolicyConfig{
		Policies:       []DispatchReviewPolicy{{RepoAddress: fx.repoAddress(), Reviewers: []string{reviewPub}, Version: "review-policy-v1"}},
		ApprovalMaxAge: time.Hour, FutureSkew: time.Minute,
	}, fx.store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(405, 0).UTC()
	resolver.now = func() time.Time { return now }
	authority := signMergeEventAt(t, fx.ownerPriv, relay.KindRepositoryAnnouncement,
		nostr.Tags{{"d", fx.mapping.RepoID}, {"maintainers", reviewPub}}, "", 390)
	if handled, err := resolver.HandleEvent(fx.ctx, authority); err != nil || !handled {
		t.Fatalf("ingest authority = %v, %v", handled, err)
	}
	validator := New(Config{Enabled: false}, fx.store, nil, nil, fx.repositoriesDir,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	validator.SetDispatchPolicyGate(resolver)
	validator.SetSourceProvenanceVerifier(allowSourceProvenanceVerifier{})
	worker := nostr.Generate()
	pool := loom.NewWorkerPool(loom.WorkerPoolConfig{
		Allowlist: []string{worker.Public().Hex()}, RequiredSoftware: []string{"act"}, AdTTL: time.Hour, FutureSkew: time.Minute,
	})
	workerNow := time.Now().UTC().Truncate(time.Second)
	if err := pool.HandleEvent(integrationWorkerAd(t, worker, workerNow, "act"), workerNow); err != nil {
		t.Fatal(err)
	}
	signer := &integrationDispatchSigner{key: nostr.Generate()}
	var result *dispatchIntegrationFixture
	dispatcher := loom.NewDispatcher(loom.DispatcherConfig{Enabled: true, MaxDuration: 15 * time.Minute,
		RelayURLs: []string{"wss://relay.invalid"}, JobTTL: time.Hour, MaxJobs: 100,
		Publish: func(_ context.Context, ev *nostr.Event) error {
			result.attempted = append(result.attempted, *ev)
			if result.publishErr != nil {
				return result.publishErr
			}
			result.published = append(result.published, *ev)
			return nil
		}},
		pool, fx.store, signer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	dispatcher.SetDispatchRevalidator(validator)
	result = &dispatchIntegrationFixture{merge: fx, resolver: resolver, validator: validator, dispatcher: dispatcher,
		req: req, envelope: envelope, reviewPriv: reviewPriv, reviewPub: reviewPub, worker: worker,
		pool: pool, signer: signer, now: now}
	return result
}

func (fx *dispatchIntegrationFixture) review(t *testing.T, createdAt int64) *nostr.Event {
	t.Helper()
	return signMergeEventAt(t, fx.reviewPriv, int(nostr.KindComment), nostr.Tags{
		{"E", fx.merge.root.ID.Hex(), "", fx.merge.mapping.Pubkey}, {"K", "1618"},
		{"e", fx.envelope.PREventID, "", fx.merge.mapping.Pubkey}, {"k", "1619"}, {"A", fx.merge.repoAddress()},
		{"base_commit", fx.merge.baseCommit}, {"tip_commit", fx.merge.sourceCommit}, {"diff_sha256", fx.envelope.PatchDigest},
	}, "review summary", createdAt)
}

func (fx *dispatchIntegrationFixture) audit(t *testing.T, reviewID string, createdAt int64) *nostr.Event {
	t.Helper()
	payload, err := json.Marshal(cascadia.CascadiaAuditReviewV1Payload{
		ReviewId: reviewID, Repository: fx.merge.repoAddress(), Commit: fx.merge.sourceCommit, Outcome: "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	return signMergeEventAt(t, fx.reviewPriv, cascadia.CAS_AUDIT, nostr.Tags{
		{"domain", canonicalReviewAuditDomain}, {"type", canonicalReviewAuditType},
		{"schema", canonicalReviewAuditSchema}, {"e", reviewID},
	}, string(payload), createdAt)
}

func (fx *dispatchIntegrationFixture) ingestReview(t *testing.T, review *nostr.Event) {
	t.Helper()
	if handled, err := fx.resolver.HandleEvent(fx.merge.ctx, review); err != nil || !handled {
		t.Fatalf("ingest review = %v, %v", handled, err)
	}
}

func (fx *dispatchIntegrationFixture) approve(t *testing.T, reviewAt, auditAt int64) {
	t.Helper()
	review := fx.review(t, reviewAt)
	fx.ingestReview(t, review)
	audit := fx.audit(t, review.ID.Hex(), auditAt)
	if handled, err := fx.resolver.HandleEvent(fx.merge.ctx, audit); err != nil || !handled {
		t.Fatalf("ingest audit = %v, %v", handled, err)
	}
	approval, err := fx.resolver.Resolve(fx.merge.ctx, fx.envelope)
	if err != nil {
		t.Fatal(err)
	}
	fx.req.ReviewEventID, fx.req.AuditEventID = approval.ReviewEventID, approval.AuditEventID
	fx.req.ReviewerPubkey, fx.req.ReviewRootEventID = approval.ReviewerPubkey, approval.RootEventID
	fx.req.ReviewBaseCommit, fx.req.ReviewPolicyVersion = approval.BaseCommit, approval.PolicyVersion
	fx.req.ReviewPolicySHA256 = approval.PolicySHA256
}

func integrationWorkerAd(t *testing.T, worker nostr.SecretKey, created time.Time, software string) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{Kind: relay.KindLoomWorkerAd, CreatedAt: nostr.Timestamp(created.Unix()), Tags: nostr.Tags{
		{"S", software, "1.0", "/usr/bin/" + software}, {"A", "linux/amd64"},
		{"price", "https://mint.invalid", "0", "sat"}, {"metric", "second"},
		{"min_duration", "0"}, {"max_duration", "3600"},
	}, Content: "{}"}
	if err := ev.Sign(worker); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestReviewedTriggerDispatchIntegrationExactlyOnce(t *testing.T) {
	fx := newDispatchIntegrationFixture(t)
	fx.approve(t, 398, 399)
	if handled, err := fx.dispatcher.Dispatch(fx.merge.ctx, fx.req); err != nil || !handled {
		t.Fatalf("valid dispatch = %v, %v", handled, err)
	}
	if handled, err := fx.dispatcher.Dispatch(fx.merge.ctx, fx.req); err != nil || !handled {
		t.Fatalf("exact replay = %v, %v", handled, err)
	}
	var signed5401, published5401, published5100 int
	for _, kind := range fx.signer.signed {
		if kind == relay.KindHiveWorkflowRun {
			signed5401++
		}
	}
	for _, ev := range fx.published {
		switch ev.Kind {
		case relay.KindHiveWorkflowRun:
			published5401++
		case relay.KindLoomJobRequest:
			published5100++
		}
	}
	if signed5401 != 1 || published5401 != 1 || published5100 != 1 {
		t.Fatalf("signed 5401=%d published 5401=%d 5100=%d", signed5401, published5401, published5100)
	}
}

func TestReviewedTriggerDispatchIntegrationRejectsBeforeSideEffects(t *testing.T) {
	tests := map[string]func(*testing.T, *dispatchIntegrationFixture){
		"missing review": func(_ *testing.T, _ *dispatchIntegrationFixture) {},
		"wrong commit": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.SourceCommit = strings.Repeat("a", 40)
		},
		"wrong tree": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.SourceTree = strings.Repeat("b", 40)
		},
		"stale approval": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.resolver.approvalMaxAge = time.Second
		},
		"revoked reviewer": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			revoked := signMergeEventAt(t, fx.merge.ownerPriv, relay.KindRepositoryAnnouncement,
				nostr.Tags{{"d", fx.merge.mapping.RepoID}}, "", 400)
			if handled, err := fx.resolver.HandleEvent(fx.merge.ctx, revoked); err != nil || !handled {
				t.Fatalf("revoke reviewer = %v, %v", handled, err)
			}
		},
		"missing audit": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.ingestReview(t, fx.review(t, 398))
		},
		"mismatched audit": func(t *testing.T, fx *dispatchIntegrationFixture) {
			review := fx.review(t, 398)
			fx.ingestReview(t, review)
			audit := fx.audit(t, strings.Repeat("f", 64), 399)
			if handled, err := fx.resolver.HandleEvent(fx.merge.ctx, audit); err != nil || !handled {
				t.Fatalf("ingest mismatch audit = %v, %v", handled, err)
			}
		},
		"unauthorized trigger": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.Actor, fx.req.TriggeredBy = strings.Repeat("c", 64), strings.Repeat("c", 64)
		},
		"policy digest mismatch": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.ReviewPolicySHA256 = strings.Repeat("d", 64)
		},
		"workflow digest mismatch": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.WorkflowDigest = strings.Repeat("e", 64)
		},
		"missing provenance evidence": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.SourceProvenanceRef = ""
		},
		"tampered provenance evidence": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.SourceProvenanceRef = store.SourceProvenanceReferencePrefix + strings.Repeat("f", 64)
		},
		"mismatched source repository": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.SourceRepoIdentity = "30617:" + strings.Repeat("f", 64) + ":other"
		},
		"credential-bearing build URL": func(t *testing.T, fx *dispatchIntegrationFixture) {
			fx.approve(t, 398, 399)
			fx.req.CloneURL = "https://user:secret@example.com/repo.git"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fx := newDispatchIntegrationFixture(t)
			mutate(t, fx)
			if handled, err := fx.dispatcher.Dispatch(fx.merge.ctx, fx.req); handled || err == nil {
				t.Fatalf("rejected dispatch = %v, %v", handled, err)
			}
			if len(fx.signer.signed) != 0 || len(fx.published) != 0 {
				t.Fatalf("denial crossed side-effect boundary: signed=%d published=%d", len(fx.signer.signed), len(fx.published))
			}
		})
	}
}

func TestReviewedTriggerDispatchRejectsReplacedWorkerBeforeSigning(t *testing.T) {
	fx := newDispatchIntegrationFixture(t)
	fx.approve(t, 398, 399)
	replacementAt := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	if err := fx.pool.HandleEvent(integrationWorkerAd(t, fx.worker, replacementAt, "docker"), replacementAt); err != nil {
		t.Fatal(err)
	}
	if handled, err := fx.dispatcher.Dispatch(fx.merge.ctx, fx.req); err != nil || handled {
		t.Fatalf("dispatch with replaced capability = %v, %v", handled, err)
	}
	if len(fx.signer.signed) != 0 || len(fx.attempted) != 0 {
		t.Fatalf("replaced worker crossed side-effect boundary: signed=%d attempted=%d", len(fx.signer.signed), len(fx.attempted))
	}
}

func TestReviewedTriggerOutboxRetryRevalidatesCurrentEvidence(t *testing.T) {
	tests := map[string]func(*testing.T, *dispatchIntegrationFixture){
		"reviewer revoked": func(t *testing.T, fx *dispatchIntegrationFixture) {
			revoked := signMergeEventAt(t, fx.merge.ownerPriv, relay.KindRepositoryAnnouncement,
				nostr.Tags{{"d", fx.merge.mapping.RepoID}}, "", 400)
			if handled, err := fx.resolver.HandleEvent(fx.merge.ctx, revoked); err != nil || !handled {
				t.Fatalf("revoke reviewer = %v, %v", handled, err)
			}
		},
		"approval becomes stale": func(_ *testing.T, fx *dispatchIntegrationFixture) {
			fx.resolver.now = func() time.Time { return fx.now.Add(2 * time.Hour) }
		},
		"provenance evidence changes": func(_ *testing.T, fx *dispatchIntegrationFixture) {
			fx.validator.SetSourceProvenanceVerifier(mismatchedSourceProvenanceVerifier{})
		},
		"canonical clone mapping changes": func(t *testing.T, fx *dispatchIntegrationFixture) {
			mapping := fx.merge.mapping
			mapping.AnnouncedCloneURL = "file:///tmp/other-canonical.git"
			if err := fx.merge.store.UpsertMapping(fx.merge.ctx, mapping); err != nil {
				t.Fatal(err)
			}
		},
		"worker advertisement replaced": func(t *testing.T, fx *dispatchIntegrationFixture) {
			replacementAt := time.Now().UTC().Truncate(time.Second).Add(time.Second)
			if err := fx.pool.HandleEvent(integrationWorkerAd(t, fx.worker, replacementAt, "act"), replacementAt); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			fx := newDispatchIntegrationFixture(t)
			fx.approve(t, 398, 399)
			fx.publishErr = errors.New("relay unavailable")
			if handled, err := fx.dispatcher.Dispatch(fx.merge.ctx, fx.req); !handled || err == nil {
				t.Fatalf("initial durable attempt = %v, %v", handled, err)
			}
			if len(fx.attempted) != 2 || len(fx.signer.signed) != 2 || len(fx.published) != 0 {
				t.Fatalf("initial outbox attempt signed=%d attempted=%d published=%d", len(fx.signer.signed), len(fx.attempted), len(fx.published))
			}
			runID := fx.attempted[0].ID.Hex()
			if err := fx.merge.store.MarkLoomDispatchRetry(fx.merge.ctx, runID, time.Now().UTC().Add(-time.Second), "due"); err != nil {
				t.Fatal(err)
			}
			invalidate(t, fx)
			before := len(fx.attempted)
			fx.publishErr = nil
			ctx, cancel := context.WithCancel(fx.merge.ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				fx.dispatcher.Run(ctx)
			}()
			time.Sleep(100 * time.Millisecond)
			cancel()
			<-done
			if len(fx.attempted) != before || len(fx.published) != 0 || len(fx.signer.signed) != 2 {
				t.Fatalf("invalidated outbox retry crossed publication: signed=%d attempted=%d published=%d", len(fx.signer.signed), len(fx.attempted), len(fx.published))
			}
		})
	}
}

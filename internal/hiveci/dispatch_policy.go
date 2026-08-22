// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/nostrauthz"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	canonicalReviewAuditSchema = "cascadia.audit.review.v1"
	canonicalReviewAuditType   = "review.attestation"
	canonicalReviewAuditDomain = "drydock"
)

var ErrDispatchPolicyDenied = errors.New("HiveCI dispatch policy denied")

// DispatchReviewPolicy is the operator-owned trust policy for one canonical
// repository. A reviewer must be listed here AND belong to the current signed
// NIP-34 owner/recursive-maintainer authority at resolution time.
type DispatchReviewPolicy struct {
	RepoAddress string   `json:"repo_address"`
	Reviewers   []string `json:"reviewers"`
	Version     string   `json:"version"`
}

type DispatchPolicyConfig struct {
	Policies       []DispatchReviewPolicy
	ApprovalMaxAge time.Duration
	FutureSkew     time.Duration
}

// DispatchApproval is the deterministic, correlation-complete output of the
// local evidence resolver. Item 2 binds its SourceTree and workflow digest to
// the emitted kind-5401 request after revalidating the Git object.
type DispatchApproval struct {
	ReviewEventID  string
	AuditEventID   string
	ReviewerPubkey string
	RepoAddress    string
	RootEventID    string
	PatchEventID   string
	BaseCommit     string
	SourceCommit   string
	SourceTree     string
	DiffSHA256     string
	PolicyVersion  string
	PolicySHA256   string
	ReviewCreated  time.Time
	AuditCreated   time.Time
}

type dispatchPolicyStore interface {
	SaveDispatchReviewEvidence(context.Context, store.DispatchReviewEvidence) error
	GetDispatchReviewEvidence(context.Context, string) (store.DispatchReviewEvidence, error)
	SaveDispatchReviewAudit(context.Context, store.DispatchReviewAudit) error
	ListDispatchReviewAuditsForSource(context.Context, string, string) ([]store.DispatchReviewAudit, error)
	SaveRepositoryAuthorityEvent(context.Context, store.RepositoryAuthorityEvent) error
	ListRepositoryAuthorityEvents(context.Context, string) ([]store.RepositoryAuthorityEvent, error)
}

type dispatchPolicyEntry struct {
	policy    DispatchReviewPolicy
	reviewers map[string]struct{}
	owner     string
	repoID    string
	digest    string
}

// DispatchPolicyResolver ingests signed evidence and resolves approvals only
// from its durable local store. It never performs a relay read while gating a
// dispatch.
type DispatchPolicyResolver struct {
	store          dispatchPolicyStore
	policies       map[string]dispatchPolicyEntry
	policiesByRepo map[string][]dispatchPolicyEntry
	approvalMaxAge time.Duration
	futureSkew     time.Duration
	now            func() time.Time
}

func NewDispatchPolicyResolver(cfg DispatchPolicyConfig, st dispatchPolicyStore) (*DispatchPolicyResolver, error) {
	if st == nil {
		return nil, fmt.Errorf("dispatch policy store is required")
	}
	if cfg.ApprovalMaxAge <= 0 || cfg.ApprovalMaxAge > 30*24*time.Hour {
		return nil, fmt.Errorf("dispatch approval maximum age must be within (0, 30d]")
	}
	if cfg.FutureSkew <= 0 || cfg.FutureSkew > time.Hour {
		return nil, fmt.Errorf("dispatch evidence future skew must be within (0, 1h]")
	}
	r := &DispatchPolicyResolver{
		store: st, policies: make(map[string]dispatchPolicyEntry), policiesByRepo: make(map[string][]dispatchPolicyEntry),
		approvalMaxAge: cfg.ApprovalMaxAge, futureSkew: cfg.FutureSkew, now: time.Now,
	}
	for _, raw := range cfg.Policies {
		policy := raw
		policy.RepoAddress = strings.TrimSpace(policy.RepoAddress)
		policy.Version = strings.TrimSpace(policy.Version)
		coord, err := nostrauthz.ParseRepositoryCoordinate(policy.RepoAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid dispatch review policy repository %q: %w", policy.RepoAddress, err)
		}
		if policy.RepoAddress != coord.String() {
			return nil, fmt.Errorf("dispatch review policy repository must use its canonical coordinate")
		}
		if policy.Version == "" {
			return nil, fmt.Errorf("dispatch review policy version is required for %s", policy.RepoAddress)
		}
		reviewers := make(map[string]struct{}, len(policy.Reviewers))
		policy.Reviewers = policy.Reviewers[:0]
		for _, rawReviewer := range raw.Reviewers {
			pk, err := nostr.PubKeyFromHex(strings.TrimSpace(rawReviewer))
			if err != nil {
				return nil, fmt.Errorf("invalid dispatch reviewer for %s: %w", policy.RepoAddress, err)
			}
			reviewer := pk.Hex()
			if _, duplicate := reviewers[reviewer]; duplicate {
				return nil, fmt.Errorf("duplicate dispatch reviewer %s for %s", reviewer, policy.RepoAddress)
			}
			reviewers[reviewer] = struct{}{}
			policy.Reviewers = append(policy.Reviewers, reviewer)
		}
		if len(reviewers) == 0 {
			return nil, fmt.Errorf("at least one dispatch reviewer is required for %s", policy.RepoAddress)
		}
		sort.Strings(policy.Reviewers)
		if _, duplicate := r.policies[policy.RepoAddress]; duplicate {
			return nil, fmt.Errorf("duplicate dispatch review policy for %s", policy.RepoAddress)
		}
		hash := sha256.Sum256(mustJSON(policy))
		entry := dispatchPolicyEntry{policy: policy, reviewers: reviewers, owner: coord.OwnerPubkey,
			repoID: coord.RepoID, digest: hex.EncodeToString(hash[:])}
		r.policies[policy.RepoAddress] = entry
		r.policiesByRepo[coord.RepoID] = append(r.policiesByRepo[coord.RepoID], entry)
	}
	return r, nil
}

func (r *DispatchPolicyResolver) Enabled() bool { return r != nil && len(r.policies) > 0 }

// HandleEvent persists only evidence relevant to configured repositories.
// handled=false lets ordinary NIP-22 comments and unrelated audits continue
// through the bridge's existing consumers.
func (r *DispatchPolicyResolver) HandleEvent(ctx context.Context, ev *nostr.Event) (bool, error) {
	if !r.Enabled() || ev == nil {
		return false, nil
	}
	switch ev.Kind {
	case nostr.KindRepositoryAnnouncement:
		return r.ingestAuthority(ctx, ev)
	case nostr.KindComment:
		return r.ingestReview(ctx, ev)
	case nostr.Kind(cascadia.CAS_AUDIT):
		return r.ingestAudit(ctx, ev)
	default:
		return false, nil
	}
}

func (r *DispatchPolicyResolver) ingestAuthority(ctx context.Context, ev *nostr.Event) (bool, error) {
	repoID, ok := routingTagValue(ev.Tags, "d")
	entries := r.policiesByRepo[repoID]
	if !ok || len(entries) == 0 {
		return false, nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return true, fmt.Errorf("dispatch authority signature validation: %w", err)
	}
	if time.Unix(int64(ev.CreatedAt), 0).UTC().After(r.now().UTC().Add(r.futureSkew)) {
		return true, dispatchPolicyDenied("repository authority timestamp is implausibly far in the future")
	}
	if _, err := strictTwoFieldTag(ev.Tags, "d"); err != nil {
		return true, fmt.Errorf("dispatch authority announcement: %w", err)
	}
	author := ev.PubKey.Hex()
	allowed := false
	for _, entry := range entries {
		if author == entry.owner {
			allowed = true
			break
		}
		if _, configured := entry.reviewers[author]; configured {
			allowed = true
			break
		}
	}
	if !allowed {
		// Admit a currently delegated intermediate maintainer without opening
		// an attacker-controlled unbounded repository-announcement cache.
		pool, err := r.authorityPool(ctx, repoID)
		if err == nil {
			pool = append(pool, *ev)
			for _, entry := range entries {
				if ok, _ := nostrauthz.NewResolver(pool).IsAuthorized(author, entry.policy.RepoAddress); ok {
					allowed = true
					break
				}
			}
		}
	}
	if !allowed {
		return false, nil
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return true, err
	}
	return true, r.store.SaveRepositoryAuthorityEvent(ctx, store.RepositoryAuthorityEvent{
		AuthorPubkey: author, RepoID: repoID, EventID: ev.ID.Hex(), EventCreatedAt: int64(ev.CreatedAt),
		EventJSON: string(raw), ObservedAt: r.now().UTC(),
	})
}

func (r *DispatchPolicyResolver) ingestReview(ctx context.Context, ev *nostr.Event) (bool, error) {
	repoAddress, hasRepo := routingTagValue(ev.Tags, "A")
	_, hasBase := routingTagValue(ev.Tags, "base_commit")
	_, hasTip := routingTagValue(ev.Tags, "tip_commit")
	_, hasDiff := routingTagValue(ev.Tags, "diff_sha256")
	entry, configured := r.policies[repoAddress]
	if !hasRepo || !configured || (!hasBase && !hasTip && !hasDiff) {
		return false, nil
	}
	if _, allowed := entry.reviewers[ev.PubKey.Hex()]; !allowed {
		return true, dispatchPolicyDenied("review signer is not allowed by repository policy")
	}
	evidence, err := parseDispatchReviewEvent(ev)
	if err != nil {
		return true, err
	}
	return true, r.store.SaveDispatchReviewEvidence(ctx, evidence)
}

func (r *DispatchPolicyResolver) ingestAudit(ctx context.Context, ev *nostr.Event) (bool, error) {
	schema, hasSchema := routingTagValue(ev.Tags, "schema")
	typeName, hasType := routingTagValue(ev.Tags, "type")
	if !hasSchema || !hasType || schema != canonicalReviewAuditSchema || typeName != canonicalReviewAuditType {
		return false, nil
	}
	audit, err := parseDispatchReviewAudit(ev)
	if err != nil {
		return true, err
	}
	entry, configured := r.policies[audit.RepoAddress]
	if !configured {
		return false, nil
	}
	if _, allowed := entry.reviewers[audit.ReviewerPubkey]; !allowed {
		return true, dispatchPolicyDenied("review attestation signer is not allowed by repository policy")
	}
	return true, r.store.SaveDispatchReviewAudit(ctx, audit)
}

// Resolve joins the exact immutable trigger source to one current, explicit
// approval. It intentionally rejects direct/manual triggers without a PR event
// ID and never treats legacy Drydock review-published audits as acceptance.
func (r *DispatchPolicyResolver) Resolve(ctx context.Context, envelope store.TriggerEnvelope) (DispatchApproval, error) {
	if !r.Enabled() {
		return DispatchApproval{}, dispatchPolicyDenied("no dispatch review policies are configured")
	}
	entry, ok := r.policies[strings.TrimSpace(envelope.RepoAddress)]
	if !ok {
		return DispatchApproval{}, dispatchPolicyDenied("repository has no dispatch review policy")
	}
	if envelope.PREventID == "" || !validEventIDString(envelope.PREventID) {
		return DispatchApproval{}, dispatchPolicyDenied("trigger lacks immutable pull-request review lineage")
	}
	if !validCommitSHA.MatchString(envelope.SourceCommit) || !validCommitSHA.MatchString(envelope.SourceTree) ||
		!validCommitSHA.MatchString(envelope.AcceptedCommit) {
		return DispatchApproval{}, dispatchPolicyDenied("trigger commit/tree lineage is malformed")
	}
	pool, err := r.authorityPool(ctx, entry.repoID)
	if err != nil {
		return DispatchApproval{}, fmt.Errorf("resolve current repository authority: %w", err)
	}
	authority, err := nostrauthz.NewResolver(pool).Resolve(entry.policy.RepoAddress)
	if err != nil {
		return DispatchApproval{}, dispatchPolicyDenied("current repository reviewer authority is unavailable: %v", err)
	}
	audits, err := r.store.ListDispatchReviewAuditsForSource(ctx, entry.policy.RepoAddress, envelope.SourceCommit)
	if err != nil {
		return DispatchApproval{}, fmt.Errorf("list review attestations: %w", err)
	}
	now := r.now().UTC()
	var accepted *DispatchApproval
	for _, storedAudit := range audits {
		if _, allowed := entry.reviewers[storedAudit.ReviewerPubkey]; !allowed || !authority.IsAuthorized(storedAudit.ReviewerPubkey) {
			continue
		}
		if storedAudit.Outcome != "approved" {
			return DispatchApproval{}, dispatchPolicyDenied("conflicting non-approved review attestation exists")
		}
		var auditEvent nostr.Event
		if err := json.Unmarshal([]byte(storedAudit.EventJSON), &auditEvent); err != nil {
			return DispatchApproval{}, dispatchPolicyDenied("persisted review attestation is invalid")
		}
		audit, err := parseDispatchReviewAudit(&auditEvent)
		if err != nil || !sameStoredReviewAudit(storedAudit, audit) {
			return DispatchApproval{}, dispatchPolicyDenied("persisted review attestation failed revalidation")
		}
		review, err := r.store.GetDispatchReviewEvidence(ctx, audit.ReviewEventID)
		if errors.Is(err, sql.ErrNoRows) {
			return DispatchApproval{}, dispatchPolicyDenied("review attestation has no signed review evidence")
		}
		if err != nil {
			return DispatchApproval{}, fmt.Errorf("load signed review evidence: %w", err)
		}
		var reviewEvent nostr.Event
		if err := json.Unmarshal([]byte(review.EventJSON), &reviewEvent); err != nil {
			return DispatchApproval{}, dispatchPolicyDenied("persisted review evidence is invalid")
		}
		parsedReview, err := parseDispatchReviewEvent(&reviewEvent)
		if err != nil || !sameStoredReviewEvidence(review, parsedReview) {
			return DispatchApproval{}, dispatchPolicyDenied("persisted review evidence failed revalidation")
		}
		if review.ReviewerPubkey != audit.ReviewerPubkey || review.EventID != audit.ReviewEventID ||
			review.RepoAddress != entry.policy.RepoAddress || review.PatchEventID != strings.ToLower(envelope.PREventID) ||
			review.TipCommit != strings.ToLower(envelope.SourceCommit) || audit.Commit != strings.ToLower(envelope.SourceCommit) {
			return DispatchApproval{}, dispatchPolicyDenied("review/audit/trigger immutable source does not match")
		}
		reviewAt := time.Unix(review.EventCreatedAt, 0).UTC()
		auditAt := time.Unix(audit.EventCreatedAt, 0).UTC()
		triggerAt := envelope.CreatedAt.UTC()
		if triggerAt.IsZero() {
			triggerAt = now
		}
		if reviewAt.After(auditAt) || reviewAt.Before(now.Add(-r.approvalMaxAge)) ||
			auditAt.Before(now.Add(-r.approvalMaxAge)) || reviewAt.After(now.Add(r.futureSkew)) ||
			auditAt.After(now.Add(r.futureSkew)) || auditAt.After(triggerAt.Add(r.futureSkew)) {
			return DispatchApproval{}, dispatchPolicyDenied("review approval is stale or outside the trigger time window")
		}
		candidate := DispatchApproval{
			ReviewEventID: review.EventID, AuditEventID: audit.EventID, ReviewerPubkey: audit.ReviewerPubkey,
			RepoAddress: review.RepoAddress, RootEventID: review.RootEventID, PatchEventID: review.PatchEventID,
			BaseCommit: review.BaseCommit, SourceCommit: review.TipCommit, SourceTree: strings.ToLower(envelope.SourceTree),
			DiffSHA256: review.DiffSHA256, PolicyVersion: entry.policy.Version, PolicySHA256: entry.digest,
			ReviewCreated: reviewAt, AuditCreated: auditAt,
		}
		if accepted != nil {
			return DispatchApproval{}, dispatchPolicyDenied("multiple current review approvals conflict for the immutable source")
		}
		accepted = &candidate
	}
	if accepted == nil {
		return DispatchApproval{}, dispatchPolicyDenied("no current authorized review approval exists for the immutable source")
	}
	return *accepted, nil
}

func (r *DispatchPolicyResolver) authorityPool(ctx context.Context, repoID string) ([]nostr.Event, error) {
	stored, err := r.store.ListRepositoryAuthorityEvents(ctx, repoID)
	if err != nil {
		return nil, err
	}
	pool := make([]nostr.Event, 0, len(stored))
	for _, record := range stored {
		var ev nostr.Event
		if err := json.Unmarshal([]byte(record.EventJSON), &ev); err != nil ||
			ev.ID.Hex() != record.EventID || ev.PubKey.Hex() != record.AuthorPubkey ||
			int64(ev.CreatedAt) != record.EventCreatedAt || ev.Kind != nostr.KindRepositoryAnnouncement ||
			nostrverify.ValidateEventIDAndSignature(&ev) != nil {
			continue
		}
		if got, err := strictTwoFieldTag(ev.Tags, "d"); err != nil || got != repoID {
			continue
		}
		pool = append(pool, ev)
	}
	return pool, nil
}

func parseDispatchReviewEvent(ev *nostr.Event) (store.DispatchReviewEvidence, error) {
	if ev == nil || ev.Kind != nostr.KindComment {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("canonical kind-1111 review evidence is required")
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review signature is invalid")
	}
	repoAddress, err := strictTwoFieldTag(ev.Tags, "A")
	if err != nil {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review repository linkage: %v", err)
	}
	coord, err := nostrauthz.ParseRepositoryCoordinate(repoAddress)
	if err != nil || coord.String() != repoAddress {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review repository coordinate is invalid")
	}
	rootID, err := strictFourFieldTag(ev.Tags, "E")
	if err != nil || !validEventIDString(rootID) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review root linkage is invalid")
	}
	patchID, err := strictFourFieldTag(ev.Tags, "e")
	if err != nil || !validEventIDString(patchID) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review patch linkage is invalid")
	}
	rootKind, err := strictTwoFieldTag(ev.Tags, "K")
	if err != nil || rootKind != strconv.Itoa(int(relay.KindPROpen)) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review root kind is not a pull request")
	}
	patchKind, err := strictTwoFieldTag(ev.Tags, "k")
	if err != nil || (patchKind != strconv.Itoa(int(relay.KindPROpen)) && patchKind != strconv.Itoa(int(relay.KindPRUpdate))) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review patch kind is not a pull-request revision")
	}
	if patchKind == strconv.Itoa(int(relay.KindPROpen)) && rootID != patchID {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("root pull-request review has mismatched root and patch linkage")
	}
	baseCommit, err := strictTwoFieldTag(ev.Tags, "base_commit")
	if err != nil || baseCommit != strings.ToLower(baseCommit) || !validCommitSHA.MatchString(baseCommit) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review base commit is invalid")
	}
	tipCommit, err := strictTwoFieldTag(ev.Tags, "tip_commit")
	if err != nil || tipCommit != strings.ToLower(tipCommit) || !validCommitSHA.MatchString(tipCommit) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review tip commit is invalid")
	}
	diffSHA, err := strictTwoFieldTag(ev.Tags, "diff_sha256")
	if err != nil || diffSHA != strings.ToLower(diffSHA) || !validEventIDString(diffSHA) {
		return store.DispatchReviewEvidence{}, dispatchPolicyDenied("review diff digest is invalid")
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return store.DispatchReviewEvidence{}, err
	}
	return store.DispatchReviewEvidence{
		EventID: ev.ID.Hex(), ReviewerPubkey: ev.PubKey.Hex(), RepoAddress: repoAddress,
		RootEventID: rootID, PatchEventID: patchID, BaseCommit: strings.ToLower(baseCommit),
		TipCommit: strings.ToLower(tipCommit), DiffSHA256: strings.ToLower(diffSHA),
		EventCreatedAt: int64(ev.CreatedAt), EventJSON: string(raw), ObservedAt: time.Now().UTC(),
	}, nil
}

func parseDispatchReviewAudit(ev *nostr.Event) (store.DispatchReviewAudit, error) {
	if ev == nil || int(ev.Kind) != cascadia.CAS_AUDIT {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("canonical kind-4903 review attestation is required")
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation signature is invalid")
	}
	for key, want := range map[string]string{
		"domain": canonicalReviewAuditDomain, "type": canonicalReviewAuditType, "schema": canonicalReviewAuditSchema,
	} {
		got, err := strictTwoFieldTag(ev.Tags, key)
		if err != nil || got != want {
			return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation %s is invalid", key)
		}
	}
	var payload cascadia.CascadiaAuditReviewV1Payload
	decoder := json.NewDecoder(bytes.NewBufferString(ev.Content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation payload is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation payload has trailing data")
	}
	if err := payload.Validate(); err != nil {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation payload is incomplete")
	}
	reviewID := strings.ToLower(strings.TrimSpace(payload.ReviewId))
	repository := strings.TrimSpace(payload.Repository)
	commit := strings.ToLower(strings.TrimSpace(payload.Commit))
	outcome := strings.ToLower(strings.TrimSpace(payload.Outcome))
	if reviewID != payload.ReviewId || repository != payload.Repository ||
		commit != payload.Commit || outcome != payload.Outcome {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation fields are not canonical")
	}
	payload.ReviewId, payload.Repository, payload.Commit, payload.Outcome = reviewID, repository, commit, outcome
	if !validEventIDString(payload.ReviewId) {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation review_id is invalid")
	}
	coord, err := nostrauthz.ParseRepositoryCoordinate(payload.Repository)
	if err != nil || coord.String() != payload.Repository {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation repository is invalid")
	}
	if !validCommitSHA.MatchString(payload.Commit) {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation commit is invalid")
	}
	if !slices.Contains([]string{"approved", "rejected", "revoked"}, payload.Outcome) {
		return store.DispatchReviewAudit{}, dispatchPolicyDenied("review attestation outcome is unsupported")
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return store.DispatchReviewAudit{}, err
	}
	return store.DispatchReviewAudit{
		EventID: ev.ID.Hex(), ReviewerPubkey: ev.PubKey.Hex(), ReviewEventID: payload.ReviewId,
		RepoAddress: payload.Repository, Commit: payload.Commit, Outcome: payload.Outcome,
		EventCreatedAt: int64(ev.CreatedAt), EventJSON: string(raw), ObservedAt: time.Now().UTC(),
	}, nil
}

func strictTwoFieldTag(tags nostr.Tags, key string) (string, error) {
	return strictTagWithLength(tags, key, 2)
}

func strictFourFieldTag(tags nostr.Tags, key string) (string, error) {
	return strictTagWithLength(tags, key, 4)
}

func strictTagWithLength(tags nostr.Tags, key string, length int) (string, error) {
	value := ""
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != length || value != "" || strings.TrimSpace(tag[1]) == "" {
			return "", fmt.Errorf("exactly one canonical %s tag is required", key)
		}
		value = strings.TrimSpace(tag[1])
	}
	if value == "" {
		return "", fmt.Errorf("missing %s tag", key)
	}
	return value, nil
}

func routingTagValue(tags nostr.Tags, key string) (string, bool) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key && strings.TrimSpace(tag[1]) != "" {
			return strings.TrimSpace(tag[1]), true
		}
	}
	return "", false
}

func sameStoredReviewEvidence(stored, parsed store.DispatchReviewEvidence) bool {
	return stored.EventID == parsed.EventID && stored.ReviewerPubkey == parsed.ReviewerPubkey &&
		stored.RepoAddress == parsed.RepoAddress && stored.RootEventID == parsed.RootEventID &&
		stored.PatchEventID == parsed.PatchEventID && stored.BaseCommit == parsed.BaseCommit &&
		stored.TipCommit == parsed.TipCommit && stored.DiffSHA256 == parsed.DiffSHA256 &&
		stored.EventCreatedAt == parsed.EventCreatedAt && stored.EventJSON == parsed.EventJSON
}

func sameStoredReviewAudit(stored, parsed store.DispatchReviewAudit) bool {
	return stored.EventID == parsed.EventID && stored.ReviewerPubkey == parsed.ReviewerPubkey &&
		stored.ReviewEventID == parsed.ReviewEventID && stored.RepoAddress == parsed.RepoAddress &&
		stored.Commit == parsed.Commit && stored.Outcome == parsed.Outcome &&
		stored.EventCreatedAt == parsed.EventCreatedAt && stored.EventJSON == parsed.EventJSON
}

type dispatchPolicyError struct{ reason string }

func (e *dispatchPolicyError) Error() string {
	return ErrDispatchPolicyDenied.Error() + ": " + e.reason
}
func (e *dispatchPolicyError) Unwrap() error      { return ErrDispatchPolicyDenied }
func (e *dispatchPolicyError) NonRetryable() bool { return true }

func dispatchPolicyDenied(format string, args ...any) error {
	return &dispatchPolicyError{reason: fmt.Sprintf(format, args...)}
}

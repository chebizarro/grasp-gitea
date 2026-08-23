// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const mergeStatusPolicyVersion = "hiveci.nip34-merge-status.v1"

var (
	ErrUnauthorizedMergeStatus = errors.New("unauthorized merge-status author")
	ErrMissingPRLinkage        = errors.New("missing persisted pull-request linkage")
	ErrStaleMergeStatus        = errors.New("stale merge status")
	ErrSupersededCommit        = errors.New("superseded pull-request commit")
	ErrMissingGitObject        = errors.New("required Git object is missing")
	ErrForcePushAmbiguity      = errors.New("force-push ambiguity")
	ErrMalformedMergeStatus    = errors.New("malformed NIP-34 merge status")
)

type mergeStatusStore interface {
	Store
	SaveReviewedPRRevision(context.Context, store.ReviewedPRRevision) error
	GetReviewedPRRevision(context.Context, string) (store.ReviewedPRRevision, error)
	GetLatestReviewedPRRevision(context.Context, string, string) (store.ReviewedPRRevision, error)
	SaveAcceptedRepositoryState(context.Context, store.AcceptedRepositoryState) error
	GetAcceptedRepositoryState(context.Context, string) (store.AcceptedRepositoryState, error)
	GetReflectedEvent(context.Context, string) (store.ReflectedEvent, error)
	ClaimMergeTriggerEnvelope(context.Context, store.MergeTriggerEnvelope) (store.MergeTriggerEnvelope, bool, error)
	GetMergeTriggerEnvelopeByStatusID(context.Context, string) (store.MergeTriggerEnvelope, error)
	SavePendingMergeStatus(context.Context, store.PendingMergeStatus) error
	ListPendingMergeStatuses(context.Context, int) ([]store.PendingMergeStatus, error)
	DeletePendingMergeStatus(context.Context, string) error
}

type mergeStatusTags struct {
	repoAddress, rootID, replyID, mergeCommit string
}

func (r *Runner) handleMergeStatus(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	st, ok := r.store.(mergeStatusStore)
	if !ok {
		return fmt.Errorf("%w: durable merge-status store unavailable", ErrMissingPRLinkage)
	}
	encodedStatus, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode merge status evidence: %w", err)
	}

	// A previously claimed envelope is the durable authorization decision. On
	// replay, resume the idempotent workflow dispatch without re-reading mutable
	// state; this recovers a crash after claim and before kind-5401 publication.
	if existing, err := st.GetMergeTriggerEnvelopeByStatusID(ctx, ev.ID.Hex()); err == nil {
		if existing.PolicyVersion != mergeStatusPolicyVersion {
			return fmt.Errorf("unsupported stored merge-status policy %q", existing.PolicyVersion)
		}
		if existing.StatusEventID != ev.ID.Hex() || existing.IdempotencyKey != mergeTriggerKey(ev.ID.Hex()) {
			return fmt.Errorf("stored merge-trigger identity is invalid")
		}
		if existing.EvidenceJSON != "" && (existing.Source != store.TriggerSourceNIP34MergeStatus ||
			existing.TriggerID != ev.ID.Hex() || existing.Actor != ev.PubKey.Hex() ||
			existing.Action != "push" || existing.EvidenceJSON != string(encodedStatus)) {
			return &store.TriggerConflictError{Source: store.TriggerSourceNIP34MergeStatus, TriggerID: ev.ID.Hex()}
		}
		ownerPub, repoID, parsed := parseRepoAddr(existing.RepoAddress)
		if !parsed {
			return fmt.Errorf("stored merge-trigger repository address is invalid")
		}
		mapping, err := st.GetProvisionedMappingByRepoAddr(ctx, ownerPub, repoID)
		if err != nil {
			return fmt.Errorf("recover merge-trigger repository mapping: %w", err)
		}
		resume := existing
		if resume.EvidenceJSON == "" {
			// Rows imported from the sibling schema predate actor/evidence
			// columns. The replayed event was signature-verified by HandleEvent,
			// so reconstruct only for this dispatch without mutating history.
			resume.Actor = ev.PubKey.Hex()
			resume.Action = "push"
			resume.EvidenceJSON = string(encodedStatus)
		}
		err = r.runForCommit(ctx, mapping, ev, sourceRelay, "push", resume.Branch,
			resume.AcceptedCommit, &resume)
		if err == nil {
			_ = st.DeletePendingMergeStatus(ctx, ev.ID.Hex())
		}
		return err
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("lookup merge-trigger replay: %w", err)
	}

	tags, err := parseMergeStatusTags(ev.Tags)
	if err != nil {
		return err
	}
	ownerPub, repoID, _ := parseRepoAddr(tags.repoAddress)
	mapping, err := st.GetProvisionedMappingByRepoAddr(ctx, ownerPub, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: repository %s is not provisioned", ErrMissingPRLinkage, tags.repoAddress)
	}
	if err != nil {
		return fmt.Errorf("resolve merge-status repository: %w", err)
	}
	if !r.isRepoCIAllowed(mapping.Owner, mapping.RepoID) {
		return fmt.Errorf("%w: repository is outside CI trigger policy", ErrUnauthorizedMergeStatus)
	}
	authorized, authErr := r.mergeStatusAuthorAuthorized(ctx, mapping, ev.PubKey.Hex())
	if authErr != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorizedMergeStatus, authErr)
	}
	if !authorized {
		return fmt.Errorf("%w: signer %s", ErrUnauthorizedMergeStatus, ev.PubKey.Hex())
	}

	pending := store.PendingMergeStatus{
		EventID: ev.ID.Hex(), EventJSON: string(encodedStatus), SourceRelay: sourceRelay,
		ObservedAt: time.Now().UTC(),
	}
	if err := st.SavePendingMergeStatus(ctx, pending); err != nil {
		return fmt.Errorf("persist pending merge status: %w", err)
	}
	keepPending := false
	defer func() {
		if !keepPending {
			_ = st.DeletePendingMergeStatus(ctx, ev.ID.Hex())
		}
	}()

	root, err := st.GetReviewedPRRevision(ctx, tags.rootID)
	if errors.Is(err, sql.ErrNoRows) {
		keepPending = true
		return retainPendingMergeStatus(ctx, st, pending,
			fmt.Errorf("%w: root %s was not reviewed", ErrMissingPRLinkage, tags.rootID))
	}
	if err != nil {
		return fmt.Errorf("lookup reviewed PR root: %w", err)
	}
	if root.EventID != root.RootEventID || root.Kind != relay.KindPROpen || root.RepoAddress != tags.repoAddress {
		return fmt.Errorf("%w: root is not a persisted PR for this repository", ErrMissingPRLinkage)
	}
	reflectedRoot, err := st.GetReflectedEvent(ctx, tags.rootID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: PR root has no persisted Gitea review", ErrMissingPRLinkage)
	}
	if err != nil {
		return fmt.Errorf("lookup reflected PR root: %w", err)
	}
	if reflectedRoot.GiteaRepoID != mapping.GiteaRepoID || reflectedRoot.GiteaIndex <= 0 || reflectedRoot.Kind != relay.KindPROpen {
		return fmt.Errorf("%w: PR root is not a reviewed PR in this repository", ErrMissingPRLinkage)
	}

	acceptedRevision := root
	if tags.replyID != "" {
		acceptedRevision, err = st.GetReviewedPRRevision(ctx, tags.replyID)
		if errors.Is(err, sql.ErrNoRows) {
			keepPending = true
			return retainPendingMergeStatus(ctx, st, pending,
				fmt.Errorf("%w: reply revision %s was not reviewed", ErrMissingPRLinkage, tags.replyID))
		}
		if err != nil {
			return fmt.Errorf("lookup reviewed PR reply: %w", err)
		}
		if acceptedRevision.Kind != relay.KindPRUpdate || acceptedRevision.RootEventID != root.EventID ||
			acceptedRevision.RepoAddress != tags.repoAddress {
			return fmt.Errorf("%w: reply does not update the linked PR", ErrMissingPRLinkage)
		}
	}
	latest, err := st.GetLatestReviewedPRRevision(ctx, root.EventID, tags.repoAddress)
	if errors.Is(err, store.ErrAmbiguousPRRevision) {
		return fmt.Errorf("%w: %v", ErrForcePushAmbiguity, err)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			keepPending = true
			return retainPendingMergeStatus(ctx, st, pending,
				fmt.Errorf("%w: no reviewed PR revision", ErrMissingPRLinkage))
		}
		return fmt.Errorf("resolve latest reviewed PR revision: %w", err)
	}
	if latest.EventID != acceptedRevision.EventID || latest.SourceCommit != acceptedRevision.SourceCommit {
		return fmt.Errorf("%w: status links %s but latest revision is %s", ErrSupersededCommit,
			acceptedRevision.EventID, latest.EventID)
	}
	if int64(ev.CreatedAt) < latest.EventCreatedAt {
		return fmt.Errorf("%w: status predates the reviewed revision", ErrStaleMergeStatus)
	}
	if err := validateStatusRecipients(ev.Tags, mapping.Pubkey, root.AuthorPubkey, acceptedRevision.AuthorPubkey); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedMergeStatus, err)
	}

	acceptedState, err := st.GetAcceptedRepositoryState(ctx, tags.repoAddress)
	if errors.Is(err, sql.ErrNoRows) {
		keepPending = true
		return retainPendingMergeStatus(ctx, st, pending,
			fmt.Errorf("%w: no accepted repository state", ErrStaleMergeStatus))
	}
	if err != nil {
		return fmt.Errorf("resolve accepted repository state: %w", err)
	}
	if int64(ev.CreatedAt) < acceptedState.EventCreatedAt {
		return fmt.Errorf("%w: status predates the accepted repository state", ErrStaleMergeStatus)
	}
	var stateEvent nostr.Event
	if err := json.Unmarshal([]byte(acceptedState.EventJSON), &stateEvent); err != nil {
		return fmt.Errorf("%w: decode accepted state: %v", ErrStaleMergeStatus, err)
	}
	stateRepoID, stateTagErr := strictExactlyOneTagValue(stateEvent.Tags, "d")
	if err := nostrverify.ValidateEventIDAndSignature(&stateEvent); err != nil ||
		stateEvent.ID.Hex() != acceptedState.EventID || stateEvent.Kind != relay.KindRepositoryState ||
		stateTagErr != nil || stateRepoID != mapping.RepoID {
		return fmt.Errorf("%w: persisted accepted state is invalid", ErrStaleMergeStatus)
	}
	branch, acceptedCommit, err := strictStateHEAD(stateEvent.Tags)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStaleMergeStatus, err)
	}
	if !strings.EqualFold(acceptedCommit, tags.mergeCommit) {
		return fmt.Errorf("%w: merge commit is not the accepted HEAD", ErrStaleMergeStatus)
	}

	repoPath := filepath.Join(r.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	retainGitDependency := func(cause error) error {
		if !errors.Is(cause, ErrMissingGitObject) {
			return cause
		}
		keepPending = true
		return retainPendingMergeStatus(ctx, st, pending, cause)
	}
	if err := requireCommitObject(ctx, repoPath, acceptedRevision.SourceCommit); err != nil {
		return retainGitDependency(err)
	}
	if err := requireCommitObject(ctx, repoPath, acceptedCommit); err != nil {
		return retainGitDependency(err)
	}
	localHead, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", "refs/heads/"+branch+"^{commit}")
	if err != nil {
		return retainGitDependency(fmt.Errorf("%w: accepted branch %s is unavailable locally: %v", ErrMissingGitObject, branch, err))
	}
	if !strings.EqualFold(localHead, acceptedCommit) {
		return fmt.Errorf("%w: local accepted branch has advanced or diverged", ErrStaleMergeStatus)
	}

	sourceTree, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", acceptedRevision.SourceCommit+"^{tree}")
	if err != nil || !validCommitSHA.MatchString(sourceTree) {
		return retainGitDependency(fmt.Errorf("%w: source tree for %s", ErrMissingGitObject, acceptedRevision.SourceCommit))
	}
	base, err := validateMergeRelationship(ctx, repoPath, acceptedRevision.SourceCommit, acceptedCommit)
	if err != nil {
		return retainGitDependency(err)
	}
	patchDigest, err := sourcePatchDigest(ctx, repoPath, base, acceptedRevision.SourceCommit)
	if err != nil {
		return retainGitDependency(err)
	}

	envelope := store.MergeTriggerEnvelope{
		IdempotencyKey: mergeTriggerKey(ev.ID.Hex()), Source: store.TriggerSourceNIP34MergeStatus,
		TriggerID: ev.ID.Hex(), Actor: ev.PubKey.Hex(), Action: "push", EvidenceJSON: string(encodedStatus),
		PREventID:     acceptedRevision.EventID,
		StatusEventID: ev.ID.Hex(), SourceCommit: acceptedRevision.SourceCommit,
		SourceTree: sourceTree, PatchDigest: patchDigest, AcceptedCommit: acceptedCommit,
		RepoAddress: tags.repoAddress, PolicyVersion: mergeStatusPolicyVersion,
		Branch: branch, CreatedAt: time.Now().UTC(),
	}
	stored, _, err := st.ClaimMergeTriggerEnvelope(ctx, envelope)
	if err != nil {
		return fmt.Errorf("persist merge-trigger envelope: %w", err)
	}
	// Retain the status until the idempotent dispatcher succeeds. This closes
	// the crash window after the envelope is claimed but before kind 5401 is
	// durably handed to the dispatcher.
	keepPending = true
	err = r.runForCommit(ctx, mapping, ev, sourceRelay, "push", branch, acceptedCommit, &stored)
	if err == nil {
		keepPending = false
	}
	return err
}

func retainPendingMergeStatus(ctx context.Context, st mergeStatusStore, pending store.PendingMergeStatus, cause error) error {
	pending.LastError = cause.Error()
	if err := st.SavePendingMergeStatus(ctx, pending); err != nil {
		return fmt.Errorf("%v; retain pending merge status: %w", cause, err)
	}
	return cause
}

// RecoverPendingMergeStatuses retries authorized statuses retained across an
// out-of-order relay delivery or process restart. Terminally invalid events are
// removed by handleMergeStatus; unresolved dependencies remain durable.
func (r *Runner) RecoverPendingMergeStatuses(ctx context.Context) error {
	return r.retryPendingMergeStatuses(ctx)
}

func (r *Runner) retryPendingMergeStatuses(ctx context.Context) error {
	st, ok := r.store.(mergeStatusStore)
	if !ok {
		return nil
	}
	pending, err := st.ListPendingMergeStatuses(ctx, 256)
	if err != nil {
		return fmt.Errorf("list pending merge statuses: %w", err)
	}
	for _, item := range pending {
		var ev nostr.Event
		if err := json.Unmarshal([]byte(item.EventJSON), &ev); err != nil ||
			ev.Kind != relay.KindStatusApplied || nostrverify.ValidateEventIDAndSignature(&ev) != nil ||
			ev.ID.Hex() != item.EventID {
			_ = st.DeletePendingMergeStatus(ctx, item.EventID)
			continue
		}
		if err := r.handleMergeStatus(ctx, &ev, item.SourceRelay); err != nil {
			r.logger.Debug("HiveCI merge status remains rejected", "event", item.EventID, "error", err)
		}
	}
	return nil
}

func (r *Runner) persistReviewedPRRevision(ctx context.Context, mapping store.Mapping, ev *nostr.Event, commit string) error {
	st, ok := r.store.(mergeStatusStore)
	if !ok {
		return nil
	}
	repoAddress, err := strictRepoAddress(ev.Tags)
	if err != nil {
		return err
	}
	wantAddress := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	if repoAddress != wantAddress {
		return fmt.Errorf("%w: PR repository address does not match mapping", ErrMalformedMergeStatus)
	}
	strictCommit, err := strictSingleSHAValue(ev.Tags, "c")
	if err != nil || !strings.EqualFold(strictCommit, commit) {
		return fmt.Errorf("reviewed PR has malformed or conflicting c tags")
	}
	rootID := ev.ID.Hex()
	if ev.Kind == relay.KindPRUpdate {
		rootID, err = strictPRUpdateRoot(ev.Tags)
		if err != nil {
			return err
		}
		root, err := st.GetReviewedPRRevision(ctx, rootID)
		if err != nil {
			return fmt.Errorf("persist PR update before root is reviewed: %w", err)
		}
		if root.RootEventID != root.EventID || root.RepoAddress != repoAddress || root.Kind != relay.KindPROpen {
			return fmt.Errorf("PR update root is not a reviewed PR")
		}
		rootAuthor, err := strictSinglePubkeyTag(ev.Tags, "P")
		if err != nil || rootAuthor != root.AuthorPubkey || ev.PubKey.Hex() != root.AuthorPubkey {
			return fmt.Errorf("PR update author/thread does not match reviewed root")
		}
		rootRef, err := st.GetReflectedEvent(ctx, rootID)
		if err != nil || rootRef.Kind != relay.KindPROpen || rootRef.GiteaIndex <= 0 {
			return fmt.Errorf("PR update root has no persisted review")
		}
		updateRef, err := st.GetReflectedEvent(ctx, ev.ID.Hex())
		if err != nil || updateRef.Kind != relay.KindPRUpdate || updateRef.GiteaRepoID != rootRef.GiteaRepoID ||
			updateRef.GiteaIndex != rootRef.GiteaIndex {
			return fmt.Errorf("PR update was not reflected into the reviewed PR")
		}
	}
	encoded, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return st.SaveReviewedPRRevision(ctx, store.ReviewedPRRevision{
		EventID: ev.ID.Hex(), RootEventID: rootID, RepoAddress: repoAddress,
		Kind: int(ev.Kind), AuthorPubkey: ev.PubKey.Hex(), SourceCommit: commit,
		EventCreatedAt: int64(ev.CreatedAt), EventJSON: string(encoded), ObservedAt: time.Now().UTC(),
	})
}

func (r *Runner) persistAcceptedRepositoryState(ctx context.Context, mapping store.Mapping, ev *nostr.Event) error {
	st, ok := r.store.(mergeStatusStore)
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	repoAddress := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
	return st.SaveAcceptedRepositoryState(ctx, store.AcceptedRepositoryState{
		RepoAddress: repoAddress, EventID: ev.ID.Hex(), AuthorPubkey: ev.PubKey.Hex(),
		EventCreatedAt: int64(ev.CreatedAt), EventJSON: string(encoded), AcceptedAt: time.Now().UTC(),
	})
}

func (r *Runner) mergeStatusAuthorAuthorized(ctx context.Context, mapping store.Mapping, author string) (bool, error) {
	author = strings.TrimSpace(author)
	if author == "" {
		return false, nil
	}
	if r.signer != nil && strings.EqualFold(strings.TrimSpace(r.signer.PublicKey()), author) {
		return true, nil
	}
	return r.workflowAuthorAuthorized(ctx, mapping, author)
}

func parseMergeStatusTags(tags nostr.Tags) (mergeStatusTags, error) {
	repoAddress, err := strictRepoAddress(tags)
	if err != nil {
		return mergeStatusTags{}, err
	}
	var rootID, replyID string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "e" {
			continue
		}
		if len(tag) < 4 || !validEventIDString(tag[1]) {
			return mergeStatusTags{}, fmt.Errorf("%w: every e tag must have a valid root/reply marker", ErrMalformedMergeStatus)
		}
		switch tag[3] {
		case "root":
			if rootID != "" {
				return mergeStatusTags{}, fmt.Errorf("%w: duplicate root e tag", ErrMalformedMergeStatus)
			}
			rootID = tag[1]
		case "reply":
			if replyID != "" {
				return mergeStatusTags{}, fmt.Errorf("%w: duplicate reply e tag", ErrMalformedMergeStatus)
			}
			replyID = tag[1]
		default:
			return mergeStatusTags{}, fmt.Errorf("%w: unrecognized e-tag marker %q", ErrMalformedMergeStatus, tag[3])
		}
	}
	if rootID == "" || replyID == rootID {
		return mergeStatusTags{}, fmt.Errorf("%w: exactly one distinct root linkage is required", ErrMalformedMergeStatus)
	}
	mergeCommit, err := strictMergeCommitValue(tags)
	if err != nil {
		return mergeStatusTags{}, fmt.Errorf("%w: %v", ErrMalformedMergeStatus, err)
	}
	matchedR := false
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "r" && strings.EqualFold(strings.TrimSpace(tag[1]), mergeCommit) {
			matchedR = true
		}
	}
	if !matchedR {
		return mergeStatusTags{}, fmt.Errorf("%w: merge commit must have a matching r tag", ErrMalformedMergeStatus)
	}
	return mergeStatusTags{repoAddress: repoAddress, rootID: rootID, replyID: replyID, mergeCommit: strings.ToLower(mergeCommit)}, nil
}

func strictRepoAddress(tags nostr.Tags) (string, error) {
	var value string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "a" {
			continue
		}
		if (len(tag) != 2 && len(tag) != 3) || strings.TrimSpace(tag[1]) == "" || value != "" {
			return "", fmt.Errorf("%w: exactly one canonical repository a tag is required", ErrMalformedMergeStatus)
		}
		value = strings.TrimSpace(tag[1])
	}
	pubkey, _, ok := parseRepoAddr(value)
	if !ok || !validEventIDString(pubkey) {
		return "", fmt.Errorf("%w: invalid repository address", ErrMalformedMergeStatus)
	}
	return value, nil
}

func strictPRUpdateRoot(tags nostr.Tags) (string, error) {
	var root string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "E" {
			continue
		}
		if len(tag) < 2 || !validEventIDString(tag[1]) || root != "" {
			return "", fmt.Errorf("PR update must contain exactly one valid E root")
		}
		root = tag[1]
	}
	if root == "" {
		return "", fmt.Errorf("PR update is missing its E root")
	}
	return root, nil
}

func strictExactlyOneTagValue(tags nostr.Tags, key string) (string, error) {
	var value string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != 2 || value != "" || strings.TrimSpace(tag[1]) == "" {
			return "", fmt.Errorf("exactly one valid %s tag is required", key)
		}
		value = strings.TrimSpace(tag[1])
	}
	if value == "" {
		return "", fmt.Errorf("missing %s tag", key)
	}
	return value, nil
}

func strictMergeCommitValue(tags nostr.Tags) (string, error) {
	var value string
	for _, tag := range tags {
		if len(tag) == 0 || (tag[0] != "merge-commit" && tag[0] != "merge-commit-id") {
			continue
		}
		if len(tag) != 2 || value != "" || !validCommitSHA.MatchString(strings.TrimSpace(tag[1])) {
			return "", fmt.Errorf("exactly one valid merge-commit or merge-commit-id tag is required")
		}
		value = strings.TrimSpace(tag[1])
	}
	if value == "" {
		return "", fmt.Errorf("missing merge-commit or merge-commit-id tag")
	}
	return value, nil
}

func strictSingleSHAValue(tags nostr.Tags, key string) (string, error) {
	var value string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != 2 || value != "" || !validCommitSHA.MatchString(strings.TrimSpace(tag[1])) {
			return "", fmt.Errorf("exactly one valid %s tag is required", key)
		}
		value = strings.TrimSpace(tag[1])
	}
	if value == "" {
		return "", fmt.Errorf("missing %s tag", key)
	}
	return value, nil
}

func strictSinglePubkeyTag(tags nostr.Tags, key string) (string, error) {
	var value string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != 2 || value != "" || !validEventIDString(strings.TrimSpace(tag[1])) {
			return "", fmt.Errorf("exactly one valid %s tag is required", key)
		}
		value = strings.TrimSpace(tag[1])
	}
	if value == "" {
		return "", fmt.Errorf("missing %s tag", key)
	}
	return value, nil
}

func validateStatusRecipients(tags nostr.Tags, required ...string) error {
	seen := make(map[string]struct{})
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "p" {
			continue
		}
		if len(tag) != 2 || !validEventIDString(strings.TrimSpace(tag[1])) {
			return fmt.Errorf("every p tag must contain one valid pubkey")
		}
		pubkey := strings.TrimSpace(tag[1])
		if _, duplicate := seen[pubkey]; duplicate {
			return fmt.Errorf("duplicate p recipient %s", pubkey)
		}
		seen[pubkey] = struct{}{}
	}
	for _, pubkey := range required {
		if _, ok := seen[strings.TrimSpace(pubkey)]; !ok {
			return fmt.Errorf("missing required p recipient %s", pubkey)
		}
	}
	return nil
}

func strictStateHEAD(tags nostr.Tags) (string, string, error) {
	head := ""
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "HEAD" {
			continue
		}
		if len(tag) != 2 || head != "" || !strings.HasPrefix(tag[1], "ref: refs/heads/") {
			return "", "", fmt.Errorf("accepted state has ambiguous HEAD")
		}
		head = strings.TrimPrefix(tag[1], "ref: refs/heads/")
	}
	if head == "" || strings.Contains(head, "..") || strings.ContainsAny(head, " ~^:?*[\\") {
		return "", "", fmt.Errorf("accepted state has no valid symbolic HEAD")
	}
	refName := "refs/heads/" + head
	commit, err := strictSingleSHAValue(tags, refName)
	if err != nil {
		return "", "", fmt.Errorf("accepted state HEAD target: %w", err)
	}
	return head, strings.ToLower(commit), nil
}

func requireCommitObject(ctx context.Context, repoPath, commit string) error {
	if !validCommitSHA.MatchString(commit) {
		return fmt.Errorf("%w: invalid commit %q", ErrMissingGitObject, commit)
	}
	cmd := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "cat-file", "-e", commit+"^{commit}")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: commit %s: %s", ErrMissingGitObject, commit, strings.TrimSpace(string(out)))
	}
	return nil
}

type mergeRelationship struct {
	base        string
	firstParent string
}

func resolveMergeRelationship(ctx context.Context, repoPath, sourceCommit, acceptedCommit string) (mergeRelationship, error) {
	parentsLine, err := gitOutput(ctx, repoPath, "rev-list", "--parents", "-n", "1", acceptedCommit)
	if err != nil {
		return mergeRelationship{}, fmt.Errorf("%w: resolve accepted commit parents: %v", ErrMissingGitObject, err)
	}
	parts := strings.Fields(parentsLine)
	if len(parts) < 2 || !strings.EqualFold(parts[0], acceptedCommit) {
		return mergeRelationship{}, fmt.Errorf("%w: accepted commit has no unambiguous base", ErrForcePushAmbiguity)
	}
	firstParent := parts[1]
	if strings.EqualFold(sourceCommit, acceptedCommit) {
		// A fast-forwarded tip does not reveal which ancestor was the target
		// branch at review time. Guessing its first parent would hash only the
		// final commit of a multi-commit PR, so fail closed until the reviewed
		// merge base is explicitly bound by a future policy version.
		return mergeRelationship{}, fmt.Errorf("%w: fast-forward merge base was not review-bound", ErrForcePushAmbiguity)
	}
	if len(parts) != 3 || !strings.EqualFold(parts[2], sourceCommit) {
		return mergeRelationship{}, fmt.Errorf("%w: reviewed source is not the unique merged parent", ErrForcePushAmbiguity)
	}
	bases, err := gitOutput(ctx, repoPath, "merge-base", "--all", firstParent, sourceCommit)
	if err != nil {
		return mergeRelationship{}, fmt.Errorf("%w: resolve reviewed merge base: %v", ErrForcePushAmbiguity, err)
	}
	baseFields := strings.Fields(bases)
	if len(baseFields) != 1 || !validCommitSHA.MatchString(baseFields[0]) {
		return mergeRelationship{}, fmt.Errorf("%w: reviewed source has multiple or missing merge bases", ErrForcePushAmbiguity)
	}
	return mergeRelationship{base: strings.ToLower(baseFields[0]), firstParent: strings.ToLower(firstParent)}, nil
}

func validateMergeRelationship(ctx context.Context, repoPath, sourceCommit, acceptedCommit string) (string, error) {
	relationship, err := resolveMergeRelationship(ctx, repoPath, sourceCommit, acceptedCommit)
	return relationship.base, err
}

func sourcePatchDigest(ctx context.Context, repoPath, base, sourceCommit string) (string, error) {
	out, err := deterministicGitDiff(ctx, "git", noninteractiveGitEnv(os.TempDir()), repoPath, base, sourceCommit)
	if err != nil {
		return "", fmt.Errorf("%w: compute reviewed patch: %v", ErrMissingGitObject, err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("hiveci.nip34.patch.v1\x00"))
	_, _ = hash.Write([]byte(strings.ToLower(base)))
	_, _ = hash.Write([]byte("\x00"))
	_, _ = hash.Write([]byte(strings.ToLower(sourceCommit)))
	_, _ = hash.Write([]byte("\x00"))
	_, _ = hash.Write(out)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func gitOutput(ctx context.Context, repoPath string, args ...string) (string, error) {
	gitArgs := append([]string{"--git-dir", repoPath}, args...)
	out, err := exec.CommandContext(ctx, "git", gitArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func validEventIDString(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func mergeTriggerKey(statusEventID string) string {
	return store.TriggerEnvelopeKey(store.TriggerSourceNIP34MergeStatus, statusEventID)
}

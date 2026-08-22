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
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const TriggerSourceLoomActions = "loom-actions"

const (
	defaultLoomActionMaxAge     = 15 * time.Minute
	defaultLoomActionFutureSkew = 5 * time.Minute
	minLoomActionMaxAge         = time.Minute
	maxLoomActionMaxAge         = 24 * time.Hour
	minLoomActionFutureSkew     = time.Second
	maxLoomActionFutureSkew     = time.Hour
)

var loomWorkflowMethod = cascadia.ContextVMMethods["ci/workflow-run"]

// LoomActionPolicy authorizes signed Hive-CI action events for one canonical
// repository. Direct dispatch is deliberately repository-specific and false
// by default; otherwise an accepted kind-1631 trigger envelope is required.
type LoomActionPolicy struct {
	RepoAddress         string   `json:"repo_address"`
	Actors              []string `json:"actors"`
	Branches            []string `json:"branches"`
	Workflows           []string `json:"workflows"`
	AllowDirectDispatch bool     `json:"allow_direct_dispatch,omitempty"`
	Version             string   `json:"version"`
}

type LoomActionConfig struct {
	Enabled         bool
	LocalPubkey     string
	RepositoriesDir string
	MaxEventAge     time.Duration
	FutureSkew      time.Duration
	Policies        []LoomActionPolicy
}

type loomActionStore interface {
	GetProvisionedMappingByRepoAddr(context.Context, string, string) (store.Mapping, error)
	GetAcceptedRepositoryState(context.Context, string) (store.AcceptedRepositoryState, error)
	GetTriggerEnvelope(context.Context, string) (store.TriggerEnvelope, error)
	GetTriggerEnvelopeByIdentity(context.Context, string, string) (store.TriggerEnvelope, error)
	ClaimTriggerEnvelope(context.Context, store.TriggerEnvelope) (store.TriggerEnvelope, bool, error)
	GetLoomJobByTriggerEnvelope(context.Context, string, string) (store.LoomJob, error)
}

type loomActionRunner interface {
	Enabled() bool
	RunTriggerEnvelope(context.Context, string, string) error
}

// LoomActionIngestor validates signed dispatch/retry actions before normalizing
// them into the same durable trigger envelope used by NIP-34 and GitHub.
type LoomActionIngestor struct {
	enabled         bool
	localPubkey     string
	repositoriesDir string
	maxEventAge     time.Duration
	futureSkew      time.Duration
	policies        map[string]LoomActionPolicy
	store           loomActionStore
	runner          loomActionRunner
	logger          *slog.Logger
	now             func() time.Time
}

func NewLoomActionIngestor(cfg LoomActionConfig, st loomActionStore, runner loomActionRunner, logger *slog.Logger) (*LoomActionIngestor, error) {
	if logger == nil {
		logger = slog.Default()
	}
	ingestor := &LoomActionIngestor{
		enabled: cfg.Enabled, localPubkey: strings.ToLower(strings.TrimSpace(cfg.LocalPubkey)),
		repositoriesDir: strings.TrimSpace(cfg.RepositoriesDir), policies: make(map[string]LoomActionPolicy),
		store: st, runner: runner, logger: logger.With("component", "hiveci.loom_actions"), now: time.Now,
	}
	if !cfg.Enabled {
		return ingestor, nil
	}
	if ingestor.repositoriesDir == "" || st == nil || runner == nil || !runner.Enabled() {
		return nil, fmt.Errorf("complete Loom action ingress configuration is required")
	}
	ingestor.maxEventAge = cfg.MaxEventAge
	if ingestor.maxEventAge == 0 {
		ingestor.maxEventAge = defaultLoomActionMaxAge
	}
	ingestor.futureSkew = cfg.FutureSkew
	if ingestor.futureSkew == 0 {
		ingestor.futureSkew = defaultLoomActionFutureSkew
	}
	if ingestor.maxEventAge < minLoomActionMaxAge || ingestor.maxEventAge > maxLoomActionMaxAge ||
		ingestor.futureSkew < minLoomActionFutureSkew || ingestor.futureSkew > maxLoomActionFutureSkew {
		return nil, fmt.Errorf("Loom action timing configuration is outside safe bounds")
	}
	if ingestor.localPubkey != "" {
		if _, err := nostr.PubKeyFromHex(ingestor.localPubkey); err != nil {
			return nil, fmt.Errorf("invalid local Loom workflow publisher: %w", err)
		}
	}
	if loomWorkflowMethod.Kind != cascadia.KindContextVMIntent || loomWorkflowMethod.Domain == "" ||
		loomWorkflowMethod.Op == "" || loomWorkflowMethod.Schema == "" {
		return nil, fmt.Errorf("canonical ci/workflow-run binding is unavailable")
	}
	for _, policy := range cfg.Policies {
		normalizeLoomActionPolicy(&policy)
		if err := validateLoomActionPolicy(policy); err != nil {
			return nil, err
		}
		if _, duplicate := ingestor.policies[policy.RepoAddress]; duplicate {
			return nil, fmt.Errorf("duplicate Loom action policy for %s", policy.RepoAddress)
		}
		ingestor.policies[policy.RepoAddress] = policy
	}
	if len(ingestor.policies) == 0 {
		return nil, fmt.Errorf("at least one Loom action policy is required")
	}
	return ingestor, nil
}

func (h *LoomActionIngestor) Enabled() bool { return h != nil && h.enabled }

// HandleEvent consumes every subscribed legacy workflow-run event so arbitrary
// commands cannot fall through to another handler. Only explicit dispatch/retry
// shapes cross the durable trigger boundary; ordinary attestations are ignored.
func (h *LoomActionIngestor) HandleEvent(ctx context.Context, ev *nostr.Event, sourceRelay string) (bool, error) {
	if !h.Enabled() || ev == nil || ev.Kind != relay.KindHiveWorkflowRun {
		return false, nil
	}
	if h.localPubkey != "" && strings.EqualFold(ev.PubKey.Hex(), h.localPubkey) {
		return true, nil
	}
	action, err := optionalSingleTag(ev.Tags, "action")
	if err != nil {
		return true, loomActionReject("invalid action tag: %v", err)
	}
	if action != "dispatch" && action != "retry" {
		return true, nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return true, loomActionReject("invalid Loom action signature")
	}
	// Freshness gates only a first-seen action. Once the exact signed identity is
	// durably claimed, later relay redelivery must remain able to resume a
	// transiently failed runner handoff without opening historical new actions.
	_, existingErr := h.store.GetTriggerEnvelopeByIdentity(ctx, TriggerSourceLoomActions, ev.ID.Hex())
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return true, existingErr
	}
	if errors.Is(existingErr, sql.ErrNoRows) {
		now := h.now().UTC()
		createdAt := time.Unix(int64(ev.CreatedAt), 0).UTC()
		if createdAt.Before(now.Add(-h.maxEventAge)) {
			return true, loomActionReject("Loom action is older than the configured maximum age")
		}
		if createdAt.After(now.Add(h.futureSkew)) {
			return true, loomActionReject("Loom action timestamp is implausibly far in the future")
		}
	}
	envelope, resumeEnvelopeID, err := h.validate(ctx, ev, action)
	if err != nil {
		return true, err
	}
	stored, _, err := h.store.ClaimTriggerEnvelope(ctx, envelope)
	if err != nil {
		return true, err
	}
	if resumeEnvelopeID == "" {
		resumeEnvelopeID = stored.IdempotencyKey
	}
	if action == "retry" {
		job, err := h.store.GetLoomJobByTriggerEnvelope(ctx, resumeEnvelopeID, stored.WorkflowPath)
		if err != nil {
			h.logger.Warn("Loom retry no longer has nonterminal workflow-run lineage", "event", ev.ID.Hex(), "error", err)
			if errors.Is(err, sql.ErrNoRows) {
				return true, loomActionReject("retry no longer has nonterminal workflow-run lineage")
			}
			return true, err
		}
		if job.WorkflowRunID != envelopeRetryRunID(stored) || store.LoomJobTerminal(job) {
			h.logger.Warn("Loom retry no longer has nonterminal workflow-run lineage", "event", ev.ID.Hex())
			return true, loomActionReject("retry no longer has nonterminal workflow-run lineage")
		}
	}
	// Complete the durable runner handoff before returning to the subscriber.
	// Relay redelivery can then resume the exact stored envelope after transient
	// failures. Retry deliberately resumes the same nonterminal logical run; it
	// never creates a second workflow run for a published trigger.
	if err := h.runner.RunTriggerEnvelope(ctx, resumeEnvelopeID, sourceRelay); err != nil {
		h.logger.Error("Loom action orchestration failed", "event", ev.ID.Hex(), "action", action, "error", err)
		return true, err
	}
	return true, nil
}

type normalizedLoomActionEvidence struct {
	SchemaVersion   string `json:"schema_version"`
	EventID         string `json:"event_id"`
	Action          string `json:"action"`
	Actor           string `json:"actor"`
	RepoAddress     string `json:"repo_address"`
	SourceCommit    string `json:"source_commit"`
	SourceTree      string `json:"source_tree"`
	AcceptedCommit  string `json:"accepted_commit"`
	Branch          string `json:"branch"`
	Workflow        string `json:"workflow"`
	PolicyVersion   string `json:"policy_version"`
	PolicySHA256    string `json:"policy_sha256"`
	EventSHA256     string `json:"event_sha256"`
	LineageEnvelope string `json:"lineage_envelope,omitempty"`
	WorkflowRunID   string `json:"workflow_run_id,omitempty"`
	DirectDispatch  bool   `json:"direct_dispatch,omitempty"`
}

type loomActionClaims struct {
	repoAddress, sourceCommit, sourceTree, acceptedCommit    string
	branch, workflow, policyVersion                          string
	lineageEnvelope, workflowRunID, prEventID, statusEventID string
	direct                                                   bool
}

func (h *LoomActionIngestor) validate(ctx context.Context, ev *nostr.Event, action string) (store.TriggerEnvelope, string, error) {
	claims, err := parseLoomActionClaims(ev.Tags, action)
	if err != nil {
		return store.TriggerEnvelope{}, "", err
	}
	if strings.TrimSpace(ev.Content) != "" {
		return store.TriggerEnvelope{}, "", loomActionReject("Loom actions must not contain raw commands")
	}
	policy, ok := h.policies[claims.repoAddress]
	if !ok {
		return store.TriggerEnvelope{}, "", loomActionReject("repository is not authorized")
	}
	actor := strings.ToLower(ev.PubKey.Hex())
	if !slices.Contains(policy.Actors, actor) {
		return store.TriggerEnvelope{}, "", loomActionReject("actor is not authorized")
	}
	if claims.policyVersion != policy.Version || !slices.Contains(policy.Branches, claims.branch) ||
		!slices.Contains(policy.Workflows, claims.workflow) {
		return store.TriggerEnvelope{}, "", loomActionReject("repository workflow or policy evidence does not match")
	}
	ownerPub, repoID, ok := parseRepoAddr(claims.repoAddress)
	if !ok {
		return store.TriggerEnvelope{}, "", loomActionReject("canonical repository coordinate is invalid")
	}
	mapping, err := h.store.GetProvisionedMappingByRepoAddr(ctx, ownerPub, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.TriggerEnvelope{}, "", loomActionReject("canonical repository is not provisioned")
	}
	if err != nil {
		return store.TriggerEnvelope{}, "", fmt.Errorf("resolve canonical repository: %w", err)
	}
	repoPath := filepath.Join(h.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	if err := validateLoomMirrorEvidence(ctx, repoPath, claims); err != nil {
		return store.TriggerEnvelope{}, "", err
	}

	patchDigest := ""
	resumeEnvelopeID := ""
	var prEventID, statusEventID string
	if action == "retry" {
		original, err := h.store.GetTriggerEnvelope(ctx, claims.lineageEnvelope)
		if errors.Is(err, sql.ErrNoRows) {
			return store.TriggerEnvelope{}, "", loomActionReject("retry trigger lineage is not accepted")
		}
		if err != nil {
			return store.TriggerEnvelope{}, "", err
		}
		if original.Source != TriggerSourceLoomActions || original.Action != "workflow_dispatch" ||
			!loomActionMatchesEnvelope(claims, original) || original.PolicyVersion != policy.Version {
			return store.TriggerEnvelope{}, "", loomActionReject("retry evidence conflicts with the original trigger")
		}
		if (claims.prEventID != "" || claims.statusEventID != "") &&
			(claims.prEventID != original.PREventID || claims.statusEventID != original.StatusEventID) {
			return store.TriggerEnvelope{}, "", loomActionReject("retry PR/status lineage conflicts with the original trigger")
		}
		job, err := h.store.GetLoomJobByTriggerEnvelope(ctx, original.IdempotencyKey, claims.workflow)
		if errors.Is(err, sql.ErrNoRows) {
			return store.TriggerEnvelope{}, "", loomActionReject("retry has no accepted workflow-run lineage")
		}
		if err != nil {
			return store.TriggerEnvelope{}, "", err
		}
		if claims.workflowRunID != job.WorkflowRunID {
			return store.TriggerEnvelope{}, "", loomActionReject("retry workflow-run evidence does not match")
		}
		if store.LoomJobTerminal(job) {
			return store.TriggerEnvelope{}, "", loomActionReject("terminal workflow results cannot be retried")
		}
		patchDigest, prEventID, statusEventID = original.PatchDigest, original.PREventID, original.StatusEventID
		resumeEnvelopeID = original.IdempotencyKey
	} else if claims.direct {
		if !policy.AllowDirectDispatch {
			return store.TriggerEnvelope{}, "", loomActionReject("direct dispatch is not permitted by repository policy")
		}
		if claims.lineageEnvelope != "" || claims.prEventID != "" || claims.statusEventID != "" ||
			claims.sourceCommit != claims.acceptedCommit {
			return store.TriggerEnvelope{}, "", loomActionReject("direct dispatch must use one accepted commit without lineage tags")
		}
		if err := h.validateDirectAcceptedState(ctx, mapping, claims); err != nil {
			return store.TriggerEnvelope{}, "", err
		}
		patchDigest = loomDirectDigest(claims)
	} else {
		lineage, err := h.store.GetTriggerEnvelope(ctx, claims.lineageEnvelope)
		if errors.Is(err, sql.ErrNoRows) {
			return store.TriggerEnvelope{}, "", loomActionReject("accepted PR/status lineage is required")
		}
		if err != nil {
			return store.TriggerEnvelope{}, "", err
		}
		if lineage.Source != store.TriggerSourceNIP34MergeStatus || lineage.PREventID == "" || lineage.StatusEventID == "" ||
			claims.prEventID != lineage.PREventID || claims.statusEventID != lineage.StatusEventID ||
			!loomActionMatchesEnvelope(claims, lineage) ||
			(lineage.WorkflowPath != "" && lineage.WorkflowPath != claims.workflow) {
			return store.TriggerEnvelope{}, "", loomActionReject("PR/status lineage evidence does not match")
		}
		patchDigest, prEventID, statusEventID = lineage.PatchDigest, lineage.PREventID, lineage.StatusEventID
	}

	eventJSON, err := json.Marshal(ev)
	if err != nil {
		return store.TriggerEnvelope{}, "", err
	}
	eventHash, policyHash := sha256.Sum256(eventJSON), sha256.Sum256(mustJSON(policy))
	evidence := normalizedLoomActionEvidence{
		SchemaVersion: loomWorkflowMethod.Schema, EventID: ev.ID.Hex(), Action: action, Actor: actor,
		RepoAddress: claims.repoAddress, SourceCommit: claims.sourceCommit, SourceTree: claims.sourceTree,
		AcceptedCommit: claims.acceptedCommit, Branch: claims.branch, Workflow: claims.workflow,
		PolicyVersion: policy.Version, PolicySHA256: hex.EncodeToString(policyHash[:]),
		EventSHA256: hex.EncodeToString(eventHash[:]), LineageEnvelope: claims.lineageEnvelope,
		WorkflowRunID: claims.workflowRunID, DirectDispatch: claims.direct,
	}
	encodedEvidence, _ := json.Marshal(evidence)
	return store.TriggerEnvelope{
		IdempotencyKey: store.TriggerEnvelopeKey(TriggerSourceLoomActions, ev.ID.Hex()),
		Source:         TriggerSourceLoomActions, TriggerID: ev.ID.Hex(), Actor: actor, Action: actionEnvelopeTrigger(action),
		WorkflowPath: claims.workflow, EvidenceJSON: string(encodedEvidence), PREventID: prEventID,
		StatusEventID: statusEventID, SourceCommit: claims.sourceCommit, SourceTree: claims.sourceTree,
		PatchDigest: patchDigest, AcceptedCommit: claims.acceptedCommit, RepoAddress: claims.repoAddress,
		PolicyVersion: policy.Version, Branch: claims.branch, CreatedAt: time.Now().UTC(),
	}, resumeEnvelopeID, nil
}

func parseLoomActionClaims(tags nostr.Tags, action string) (loomActionClaims, error) {
	required := map[string]*string{}
	claims := loomActionClaims{}
	required["domain"], required["op"], required["schema"] = new(string), new(string), new(string)
	required["a"], required["commit"], required["source-commit"] = &claims.repoAddress, &claims.acceptedCommit, &claims.sourceCommit
	required["source-tree"], required["branch"], required["workflow"] = &claims.sourceTree, &claims.branch, &claims.workflow
	required["policy"] = &claims.policyVersion
	for key, target := range required {
		value, err := strictExactlyOneTagValue(tags, key)
		if err != nil {
			return loomActionClaims{}, loomActionReject("invalid %s evidence: %v", key, err)
		}
		*target = value
	}
	if *required["domain"] != loomWorkflowMethod.Domain || *required["op"] != loomWorkflowMethod.Op ||
		*required["schema"] != loomWorkflowMethod.Schema {
		return loomActionClaims{}, loomActionReject("canonical ci/workflow-run schema is required")
	}
	claims.sourceCommit = strings.ToLower(claims.sourceCommit)
	claims.sourceTree = strings.ToLower(claims.sourceTree)
	claims.acceptedCommit = strings.ToLower(claims.acceptedCommit)
	if !validCommitSHA.MatchString(claims.sourceCommit) || !validCommitSHA.MatchString(claims.sourceTree) ||
		!validCommitSHA.MatchString(claims.acceptedCommit) {
		return loomActionClaims{}, loomActionReject("exact commit and tree evidence is required")
	}
	var err error
	if claims.lineageEnvelope, err = optionalSingleTag(tags, "trigger-envelope"); err != nil {
		return loomActionClaims{}, loomActionReject("invalid trigger lineage: %v", err)
	}
	if claims.workflowRunID, err = optionalSingleTag(tags, "e"); err != nil {
		return loomActionClaims{}, loomActionReject("invalid workflow-run lineage: %v", err)
	}
	if claims.prEventID, err = optionalSingleTag(tags, "pr-event"); err != nil {
		return loomActionClaims{}, loomActionReject("invalid PR lineage: %v", err)
	}
	if claims.statusEventID, err = optionalSingleTag(tags, "status-event"); err != nil {
		return loomActionClaims{}, loomActionReject("invalid status lineage: %v", err)
	}
	direct, err := optionalSingleTag(tags, "direct")
	if err != nil || (direct != "" && direct != "true") {
		return loomActionClaims{}, loomActionReject("direct evidence must be exactly true when present")
	}
	claims.direct = direct == "true"
	if action == "retry" {
		if !validEventIDString(claims.lineageEnvelope) || !validEventIDString(claims.workflowRunID) || claims.direct {
			return loomActionClaims{}, loomActionReject("retry requires exact trigger-envelope and workflow-run lineage")
		}
	} else if !claims.direct && !validEventIDString(claims.lineageEnvelope) {
		return loomActionClaims{}, loomActionReject("dispatch requires accepted trigger lineage or explicit direct policy")
	}
	return claims, nil
}

func validateLoomMirrorEvidence(ctx context.Context, repoPath string, claims loomActionClaims) error {
	if err := requireCommitObject(ctx, repoPath, claims.sourceCommit); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return loomActionReject("source commit is not mirrored")
	}
	if err := requireCommitObject(ctx, repoPath, claims.acceptedCommit); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return loomActionReject("accepted commit is not mirrored")
	}
	tree, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", claims.sourceCommit+"^{tree}")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !strings.EqualFold(tree, claims.sourceTree) {
		return loomActionReject("source tree evidence does not match the mirror")
	}
	workflows, err := detectWorkflows(ctx, repoPath, claims.acceptedCommit)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return loomActionReject("workflow commit is not mirrored")
	}
	if _, err := selectTriggerWorkflows(workflows, claims.workflow, claims.acceptedCommit); err != nil {
		return loomActionReject("authorized workflow is not present at the accepted commit")
	}
	return nil
}

func (h *LoomActionIngestor) validateDirectAcceptedState(ctx context.Context, mapping store.Mapping, claims loomActionClaims) error {
	state, err := h.store.GetAcceptedRepositoryState(ctx, claims.repoAddress)
	if errors.Is(err, sql.ErrNoRows) {
		return loomActionReject("direct dispatch has no accepted repository state")
	}
	if err != nil {
		return err
	}
	var ev nostr.Event
	if err := json.Unmarshal([]byte(state.EventJSON), &ev); err != nil {
		return loomActionReject("accepted repository state is invalid")
	}
	repoID, tagErr := strictExactlyOneTagValue(ev.Tags, "d")
	branch, commit, headErr := strictStateHEAD(ev.Tags)
	if nostrverify.ValidateEventIDAndSignature(&ev) != nil || ev.ID.Hex() != state.EventID ||
		ev.Kind != relay.KindRepositoryState || tagErr != nil || repoID != mapping.RepoID || headErr != nil ||
		branch != claims.branch || !strings.EqualFold(commit, claims.acceptedCommit) {
		return loomActionReject("direct dispatch does not match accepted repository state")
	}
	repoPath := filepath.Join(h.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	local, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", "refs/heads/"+claims.branch+"^{commit}")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !strings.EqualFold(local, claims.acceptedCommit) {
		return loomActionReject("direct dispatch branch is not proven by the canonical mirror")
	}
	return nil
}

func loomActionMatchesEnvelope(claims loomActionClaims, envelope store.TriggerEnvelope) bool {
	return claims.repoAddress == envelope.RepoAddress &&
		strings.EqualFold(claims.sourceCommit, envelope.SourceCommit) &&
		strings.EqualFold(claims.sourceTree, envelope.SourceTree) &&
		strings.EqualFold(claims.acceptedCommit, envelope.AcceptedCommit) &&
		claims.branch == envelope.Branch && (envelope.WorkflowPath == "" || claims.workflow == envelope.WorkflowPath)
}

func actionEnvelopeTrigger(action string) string {
	if action == "dispatch" {
		return "workflow_dispatch"
	}
	return "retry"
}

func envelopeRetryRunID(envelope store.TriggerEnvelope) string {
	var evidence normalizedLoomActionEvidence
	if json.Unmarshal([]byte(envelope.EvidenceJSON), &evidence) != nil {
		return ""
	}
	return evidence.WorkflowRunID
}

func loomDirectDigest(claims loomActionClaims) string {
	sum := sha256.Sum256([]byte(loomWorkflowMethod.Schema + "\x00direct\x00" + claims.repoAddress + "\x00" +
		claims.sourceCommit + "\x00" + claims.sourceTree + "\x00" + claims.workflow + "\x00" + claims.policyVersion))
	return hex.EncodeToString(sum[:])
}

func optionalSingleTag(tags nostr.Tags, key string) (string, error) {
	value := ""
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != 2 || value != "" || strings.TrimSpace(tag[1]) == "" {
			return "", fmt.Errorf("at most one valid %s tag is allowed", key)
		}
		value = strings.TrimSpace(tag[1])
	}
	return value, nil
}

type loomActionValidationError struct{ message string }

func (e *loomActionValidationError) Error() string      { return e.message }
func (e *loomActionValidationError) NonRetryable() bool { return true }
func loomActionReject(format string, args ...any) error {
	return &loomActionValidationError{message: fmt.Sprintf(format, args...)}
}

func normalizeLoomActionPolicy(policy *LoomActionPolicy) {
	policy.RepoAddress = strings.TrimSpace(policy.RepoAddress)
	policy.Version = strings.TrimSpace(policy.Version)
	for i := range policy.Actors {
		policy.Actors[i] = strings.ToLower(strings.TrimSpace(policy.Actors[i]))
	}
	for i := range policy.Branches {
		policy.Branches[i] = strings.TrimSpace(policy.Branches[i])
	}
	for i := range policy.Workflows {
		policy.Workflows[i] = filepath.ToSlash(strings.TrimSpace(policy.Workflows[i]))
	}
}

func validateLoomActionPolicy(policy LoomActionPolicy) error {
	if policy.RepoAddress == "" || len(policy.Actors) == 0 || len(policy.Branches) == 0 ||
		len(policy.Workflows) == 0 || policy.Version == "" {
		return fmt.Errorf("complete Loom action policy is required for %q", policy.RepoAddress)
	}
	if _, _, ok := parseRepoAddr(policy.RepoAddress); !ok {
		return fmt.Errorf("invalid canonical repo_address for Loom action policy %s", policy.RepoAddress)
	}
	for _, actor := range policy.Actors {
		if _, err := nostr.PubKeyFromHex(actor); err != nil {
			return fmt.Errorf("invalid Loom action actor for %s: %w", policy.RepoAddress, err)
		}
	}
	for _, branch := range policy.Branches {
		if branch == "" || strings.Contains(branch, "..") || strings.ContainsAny(branch, " ~^:?*[\\") {
			return fmt.Errorf("invalid Loom action branch %q", branch)
		}
	}
	for _, workflow := range policy.Workflows {
		if workflow == "" || workflow != filepath.ToSlash(filepath.Clean(workflow)) || strings.HasPrefix(workflow, "/") {
			return fmt.Errorf("invalid Loom action workflow %q", workflow)
		}
	}
	return nil
}

var _ loomActionStore = (*store.SQLiteStore)(nil)

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	GitHubActionsRoute         = "/webhook/github/actions"
	TriggerSourceGitHubActions = "github-actions"
	githubActionPolicySchema   = "hiveci.github_action.v1"
	maxGitHubActionBodyBytes   = 1 << 20
)

// GitHubActionPolicy binds a GitHub mirror name to one canonical repository.
// Static actors, protected branches, workflows, and dispatch action names are
// the deliberately fail-closed v1 substitute for mutable GitHub API lookups.
type GitHubActionPolicy struct {
	Repository                string   `json:"repository"`
	RepositoryID              int64    `json:"repository_id"`
	RepoAddress               string   `json:"repo_address"`
	Actors                    []string `json:"actors"`
	ActorIDs                  []int64  `json:"actor_ids"`
	Events                    []string `json:"events"`
	ProtectedBranches         []string `json:"protected_branches"`
	Workflows                 []string `json:"workflows"`
	RepositoryDispatchActions []string `json:"repository_dispatch_actions,omitempty"`
	Version                   string   `json:"version"`
}

type GitHubActionConfig struct {
	Secret          string
	RepositoriesDir string
	Policies        []GitHubActionPolicy
}

type githubActionStore interface {
	GetProvisionedMappingByRepoAddr(context.Context, string, string) (store.Mapping, error)
	ClaimTriggerEnvelope(context.Context, store.TriggerEnvelope) (store.TriggerEnvelope, bool, error)
}

type githubActionRunner interface {
	Enabled() bool
	RunTriggerEnvelope(context.Context, string, string) error
}

// GitHubActionHandler verifies and normalizes GitHub action webhooks. Every
// policy or immutable-evidence failure is returned as a terminal 4xx response;
// execution begins only after the shared envelope is durably claimed.
type GitHubActionHandler struct {
	secret          []byte
	repositoriesDir string
	policies        map[string]GitHubActionPolicy
	store           githubActionStore
	runner          githubActionRunner
	logger          *slog.Logger
}

func NewGitHubActionHandler(cfg GitHubActionConfig, st githubActionStore, runner githubActionRunner, logger *slog.Logger) (*GitHubActionHandler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	h := &GitHubActionHandler{
		secret: []byte(strings.TrimSpace(cfg.Secret)), repositoriesDir: strings.TrimSpace(cfg.RepositoriesDir),
		policies: make(map[string]GitHubActionPolicy), store: st, runner: runner,
		logger: logger.With("component", "hiveci.github_actions"),
	}
	if len(h.secret) == 0 || h.repositoriesDir == "" || st == nil || runner == nil || !runner.Enabled() {
		return nil, fmt.Errorf("complete GitHub action ingress configuration is required")
	}
	for _, policy := range cfg.Policies {
		normalizeGitHubActionPolicy(&policy)
		if err := validateGitHubActionPolicy(policy); err != nil {
			return nil, err
		}
		key := strings.ToLower(policy.Repository)
		if _, duplicate := h.policies[key]; duplicate {
			return nil, fmt.Errorf("duplicate GitHub action policy for %s", policy.Repository)
		}
		h.policies[key] = policy
	}
	if len(h.policies) == 0 {
		return nil, fmt.Errorf("at least one GitHub action policy is required")
	}
	return h, nil
}

func (h *GitHubActionHandler) RegisterRoutes(mux *http.ServeMux) {
	if h != nil && mux != nil {
		mux.Handle(GitHubActionsRoute, h)
	}
}

func (h *GitHubActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		githubActionError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGitHubActionBodyBytes+1))
	if err != nil || len(body) > maxGitHubActionBodyBytes {
		githubActionError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !verifyGitHubHMAC(h.secret, r.Header.Get("X-Hub-Signature-256"), body) {
		githubActionError(w, http.StatusUnauthorized, "signature mismatch")
		return
	}
	eventType := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	deliveryID := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if eventType == "" || deliveryID == "" {
		githubActionError(w, http.StatusBadRequest, "GitHub event and delivery headers are required")
		return
	}

	envelope, err := h.validate(r.Context(), eventType, deliveryID, body)
	if err != nil {
		h.logger.Warn("GitHub action rejected", "event", eventType, "delivery", deliveryID, "error", err)
		status, message := githubActionStatus(err), err.Error()
		if status >= 500 {
			message = "GitHub action validation unavailable"
		}
		githubActionError(w, status, message)
		return
	}
	stored, claimed, err := h.store.ClaimTriggerEnvelope(r.Context(), envelope)
	if err != nil {
		h.logger.Warn("GitHub action claim failed", "event", eventType, "delivery", deliveryID, "error", err)
		status, message := githubActionStatus(err), err.Error()
		if status >= 500 {
			message = "GitHub action persistence unavailable"
		}
		githubActionError(w, status, message)
		return
	}
	// Complete the initial durable per-workflow handoff before acknowledging.
	// A transient failure returns 5xx so GitHub redelivery resumes the exact
	// stored envelope instead of leaving an acknowledged claim stranded.
	if err := h.runner.RunTriggerEnvelope(r.Context(), stored.IdempotencyKey, "github:"+eventType); err != nil {
		h.logger.Error("GitHub action orchestration failed", "event", eventType, "delivery", deliveryID, "error", err)
		status, message := githubActionStatus(err), err.Error()
		if status >= 500 {
			message = "GitHub action orchestration unavailable"
		}
		githubActionError(w, status, message)
		return
	}
	status := http.StatusOK
	if claimed {
		status = http.StatusAccepted
	}
	githubActionJSON(w, status, map[string]any{"accepted": true, "replay": !claimed, "trigger_envelope_id": stored.IdempotencyKey})
}

type githubWebhook struct {
	Action     string `json:"action"`
	Ref        string `json:"ref"`
	Workflow   string `json:"workflow"`
	Repository struct {
		FullName string `json:"full_name"`
		ID       int64  `json:"id"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"sender"`
	Inputs        githubActionClaims `json:"inputs"`
	ClientPayload githubActionClaims `json:"client_payload"`
	PullRequest   struct {
		Merged         bool   `json:"merged"`
		MergeCommitSHA string `json:"merge_commit_sha"`
		Head           struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref  string `json:"ref"`
			Repo struct {
				FullName string `json:"full_name"`
				ID       int64  `json:"id"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

type githubActionClaims struct {
	RepoAddress    string `json:"repo_address"`
	SourceCommit   string `json:"source_commit"`
	AcceptedCommit string `json:"accepted_commit"`
	SourceTree     string `json:"source_tree"`
	Workflow       string `json:"workflow"`
	PolicyVersion  string `json:"policy_version"`
	MirrorRef      string `json:"mirror_ref"`
}

type normalizedGitHubEvidence struct {
	SchemaVersion  string `json:"schema_version"`
	Event          string `json:"event"`
	DeliveryID     string `json:"delivery_id"`
	Repository     string `json:"repository"`
	RepositoryID   int64  `json:"repository_id"`
	RepoAddress    string `json:"repo_address"`
	Actor          string `json:"actor"`
	ActorID        int64  `json:"actor_id"`
	Action         string `json:"action"`
	DispatchAction string `json:"dispatch_action,omitempty"`
	Branch         string `json:"branch"`
	MirrorRef      string `json:"mirror_ref"`
	SourceCommit   string `json:"source_commit"`
	SourceTree     string `json:"source_tree"`
	AcceptedCommit string `json:"accepted_commit"`
	Workflow       string `json:"workflow"`
	PolicyVersion  string `json:"policy_version"`
	PolicySHA256   string `json:"policy_sha256"`
	PayloadSHA256  string `json:"payload_sha256"`
}

type githubValidationError struct {
	status int
	msg    string
}

func (e *githubValidationError) Error() string { return e.msg }

func githubReject(status int, format string, args ...any) error {
	return &githubValidationError{status: status, msg: fmt.Sprintf(format, args...)}
}

func (h *GitHubActionHandler) validate(ctx context.Context, eventType, deliveryID string, body []byte) (store.TriggerEnvelope, error) {
	var payload githubWebhook
	if err := json.Unmarshal(body, &payload); err != nil {
		return store.TriggerEnvelope{}, githubReject(http.StatusBadRequest, "invalid GitHub payload")
	}
	repository := strings.ToLower(strings.TrimSpace(payload.Repository.FullName))
	actor := strings.ToLower(strings.TrimSpace(payload.Sender.Login))
	policy, ok := h.policies[repository]
	if !ok {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "repository is not authorized")
	}
	if payload.Repository.ID <= 0 || payload.Repository.ID != policy.RepositoryID {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "repository identity is not authorized")
	}
	if actor == "" || !authorizedGitHubActor(policy, actor, payload.Sender.ID) {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "actor is not authorized")
	}
	if !slices.Contains(policy.Events, eventType) {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "GitHub event is not enabled by policy")
	}

	claims := payload.Inputs
	branch, mirrorRef, action, dispatchAction := "", "", eventType, ""
	switch eventType {
	case "workflow_dispatch":
		branch, mirrorRef = githubBranchAndRef(payload.Ref, claims.MirrorRef)
		payload.Workflow = strings.TrimSpace(payload.Workflow)
		if payload.Workflow == "" || (claims.Workflow != "" && strings.TrimSpace(claims.Workflow) != payload.Workflow) {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "workflow evidence does not match the dispatched workflow")
		}
		claims.Workflow = payload.Workflow
	case "repository_dispatch":
		claims = payload.ClientPayload
		branch, mirrorRef = githubBranchAndRef(claims.MirrorRef, claims.MirrorRef)
		if payload.Action == "" || !slices.Contains(policy.RepositoryDispatchActions, payload.Action) {
			return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "repository dispatch action is not authorized")
		}
		action = "repository_dispatch"
		dispatchAction = payload.Action
	case "pull_request":
		if payload.Action != "closed" || !payload.PullRequest.Merged {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "pull request is not a merged event")
		}
		if !strings.EqualFold(payload.PullRequest.Base.Repo.FullName, payload.Repository.FullName) ||
			payload.PullRequest.Base.Repo.ID != payload.Repository.ID {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "pull request base repository does not match")
		}
		if len(policy.Workflows) != 1 {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "protected merge policy must select exactly one workflow")
		}
		branch = strings.TrimSpace(payload.PullRequest.Base.Ref)
		mirrorRef = "refs/heads/" + branch
		claims = githubActionClaims{
			RepoAddress: policy.RepoAddress, SourceCommit: payload.PullRequest.Head.SHA,
			AcceptedCommit: payload.PullRequest.MergeCommitSHA, Workflow: policy.Workflows[0],
			PolicyVersion: policy.Version, MirrorRef: mirrorRef,
		}
		action = "pull_request"
	default:
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "GitHub event is not an authorized action trigger")
	}

	claims.RepoAddress = strings.TrimSpace(claims.RepoAddress)
	claims.SourceCommit = strings.ToLower(strings.TrimSpace(claims.SourceCommit))
	claims.AcceptedCommit = strings.ToLower(strings.TrimSpace(claims.AcceptedCommit))
	claims.SourceTree = strings.ToLower(strings.TrimSpace(claims.SourceTree))
	claims.Workflow = strings.TrimSpace(claims.Workflow)
	claims.PolicyVersion = strings.TrimSpace(claims.PolicyVersion)
	if branch == "" || mirrorRef == "" || !slices.Contains(policy.ProtectedBranches, branch) {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "branch is not protected by trigger policy")
	}
	if claims.RepoAddress != policy.RepoAddress || claims.PolicyVersion != policy.Version {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "canonical repository or policy evidence does not match")
	}
	if !validCommitSHA.MatchString(claims.SourceCommit) || !validCommitSHA.MatchString(claims.AcceptedCommit) {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "exact source and accepted commits are required")
	}
	if eventType != "pull_request" && claims.SourceCommit != claims.AcceptedCommit {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "manual action source and accepted commits must match")
	}
	if claims.Workflow == "" || !slices.Contains(policy.Workflows, claims.Workflow) {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "workflow is not authorized")
	}

	ownerPub, repoID, ok := parseRepoAddr(policy.RepoAddress)
	if !ok {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "canonical repository policy is invalid")
	}
	mapping, err := h.store.GetProvisionedMappingByRepoAddr(ctx, ownerPub, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.TriggerEnvelope{}, githubReject(http.StatusForbidden, "canonical repository mirror is not provisioned")
	}
	if err != nil {
		return store.TriggerEnvelope{}, fmt.Errorf("resolve canonical repository mirror: %w", err)
	}
	repoPath := filepath.Join(h.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	if err := requireCommitObject(ctx, repoPath, claims.SourceCommit); err != nil {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "source commit is not mirrored")
	}
	if err := requireCommitObject(ctx, repoPath, claims.AcceptedCommit); err != nil {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "accepted commit is not mirrored")
	}
	localRef, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", mirrorRef+"^{commit}")
	refProvesCommit := err == nil && strings.EqualFold(localRef, claims.AcceptedCommit)
	if eventType == "pull_request" && err == nil && !refProvesCommit {
		refProvesCommit = exec.CommandContext(ctx, "git", "--git-dir", repoPath, "merge-base", "--is-ancestor", claims.AcceptedCommit, localRef).Run() == nil
	}
	if !refProvesCommit {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "mirror ref does not prove the accepted commit")
	}
	sourceTree, err := gitOutput(ctx, repoPath, "rev-parse", "--verify", claims.SourceCommit+"^{tree}")
	if err != nil || !validCommitSHA.MatchString(sourceTree) {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "source tree is not mirrored")
	}
	if eventType != "pull_request" && (claims.SourceTree == "" || !strings.EqualFold(sourceTree, claims.SourceTree)) {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "source tree evidence does not match the mirror")
	}
	workflows, err := detectWorkflows(ctx, repoPath, claims.AcceptedCommit)
	if err != nil {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "workflow commit is not mirrored")
	}
	if _, err := selectTriggerWorkflows(workflows, claims.Workflow, claims.AcceptedCommit); err != nil {
		return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "authorized workflow is not present at the accepted commit")
	}

	patchDigest := githubActionDigest(claims.SourceCommit, sourceTree, claims.AcceptedCommit)
	if eventType == "pull_request" {
		base, relationshipErr := validateMergeRelationship(ctx, repoPath, claims.SourceCommit, claims.AcceptedCommit)
		if relationshipErr != nil {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "protected merge does not contain the exact source commit")
		}
		patchDigest, err = sourcePatchDigest(ctx, repoPath, base, claims.SourceCommit)
		if err != nil {
			return store.TriggerEnvelope{}, githubReject(http.StatusUnprocessableEntity, "protected merge patch is unavailable")
		}
	}
	payloadHash := sha256.Sum256(body)
	policyHash := sha256.Sum256(mustJSON(policy))
	evidence := normalizedGitHubEvidence{
		SchemaVersion: githubActionPolicySchema, Event: eventType, DeliveryID: deliveryID,
		Repository: repository, RepositoryID: payload.Repository.ID, RepoAddress: policy.RepoAddress,
		Actor: actor, ActorID: payload.Sender.ID, Action: action,
		DispatchAction: dispatchAction,
		Branch:         branch, MirrorRef: mirrorRef, SourceCommit: claims.SourceCommit, SourceTree: sourceTree,
		AcceptedCommit: claims.AcceptedCommit, Workflow: claims.Workflow, PolicyVersion: policy.Version,
		PolicySHA256:  hex.EncodeToString(policyHash[:]),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
	}
	encodedEvidence, _ := json.Marshal(evidence)
	return store.TriggerEnvelope{
		IdempotencyKey: store.TriggerEnvelopeKey(TriggerSourceGitHubActions, deliveryID),
		Source:         TriggerSourceGitHubActions, TriggerID: deliveryID, Actor: actor, Action: action,
		WorkflowPath: claims.Workflow, EvidenceJSON: string(encodedEvidence), SourceCommit: claims.SourceCommit,
		SourceTree: sourceTree, PatchDigest: patchDigest, AcceptedCommit: claims.AcceptedCommit,
		RepoAddress: policy.RepoAddress, PolicyVersion: policy.Version, Branch: branch, CreatedAt: time.Now().UTC(),
	}, nil
}

func normalizeGitHubActionPolicy(policy *GitHubActionPolicy) {
	policy.Repository = strings.ToLower(strings.TrimSpace(policy.Repository))
	policy.RepoAddress = strings.TrimSpace(policy.RepoAddress)
	policy.Version = strings.TrimSpace(policy.Version)
	for i := range policy.Actors {
		policy.Actors[i] = strings.ToLower(strings.TrimSpace(policy.Actors[i]))
	}
	for i := range policy.ProtectedBranches {
		policy.ProtectedBranches[i] = strings.TrimSpace(policy.ProtectedBranches[i])
	}
	for i := range policy.Workflows {
		policy.Workflows[i] = strings.TrimSpace(policy.Workflows[i])
	}
	for i := range policy.RepositoryDispatchActions {
		policy.RepositoryDispatchActions[i] = strings.TrimSpace(policy.RepositoryDispatchActions[i])
	}
	for i := range policy.Events {
		policy.Events[i] = strings.ToLower(strings.TrimSpace(policy.Events[i]))
	}
}

func validateGitHubActionPolicy(policy GitHubActionPolicy) error {
	if policy.Repository == "" || !strings.Contains(policy.Repository, "/") || policy.RepositoryID <= 0 || policy.RepoAddress == "" ||
		len(policy.Actors) == 0 || len(policy.Actors) != len(policy.ActorIDs) || len(policy.Events) == 0 ||
		len(policy.ProtectedBranches) == 0 || len(policy.Workflows) == 0 || policy.Version == "" {
		return fmt.Errorf("complete GitHub action policy is required for %q", policy.Repository)
	}
	if _, _, ok := parseRepoAddr(policy.RepoAddress); !ok {
		return fmt.Errorf("invalid canonical repo_address for GitHub repository %s", policy.Repository)
	}
	for _, workflow := range policy.Workflows {
		if workflow == "" || workflow != filepath.ToSlash(filepath.Clean(workflow)) || strings.HasPrefix(workflow, "/") {
			return fmt.Errorf("invalid workflow path %q for GitHub repository %s", workflow, policy.Repository)
		}
	}
	for i, id := range policy.ActorIDs {
		if id <= 0 || policy.Actors[i] == "" {
			return fmt.Errorf("invalid GitHub actor identity for repository %s", policy.Repository)
		}
	}
	for _, event := range policy.Events {
		if event != "workflow_dispatch" && event != "repository_dispatch" && event != "pull_request" {
			return fmt.Errorf("invalid GitHub action event %q for repository %s", event, policy.Repository)
		}
	}
	return nil
}

func authorizedGitHubActor(policy GitHubActionPolicy, login string, id int64) bool {
	for i, allowed := range policy.Actors {
		if strings.EqualFold(allowed, login) && i < len(policy.ActorIDs) && policy.ActorIDs[i] == id {
			return true
		}
	}
	return false
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func githubBranchAndRef(rawRef, proofRef string) (string, string) {
	rawRef, proofRef = strings.TrimSpace(rawRef), strings.TrimSpace(proofRef)
	branch := strings.TrimPrefix(rawRef, "refs/heads/")
	want := "refs/heads/" + branch
	if branch == "" || strings.Contains(branch, "..") || strings.ContainsAny(branch, " ~^:?*[\\") || proofRef != want {
		return "", ""
	}
	return branch, want
}

func githubActionDigest(sourceCommit, sourceTree, acceptedCommit string) string {
	sum := sha256.Sum256([]byte(githubActionPolicySchema + "\x00" + sourceCommit + "\x00" + sourceTree + "\x00" + acceptedCommit))
	return hex.EncodeToString(sum[:])
}

func verifyGitHubHMAC(secret []byte, header string, body []byte) bool {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func githubActionStatus(err error) int {
	var validation *githubValidationError
	if errors.As(err, &validation) {
		return validation.status
	}
	if errors.Is(err, store.ErrTriggerConflict) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrTriggerWorkflow) {
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

func githubActionError(w http.ResponseWriter, status int, message string) {
	githubActionJSON(w, status, map[string]string{"error": message})
}

func githubActionJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

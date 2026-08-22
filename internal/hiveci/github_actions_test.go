// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type githubRunnerCapture struct {
	mu       sync.Mutex
	ids      []string
	error    error
	calls    chan struct{}
	disabled bool
}

func (r *githubRunnerCapture) Enabled() bool { return r != nil && !r.disabled }

func (r *githubRunnerCapture) RunTriggerEnvelope(_ context.Context, id, _ string) error {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
	if r.calls != nil {
		r.calls <- struct{}{}
	}
	return r.error
}

func (r *githubRunnerCapture) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

func (r *githubRunnerCapture) wait(t *testing.T, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case <-r.calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for runner call %d", i+1)
		}
	}
}

type githubActionFixture struct {
	merge      *mergeFixture
	handler    *GitHubActionHandler
	runner     *githubRunnerCapture
	secret     string
	sourceTree string
	policy     GitHubActionPolicy
}

func newGitHubActionFixture(t *testing.T) *githubActionFixture {
	t.Helper()
	fx := newMergeFixture(t, true)
	tree := strings.TrimSpace(hiveGitOutput(t, "", "--git-dir", fx.repoPath, "rev-parse", fx.acceptedCommit+"^{tree}"))
	policy := GitHubActionPolicy{
		Repository: "upstream/project", RepositoryID: 1234, RepoAddress: fx.repoAddress(),
		Actors: []string{"release-bot"}, ActorIDs: []int64{5678},
		Events:            []string{"workflow_dispatch", "repository_dispatch", "pull_request"},
		ProtectedBranches: []string{"main"}, Workflows: []string{".gitea/workflows/deploy.yml"},
		RepositoryDispatchActions: []string{"deploy"}, Version: "release-v1",
	}
	runner := &githubRunnerCapture{calls: make(chan struct{}, 8)}
	handler, err := NewGitHubActionHandler(GitHubActionConfig{
		Secret: "github-secret", RepositoriesDir: fx.repositoriesDir, Policies: []GitHubActionPolicy{policy},
	}, fx.store, runner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &githubActionFixture{merge: fx, handler: handler, runner: runner, secret: "github-secret", sourceTree: tree, policy: policy}
}

func (fx *githubActionFixture) manualPayload() map[string]any {
	return map[string]any{
		"ref": "refs/heads/main", "workflow": fx.policy.Workflows[0],
		"repository": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID},
		"sender":     map[string]any{"login": "release-bot", "id": fx.policy.ActorIDs[0]},
		"inputs": map[string]any{
			"repo_address": fx.policy.RepoAddress, "source_commit": fx.merge.acceptedCommit,
			"accepted_commit": fx.merge.acceptedCommit, "source_tree": fx.sourceTree,
			"workflow": fx.policy.Workflows[0], "policy_version": fx.policy.Version,
			"mirror_ref": "refs/heads/main",
		},
	}
}

func TestGitHubWorkflowDispatchClaimsAndObservesReplay(t *testing.T) {
	fx := newGitHubActionFixture(t)
	body, _ := json.Marshal(fx.manualPayload())
	first := fx.request(t, "workflow_dispatch", "delivery-1", body, fx.secret)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	fx.runner.wait(t, 1)
	replay := fx.request(t, "workflow_dispatch", "delivery-1", body, fx.secret)
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replay":true`) {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	fx.runner.wait(t, 1)
	ids := fx.runner.snapshot()
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("runner ids=%v", ids)
	}
	envelope, err := fx.merge.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceGitHubActions, "delivery-1")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.RepoAddress != fx.policy.RepoAddress || envelope.SourceCommit != fx.merge.acceptedCommit ||
		envelope.AcceptedCommit != fx.merge.acceptedCommit || envelope.SourceTree != fx.sourceTree ||
		envelope.WorkflowPath != fx.policy.Workflows[0] || envelope.PolicyVersion != fx.policy.Version ||
		envelope.Actor != "release-bot" || envelope.Action != "workflow_dispatch" {
		t.Fatalf("incomplete envelope: %#v", envelope)
	}
	if !strings.Contains(envelope.EvidenceJSON, `"repository_id":1234`) ||
		!strings.Contains(envelope.EvidenceJSON, `"actor_id":5678`) ||
		!strings.Contains(envelope.EvidenceJSON, `"policy_sha256":"`) {
		t.Fatalf("immutable identity/policy proof missing: %s", envelope.EvidenceJSON)
	}
}

func TestGitHubRepositoryDispatchAccepted(t *testing.T) {
	fx := newGitHubActionFixture(t)
	manual := fx.manualPayload()["inputs"]
	payload := map[string]any{
		"action": "deploy", "repository": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID},
		"sender": map[string]any{"login": "release-bot", "id": fx.policy.ActorIDs[0]}, "client_payload": manual,
	}
	body, _ := json.Marshal(payload)
	response := fx.request(t, "repository_dispatch", "repository-delivery", body, fx.secret)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	fx.runner.wait(t, 1)
}

func TestGitHubProtectedMergedPullRequestAccepted(t *testing.T) {
	fx := newGitHubActionFixture(t)
	payload := map[string]any{
		"action": "closed", "repository": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID},
		"sender": map[string]any{"login": "release-bot", "id": fx.policy.ActorIDs[0]},
		"pull_request": map[string]any{
			"merged": true, "merge_commit_sha": fx.merge.acceptedCommit,
			"head": map[string]any{"sha": fx.merge.sourceCommit},
			"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID}},
		},
	}
	body, _ := json.Marshal(payload)
	response := fx.request(t, "pull_request", "merge-delivery", body, fx.secret)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	fx.runner.wait(t, 1)
	envelope, err := fx.merge.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceGitHubActions, "merge-delivery")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.SourceCommit != fx.merge.sourceCommit || envelope.AcceptedCommit != fx.merge.acceptedCommit || envelope.Action != "pull_request" {
		t.Fatalf("unexpected protected merge envelope: %#v", envelope)
	}
}

func TestGitHubPullRequestMustBeMergedToProtectedBranch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		merged bool
		branch string
	}{
		{name: "not merged", merged: false, branch: "main"},
		{name: "unprotected branch", merged: true, branch: "preview"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newGitHubActionFixture(t)
			payload := map[string]any{
				"action": "closed", "repository": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID},
				"sender": map[string]any{"login": "release-bot", "id": fx.policy.ActorIDs[0]},
				"pull_request": map[string]any{
					"merged": tc.merged, "merge_commit_sha": fx.merge.acceptedCommit,
					"head": map[string]any{"sha": fx.merge.sourceCommit},
					"base": map[string]any{"ref": tc.branch, "repo": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID}},
				},
			}
			body, _ := json.Marshal(payload)
			response := fx.request(t, "pull_request", "rejected-pr", body, fx.secret)
			if response.Code < 400 || response.Code >= 500 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if ids := fx.runner.snapshot(); len(ids) != 0 {
				t.Fatalf("rejected PR ran envelope: %v", ids)
			}
		})
	}
}

func TestGitHubActionIngressFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		status int
	}{
		{"missing mirror proof", func(p map[string]any) { p["inputs"].(map[string]any)["mirror_ref"] = "" }, http.StatusForbidden},
		{"wrong repository", func(p map[string]any) { p["repository"].(map[string]any)["full_name"] = "attacker/repo" }, http.StatusForbidden},
		{"wrong repository id", func(p map[string]any) { p["repository"].(map[string]any)["id"] = int64(9999) }, http.StatusForbidden},
		{"wrong canonical coordinate", func(p map[string]any) { p["inputs"].(map[string]any)["repo_address"] = "30617:wrong:repo" }, http.StatusForbidden},
		{"wrong commit", func(p map[string]any) {
			p["inputs"].(map[string]any)["source_commit"] = strings.Repeat("f", 40)
			p["inputs"].(map[string]any)["accepted_commit"] = strings.Repeat("f", 40)
		}, http.StatusUnprocessableEntity},
		{"wrong tree", func(p map[string]any) { p["inputs"].(map[string]any)["source_tree"] = strings.Repeat("a", 40) }, http.StatusUnprocessableEntity},
		{"unauthorized actor", func(p map[string]any) { p["sender"].(map[string]any)["login"] = "intruder" }, http.StatusForbidden},
		{"wrong actor id", func(p map[string]any) { p["sender"].(map[string]any)["id"] = int64(9999) }, http.StatusForbidden},
		{"wrong workflow", func(p map[string]any) { p["inputs"].(map[string]any)["workflow"] = ".github/workflows/other.yml" }, http.StatusUnprocessableEntity},
		{"wrong policy", func(p map[string]any) { p["inputs"].(map[string]any)["policy_version"] = "old" }, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newGitHubActionFixture(t)
			payload := fx.manualPayload()
			tt.mutate(payload)
			body, _ := json.Marshal(payload)
			response := fx.request(t, "workflow_dispatch", "rejected", body, fx.secret)
			if response.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tt.status, response.Body.String())
			}
			if ids := fx.runner.snapshot(); len(ids) != 0 {
				t.Fatalf("rejected request ran envelopes: %v", ids)
			}
			if _, err := fx.merge.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceGitHubActions, "rejected"); err == nil {
				t.Fatal("rejected request left a durable envelope")
			}
		})
	}
}

func TestGitHubActionDuplicateConflictIsTerminal(t *testing.T) {
	fx := newGitHubActionFixture(t)
	payload := fx.manualPayload()
	body, _ := json.Marshal(payload)
	if response := fx.request(t, "workflow_dispatch", "conflict-delivery", body, fx.secret); response.Code != http.StatusAccepted {
		t.Fatalf("initial status=%d body=%s", response.Code, response.Body.String())
	}
	fx.runner.wait(t, 1)
	payload["nonce"] = "changed"
	conflictingBody, _ := json.Marshal(payload)
	response := fx.request(t, "workflow_dispatch", "conflict-delivery", conflictingBody, fx.secret)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", response.Code, response.Body.String())
	}
	if ids := fx.runner.snapshot(); len(ids) != 1 {
		t.Fatalf("conflict re-ran workflow: %v", ids)
	}
}

func TestGitHubActionRunnerFailureIsRetryableAndReplayResumes(t *testing.T) {
	fx := newGitHubActionFixture(t)
	body, _ := json.Marshal(fx.manualPayload())
	fx.runner.error = errors.New("temporary runner failure")
	failed := fx.request(t, "workflow_dispatch", "runner-retry", body, fx.secret)
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("failure status=%d body=%s", failed.Code, failed.Body.String())
	}
	if _, err := fx.merge.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceGitHubActions, "runner-retry"); err != nil {
		t.Fatalf("runner failure did not retain envelope: %v", err)
	}
	fx.runner.error = nil
	replay := fx.request(t, "workflow_dispatch", "runner-retry", body, fx.secret)
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replay":true`) {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	ids := fx.runner.snapshot()
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("runner replay ids=%v", ids)
	}
}

func TestGitHubActionRequiresValidHMACAndHeaders(t *testing.T) {
	fx := newGitHubActionFixture(t)
	body, _ := json.Marshal(fx.manualPayload())
	if response := fx.request(t, "workflow_dispatch", "delivery", body, "wrong"); response.Code != http.StatusUnauthorized {
		t.Fatalf("bad HMAC status=%d body=%s", response.Code, response.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, GitHubActionsRoute, bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", githubSignature(fx.secret, body))
	response := httptest.NewRecorder()
	fx.handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing headers status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGitHubRepositoryDispatchRequiresAuthorizedAction(t *testing.T) {
	fx := newGitHubActionFixture(t)
	payload := map[string]any{
		"action": "destroy", "repository": map[string]any{"full_name": fx.policy.Repository, "id": fx.policy.RepositoryID},
		"sender": map[string]any{"login": "release-bot", "id": fx.policy.ActorIDs[0]}, "client_payload": fx.manualPayload()["inputs"],
	}
	body, _ := json.Marshal(payload)
	response := fx.request(t, "repository_dispatch", "bad-action", body, fx.secret)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGitHubActionPolicyRejectsInvalidCoordinate(t *testing.T) {
	fx := newMergeFixture(t, true)
	_, err := NewGitHubActionHandler(GitHubActionConfig{
		Secret: "secret", RepositoriesDir: fx.repositoriesDir,
		Policies: []GitHubActionPolicy{{Repository: "upstream/project", RepositoryID: 1, RepoAddress: "30617:wrong", Actors: []string{"bot"}, ActorIDs: []int64{2}, Events: []string{"workflow_dispatch"}, ProtectedBranches: []string{"main"}, Workflows: []string{".github/workflows/deploy.yml"}, Version: "v1"}},
	}, fx.store, &githubRunnerCapture{}, nil)
	if err == nil {
		t.Fatal("invalid canonical repository coordinate accepted")
	}
}

func TestGitHubActionIngressRequiresEnabledRunner(t *testing.T) {
	fx := newMergeFixture(t, true)
	_, err := NewGitHubActionHandler(GitHubActionConfig{
		Secret: "secret", RepositoriesDir: fx.repositoriesDir,
		Policies: []GitHubActionPolicy{{Repository: "upstream/project", RepositoryID: 1,
			RepoAddress: fx.repoAddress(), Actors: []string{"bot"}, ActorIDs: []int64{2},
			Events: []string{"workflow_dispatch"}, ProtectedBranches: []string{"main"},
			Workflows: []string{".github/workflows/deploy.yml"}, Version: "v1"}},
	}, fx.store, &githubRunnerCapture{disabled: true}, nil)
	if err == nil {
		t.Fatal("disabled runner accepted for GitHub action ingress")
	}
}

func (fx *githubActionFixture) request(t *testing.T, event, delivery string, body []byte, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, GitHubActionsRoute, bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", githubSignature(secret, body))
	response := httptest.NewRecorder()
	fx.handler.ServeHTTP(response, req)
	return response
}

func githubSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

var _ githubActionStore = (*store.SQLiteStore)(nil)

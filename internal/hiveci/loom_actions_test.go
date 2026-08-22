// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-go"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type loomActionFixtureStore struct {
	*store.SQLiteStore
	jobs map[string]store.LoomJob
}

func (s *loomActionFixtureStore) GetLoomJobByTriggerEnvelope(_ context.Context, envelopeID, workflow string) (store.LoomJob, error) {
	job, ok := s.jobs[envelopeID+"\x00"+workflow]
	if !ok {
		return store.LoomJob{}, sql.ErrNoRows
	}
	return job, nil
}

type loomActionFixture struct {
	merge      *mergeFixture
	store      *loomActionFixtureStore
	runner     *githubRunnerCapture
	handler    *LoomActionIngestor
	policy     LoomActionPolicy
	actorPriv  string
	actorPub   string
	workflow   string
	lineage    store.TriggerEnvelope
	sourceTree string
}

func newLoomActionFixture(t *testing.T, allowDirect bool) *loomActionFixture {
	t.Helper()
	merge := newMergeFixture(t, true)
	remote := &mergeRemoteDispatcher{}
	status := merge.statusEvent(t, merge.ownerPriv, true, merge.acceptedCommit, merge.stateCreatedAt+1)
	if err := newMergeRunner(merge, remote).HandleEvent(merge.ctx, status, "wss://lineage.test"); err != nil {
		t.Fatal(err)
	}
	lineage, err := merge.store.GetMergeTriggerEnvelopeByStatusID(merge.ctx, status.ID.Hex())
	if err != nil {
		t.Fatal(err)
	}
	actorPub, err := derivePubHex(merge.ownerPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy := LoomActionPolicy{
		RepoAddress: merge.repoAddress(), Actors: []string{actorPub}, Branches: []string{"main"},
		Workflows: []string{".gitea/workflows/deploy.yml"}, AllowDirectDispatch: allowDirect, Version: "loom-release-v1",
	}
	fixtureStore := &loomActionFixtureStore{SQLiteStore: merge.store, jobs: make(map[string]store.LoomJob)}
	runner := &githubRunnerCapture{calls: make(chan struct{}, 16)}
	handler, err := NewLoomActionIngestor(LoomActionConfig{
		Enabled: true, RepositoriesDir: merge.repositoriesDir, Policies: []LoomActionPolicy{policy},
	}, fixtureStore, runner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &loomActionFixture{
		merge: merge, store: fixtureStore, runner: runner, handler: handler, policy: policy,
		actorPriv: merge.ownerPriv, actorPub: actorPub, workflow: policy.Workflows[0], lineage: lineage,
		sourceTree: lineage.SourceTree,
	}
}

func (fx *loomActionFixture) lineageDispatch(t *testing.T) *nostr.Event {
	t.Helper()
	return fx.actionEvent(t, fx.actorPriv, "dispatch", nostr.Tags{
		{"trigger-envelope", fx.lineage.IdempotencyKey},
		{"pr-event", fx.lineage.PREventID}, {"status-event", fx.lineage.StatusEventID},
	}, fx.lineage.SourceCommit, fx.lineage.SourceTree, fx.lineage.AcceptedCommit)
}

func (fx *loomActionFixture) directDispatch(t *testing.T) *nostr.Event {
	t.Helper()
	tree := strings.TrimSpace(hiveGitOutput(t, "", "--git-dir", fx.merge.repoPath,
		"rev-parse", fx.merge.acceptedCommit+"^{tree}"))
	return fx.actionEvent(t, fx.actorPriv, "dispatch", nostr.Tags{{"direct", "true"}},
		fx.merge.acceptedCommit, tree, fx.merge.acceptedCommit)
}

func (fx *loomActionFixture) retry(t *testing.T, original store.TriggerEnvelope, runID string) *nostr.Event {
	t.Helper()
	return fx.actionEvent(t, fx.actorPriv, "retry", nostr.Tags{
		{"trigger-envelope", original.IdempotencyKey}, {"e", runID},
	}, original.SourceCommit, original.SourceTree, original.AcceptedCommit)
}

func (fx *loomActionFixture) actionEvent(t *testing.T, priv, action string, extra nostr.Tags,
	sourceCommit, sourceTree, acceptedCommit string) *nostr.Event {
	t.Helper()
	tags := nostr.Tags{
		{"action", action}, {"domain", loomWorkflowMethod.Domain}, {"op", loomWorkflowMethod.Op},
		{"schema", loomWorkflowMethod.Schema}, {"a", fx.policy.RepoAddress},
		{"commit", acceptedCommit}, {"source-commit", sourceCommit}, {"source-tree", sourceTree},
		{"branch", "main"}, {"workflow", fx.workflow}, {"policy", fx.policy.Version},
	}
	tags = append(tags, extra...)
	return signMergeEventAt(t, priv, int(relay.KindHiveWorkflowRun), tags, "", time.Now().Unix())
}

func TestLoomActionAcceptedLineageAndDuplicateObservation(t *testing.T) {
	fx := newLoomActionFixture(t, false)
	ev := fx.lineageDispatch(t)
	handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, "wss://loom.test")
	if err != nil || !handled {
		t.Fatalf("accepted dispatch = %v, %v", handled, err)
	}
	fx.runner.wait(t, 1)
	envelope, err := fx.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceLoomActions, ev.ID.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if envelope.WorkflowPath != fx.workflow || envelope.Action != "workflow_dispatch" ||
		envelope.PREventID != fx.lineage.PREventID || envelope.StatusEventID != fx.lineage.StatusEventID ||
		envelope.SourceCommit != fx.lineage.SourceCommit || envelope.SourceTree != fx.lineage.SourceTree ||
		envelope.AcceptedCommit != fx.lineage.AcceptedCommit || envelope.Actor != fx.actorPub {
		t.Fatalf("incomplete Loom envelope: %#v", envelope)
	}
	if !strings.Contains(envelope.EvidenceJSON, `"schema_version":"`+loomWorkflowMethod.Schema+`"`) ||
		!strings.Contains(envelope.EvidenceJSON, `"policy_sha256":"`) {
		t.Fatalf("normalized evidence is incomplete: %s", envelope.EvidenceJSON)
	}
	if handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, "wss://loom.other"); err != nil || !handled {
		t.Fatalf("duplicate dispatch = %v, %v", handled, err)
	}
	fx.runner.wait(t, 1)
	if calls := fx.runner.snapshot(); len(calls) != 2 || calls[0] != envelope.IdempotencyKey || calls[1] != envelope.IdempotencyKey {
		t.Fatalf("duplicate did not resume the same durable trigger: %v", calls)
	}
}

func TestLoomActionRejectsUnauthorizedActorAndMissingLineage(t *testing.T) {
	t.Run("unauthorized actor", func(t *testing.T) {
		fx := newLoomActionFixture(t, false)
		ev := fx.actionEvent(t, fx.merge.contributorPriv, "dispatch", nostr.Tags{
			{"trigger-envelope", fx.lineage.IdempotencyKey}, {"pr-event", fx.lineage.PREventID},
			{"status-event", fx.lineage.StatusEventID},
		}, fx.lineage.SourceCommit, fx.lineage.SourceTree, fx.lineage.AcceptedCommit)
		if handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, ""); !handled || !isNonRetryable(err) {
			t.Fatalf("unauthorized actor = %v, %v", handled, err)
		}
	})
	t.Run("missing lineage", func(t *testing.T) {
		fx := newLoomActionFixture(t, false)
		ev := fx.actionEvent(t, fx.actorPriv, "dispatch", nil,
			fx.lineage.SourceCommit, fx.lineage.SourceTree, fx.lineage.AcceptedCommit)
		if handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, ""); !handled || !isNonRetryable(err) {
			t.Fatalf("missing lineage = %v, %v", handled, err)
		}
	})
}

func TestLoomActionDirectPolicyDenyAndAllow(t *testing.T) {
	denied := newLoomActionFixture(t, false)
	if handled, err := denied.handler.HandleEvent(denied.merge.ctx, denied.directDispatch(t), ""); !handled || !isNonRetryable(err) {
		t.Fatalf("direct deny = %v, %v", handled, err)
	}
	allowed := newLoomActionFixture(t, true)
	ev := allowed.directDispatch(t)
	if handled, err := allowed.handler.HandleEvent(allowed.merge.ctx, ev, ""); err != nil || !handled {
		t.Fatalf("direct allow = %v, %v", handled, err)
	}
	allowed.runner.wait(t, 1)
	envelope, err := allowed.store.GetTriggerEnvelopeByIdentity(allowed.merge.ctx, TriggerSourceLoomActions, ev.ID.Hex())
	if err != nil || envelope.PREventID != "" || envelope.StatusEventID != "" || envelope.SourceCommit != envelope.AcceptedCommit {
		t.Fatalf("direct envelope = %#v, %v", envelope, err)
	}
}

func TestLoomActionRejectsWrongImmutableEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*loomActionFixture, nostr.Tags)
	}{
		{"wrong repository", func(_ *loomActionFixture, tags nostr.Tags) { replaceLoomTag(tags, "a", "30617:wrong:repo") }},
		{"wrong commit", func(_ *loomActionFixture, tags nostr.Tags) { replaceLoomTag(tags, "commit", strings.Repeat("f", 40)) }},
		{"wrong source tree", func(_ *loomActionFixture, tags nostr.Tags) {
			replaceLoomTag(tags, "source-tree", strings.Repeat("a", 40))
		}},
		{"wrong workflow", func(_ *loomActionFixture, tags nostr.Tags) {
			replaceLoomTag(tags, "workflow", ".gitea/workflows/other.yml")
		}},
		{"wrong policy", func(_ *loomActionFixture, tags nostr.Tags) { replaceLoomTag(tags, "policy", "old") }},
		{"wrong status lineage", func(_ *loomActionFixture, tags nostr.Tags) {
			replaceLoomTag(tags, "status-event", strings.Repeat("b", 64))
		}},
		{"wrong schema", func(_ *loomActionFixture, tags nostr.Tags) { replaceLoomTag(tags, "schema", "arbitrary.command.v1") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newLoomActionFixture(t, false)
			ev := fx.lineageDispatch(t)
			tt.mutate(fx, ev.Tags)
			resignMergeEvent(t, ev, fx.actorPriv)
			if handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, ""); !handled || !isNonRetryable(err) {
				t.Fatalf("wrong evidence = %v, %v", handled, err)
			}
			if calls := fx.runner.snapshot(); len(calls) != 0 {
				t.Fatalf("rejected evidence ran trigger: %v", calls)
			}
		})
	}
}

func TestLoomActionConflictIsNonRetryable(t *testing.T) {
	fx := newLoomActionFixture(t, false)
	ev := fx.lineageDispatch(t)
	conflict := store.TriggerEnvelope{
		IdempotencyKey: store.TriggerEnvelopeKey(TriggerSourceLoomActions, ev.ID.Hex()),
		Source:         TriggerSourceLoomActions, TriggerID: ev.ID.Hex(), Actor: fx.actorPub, Action: "workflow_dispatch",
		WorkflowPath: fx.workflow, EvidenceJSON: `{"preclaimed":true}`, SourceCommit: fx.lineage.SourceCommit,
		SourceTree: fx.lineage.SourceTree, PatchDigest: fx.lineage.PatchDigest,
		AcceptedCommit: fx.lineage.AcceptedCommit, RepoAddress: fx.lineage.RepoAddress,
		PolicyVersion: "conflicting-policy", Branch: fx.lineage.Branch,
	}
	if _, _, err := fx.store.ClaimTriggerEnvelope(fx.merge.ctx, conflict); err != nil {
		t.Fatal(err)
	}
	handled, err := fx.handler.HandleEvent(fx.merge.ctx, ev, "")
	if !handled || !errors.Is(err, store.ErrTriggerConflict) || !isNonRetryable(err) {
		t.Fatalf("conflict = %v, %v", handled, err)
	}
}

func TestLoomActionRetryResumesSameNonterminalRunAndRejectsTerminal(t *testing.T) {
	fx := newLoomActionFixture(t, false)
	dispatch := fx.lineageDispatch(t)
	if _, err := fx.handler.HandleEvent(fx.merge.ctx, dispatch, ""); err != nil {
		t.Fatal(err)
	}
	fx.runner.wait(t, 1)
	original, err := fx.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceLoomActions, dispatch.ID.Hex())
	if err != nil {
		t.Fatal(err)
	}
	runID := strings.Repeat("9", 64)
	jobKey := original.IdempotencyKey + "\x00" + fx.workflow
	fx.store.jobs[jobKey] = store.LoomJob{WorkflowRunID: runID, Status: store.LoomStatusPending}
	retry := fx.retry(t, original, runID)
	if handled, err := fx.handler.HandleEvent(fx.merge.ctx, retry, "wss://retry.test"); err != nil || !handled {
		t.Fatalf("nonterminal retry = %v, %v", handled, err)
	}
	fx.runner.wait(t, 1)
	calls := fx.runner.snapshot()
	if len(calls) != 2 || calls[1] != original.IdempotencyKey {
		t.Fatalf("retry did not resume original trigger: %v", calls)
	}
	retryEnvelope, err := fx.store.GetTriggerEnvelopeByIdentity(fx.merge.ctx, TriggerSourceLoomActions, retry.ID.Hex())
	if err != nil || retryEnvelope.Action != "retry" {
		t.Fatalf("retry envelope = %#v, %v", retryEnvelope, err)
	}

	fx.store.jobs[jobKey] = store.LoomJob{WorkflowRunID: runID, Status: store.LoomStatusSuccess}
	terminalRetry := fx.retry(t, original, runID)
	terminalRetry.CreatedAt++
	resignMergeEvent(t, terminalRetry, fx.actorPriv)
	if handled, err := fx.handler.HandleEvent(fx.merge.ctx, terminalRetry, ""); !handled || !isNonRetryable(err) ||
		!strings.Contains(err.Error(), "terminal") {
		t.Fatalf("terminal retry = %v, %v", handled, err)
	}
}

func TestLoomActionIgnoresLocalWorkflowRunSelfEchoAndRawCommands(t *testing.T) {
	fx := newLoomActionFixture(t, false)
	local, err := NewLoomActionIngestor(LoomActionConfig{
		Enabled: true, LocalPubkey: fx.actorPub, RepositoriesDir: fx.merge.repositoriesDir,
		Policies: []LoomActionPolicy{fx.policy},
	}, fx.store, fx.runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := local.HandleEvent(fx.merge.ctx, fx.lineageDispatch(t), ""); err != nil || !handled {
		t.Fatalf("self echo = %v, %v", handled, err)
	}
	raw := signMergeEventAt(t, fx.actorPriv, int(relay.KindHiveWorkflowRun), nostr.Tags{
		{"a", fx.policy.RepoAddress}, {"cmd", "rm"}, {"args", "-rf"},
	}, "arbitrary", time.Now().Unix())
	if handled, err := fx.handler.HandleEvent(fx.merge.ctx, raw, ""); err != nil || !handled {
		t.Fatalf("raw workflow event = %v, %v", handled, err)
	}
	if calls := fx.runner.snapshot(); len(calls) != 0 {
		t.Fatalf("self echo/raw command ran trigger: %v", calls)
	}
}

func TestLoomActionOperationalCancellationRemainsRetryable(t *testing.T) {
	fx := newLoomActionFixture(t, false)
	ctx, cancel := context.WithCancel(fx.merge.ctx)
	cancel()
	handled, err := fx.handler.HandleEvent(ctx, fx.lineageDispatch(t), "")
	if !handled || err == nil || isNonRetryable(err) {
		t.Fatalf("canceled validation = %v, %v", handled, err)
	}
}

func TestLoomActionUsesCanonicalLegacyWorkflowBinding(t *testing.T) {
	if loomWorkflowMethod.Kind != cascadia.KindContextVMIntent || loomWorkflowMethod.Domain != "ci" ||
		loomWorkflowMethod.Op != "workflow-run" || loomWorkflowMethod.Schema == "" {
		t.Fatalf("unexpected canonical workflow binding: %#v", loomWorkflowMethod)
	}
}

func replaceLoomTag(tags nostr.Tags, key, value string) {
	for i := range tags {
		if len(tags[i]) >= 2 && tags[i][0] == key {
			tags[i][1] = value
			return
		}
	}
}

func isNonRetryable(err error) bool {
	if err == nil {
		return false
	}
	var terminal interface{ NonRetryable() bool }
	return errors.As(err, &terminal) && terminal.NonRetryable()
}

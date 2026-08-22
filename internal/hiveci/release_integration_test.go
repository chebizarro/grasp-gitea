// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type allowReleaseLineageVerifier struct {
	calls int
	err   error
}

func (v *allowReleaseLineageVerifier) RevalidateDispatch(_ context.Context, _ store.LoomJob) error {
	v.calls++
	return v.err
}

func loomReleaseFixture(t *testing.T, request ReleaseRequest) (store.LoomJob, *nostr.Event, nostr.SecretKey) {
	t.Helper()
	operator, publisher := nostr.Generate(), nostr.Generate()
	run := &nostr.Event{
		Kind: relay.KindHiveWorkflowRun,
		Tags: nostr.Tags{
			{"trigger-envelope", request.Lineage.TriggerIdentity},
			{"idempotency", request.Lineage.TriggerIdentity},
			{"trigger-source", request.Lineage.TriggerSource},
			{"trigger-id", request.Lineage.TriggerID},
			{"pr-event", request.Lineage.PREventID},
			{"pr", request.Lineage.PREventID},
			{"review", request.Lineage.ReviewEventID},
			{"audit", request.Lineage.AuditEventID},
			{"a", request.Lineage.RepoAddress},
			{"repo-address", request.Lineage.RepoAddress},
			{"source-repo", request.Lineage.SourceRepoIdentity},
			{"source-provenance", request.Lineage.SourceProvenanceRef},
			{"commit", request.Lineage.Commit},
			{"tree", request.Lineage.Tree},
			{"workflow-digest", request.Lineage.WorkflowDigest},
			{"worker", request.Execution.WorkerIdentity},
			{"worker-ad", "ad-" + request.Execution.WorkerIdentity},
			{"worker-capability", request.Execution.WorkerCapability},
			{"publisher", publisher.Public().Hex()},
		},
	}
	if err := run.Sign(operator); err != nil {
		t.Fatal(err)
	}
	runJSON, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	job := store.LoomJob{
		WorkflowRunID: run.ID.Hex(), PublisherPub: publisher.Public().Hex(),
		WorkerPub: request.Execution.WorkerIdentity, WorkerAdID: "ad-" + request.Execution.WorkerIdentity,
		WorkflowRunEvent: string(runJSON), CommitSHA: request.Lineage.Commit,
	}
	complete, exitCode, durationMS := true, 0, request.Execution.DurationMS
	payload := loomReleasePayload{
		Status: "success", Complete: &complete, ExitCode: &exitCode, DurationMS: &durationMS,
		BuildEnvironmentImageDigest: request.Execution.BuildEnvironmentImageDigest,
		Tests:                       request.Execution.Tests, ImageRepo: request.ImageRepository, ImageTag: request.ImageTag,
		ImageDigest: request.Manifest.Digest, ManifestMediaType: request.Manifest.MediaType,
		OCIManifestBase64: base64.StdEncoding.EncodeToString(request.Manifest.Content), SBOMDigest: request.SBOM.Digest,
		SBOMMediaType: request.SBOM.MediaType, SBOMBase64: base64.StdEncoding.EncodeToString(request.SBOM.Content),
		LogURL: request.Execution.DurableLogReference,
	}
	content, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	result := &nostr.Event{
		Kind: relay.KindHiveWorkflowResult,
		Tags: nostr.Tags{
			{"e", run.ID.Hex()}, {"status", "success"}, {"complete", "true"},
			{"exit_code", "0"}, {"duration_ms", strconv.FormatInt(request.Execution.DurationMS, 10)},
			{"log_url", request.Execution.DurableLogReference},
			{"image_repo", request.ImageRepository}, {"image_tag", request.ImageTag},
			{"image_digest", request.Manifest.Digest}, {"sbom_digest", request.SBOM.Digest},
			{"build_image_digest", request.Execution.BuildEnvironmentImageDigest},
			{"worker", request.Execution.WorkerIdentity},
			{"worker_capability", request.Execution.WorkerCapability},
		},
		Content: string(content),
	}
	if err := result.Sign(publisher); err != nil {
		t.Fatal(err)
	}
	return job, result, publisher
}

func TestLoomReleaseFinalizationPublishesSignedBahiaCompatibleResultAndReplays(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	request.ImageTag = "release-20260821"
	job, workerResult, _ := loomReleaseFixture(t, request)

	runner := New(Config{}, st, signer, nil, "", nil)
	verifier := &allowReleaseLineageVerifier{}
	runner.SetReleaseLineageVerifier(verifier)
	runner.SetReleasePublisher(NewReleasePublisher(st, registry, signer), request.RegistryRepository, request.ImageRepository)
	var relayed []*nostr.Event
	runner.publish = func(_ context.Context, event *nostr.Event) error {
		copyEvent := *event
		copyEvent.Tags = cloneReleaseTags(event.Tags)
		relayed = append(relayed, &copyEvent)
		return nil
	}

	if err := runner.FinalizeRelease(ctx, job, workerResult); err != nil {
		t.Fatal(err)
	}
	if len(relayed) != 1 {
		t.Fatalf("published results=%d, want 1", len(relayed))
	}
	release := relayed[0]
	for key, want := range map[string]string{
		"e": job.WorkflowRunID, "status": "success", "result": ReleaseResultType,
		"exit_code": "0", "duration": strconv.FormatInt(request.Execution.DurationMS/1000, 10),
		"log_url":    request.Execution.DurableLogReference,
		"image_repo": request.ImageRepository, "image_tag": request.ImageTag,
		"image_digest": request.Manifest.Digest,
	} {
		if got := tagValue(release.Tags, key); got != want {
			t.Fatalf("release tag %s=%q, want %q", key, got, want)
		}
	}
	var body ReleaseResult
	if err := json.Unmarshal([]byte(release.Content), &body); err != nil {
		t.Fatal(err)
	}
	if body.Lineage.TriggerIdentity != request.Lineage.TriggerIdentity ||
		body.Lineage.SourceProvenanceRef != request.Lineage.SourceProvenanceRef ||
		body.Execution.WorkerIdentity != request.Execution.WorkerIdentity ||
		body.Execution.WorkerCapability != request.Execution.WorkerCapability ||
		body.Execution.BuildEnvironmentImageDigest != request.Execution.BuildEnvironmentImageDigest {
		t.Fatalf("release lost exact lineage/execution evidence: %+v", body)
	}

	if err := runner.FinalizeRelease(ctx, job, workerResult); err != nil {
		t.Fatal(err)
	}
	if len(relayed) != 2 || relayed[1].ID != release.ID || registry.callCount() != 3 || signer.calls != 1 {
		t.Fatalf("replay changed identity or side effects: relayed=%d registry=%d signer=%d",
			len(relayed), registry.callCount(), signer.calls)
	}
	if verifier.calls != 2 {
		t.Fatalf("release replay skipped lineage revalidation: %d", verifier.calls)
	}
}

func TestLoomReleaseFinalizationRejectsConflictingDurationEvidence(t *testing.T) {
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	job, workerResult, publisher := loomReleaseFixture(t, request)
	workerResult.Tags = append(workerResult.Tags, nostr.Tag{"duration", "99"})
	workerResult.ID, workerResult.Sig = nostr.ID{}, [64]byte{}
	if err := workerResult.Sign(publisher); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{}, st, signer, nil, "", nil)
	runner.SetReleaseLineageVerifier(&allowReleaseLineageVerifier{})
	runner.SetReleasePublisher(NewReleasePublisher(st, registry, signer), request.RegistryRepository, request.ImageRepository)
	runner.publish = func(context.Context, *nostr.Event) error { return nil }
	if err := runner.FinalizeRelease(context.Background(), job, workerResult); !errors.Is(err, ErrIncompleteRelease) {
		t.Fatalf("error=%v, want conflicting duration rejection", err)
	}
	if registry.callCount() != 0 || signer.calls != 0 {
		t.Fatal("conflicting duration crossed release side-effect boundary")
	}
}

func TestLoomReleaseFinalizationRejectsConflictingSuccessEvidence(t *testing.T) {
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	job, workerResult, publisher := loomReleaseFixture(t, request)
	var payload loomReleasePayload
	if err := json.Unmarshal([]byte(workerResult.Content), &payload); err != nil {
		t.Fatal(err)
	}
	payload.Status = "failure"
	content, _ := json.Marshal(payload)
	workerResult.Content = string(content)
	workerResult.ID, workerResult.Sig = nostr.ID{}, [64]byte{}
	if err := workerResult.Sign(publisher); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{}, st, signer, nil, "", nil)
	runner.SetReleaseLineageVerifier(&allowReleaseLineageVerifier{})
	runner.SetReleasePublisher(NewReleasePublisher(st, registry, signer), request.RegistryRepository, request.ImageRepository)
	runner.publish = func(context.Context, *nostr.Event) error { return nil }
	if err := runner.FinalizeRelease(context.Background(), job, workerResult); !errors.Is(err, ErrIncompleteRelease) {
		t.Fatalf("error=%v, want conflicting success rejection", err)
	}
	if registry.callCount() != 0 || signer.calls != 0 {
		t.Fatal("conflicting success evidence crossed release side-effect boundary")
	}
}

func TestLoomReleaseFinalizationFailedTestsCannotCrossSideEffectBoundary(t *testing.T) {
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	request.ImageTag = "release-20260821"
	job, workerResult, publisher := loomReleaseFixture(t, request)

	var payload loomReleasePayload
	if err := json.Unmarshal([]byte(workerResult.Content), &payload); err != nil {
		t.Fatal(err)
	}
	payload.Tests.Status, payload.Tests.Total = "failure", 2
	payload.Tests.Passed, payload.Tests.Failed = 1, 1
	content, _ := json.Marshal(payload)
	workerResult.Content = string(content)
	workerResult.ID, workerResult.Sig = nostr.ID{}, [64]byte{}
	if err := workerResult.Sign(publisher); err != nil {
		t.Fatal(err)
	}

	runner := New(Config{}, st, signer, nil, "", nil)
	runner.SetReleaseLineageVerifier(&allowReleaseLineageVerifier{})
	runner.SetReleasePublisher(NewReleasePublisher(st, registry, signer), request.RegistryRepository, request.ImageRepository)
	relayed := 0
	runner.publish = func(context.Context, *nostr.Event) error { relayed++; return nil }

	err := runner.FinalizeRelease(context.Background(), job, workerResult)
	if !errors.Is(err, ErrIncompleteRelease) {
		t.Fatalf("error=%v, want incomplete release", err)
	}
	if registry.callCount() != 0 || signer.calls != 0 || relayed != 0 {
		t.Fatalf("failed tests crossed success boundary: registry=%d signer=%d relayed=%d",
			registry.callCount(), signer.calls, relayed)
	}
}

func cloneReleaseTags(tags nostr.Tags) nostr.Tags {
	cloned := make(nostr.Tags, len(tags))
	for i := range tags {
		cloned[i] = append(nostr.Tag(nil), tags[i]...)
	}
	return cloned
}

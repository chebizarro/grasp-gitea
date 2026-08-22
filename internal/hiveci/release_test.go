// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeReleaseRegistry struct {
	mu         sync.Mutex
	calls      []RegistryObject
	failAt     int
	conflictAt int
}

func (r *fakeReleaseRegistry) PushByDigest(_ context.Context, repository string, object RegistryObject) (RegistryReference, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, object)
	call := len(r.calls)
	if r.failAt == call {
		return RegistryReference{}, errors.New("fixture upload failure")
	}
	if r.conflictAt == call {
		return RegistryReference{}, ErrRegistryConflict
	}
	if err := validateRegistryObject(repository, object); err != nil {
		return RegistryReference{}, err
	}
	return RegistryReference{Repository: repository, Digest: object.Digest,
		MediaType: object.MediaType, Size: int64(len(object.Content))}, nil
}

func (r *fakeReleaseRegistry) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type countingReleaseSigner struct {
	base  fakeSigner
	fail  bool
	calls int
}

func (s *countingReleaseSigner) PublicKey() string { return s.base.PublicKey() }
func (s *countingReleaseSigner) SignEvent(ctx context.Context, event *nostr.Event) error {
	s.calls++
	if s.fail {
		return errors.New("fixture Signet unavailable")
	}
	return s.base.SignEvent(ctx, event)
}

func openReleaseTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "release.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func validReleaseRequest(t *testing.T) ReleaseRequest {
	t.Helper()
	configDigest := "sha256:" + strings.Repeat("5", 64)
	layerDigest := "sha256:" + strings.Repeat("6", 64)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":3}]}`,
		OCIImageManifestV1, configDigest, layerDigest))
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	return ReleaseRequest{
		Lineage: ReleaseLineage{
			WorkflowRunEventID: strings.Repeat("a", 64),
			TriggerIdentity:    strings.Repeat("b", 64), TriggerSource: "github-actions",
			TriggerID: "delivery-123", PREventID: strings.Repeat("c", 64),
			ReviewEventID: strings.Repeat("d", 64), AuditEventID: strings.Repeat("e", 64),
			RepoAddress:         "30617:" + strings.Repeat("f", 64) + ":sap",
			SourceRepoIdentity:  "https://git.example/sap.git",
			SourceProvenanceRef: store.SourceProvenanceReferencePrefix + strings.Repeat("7", 64),
			Commit:              strings.Repeat("8", 40), Tree: strings.Repeat("9", 40),
			WorkflowDigest: strings.Repeat("1", 64),
		},
		Execution: ReleaseExecution{
			Complete: true, Status: "success", ExitCode: 0, DurationMS: 1250,
			WorkerIdentity: strings.Repeat("2", 64), WorkerCapability: "linux-amd64:docker-buildx",
			BuildEnvironmentImageDigest: "sha256:" + strings.Repeat("3", 64),
			Tests:                       ReleaseTestSummary{Status: "success", Total: 3, Passed: 2, Skipped: 1},
			DurableLogReference:         "oci://harbor.example/sap/logs/run@sha256:" + strings.Repeat("4", 64),
		},
		RegistryRepository: "sap/application",
		ImageRepository:    "harbor.example.com/sap/application",
		Manifest:           RegistryObject{Digest: DigestBytes(manifest), MediaType: OCIImageManifestV1, Content: manifest},
		SBOM:               RegistryObject{Digest: DigestBytes(sbom), MediaType: CycloneDXJSONMediaType, Content: sbom},
	}
}

func TestReleasePublisherSuccessProducesSignedImmutableTerminalResult(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	publisher := NewReleasePublisher(st, registry, signer)
	request := validReleaseRequest(t)

	release, err := publisher.Publish(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if release.Replay || release.Identity == "" || release.Event == nil {
		t.Fatalf("unexpected release result: %+v", release)
	}
	if release.Event.Kind != relay.KindHiveWorkflowResult ||
		tagValue(release.Event.Tags, "status") != "success" ||
		tagValue(release.Event.Tags, "result") != ReleaseResultType ||
		tagValue(release.Event.Tags, "e") != request.Lineage.WorkflowRunEventID ||
		tagValue(release.Event.Tags, "image_repo") != request.ImageRepository ||
		tagValue(release.Event.Tags, "image_digest") != request.Manifest.Digest ||
		tagValue(release.Event.Tags, "sbom_digest") != request.SBOM.Digest ||
		tagValue(release.Event.Tags, "provenance_digest") != release.Provenance.Digest {
		t.Fatalf("terminal result lacks release correlation: %+v", release.Event.Tags)
	}
	if err := nostrverify.ValidateEventIDAndSignature(release.Event); err != nil {
		t.Fatalf("signed terminal result: %v", err)
	}
	if registry.callCount() != 3 || signer.calls != 1 {
		t.Fatalf("calls registry=%d signer=%d, want 3/1", registry.callCount(), signer.calls)
	}
	record, err := st.GetReleaseProvenance(ctx, release.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if record.SignedEventID != release.Event.ID.Hex() || record.ManifestDigest != request.Manifest.Digest ||
		record.SBOMDigest != request.SBOM.Digest || record.ProvenanceDigest != release.Provenance.Digest {
		t.Fatalf("durable record does not bind artifacts: %+v", record)
	}
}

type rotatingReleaseSigner struct {
	first  nostr.SecretKey
	second nostr.SecretKey
	calls  int
}

func (s *rotatingReleaseSigner) PublicKey() string {
	s.calls++
	if s.calls == 1 {
		return s.first.Public().Hex()
	}
	return s.second.Public().Hex()
}

func (s *rotatingReleaseSigner) SignEvent(_ context.Context, event *nostr.Event) error {
	return event.Sign(s.first)
}

func TestReleasePublisherSnapshotsSignerIdentityBeforeAttestation(t *testing.T) {
	signer := &rotatingReleaseSigner{first: nostr.Generate(), second: nostr.Generate()}
	release, err := NewReleasePublisher(openReleaseTestStore(t), &fakeReleaseRegistry{}, signer).
		Publish(context.Background(), validReleaseRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if signer.calls != 1 || release.Event.PubKey.Hex() != signer.first.Public().Hex() {
		t.Fatalf("attestation signer was not a single identity snapshot: calls=%d pubkey=%s",
			signer.calls, release.Event.PubKey.Hex())
	}
}

func TestReleasePublisherRejectsFailedIncompleteAndLocalImageOnlyRuns(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReleaseRequest)
	}{
		{"failed tests", func(r *ReleaseRequest) {
			r.Execution.Status, r.Execution.ExitCode = "failure", 1
			r.Execution.Tests.Status, r.Execution.Tests.Failed = "failure", 1
			r.Execution.Tests.Passed = 1
			r.Execution.Tests.Total = 3
		}},
		{"incomplete", func(r *ReleaseRequest) { r.Execution.Complete = false }},
		{"local image id without manifest", func(r *ReleaseRequest) {
			r.Manifest.Content = nil
			r.Manifest.Digest = "sha256:" + strings.Repeat("5", 64)
		}},
		{"JSON mislabeled as SBOM", func(r *ReleaseRequest) {
			r.SBOM.Content = []byte(`{"not":"an sbom"}`)
			r.SBOM.Digest = DigestBytes(r.SBOM.Content)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			st := openReleaseTestStore(t)
			registry := &fakeReleaseRegistry{}
			signer := &countingReleaseSigner{base: newFakeSigner(t)}
			request := validReleaseRequest(t)
			test.mutate(&request)
			_, err := NewReleasePublisher(st, registry, signer).Publish(context.Background(), request)
			if !errors.Is(err, ErrIncompleteRelease) {
				t.Fatalf("error=%v, want incomplete release", err)
			}
			if registry.callCount() != 0 || signer.calls != 0 {
				t.Fatalf("invalid run crossed side-effect boundary: registry=%d signer=%d",
					registry.callCount(), signer.calls)
			}
		})
	}
}

func TestReleasePublisherPartialUploadCannotCommitSuccess(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{failAt: 2}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	identity, _ := releaseIdentity(request.Lineage)

	if _, err := NewReleasePublisher(st, registry, signer).Publish(ctx, request); err == nil {
		t.Fatal("expected partial upload failure")
	}
	if registry.callCount() != 2 || signer.calls != 0 {
		t.Fatalf("calls registry=%d signer=%d, want 2/0", registry.callCount(), signer.calls)
	}
	if _, err := st.GetReleaseProvenance(ctx, identity); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("partial upload committed release: %v", err)
	}
}

func TestReleasePublisherRegistryConflictCannotCommitSuccess(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{conflictAt: 1}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	request := validReleaseRequest(t)
	identity, _ := releaseIdentity(request.Lineage)

	_, err := NewReleasePublisher(st, registry, signer).Publish(ctx, request)
	if !errors.Is(err, ErrRegistryConflict) {
		t.Fatalf("error=%v, want registry conflict", err)
	}
	if signer.calls != 0 {
		t.Fatalf("registry conflict was signed")
	}
	if _, err := st.GetReleaseProvenance(ctx, identity); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("registry conflict committed release: %v", err)
	}
}

func TestReleasePublisherAttestationFailureCannotCommitSuccess(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t), fail: true}
	request := validReleaseRequest(t)
	identity, _ := releaseIdentity(request.Lineage)

	if _, err := NewReleasePublisher(st, registry, signer).Publish(ctx, request); err == nil {
		t.Fatal("expected attestation failure")
	}
	if registry.callCount() != 3 || signer.calls != 1 {
		t.Fatalf("calls registry=%d signer=%d, want 3/1", registry.callCount(), signer.calls)
	}
	if _, err := st.GetReleaseProvenance(ctx, identity); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("attestation failure committed release: %v", err)
	}
}

func TestReleasePublisherExactReplayReturnsSameEventWithoutSideEffects(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	publisher := NewReleasePublisher(st, registry, signer)
	request := validReleaseRequest(t)

	first, err := publisher.Publish(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publisher.Publish(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replay || second.Identity != first.Identity || second.Event.ID != first.Event.ID ||
		second.Event.Sig != first.Event.Sig {
		t.Fatalf("replay changed release identity or event")
	}
	if registry.callCount() != 3 || signer.calls != 1 {
		t.Fatalf("replay repeated side effects: registry=%d signer=%d", registry.callCount(), signer.calls)
	}
}

func TestReleasePublisherConflictingContentIsRejectedAndQuarantined(t *testing.T) {
	ctx := context.Background()
	st := openReleaseTestStore(t)
	registry := &fakeReleaseRegistry{}
	signer := &countingReleaseSigner{base: newFakeSigner(t)}
	publisher := NewReleasePublisher(st, registry, signer)
	request := validReleaseRequest(t)
	first, err := publisher.Publish(ctx, request)
	if err != nil {
		t.Fatal(err)
	}

	conflict := validReleaseRequest(t)
	conflict.Execution.WorkerCapability = "linux-amd64:different-builder"
	_, err = publisher.Publish(ctx, conflict)
	if !errors.Is(err, store.ErrReleaseProvenanceConflict) {
		t.Fatalf("error=%v, want release conflict", err)
	}
	if registry.callCount() != 3 || signer.calls != 1 {
		t.Fatalf("conflict side effects registry=%d signer=%d, want 3/1", registry.callCount(), signer.calls)
	}
	record, err := st.GetReleaseProvenance(ctx, first.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if record.SignedEventID != first.Event.ID.Hex() {
		t.Fatal("conflict rebound authoritative release")
	}
	quarantine, err := st.ListReleaseQuarantine(ctx, first.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantine) != 1 || quarantine[0].ExistingContentDigest == quarantine[0].ConflictingContentDigest ||
		quarantine[0].CandidateJSON == "" {
		t.Fatalf("conflict was not durably quarantined: %+v", quarantine)
	}
}

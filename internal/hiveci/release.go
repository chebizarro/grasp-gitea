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
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	ReleaseResultType      = "RELEASE"
	OCIImageManifestV1     = "application/vnd.oci.image.manifest.v1+json"
	CycloneDXJSONMediaType = "application/vnd.cyclonedx+json"
	SPDXJSONMediaType      = "application/spdx+json"
	InTotoJSONMediaType    = "application/vnd.in-toto+json"
	releasePredicateType   = "https://sharegap.net/hiveci/release-provenance/v1"
	releaseAttestationType = "https://sharegap.net/hiveci/signet-artifact-attestation/v1"
)

var ErrIncompleteRelease = errors.New("successful release provenance is incomplete or not green")

// ReleaseLineage closes the signed terminal result back to the accepted 5401
// dispatch, review/audit join, and independently verified source.
type ReleaseLineage struct {
	WorkflowRunEventID  string `json:"workflow_run_event_id"`
	TriggerIdentity     string `json:"trigger_identity"`
	TriggerSource       string `json:"trigger_source"`
	TriggerID           string `json:"trigger_id"`
	PREventID           string `json:"pr_event_id"`
	ReviewEventID       string `json:"review_event_id"`
	AuditEventID        string `json:"audit_event_id"`
	RepoAddress         string `json:"repo_address"`
	SourceRepoIdentity  string `json:"source_repo_identity"`
	SourceProvenanceRef string `json:"source_provenance_ref"`
	Commit              string `json:"commit"`
	Tree                string `json:"tree"`
	WorkflowDigest      string `json:"workflow_digest"`
}

type ReleaseTestSummary struct {
	Status  string `json:"status"`
	Total   int    `json:"total"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Skipped int    `json:"skipped"`
}

type ReleaseExecution struct {
	Complete                    bool               `json:"complete"`
	Status                      string             `json:"status"`
	ExitCode                    int                `json:"exit_code"`
	DurationMS                  int64              `json:"duration_ms"`
	BahiaDuration               string             `json:"duration,omitempty"`
	WorkerIdentity              string             `json:"worker_identity"`
	WorkerCapability            string             `json:"worker_capability"`
	BuildEnvironmentImageDigest string             `json:"build_environment_image_digest"`
	Tests                       ReleaseTestSummary `json:"tests"`
	DurableLogReference         string             `json:"durable_log_reference"`
}

// ReleaseRequest supplies the immutable image manifest and SBOM bytes.
// Provenance bytes are generated from the validated request so callers cannot
// upload a statement that omits or changes lineage.
type ReleaseRequest struct {
	Lineage            ReleaseLineage
	Execution          ReleaseExecution
	RegistryRepository string
	ImageRepository    string
	ImageTag           string
	Manifest           RegistryObject
	SBOM               RegistryObject
}

type ReleaseArtifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	Size       int64  `json:"size"`
}

type SignetArtifactAttestation struct {
	Type         string            `json:"type"`
	SignerPubkey string            `json:"signer_pubkey"`
	Subjects     []ReleaseArtifact `json:"subjects"`
}

type ReleaseResult struct {
	SchemaVersion       string                    `json:"schema_version"`
	ResultType          string                    `json:"result_type"`
	Status              string                    `json:"status"`
	ReleaseIdentity     string                    `json:"release_identity"`
	Lineage             ReleaseLineage            `json:"lineage"`
	Execution           ReleaseExecution          `json:"execution"`
	ImageTag            string                    `json:"image_tag,omitempty"`
	Manifest            ReleaseArtifact           `json:"manifest"`
	SBOM                ReleaseArtifact           `json:"sbom"`
	Provenance          ReleaseArtifact           `json:"provenance"`
	ArtifactAttestation SignetArtifactAttestation `json:"artifact_attestation"`
}

type PublishedRelease struct {
	Identity   string
	Event      *nostr.Event
	Manifest   RegistryReference
	SBOM       RegistryReference
	Provenance RegistryReference
	Replay     bool
}

type ReleasePublisher struct {
	store    store.ReleaseProvenanceStore
	registry OCIRegistry
	signer   Signer
	now      func() time.Time
}

func NewReleasePublisher(st store.ReleaseProvenanceStore, registry OCIRegistry, signer Signer) *ReleasePublisher {
	return &ReleasePublisher{store: st, registry: registry, signer: signer, now: time.Now}
}

// Publish validates a green completed run, uploads all objects by digest,
// signs a terminal kind-5402 RELEASE attestation, then atomically commits it.
// It never publishes to a relay; runtime wiring owns delivery of the returned
// event after this method succeeds.
func (p *ReleasePublisher) Publish(ctx context.Context, request ReleaseRequest) (PublishedRelease, error) {
	if p == nil || p.store == nil || p.registry == nil || p.signer == nil {
		return PublishedRelease{}, fmt.Errorf("%w: release publisher dependencies are unavailable", ErrIncompleteRelease)
	}
	if err := normalizeAndValidateReleaseRequest(&request); err != nil {
		return PublishedRelease{}, err
	}
	identity, err := releaseIdentity(request.Lineage)
	if err != nil {
		return PublishedRelease{}, err
	}
	provenanceBytes, err := buildReleaseProvenance(identity, request)
	if err != nil {
		return PublishedRelease{}, err
	}
	provenanceObject := RegistryObject{Kind: RegistryObjectBlob, Digest: DigestBytes(provenanceBytes),
		MediaType: InTotoJSONMediaType, Content: provenanceBytes}
	signerPub := strings.ToLower(strings.TrimSpace(p.signer.PublicKey()))
	if !releaseEventID(signerPub) {
		return PublishedRelease{}, fmt.Errorf("%w: signer returned invalid pubkey", ErrIncompleteRelease)
	}
	result := releaseResult(identity, signerPub, request, provenanceObject)
	content, err := json.Marshal(result)
	if err != nil {
		return PublishedRelease{}, fmt.Errorf("encode release attestation: %w", err)
	}
	contentDigest := DigestBytes(content)

	existing, err := p.store.GetReleaseProvenance(ctx, identity)
	switch {
	case err == nil && existing.ContentDigest == contentDigest:
		return publishedReleaseFromRecord(existing, true)
	case err == nil:
		// Persist the conflict atomically before any registry or signer side
		// effect. The canonical unsigned result is sufficient to diagnose it.
		conflictErr := p.store.QuarantineReleaseConflict(ctx, identity, contentDigest, string(content))
		if conflictErr == nil {
			return PublishedRelease{}, fmt.Errorf("release conflict unexpectedly committed")
		}
		return PublishedRelease{}, conflictErr
	case !errors.Is(err, sql.ErrNoRows):
		return PublishedRelease{}, fmt.Errorf("load release identity: %w", err)
	}

	manifestRef, err := p.registry.PushByDigest(ctx, request.RegistryRepository, request.Manifest)
	if err != nil {
		return PublishedRelease{}, fmt.Errorf("push immutable OCI manifest: %w", err)
	}
	if err := exactRegistryReference(manifestRef, request.RegistryRepository, request.Manifest); err != nil {
		return PublishedRelease{}, err
	}
	sbomRef, err := p.registry.PushByDigest(ctx, request.RegistryRepository, request.SBOM)
	if err != nil {
		return PublishedRelease{}, fmt.Errorf("push immutable SBOM: %w", err)
	}
	if err := exactRegistryReference(sbomRef, request.RegistryRepository, request.SBOM); err != nil {
		return PublishedRelease{}, err
	}
	provenanceRef, err := p.registry.PushByDigest(ctx, request.RegistryRepository, provenanceObject)
	if err != nil {
		return PublishedRelease{}, fmt.Errorf("push immutable provenance: %w", err)
	}
	if err := exactRegistryReference(provenanceRef, request.RegistryRepository, provenanceObject); err != nil {
		return PublishedRelease{}, err
	}

	event, eventJSON, err := p.signResult(ctx, request, result, content)
	if err != nil {
		return PublishedRelease{}, err
	}
	committed, err := p.store.CommitReleaseProvenance(ctx, releaseRecord(request, result,
		contentDigest, event, eventJSON, p.now().UTC()))
	if err != nil {
		return PublishedRelease{}, err
	}
	if committed.Replay {
		return publishedReleaseFromRecord(committed.Record, true)
	}
	return PublishedRelease{Identity: identity, Event: event,
		Manifest:   artifactRegistryReference(result.Manifest),
		SBOM:       artifactRegistryReference(result.SBOM),
		Provenance: artifactRegistryReference(result.Provenance)}, nil
}

func normalizeAndValidateReleaseRequest(request *ReleaseRequest) error {
	lineage := &request.Lineage
	for _, value := range []*string{
		&lineage.WorkflowRunEventID, &lineage.TriggerIdentity, &lineage.PREventID,
		&lineage.ReviewEventID, &lineage.AuditEventID, &lineage.Commit, &lineage.Tree,
		&lineage.WorkflowDigest, &request.Execution.WorkerIdentity,
	} {
		*value = strings.ToLower(strings.TrimSpace(*value))
	}
	for _, value := range []*string{
		&lineage.TriggerSource, &lineage.TriggerID, &lineage.RepoAddress,
		&lineage.SourceProvenanceRef, &request.Execution.WorkerCapability,
		&request.Execution.DurableLogReference, &request.RegistryRepository,
		&request.ImageRepository, &request.ImageTag,
	} {
		*value = strings.TrimSpace(*value)
	}
	var err error
	lineage.SourceRepoIdentity, err = store.SanitizeSourceRepoIdentity(lineage.SourceRepoIdentity)
	if err != nil {
		return fmt.Errorf("%w: source repository identity: %v", ErrIncompleteRelease, err)
	}
	if !releaseEventID(lineage.WorkflowRunEventID) || !releaseEventID(lineage.TriggerIdentity) ||
		!releaseEventID(lineage.PREventID) || !releaseEventID(lineage.ReviewEventID) ||
		!releaseEventID(lineage.AuditEventID) {
		return fmt.Errorf("%w: exact trigger, PR, review, audit, and workflow-run identities are required", ErrIncompleteRelease)
	}
	if lineage.TriggerSource == "" || lineage.TriggerID == "" || lineage.RepoAddress == "" ||
		strings.ContainsAny(lineage.TriggerSource+lineage.TriggerID+lineage.RepoAddress, "\x00\r\n\t") {
		return fmt.Errorf("%w: complete trigger and repository correlation is required", ErrIncompleteRelease)
	}
	ownerPub, repoID, repoOK := parseRepoAddr(lineage.RepoAddress)
	if !repoOK || !releaseEventID(strings.ToLower(ownerPub)) ||
		strings.ContainsAny(repoID, "\x00\r\n\t") {
		return fmt.Errorf("%w: canonical NIP-34 repository address is required", ErrIncompleteRelease)
	}
	if !validCommitSHA.MatchString(lineage.Commit) || !validCommitSHA.MatchString(lineage.Tree) ||
		!releaseEventID(lineage.WorkflowDigest) ||
		!strings.HasPrefix(lineage.SourceProvenanceRef, store.SourceProvenanceReferencePrefix) ||
		!releaseEventID(strings.TrimPrefix(lineage.SourceProvenanceRef, store.SourceProvenanceReferencePrefix)) {
		return fmt.Errorf("%w: complete commit, tree, workflow, and source-provenance evidence is required", ErrIncompleteRelease)
	}
	execution := &request.Execution
	execution.Status = strings.ToLower(strings.TrimSpace(execution.Status))
	execution.BahiaDuration = strings.TrimSpace(execution.BahiaDuration)
	if execution.BahiaDuration == "" {
		execution.BahiaDuration = strconv.FormatInt(execution.DurationMS, 10)
	}
	bahiaDuration, bahiaDurationErr := strconv.ParseInt(execution.BahiaDuration, 10, 64)
	execution.BuildEnvironmentImageDigest = strings.ToLower(strings.TrimSpace(execution.BuildEnvironmentImageDigest))
	execution.Tests.Status = strings.ToLower(strings.TrimSpace(execution.Tests.Status))
	if !execution.Complete || execution.Status != "success" || execution.ExitCode != 0 ||
		execution.DurationMS < 0 || bahiaDurationErr != nil || bahiaDuration < 0 || !releaseEventID(execution.WorkerIdentity) ||
		execution.WorkerCapability == "" || len(execution.WorkerCapability) > 512 ||
		!registryDigestRE.MatchString(execution.BuildEnvironmentImageDigest) ||
		!durableLogReference(execution.DurableLogReference) {
		return fmt.Errorf("%w: complete successful execution, worker, build image, and durable logs are required", ErrIncompleteRelease)
	}
	tests := execution.Tests
	if tests.Status != "success" || tests.Total <= 0 || tests.Passed <= 0 ||
		tests.Failed != 0 || tests.Skipped < 0 || tests.Passed+tests.Failed+tests.Skipped != tests.Total {
		return fmt.Errorf("%w: passing complete test summary is required", ErrIncompleteRelease)
	}
	request.Manifest.Kind = RegistryObjectManifest
	request.Manifest.Digest = strings.ToLower(strings.TrimSpace(request.Manifest.Digest))
	request.Manifest.MediaType = strings.TrimSpace(request.Manifest.MediaType)
	request.SBOM.Kind = RegistryObjectBlob
	request.SBOM.Digest = strings.ToLower(strings.TrimSpace(request.SBOM.Digest))
	request.SBOM.MediaType = strings.TrimSpace(request.SBOM.MediaType)
	if !validImageRepository(request.ImageRepository) {
		return fmt.Errorf("%w: pullable Harbor image repository is required", ErrIncompleteRelease)
	}
	if request.ImageTag != "" && !registryTagRE.MatchString(request.ImageTag) {
		return fmt.Errorf("%w: valid OCI image tag alias is required", ErrIncompleteRelease)
	}
	if err := validateRegistryObject(request.RegistryRepository, request.Manifest); err != nil {
		return fmt.Errorf("%w: manifest: %v", ErrIncompleteRelease, err)
	}
	if request.Manifest.MediaType != OCIImageManifestV1 || !validOCIManifest(request.Manifest.Content) {
		return fmt.Errorf("%w: an OCI image manifest with immutable config and layer digests is required", ErrIncompleteRelease)
	}
	if err := validateRegistryObject(request.RegistryRepository, request.SBOM); err != nil {
		return fmt.Errorf("%w: SBOM: %v", ErrIncompleteRelease, err)
	}
	if request.SBOM.MediaType != CycloneDXJSONMediaType && request.SBOM.MediaType != SPDXJSONMediaType {
		return fmt.Errorf("%w: supported JSON SBOM media type is required", ErrIncompleteRelease)
	}
	if !validSBOM(request.SBOM.Content, request.SBOM.MediaType) {
		return fmt.Errorf("%w: structurally identified JSON SBOM content is required", ErrIncompleteRelease)
	}
	return nil
}

func releaseIdentity(lineage ReleaseLineage) (string, error) {
	stable := struct {
		Schema  string         `json:"schema"`
		Lineage ReleaseLineage `json:"lineage"`
	}{Schema: store.ReleaseProvenanceSchemaV1, Lineage: lineage}
	encoded, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return store.ReleaseIdentityPrefix + hex.EncodeToString(sum[:]), nil
}

type releaseProvenanceStatement struct {
	Type          string                     `json:"_type"`
	Subject       []releaseProvenanceSubject `json:"subject"`
	PredicateType string                     `json:"predicateType"`
	Predicate     releaseProvenancePredicate `json:"predicate"`
}
type releaseProvenanceSubject struct {
	Name   string                  `json:"name"`
	Digest releaseProvenanceDigest `json:"digest"`
}
type releaseProvenanceDigest struct {
	SHA256 string `json:"sha256"`
}
type releaseProvenancePredicate struct {
	ReleaseIdentity string           `json:"release_identity"`
	Lineage         ReleaseLineage   `json:"lineage"`
	Execution       ReleaseExecution `json:"execution"`
	SBOMDigest      string           `json:"sbom_digest"`
}

func buildReleaseProvenance(identity string, request ReleaseRequest) ([]byte, error) {
	statement := releaseProvenanceStatement{
		Type: "https://in-toto.io/Statement/v1", PredicateType: releasePredicateType,
		Subject: []releaseProvenanceSubject{{Name: request.ImageRepository,
			Digest: releaseProvenanceDigest{SHA256: strings.TrimPrefix(request.Manifest.Digest, "sha256:")}}},
		Predicate: releaseProvenancePredicate{ReleaseIdentity: identity, Lineage: request.Lineage,
			Execution: request.Execution, SBOMDigest: request.SBOM.Digest},
	}
	return json.Marshal(statement)
}

func releaseResult(identity, signerPub string, request ReleaseRequest, provenance RegistryObject) ReleaseResult {
	artifact := func(object RegistryObject) ReleaseArtifact {
		return ReleaseArtifact{Repository: request.ImageRepository, Digest: object.Digest,
			MediaType: object.MediaType, Size: int64(len(object.Content))}
	}
	manifest, sbom, prov := artifact(request.Manifest), artifact(request.SBOM), artifact(provenance)
	return ReleaseResult{SchemaVersion: store.ReleaseProvenanceSchemaV1, ResultType: ReleaseResultType,
		Status: "success", ReleaseIdentity: identity, Lineage: request.Lineage, Execution: request.Execution,
		ImageTag: request.ImageTag,
		Manifest: manifest, SBOM: sbom, Provenance: prov,
		ArtifactAttestation: SignetArtifactAttestation{Type: releaseAttestationType,
			SignerPubkey: signerPub, Subjects: []ReleaseArtifact{manifest, sbom, prov}}}
}

func (p *ReleasePublisher) signResult(ctx context.Context, request ReleaseRequest, result ReleaseResult, content []byte) (*nostr.Event, string, error) {
	pubkey, err := nostr.PubKeyFromHex(strings.TrimSpace(result.ArtifactAttestation.SignerPubkey))
	if err != nil {
		return nil, "", fmt.Errorf("invalid release signer pubkey: %w", err)
	}
	now := p.now().UTC()
	event := &nostr.Event{PubKey: pubkey, CreatedAt: nostr.Timestamp(now.Unix()),
		Kind: relay.KindHiveWorkflowResult, Content: string(content),
		Tags: nostr.Tags{
			{"e", request.Lineage.WorkflowRunEventID}, {"status", "success"}, {"result", ReleaseResultType},
			{"release", result.ReleaseIdentity}, {"trigger-envelope", request.Lineage.TriggerIdentity},
			{"trigger-source", request.Lineage.TriggerSource}, {"trigger-id", request.Lineage.TriggerID},
			{"pr", request.Lineage.PREventID}, {"review", request.Lineage.ReviewEventID},
			{"audit", request.Lineage.AuditEventID}, {"a", request.Lineage.RepoAddress},
			{"source-repo", request.Lineage.SourceRepoIdentity},
			{"source-provenance", request.Lineage.SourceProvenanceRef},
			{"commit", request.Lineage.Commit}, {"tree", request.Lineage.Tree},
			{"workflow-digest", request.Lineage.WorkflowDigest},
			{"worker", request.Execution.WorkerIdentity},
			{"worker-capability", request.Execution.WorkerCapability},
			{"build-image", request.Execution.BuildEnvironmentImageDigest},
			{"exit_code", "0"}, {"duration", request.Execution.BahiaDuration},
			{"log_url", request.Execution.DurableLogReference},
			{"image_repo", request.ImageRepository}, {"image_digest", request.Manifest.Digest},
			{"sbom_digest", request.SBOM.Digest}, {"provenance_digest", result.Provenance.Digest},
		}}
	if request.ImageTag != "" {
		event.Tags = append(event.Tags, nostr.Tag{"image_tag", request.ImageTag})
	}
	event.ID = nostr.ID{}
	event.Sig = [64]byte{}
	if err := p.signer.SignEvent(ctx, event); err != nil {
		return nil, "", fmt.Errorf("sign release artifact attestation: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(event); err != nil {
		return nil, "", fmt.Errorf("release signer returned invalid artifact attestation: %w", err)
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, "", err
	}
	return event, string(eventJSON), nil
}

func releaseRecord(request ReleaseRequest, result ReleaseResult, contentDigest string,
	event *nostr.Event, eventJSON string, createdAt time.Time) store.ReleaseProvenanceRecord {
	return store.ReleaseProvenanceRecord{ReleaseIdentity: result.ReleaseIdentity,
		SchemaVersion: store.ReleaseProvenanceSchemaV1, ContentDigest: contentDigest,
		RegistryRepository: request.ImageRepository, ManifestDigest: request.Manifest.Digest,
		SBOMDigest: request.SBOM.Digest, ProvenanceDigest: result.Provenance.Digest,
		SignedEventID: event.ID.Hex(), SignedEventJSON: eventJSON, CreatedAt: createdAt}
}

func publishedReleaseFromRecord(record store.ReleaseProvenanceRecord, replay bool) (PublishedRelease, error) {
	var event nostr.Event
	if err := json.Unmarshal([]byte(record.SignedEventJSON), &event); err != nil ||
		event.ID.Hex() != record.SignedEventID || event.Kind != relay.KindHiveWorkflowResult ||
		nostrverify.ValidateEventIDAndSignature(&event) != nil {
		return PublishedRelease{}, fmt.Errorf("stored release event failed signature validation")
	}
	var result ReleaseResult
	if err := json.Unmarshal([]byte(event.Content), &result); err != nil ||
		result.SchemaVersion != store.ReleaseProvenanceSchemaV1 ||
		result.ResultType != ReleaseResultType || result.Status != "success" ||
		result.ReleaseIdentity != record.ReleaseIdentity ||
		DigestBytes([]byte(event.Content)) != record.ContentDigest ||
		result.Manifest.Digest != record.ManifestDigest || result.SBOM.Digest != record.SBOMDigest ||
		result.Provenance.Digest != record.ProvenanceDigest {
		return PublishedRelease{}, fmt.Errorf("stored release event does not match durable artifact record")
	}
	if result.ArtifactAttestation.SignerPubkey != event.PubKey.Hex() ||
		result.ArtifactAttestation.Type != releaseAttestationType ||
		len(result.ArtifactAttestation.Subjects) != 3 ||
		result.ArtifactAttestation.Subjects[0] != result.Manifest ||
		result.ArtifactAttestation.Subjects[1] != result.SBOM ||
		result.ArtifactAttestation.Subjects[2] != result.Provenance ||
		result.Manifest.Repository != record.RegistryRepository ||
		result.SBOM.Repository != record.RegistryRepository ||
		result.Provenance.Repository != record.RegistryRepository {
		return PublishedRelease{}, fmt.Errorf("stored release signer or repository binding is invalid")
	}
	if tagValue(event.Tags, "status") != "success" ||
		tagValue(event.Tags, "result") != ReleaseResultType ||
		tagValue(event.Tags, "release") != record.ReleaseIdentity ||
		tagValue(event.Tags, "e") != result.Lineage.WorkflowRunEventID ||
		tagValue(event.Tags, "image_repo") != result.Manifest.Repository ||
		tagValue(event.Tags, "image_digest") != result.Manifest.Digest ||
		tagValue(event.Tags, "sbom_digest") != result.SBOM.Digest ||
		tagValue(event.Tags, "provenance_digest") != result.Provenance.Digest {
		return PublishedRelease{}, fmt.Errorf("stored release tags do not match signed release content")
	}
	toRef := func(artifact ReleaseArtifact) RegistryReference {
		return RegistryReference{Repository: artifact.Repository, Digest: artifact.Digest,
			MediaType: artifact.MediaType, Size: artifact.Size}
	}
	return PublishedRelease{Identity: record.ReleaseIdentity, Event: &event, Replay: replay,
		Manifest: toRef(result.Manifest), SBOM: toRef(result.SBOM), Provenance: toRef(result.Provenance)}, nil
}

func artifactRegistryReference(artifact ReleaseArtifact) RegistryReference {
	return RegistryReference{Repository: artifact.Repository, Digest: artifact.Digest,
		MediaType: artifact.MediaType, Size: artifact.Size}
}

func validImageRepository(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "://") || strings.ContainsAny(raw, "@?#\x00\r\n\t") {
		return false
	}
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Host != strings.ToLower(u.Host) {
		return false
	}
	repository := strings.TrimPrefix(u.EscapedPath(), "/")
	return repository != "" && !strings.Contains(repository, "%") && registryRepoRE.MatchString(repository)
}

func exactRegistryReference(ref RegistryReference, repository string, object RegistryObject) error {
	if ref.Repository != repository || ref.Digest != object.Digest || ref.MediaType != object.MediaType ||
		ref.Size != int64(len(object.Content)) {
		return fmt.Errorf("%w: registry did not preserve exact immutable object identity", ErrRegistryConflict)
	}
	return nil
}

func releaseEventID(value string) bool {
	return len(value) == 64 && releaseHex(value)
}

func releaseHex(value string) bool {
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func durableLogReference(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "oci":
		return u.Host != "" && strings.Contains(u.Path, "@sha256:") &&
			registryDigestRE.MatchString(u.Path[strings.LastIndex(u.Path, "@")+1:])
	case "cas":
		return u.Host == "sha256" && releaseEventID(strings.TrimPrefix(u.Path, "/"))
	case "https":
		if u.Host == "" {
			return false
		}
		at := strings.LastIndex(u.Path, "@")
		if at >= 0 && registryDigestRE.MatchString(u.Path[at+1:]) {
			return true
		}
		// Canonical Blossom log URLs bind content with a lowercase SHA-256
		// digest as their final path segment.
		last := strings.TrimPrefix(path.Base(u.EscapedPath()), "/")
		return releaseEventID(last)
	default:
		return false
	}
}

func validOCIManifest(content []byte) bool {
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if json.Unmarshal(content, &manifest) != nil || manifest.SchemaVersion != 2 ||
		(manifest.MediaType != "" && manifest.MediaType != OCIImageManifestV1) ||
		!registryDigestRE.MatchString(strings.ToLower(manifest.Config.Digest)) {
		return false
	}
	for _, layer := range manifest.Layers {
		if !registryDigestRE.MatchString(strings.ToLower(layer.Digest)) {
			return false
		}
	}
	return true
}

func validSBOM(content []byte, mediaType string) bool {
	var document map[string]any
	if json.Unmarshal(content, &document) != nil {
		return false
	}
	stringField := func(key string) string {
		value, _ := document[key].(string)
		return strings.TrimSpace(value)
	}
	switch mediaType {
	case CycloneDXJSONMediaType:
		return stringField("bomFormat") == "CycloneDX" && stringField("specVersion") != ""
	case SPDXJSONMediaType:
		return strings.HasPrefix(stringField("spdxVersion"), "SPDX-") && stringField("SPDXID") != ""
	default:
		return false
	}
}

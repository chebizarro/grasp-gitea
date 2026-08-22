// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// ReleaseLineageVerifier revalidates the durable signed 5401, accepted trigger,
// review policy, Git objects, and source-provenance record at release time.
type ReleaseLineageVerifier interface {
	RevalidateDispatch(context.Context, store.LoomJob) error
}

// SetReleasePublisher enables the opt-in terminal release gate for remote Loom
// results. Disabled/default runners retain the existing check-only behavior.
func (r *Runner) SetReleasePublisher(publisher *ReleasePublisher, repository, imageRepository string) {
	if r == nil {
		return
	}
	r.releasePublisher = publisher
	r.releaseRepository = strings.TrimSpace(repository)
	r.releaseImageRepository = strings.TrimSpace(imageRepository)
}

// ReleaseEnabled reports whether successful remote results must cross the
// immutable artifact and Signet attestation boundary.
func (r *Runner) ReleaseEnabled() bool {
	return r != nil && r.releasePublisher != nil && r.releaseRepository != "" &&
		r.releaseImageRepository != "" && r.publish != nil && r.releaseLineageVerifier != nil
}

// SetReleaseLineageVerifier replaces release-time dispatch revalidation. It is
// intended for hermetic tests and controlled embeddings; nil fails closed.
func (r *Runner) SetReleaseLineageVerifier(verifier ReleaseLineageVerifier) {
	if r != nil {
		r.releaseLineageVerifier = verifier
	}
}

// FinalizeRelease converts one validated delegated-publisher result into the
// bridge/Signet-signed RELEASE result. It revalidates the persisted dispatch
// immediately before any registry, signer, or relay side effect.
func (r *Runner) FinalizeRelease(ctx context.Context, job store.LoomJob, result *nostr.Event) error {
	if !r.ReleaseEnabled() {
		return fmt.Errorf("%w: release publication is disabled", ErrIncompleteRelease)
	}
	if result == nil || result.Kind != relay.KindHiveWorkflowResult ||
		result.ID.Hex() == "" || nostrverify.ValidateEventIDAndSignature(result) != nil {
		return fmt.Errorf("%w: signed terminal workflow result is required", ErrIncompleteRelease)
	}
	if result.PubKey.Hex() != job.PublisherPub || tagValue(result.Tags, "e") != job.WorkflowRunID {
		return fmt.Errorf("%w: terminal result does not match its delegated dispatch", ErrIncompleteRelease)
	}
	if err := r.releaseLineageVerifier.RevalidateDispatch(ctx, job); err != nil {
		return fmt.Errorf("%w: terminal release lineage no longer authorizes dispatch: %v", ErrIncompleteRelease, err)
	}
	request, err := r.releaseRequestFromLoom(job, result)
	if err != nil {
		return err
	}
	published, err := r.releasePublisher.Publish(ctx, request)
	if err != nil {
		return err
	}
	if err := r.publish(ctx, published.Event); err != nil {
		return fmt.Errorf("publish signed HiveCI RELEASE result: %w", err)
	}
	return nil
}

type loomReleasePayload struct {
	Status                      string             `json:"status"`
	Complete                    *bool              `json:"complete"`
	ExitCode                    *int               `json:"exit_code"`
	DurationMS                  *int64             `json:"duration_ms"`
	Duration                    *int64             `json:"duration"`
	BuildEnvironmentImageDigest string             `json:"build_environment_image_digest"`
	WorkerIdentity              string             `json:"worker_identity"`
	WorkerCapability            string             `json:"worker_capability"`
	Tests                       ReleaseTestSummary `json:"tests"`
	TestSummary                 ReleaseTestSummary `json:"test_summary"`
	ImageRepo                   string             `json:"image_repo"`
	ImageTag                    string             `json:"image_tag"`
	ImageDigest                 string             `json:"image_digest"`
	ManifestDigest              string             `json:"manifest_digest"`
	ManifestMediaType           string             `json:"manifest_media_type"`
	OCIManifestBase64           string             `json:"oci_manifest_b64"`
	OCIManifest                 json.RawMessage    `json:"oci_manifest"`
	Manifest                    json.RawMessage    `json:"manifest"`
	SBOMDigest                  string             `json:"sbom_digest"`
	SBOMMediaType               string             `json:"sbom_media_type"`
	SBOMBase64                  string             `json:"sbom_b64"`
	SBOM                        json.RawMessage    `json:"sbom"`
	LogURL                      string             `json:"log_url"`
}

func (r *Runner) releaseRequestFromLoom(job store.LoomJob, result *nostr.Event) (ReleaseRequest, error) {
	var run nostr.Event
	if err := json.Unmarshal([]byte(job.WorkflowRunEvent), &run); err != nil ||
		run.Kind != relay.KindHiveWorkflowRun || run.ID.Hex() != job.WorkflowRunID ||
		nostrverify.ValidateEventIDAndSignature(&run) != nil {
		return ReleaseRequest{}, fmt.Errorf("%w: persisted signed workflow run is invalid", ErrIncompleteRelease)
	}
	if tagValue(run.Tags, "publisher") != job.PublisherPub ||
		tagValue(run.Tags, "worker-ad") != job.WorkerAdID {
		return ReleaseRequest{}, fmt.Errorf("%w: persisted publisher or worker advertisement changed", ErrIncompleteRelease)
	}
	var payload loomReleasePayload
	if strings.TrimSpace(result.Content) == "" || json.Unmarshal([]byte(result.Content), &payload) != nil {
		return ReleaseRequest{}, fmt.Errorf("%w: structured terminal release payload is required", ErrIncompleteRelease)
	}
	status, consistent := consistentReleaseValue(true, tagValue(result.Tags, "status"), payload.Status)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: terminal workflow status evidence conflicts", ErrIncompleteRelease)
	}
	if status != "success" {
		return ReleaseRequest{}, fmt.Errorf("%w: terminal workflow is not successful", ErrIncompleteRelease)
	}
	complete, ok := explicitBool(result.Tags, "complete", payload.Complete)
	if !ok || !complete {
		return ReleaseRequest{}, fmt.Errorf("%w: terminal workflow did not attest completion", ErrIncompleteRelease)
	}
	exitCode, ok := explicitInt(result.Tags, "exit_code", payload.ExitCode)
	if !ok || exitCode != 0 {
		return ReleaseRequest{}, fmt.Errorf("%w: terminal workflow exit code is not successful", ErrIncompleteRelease)
	}
	durationMS, bahiaDuration, ok := explicitDurationMS(result.Tags, payload)
	if !ok {
		return ReleaseRequest{}, fmt.Errorf("%w: terminal workflow duration is required", ErrIncompleteRelease)
	}
	tests := payload.Tests
	if tests.Status != "" && payload.TestSummary.Status != "" && tests != payload.TestSummary {
		return ReleaseRequest{}, fmt.Errorf("%w: test summary evidence conflicts", ErrIncompleteRelease)
	}
	if tests.Status == "" {
		tests = payload.TestSummary
	}
	if !applyTestTags(&tests, result.Tags) {
		return ReleaseRequest{}, fmt.Errorf("%w: test summary tags are malformed or conflicting", ErrIncompleteRelease)
	}

	workerCapability := tagValue(run.Tags, "worker-capability")
	reportedCapability, consistent := consistentReleaseValue(false,
		tagValue(result.Tags, "worker-capability"), tagValue(result.Tags, "worker_capability"), payload.WorkerCapability)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: worker capability evidence conflicts", ErrIncompleteRelease)
	}
	if reported := reportedCapability; reported != "" &&
		reported != workerCapability {
		return ReleaseRequest{}, fmt.Errorf("%w: worker capability changed after dispatch", ErrIncompleteRelease)
	}
	reportedWorker, consistent := consistentReleaseValue(true, tagValue(result.Tags, "worker"), payload.WorkerIdentity)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: worker identity evidence conflicts", ErrIncompleteRelease)
	}
	if reported := reportedWorker; reported != "" &&
		reported != job.WorkerPub {
		return ReleaseRequest{}, fmt.Errorf("%w: worker identity changed after dispatch", ErrIncompleteRelease)
	}
	if tagValue(run.Tags, "worker") != job.WorkerPub || workerCapability == "" {
		return ReleaseRequest{}, fmt.Errorf("%w: exact selected worker evidence is unavailable", ErrIncompleteRelease)
	}

	repository, consistent := consistentReleaseValue(false, tagValue(result.Tags, "image_repo"), payload.ImageRepo)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: image repository evidence conflicts", ErrIncompleteRelease)
	}
	if repository != r.releaseImageRepository {
		return ReleaseRequest{}, fmt.Errorf("%w: result registry repository is not the configured sovereign target", ErrIncompleteRelease)
	}
	imageTag, consistent := consistentReleaseValue(false, tagValue(result.Tags, "image_tag"), payload.ImageTag)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: image tag evidence conflicts", ErrIncompleteRelease)
	}
	manifestDigest, consistent := consistentReleaseValue(true,
		tagValue(result.Tags, "image_digest"), tagValue(result.Tags, "manifest_digest"),
		payload.ImageDigest, payload.ManifestDigest)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: OCI manifest digest evidence conflicts", ErrIncompleteRelease)
	}
	manifest, err := inlineReleaseObject(payload.OCIManifestBase64, payload.OCIManifest)
	if err != nil {
		return ReleaseRequest{}, fmt.Errorf("%w: OCI manifest bytes are malformed", ErrIncompleteRelease)
	}
	if len(manifest) == 0 {
		manifest = append([]byte(nil), payload.Manifest...)
	}
	sbom, err := inlineReleaseObject(payload.SBOMBase64, payload.SBOM)
	if err != nil {
		return ReleaseRequest{}, fmt.Errorf("%w: SBOM bytes are malformed", ErrIncompleteRelease)
	}
	sbomDigest, consistent := consistentReleaseValue(true, tagValue(result.Tags, "sbom_digest"), payload.SBOMDigest)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: SBOM digest evidence conflicts", ErrIncompleteRelease)
	}
	sbomMediaType, consistent := consistentReleaseValue(false, tagValue(result.Tags, "sbom_media_type"), payload.SBOMMediaType)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: SBOM media type evidence conflicts", ErrIncompleteRelease)
	}
	if sbomMediaType == "" {
		sbomMediaType = CycloneDXJSONMediaType
	}
	buildImage, consistent := consistentReleaseValue(true,
		tagValue(result.Tags, "build_image_digest"), tagValue(result.Tags, "build-image"),
		payload.BuildEnvironmentImageDigest)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: build image digest evidence conflicts", ErrIncompleteRelease)
	}
	logReference, consistent := consistentReleaseValue(false, tagValue(result.Tags, "log_url"), payload.LogURL)
	if !consistent {
		return ReleaseRequest{}, fmt.Errorf("%w: durable log evidence conflicts", ErrIncompleteRelease)
	}

	return ReleaseRequest{
		Lineage: ReleaseLineage{
			WorkflowRunEventID:  job.WorkflowRunID,
			TriggerIdentity:     firstNonEmpty(tagValue(run.Tags, "trigger-envelope"), tagValue(run.Tags, "idempotency")),
			TriggerSource:       tagValue(run.Tags, "trigger-source"),
			TriggerID:           tagValue(run.Tags, "trigger-id"),
			PREventID:           firstNonEmpty(tagValue(run.Tags, "pr-event"), tagValue(run.Tags, "pr")),
			ReviewEventID:       tagValue(run.Tags, "review"),
			AuditEventID:        tagValue(run.Tags, "audit"),
			RepoAddress:         firstNonEmpty(tagValue(run.Tags, "repo-address"), tagValue(run.Tags, "a")),
			SourceRepoIdentity:  tagValue(run.Tags, "source-repo"),
			SourceProvenanceRef: tagValue(run.Tags, "source-provenance"),
			Commit:              tagValue(run.Tags, "commit"),
			Tree:                tagValue(run.Tags, "tree"),
			WorkflowDigest:      tagValue(run.Tags, "workflow-digest"),
		},
		Execution: ReleaseExecution{
			Complete: true, Status: "success", ExitCode: exitCode, DurationMS: durationMS,
			BahiaDuration: bahiaDuration, WorkerIdentity: job.WorkerPub, WorkerCapability: workerCapability,
			BuildEnvironmentImageDigest: buildImage, Tests: tests,
			DurableLogReference: logReference,
		},
		RegistryRepository: r.releaseRepository,
		ImageRepository:    repository,
		ImageTag:           imageTag,
		Manifest: RegistryObject{
			Digest: manifestDigest, MediaType: firstNonEmpty(payload.ManifestMediaType, OCIImageManifestV1),
			Content: append([]byte(nil), manifest...),
		},
		SBOM: RegistryObject{
			Digest: sbomDigest, MediaType: sbomMediaType,
			Content: sbom,
		},
	}, nil
}

func inlineReleaseObject(encoded string, raw json.RawMessage) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded != "" {
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		if len(raw) != 0 && string(raw) != "null" && !bytes.Equal(content, raw) {
			return nil, fmt.Errorf("base64 and JSON object representations conflict")
		}
		return content, nil
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	return append([]byte(nil), raw...), nil
}

func explicitBool(tags nostr.Tags, key string, fallback *bool) (bool, bool) {
	if raw := tagValue(tags, key); raw != "" {
		value, err := strconv.ParseBool(raw)
		return value, err == nil && (fallback == nil || value == *fallback)
	}
	if fallback == nil {
		return false, false
	}
	return *fallback, true
}

func explicitInt(tags nostr.Tags, key string, fallback *int) (int, bool) {
	if raw := tagValue(tags, key); raw != "" {
		value, err := strconv.Atoi(raw)
		return value, err == nil && (fallback == nil || value == *fallback)
	}
	if fallback == nil {
		return 0, false
	}
	return *fallback, true
}

func explicitDurationMS(tags nostr.Tags, payload loomReleasePayload) (int64, string, bool) {
	var milliseconds *int64
	if raw := tagValue(tags, "duration_ms"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return 0, "", false
		}
		milliseconds = &value
	}
	if payload.DurationMS != nil {
		if *payload.DurationMS < 0 || (milliseconds != nil && *milliseconds != *payload.DurationMS) {
			return 0, "", false
		}
		value := *payload.DurationMS
		milliseconds = &value
	}

	var seconds *int64
	if raw := tagValue(tags, "duration"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return 0, "", false
		}
		seconds = &value
	}
	if payload.Duration != nil {
		if *payload.Duration < 0 || (seconds != nil && *seconds != *payload.Duration) {
			return 0, "", false
		}
		value := *payload.Duration
		seconds = &value
	}
	if milliseconds != nil {
		compatibleSeconds := *milliseconds / 1000
		if seconds != nil && *seconds != compatibleSeconds {
			return 0, "", false
		}
		return *milliseconds, strconv.FormatInt(compatibleSeconds, 10), true
	}
	if seconds == nil || *seconds > int64(^uint64(0)>>1)/1000 {
		return 0, "", false
	}
	return *seconds * 1000, strconv.FormatInt(*seconds, 10), true
}

func applyTestTags(summary *ReleaseTestSummary, tags nostr.Tags) bool {
	if status := tagValue(tags, "test_status"); status != "" {
		if summary.Status != "" && !strings.EqualFold(strings.TrimSpace(summary.Status), strings.TrimSpace(status)) {
			return false
		}
		summary.Status = status
	}
	for key, target := range map[string]*int{
		"test_total": &summary.Total, "test_passed": &summary.Passed,
		"test_failed": &summary.Failed, "test_skipped": &summary.Skipped,
	} {
		if raw := tagValue(tags, key); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || (*target != 0 && *target != value) {
				return false
			}
			*target = value
		}
	}
	return true
}

func consistentReleaseValue(lower bool, values ...string) (string, bool) {
	canonical := ""
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if canonical != "" && canonical != value {
			return "", false
		}
		canonical = value
	}
	return canonical, true
}

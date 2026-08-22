// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	// SourceProvenanceSchemaV1 identifies the immutable evidence layout. A new
	// schema version must use a new reference domain rather than reinterpret a
	// record already consumed by CI, Bahia, or a validator.
	SourceProvenanceSchemaV1 = "hiveci.source-provenance.v1"
	// SourceProvenanceReferencePrefix makes the persisted evidence address
	// self-describing when passed between otherwise decoupled consumers.
	SourceProvenanceReferencePrefix = "hiveci-source-provenance:v1:"
)

var (
	ErrSourceProvenanceConflict = errors.New("source provenance conflict")
	hexObjectID                 = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	hexSHA256                   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SourceProvenanceEvidence is the durable, successful result of independently
// resolving accepted source. RepoIdentity is credential-free and immutable;
// no branch, tag, transport credential, or local mirror path is retained.
//
// SourceCommit/SourceTree identify the reviewed head. AcceptedCommit and
// AcceptedTree identify the exact build input. Canonical and mirror fields
// independently bind the accepted result in those repositories and therefore
// must equal the accepted identity before the record can be stored.
type SourceProvenanceEvidence struct {
	EvidenceRef             string
	SchemaVersion           string
	RepoIdentity            string
	ReviewBaseCommit        string
	SourceCommit            string
	SourceTree              string
	AcceptedCommit          string
	AcceptedTree            string
	CanonicalCommit         string
	CanonicalTree           string
	MirrorCommit            string
	MirrorTree              string
	SignedReviewPatchSHA256 string
	SourceDiffSHA256        string
	MergeResultDiffSHA256   string
	VerifiedAt              time.Time
}

// SourceProvenanceStore is the persistence contract used by source resolvers
// and downstream evidence consumers.
type SourceProvenanceStore interface {
	SaveSourceProvenanceEvidence(context.Context, SourceProvenanceEvidence) error
	GetSourceProvenanceEvidence(context.Context, string) (SourceProvenanceEvidence, error)
}

var _ SourceProvenanceStore = (*SQLiteStore)(nil)

// SourceProvenanceConflictError is terminal: a stable evidence reference can
// never be rebound to different verification results.
type SourceProvenanceConflictError struct {
	EvidenceRef string
}

func (e *SourceProvenanceConflictError) Error() string {
	return fmt.Sprintf("%s: %s", ErrSourceProvenanceConflict, e.EvidenceRef)
}

func (e *SourceProvenanceConflictError) Unwrap() error      { return ErrSourceProvenanceConflict }
func (e *SourceProvenanceConflictError) NonRetryable() bool { return true }

// SanitizeSourceRepoIdentity returns the credential-free canonical form used
// in the stable evidence reference. Absolute repository URLs may not contain
// userinfo, query parameters, or fragments. Non-URL identities (including
// NIP-34 repository coordinates) may not contain URL/scp credential syntax.
func SanitizeSourceRepoIdentity(raw string) (string, error) {
	identity := strings.TrimSpace(raw)
	if identity == "" || strings.ContainsAny(identity, "\x00\r\n\t") {
		return "", fmt.Errorf("valid immutable repository identity is required")
	}
	if strings.HasPrefix(identity, "refs/heads/") || strings.HasPrefix(identity, "refs/tags/") {
		return "", fmt.Errorf("mutable repository ref is not an immutable repository identity")
	}
	if !strings.Contains(identity, "://") {
		if strings.ContainsAny(identity, "@?#\\") {
			return "", fmt.Errorf("repository identity contains credential or mutable URL syntax")
		}
		return identity, nil
	}

	u, err := url.Parse(identity)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.Path == "" {
		return "", fmt.Errorf("valid absolute repository URL is required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("repository URL must not contain credentials, query parameters, or fragments")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(path.Clean(u.Path), "/")
	if u.Path == "." || u.Path == "/" {
		return "", fmt.Errorf("repository URL path is required")
	}
	return u.String(), nil
}

// SourceProvenanceReference derives the stable, domain-separated evidence
// address. Its inputs alone are sufficient to identify the immutable build
// input; verification digests remain immutable contents at that address.
func SourceProvenanceReference(repoIdentity, acceptedCommit, acceptedTree string) (string, error) {
	repoIdentity, err := SanitizeSourceRepoIdentity(repoIdentity)
	if err != nil {
		return "", err
	}
	acceptedCommit = strings.ToLower(strings.TrimSpace(acceptedCommit))
	acceptedTree = strings.ToLower(strings.TrimSpace(acceptedTree))
	if !hexObjectID.MatchString(acceptedCommit) || !hexObjectID.MatchString(acceptedTree) {
		return "", fmt.Errorf("exact accepted commit and tree object IDs are required")
	}
	sum := sha256.Sum256([]byte(SourceProvenanceSchemaV1 + "\x00" + repoIdentity + "\x00" + acceptedCommit + "\x00" + acceptedTree))
	return SourceProvenanceReferencePrefix + hex.EncodeToString(sum[:]), nil
}

func (s *SQLiteStore) EnsureSourceProvenanceTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS hiveci_source_provenance (
			evidence_ref TEXT PRIMARY KEY,
			schema_version TEXT NOT NULL,
			repo_identity TEXT NOT NULL,
			review_base_commit TEXT NOT NULL,
			source_commit TEXT NOT NULL,
			source_tree TEXT NOT NULL,
			accepted_commit TEXT NOT NULL,
			accepted_tree TEXT NOT NULL,
			canonical_commit TEXT NOT NULL,
			canonical_tree TEXT NOT NULL,
			mirror_commit TEXT NOT NULL,
			mirror_tree TEXT NOT NULL,
			signed_review_patch_sha256 TEXT NOT NULL,
			source_diff_sha256 TEXT NOT NULL,
			merge_result_diff_sha256 TEXT NOT NULL,
			verified_at INTEGER NOT NULL,
			UNIQUE(repo_identity, accepted_commit, accepted_tree)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hiveci_source_provenance_source
			ON hiveci_source_provenance(repo_identity, source_commit, source_tree)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize HiveCI source-provenance persistence: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) SaveSourceProvenanceEvidence(ctx context.Context, evidence SourceProvenanceEvidence) error {
	if err := normalizeSourceProvenanceEvidence(&evidence); err != nil {
		return err
	}
	if evidence.VerifiedAt.IsZero() {
		evidence.VerifiedAt = time.Now().UTC()
	}
	if err := validateSourceProvenanceEvidence(evidence); err != nil {
		return err
	}
	if err := s.EnsureSourceProvenanceTables(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hiveci_source_provenance(
		evidence_ref, schema_version, repo_identity, review_base_commit, source_commit,
		source_tree, accepted_commit, accepted_tree, canonical_commit, canonical_tree,
		mirror_commit, mirror_tree, signed_review_patch_sha256, source_diff_sha256,
		merge_result_diff_sha256, verified_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, evidence.EvidenceRef,
		evidence.SchemaVersion, evidence.RepoIdentity, evidence.ReviewBaseCommit,
		evidence.SourceCommit, evidence.SourceTree, evidence.AcceptedCommit, evidence.AcceptedTree,
		evidence.CanonicalCommit, evidence.CanonicalTree, evidence.MirrorCommit, evidence.MirrorTree,
		evidence.SignedReviewPatchSHA256, evidence.SourceDiffSHA256,
		evidence.MergeResultDiffSHA256, evidence.VerifiedAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("save source provenance evidence: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 0 {
		return nil
	}
	existing, err := s.GetSourceProvenanceEvidence(ctx, evidence.EvidenceRef)
	if err != nil {
		return err
	}
	if !sameSourceProvenanceEvidence(existing, evidence) {
		return &SourceProvenanceConflictError{EvidenceRef: evidence.EvidenceRef}
	}
	return nil
}

func (s *SQLiteStore) GetSourceProvenanceEvidence(ctx context.Context, evidenceRef string) (SourceProvenanceEvidence, error) {
	evidenceRef = strings.TrimSpace(evidenceRef)
	if !validSourceProvenanceReference(evidenceRef) {
		return SourceProvenanceEvidence{}, fmt.Errorf("valid source provenance reference is required")
	}
	if err := s.EnsureSourceProvenanceTables(ctx); err != nil {
		return SourceProvenanceEvidence{}, err
	}
	var evidence SourceProvenanceEvidence
	var verifiedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT evidence_ref, schema_version, repo_identity,
		review_base_commit, source_commit, source_tree, accepted_commit, accepted_tree,
		canonical_commit, canonical_tree, mirror_commit, mirror_tree,
		signed_review_patch_sha256, source_diff_sha256, merge_result_diff_sha256, verified_at
		FROM hiveci_source_provenance WHERE evidence_ref = ?`, evidenceRef).Scan(
		&evidence.EvidenceRef, &evidence.SchemaVersion, &evidence.RepoIdentity,
		&evidence.ReviewBaseCommit, &evidence.SourceCommit, &evidence.SourceTree,
		&evidence.AcceptedCommit, &evidence.AcceptedTree, &evidence.CanonicalCommit,
		&evidence.CanonicalTree, &evidence.MirrorCommit, &evidence.MirrorTree,
		&evidence.SignedReviewPatchSHA256, &evidence.SourceDiffSHA256,
		&evidence.MergeResultDiffSHA256, &verifiedAt)
	if err != nil {
		return SourceProvenanceEvidence{}, err
	}
	evidence.VerifiedAt = time.Unix(verifiedAt, 0).UTC()
	if err := validateSourceProvenanceEvidence(evidence); err != nil {
		return SourceProvenanceEvidence{}, fmt.Errorf("stored source provenance evidence is invalid: %w", err)
	}
	return evidence, nil
}

func normalizeSourceProvenanceEvidence(evidence *SourceProvenanceEvidence) error {
	identity, err := SanitizeSourceRepoIdentity(evidence.RepoIdentity)
	if err != nil {
		return err
	}
	evidence.RepoIdentity = identity
	evidence.SchemaVersion = strings.TrimSpace(evidence.SchemaVersion)
	evidence.EvidenceRef = strings.TrimSpace(evidence.EvidenceRef)
	for _, value := range []*string{
		&evidence.ReviewBaseCommit, &evidence.SourceCommit, &evidence.SourceTree,
		&evidence.AcceptedCommit, &evidence.AcceptedTree, &evidence.CanonicalCommit,
		&evidence.CanonicalTree, &evidence.MirrorCommit, &evidence.MirrorTree,
		&evidence.SignedReviewPatchSHA256, &evidence.SourceDiffSHA256,
		&evidence.MergeResultDiffSHA256,
	} {
		*value = strings.ToLower(strings.TrimSpace(*value))
	}
	wantRef, err := SourceProvenanceReference(evidence.RepoIdentity, evidence.AcceptedCommit, evidence.AcceptedTree)
	if err != nil {
		return err
	}
	if evidence.EvidenceRef == "" {
		evidence.EvidenceRef = wantRef
	} else if evidence.EvidenceRef != wantRef {
		return fmt.Errorf("source provenance reference does not match immutable build identity")
	}
	return nil
}

func validateSourceProvenanceEvidence(evidence SourceProvenanceEvidence) error {
	if evidence.SchemaVersion != SourceProvenanceSchemaV1 || !validSourceProvenanceReference(evidence.EvidenceRef) {
		return fmt.Errorf("supported source provenance schema and reference are required")
	}
	for _, objectID := range []string{
		evidence.ReviewBaseCommit, evidence.SourceCommit, evidence.SourceTree,
		evidence.AcceptedCommit, evidence.AcceptedTree, evidence.CanonicalCommit,
		evidence.CanonicalTree, evidence.MirrorCommit, evidence.MirrorTree,
	} {
		if !hexObjectID.MatchString(objectID) {
			return fmt.Errorf("complete immutable commit and tree object IDs are required")
		}
	}
	for _, digest := range []string{
		evidence.SignedReviewPatchSHA256, evidence.SourceDiffSHA256, evidence.MergeResultDiffSHA256,
	} {
		if !hexSHA256.MatchString(digest) {
			return fmt.Errorf("complete SHA-256 provenance digests are required")
		}
	}
	if evidence.CanonicalCommit != evidence.AcceptedCommit || evidence.CanonicalTree != evidence.AcceptedTree {
		return fmt.Errorf("canonical repository result does not match accepted build identity")
	}
	if evidence.MirrorCommit != evidence.CanonicalCommit || evidence.MirrorTree != evidence.CanonicalTree {
		return fmt.Errorf("mirror result does not match canonical repository identity")
	}
	if evidence.VerifiedAt.IsZero() || evidence.VerifiedAt.Unix() <= 0 {
		return fmt.Errorf("positive source provenance verification time is required")
	}
	return nil
}

func validSourceProvenanceReference(ref string) bool {
	return strings.HasPrefix(ref, SourceProvenanceReferencePrefix) &&
		hexSHA256.MatchString(strings.TrimPrefix(ref, SourceProvenanceReferencePrefix))
}

func sameSourceProvenanceEvidence(a, b SourceProvenanceEvidence) bool {
	return a.EvidenceRef == b.EvidenceRef && a.SchemaVersion == b.SchemaVersion &&
		a.RepoIdentity == b.RepoIdentity && a.ReviewBaseCommit == b.ReviewBaseCommit &&
		a.SourceCommit == b.SourceCommit && a.SourceTree == b.SourceTree &&
		a.AcceptedCommit == b.AcceptedCommit && a.AcceptedTree == b.AcceptedTree &&
		a.CanonicalCommit == b.CanonicalCommit && a.CanonicalTree == b.CanonicalTree &&
		a.MirrorCommit == b.MirrorCommit && a.MirrorTree == b.MirrorTree &&
		a.SignedReviewPatchSHA256 == b.SignedReviewPatchSHA256 &&
		a.SourceDiffSHA256 == b.SourceDiffSHA256 &&
		a.MergeResultDiffSHA256 == b.MergeResultDiffSHA256
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

var (
	ErrSourceProvenanceInput = errors.New("invalid source provenance input")
	ErrCanonicalSource       = errors.New("canonical source verification failed")
	ErrMirrorSource          = errors.New("mirror source verification failed")
	ErrSourcePatchMismatch   = errors.New("reviewed and merged source patches differ")
)

// SourceProvenanceRequest contains only immutable source identities plus the
// two repository locations used to prove them. CanonicalCloneURL is transport
// input only and is never copied into evidence. RepoIdentity is the durable,
// credential-free repository address consumed downstream.
type SourceProvenanceRequest struct {
	RepoIdentity           string
	CanonicalCloneURL      string
	MirrorRepoPath         string
	ReviewBaseCommit       string
	SourceCommit           string
	SourceTree             string
	AcceptedCommit         string
	AcceptedTree           string
	SignedReviewDiffSHA256 string
}

// SourceProvenanceResolver independently clones canonical repository state
// into a fresh temporary bare repository. The zero value is ready for use.
// GitPath and TempDir exist only for controlled deployments and tests; neither
// is retained in evidence or included in returned errors.
type SourceProvenanceResolver struct {
	GitPath string
	TempDir string
	now     func() time.Time
}

// ResolveSourceProvenance uses the system Git executable and an OS temporary
// directory to resolve one immutable build input.
func ResolveSourceProvenance(ctx context.Context, request SourceProvenanceRequest) (store.SourceProvenanceEvidence, error) {
	return (SourceProvenanceResolver{}).Resolve(ctx, request)
}

// Resolve proves that signed review source, canonical merged result, and local
// mirror all identify the same immutable build input. It performs no writes to
// the durable evidence store; callers persist the successful returned record.
func (r SourceProvenanceResolver) Resolve(ctx context.Context, request SourceProvenanceRequest) (store.SourceProvenanceEvidence, error) {
	normalized, cloneURL, err := normalizeSourceProvenanceRequest(request)
	if err != nil {
		return store.SourceProvenanceEvidence{}, err
	}
	gitPath := strings.TrimSpace(r.GitPath)
	if gitPath == "" {
		gitPath = "git"
	}
	parent, err := os.MkdirTemp(r.TempDir, "hiveci-canonical-source-*")
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: create isolated repository", ErrCanonicalSource)
	}
	defer os.RemoveAll(parent)
	canonicalRepo := filepath.Join(parent, "canonical.git")
	env := noninteractiveGitEnv(parent)
	if err := runCredentialFreeGit(ctx, gitPath, env, "clone", "--mirror", "--no-local", "--", cloneURL, canonicalRepo); err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: independently clone repository", ErrCanonicalSource)
	}

	canonicalSourceTree, err := verifiedCommitTree(ctx, gitPath, env, canonicalRepo, normalized.SourceCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: reviewed source object is unavailable", ErrCanonicalSource)
	}
	if canonicalSourceTree != normalized.SourceTree {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: reviewed source tree changed", ErrCanonicalSource)
	}
	canonicalAcceptedTree, err := verifiedCommitTree(ctx, gitPath, env, canonicalRepo, normalized.AcceptedCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: accepted commit is missing or unreachable", ErrCanonicalSource)
	}
	if canonicalAcceptedTree != normalized.AcceptedTree {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: accepted tree changed", ErrCanonicalSource)
	}
	if _, err := verifiedCommitTree(ctx, gitPath, env, canonicalRepo, normalized.ReviewBaseCommit); err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: signed review base is unavailable", ErrCanonicalSource)
	}

	relationship, err := resolveMergeRelationship(ctx, canonicalRepo,
		normalized.SourceCommit, normalized.AcceptedCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: %v", ErrCanonicalSource, err)
	}
	base, firstParent := relationship.base, relationship.firstParent
	if base != normalized.ReviewBaseCommit {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: signed review base does not match canonical ancestry", ErrSourcePatchMismatch)
	}
	sourceDiff, err := deterministicGitDiff(ctx, gitPath, env, canonicalRepo, base, normalized.SourceCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: canonical reviewed patch is unavailable", ErrCanonicalSource)
	}
	mergeDiff, err := deterministicGitDiff(ctx, gitPath, env, canonicalRepo, firstParent, normalized.AcceptedCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: canonical merge-result patch is unavailable", ErrCanonicalSource)
	}
	sourceDigest := sha256Hex(sourceDiff)
	mergeDigest := sha256Hex(mergeDiff)
	signedDigest := reviewedPatchDigest(base, normalized.SourceCommit, sourceDiff)
	if signedDigest != normalized.SignedReviewDiffSHA256 {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: signed review digest does not match canonical patch", ErrSourcePatchMismatch)
	}
	if sourceDigest != mergeDigest {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: canonical merge result changed reviewed patch bytes", ErrSourcePatchMismatch)
	}

	mirrorTree, err := verifiedCommitTree(ctx, gitPath, env, normalized.MirrorRepoPath, normalized.AcceptedCommit)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: accepted canonical commit is not present in mirror", ErrMirrorSource)
	}
	if mirrorTree != canonicalAcceptedTree {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: accepted mirror tree differs from canonical tree", ErrMirrorSource)
	}
	mirrorSourceTree, err := verifiedCommitTree(ctx, gitPath, env, normalized.MirrorRepoPath, normalized.SourceCommit)
	if err != nil || mirrorSourceTree != canonicalSourceTree {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: reviewed source does not match canonical repository", ErrMirrorSource)
	}

	ref, err := store.SourceProvenanceReference(normalized.RepoIdentity,
		normalized.AcceptedCommit, normalized.AcceptedTree)
	if err != nil {
		return store.SourceProvenanceEvidence{}, fmt.Errorf("%w: derive stable evidence reference", ErrSourceProvenanceInput)
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	return store.SourceProvenanceEvidence{
		EvidenceRef: ref, SchemaVersion: store.SourceProvenanceSchemaV1,
		RepoIdentity: normalized.RepoIdentity, ReviewBaseCommit: normalized.ReviewBaseCommit,
		SourceCommit: normalized.SourceCommit, SourceTree: normalized.SourceTree,
		AcceptedCommit: normalized.AcceptedCommit, AcceptedTree: normalized.AcceptedTree,
		CanonicalCommit: normalized.AcceptedCommit, CanonicalTree: canonicalAcceptedTree,
		MirrorCommit: normalized.AcceptedCommit, MirrorTree: mirrorTree,
		SignedReviewPatchSHA256: normalized.SignedReviewDiffSHA256,
		SourceDiffSHA256:        sourceDigest, MergeResultDiffSHA256: mergeDigest,
		VerifiedAt: now().UTC(),
	}, nil
}

func reviewedPatchDigest(base, sourceCommit string, diff []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("hiveci.nip34.patch.v1\x00"))
	_, _ = hash.Write([]byte(strings.ToLower(base)))
	_, _ = hash.Write([]byte("\x00"))
	_, _ = hash.Write([]byte(strings.ToLower(sourceCommit)))
	_, _ = hash.Write([]byte("\x00"))
	_, _ = hash.Write(diff)
	return hex.EncodeToString(hash.Sum(nil))
}

func normalizeSourceProvenanceRequest(request SourceProvenanceRequest) (SourceProvenanceRequest, string, error) {
	identity, err := store.SanitizeSourceRepoIdentity(request.RepoIdentity)
	if err != nil {
		return SourceProvenanceRequest{}, "", fmt.Errorf("%w: credential-free immutable repository identity is required", ErrSourceProvenanceInput)
	}
	cloneURL, err := credentialFreeCanonicalCloneURL(request.CanonicalCloneURL)
	if err != nil {
		return SourceProvenanceRequest{}, "", err
	}
	request.RepoIdentity = identity
	request.MirrorRepoPath = strings.TrimSpace(request.MirrorRepoPath)
	if !filepath.IsAbs(request.MirrorRepoPath) || filepath.Clean(request.MirrorRepoPath) != request.MirrorRepoPath ||
		strings.ContainsAny(request.MirrorRepoPath, "\x00\r\n@?#") || strings.Contains(request.MirrorRepoPath, "://") {
		return SourceProvenanceRequest{}, "", fmt.Errorf("%w: clean absolute credential-free mirror repository path is required", ErrSourceProvenanceInput)
	}
	if canonical, parseErr := url.Parse(cloneURL); parseErr == nil && canonical.Scheme == "file" &&
		filepath.Clean(canonical.Path) == filepath.Clean(request.MirrorRepoPath) {
		return SourceProvenanceRequest{}, "", fmt.Errorf("%w: canonical repository must be independent of the local mirror", ErrSourceProvenanceInput)
	}
	objects := []*string{
		&request.ReviewBaseCommit, &request.SourceCommit, &request.SourceTree,
		&request.AcceptedCommit, &request.AcceptedTree,
	}
	for _, object := range objects {
		*object = strings.ToLower(strings.TrimSpace(*object))
		if !validCommitSHA.MatchString(*object) {
			return SourceProvenanceRequest{}, "", fmt.Errorf("%w: literal 40- or 64-hex commit and tree IDs are required", ErrSourceProvenanceInput)
		}
	}
	request.SignedReviewDiffSHA256 = strings.ToLower(strings.TrimSpace(request.SignedReviewDiffSHA256))
	if len(request.SignedReviewDiffSHA256) != sha256.Size*2 {
		return SourceProvenanceRequest{}, "", fmt.Errorf("%w: exact signed SHA-256 review digest is required", ErrSourceProvenanceInput)
	}
	if _, err := hex.DecodeString(request.SignedReviewDiffSHA256); err != nil {
		return SourceProvenanceRequest{}, "", fmt.Errorf("%w: exact signed SHA-256 review digest is required", ErrSourceProvenanceInput)
	}
	return request, cloneURL, nil
}

// credentialFreeCanonicalCloneURL is intentionally narrow in v1. Public HTTPS
// is the production transport; file URLs exist for hermetic tests and local
// operators. SSH, git, HTTP, scp syntax, userinfo, query, and fragments are
// rejected before Git sees any argv.
func credentialFreeCanonicalCloneURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n\t") {
		return "", fmt.Errorf("%w: supported canonical repository URL is required", ErrSourceProvenanceInput)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("%w: canonical repository URL contains credentials or unsupported syntax", ErrSourceProvenanceInput)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" || u.Path == "" || u.Path == "/" {
			return "", fmt.Errorf("%w: complete HTTPS canonical repository URL is required", ErrSourceProvenanceInput)
		}
		u.Scheme = "https"
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimSuffix(u.Path, "/")
	case "file":
		if (u.Host != "" && !strings.EqualFold(u.Host, "localhost")) || !filepath.IsAbs(u.Path) {
			return "", fmt.Errorf("%w: file canonical repository URL must be local and absolute", ErrSourceProvenanceInput)
		}
		u.Scheme = "file"
		u.Host = ""
	default:
		return "", fmt.Errorf("%w: canonical repository transport is unsupported", ErrSourceProvenanceInput)
	}
	return u.String(), nil
}

func noninteractiveGitEnv(home string) []string {
	env := []string{
		"HOME=" + home,
		"LC_ALL=C", "LANG=C",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
	}
	if path := os.Getenv("PATH"); path != "" {
		env = append(env, "PATH="+path)
	}
	return env
}

func runCredentialFreeGit(ctx context.Context, gitPath string, env []string, args ...string) error {
	common := []string{"-c", "credential.helper=", "-c", "core.askPass=", "-c", "core.quotePath=true",
		"-c", "diff.mnemonicPrefix=false", "-c", "diff.noprefix=false"}
	cmd := exec.CommandContext(ctx, gitPath, append(common, args...)...)
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("git operation failed")
	}
	return nil
}

func credentialFreeGitOutput(ctx context.Context, gitPath string, env []string, args ...string) ([]byte, error) {
	common := []string{"-c", "credential.helper=", "-c", "core.askPass=", "-c", "core.quotePath=true",
		"-c", "diff.mnemonicPrefix=false", "-c", "diff.noprefix=false"}
	cmd := exec.CommandContext(ctx, gitPath, append(common, args...)...)
	cmd.Env = env
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("git operation failed")
	}
	return out, nil
}

func verifiedCommitTree(ctx context.Context, gitPath string, env []string, repoPath, commit string) (string, error) {
	out, err := credentialFreeGitOutput(ctx, gitPath, env, "--git-dir", repoPath,
		"rev-parse", "--verify", commit+"^{tree}")
	if err != nil {
		return "", err
	}
	tree := strings.ToLower(strings.TrimSpace(string(out)))
	if !validCommitSHA.MatchString(tree) {
		return "", errors.New("invalid tree object")
	}
	return tree, nil
}

func deterministicGitDiff(ctx context.Context, gitPath string, env []string, repoPath, from, to string) ([]byte, error) {
	return credentialFreeGitOutput(ctx, gitPath, env, "--git-dir", repoPath, "diff",
		"--binary", "--full-index", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
		"--no-indent-heuristic", "--diff-algorithm=myers", "--src-prefix=a/", "--dst-prefix=b/",
		from, to, "--")
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

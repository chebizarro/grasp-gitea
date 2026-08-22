// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type sourceProvenanceFixture struct {
	ctx          context.Context
	canonical    string
	mirror       string
	base         string
	source       string
	sourceTree   string
	accepted     string
	acceptedTree string
	diff         string
	rawDiff      string
}

func newSourceProvenanceFixture(t *testing.T, alterMergeResult bool) *sourceProvenanceFixture {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	canonical := filepath.Join(dir, "canonical.git")
	mirror := filepath.Join(dir, "mirror.git")
	hiveGit(t, dir, "init", "-b", "main", work)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", "README.md")
	hiveGit(t, work, "commit", "-m", "base")
	base := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	hiveGit(t, work, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(work, "feature.txt"), []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", "feature.txt")
	hiveGit(t, work, "commit", "-m", "reviewed source")
	source := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	sourceTree := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD^{tree}"))
	hiveGit(t, work, "checkout", "main")
	if err := os.WriteFile(filepath.Join(work, "main.txt"), []byte("main advance\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", "main.txt")
	hiveGit(t, work, "commit", "-m", "main advance")
	hiveGit(t, work, "merge", "--no-ff", "feature", "-m", "merge reviewed source")
	if alterMergeResult {
		if err := os.WriteFile(filepath.Join(work, "unreviewed.txt"), []byte("not reviewed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		hiveGit(t, work, "add", "unreviewed.txt")
		hiveGit(t, work, "commit", "--amend", "--no-edit")
	}
	accepted := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	acceptedTree := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD^{tree}"))
	hiveGit(t, dir, "clone", "--bare", work, canonical)
	hiveGit(t, dir, "clone", "--bare", work, mirror)
	diffBytes, err := deterministicGitDiff(context.Background(), "git", noninteractiveGitEnv(t.TempDir()),
		canonical, base, source)
	if err != nil {
		t.Fatal(err)
	}
	return &sourceProvenanceFixture{
		ctx: context.Background(), canonical: canonical, mirror: mirror, base: base,
		source: source, sourceTree: sourceTree, accepted: accepted,
		acceptedTree: acceptedTree, diff: reviewedPatchDigest(base, source, diffBytes), rawDiff: sha256Hex(diffBytes),
	}
}

func (fx *sourceProvenanceFixture) request() SourceProvenanceRequest {
	canonicalURL := (&url.URL{Scheme: "file", Path: fx.canonical}).String()
	return SourceProvenanceRequest{
		RepoIdentity:      "https://github.com/sharegap/grasp-gitea.git",
		CanonicalCloneURL: canonicalURL, MirrorRepoPath: fx.mirror,
		ReviewBaseCommit: fx.base, SourceCommit: fx.source, SourceTree: fx.sourceTree,
		AcceptedCommit: fx.accepted, AcceptedTree: fx.acceptedTree,
		SignedReviewDiffSHA256: fx.diff,
	}
}

func TestSourceProvenanceResolverProvesIndependentCanonicalAndMirrorIdentity(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	verifiedAt := time.Unix(1234, 0).UTC()
	resolver := SourceProvenanceResolver{now: func() time.Time { return verifiedAt }}
	evidence, err := resolver.Resolve(fx.ctx, fx.request())
	if err != nil {
		t.Fatal(err)
	}
	wantRef, err := store.SourceProvenanceReference(fx.request().RepoIdentity, fx.accepted, fx.acceptedTree)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.EvidenceRef != wantRef || evidence.RepoIdentity != fx.request().RepoIdentity ||
		evidence.ReviewBaseCommit != fx.base || evidence.SourceCommit != fx.source ||
		evidence.SourceTree != fx.sourceTree || evidence.AcceptedCommit != fx.accepted ||
		evidence.AcceptedTree != fx.acceptedTree || evidence.CanonicalCommit != fx.accepted ||
		evidence.CanonicalTree != fx.acceptedTree || evidence.MirrorCommit != fx.accepted ||
		evidence.MirrorTree != fx.acceptedTree || evidence.SignedReviewPatchSHA256 != fx.diff ||
		evidence.SourceDiffSHA256 != fx.rawDiff || evidence.MergeResultDiffSHA256 != fx.rawDiff ||
		!evidence.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("incomplete provenance evidence: %#v", evidence)
	}
}

func TestSourceProvenanceResolverRejectsMutableOrIncompleteObjectInputsBeforeGit(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	tests := map[string]func(*SourceProvenanceRequest){
		"branch-only source":         func(r *SourceProvenanceRequest) { r.SourceCommit = "refs/heads/feature" },
		"tag-only accepted":          func(r *SourceProvenanceRequest) { r.AcceptedCommit = "refs/tags/v1" },
		"short commit":               func(r *SourceProvenanceRequest) { r.AcceptedCommit = strings.Repeat("a", 12) },
		"missing tree":               func(r *SourceProvenanceRequest) { r.AcceptedTree = "" },
		"branch repository identity": func(r *SourceProvenanceRequest) { r.RepoIdentity = "refs/heads/main" },
		"canonical is mirror": func(r *SourceProvenanceRequest) {
			r.CanonicalCloneURL = (&url.URL{Scheme: "file", Path: r.MirrorRepoPath}).String()
		},
		"credential-like mirror path": func(r *SourceProvenanceRequest) { r.MirrorRepoPath += "?token=hidden" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fx.request()
			mutate(&request)
			_, err := (SourceProvenanceResolver{GitPath: filepath.Join(t.TempDir(), "git-must-not-run")}).Resolve(fx.ctx, request)
			if !errors.Is(err, ErrSourceProvenanceInput) {
				t.Fatalf("error = %v, want ErrSourceProvenanceInput", err)
			}
		})
	}
}

func TestSourceProvenanceResolverRejectsCredentialBearingURLBeforeGitWithoutDisclosure(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	for _, rawURL := range []string{
		"https://build-user:super-secret@example.com/org/repo.git",
		"https://example.com/org/repo.git?token=super-secret",
		"ssh://git@example.com/org/repo.git",
		"git@example.com:org/repo.git",
	} {
		request := fx.request()
		request.CanonicalCloneURL = rawURL
		_, err := (SourceProvenanceResolver{GitPath: filepath.Join(t.TempDir(), "git-must-not-run")}).Resolve(fx.ctx, request)
		if !errors.Is(err, ErrSourceProvenanceInput) {
			t.Fatalf("URL %q error = %v, want ErrSourceProvenanceInput", rawURL, err)
		}
		if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "build-user") || strings.Contains(err.Error(), rawURL) {
			t.Fatalf("credential-bearing URL disclosed in error: %v", err)
		}
	}
}

func TestSourceProvenanceResolverRejectsMissingAndChangedCanonicalObjects(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	tests := map[string]func(*SourceProvenanceRequest){
		"missing accepted":      func(r *SourceProvenanceRequest) { r.AcceptedCommit = strings.Repeat("a", 40) },
		"changed source tree":   func(r *SourceProvenanceRequest) { r.SourceTree = strings.Repeat("b", 40) },
		"changed accepted tree": func(r *SourceProvenanceRequest) { r.AcceptedTree = strings.Repeat("c", 40) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fx.request()
			mutate(&request)
			_, err := ResolveSourceProvenance(fx.ctx, request)
			if !errors.Is(err, ErrCanonicalSource) {
				t.Fatalf("error = %v, want ErrCanonicalSource", err)
			}
		})
	}
}

func TestSourceProvenanceResolverRejectsForcePushedCanonicalObject(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	hiveGit(t, "", "--git-dir", fx.canonical, "update-ref", "refs/heads/main", fx.source)
	hiveGit(t, "", "--git-dir", fx.canonical, "reflog", "expire", "--expire=now", "--all")
	hiveGit(t, "", "--git-dir", fx.canonical, "gc", "--prune=now")
	_, err := ResolveSourceProvenance(fx.ctx, fx.request())
	if !errors.Is(err, ErrCanonicalSource) {
		t.Fatalf("error = %v, want ErrCanonicalSource", err)
	}
}

func TestSourceProvenanceResolverRejectsMismatchedMirror(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	hiveGit(t, "", "--git-dir", fx.mirror, "update-ref", "refs/heads/main", fx.source)
	hiveGit(t, "", "--git-dir", fx.mirror, "reflog", "expire", "--expire=now", "--all")
	hiveGit(t, "", "--git-dir", fx.mirror, "gc", "--prune=now")
	_, err := ResolveSourceProvenance(fx.ctx, fx.request())
	if !errors.Is(err, ErrMirrorSource) {
		t.Fatalf("error = %v, want ErrMirrorSource", err)
	}
}

func TestSourceProvenanceResolverRejectsSignedDigestAndMergeResultChanges(t *testing.T) {
	t.Run("signed digest", func(t *testing.T) {
		fx := newSourceProvenanceFixture(t, false)
		request := fx.request()
		request.SignedReviewDiffSHA256 = strings.Repeat("d", 64)
		_, err := ResolveSourceProvenance(fx.ctx, request)
		if !errors.Is(err, ErrSourcePatchMismatch) {
			t.Fatalf("error = %v, want ErrSourcePatchMismatch", err)
		}
	})
	t.Run("merge result", func(t *testing.T) {
		fx := newSourceProvenanceFixture(t, true)
		_, err := ResolveSourceProvenance(fx.ctx, fx.request())
		if !errors.Is(err, ErrSourcePatchMismatch) {
			t.Fatalf("error = %v, want ErrSourcePatchMismatch", err)
		}
	})
}

func TestSourceProvenanceResolverRejectsUnsignedReviewBase(t *testing.T) {
	fx := newSourceProvenanceFixture(t, false)
	request := fx.request()
	request.ReviewBaseCommit = fx.source
	_, err := ResolveSourceProvenance(fx.ctx, request)
	if !errors.Is(err, ErrSourcePatchMismatch) {
		t.Fatalf("error = %v, want ErrSourcePatchMismatch", err)
	}
}

func TestCanonicalSourceForEnvelopeUsesPolicyBoundGitHubOrigin(t *testing.T) {
	evidence, err := json.Marshal(normalizedGitHubEvidence{
		Repository: "ShareGap/Grasp-Gitea", RepoAddress: "30617:owner:repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := store.TriggerEnvelope{
		Source: TriggerSourceGitHubActions, RepoAddress: "30617:owner:repo", EvidenceJSON: string(evidence),
	}
	canonical, err := canonicalSourceForEnvelope(store.Mapping{}, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.repoIdentity != "https://github.com/sharegap/grasp-gitea.git" || canonical.cloneURL != canonical.repoIdentity {
		t.Fatalf("GitHub canonical source = %#v", canonical)
	}
	envelope.RepoAddress = "30617:owner:other"
	if _, err := canonicalSourceForEnvelope(store.Mapping{}, envelope); !errors.Is(err, ErrDispatchPolicyDenied) {
		t.Fatalf("policy-unbound GitHub repository accepted: %v", err)
	}
}

func TestCanonicalSourceForEnvelopeNIP34RequiresCredentialFreeAnnouncement(t *testing.T) {
	envelope := store.TriggerEnvelope{Source: store.TriggerSourceNIP34MergeStatus, RepoAddress: "30617:owner:repo"}
	mapping := store.Mapping{AnnouncedCloneURL: "https://git.example/owner/repo.git/"}
	canonical, err := canonicalSourceForEnvelope(mapping, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.repoIdentity != envelope.RepoAddress || canonical.cloneURL != "https://git.example/owner/repo.git" {
		t.Fatalf("NIP-34 canonical source = %#v", canonical)
	}
	mapping.AnnouncedCloneURL = ""
	if _, err := canonicalSourceForEnvelope(mapping, envelope); !errors.Is(err, ErrDispatchPolicyDenied) {
		t.Fatalf("missing canonical announcement accepted: %v", err)
	}
}

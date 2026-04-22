package proactivesync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/store"
)

var (
	validRef = regexp.MustCompile(`^refs/(heads|tags)/[a-zA-Z0-9][a-zA-Z0-9._/\-]*$`)
	validHex = regexp.MustCompile(`^[0-9a-f]{4,64}$`)
)

// OrgResolver looks up the Gitea org name for a given npub/repoID.
// Returns empty string if not found.
type OrgResolver interface {
	GetMapping(ctx context.Context, npub string, repoID string) (store.Mapping, error)
}

type Service struct {
	repositoriesDir string
	orgResolver     OrgResolver
	logger          *slog.Logger
}

func New(repositoriesDir string, orgResolver OrgResolver, logger *slog.Logger) *Service {
	return &Service{repositoriesDir: repositoriesDir, orgResolver: orgResolver, logger: logger}
}

func (s *Service) HandleStateEvent(ctx context.Context, ev *nostr.Event) error {
	if ev == nil || ev.Kind != nostr.KindRepositoryState {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return err
	}

	repoID := tagValue(ev.Tags, "d")
	if repoID == "" {
		return fmt.Errorf("state event missing d tag")
	}

	npub, err := nip19.EncodePublicKey(ev.PubKey)
	if err != nil {
		return fmt.Errorf("encode pubkey to npub: %w", err)
	}

	// Look up the actual Gitea org name from the store, since repos are
	// created under the NIP-05-resolved org name, not the raw npub.
	orgName := npub
	if s.orgResolver != nil {
		mapping, lookupErr := s.orgResolver.GetMapping(ctx, npub, repoID)
		if lookupErr != nil {
			// Repo not provisioned yet; skip silently.
			return nil
		}
		if mapping.Owner != "" {
			orgName = mapping.Owner
		}
	}

	repoPath := filepath.Join(s.repositoriesDir, orgName, repoID+".git")
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return nil
	}

	state := nip34.ParseRepositoryState(*ev)
	for branch, sha := range state.Branches {
		ref := "refs/heads/" + branch
		if !validRef.MatchString(ref) || !validHex.MatchString(sha) {
			s.logger.Warn("proactive sync skipped invalid ref or sha", "repo", repoPath, "ref", ref, "sha", sha)
			continue
		}
		if err := s.updateRefIfObjectExists(ctx, repoPath, ref, sha); err != nil {
			s.logger.Warn("proactive sync branch update failed", "repo", repoPath, "ref", branch, "error", err)
		}
	}
	for tag, sha := range state.Tags {
		if strings.HasSuffix(tag, "^{}") {
			continue
		}
		ref := "refs/tags/" + tag
		if !validRef.MatchString(ref) || !validHex.MatchString(sha) {
			s.logger.Warn("proactive sync skipped invalid ref or sha", "repo", repoPath, "ref", ref, "sha", sha)
			continue
		}
		if err := s.updateRefIfObjectExists(ctx, repoPath, ref, sha); err != nil {
			s.logger.Warn("proactive sync tag update failed", "repo", repoPath, "ref", tag, "error", err)
		}
	}

	s.logger.Info("proactive sync applied state event", "repo", repoPath, "event", ev.ID)
	return nil
}

func (s *Service) updateRefIfObjectExists(ctx context.Context, repoPath string, ref string, sha string) error {
	if err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "cat-file", "-e", sha).Run(); err != nil {
		return fmt.Errorf("object %s not present locally", sha)
	}
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", ref, sha).CombinedOutput(); err != nil {
		return fmt.Errorf("update-ref failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func tagValue(tags nostr.Tags, key string) string {
	v := tags.GetFirst([]string{key, ""})
	if v == nil || len(*v) < 2 {
		return ""
	}
	return (*v)[1]
}

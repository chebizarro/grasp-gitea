package proactivesync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

type Service struct {
	repositoriesDir string
	logger          *slog.Logger
}

func New(repositoriesDir string, logger *slog.Logger) *Service {
	return &Service{repositoriesDir: repositoriesDir, logger: logger}
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

	repoPath := filepath.Join(s.repositoriesDir, npub, repoID+".git")
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return nil
	}

	state := nip34.ParseRepositoryState(*ev)
	for branch, sha := range state.Branches {
		if err := s.updateRefIfObjectExists(ctx, repoPath, "refs/heads/"+branch, sha); err != nil {
			s.logger.Warn("proactive sync branch update failed", "repo", repoPath, "ref", branch, "error", err)
		}
	}
	for tag, sha := range state.Tags {
		if strings.HasSuffix(tag, "^{}") {
			continue
		}
		if err := s.updateRefIfObjectExists(ctx, repoPath, "refs/tags/"+tag, sha); err != nil {
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
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

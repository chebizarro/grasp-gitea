package nostrauthz_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nostrauthz"
	"github.com/sharegap/grasp-gitea/internal/proactivesync"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type regressionMappings struct {
	mapping store.Mapping
}

func (m regressionMappings) GetMapping(_ context.Context, npub, repoID string) (store.Mapping, error) {
	if npub == m.mapping.Npub && repoID == m.mapping.RepoID {
		return m.mapping, nil
	}
	return store.Mapping{}, sql.ErrNoRows
}

func (m regressionMappings) ListMappings(context.Context) ([]store.Mapping, error) {
	return []store.Mapping{m.mapping}, nil
}

func TestSpoofedOwnerHintCannotDeleteRepositoryRefs(t *testing.T) {
	ctx := context.Background()
	repositoriesDir := t.TempDir()
	repoPath := filepath.Join(repositoriesDir, "alice", "project.git")
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatalf("mkdir repositories: %v", err)
	}
	runGit(t, "", nil, "init", "--bare", repoPath)
	treeID := strings.TrimSpace(runGit(t, repoPath, strings.NewReader(""), "mktree"))
	objectID := strings.TrimSpace(runGit(t, repoPath, strings.NewReader("protected ref\n"), "commit-tree", treeID))
	runGit(t, repoPath, nil, "update-ref", "refs/heads/main", objectID)

	owner := nostr.Generate()
	attacker := nostr.Generate()
	announcement := nostr.Event{
		PubKey:    owner.Public(),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      nostr.KindRepositoryAnnouncement,
		Tags:      nostr.Tags{{"d", "project"}},
	}
	if err := announcement.Sign(owner); err != nil {
		t.Fatalf("sign owner announcement: %v", err)
	}
	announcementJSON, err := json.Marshal(announcement)
	if err != nil {
		t.Fatalf("marshal owner announcement: %v", err)
	}
	mapping := store.Mapping{
		Npub:                  nip19.EncodeNpub(owner.Public()),
		RepoID:                "project",
		Pubkey:                owner.Public().Hex(),
		Owner:                 "alice",
		RepoName:              "project",
		AnnouncementEventJSON: string(announcementJSON),
	}

	// Omitting every refs/heads tag would prune main if the attacker-controlled
	// p hint were still trusted as repository authority.
	attack := nostr.Event{
		PubKey:    attacker.Public(),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      nostr.KindRepositoryState,
		Tags: nostr.Tags{
			{"d", "project"},
			{"p", owner.Public().Hex()},
		},
	}
	if err := attack.Sign(attacker); err != nil {
		t.Fatalf("sign attack state: %v", err)
	}

	svc := proactivesync.New(repositoriesDir, regressionMappings{mapping: mapping}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	err = svc.HandleStateEvent(ctx, &attack)
	if !errors.Is(err, nostrauthz.ErrUnauthorized) {
		t.Fatalf("HandleStateEvent() error = %v, want ErrUnauthorized", err)
	}
	got := strings.TrimSpace(runGit(t, repoPath, nil, "rev-parse", "refs/heads/main"))
	if got != objectID {
		t.Fatalf("protected main ref changed from %s to %s", objectID, got)
	}
}

func runGit(t *testing.T, gitDir string, stdin io.Reader, args ...string) string {
	t.Helper()
	if gitDir != "" {
		args = append([]string{"--git-dir", gitDir}, args...)
	}
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=GRASP Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=GRASP Test", "GIT_COMMITTER_EMAIL=test@example.invalid",
	)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, strings.TrimSpace(string(out)))
	}
	return string(out)
}

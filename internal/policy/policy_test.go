package policy

import (
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func TestStoreReplacesCopiedSnapshot(t *testing.T) {
	cfg := config.Config{
		PubkeyAllowlist: map[string]struct{}{"old": {}},
		CITriggerRepos:  []string{"owner/old"},
		CIEnabled:       true,
	}
	store := New(cfg)

	cfg.PubkeyAllowlist["mutated"] = struct{}{}
	cfg.CITriggerRepos[0] = "owner/mutated"
	initial := store.Current()
	if _, ok := initial.PubkeyAllowlist["mutated"]; ok || initial.CITriggerRepos[0] != "owner/old" {
		t.Fatal("snapshot retained mutable configuration data")
	}

	store.Store(config.Config{
		PubkeyAllowlist: map[string]struct{}{"new": {}},
		CITriggerRepos:  []string{"*"},
	})
	current := store.Current()
	if _, ok := current.PubkeyAllowlist["new"]; !ok {
		t.Fatal("replacement allowlist was not published")
	}
	if current.CIEnabled || len(current.CITriggerRepos) != 1 || current.CITriggerRepos[0] != "*" {
		t.Fatalf("unexpected replacement snapshot: %#v", current)
	}
}

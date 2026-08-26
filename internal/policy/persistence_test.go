package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func validSeed() config.Config {
	return config.Config{
		RelayURLs: []string{"wss://seed-relay.example"}, HookRelayURL: "wss://seed-hook.example",
		CIEnabled: true, CITriggerRepos: []string{"owner/seed"}, ProvisionRateLimit: 3,
		ProfileSyncInterval: 10 * time.Minute, ProfileSyncWorkers: 4,
		HiveCIJobTimeoutMinutes: 15, HiveCINostrRelays: []string{"wss://hive-seed.example"},
	}
}

func TestOpenSeedsOnceAndExistingProjectionWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Open(path, validSeed())
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Current().CITriggerRepos; len(got) != 1 || got[0] != "owner/seed" {
		t.Fatalf("seed trigger repos = %v", got)
	}
	if err := store.UpdateGroup("ci", []byte(`{"enabled":false,"trigger_repos":["owner/persisted"]}`)); err != nil {
		t.Fatal(err)
	}

	replacementEnv := validSeed()
	replacementEnv.CIEnabled = true
	replacementEnv.CITriggerRepos = []string{"owner/env-override"}
	reopened, err := Open(path, replacementEnv)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Current()
	if got.CIEnabled || len(got.CITriggerRepos) != 1 || got.CITriggerRepos[0] != "owner/persisted" {
		t.Fatalf("existing projection was overridden by seed: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
}

func TestUpdatePersistsBeforeHotApplyAndInvalidCandidateKeepsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Open(path, validSeed())
	if err != nil {
		t.Fatal(err)
	}
	changes := store.Changes()
	if err := store.UpdateGroup("hive_ci", []byte(`{"nostr_relays":["wss://new.example"],"cashu_mint_url":"https://mint.example","blossom_url":"https://blossom.example","job_timeout_minutes":22,"clone_url_template":"https://git.example/{owner}/{repo}.git"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	default:
		t.Fatal("successful update did not notify live consumers")
	}
	if got := store.Current(); got.HiveCIJobTimeout != 22*time.Minute || got.HiveCINostrRelays[0] != "wss://new.example" {
		t.Fatalf("hot snapshot = %#v", got)
	}
	reopened, err := Open(path, validSeed())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current().HiveCIJobTimeout != 22*time.Minute {
		t.Fatal("update was not durable before apply")
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateGroup("hive_ci", []byte(`{"nostr_relays":[],"job_timeout_minutes":0}`)); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || store.Current().HiveCIJobTimeout != 22*time.Minute {
		t.Fatal("invalid candidate replaced durable or effective policy")
	}
}

func TestReloadRejectsInvalidFileAndKeepsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Open(path, validSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("invalid persisted policy reloaded")
	}
	if got := store.Current().CITriggerRepos[0]; got != "owner/seed" {
		t.Fatalf("snapshot changed after failed reload: %q", got)
	}
}

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestConfigFabricTrustRootsSeedOnceAndLocalRecoveryPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	authorA := strings.Repeat("a", 64)
	authorB := strings.Repeat("b", 64)
	seed := validSeed()
	seed.ConfigTrustedAuthors = []string{authorA}
	seed.ConfigScope = "staging"
	store, err := Open(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Current().ConfigTrustedAuthors; len(got) != 1 || got[0] != authorA {
		t.Fatalf("seeded trust roots = %v", got)
	}

	replacement := validSeed()
	replacement.ConfigTrustedAuthors = []string{authorB}
	replacement.ConfigScope = "prod"
	reopened, err := Open(path, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Current(); got.ConfigTrustedAuthors[0] != authorA || got.ConfigScope != "staging" {
		t.Fatalf("persisted fabric state overridden by env: %#v", got)
	}

	body := []byte(`{"trusted_authors":["` + authorB + `"],"scope":"prod"}`)
	if err := reopened.UpdateGroup("config_fabric", body); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Current(); got.ConfigTrustedAuthors[0] != authorB || got.ConfigScope != "prod" {
		t.Fatalf("local recovery did not persist: %#v", got)
	}
}

func TestLegacyProjectionMigrationDoesNotImportEnvTrustRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	seed := validSeed()
	seed.ConfigScope = "prod"
	store, err := Open(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	doc := store.Document()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "config_fabric")
	data, _ = json.Marshal(raw)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	legacyBoot := validSeed()
	legacyBoot.ConfigScope = "staging"
	legacyBoot.ConfigTrustedAuthors = []string{strings.Repeat("c", 64)}
	migrated, err := Open(path, legacyBoot)
	if err != nil {
		t.Fatal(err)
	}
	if got := migrated.Current(); got.ConfigScope != "staging" || len(got.ConfigTrustedAuthors) != 0 || got.EnvSeedImport != nil {
		t.Fatalf("legacy metadata migration imported mutable env policy: %#v", got)
	}
	if _, seeded := migrated.SeedImport(); seeded {
		t.Fatal("legacy persisted projection was reported as a new env import")
	}
}

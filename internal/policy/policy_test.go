package policy

import (
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func TestDocumentReturnsDefensiveCopy(t *testing.T) {
	seed := Document{
		Access: AccessPolicy{PubkeyAllowlist: []string{"owner"}},
		CI:     CIPolicy{TriggerRepos: []string{"owner/repo"}},
		Relays: RelayPolicy{URLs: []string{"wss://relay.example"}},
		HiveCI: HiveCIPolicy{NostrRelays: []string{"wss://hive.example"}},
		ConfigFabric: ConfigFabricPolicy{
			TrustedAuthors: []string{"author"},
			Accepted:       map[string]AcceptedConfig{"config": {Author: "author"}},
			EnvSeed:        &EnvSeedImport{ConsideredVariables: []string{"RELAY_URLS"}},
		},
	}
	store := &Store{}
	store.publish(seed)
	seed.Access.PubkeyAllowlist[0] = "changed before read"
	doc := store.Document()
	doc.Access.PubkeyAllowlist[0] = "changed"
	doc.CI.TriggerRepos[0] = "changed"
	doc.Relays.URLs[0] = "changed"
	doc.HiveCI.NostrRelays[0] = "changed"
	doc.ConfigFabric.TrustedAuthors[0] = "changed"
	doc.ConfigFabric.Accepted["config"] = AcceptedConfig{Author: "changed"}
	doc.ConfigFabric.EnvSeed.ConsideredVariables[0] = "changed"
	got := store.Document()
	if got.Access.PubkeyAllowlist[0] != "owner" || got.CI.TriggerRepos[0] != "owner/repo" ||
		got.Relays.URLs[0] != "wss://relay.example" || got.HiveCI.NostrRelays[0] != "wss://hive.example" ||
		got.ConfigFabric.TrustedAuthors[0] != "author" || got.ConfigFabric.Accepted["config"].Author != "author" ||
		got.ConfigFabric.EnvSeed.ConsideredVariables[0] != "RELAY_URLS" {
		t.Fatalf("Document retained mutable policy data: %#v", got)
	}

	empty := &Store{}
	empty.publish(Document{
		Access:       AccessPolicy{PubkeyAllowlist: []string{}},
		ConfigFabric: ConfigFabricPolicy{Accepted: map[string]AcceptedConfig{}, EnvSeed: &EnvSeedImport{ConsideredVariables: []string{}}},
	})
	emptyDoc := empty.Document()
	if emptyDoc.Access.PubkeyAllowlist == nil || emptyDoc.CI.TriggerRepos != nil ||
		emptyDoc.ConfigFabric.Accepted == nil || emptyDoc.ConfigFabric.EnvSeed.ConsideredVariables == nil {
		t.Fatalf("Document changed nil versus empty fields: %#v", emptyDoc)
	}
}

func TestStoreReplacesCopiedSnapshot(t *testing.T) {
	cfg := config.Config{
		PubkeyAllowlist: map[string]struct{}{"old": {}},
		CITriggerRepos:  []string{"owner/old"},
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
	if len(current.CITriggerRepos) != 1 || current.CITriggerRepos[0] != "*" {
		t.Fatalf("unexpected replacement snapshot: %#v", current)
	}
}

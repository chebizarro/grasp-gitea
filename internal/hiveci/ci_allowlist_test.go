package hiveci

import (
	"testing"

	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestRepoCIAllowlistUsesImmutableIdentityWithLegacyCompatibility(t *testing.T) {
	mapping := store.Mapping{Pubkey: "owner-pubkey", Owner: "physical-owner", RepoID: "repo"}
	for _, tc := range []struct {
		name    string
		entries []string
		want    bool
	}{
		{name: "immutable owner pubkey and repo id", entries: []string{"owner-pubkey/repo"}, want: true},
		{name: "legacy physical owner and repo id", entries: []string{"physical-owner/repo"}, want: true},
		{name: "wildcard", entries: []string{"*"}, want: true},
		{name: "other repository", entries: []string{"owner-pubkey/other"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &Runner{triggerRepos: tc.entries}
			if got := runner.isRepoCIAllowed(mapping); got != tc.want {
				t.Fatalf("isRepoCIAllowed()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestRepoCIAllowlistRejectsAmbiguousTenantLegacyKey(t *testing.T) {
	first := store.Mapping{Pubkey: "pubkey-one", Owner: "tenant-org", RepoID: "repo", TenantHost: "tenant.example"}
	second := store.Mapping{Pubkey: "pubkey-two", Owner: "tenant-org", RepoID: "repo", TenantHost: "tenant.example"}

	legacy := &Runner{triggerRepos: []string{"tenant-org/repo"}}
	if legacy.isRepoCIAllowed(first) || legacy.isRepoCIAllowed(second) {
		t.Fatal("ambiguous tenant owner/repo-id key authorized a tenant mapping")
	}

	immutable := &Runner{triggerRepos: []string{"pubkey-one/repo"}}
	if !immutable.isRepoCIAllowed(first) {
		t.Fatal("immutable tenant allow-list key did not authorize its repository")
	}
	if immutable.isRepoCIAllowed(second) {
		t.Fatal("one tenant owner's immutable key authorized another owner's colliding repo-id")
	}
}

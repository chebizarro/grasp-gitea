package nostrstate

import (
	"testing"

	"fiatjaf.com/nostr"
)

// testPubKey generates a PubKey from a fixed byte seed for reproducible tests.
func testPubKey(seed byte) nostr.PubKey {
	var sk nostr.SecretKey
	sk[31] = seed
	return sk.Public()
}

func TestExtractMaintainersRecursive(t *testing.T) {
	owner := testPubKey(1)
	alice := testPubKey(2)
	bob := testPubKey(3)
	other := testPubKey(4)

	events := []nostr.Event{
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: owner,
			Tags: nostr.Tags{
				{"d", "repo1"},
				{"maintainers", alice.Hex()},
			},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: alice,
			Tags: nostr.Tags{
				{"d", "repo1"},
				{"maintainers", bob.Hex()},
			},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: bob,
			Tags: nostr.Tags{{"d", "repo1"}},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: other,
			Tags: nostr.Tags{{"d", "repo2"}},
		},
	}

	maintainers, err := extractMaintainers(events, owner.Hex(), "repo1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(maintainers) != 3 {
		t.Fatalf("expected 3 maintainers, got %d (%v)", len(maintainers), maintainers)
	}
}

package nostrstate

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestExtractMaintainersRecursive(t *testing.T) {
	events := []nostr.Event{
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: "owner",
			Tags: nostr.Tags{
				{"d", "repo1"},
				{"maintainers", "alice"},
			},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: "alice",
			Tags: nostr.Tags{
				{"d", "repo1"},
				{"maintainers", "bob"},
			},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: "bob",
			Tags:   nostr.Tags{{"d", "repo1"}},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: "other",
			Tags:   nostr.Tags{{"d", "repo2"}},
		},
	}

	maintainers, err := extractMaintainers(events, "owner", "repo1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(maintainers) != 3 {
		t.Fatalf("expected 3 maintainers, got %d (%v)", len(maintainers), maintainers)
	}
}

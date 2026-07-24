package nostrstate

import (
	"testing"

	"fiatjaf.com/nostr"
)

func TestExtractMaintainersRecursive(t *testing.T) {
	owner := nostr.Generate().Public()
	alice := nostr.Generate().Public()
	bob := nostr.Generate().Public()
	other := nostr.Generate().Public()
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
			Tags:   nostr.Tags{{"d", "repo1"}},
		},
		{
			Kind:   nostr.KindRepositoryAnnouncement,
			PubKey: other,
			Tags:   nostr.Tags{{"d", "repo2"}},
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

func stateEventWithID(pk nostr.PubKey, createdAt nostr.Timestamp, idByte byte, branchSHA string) nostr.Event {
	var id nostr.ID
	for i := range id {
		id[i] = idByte
	}
	return nostr.Event{
		ID:        id,
		Kind:      nostr.KindRepositoryState,
		PubKey:    pk,
		CreatedAt: createdAt,
		Tags:      nostr.Tags{{"d", "repo1"}, {"refs/heads/main", branchSHA}},
	}
}

func TestSelectLatestStateNewerTimestampWins(t *testing.T) {
	maintainer := nostr.Generate().Public()
	set := map[string]struct{}{maintainer.Hex(): {}}
	older := stateEventWithID(maintainer, 100, 0x01, "aaa")
	newer := stateEventWithID(maintainer, 200, 0xff, "bbb")

	got := selectLatestState([]nostr.Event{older, newer}, set)
	if got == nil || got.CreatedAt != 200 {
		t.Fatalf("expected newer state to win, got %+v", got)
	}
}

func TestSelectLatestStateEqualTimestampLowestIDWins(t *testing.T) {
	maintainer := nostr.Generate().Public()
	set := map[string]struct{}{maintainer.Hex(): {}}
	high := stateEventWithID(maintainer, 100, 0xff, "high")
	low := stateEventWithID(maintainer, 100, 0x01, "low")

	// Order independence: lowest event id must win either way.
	for _, events := range [][]nostr.Event{{high, low}, {low, high}} {
		got := selectLatestState(events, set)
		if got == nil || got.ID != low.ID {
			t.Fatalf("expected lexically-lowest id to win equal timestamps, got %+v", got)
		}
	}
}

func TestSelectLatestStateRequiresMaintainerSigner(t *testing.T) {
	maintainer := nostr.Generate().Public()
	stranger := nostr.Generate().Public()
	set := map[string]struct{}{maintainer.Hex(): {}}

	authorized := stateEventWithID(maintainer, 100, 0x01, "ok")
	unauthorized := stateEventWithID(stranger, 999, 0x02, "evil")

	got := selectLatestState([]nostr.Event{authorized, unauthorized}, set)
	if got == nil || got.PubKey != maintainer {
		t.Fatalf("expected non-maintainer state to be ignored, got %+v", got)
	}

	if got := selectLatestState([]nostr.Event{unauthorized}, set); got != nil {
		t.Fatalf("expected nil when only non-maintainer states exist, got %+v", got)
	}
}

func TestExtractMaintainersUsesWinningAnnouncementPerPubkey(t *testing.T) {
	owner := nostr.Generate().Public()
	alice := nostr.Generate().Public()

	withMaintainer := nostr.Event{
		Kind: nostr.KindRepositoryAnnouncement, PubKey: owner, CreatedAt: 100,
		Tags: nostr.Tags{{"d", "repo1"}, {"maintainers", alice.Hex()}},
	}
	// Newer replacement announcement drops alice.
	withoutMaintainer := nostr.Event{
		Kind: nostr.KindRepositoryAnnouncement, PubKey: owner, CreatedAt: 200,
		Tags: nostr.Tags{{"d", "repo1"}},
	}

	// Order independence: the newer announcement must govern either way.
	for _, events := range [][]nostr.Event{
		{withMaintainer, withoutMaintainer},
		{withoutMaintainer, withMaintainer},
	} {
		maintainers, err := extractMaintainers(events, owner.Hex(), "repo1")
		if err != nil {
			t.Fatalf("extractMaintainers: %v", err)
		}
		if len(maintainers) != 1 || maintainers[0] != owner.Hex() {
			t.Fatalf("expected stale maintainer grant to be superseded, got %v", maintainers)
		}
	}
}

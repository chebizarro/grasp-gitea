package nostrauthz

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func signedAnnouncement(t *testing.T, signer nostr.SecretKey, repoID string, maintainers ...nostr.PubKey) nostr.Event {
	t.Helper()
	tags := nostr.Tags{{"d", repoID}}
	for _, maintainer := range maintainers {
		tags = append(tags, nostr.Tag{"maintainers", maintainer.Hex()})
	}
	ev := nostr.Event{
		PubKey:    signer.Public(),
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      nostr.KindRepositoryAnnouncement,
		Tags:      tags,
	}
	if err := ev.Sign(signer); err != nil {
		t.Fatalf("sign announcement: %v", err)
	}
	return ev
}

func TestResolverAuthorizesOwnerAndRecursiveMaintainers(t *testing.T) {
	owner := nostr.Generate()
	alice := nostr.Generate()
	bob := nostr.Generate()
	stranger := nostr.Generate()
	repoID := "project"
	coord := fmt.Sprintf("%d:%s:%s", nostr.KindRepositoryAnnouncement, owner.Public().Hex(), repoID)

	resolver := NewResolver([]nostr.Event{
		signedAnnouncement(t, owner, repoID, alice.Public()),
		signedAnnouncement(t, alice, repoID, bob.Public()),
		signedAnnouncement(t, bob, repoID),
	})
	for _, pubkey := range []string{owner.Public().Hex(), alice.Public().Hex(), bob.Public().Hex()} {
		ok, err := resolver.IsAuthorized(pubkey, coord)
		if err != nil || !ok {
			t.Fatalf("IsAuthorized(%s) = %v, %v; want true", pubkey, ok, err)
		}
	}
	if ok, err := resolver.IsAuthorized(stranger.Public().Hex(), coord); err != nil || ok {
		t.Fatalf("stranger authorization = %v, %v; want false, nil", ok, err)
	}
}

func TestResolverIgnoresInvalidAnnouncements(t *testing.T) {
	owner := nostr.Generate()
	attacker := nostr.Generate()
	repoID := "project"
	invalidOwner := nostr.Event{
		PubKey: owner.Public(),
		Kind:   nostr.KindRepositoryAnnouncement,
		Tags:   nostr.Tags{{"d", repoID}, {"maintainers", attacker.Public().Hex()}},
	}
	coord := fmt.Sprintf("%d:%s:%s", nostr.KindRepositoryAnnouncement, owner.Public().Hex(), repoID)

	_, err := NewResolver([]nostr.Event{invalidOwner}).Resolve(coord)
	if !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrAuthorityUnavailable", err)
	}
}

func TestParseRepositoryCoordinate(t *testing.T) {
	owner := nostr.Generate().Public()
	raw := fmt.Sprintf("%d:%s:repo:with:colons", nostr.KindRepositoryAnnouncement, owner.Hex())
	coord, err := ParseRepositoryCoordinate(raw)
	if err != nil {
		t.Fatalf("ParseRepositoryCoordinate: %v", err)
	}
	if coord.OwnerPubkey != owner.Hex() || coord.RepoID != "repo:with:colons" || coord.String() != raw {
		t.Fatalf("coordinate = %#v (%q), want %q", coord, coord.String(), raw)
	}
	if _, err := ParseRepositoryCoordinate("1:" + owner.Hex() + ":repo"); !errors.Is(err, ErrInvalidCoordinate) {
		t.Fatalf("wrong-kind error = %v, want ErrInvalidCoordinate", err)
	}
}

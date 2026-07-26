// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package nostrauthz resolves NIP-34 repository ownership and maintainer
// authority from cryptographically valid repository announcements.
package nostrauthz

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

var (
	// ErrInvalidCoordinate reports a malformed or non-repository Nostr address.
	ErrInvalidCoordinate = errors.New("invalid repository coordinate")
	// ErrAuthorityUnavailable reports that no valid owner announcement was
	// available for the requested repository.
	ErrAuthorityUnavailable = errors.New("repository authority unavailable")
	// ErrUnauthorized reports a signer that is not in the resolved owner and
	// recursive maintainer set.
	ErrUnauthorized = errors.New("repository state signer is unauthorized")
	// ErrAmbiguousRepository reports that an event is authorized for more than
	// one repository and its signed hints do not select exactly one of them.
	ErrAmbiguousRepository = errors.New("ambiguous repository authority")
)

// RepositoryCoordinate is a validated NIP-34 repository address.
type RepositoryCoordinate struct {
	OwnerPubkey string
	RepoID      string
}

// ParseRepositoryCoordinate validates a NIP-34 repository coordinate in the
// form 30617:<owner-pubkey>:<repository-id>.
func ParseRepositoryCoordinate(raw string) (RepositoryCoordinate, error) {
	parts := strings.SplitN(strings.TrimSpace(raw), ":", 3)
	if len(parts) != 3 {
		return RepositoryCoordinate{}, fmt.Errorf("%w: expected kind:pubkey:identifier", ErrInvalidCoordinate)
	}
	kind, err := strconv.Atoi(parts[0])
	if err != nil || kind != int(nostr.KindRepositoryAnnouncement) {
		return RepositoryCoordinate{}, fmt.Errorf("%w: kind must be %d", ErrInvalidCoordinate, nostr.KindRepositoryAnnouncement)
	}
	pk, err := nostr.PubKeyFromHex(parts[1])
	if err != nil {
		return RepositoryCoordinate{}, fmt.Errorf("%w: invalid owner pubkey: %v", ErrInvalidCoordinate, err)
	}
	repoID := strings.TrimSpace(parts[2])
	if repoID == "" {
		return RepositoryCoordinate{}, fmt.Errorf("%w: empty repository identifier", ErrInvalidCoordinate)
	}
	return RepositoryCoordinate{OwnerPubkey: pk.Hex(), RepoID: repoID}, nil
}

// String returns the canonical NIP-34 repository coordinate.
func (c RepositoryCoordinate) String() string {
	return fmt.Sprintf("%d:%s:%s", nostr.KindRepositoryAnnouncement, c.OwnerPubkey, c.RepoID)
}

// Authority is the resolved owner and recursive maintainer set for a repository.
// Maintainers is ordered owner-first and returned as a defensive copy by Resolve.
type Authority struct {
	Coordinate  RepositoryCoordinate
	Maintainers []string
	members     map[string]struct{}
}

// IsAuthorized reports whether pubkey belongs to this resolved authority.
func (a Authority) IsAuthorized(pubkey string) bool {
	pk, err := nostr.PubKeyFromHex(strings.TrimSpace(pubkey))
	if err != nil {
		return false
	}
	_, ok := a.members[pk.Hex()]
	return ok
}

// Resolver is an immutable repository-authority resolver built from a caller-
// supplied event pool. Only validly signed kind:30617 announcements participate.
//
// Callers remain responsible for obtaining an authoritative event pool (for
// example, current relay announcements plus a provisioned owner's cached
// announcement). State-event p/a tags are routing hints and must not be added to
// this pool as authority.
type Resolver struct {
	announcements []nostr.Event
}

// NewResolver constructs a resolver from cryptographically valid repository
// announcements. Invalid, unsigned, and non-announcement events are ignored.
func NewResolver(events []nostr.Event) *Resolver {
	announcements := make([]nostr.Event, 0, len(events))
	for i := range events {
		ev := events[i]
		if ev.Kind != nostr.KindRepositoryAnnouncement {
			continue
		}
		if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
			continue
		}
		ev.Tags = cloneTags(ev.Tags)
		announcements = append(announcements, ev)
	}
	return &Resolver{announcements: announcements}
}

// Resolve returns the validated owner and recursive maintainer authority for
// repoCoord. The owner's valid announcement is required.
func (r *Resolver) Resolve(repoCoord string) (Authority, error) {
	coord, err := ParseRepositoryCoordinate(repoCoord)
	if err != nil {
		return Authority{}, err
	}
	if r == nil {
		return Authority{}, fmt.Errorf("%w: nil resolver", ErrAuthorityUnavailable)
	}
	maintainers, err := nostrstate.Maintainers(r.announcements, coord.OwnerPubkey, coord.RepoID)
	if err != nil {
		return Authority{}, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
	}
	members := make(map[string]struct{}, len(maintainers))
	out := make([]string, 0, len(maintainers))
	for _, maintainer := range maintainers {
		pk, err := nostr.PubKeyFromHex(maintainer)
		if err != nil {
			continue
		}
		canonical := pk.Hex()
		if _, exists := members[canonical]; exists {
			continue
		}
		members[canonical] = struct{}{}
		out = append(out, canonical)
	}
	if _, ok := members[coord.OwnerPubkey]; !ok {
		return Authority{}, fmt.Errorf("%w: owner is absent", ErrAuthorityUnavailable)
	}
	return Authority{Coordinate: coord, Maintainers: out, members: members}, nil
}

// IsAuthorized resolves repoCoord and reports whether pubkey belongs to its
// owner and recursive maintainer set. A false result with a nil error means the
// coordinate was resolved but the signer is not authorized.
func (r *Resolver) IsAuthorized(pubkey, repoCoord string) (bool, error) {
	pk, err := nostr.PubKeyFromHex(strings.TrimSpace(pubkey))
	if err != nil {
		return false, fmt.Errorf("invalid signer pubkey: %w", err)
	}
	authority, err := r.Resolve(repoCoord)
	if err != nil {
		return false, err
	}
	_, ok := authority.members[pk.Hex()]
	return ok, nil
}

func cloneTags(tags nostr.Tags) nostr.Tags {
	out := make(nostr.Tags, len(tags))
	for i, tag := range tags {
		out[i] = append(nostr.Tag(nil), tag...)
	}
	return out
}

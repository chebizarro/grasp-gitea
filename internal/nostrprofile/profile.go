// Package nostrprofile fetches and parses Nostr kind:0 metadata events.
// Used to sync a user's Nostr identity (display name, avatar, bio, website)
// into their Gitea profile on first provision or NIP-07 login.
package nostrprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

// ErrProfileNotFound means no valid kind:0 event was found for the pubkey on
// any relay. It is distinct from a relay connection/subscription failure.
var ErrProfileNotFound = errors.New("no kind:0 profile found")

// Snapshot is a parsed kind:0 profile plus the event metadata a caller needs
// to deduplicate (replaceable-event semantics: newest created_at wins).
type Snapshot struct {
	Profile   Profile
	EventID   string
	CreatedAt int64
}

// Profile holds the fields from a Nostr kind:0 metadata event that are
// relevant for Gitea profile sync.
type Profile struct {
	Name        string // "name" — short handle
	DisplayName string // "display_name" — full display name → Gitea full_name
	Picture     string // "picture" — avatar image URL
	About       string // "about" — bio → Gitea description
	Website     string // "website" — → Gitea website
	NIP05       string // "nip05" — verified identifier
}

// IsEmpty returns true if no meaningful profile fields are populated.
func (p Profile) IsEmpty() bool {
	return p.DisplayName == "" && p.Picture == "" && p.About == "" && p.Website == ""
}

// Fetch returns the parsed Profile only, for callers that do not need event
// metadata. It delegates to FetchLatest and maps ErrProfileNotFound to a nil
// profile for backward compatibility.
func Fetch(ctx context.Context, pubkey string, relayURLs []string) (*Profile, error) {
	snap, err := FetchLatest(ctx, pubkey, relayURLs)
	if errors.Is(err, ErrProfileNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := snap.Profile
	return &p, nil
}

// FetchLatest queries every relay and returns the highest-created_at verified
// kind:0 event, with its id and timestamp. Event id breaks a created_at tie
// deterministically. Returns ErrProfileNotFound when no relay yielded a valid
// profile but at least one was reachable; a wrapped transport error when
// every relay failed to connect.
func FetchLatest(ctx context.Context, pubkey string, relayURLs []string) (Snapshot, error) {
	if len(relayURLs) == 0 {
		return Snapshot{}, fmt.Errorf("no relay URLs provided")
	}
	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse pubkey: %w", err)
	}

	var best *Snapshot
	var lastErr error
	reachable := false
	for _, relayURL := range relayURLs {
		snap, err := fetchSnapshotFromRelay(ctx, pk, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		reachable = true
		if snap == nil {
			continue // reachable, but no profile stored here
		}
		if best == nil || snap.CreatedAt > best.CreatedAt ||
			(snap.CreatedAt == best.CreatedAt && snap.EventID > best.EventID) {
			best = snap
		}
	}

	if best != nil {
		return *best, nil
	}
	if reachable {
		return Snapshot{}, ErrProfileNotFound
	}
	return Snapshot{}, fmt.Errorf("fetch kind:0 from all relays: %w", lastErr)
}

func fetchSnapshotFromRelay(ctx context.Context, pk nostr.PubKey, relayURL string) (*Snapshot, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	relay, err := nostr.RelayConnect(fetchCtx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", relayURL, err)
	}
	defer relay.Close()

	filter := nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{0},
		Limit:   1,
	}

	sub, err := relay.Subscribe(fetchCtx, filter, nostr.SubscriptionOptions{Label: "profile-sync"})
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	defer sub.Unsub()

	select {
	case ev := <-sub.Events:
		if ev.Kind != 0 {
			return nil, fmt.Errorf("relay %s returned kind %d for kind-0 query", relayURL, ev.Kind)
		}
		if ev.PubKey != pk {
			return nil, fmt.Errorf("relay %s returned kind-0 event for unexpected author %s", relayURL, ev.PubKey.Hex())
		}
		if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
			return nil, fmt.Errorf("relay %s returned invalid kind-0 event: %w", relayURL, err)
		}
		p, err := parse(ev.Content)
		if err != nil {
			return nil, err
		}
		return &Snapshot{Profile: *p, EventID: ev.ID.Hex(), CreatedAt: int64(ev.CreatedAt)}, nil
	case <-sub.EndOfStoredEvents:
		return nil, nil // reachable, no kind:0 stored here
	case <-fetchCtx.Done():
		return nil, fmt.Errorf("timeout waiting for kind:0 from %s", relayURL)
	}
}

// kind0Content is the JSON structure of a Nostr kind:0 event content.
type kind0Content struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Picture     string `json:"picture"`
	About       string `json:"about"`
	Website     string `json:"website"`
	NIP05       string `json:"nip05"`
	// lud06/lud16 are intentionally omitted — not relevant for Gitea sync.
}

func parse(content string) (*Profile, error) {
	var c kind0Content
	if err := json.Unmarshal([]byte(content), &c); err != nil {
		return nil, fmt.Errorf("parse kind:0 content: %w", err)
	}
	p := &Profile{
		Name:        c.Name,
		DisplayName: c.DisplayName,
		Picture:     c.Picture,
		About:       c.About,
		Website:     c.Website,
		NIP05:       c.NIP05,
	}
	// Fall back to name if display_name is not set.
	if p.DisplayName == "" {
		p.DisplayName = p.Name
	}
	return p, nil
}

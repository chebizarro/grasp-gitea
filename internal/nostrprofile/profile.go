// Package nostrprofile fetches and parses Nostr kind:0 metadata events.
// Used to sync a user's Nostr identity (display name, avatar, bio, website)
// into their Gitea profile on first provision or NIP-07 login.
package nostrprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

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

// Fetch fetches the most recent kind:0 event for pubkey from any of the
// provided relay URLs and returns a parsed Profile. Returns nil if no event
// is found within the timeout.
func Fetch(ctx context.Context, pubkey string, relayURLs []string) (*Profile, error) {
	if len(relayURLs) == 0 {
		return nil, fmt.Errorf("no relay URLs provided")
	}

	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}

	// Try each relay in order, return on first successful fetch.
	var lastErr error
	for _, relayURL := range relayURLs {
		p, err := fetchFromRelay(ctx, pk, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		return p, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("fetch kind:0 from all relays: %w", lastErr)
	}
	return nil, nil
}

func fetchFromRelay(ctx context.Context, pk nostr.PubKey, relayURL string) (*Profile, error) {
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
		return parse(ev.Content)
	case <-sub.EndOfStoredEvents:
		return nil, nil // no kind:0 stored on this relay
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

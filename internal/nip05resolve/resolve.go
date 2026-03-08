package nip05resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip05"
)

var validOrgName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// OrgName resolves a short, Gitea-safe org name for a given pubkey.
//
// Strategy:
//  1. Fetch the user's kind 0 (profile) event from the relay.
//  2. Parse the "nip05" field from the profile content.
//  3. Verify the NIP-05 identifier maps back to this pubkey.
//  4. Return the sanitized local-part (e.g. "bizarro" from "bizarro@sharegap.net").
//
// Fallback: if no valid NIP-05 is found, returns the first 39 hex chars of the
// pubkey — always unique, always within Gitea's 40-char limit.
func OrgName(ctx context.Context, pubkey string, relayURL string) string {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	name, err := resolve(ctx, pubkey, relayURL)
	if err != nil || name == "" {
		// Fallback: hex prefix (39 chars, unique per key, always valid)
		if len(pubkey) >= 39 {
			return pubkey[:39]
		}
		return pubkey
	}
	return name
}

func resolve(ctx context.Context, pubkey string, relayURL string) (string, error) {
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return "", fmt.Errorf("connect to relay: %w", err)
	}
	defer relay.Close()

	filters := nostr.Filters{{
		Authors: []string{pubkey},
		Kinds:   []int{0},
		Limit:   1,
	}}

	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		return "", fmt.Errorf("subscribe for kind 0: %w", err)
	}
	defer sub.Unsub()

	var ev *nostr.Event
	select {
	case e := <-sub.Events:
		ev = e
	case <-ctx.Done():
		return "", fmt.Errorf("timeout waiting for kind 0")
	}

	if ev == nil {
		return "", fmt.Errorf("no kind 0 event found")
	}

	var profile struct {
		NIP05 string `json:"nip05"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &profile); err != nil {
		return "", fmt.Errorf("parse profile content: %w", err)
	}
	if profile.NIP05 == "" {
		return "", fmt.Errorf("no nip05 in profile")
	}

	localPart, _, err := nip05.ParseIdentifier(profile.NIP05)
	if err != nil {
		return "", fmt.Errorf("parse nip05 identifier: %w", err)
	}

	// Verify the NIP-05 identifier resolves back to this pubkey.
	pointer, err := nip05.QueryIdentifier(ctx, profile.NIP05)
	if err != nil {
		return "", fmt.Errorf("verify nip05: %w", err)
	}
	if pointer.PublicKey != pubkey {
		return "", fmt.Errorf("nip05 pubkey mismatch")
	}

	return sanitize(localPart), nil
}

// sanitize converts a NIP-05 local-part to a Gitea-safe username:
//   - lowercase
//   - replace disallowed chars with '-'
//   - strip leading/trailing hyphens
//   - truncate to 39 chars (within Gitea's 40-char API limit)
func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	result := strings.Trim(b.String(), "-.")
	if len(result) > 39 {
		result = result[:39]
	}
	if result == "" {
		return ""
	}
	return result
}

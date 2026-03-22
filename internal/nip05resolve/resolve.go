package nip05resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip05"
)

var validOrgName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// OrgName resolves a short, Gitea-safe org name for a given pubkey (hex string).
func OrgName(ctx context.Context, pubkey string, relayURL string) string {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	name, err := resolve(ctx, pubkey, relayURL)
	if err != nil || name == "" {
		if len(pubkey) >= 39 {
			return pubkey[:39]
		}
		return pubkey
	}
	return name
}

func resolve(ctx context.Context, pubkey string, relayURL string) (string, error) {
	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return "", fmt.Errorf("parse pubkey: %w", err)
	}

	relay, err := nostr.RelayConnect(ctx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return "", fmt.Errorf("connect to relay: %w", err)
	}
	defer relay.Close()

	filter := nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{0},
		Limit:   1,
	}

	sub, err := relay.Subscribe(ctx, filter, nostr.SubscriptionOptions{Label: "nip05"})
	if err != nil {
		return "", fmt.Errorf("subscribe for kind 0: %w", err)
	}

	var ev *nostr.Event
	select {
	case e := <-sub.Events:
		copy := e
		ev = &copy
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

	pointer, err := nip05.QueryIdentifier(ctx, profile.NIP05)
	if err != nil {
		return "", fmt.Errorf("verify nip05: %w", err)
	}
	if pointer.PublicKey.Hex() != pubkey {
		return "", fmt.Errorf("nip05 pubkey mismatch")
	}

	return sanitize(localPart), nil
}

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

// ResolveFromPubkey is kept for compatibility — same as OrgName but returns error.
func ResolveFromPubkey(ctx context.Context, pubkey string) (string, error) {
	_ = validOrgName // keep for future validation use
	return resolve(ctx, pubkey, "")
}

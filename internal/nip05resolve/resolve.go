// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip05"
)

// resolveTimeout is the per-relay timeout for NIP-05 resolution.
const resolveTimeout = 8 * time.Second

// cacheEntry holds a cached org name resolution result.
type cacheEntry struct {
	orgName   string
	expiresAt time.Time
}

// Resolver caches NIP-05 org name lookups to avoid repeated relay+HTTP
// round-trips for the same pubkey.
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]cacheEntry
	cacheTTL time.Duration
}

// NewResolver creates a Resolver with the given cache TTL.
// A TTL of 0 disables caching.
func NewResolver(cacheTTL time.Duration) *Resolver {
	return &Resolver{
		cache:    make(map[string]cacheEntry),
		cacheTTL: cacheTTL,
	}
}

// ResolveOrgName resolves a short, Gitea-safe org name for a given pubkey.
//
// It tries each relay in order. The first relay that returns a verified
// NIP-05 name wins. If ALL relays fail or return no NIP-05, returns the
// hex prefix fallback.
//
// Results (including failures) are cached by pubkey for the configured TTL.
func (r *Resolver) ResolveOrgName(ctx context.Context, pubkey string, relayURLs []string) string {
	// Check cache first.
	if r.cacheTTL > 0 {
		r.mu.RLock()
		entry, ok := r.cache[pubkey]
		r.mu.RUnlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return entry.orgName
		}
	}

	// Try each relay in order until one succeeds with a real NIP-05 name.
	var lastErr error
	for _, relayURL := range relayURLs {
		name, err := resolveFromRelay(ctx, pubkey, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		if name != "" {
			r.cacheResult(pubkey, name)
			return name
		}
	}

	// All relays failed or returned no NIP-05. Use hex prefix fallback.
	_ = lastErr // logged by caller if needed
	fallback := hexFallback(pubkey)
	r.cacheResult(pubkey, fallback)
	return fallback
}

// CacheSize returns the number of entries in the cache (for testing/metrics).
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

func (r *Resolver) cacheResult(pubkey string, orgName string) {
	if r.cacheTTL <= 0 {
		return
	}
	r.mu.Lock()
	r.cache[pubkey] = cacheEntry{
		orgName:   orgName,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()
}

// resolveFromRelay connects to a single relay and attempts NIP-05 resolution.
// Returns ("", nil) if the profile exists but has no NIP-05 or it doesn't verify.
// Returns ("", err) on connection/subscription failure.
func resolveFromRelay(ctx context.Context, pubkey string, relayURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return "", fmt.Errorf("connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()

	sub, err := relay.Subscribe(ctx, nostr.Filters{{
		Authors: []string{pubkey},
		Kinds:   []int{0},
		Limit:   1,
	}})
	if err != nil {
		return "", fmt.Errorf("subscribe for kind 0 on %s: %w", relayURL, err)
	}
	defer sub.Unsub()

	var ev *nostr.Event
	select {
	case e := <-sub.Events:
		ev = e
	case <-ctx.Done():
		return "", fmt.Errorf("timeout waiting for kind 0 from %s", relayURL)
	}

	if ev == nil {
		return "", nil // no profile on this relay
	}

	var profile struct {
		NIP05 string `json:"nip05"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &profile); err != nil {
		return "", nil // malformed profile, not a connection error
	}
	if profile.NIP05 == "" {
		return "", nil // profile exists but no NIP-05 set
	}

	localPart, _, err := nip05.ParseIdentifier(profile.NIP05)
	if err != nil {
		return "", nil // invalid NIP-05 format
	}

	// Verify the NIP-05 identifier resolves back to this pubkey.
	pointer, err := nip05.QueryIdentifier(ctx, profile.NIP05)
	if err != nil {
		return "", nil // verification failed, not a relay error
	}
	if pointer.PublicKey != pubkey {
		return "", nil // NIP-05 points to a different pubkey
	}

	name := sanitize(localPart)
	if name == "" {
		return "", nil
	}
	return name, nil
}

// hexFallback returns the first 39 hex chars of a pubkey.
// Always unique per key, always within Gitea's 40-char API limit.
func hexFallback(pubkey string) string {
	if len(pubkey) > 39 {
		return pubkey[:39]
	}
	return pubkey
}

// sanitize converts a NIP-05 local-part to a Gitea-safe username:
//   - lowercase
//   - replace disallowed chars with '-'
//   - strip leading/trailing hyphens/dots
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
	return result
}

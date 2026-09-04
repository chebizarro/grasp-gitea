// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05resolve

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip05"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/safefetch"
)

// resolveTimeout is the per-relay timeout for NIP-05 resolution.
const resolveTimeout = 8 * time.Second

var nip05HTTPClient = safefetch.NewClient()

// cacheEntry holds a cached org name resolution result.
type cacheEntry struct {
	orgName   string
	nip05     string
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
		name, nip05, err := resolveFromRelay(ctx, pubkey, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		if name != "" {
			r.cacheResult(pubkey, name, nip05)
			return name
		}
	}

	// All relays failed or returned no NIP-05. Use hex prefix fallback.
	_ = lastErr // logged by caller if needed
	fallback := hexFallback(pubkey)
	r.cacheResult(pubkey, fallback, "")
	return fallback
}

// ResolveNIP05 resolves the original NIP-05 identifier for a given pubkey.
func (r *Resolver) ResolveNIP05(ctx context.Context, pubkey string, relayURLs []string) string {
	// ResolveOrgName handles the heavy lifting and caching.
	r.ResolveOrgName(ctx, pubkey, relayURLs)

	// Return the cached NIP-05 identifier.
	r.mu.RLock()
	entry, ok := r.cache[pubkey]
	r.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.nip05
	}
	return ""
}

// CacheSize returns the number of entries in the cache (for testing/metrics).
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

func (r *Resolver) cacheResult(pubkey string, orgName string, nip05 string) {
	if r.cacheTTL <= 0 {
		return
	}
	r.mu.Lock()
	r.cache[pubkey] = cacheEntry{
		orgName:   orgName,
		nip05:     nip05,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()
}

// resolveFromRelay connects to a single relay and attempts NIP-05 resolution.
// Returns ("", "", nil) if the profile exists but has no NIP-05 or it doesn't verify.
// Returns ("", "", err) on connection/subscription failure.
func resolveFromRelay(ctx context.Context, pubkey string, relayURL string) (string, string, error) {
	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return "", "", fmt.Errorf("invalid pubkey %q: %w", pubkey, err)
	}

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	relay, err := nostr.RelayConnect(ctx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return "", "", fmt.Errorf("connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()

	sub, err := relay.Subscribe(ctx, nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{0},
		Limit:   1,
	}, nostr.SubscriptionOptions{})
	if err != nil {
		return "", "", fmt.Errorf("subscribe for kind 0 on %s: %w", relayURL, err)
	}
	defer sub.Unsub()

	var ev *nostr.Event
	select {
	case e := <-sub.Events:
		ev = &e
	case <-ctx.Done():
		return "", "", fmt.Errorf("timeout waiting for kind 0 from %s", relayURL)
	}

	if ev == nil {
		return "", "", nil // no profile on this relay
	}
	if ev.Kind != 0 {
		return "", "", fmt.Errorf("relay %s returned kind %d for kind-0 query", relayURL, ev.Kind)
	}
	if ev.PubKey != pk {
		return "", "", fmt.Errorf("relay %s returned kind-0 event for unexpected author %s", relayURL, ev.PubKey.Hex())
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return "", "", nil // verification failed, not a relay error
	}

	var profile struct {
		NIP05 string `json:"nip05"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &profile); err != nil {
		return "", "", nil // malformed profile, not a connection error
	}
	if profile.NIP05 == "" {
		return "", "", nil // profile exists but no NIP-05 set
	}

	localPart, domain, err := nip05.ParseIdentifier(profile.NIP05)
	if err != nil {
		return "", "", nil // invalid NIP-05 format
	}

	// Verify the NIP-05 identifier resolves back to this pubkey. The domain is
	// attacker-controlled profile content, so the well-known request must use
	// the same guarded egress policy as avatar downloads.
	if err := verifyIdentifier(ctx, localPart, domain, pk); err != nil {
		return "", "", nil // verification failed, not a relay error
	}

	name := qualifiedName(localPart, domain, pubkey)
	if name == "" {
		return "", "", nil
	}
	return name, profile.NIP05, nil
}

func verifyIdentifier(ctx context.Context, localPart, domain string, expected nostr.PubKey) error {
	u := url.URL{Scheme: "https", Host: domain, Path: "/.well-known/nostr.json"}
	q := u.Query()
	q.Set("name", localPart)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := nip05HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NIP-05 endpoint returned HTTP %d", resp.StatusCode)
	}

	const maxResponseSize = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseSize {
		return fmt.Errorf("NIP-05 response exceeds %d-byte limit", resp.StatusCode)
	}

	var result nip05.WellKnownResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return err
	}
	resolved, ok := result.Names[localPart]
	if !ok {
		return fmt.Errorf("NIP-05 response has no entry for %q", localPart)
	}
	if resolved != expected {
		return fmt.Errorf("NIP-05 identifier resolves to a different pubkey")
	}
	return nil
}

// qualifiedName creates a stable, visibly domain-qualified Gitea namespace.
// Fixed component budgets ensure truncation can never discard the domain, while
// the 80-bit identity suffix prevents practical collisions and NIP-05
// reassignment from taking over a namespace owned by a different key.
func qualifiedName(localPart, domain, pubkey string) string {
	canonicalDomain := strings.ToLower(strings.TrimSuffix(domain, "."))
	localComponent := truncateComponent(sanitize(localPart), 8)
	domainComponent := truncateComponent(sanitize(canonicalDomain), 9)
	if localComponent == "" {
		localComponent = "user"
	}
	if domainComponent == "" {
		domainComponent = "domain"
	}

	canonicalIdentifier := strings.ToLower(localPart) + "@" + canonicalDomain
	sum := sha256.Sum256([]byte(canonicalIdentifier + "\x00" + strings.ToLower(pubkey)))
	return localComponent + "-" + domainComponent + fmt.Sprintf("-%x", sum[:10])
}

func truncateComponent(value string, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.Trim(value, "-.")
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

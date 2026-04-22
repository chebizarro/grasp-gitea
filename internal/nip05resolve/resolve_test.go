// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05resolve

import (
	"context"
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"bizarro", "bizarro"},
		{"Bizarro", "bizarro"},
		{"user@domain", "user-domain"},
		{"hello world", "hello-world"},
		{"-leading", "leading"},
		{"trailing-", "trailing"},
		{".dotted.", "dotted"},
		{"a.b_c-d", "a.b_c-d"},
		{"", ""},
		{"a", "a"},
		// Truncation to 39 chars.
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}

	for _, tt := range tests {
		got := sanitize(tt.input)
		if got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHexFallback(t *testing.T) {
	short := "deadbeef"
	if got := hexFallback(short); got != short {
		t.Errorf("hexFallback(%q) = %q, want %q", short, got, short)
	}

	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got := hexFallback(long); len(got) != 39 {
		t.Errorf("hexFallback(64-char) should be 39 chars, got %d", len(got))
	}
}

func TestResolverCacheHit(t *testing.T) {
	r := NewResolver(1 * time.Minute)

	// Pre-populate the cache.
	r.cacheResult("pubkey1", "cached-org")

	// ResolveOrgName should return the cached value without trying any relays.
	// (We pass no relay URLs, so if it tries to connect it will just fall through.)
	got := r.ResolveOrgName(context.Background(), "pubkey1", nil)
	if got != "cached-org" {
		t.Errorf("expected cached value 'cached-org', got %q", got)
	}
}

func TestResolverCacheExpiry(t *testing.T) {
	r := NewResolver(1 * time.Millisecond)

	r.cacheResult("pubkey1", "cached-org")
	time.Sleep(5 * time.Millisecond)

	// Cache should be expired. With no relays, falls back to hex.
	got := r.ResolveOrgName(context.Background(), "pubkey1", nil)
	if got != "pubkey1" {
		t.Errorf("expected hex fallback after cache expiry, got %q", got)
	}
}

func TestResolverFallbackWhenNoRelays(t *testing.T) {
	r := NewResolver(1 * time.Minute)

	// No relays → hex fallback.
	got := r.ResolveOrgName(context.Background(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	if len(got) != 39 {
		t.Errorf("expected 39-char hex fallback, got %d chars: %q", len(got), got)
	}
}

func TestResolverFallbackCached(t *testing.T) {
	r := NewResolver(1 * time.Minute)

	// First call: no relays, falls back to hex.
	pubkey := "deadbeefdeadbeef"
	r.ResolveOrgName(context.Background(), pubkey, nil)

	// Second call: should hit cache.
	if r.CacheSize() != 1 {
		t.Errorf("expected 1 cache entry, got %d", r.CacheSize())
	}

	got := r.ResolveOrgName(context.Background(), pubkey, nil)
	if got != pubkey {
		t.Errorf("expected %q from cache, got %q", pubkey, got)
	}
}

func TestResolverCacheDisabledWhenTTLZero(t *testing.T) {
	r := NewResolver(0)

	r.ResolveOrgName(context.Background(), "pubkey1", nil)

	if r.CacheSize() != 0 {
		t.Errorf("expected 0 cache entries with TTL=0, got %d", r.CacheSize())
	}
}

func TestResolverFailedRelayTriesNext(t *testing.T) {
	r := NewResolver(1 * time.Minute)

	// Pass unreachable relay URLs. The resolver should try each, fail,
	// and eventually fall back to hex.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := r.ResolveOrgName(ctx, "aabbccdd", []string{
		"ws://127.0.0.1:19999", // unreachable
		"ws://127.0.0.1:19998", // also unreachable
	})
	if got != "aabbccdd" {
		t.Errorf("expected hex fallback after all relays fail, got %q", got)
	}
}

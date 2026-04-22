// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package main

import (
	"testing"
)

func TestMergeRelayURLsEmpty(t *testing.T) {
	result := mergeRelayURLs(nil, "")
	if len(result) != 0 {
		t.Errorf("expected 0 URLs, got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsNoEmbedded(t *testing.T) {
	configured := []string{"wss://r1", "wss://r2"}
	result := mergeRelayURLs(configured, "")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[0] != "wss://r1" || result[1] != "wss://r2" {
		t.Errorf("unexpected URLs: %v", result)
	}
}

func TestMergeRelayURLsAppendsEmbedded(t *testing.T) {
	configured := []string{"wss://external"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[1] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL appended, got %v", result)
	}
}

func TestMergeRelayURLsDeduplicates(t *testing.T) {
	configured := []string{"ws://localhost:3334", "wss://other"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Errorf("expected 2 URLs (no duplicate), got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsEmbeddedOnly(t *testing.T) {
	result := mergeRelayURLs(nil, "ws://localhost:3334")
	if len(result) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(result), result)
	}
	if result[0] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL, got %v", result)
	}
}

func TestMergeRelayURLsDoesNotMutateInput(t *testing.T) {
	configured := []string{"wss://r1"}
	original := make([]string, len(configured))
	copy(original, configured)

	_ = mergeRelayURLs(configured, "ws://localhost:3334")

	if len(configured) != len(original) {
		t.Error("mergeRelayURLs mutated the input slice")
	}
	if configured[0] != original[0] {
		t.Error("mergeRelayURLs mutated the input slice content")
	}
}

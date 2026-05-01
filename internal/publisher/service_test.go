// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"testing"
)

func TestComputeDigestDeterministic(t *testing.T) {
	branches := map[string]string{
		"main":    "abc123",
		"develop": "def456",
	}
	tags := map[string]string{
		"v1.0": "111aaa",
		"v2.0": "222bbb",
	}

	d1 := computeDigest("main", branches, tags)
	d2 := computeDigest("main", branches, tags)
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %s != %s", d1, d2)
	}
	if d1 == "" {
		t.Fatal("digest should not be empty")
	}
}

func TestComputeDigestChangesOnDifferentInput(t *testing.T) {
	b1 := map[string]string{"main": "abc123"}
	b2 := map[string]string{"main": "abc124"}

	d1 := computeDigest("main", b1, nil)
	d2 := computeDigest("main", b2, nil)
	if d1 == d2 {
		t.Fatal("different branches should produce different digests")
	}
}

func TestComputeDigestChangesOnDifferentHead(t *testing.T) {
	branches := map[string]string{"main": "abc123", "develop": "def456"}

	d1 := computeDigest("main", branches, nil)
	d2 := computeDigest("develop", branches, nil)
	if d1 == d2 {
		t.Fatal("different HEAD should produce different digests")
	}
}

func TestComputeDigestEmptyRepo(t *testing.T) {
	d := computeDigest("", nil, nil)
	if d == "" {
		t.Fatal("digest should not be empty even for empty repo")
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]string{
		"c": "3",
		"a": "1",
		"b": "2",
	}
	keys := sortedKeys(m)
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("keys not sorted: %v", keys)
	}
}

func TestSortedKeysEmpty(t *testing.T) {
	keys := sortedKeys(nil)
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestNewServiceNoNsec(t *testing.T) {
	svc, err := New("", nil, nil, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.Enabled() {
		t.Fatal("service should not be enabled without nsec")
	}
}

func TestNewServiceInvalidNsec(t *testing.T) {
	_, err := New("not-an-nsec", nil, nil, "/tmp", nil)
	if err == nil {
		t.Fatal("expected error for invalid nsec")
	}
}

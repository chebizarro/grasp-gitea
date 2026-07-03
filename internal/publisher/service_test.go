// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/relay"
)

func genNsec(t *testing.T) string {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	nsec, err := nip19.EncodePrivateKey(sk)
	if err != nil {
		t.Fatalf("encode nsec: %v", err)
	}
	return nsec
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func firstVal(ev *nostr.Event, key string) (string, bool) {
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1], true
		}
	}
	return "", false
}

func tagIndex(ev *nostr.Event, key string) int {
	for i, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == key {
			return i
		}
	}
	return -1
}

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

func TestBuildStateEventSignedAndStructured(t *testing.T) {
	svc, err := New(genNsec(t), nil, nil, "/tmp", discardLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	owner := "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"
	branches := map[string]string{
		"main": "1111111111111111111111111111111111111111",
		"dev":  "2222222222222222222222222222222222222222",
	}
	tags := map[string]string{"v1.0": "3333333333333333333333333333333333333333"}

	ev, err := svc.buildStateEvent(owner, "myrepo", "main", branches, tags)
	if err != nil {
		t.Fatalf("buildStateEvent: %v", err)
	}

	if ev.Kind != relay.KindRepositoryState {
		t.Errorf("kind = %d, want %d", ev.Kind, relay.KindRepositoryState)
	}
	// State events are owner-authored templates. They stay unsigned here so the
	// outbox can sign them with the owner's grant; bridge signing is only a
	// transition fallback in RepublishForGiteaRepo.
	if ev.PubKey != owner {
		t.Errorf("state event pubkey = %q, want owner pubkey %q", ev.PubKey, owner)
	}
	if ev.ID != "" || ev.Sig != "" {
		t.Errorf("state event should be unsigned, got id=%q sig=%q", ev.ID, ev.Sig)
	}

	want := map[string]string{
		"d":               "myrepo",
		"p":               owner,
		"refs/heads/main": branches["main"],
		"refs/heads/dev":  branches["dev"],
		"refs/tags/v1.0":  tags["v1.0"],
		"HEAD":            "ref: refs/heads/main",
	}
	for k, v := range want {
		got, ok := firstVal(ev, k)
		if !ok {
			t.Errorf("missing tag %q", k)
			continue
		}
		if got != v {
			t.Errorf("tag %q = %q, want %q", k, got, v)
		}
	}

	// Branch tags must be emitted in deterministic (sorted) order so the digest
	// and event content are stable across runs: dev before main.
	if di, mi := tagIndex(ev, "refs/heads/dev"), tagIndex(ev, "refs/heads/main"); di == -1 || mi == -1 || di > mi {
		t.Errorf("branch tags not in sorted order: dev@%d main@%d", di, mi)
	}
}

func TestBuildStateEventOmitsEmptyOwnerAndHead(t *testing.T) {
	svc, err := New(genNsec(t), nil, nil, "/tmp", discardLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ev, err := svc.buildStateEvent("", "repo", "", map[string]string{}, map[string]string{})
	if err != nil {
		t.Fatalf("buildStateEvent: %v", err)
	}

	if _, ok := firstVal(ev, "p"); ok {
		t.Error("empty owner pubkey should omit the 'p' tag")
	}
	if _, ok := firstVal(ev, "HEAD"); ok {
		t.Error("empty head should omit the 'HEAD' tag")
	}
	if v, _ := firstVal(ev, "d"); v != "repo" {
		t.Errorf("d tag = %q, want repo", v)
	}
	if ev.PubKey != "" {
		t.Errorf("empty owner pubkey should leave event pubkey empty, got %q", ev.PubKey)
	}
	if ev.ID != "" || ev.Sig != "" {
		t.Errorf("state event should be unsigned, got id=%q sig=%q", ev.ID, ev.Sig)
	}
}

func TestFetchEventNoRelays(t *testing.T) {
	svc, err := New("", nil, nil, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With no relay URLs configured, FetchEvent cannot query anything and
	// must surface an error rather than silently returning a nil event.
	ev, err := svc.FetchEvent(context.Background(), "deadbeef")
	if err == nil {
		t.Fatal("expected error when no relay URLs are configured")
	}
	if ev != nil {
		t.Fatalf("expected nil event on error, got %v", ev)
	}
}

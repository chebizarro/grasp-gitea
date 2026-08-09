package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip34"
)

func TestFetchProposedRepositoryState(t *testing.T) {
	key := nostr.Generate()
	event := nostr.Event{
		Kind:      nostr.KindRepositoryState,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"d", "demo"},
			{"refs/heads/main", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{"HEAD", "ref: refs/heads/main"},
		},
	}
	if err := event.Sign(key); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer hook-token" {
			t.Fatalf("authorization = %q", got)
		}
		if r.URL.Query().Get("pubkey") != key.Public().Hex() || r.URL.Query().Get("repo_id") != "demo" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"event": event})
	}))
	defer server.Close()
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("hook-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRASP_HOOK_ADMIN_URL", server.URL)
	t.Setenv("GRASP_HOOK_ADMIN_TOKEN_FILE", tokenFile)
	state, err := fetchProposedRepositoryState(t.Context(), key.Public().Hex(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if state.Branches["main"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected state: %#v", state)
	}
}

func TestDecodedPubkeyHexAcceptsTypedNIP19Result(t *testing.T) {
	key := nostr.Generate().Public()
	got, ok := decodedPubkeyHex(key)
	if !ok || got != key.Hex() {
		t.Fatalf("typed pubkey decode failed: got=%q ok=%v", got, ok)
	}
	if _, ok := decodedPubkeyHex(nostr.PubKey{}); ok {
		t.Fatal("zero typed pubkey accepted")
	}
}

func TestValidateRefAgainstState(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123"},
		Tags:     map[string]string{"v1.0.0": "def456"},
	}

	if ok, _ := validateRefAgainstState("refs/heads/main", "abc123", state); !ok {
		t.Fatalf("expected branch ref to pass")
	}

	if ok, _ := validateRefAgainstState("refs/tags/v1.0.0", "def456", state); !ok {
		t.Fatalf("expected tag ref to pass")
	}

	if ok, _ := validateRefAgainstState("refs/heads/main", "zzz999", state); ok {
		t.Fatalf("expected mismatched sha to fail")
	}

	if ok, _ := validateRefAgainstState("refs/heads/dev", "abc123", state); ok {
		t.Fatalf("expected unknown branch to fail")
	}
}

func TestEvaluatePushRefNostrAndPRPolicy(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123"},
	}

	if ok, _ := evaluatePushRef("refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc123", state, nil); !ok {
		t.Fatalf("expected valid refs/nostr event id to pass")
	}

	if ok, _ := evaluatePushRef("refs/nostr/not-a-valid-id", "abc123", state, nil); ok {
		t.Fatalf("expected invalid refs/nostr event id to fail")
	}

	if ok, _ := evaluatePushRef("refs/heads/pr/feature", "abc123", state, nil); ok {
		t.Fatalf("expected refs/heads/pr/* to fail")
	}
}

func TestRefDeletionSemantics(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123"},
		Tags:     map[string]string{"v1.0.0": "def456"},
	}

	// Deletion accepted when state omits the ref.
	if ok, _ := validateRefAgainstState("refs/heads/old-feature", zeroSHA, state); !ok {
		t.Fatalf("expected deletion of omitted branch to pass")
	}
	if ok, _ := validateRefAgainstState("refs/tags/v0.9.0", zeroSHA, state); !ok {
		t.Fatalf("expected deletion of omitted tag to pass")
	}

	// Deletion rejected while state still declares the ref.
	if ok, reason := validateRefAgainstState("refs/heads/main", zeroSHA, state); ok {
		t.Fatalf("expected deletion of declared branch to fail")
	} else if reason == "" {
		t.Fatalf("expected a rejection reason")
	}
	if ok, _ := validateRefAgainstState("refs/tags/v1.0.0", zeroSHA, state); ok {
		t.Fatalf("expected deletion of declared tag to fail")
	}
}

func TestAtomicMixedPushWithAdditionsUpdatesAndDeletions(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123", "feature": "fff000"},
		Tags:     map[string]string{"v1.1.0": "def456"},
	}

	// All updates authorized: update main, create feature, delete omitted refs.
	good := []pushUpdate{
		{refName: "refs/heads/main", newSHA: "abc123"},
		{refName: "refs/heads/feature", newSHA: "fff000"},
		{refName: "refs/heads/dead-branch", newSHA: zeroSHA},
		{refName: "refs/tags/v1.1.0", newSHA: "def456"},
		{refName: "refs/tags/v1.0.0", newSHA: zeroSHA},
	}
	if err := evaluatePushUpdates(good, state, nil); err != nil {
		t.Fatalf("expected mixed push to pass, got %v", err)
	}

	// One unauthorized deletion poisons the whole push.
	bad := append(good, pushUpdate{refName: "refs/heads/feature", newSHA: zeroSHA})
	if err := evaluatePushUpdates(bad, state, nil); err == nil {
		t.Fatalf("expected mixed push with declared-branch deletion to fail")
	}
}

func TestNostrRefRelayLookupIsKindAgnostic(t *testing.T) {
	eventID := nostr.MustIDFromHex(strings.Repeat("ab", 32))
	filter := nostrRefEventFilter(eventID)
	if len(filter.IDs) != 1 || filter.IDs[0] != eventID {
		t.Fatalf("unexpected event filter IDs: %#v", filter.IDs)
	}
	if len(filter.Kinds) != 0 {
		t.Fatalf("refs/nostr conflict lookup must not restrict event kinds: %#v", filter.Kinds)
	}
}

func TestNostrRefConflictRejectedDuringPreReceive(t *testing.T) {
	eventID := strings.Repeat("ab", 32)
	otherID := strings.Repeat("cd", 32)
	tip := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Checker simulating a relay event that declares a different tip for eventID.
	checker := func(id string, sha string) error {
		if id == eventID {
			return fmt.Errorf("push rejected: refs/nostr/%s conflicts with the relay event's declared tip", id)
		}
		return nil
	}

	// Conflicting push rejected in pre-receive.
	if ok, reason := evaluatePushRef("refs/nostr/"+eventID, tip, nil, checker); ok {
		t.Fatalf("expected conflicting refs/nostr push to be rejected")
	} else if !strings.Contains(reason, "conflicts") {
		t.Fatalf("expected conflict reason, got %q", reason)
	}

	// Valid ID without a conflicting relay event accepted.
	if ok, reason := evaluatePushRef("refs/nostr/"+otherID, tip, nil, checker); !ok {
		t.Fatalf("expected non-conflicting refs/nostr push to pass, got %q", reason)
	}

	// Deletion of a refs/nostr ref bypasses the tip check.
	called := false
	spy := func(string, string) error { called = true; return nil }
	if ok, _ := evaluatePushRef("refs/nostr/"+eventID, zeroSHA, nil, spy); !ok {
		t.Fatalf("expected refs/nostr deletion to pass")
	}
	if called {
		t.Fatalf("expected deletion to skip relay tip check")
	}
}

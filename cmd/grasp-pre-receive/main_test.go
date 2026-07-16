package main

import (
	"testing"

	"fiatjaf.com/nostr/nip34"
)

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

	if ok, _ := evaluatePushRef("refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc123", state); !ok {
		t.Fatalf("expected valid refs/nostr event id to pass")
	}

	if ok, _ := evaluatePushRef("refs/nostr/not-a-valid-id", "abc123", state); ok {
		t.Fatalf("expected invalid refs/nostr event id to fail")
	}

	if ok, _ := evaluatePushRef("refs/heads/pr/feature", "abc123", state); ok {
		t.Fatalf("expected refs/heads/pr/* to fail")
	}
}

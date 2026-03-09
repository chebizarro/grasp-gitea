package main

import (
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr/nip34"
)

func TestEvaluatePushUpdatesIntegration(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123", "dev": "bbb222"},
		Tags:     map[string]string{"v1.0.0": "def456"},
	}

	tests := []struct {
		name      string
		input     string
		state     *nip34.RepositoryState
		wantError string
	}{
		{
			name:  "accepts matching heads and tags",
			state: state,
			input: "0000000000000000000000000000000000000000 abc123 refs/heads/main\n0000000000000000000000000000000000000000 def456 refs/tags/v1.0.0\n",
		},
		{
			name:  "accepts refs nostr event id without state",
			state: nil,
			input: "0000000000000000000000000000000000000000 abc123 refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		},
		{
			name:      "rejects invalid stdin format",
			state:     state,
			input:     "bad-line\n",
			wantError: "invalid hook stdin format",
		},
		{
			name:      "rejects pr branch under refs heads",
			state:     state,
			input:     "0000000000000000000000000000000000000000 abc123 refs/heads/pr/feature\n",
			wantError: "push rejected: pr/* branches should be sent over nostr refs, not refs/heads",
		},
		{
			name:      "rejects mismatched state sha",
			state:     state,
			input:     "0000000000000000000000000000000000000000 zzz999 refs/heads/main\n",
			wantError: "push rejected: SHA mismatch with NIP-34 state",
		},
		{
			name:      "rejects invalid nostr id",
			state:     nil,
			input:     "0000000000000000000000000000000000000000 abc123 refs/nostr/not-a-valid-id\n",
			wantError: "refs/nostr/<event-id> must use a valid event id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates, err := collectPushUpdates(strings.NewReader(tt.input))
			if tt.wantError == "invalid hook stdin format" {
				if err == nil || err.Error() != tt.wantError {
					t.Fatalf("expected parse error %q, got %v", tt.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			err = evaluatePushUpdates(updates, tt.state)
			if tt.wantError == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.wantError != "" && tt.wantError != "invalid hook stdin format" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantError)
				}
				if err.Error() != tt.wantError {
					t.Fatalf("expected error %q, got %q", tt.wantError, err.Error())
				}
			}
		})
	}
}

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr/nip34"
)

// processHookInput is a test helper that replicates the main loop logic
// using a pre-fetched state, so unit tests don't need a live relay.
func processHookInput(input string, state *nip34.RepositoryState) error {
	lines, err := readLines(strings.NewReader(input))
	if err != nil {
		return fmt.Errorf("failed to read hook input")
	}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return fmt.Errorf("invalid hook stdin format")
		}
		newSHA := parts[1]
		refName := parts[2]
		if ok, reason := evaluatePushRef(refName, newSHA, state); !ok {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
}

func TestProcessHookInputIntegration(t *testing.T) {
	state := &nip34.RepositoryState{
		Branches: map[string]string{"main": "abc123", "dev": "bbb222"},
		Tags:     map[string]string{"v1.0.0": "def456"},
	}

	tests := []struct {
		name      string
		input     string
		wantError string
	}{
		{
			name:  "accepts matching heads and tags",
			input: "0000000000000000000000000000000000000000 abc123 refs/heads/main\n0000000000000000000000000000000000000000 def456 refs/tags/v1.0.0\n",
		},
		{
			name:  "accepts refs nostr event id",
			input: "0000000000000000000000000000000000000000 abc123 refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		},
		{
			name:      "rejects invalid stdin format",
			input:     "bad-line\n",
			wantError: "invalid hook stdin format",
		},
		{
			name:      "rejects pr branch under refs heads",
			input:     "0000000000000000000000000000000000000000 abc123 refs/heads/pr/feature\n",
			wantError: "push rejected: pr/* branches should be sent over nostr refs, not refs/heads",
		},
		{
			name:      "rejects mismatched state sha",
			input:     "0000000000000000000000000000000000000000 zzz999 refs/heads/main\n",
			wantError: "push rejected: SHA mismatch with NIP-34 state",
		},
		{
			name:      "rejects invalid nostr id",
			input:     "0000000000000000000000000000000000000000 abc123 refs/nostr/not-a-valid-id\n",
			wantError: "refs/nostr/<event-id> must use a valid event id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := processHookInput(tt.input, state)
			if tt.wantError == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.wantError != "" {
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

func TestRequiresStateCheck(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{
			name:  "refs/nostr only — no state check needed",
			lines: []string{"aaa bbb refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			want:  false,
		},
		{
			name:  "refs/heads — state check needed",
			lines: []string{"aaa bbb refs/heads/main"},
			want:  true,
		},
		{
			name:  "mixed — state check needed",
			lines: []string{"aaa bbb refs/nostr/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaa bbb refs/heads/main"},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requiresStateCheck(tt.lines); got != tt.want {
				t.Fatalf("requiresStateCheck = %v, want %v", got, tt.want)
			}
		})
	}
}

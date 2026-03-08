package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
)


func main() {
	relayURL := envOrDefault("GRASP_HOOK_RELAY_URL", envOrDefault("HOOK_RELAY_URL", "ws://localhost:3334"))
	npub := strings.TrimSpace(os.Getenv("GRASP_REPO_NPUB"))
	repoID := strings.TrimSpace(os.Getenv("GRASP_REPO_ID"))

	if npub == "" || repoID == "" {
		reject("missing GRASP_REPO_NPUB or GRASP_REPO_ID")
	}

	decodedType, v, err := nip19.Decode(npub)
	if err != nil || decodedType != "npub" {
		reject("invalid npub in GRASP_REPO_NPUB")
	}
	pubkey, ok := v.(string)
	if !ok || strings.TrimSpace(pubkey) == "" {
		reject("invalid decoded pubkey")
	}

	// Read all push refs from stdin before hitting the relay, so that
	// refs/nostr/<event-id> pushes (which need no state check) are not
	// blocked by a missing kind 30618 event.
	lines, err := readLines(os.Stdin)
	if err != nil {
		reject("failed to read hook input")
	}

	// Only fetch the NIP-34 state if at least one ref actually needs it.
	var state *nip34.RepositoryState
	if requiresStateCheck(lines) {
		ctx := context.Background()
		_, state, _, err = nostrstate.FetchLatestRepositoryStateForRepo(ctx, relayURL, pubkey, repoID)
		if err != nil {
			reject("no valid NIP-34 state event found; publish kind 30618 before pushing")
		}
	}

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			reject("invalid hook stdin format")
		}
		newSHA := parts[1]
		refName := parts[2]
		if ok, reason := evaluatePushRef(refName, newSHA, state); !ok {
			reject(reason)
		}
	}
}

// readLines drains r into a slice of non-empty lines.
func readLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// requiresStateCheck returns true if any ref in lines needs a NIP-34 state lookup.
func requiresStateCheck(lines []string) bool {
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		refName := parts[2]
		if !strings.HasPrefix(refName, "refs/nostr/") {
			return true
		}
	}
	return false
}


func evaluatePushRef(refName string, newSHA string, state *nip34.RepositoryState) (bool, string) {
	if strings.HasPrefix(refName, "refs/nostr/") {
		eventID := strings.TrimPrefix(refName, "refs/nostr/")
		if !nostr.IsValid32ByteHex(eventID) {
			return false, "refs/nostr/<event-id> must use a valid event id"
		}
		return true, ""
	}

	if strings.HasPrefix(refName, "refs/heads/pr/") {
		return false, "push rejected: pr/* branches should be sent over nostr refs, not refs/heads"
	}

	return validateRefAgainstState(refName, newSHA, state)
}

func validateRefAgainstState(refName string, newSHA string, state *nip34.RepositoryState) (bool, string) {
	if strings.HasPrefix(refName, "refs/heads/") {
		branch := strings.TrimPrefix(refName, "refs/heads/")
		expected, ok := state.Branches[branch]
		if !ok {
			return false, fmt.Sprintf("push rejected: branch %s is not present in NIP-34 state", branch)
		}
		if expected != newSHA {
			return false, "push rejected: SHA mismatch with NIP-34 state"
		}
		return true, ""
	}

	if strings.HasPrefix(refName, "refs/tags/") {
		tag := strings.TrimPrefix(refName, "refs/tags/")
		expected, ok := state.Tags[tag]
		if !ok {
			return false, fmt.Sprintf("push rejected: tag %s is not present in NIP-34 state", tag)
		}
		if expected != newSHA {
			return false, "push rejected: SHA mismatch with NIP-34 state"
		}
		return true, ""
	}

	return false, fmt.Sprintf("push rejected: ref %s is not allowed", refName)
}

func envOrDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func reject(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

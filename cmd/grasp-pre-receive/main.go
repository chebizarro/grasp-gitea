package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
)

type pushUpdate struct {
	newSHA  string
	refName string
}

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
	pk, ok := v.(nostr.PubKey)
	if !ok {
		reject("invalid decoded pubkey")
	}
	pubkey := pk.Hex()
	if pubkey == "" {
		reject("invalid decoded pubkey")
	}

	updates, err := collectPushUpdates(os.Stdin)
	if err != nil {
		reject(err.Error())
	}

	var state *nip34.RepositoryState
	if requiresStateCheck(updates) {
		ctx := context.Background()
		_, state, _, err = nostrstate.FetchLatestRepositoryStateForRepo(ctx, relayURL, pubkey, repoID)
		if err != nil {
			reject("no valid NIP-34 state event found; publish kind 30618 before pushing")
		}
	}

	if err := evaluatePushUpdates(updates, state); err != nil {
		reject(err.Error())
	}
}

func collectPushUpdates(r io.Reader) ([]pushUpdate, error) {
	scanner := bufio.NewScanner(r)
	updates := make([]pushUpdate, 0)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid hook stdin format")
		}
		updates = append(updates, pushUpdate{newSHA: parts[1], refName: parts[2]})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read hook input")
	}
	return updates, nil
}

func requiresStateCheck(updates []pushUpdate) bool {
	for _, update := range updates {
		if !strings.HasPrefix(update.refName, "refs/nostr/") {
			return true
		}
	}
	return false
}

func evaluatePushUpdates(updates []pushUpdate, state *nip34.RepositoryState) error {
	for _, update := range updates {
		if ok, reason := evaluatePushRef(update.refName, update.newSHA, state); !ok {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
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
	if state == nil {
		return false, "no valid NIP-34 state event found; publish kind 30618 before pushing"
	}
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

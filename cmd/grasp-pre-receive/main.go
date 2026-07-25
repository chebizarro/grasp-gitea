package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
)

type pushUpdate struct {
	newSHA  string
	refName string
}

// zeroSHA is git's all-zero object id, which signals ref deletion in a
// pre-receive update line.
const zeroSHA = "0000000000000000000000000000000000000000"

func isDeletion(newSHA string) bool {
	return newSHA == zeroSHA
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
	pubkey, ok := decodedPubkeyHex(v)
	if !ok {
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
		if err != nil || evaluatePushUpdates(updates, state, nil) != nil {
			proposed, proposedErr := fetchProposedRepositoryState(ctx, pubkey, repoID)
			if proposedErr == nil {
				state = proposed
			} else if err != nil {
				reject("no valid NIP-34 state event found; publish kind 30618 before pushing")
			}
		}
	}

	checker := newRelayNostrRefChecker(relayURL)
	if err := evaluatePushUpdates(updates, state, checker); err != nil {
		reject(err.Error())
	}
}

func fetchProposedRepositoryState(ctx context.Context, pubkey string, repoID string) (*nip34.RepositoryState, error) {
	tokenFile := envOrDefault("GRASP_HOOK_ADMIN_TOKEN_FILE", "/run/secrets/grasp-admin-api-token")
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read hook credential: %w", err)
	}
	adminURL := strings.TrimRight(envOrDefault("GRASP_HOOK_ADMIN_URL", "http://grasp-bridge:8090"), "/")
	endpoint, err := url.Parse(adminURL + "/repository-state/proposed")
	if err != nil {
		return nil, fmt.Errorf("parse admin url: %w", err)
	}
	query := endpoint.Query()
	query.Set("pubkey", pubkey)
	query.Set("repo_id", repoID)
	endpoint.RawQuery = query.Encode()

	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build proposed-state request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch proposed state: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch proposed state: status %d", response.StatusCode)
	}
	var payload struct {
		Event nostr.Event `json:"event"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode proposed state: %w", err)
	}
	if payload.Event.Kind != nostr.KindRepositoryState ||
		payload.Event.PubKey.Hex() != pubkey ||
		!payload.Event.VerifySignature() {
		return nil, fmt.Errorf("invalid proposed state event")
	}
	parsed := nip34.ParseRepositoryState(payload.Event)
	if parsed.ID != repoID {
		return nil, fmt.Errorf("proposed state repository mismatch")
	}
	return &parsed, nil
}

func decodedPubkeyHex(value any) (string, bool) {
	switch decoded := value.(type) {
	case string:
		decoded = strings.TrimSpace(decoded)
		return decoded, decoded != ""
	case nostr.PubKey:
		return decoded.Hex(), decoded != (nostr.PubKey{})
	default:
		return "", false
	}
}

// nostrRefChecker validates a refs/nostr/<event-id> push against relay state.
// It returns an error when the push must be rejected.
type nostrRefChecker func(eventID string, tipSHA string) error

// newRelayNostrRefChecker enforces GRASP-01 differing-tip rejection before the
// git update commits: if the relay already holds the PR/PR-update event named
// by the ref and that event lists a different tip commit, the push is
// rejected during pre-receive rather than being noticed later by a webhook.
// Valid IDs with no relay event are accepted. Relay unreachability fails
// closed, matching the state-check path.
func newRelayNostrRefChecker(relayURL string) nostrRefChecker {
	return func(eventID string, tipSHA string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		fetcher := relayEventFetcher{relayURL: relayURL}
		_, err := refsnostr.FetchEventForTip(ctx, fetcher, eventID, tipSHA)
		if errors.Is(err, refsnostr.ErrDifferingTip) {
			return fmt.Errorf("push rejected: refs/nostr/%s conflicts with the relay event's declared tip", eventID)
		}
		if err != nil {
			return fmt.Errorf("push rejected: cannot verify refs/nostr/%s against relay: %v", eventID, err)
		}
		return nil
	}
}

type relayEventFetcher struct {
	relayURL string
}

func (f relayEventFetcher) FetchEvent(ctx context.Context, id string) (*nostr.Event, error) {
	eid, err := nostr.IDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid event id: %w", err)
	}
	r, err := nostr.RelayConnect(ctx, f.relayURL, nostr.RelayOptions{})
	if err != nil {
		return nil, fmt.Errorf("connect relay: %w", err)
	}
	defer r.Close()
	for ev := range r.QueryEvents(nostr.Filter{
		IDs:   []nostr.ID{eid},
		Kinds: []nostr.Kind{relay.KindPROpen, relay.KindPRUpdate},
		Limit: 1,
	}) {
		e := ev
		return &e, nil
	}
	return nil, nil
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

func evaluatePushUpdates(updates []pushUpdate, state *nip34.RepositoryState, checkNostrRef nostrRefChecker) error {
	for _, update := range updates {
		if ok, reason := evaluatePushRef(update.refName, update.newSHA, state, checkNostrRef); !ok {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
}

func evaluatePushRef(refName string, newSHA string, state *nip34.RepositoryState, checkNostrRef nostrRefChecker) (bool, string) {
	if strings.HasPrefix(refName, "refs/nostr/") {
		eventID := strings.TrimPrefix(refName, "refs/nostr/")
		if !nostr.IsValid32ByteHex(eventID) {
			return false, "refs/nostr/<event-id> must use a valid event id"
		}
		if isDeletion(newSHA) {
			// Deletion of refs/nostr is handled by the retention reaper and
			// carries no tip to conflict with.
			return true, ""
		}
		if checkNostrRef != nil {
			if err := checkNostrRef(eventID, newSHA); err != nil {
				return false, err.Error()
			}
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
		if isDeletion(newSHA) {
			// Repository state represents deletion by omitting the ref: a
			// deletion push is authorized exactly when the latest signed state
			// no longer declares the branch.
			if ok {
				return false, fmt.Sprintf("push rejected: NIP-34 state still declares branch %s; publish updated state before deleting", branch)
			}
			return true, ""
		}
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
		if isDeletion(newSHA) {
			if ok {
				return false, fmt.Sprintf("push rejected: NIP-34 state still declares tag %s; publish updated state before deleting", tag)
			}
			return true, ""
		}
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

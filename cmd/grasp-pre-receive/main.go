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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrstate"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
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
	timeout, err := envDuration("GRASP_HOOK_TIMEOUT", 15*time.Second)
	if err != nil {
		reject(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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
	if err := enforceNostrPushLimits(ctx, updates); err != nil {
		reject(err.Error())
	}

	var state *nip34.RepositoryState
	if requiresStateCheck(updates) {
		_, state, _, err = nostrstate.FetchLatestRepositoryStateForRepo(ctx, relayURL, pubkey, repoID)
		if err != nil || evaluatePushUpdates(updates, state, nil) != nil {
			proposed, proposedErr := fetchProposedRepositoryState(ctx, pubkey, repoID)
			if proposedErr == nil {
				state = proposed
			} else if err != nil {
				if ctx.Err() != nil {
					reject("push verification timed out")
				}
				reject("no valid NIP-34 state event found; publish kind 30618 before pushing")
			}
		}
	}

	checker := newRelayNostrRefChecker(ctx, relayURL)
	if err := evaluatePushUpdates(updates, state, checker); err != nil {
		if ctx.Err() != nil {
			reject("push verification timed out")
		}
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
		nostrverify.ValidateEventIDAndSignature(&payload.Event) != nil {
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
// git update commits: if the relay already holds the event named by the ref
// and that event lists a different tip commit, the push is rejected during
// pre-receive rather than being noticed later by a webhook.
// Valid IDs with no relay event are accepted. Relay unreachability fails
// closed, matching the state-check path.
func newRelayNostrRefChecker(parent context.Context, relayURL string) nostrRefChecker {
	return func(eventID string, tipSHA string) error {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
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
	for ev := range r.QueryEvents(nostrRefEventFilter(eid)) {
		e := ev
		if e.ID.Hex() != id || nostrverify.ValidateEventIDAndSignature(&e) != nil {
			return nil, fmt.Errorf("relay returned invalid event")
		}
		return &e, nil
	}
	return nil, nil
}

// nostrRefEventFilter deliberately does not constrain event kind. GRASP-01
// requires conflict rejection whenever the event named by refs/nostr/<id>
// exists and lists a different tip; PR-kind filtering applies only to the
// later retention decision.
func nostrRefEventFilter(eventID nostr.ID) nostr.Filter {
	return nostr.Filter{
		IDs:   []nostr.ID{eventID},
		Limit: 1,
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

type nostrPushLimits struct {
	maxUpdates          int64
	maxActiveRefs       int64
	maxQuarantineBytes  int64
	maxObjects          int64
	maxObjectBytes      int64
	maxSingleObjectByte int64
}

func loadNostrPushLimits() (nostrPushLimits, error) {
	maxUpdates, err := envPositiveInt64("GRASP_HOOK_MAX_NOSTR_UPDATES", 16)
	if err != nil {
		return nostrPushLimits{}, err
	}
	maxActiveRefs, err := envPositiveInt64("GRASP_HOOK_MAX_NOSTR_REFS", 256)
	if err != nil {
		return nostrPushLimits{}, err
	}
	maxQuarantineBytes, err := envPositiveInt64("GRASP_HOOK_MAX_PACK_BYTES", 256<<20)
	if err != nil {
		return nostrPushLimits{}, err
	}
	maxObjects, err := envPositiveInt64("GRASP_HOOK_MAX_OBJECTS", 50000)
	if err != nil {
		return nostrPushLimits{}, err
	}
	maxObjectBytes, err := envPositiveInt64("GRASP_HOOK_MAX_OBJECT_BYTES", 512<<20)
	if err != nil {
		return nostrPushLimits{}, err
	}
	maxSingleObjectByte, err := envPositiveInt64("GRASP_HOOK_MAX_SINGLE_OBJECT_BYTES", 64<<20)
	if err != nil {
		return nostrPushLimits{}, err
	}
	return nostrPushLimits{maxUpdates, maxActiveRefs, maxQuarantineBytes, maxObjects, maxObjectBytes, maxSingleObjectByte}, nil
}

func enforceNostrPushLimits(ctx context.Context, updates []pushUpdate) error {
	limits, err := loadNostrPushLimits()
	if err != nil {
		return err
	}

	seenUpdates := make(map[string]struct{}, len(updates))
	nostrUpdates := make([]pushUpdate, 0, len(updates))
	for _, update := range updates {
		if _, duplicate := seenUpdates[update.refName]; duplicate {
			return fmt.Errorf("duplicate update for ref %s", update.refName)
		}
		seenUpdates[update.refName] = struct{}{}
		if strings.HasPrefix(update.refName, refsnostr.RefPrefix) {
			nostrUpdates = append(nostrUpdates, update)
		}
	}
	if len(nostrUpdates) == 0 {
		return nil
	}
	if int64(len(nostrUpdates)) > limits.maxUpdates {
		return fmt.Errorf("push rejected: refs/nostr update quota exceeded (%d > %d)", len(nostrUpdates), limits.maxUpdates)
	}

	active, err := activeNostrRefs(ctx)
	if err != nil {
		return fmt.Errorf("inspect refs/nostr quota: %w", err)
	}
	for _, update := range nostrUpdates {
		if isDeletion(update.newSHA) {
			delete(active, update.refName)
		} else {
			active[update.refName] = struct{}{}
		}
	}
	if int64(len(active)) > limits.maxActiveRefs {
		return fmt.Errorf("push rejected: active refs/nostr quota exceeded (%d > %d)", len(active), limits.maxActiveRefs)
	}

	if err := enforceQuarantineBytes(ctx, limits.maxQuarantineBytes); err != nil {
		return err
	}

	tips := make([]string, 0, len(nostrUpdates))
	for _, update := range nostrUpdates {
		if isDeletion(update.newSHA) {
			continue
		}
		if !isGitObjectID(update.newSHA) {
			return fmt.Errorf("push rejected: invalid object id for %s", update.refName)
		}
		if out, err := exec.CommandContext(ctx, "git", "cat-file", "-e", update.newSHA+"^{commit}").CombinedOutput(); err != nil {
			return fmt.Errorf("push rejected: %s must point to a commit: %s", update.refName, strings.TrimSpace(string(out)))
		}
		tips = append(tips, update.newSHA)
	}
	if len(tips) == 0 {
		return nil
	}
	return enforceNewObjectLimits(ctx, tips, limits)
}

func activeNostrRefs(ctx context.Context) (map[string]struct{}, error) {
	out, err := exec.CommandContext(ctx, "git", "for-each-ref", "--format=%(refname)", refsnostr.RefPrefix).Output()
	if err != nil {
		return nil, err
	}
	refs := make(map[string]struct{})
	for _, ref := range strings.Fields(string(out)) {
		refs[ref] = struct{}{}
	}
	return refs, nil
}

func enforceQuarantineBytes(ctx context.Context, maxBytes int64) error {
	root := strings.TrimSpace(os.Getenv("GIT_QUARANTINE_PATH"))
	if root == "" {
		root = strings.TrimSpace(os.Getenv("GIT_OBJECT_DIRECTORY"))
	}
	if root == "" {
		return nil
	}
	var total int64
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > maxBytes {
			return fmt.Errorf("push rejected: quarantine pack quota exceeded (%d > %d bytes)", total, maxBytes)
		}
		return nil
	})
	return err
}

func enforceNewObjectLimits(ctx context.Context, tips []string, limits nostrPushLimits) error {
	args := append([]string{"rev-list", "--objects"}, tips...)
	args = append(args, "--not", "--all")
	revCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(revCtx, "git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("enumerate new objects: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("enumerate new objects: %w", err)
	}

	ids := make([]string, 0, min(int(limits.maxObjects), 1024))
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if _, ok := seen[fields[0]]; ok {
			continue
		}
		seen[fields[0]] = struct{}{}
		ids = append(ids, fields[0])
		if int64(len(ids)) > limits.maxObjects {
			cancel()
			_ = cmd.Wait()
			return fmt.Errorf("push rejected: new object quota exceeded (%d > %d)", len(ids), limits.maxObjects)
		}
	}
	if err := scanner.Err(); err != nil {
		cancel()
		_ = cmd.Wait()
		return fmt.Errorf("enumerate new objects: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("enumerate new objects: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}

	catCmd := exec.CommandContext(ctx, "git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	catCmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	checked, err := catCmd.Output()
	if err != nil {
		return fmt.Errorf("inspect new objects: %w", err)
	}
	var total int64
	for _, line := range strings.Split(strings.TrimSpace(string(checked)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("inspect new objects: unexpected git output")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("inspect new objects: invalid object size")
		}
		if size > limits.maxSingleObjectByte {
			return fmt.Errorf("push rejected: object %s exceeds single-object quota (%d > %d bytes)", fields[0], size, limits.maxSingleObjectByte)
		}
		total += size
		if total > limits.maxObjectBytes {
			return fmt.Errorf("push rejected: decompressed object quota exceeded (%d > %d bytes)", total, limits.maxObjectBytes)
		}
	}
	return nil
}

func isGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func envPositiveInt64(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return value, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return value, nil
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

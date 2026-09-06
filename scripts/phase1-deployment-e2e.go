//go:build ignore

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/relay"
)

const (
	publicURL = "https://grasp.test"
	zeroSHA   = "0000000000000000000000000000000000000000"
)

type challenge struct {
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
}

type verifyResult struct {
	OK       bool `json:"ok"`
	Identity struct {
		GiteaUser string `json:"gitea_user"`
	} `json:"identity"`
	HandoffURL string `json:"handoff_url"`
}

type hookFixture struct {
	token  string
	key    nostr.SecretKey
	commit atomic.Value
	calls  atomic.Int64
	delay  atomic.Bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "phase1 deployment E2E FAILED:", err)
		os.Exit(1)
	}
}

func run() error {
	key := nostr.Generate()
	client := browserClient()
	if os.Getenv("E2E_OWNERSHIP_ONLY") == "true" {
		if err := runRepositoryOwnershipE2E(client, key); err != nil {
			return err
		}
		fmt.Println("phase1 repository ownership E2E PASSED")
		return nil
	}

	fmt.Println("[1/11] signed NIP-07 verification through canonical TLS/nginx")
	var ch challenge
	if err := jsonRequest(client, http.MethodPost, publicURL+"/auth/nip07/challenge", map[string]string{"redirect_uri": "/"}, &ch, http.StatusOK); err != nil {
		return err
	}
	event := nostr.Event{Kind: 27235, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"u", ch.URL}, {"method", "POST"}, {"nonce", ch.Nonce}}}
	if err := event.Sign(key); err != nil {
		return fmt.Errorf("sign NIP-07 event: %w", err)
	}
	var verified verifyResult
	if err := jsonRequest(client, http.MethodPost, publicURL+"/auth/nip07/verify", map[string]any{"signed_event": event}, &verified, http.StatusOK); err != nil {
		return err
	}
	if !verified.OK || verified.Identity.GiteaUser == "" || verified.HandoffURL == "" {
		return fmt.Errorf("incomplete verify response: %+v", verified)
	}

	fmt.Println("[2/11] cross-browser handoff and internal-header spoofing fail")
	if status, _, err := get(browserClient(), verified.HandoffURL, nil); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("cross-browser handoff = %d, %v; want 401", status, err)
	}
	spoof := http.Header{
		"X-Grasp-Auth-User":     []string{"e2e-admin"},
		"X-Grasp-Session-Proxy": []string{"1"},
		"X-Grasp-Edge-Secret":   []string{os.Getenv("E2E_EDGE_SECRET")},
	}
	if status, _, err := get(browserClient(), publicURL+"/api/v1/user", spoof); err != nil || (status != http.StatusUnauthorized && status != http.StatusForbidden) {
		return fmt.Errorf("spoofed request = %d, %v; want 401/403", status, err)
	}

	fmt.Println("[3/11] handoff emits durable Gitea cookie and header-free session")
	status, body, err := get(client, verified.HandoffURL, nil)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("handoff = %d, %v: %s", status, err, body)
	}
	u, _ := url.Parse(publicURL)
	hasGiteaCookie := false
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == "i_like_gitea" {
			hasGiteaCookie = true
		}
	}
	if !hasGiteaCookie {
		return fmt.Errorf("handoff did not emit i_like_gitea session cookie")
	}
	status, body, err = get(client, publicURL+"/", nil)
	if err != nil || status != http.StatusOK || !strings.Contains(body, verified.Identity.GiteaUser) {
		return fmt.Errorf("header-free session not durable: status=%d err=%v user=%q", status, err, verified.Identity.GiteaUser)
	}

	fmt.Println("[4/11] one-time handoff replay fails")
	if status, _, err := get(client, verified.HandoffURL, nil); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("handoff replay = %d, %v; want 401", status, err)
	}

	fmt.Println("[5/11] NIP-55 endpoint emits launchable Android deep link")
	var nip55 struct {
		URI      string `json:"nostrsigner_uri"`
		Callback string `json:"callback_url"`
	}
	if err := jsonRequest(browserClient(), http.MethodGet, publicURL+"/auth/nip55/challenge?redirect_uri=%2F", nil, &nip55, http.StatusOK); err != nil {
		return err
	}
	if !strings.HasPrefix(nip55.URI, "nostrsigner:") || !strings.Contains(nip55.URI, "type=sign_event") || nip55.Callback != publicURL+"/auth/nip55/callback" {
		return fmt.Errorf("invalid NIP-55 deep link: %+v", nip55)
	}
	status, js, err := get(browserClient(), publicURL+"/assets/js/grasp-nostr-login.js", nil)
	if err != nil || status != http.StatusOK || !strings.Contains(js, "window.location.assign(challenge.nostrsigner_uri)") {
		return fmt.Errorf("deployed login asset does not launch NIP-55 URI: status=%d err=%v", status, err)
	}

	fmt.Println("[6/11] REST bridge-token scopes and bounded direct NIP-98 work through Gitea")
	apiClient := browserClient()
	apiClient.Jar = nil // API authentication must not be shadowed by the browser-session cookie.
	readToken, err := mintBridgeToken(apiClient, key, "phase4-read", []string{"api:read"})
	if err != nil {
		return err
	}
	writeToken, err := mintBridgeToken(apiClient, key, "phase4-write", []string{"api:write"})
	if err != nil {
		return err
	}
	if status, _, err := request(apiClient, http.MethodGet, publicURL+"/api/v1/user", nil, "Bearer "+readToken); err != nil || status != http.StatusOK {
		return fmt.Errorf("api:read token GET /api/v1/user = %d, %v; want 200", status, err)
	}
	readDeniedBody := []byte(`{"name":"phase4-read-must-not-create"}`)
	if status, _, err := request(apiClient, http.MethodPost, publicURL+"/api/v1/user/repos", readDeniedBody, "Bearer "+readToken); err != nil || status != http.StatusForbidden {
		return fmt.Errorf("api:read token POST /api/v1/user/repos = %d, %v; want 403", status, err)
	}
	writeBody := []byte(`{"name":"phase4-bridge-write"}`)
	if status, body, err := request(apiClient, http.MethodPost, publicURL+"/api/v1/user/repos", writeBody, "Bearer "+writeToken); err != nil || status != http.StatusCreated {
		return fmt.Errorf("api:write token POST /api/v1/user/repos = %d, %v: %s", status, err, body)
	}

	directGetAuth, err := nip98Authorization(key, http.MethodGet, publicURL+"/api/v1/user", nil)
	if err != nil {
		return err
	}
	if status, _, err := request(apiClient, http.MethodGet, publicURL+"/api/v1/user", nil, directGetAuth); err != nil || status != http.StatusOK {
		return fmt.Errorf("direct NIP-98 GET /api/v1/user = %d, %v; want 200", status, err)
	}
	if status, _, err := request(apiClient, http.MethodGet, publicURL+"/api/v1/user", nil, directGetAuth); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("replayed direct NIP-98 GET = %d, %v; want 401", status, err)
	}
	directBody := []byte(`{"name":"phase4-direct-write"}`)
	directPostAuth, err := nip98Authorization(key, http.MethodPost, publicURL+"/api/v1/user/repos", directBody)
	if err != nil {
		return err
	}
	if status, body, err := request(apiClient, http.MethodPost, publicURL+"/api/v1/user/repos", directBody, directPostAuth); err != nil || status != http.StatusCreated {
		return fmt.Errorf("direct NIP-98 POST /api/v1/user/repos = %d, %v: %s", status, err, body)
	}
	mismatchedBody := []byte(`{"name":"phase4-payload-mismatch"}`)
	mismatchedAuth, err := nip98Authorization(key, http.MethodPost, publicURL+"/api/v1/user/repos", []byte(`{"name":"different"}`))
	if err != nil {
		return err
	}
	if status, _, err := request(apiClient, http.MethodPost, publicURL+"/api/v1/user/repos", mismatchedBody, mismatchedAuth); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("payload-mismatched direct NIP-98 POST = %d, %v; want 401", status, err)
	}

	fmt.Println("[7/11] LFS batch scopes, streamed object round-trip, URL rewrite, NIP-98 denial, and locks")
	if err := runLFSE2E(apiClient, key, verified.Identity.GiteaUser); err != nil {
		return err
	}

	fmt.Println("[8/11] NIP-34 proposal remains writable by Gitea and leaves no ownership drift")
	if err := runRepositoryOwnershipE2E(apiClient, key); err != nil {
		return err
	}

	fmt.Println("[9/11] mounted hook reads admin-token secret and accepts proposed state")
	fixture := &hookFixture{token: os.Getenv("E2E_ADMIN_TOKEN"), key: key}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: fixture}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	commit, err := composeExec(`set -eu
repo=/tmp/grasp-phase1-e2e.git
rm -rf "$repo"
git init --bare -q "$repo"
cd "$repo"
blob=$(printf 'phase1-e2e\n' | git hash-object -w --stdin)
tree=$(printf '100644 blob %s\tproof.txt\n' "$blob" | git mktree)
commit=$(printf 'phase1 e2e\n' | GIT_AUTHOR_NAME=e2e GIT_AUTHOR_EMAIL=e2e@example.invalid GIT_AUTHOR_DATE='1700000000 +0000' GIT_COMMITTER_NAME=e2e GIT_COMMITTER_EMAIL=e2e@example.invalid GIT_COMMITTER_DATE='1700000000 +0000' git commit-tree "$tree")
cat > hooks/pre-receive <<'EOF'
#!/bin/sh
exec /opt/grasp/grasp-pre-receive
EOF
chmod +x hooks/pre-receive
printf '%s' "$commit"`)
	if err != nil {
		return fmt.Errorf("prepare hook repository: %w", err)
	}
	commit = strings.TrimSpace(commit)
	fixture.commit.Store(commit)
	npub := nip19.EncodeNpub(key.Public())
	adminURL := fmt.Sprintf("http://host.docker.internal:%d", listener.Addr().(*net.TCPAddr).Port)
	accepted := fmt.Sprintf(`cd /tmp/grasp-phase1-e2e.git
printf '%s %s refs/heads/main\n' | env GRASP_REPO_NPUB='%s' GRASP_REPO_ID=demo GRASP_HOOK_RELAY_URL=ws://127.0.0.1:1 GRASP_HOOK_ADMIN_URL='%s' GRASP_HOOK_TIMEOUT=5s hooks/pre-receive`, zeroSHA, commit, npub, adminURL)
	if out, err := composeExec(accepted); err != nil {
		return fmt.Errorf("proposed-state hook acceptance: %w: %s", err, out)
	}
	if fixture.calls.Load() == 0 {
		return fmt.Errorf("hook never requested proposed state with mounted credential")
	}

	fmt.Println("[10/11] in-container hook rejects new-object quota overflow")
	quota := fmt.Sprintf(`cd /tmp/grasp-phase1-e2e.git
printf '%s %s refs/nostr/%s\n' | env GRASP_REPO_NPUB='%s' GRASP_REPO_ID=demo GRASP_HOOK_RELAY_URL=ws://127.0.0.1:1 GRASP_HOOK_MAX_OBJECTS=1 hooks/pre-receive`, zeroSHA, commit, strings.Repeat("a", 64), npub)
	if out, err := composeExec(quota); err == nil || !strings.Contains(out, "new object quota exceeded") {
		return fmt.Errorf("object quota was not enforced: err=%v output=%s", err, out)
	}

	fmt.Println("[11/11] in-container hook obeys configured timeout")
	fixture.delay.Store(true)
	started := time.Now()
	timed := fmt.Sprintf(`cd /tmp/grasp-phase1-e2e.git
printf '%s %s refs/heads/main\n' | env GRASP_REPO_NPUB='%s' GRASP_REPO_ID=slow GRASP_HOOK_RELAY_URL=ws://127.0.0.1:1 GRASP_HOOK_ADMIN_URL='%s' GRASP_HOOK_TIMEOUT=100ms hooks/pre-receive`, zeroSHA, commit, npub, adminURL)
	out, timedErr := composeExec(timed)
	if timedErr == nil || time.Since(started) > 2*time.Second || !strings.Contains(out, "push verification timed out") {
		return fmt.Errorf("hook timeout not enforced promptly: duration=%s err=%v output=%s", time.Since(started), timedErr, out)
	}

	fmt.Println("phase1 deployment E2E PASSED")
	return nil
}

func runRepositoryOwnershipE2E(_ *http.Client, ownerKey nostr.SecretKey) error {
	bridgeID, err := composeExecService("grasp-bridge", "", `awk '/^Uid:/{u=$2} /^Gid:/{g=$2} END{printf "%s:%s",u,g}' /proc/1/status`)
	if err != nil {
		return fmt.Errorf("read bridge uid/gid: %w: %s", err, bridgeID)
	}
	giteaID, err := composeExecService("gitea", "git", "printf '%s:%s' \"$(id -u)\" \"$(id -g)\"")
	if err != nil {
		return fmt.Errorf("read Gitea git uid/gid: %w: %s", err, giteaID)
	}
	bridgeID, giteaID = strings.TrimSpace(bridgeID), strings.TrimSpace(giteaID)
	if bridgeID != giteaID {
		return fmt.Errorf("bridge uid/gid %s does not match Gitea git uid/gid %s", bridgeID, giteaID)
	}

	repoID := "ownership-e2e"
	ownerPubkey := ownerKey.Public().Hex()
	ownerOrg := ownerPubkey[:39]
	npub := nip19.EncodeNpub(ownerKey.Public())
	announcement := nostr.Event{
		Kind:      relay.KindRepositoryAnnouncement,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"d", repoID},
			{"clone", publicURL + "/" + npub + "/" + repoID + ".git"},
			{"relays", "wss://grasp.test"},
		},
	}
	if err := announcement.Sign(ownerKey); err != nil {
		return fmt.Errorf("sign ownership announcement: %w", err)
	}
	if err := publishE2EEvent(&announcement); err != nil {
		return fmt.Errorf("publish ownership announcement: %w", err)
	}

	repoPath := "/data/git/repositories/" + ownerOrg + "/" + repoID + ".git"
	if err := waitForComposeTest("gitea", "git", "test -d "+shellQuoteE2E(repoPath), 30*time.Second); err != nil {
		return fmt.Errorf("wait for provisioned repository: %w", err)
	}

	seed := fmt.Sprintf(`set -eu
work=/tmp/grasp-ownership-source
rm -rf "$work"
git init -q "$work"
cd "$work"
git config user.name e2e
git config user.email e2e@example.invalid
printf 'base\n' > README.md
git add README.md
git commit -qm base
base=$(git rev-parse HEAD)
printf 'base\nproposal\n' > README.md
git commit -qam proposal
printf 'BASE=%%s\n' "$base"
git format-patch --stdout -1 HEAD`)
	seeded, err := composeExec(seed)
	if err != nil {
		return fmt.Errorf("seed hosted base and proposal patch: %w: %s", err, seeded)
	}
	parts := strings.SplitN(seeded, "\n", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "BASE=") || !strings.HasPrefix(parts[1], "From ") {
		return fmt.Errorf("unexpected proposal fixture output: %s", seeded)
	}
	baseSHA := strings.TrimPrefix(parts[0], "BASE=")
	state := nostr.Event{
		Kind:      relay.KindRepositoryState,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"d", repoID},
			{"HEAD", "ref: refs/heads/main"},
			{"refs/heads/main", baseSHA},
		},
	}
	if err := state.Sign(ownerKey); err != nil {
		return fmt.Errorf("sign base repository state: %w", err)
	}
	if err := publishE2EEvent(&state); err != nil {
		return fmt.Errorf("publish base repository state: %w", err)
	}
	pushURL := fmt.Sprintf("http://e2e-admin:%s@127.0.0.1:3000/%s/%s.git", url.PathEscape(os.Getenv("E2E_GITEA_ADMIN_TOKEN")), ownerOrg, repoID)
	push := fmt.Sprintf(`git -C /tmp/grasp-ownership-source push -q %s HEAD~1:refs/heads/main`, shellQuoteE2E(pushURL))
	pushDeadline := time.Now().Add(10 * time.Second)
	var pushOutput string
	for {
		pushOutput, err = composeExec(push)
		if err == nil {
			break
		}
		if time.Now().After(pushDeadline) {
			return fmt.Errorf("push base through Gitea after state publication: %w: %s", err, pushOutput)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// The push updates Gitea's repository metadata asynchronously. Do not race
	// proposal reflection against the base branch becoming API-visible.
	baseAPI := fmt.Sprintf("http://127.0.0.1:3000/api/v1/repos/%s/%s/branches/main", ownerOrg, repoID)
	baseAuth := shellQuoteE2E("Authorization: token " + os.Getenv("E2E_GITEA_ADMIN_TOKEN"))
	if err := waitForComposeTest("gitea", "git", fmt.Sprintf("curl -fsS -H %s %s >/dev/null", baseAuth, shellQuoteE2E(baseAPI)), 10*time.Second); err != nil {
		return fmt.Errorf("wait for pushed base branch in Gitea API: %w", err)
	}
	time.Sleep(time.Second)

	proposal := nostr.Event{
		Kind:      relay.KindPROpen,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("30617:%s:%s", ownerPubkey, repoID)},
			{"subject", "Ownership-safe proposal"},
			{"branch-name", "ownership-proposal"},
		},
		Content: parts[1],
	}
	if err := proposal.Sign(nostr.Generate()); err != nil {
		return fmt.Errorf("sign ownership proposal: %w", err)
	}
	if err := publishE2EEvent(&proposal); err != nil {
		return fmt.Errorf("publish ownership proposal: %w", err)
	}

	apiBase := fmt.Sprintf("http://127.0.0.1:3000/api/v1/repos/%s/%s", ownerOrg, repoID)
	authHeader := shellQuoteE2E("Authorization: token " + os.Getenv("E2E_GITEA_ADMIN_TOKEN"))
	var pullNumber int64
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		body, reqErr := composeExec(fmt.Sprintf(`curl -fsS -H %s %s/pulls?state=all`, authHeader, shellQuoteE2E(apiBase)))
		if reqErr == nil {
			var pulls []struct {
				Number int64  `json:"number"`
				Title  string `json:"title"`
			}
			if json.Unmarshal([]byte(body), &pulls) == nil && len(pulls) > 0 {
				pullNumber = pulls[0].Number
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if pullNumber == 0 {
		return fmt.Errorf("Gitea did not create PR after NIP-34 proposal")
	}
	update, err := composeExec(fmt.Sprintf(`curl -fsS -X PATCH -H %s -H 'Content-Type: application/json' --data '{"title":"Ownership-safe proposal updated"}' %s/pulls/%d`, authHeader, shellQuoteE2E(apiBase), pullNumber))
	if err != nil || !strings.Contains(update, "Ownership-safe proposal updated") {
		return fmt.Errorf("Gitea PR update after proposal failed: %v: %s", err, update)
	}

	// Reproduce the legacy root-writer damage across non-loose-ref paths while
	// the bridge is stopped, then exercise the explicit entrypoint repair.
	if out, err := composeControl("stop", "grasp-bridge"); err != nil {
		return fmt.Errorf("stop bridge before legacy ownership fixture: %w: %s", err, out)
	}
	seedDrift := fmt.Sprintf(`set -eu
repo=%s
git --git-dir "$repo" pack-refs --all
printf 'migration in progress
' > "$repo/grasp-migrating"
printf 'legacy root hook
' > "$repo/hooks/legacy-root"
chown 0:0 "$repo/HEAD" "$repo/config" "$repo/packed-refs" "$repo/grasp-migrating"
chown -R 0:0 "$repo/hooks"
chmod 0400 "$repo/HEAD" "$repo/config" "$repo/packed-refs" "$repo/grasp-migrating"
chmod 0500 "$repo/hooks"`, shellQuoteE2E(repoPath))
	if out, err := composeExecService("gitea", "root", seedDrift); err != nil {
		return fmt.Errorf("seed legacy root-owned repository paths: %w: %s", err, out)
	}
	if out, err := composeControl("start", "grasp-bridge"); err != nil {
		return fmt.Errorf("restart bridge for explicit ownership repair: %w: %s", err, out)
	}
	if err := waitForComposeTest("grasp-bridge", "", `test "$(awk '/^Uid:/{print $2}' /proc/1/status)" = 1000`, 20*time.Second); err != nil {
		return fmt.Errorf("wait for repaired non-root bridge restart: %w", err)
	}

	postRepairRepoID := "ownership-post-repair"
	postRepairAnnouncement := nostr.Event{
		Kind:      relay.KindRepositoryAnnouncement,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"d", postRepairRepoID},
			{"clone", publicURL + "/" + npub + "/" + postRepairRepoID + ".git"},
			{"relays", "wss://grasp.test"},
		},
	}
	if err := postRepairAnnouncement.Sign(ownerKey); err != nil {
		return fmt.Errorf("sign post-repair repository announcement: %w", err)
	}
	publishDeadline := time.Now().Add(20 * time.Second)
	for {
		err = publishE2EEvent(&postRepairAnnouncement)
		if err == nil {
			break
		}
		if time.Now().After(publishDeadline) {
			return fmt.Errorf("publish post-repair repository announcement: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	postRepairRepoPath := "/data/git/repositories/" + ownerOrg + "/" + postRepairRepoID + ".git"
	if err := waitForComposeTest("gitea", "git", "test -x "+shellQuoteE2E(postRepairRepoPath+"/hooks/pre-receive"), 30*time.Second); err != nil {
		return fmt.Errorf("post-repair repository hook installation: %w", err)
	}

	postRepairWrites := fmt.Sprintf(`set -eu
repo=%s
cp "$repo/hooks/pre-receive" "$repo/hooks/.pre-receive-ownership-test"
chmod 0755 "$repo/hooks/.pre-receive-ownership-test"
mv "$repo/hooks/.pre-receive-ownership-test" "$repo/hooks/pre-receive"
git --git-dir "$repo" symbolic-ref HEAD refs/heads/main
git --git-dir "$repo" pack-refs --all
git --git-dir "$repo" config uploadpack.allowFilter true
printf 'migration in progress
' > "$repo/grasp-migrating"
rm "$repo/grasp-migrating"`, shellQuoteE2E(repoPath))
	if out, err := composeExec(postRepairWrites); err != nil {
		return fmt.Errorf("non-root hook/HEAD/packed-ref/config/migration writes after repair: %w: %s", err, out)
	}

	expectedOwner := bridgeID
	ownershipCheck := fmt.Sprintf(`find %s %s -exec sh -ec '
expected=$1; shift
for path do
	if [ -L "$path" ]; then echo "symlink: $path"; exit 1; fi
	actual=$(stat -c "%%u:%%g" "$path")
	if [ "$actual" != "$expected" ]; then echo "$actual $path"; exit 1; fi
	if [ -d "$path" ]; then
	[ -w "$path" ] && [ -x "$path" ] || { echo "directory not writable/searchable: $path"; exit 1; }
	elif [ -f "$path" ]; then
	[ -w "$path" ] || { echo "file not writable: $path"; exit 1; }
	fi
done
' sh %s {} +`, shellQuoteE2E(repoPath), shellQuoteE2E(postRepairRepoPath), shellQuoteE2E(expectedOwner))
	if out, err := composeExec(ownershipCheck); err != nil {
		return fmt.Errorf("unsafe ownership, mode, or symlink remains in managed bare repository: %w: %s", err, out)
	}
	return nil
}

func publishE2EEvent(ev *nostr.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := nostr.NewRelay(context.Background(), "wss://grasp.test", nostr.RelayOptions{})
	if err := r.ConnectWithClient(ctx, browserClient()); err != nil {
		return err
	}
	defer r.Close()
	return r.Publish(ctx, *ev)
}

func waitForComposeTest(service, user, script string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := composeExecService(service, user, script)
		last = out
		if err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out: %s", last)
}

func shellQuoteE2E(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

type lfsAction struct {
	Href   string            `json:"href"`
	Header map[string]string `json:"header"`
}

type lfsBatchResponse struct {
	Objects []struct {
		OID     string               `json:"oid"`
		Size    int64                `json:"size"`
		Actions map[string]lfsAction `json:"actions"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"objects"`
}

func runLFSE2E(client *http.Client, key nostr.SecretKey, giteaUser string) error {
	oldTimeout := client.Timeout
	client.Timeout = 60 * time.Second
	defer func() { client.Timeout = oldTimeout }()

	readToken, err := mintBridgeToken(client, key, "phase5-lfs-read", []string{"lfs:read"})
	if err != nil {
		return err
	}
	writeToken, err := mintBridgeToken(client, key, "phase5-lfs-write", []string{"lfs:write"})
	if err != nil {
		return err
	}

	object := make([]byte, 16<<20)
	for i := range object {
		object[i] = byte((i*31 + 17) % 251)
	}
	digest := sha256.Sum256(object)
	oid := hex.EncodeToString(digest[:])
	endpoint := publicURL + "/" + url.PathEscape(giteaUser) + "/phase4-bridge-write.git/info/lfs"
	uploadBody, err := json.Marshal(map[string]any{
		"operation": "upload",
		"transfers": []string{"basic"},
		"objects":   []map[string]any{{"oid": oid, "size": len(object)}},
	})
	if err != nil {
		return err
	}

	status, denied, err := lfsRequest(client, http.MethodPost, endpoint+"/objects/batch", uploadBody, "Bearer "+readToken, 1<<20)
	if err != nil || status != http.StatusForbidden {
		return fmt.Errorf("lfs:read upload batch = %d, %v; want 403: %s", status, err, denied)
	}
	status, denied, err = lfsRequest(client, http.MethodPost, endpoint+"/objects/batch", uploadBody, "", 1<<20)
	if err != nil || (status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusNotFound) {
		return fmt.Errorf("anonymous LFS upload batch = %d, %v; want 401/403/404 denial: %s", status, err, denied)
	}
	directAuth, err := nip98Authorization(key, http.MethodPost, endpoint+"/objects/batch", uploadBody)
	if err != nil {
		return err
	}
	status, denied, err = lfsRequest(client, http.MethodPost, endpoint+"/objects/batch", uploadBody, directAuth, 1<<20)
	if err != nil || status != http.StatusForbidden {
		return fmt.Errorf("direct NIP-98 LFS batch = %d, %v; want 403: %s", status, err, denied)
	}

	status, payload, err := lfsRequest(client, http.MethodPost, endpoint+"/objects/batch", uploadBody, "Bearer "+writeToken, 1<<20)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("lfs:write upload batch = %d, %v: %s", status, err, payload)
	}
	var upload lfsBatchResponse
	if err := json.Unmarshal(payload, &upload); err != nil {
		return fmt.Errorf("decode LFS upload batch: %w: %s", err, payload)
	}
	uploadAction, err := lfsObjectAction(upload, oid, "upload")
	if err != nil {
		return err
	}
	if err := validatePublicLFSAction(uploadAction, writeToken); err != nil {
		return fmt.Errorf("upload action: %w", err)
	}
	status, payload, err = lfsRequest(client, http.MethodPut, uploadAction.Href, object, uploadAction.Header["Authorization"], 1<<20)
	if err != nil || (status != http.StatusOK && status != http.StatusCreated) {
		return fmt.Errorf("stream 16 MiB LFS upload = %d, %v: %s", status, err, payload)
	}

	downloadBody, err := json.Marshal(map[string]any{
		"operation": "download",
		"transfers": []string{"basic"},
		"objects":   []map[string]any{{"oid": oid, "size": len(object)}},
	})
	if err != nil {
		return err
	}
	status, payload, err = lfsRequest(client, http.MethodPost, endpoint+"/objects/batch", downloadBody, "Bearer "+readToken, 1<<20)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("lfs:read download batch = %d, %v: %s", status, err, payload)
	}
	var download lfsBatchResponse
	if err := json.Unmarshal(payload, &download); err != nil {
		return fmt.Errorf("decode LFS download batch: %w: %s", err, payload)
	}
	downloadAction, err := lfsObjectAction(download, oid, "download")
	if err != nil {
		return err
	}
	if err := validatePublicLFSAction(downloadAction, readToken); err != nil {
		return fmt.Errorf("download action: %w", err)
	}
	status, downloaded, err := lfsRequest(client, http.MethodGet, downloadAction.Href, nil, downloadAction.Header["Authorization"], int64(len(object)+1))
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("stream 16 MiB LFS download = %d, %v: %s", status, err, downloaded)
	}
	if !bytes.Equal(downloaded, object) {
		return fmt.Errorf("LFS object round-trip mismatch: got %d bytes, want %d", len(downloaded), len(object))
	}

	lockBody := []byte(`{"path":"phase5-lfs-locked.bin"}`)
	status, payload, err = lfsRequest(client, http.MethodPost, endpoint+"/locks", lockBody, "Bearer "+writeToken, 1<<20)
	if err != nil || status != http.StatusCreated {
		return fmt.Errorf("lfs:write create lock = %d, %v: %s", status, err, payload)
	}
	var created struct {
		Lock struct {
			ID string `json:"id"`
		} `json:"lock"`
	}
	if err := json.Unmarshal(payload, &created); err != nil || created.Lock.ID == "" {
		return fmt.Errorf("decode created LFS lock: %v: %s", err, payload)
	}
	status, payload, err = lfsRequest(client, http.MethodGet, endpoint+"/locks", nil, "Bearer "+readToken, 1<<20)
	if err != nil || status != http.StatusOK || !bytes.Contains(payload, []byte(created.Lock.ID)) {
		return fmt.Errorf("lfs:read list locks = %d, %v: %s", status, err, payload)
	}
	status, payload, err = lfsRequest(client, http.MethodPost, endpoint+"/locks/"+url.PathEscape(created.Lock.ID)+"/unlock", []byte(`{}`), "Bearer "+writeToken, 1<<20)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("lfs:write unlock = %d, %v: %s", status, err, payload)
	}
	return nil
}

func lfsObjectAction(batch lfsBatchResponse, oid, name string) (lfsAction, error) {
	for _, object := range batch.Objects {
		if object.OID != oid {
			continue
		}
		if object.Error != nil {
			return lfsAction{}, fmt.Errorf("LFS batch object error %d: %s", object.Error.Code, object.Error.Message)
		}
		action, ok := object.Actions[name]
		if !ok || action.Href == "" {
			return lfsAction{}, fmt.Errorf("LFS batch object has no %s action", name)
		}
		return action, nil
	}
	return lfsAction{}, fmt.Errorf("LFS batch omitted object %s", oid)
}

func validatePublicLFSAction(action lfsAction, bridgeToken string) error {
	parsed, err := url.Parse(action.Href)
	if err != nil {
		return fmt.Errorf("invalid transfer URL %q: %w", action.Href, err)
	}
	if parsed.Scheme != "https" || parsed.Host != "grasp.test" {
		return fmt.Errorf("transfer URL did not use public origin: %q", action.Href)
	}
	if authorization := action.Header["Authorization"]; authorization != "Bearer "+bridgeToken {
		return fmt.Errorf("transfer action did not carry the scoped bridge token")
	}
	return nil
}

func lfsRequest(client *http.Client, method, target string, body []byte, authorization string, limit int64) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		if method == http.MethodPut {
			req.Header.Set("Content-Type", "application/octet-stream")
		} else {
			req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
		}
	}
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, payload, err
}

func (f *hookFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.delay.Load() {
		time.Sleep(2 * time.Second)
	}
	if r.URL.Path != "/repository-state/proposed" || r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	f.calls.Add(1)
	commit, _ := f.commit.Load().(string)
	event := nostr.Event{Kind: nostr.KindRepositoryState, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"d", r.URL.Query().Get("repo_id")}, {"HEAD", "ref: refs/heads/main"}, {"refs/heads/main", commit}}}
	if err := event.Sign(f.key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"event": event})
}

func browserClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ephemeral local E2E certificate
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:443")
		},
	}
	return &http.Client{Jar: jar, Transport: transport, Timeout: 15 * time.Second}
}

func mintBridgeToken(client *http.Client, key nostr.SecretKey, name string, scopes []string) (string, error) {
	body, err := json.Marshal(map[string]any{"name": name, "scopes": scopes})
	if err != nil {
		return "", err
	}
	authorization, err := nip98Authorization(key, http.MethodPost, publicURL+"/auth/token", body)
	if err != nil {
		return "", err
	}
	status, responseBody, err := request(client, http.MethodPost, publicURL+"/auth/token", body, authorization)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("mint %s bridge token = %d, want 201: %s", name, status, responseBody)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(responseBody), &result); err != nil {
		return "", fmt.Errorf("decode minted bridge token: %w: %s", err, responseBody)
	}
	if !strings.HasPrefix(result.Token, "grasp_v1_") {
		return "", fmt.Errorf("minted token has unexpected format")
	}
	return result.Token, nil
}

func nip98Authorization(key nostr.SecretKey, method, target string, body []byte) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	tags := nostr.Tags{{"u", target}, {"method", method}, {"nonce", hex.EncodeToString(nonce)}}
	if len(body) > 0 {
		payloadHash := sha256.Sum256(body)
		tags = append(tags, nostr.Tag{"payload", hex.EncodeToString(payloadHash[:])})
	}
	event := nostr.Event{Kind: 27235, CreatedAt: nostr.Now(), Tags: tags}
	if err := event.Sign(key); err != nil {
		return "", fmt.Errorf("sign NIP-98 event: %w", err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(raw), nil
}

func request(client *http.Client, method, target string, body []byte, authorization string) (int, string, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, string(responseBody), err
}

func jsonRequest(client *http.Client, method, target string, requestBody, responseBody any, want int) error {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return err
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s = %d, want %d: %s", method, target, resp.StatusCode, want, payload)
	}
	if responseBody != nil {
		if err := json.Unmarshal(payload, responseBody); err != nil {
			return fmt.Errorf("decode %s %s response: %w: %s", method, target, err, payload)
		}
	}
	return nil
}

func get(client *http.Client, target string, headers http.Header) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, "", err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, string(body), err
}

func composeExec(script string) (string, error) {
	return composeExecService("gitea", "git", script)
}

func composeControl(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func composeExecService(service, user, script string) (string, error) {
	args := []string{"compose", "exec", "-T"}
	if user != "" {
		args = append(args, "--user", user)
	}
	args = append(args, service, "sh", "-ec", script)
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

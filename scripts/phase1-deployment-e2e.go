//go:build ignore

package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

	fmt.Println("[1/8] signed NIP-07 verification through canonical TLS/nginx")
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

	fmt.Println("[2/8] cross-browser handoff and internal-header spoofing fail")
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

	fmt.Println("[3/8] handoff emits durable Gitea cookie and header-free session")
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

	fmt.Println("[4/8] one-time handoff replay fails")
	if status, _, err := get(client, verified.HandoffURL, nil); err != nil || status != http.StatusUnauthorized {
		return fmt.Errorf("handoff replay = %d, %v; want 401", status, err)
	}

	fmt.Println("[5/8] NIP-55 endpoint emits launchable Android deep link")
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

	fmt.Println("[6/8] mounted hook reads admin-token secret and accepts proposed state")
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

	fmt.Println("[7/8] in-container hook rejects new-object quota overflow")
	quota := fmt.Sprintf(`cd /tmp/grasp-phase1-e2e.git
printf '%s %s refs/nostr/%s\n' | env GRASP_REPO_NPUB='%s' GRASP_REPO_ID=demo GRASP_HOOK_RELAY_URL=ws://127.0.0.1:1 GRASP_HOOK_MAX_OBJECTS=1 hooks/pre-receive`, zeroSHA, commit, strings.Repeat("a", 64), npub)
	if out, err := composeExec(quota); err == nil || !strings.Contains(out, "new object quota exceeded") {
		return fmt.Errorf("object quota was not enforced: err=%v output=%s", err, out)
	}

	fmt.Println("[8/8] in-container hook obeys configured timeout")
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
	cmd := exec.Command("docker", "compose", "exec", "-T", "gitea", "sh", "-ec", script)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

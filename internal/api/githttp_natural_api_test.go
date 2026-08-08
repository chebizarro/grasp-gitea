// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Natural git API conformance suite (phase1-0vv).
//
// These tests prove the npub git smart-HTTP surface conforms to the
// "natural" git API consumed by nostr discovery clients (the reference
// implementation lives in git-natural-api: refs.ts + packs.ts). They run the
// real pipeline: a bare repository configured by hooks.Installer, served by
// `git http-backend` (CGI), fronted by the giteaproxy through the
// /<npub>/<id>.git path — then replay the exact byte-level request shapes the
// client sends and parse responses the same way the client does.
//
// Failure messages name the natural-api client function that would break:
// getInfoRefs, fetchPackfile, getObject, fetchCommitsOnly,
// getDirectoryTreeAt.
package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// Capability sets from git-natural-api packs.ts. necessary + default are the
// ones the client echoes on its want line; required are only checked in the
// advertisement (shallow, object-format=sha1 are server-side declarations).
var (
	naturalNecessaryCaps = []string{"multi_ack_detailed", "side-band-64k"}
	naturalRequiredCaps  = []string{"shallow", "object-format=sha1"}
	naturalDefaultCaps   = []string{"ofs-delta", "no-progress"}
)

const (
	naturalNpub   = "npub1naturalowner"
	naturalRepoID = "natural-repo"
	naturalOrg    = "natural-org"
)

// naturalGitEnv is a full npub git smart-HTTP stack over a real repository.
type naturalGitEnv struct {
	srv    *Server
	gitBin string

	repoPath string // request path prefix: /<npub>/<id>.git

	headCommit   string // tip of refs/heads/main
	parentCommit string // HEAD~1, excluded by deepen 1
	rootTree     string // HEAD^{tree}
	subTree      string // tree of the nested directory
	blobSHA      string // reachable blob that is not a ref tip
	blobContent  string

	danglingBlobSHA     string // blob in the odb reachable from no ref at all
	danglingBlobContent string
}

func newNaturalGitEnv(t *testing.T) *naturalGitEnv {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not found; skipping natural git API conformance tests")
	}

	env := &naturalGitEnv{
		gitBin:   gitBin,
		repoPath: "/" + naturalNpub + "/" + naturalRepoID + ".git",
	}

	// Build a bare repository at <reposRoot>/<org>/<repoID>.git — the exact
	// layout hooks.Installer and git http-backend both address.
	reposRoot := t.TempDir()
	bareDir := filepath.Join(reposRoot, naturalOrg, naturalRepoID+".git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatalf("create org dir: %v", err)
	}

	work := t.TempDir()
	env.git(t, work, "-c", "init.defaultBranch=main", "init", "-q")
	env.blobContent = "natural api readme\n"
	writeFile(t, filepath.Join(work, "README.md"), env.blobContent)
	writeFile(t, filepath.Join(work, "docs", "guide.md"), "guide\n")
	env.git(t, work, "add", ".")
	env.git(t, work, "commit", "-q", "-m", "first commit")
	writeFile(t, filepath.Join(work, "docs", "guide.md"), "guide v2\n")
	env.git(t, work, "commit", "-q", "-a", "-m", "second commit")

	env.git(t, work, "-c", "init.defaultBranch=main", "init", "-q", "--bare", bareDir)
	env.git(t, work, "push", "-q", bareDir, "main")

	env.headCommit = env.git(t, bareDir, "rev-parse", "HEAD")
	env.parentCommit = env.git(t, bareDir, "rev-parse", "HEAD~1")
	env.rootTree = env.git(t, bareDir, "rev-parse", "HEAD^{tree}")
	env.subTree = env.git(t, bareDir, "rev-parse", "HEAD:docs")
	env.blobSHA = env.git(t, bareDir, "rev-parse", "HEAD:README.md")

	// A dangling blob: present in the object database, reachable from no
	// ref. Nostr discovery clients can hold SHAs (from events) before any
	// ref points at them.
	env.danglingBlobContent = "dangling natural object\n"
	danglingSrc := filepath.Join(t.TempDir(), "dangling")
	writeFile(t, danglingSrc, env.danglingBlobContent)
	env.danglingBlobSHA = env.git(t, bareDir, "hash-object", "-w", danglingSrc)

	// The behavior under test: the per-repo upload-pack capabilities the
	// provisioner installs (allowFilter, allowTip/Reachable/AnySHA1InWant).
	if err := hooks.NewInstaller(reposRoot, "", "").ConfigureUploadPack(naturalOrg, naturalRepoID); err != nil {
		t.Fatalf("ConfigureUploadPack: %v", err)
	}

	// Upstream stand-in for Gitea's git smart-HTTP: git http-backend over CGI
	// serving the same bare repository tree.
	backend := httptest.NewServer(&cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Dir:  reposRoot,
		Env: []string{
			"GIT_PROJECT_ROOT=" + reposRoot,
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
		},
		InheritEnv: []string{"PATH"},
	})
	t.Cleanup(backend.Close)

	st := openGitHTTPProxyTestStore(t)
	seedGitHTTPProxyMapping(t, context.Background(), st, store.Mapping{
		Npub:        naturalNpub,
		RepoID:      naturalRepoID,
		Pubkey:      "pubkey",
		Owner:       naturalOrg,
		RepoName:    naturalRepoID,
		GiteaRepoID: 314,
		CloneURL:    backend.URL + "/" + naturalOrg + "/" + naturalRepoID + ".git",
		SourceEvent: "event-natural",
	})
	env.srv = newGitProxyTestServer(t, config.Config{GiteaURL: backend.URL}, st, publicRepo(314))
	return env
}

func (e *naturalGitEnv) git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(e.gitBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Natural API",
		"GIT_AUTHOR_EMAIL=natural@example.com",
		"GIT_AUTHOR_DATE=2026-01-02T03:04:05Z",
		"GIT_COMMITTER_NAME=Natural API",
		"GIT_COMMITTER_EMAIL=natural@example.com",
		"GIT_COMMITTER_DATE=2026-01-02T03:04:05Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (in %s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func (e *naturalGitEnv) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, req)
	return w
}

// --- refs.ts replica -------------------------------------------------------

type naturalInfoRefs struct {
	refs         map[string]string
	capabilities []string
	symrefs      map[string]string
}

func (n naturalInfoRefs) hasCapability(cap string) bool {
	for _, c := range n.capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// parseInfoRefsLikeRefsTS is a line-for-line Go port of getInfoRefs in
// git-natural-api refs.ts, including its quirks (newline splitting, JS
// substring clamping). If this parser cannot extract refs/capabilities from
// the advertisement, getInfoRefs would return garbage for real clients.
func parseInfoRefsLikeRefsTS(body string) naturalInfoRefs {
	result := naturalInfoRefs{
		refs:    map[string]string{},
		symrefs: map[string]string{},
	}

	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	for i, line := range lines {
		// skip flush packets (0000)
		if strings.HasPrefix(line, "0000") {
			line = line[4:]
		}
		if len(line) < 4 {
			continue
		}
		length, err := strconv.ParseInt(line[:4], 16, 32)
		if err != nil {
			continue
		}
		// JS String.prototype.substring clamps out-of-range indexes.
		end := int(length)
		if end > len(line) {
			end = len(line)
		}
		if end < 4 {
			end = 4
		}
		content := line[4:end]

		if i == 0 && strings.HasPrefix(content, "# service=") {
			continue
		}
		if !strings.Contains(content, " ") {
			continue
		}
		parts := strings.Split(content, " ")
		hash := parts[0]
		refAndCaps := strings.Join(parts[1:], " ")
		if strings.Contains(refAndCaps, "\x00") {
			refCaps := strings.SplitN(refAndCaps, "\x00", 2)
			result.refs[strings.TrimSpace(refCaps[0])] = hash
			caps := strings.Split(strings.TrimSpace(refCaps[1]), " ")
			result.capabilities = caps
			for _, cap := range caps {
				if strings.HasPrefix(cap, "symref=") {
					fromTo := strings.SplitN(cap[len("symref="):], ":", 2)
					if len(fromTo) == 2 {
						result.symrefs[fromTo[0]] = fromTo[1]
					}
				}
			}
		} else {
			result.refs[strings.TrimSpace(refAndCaps)] = hash
		}
	}
	return result
}

// --- packs.ts replica ------------------------------------------------------

// pktEncode mirrors pktEncode in packs.ts: "" becomes a flush-pkt.
func pktEncode(data string) string {
	if len(data) == 0 {
		return "0000"
	}
	return fmt.Sprintf("%04x%s", len(data)+4, data)
}

// naturalWantRequest mirrors createWantRequest in packs.ts byte for byte:
// pkt-lines `want <sha> <caps> agent=nsa/1.0.0`, optional `deepen N`,
// optional `filter <spec>`, flush, `done`.
func naturalWantRequest(sha string, capabilities []string, deepen int, filter string) string {
	pkts := []string{
		fmt.Sprintf("want %s %s agent=nsa/1.0.0\n", sha, strings.Join(capabilities, " ")),
	}
	if deepen >= 0 {
		pkts = append(pkts, fmt.Sprintf("deepen %d\n", deepen))
	}
	if filter != "" {
		pkts = append(pkts, "filter "+filter+"\n")
	}
	pkts = append(pkts, "", "done\n")

	var b strings.Builder
	for _, p := range pkts {
		b.WriteString(pktEncode(p))
	}
	return b.String()
}

// demuxUploadPackLikePacksTS extracts the packfile from an upload-pack
// response the way fetchPackfile in packs.ts does: scan newline-delimited
// data until a line ending in "NAK", then side-band-64k demux keeping band 1.
// Any divergence fatal here means fetchPackfile (and everything built on it:
// getObject, fetchCommitsOnly, getDirectoryTreeAt) would fail or return
// garbage.
func demuxUploadPackLikePacksTS(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) == 0 {
		t.Fatal("fetchPackfile would fail: empty git-upload-pack response body")
	}

	// Find the NAK line (packs.ts scans byte 10 = '\n').
	offset := 0
	for {
		if offset >= len(data) {
			t.Fatalf("fetchPackfile would fail: no NAK found in upload-pack response; first bytes: %q", clip(data, 64))
		}
		prev := offset
		idx := bytes.IndexByte(data[prev+1:], '\n')
		if idx == -1 {
			// packs.ts special-cases the pkt-line `ERR upload-pack: not our ref`.
			if len(data) >= 32 && string(data[4:32]) == "ERR upload-pack: not our ref" {
				t.Fatalf("fetchPackfile would throw MissingRef: server refused the want: %q", clip(data, 96))
			}
			t.Fatalf("fetchPackfile would fail: unexpected upload-pack response %q", clip(data, 64))
		}
		offset = prev + idx + 1
		if offset >= 3 && string(data[offset-3:offset]) == "NAK" {
			break
		}
	}
	offset++ // past NAK's '\n'

	// Side-band-64k demux: keep band 1 (pack data), ignore band 2 (progress).
	var pack []byte
	for offset < len(data) {
		if offset+4 > len(data) {
			t.Fatalf("fetchPackfile would fail: truncated pkt-line header at offset %d", offset)
		}
		length64, err := strconv.ParseInt(string(data[offset:offset+4]), 16, 32)
		if err != nil {
			t.Fatalf("fetchPackfile would fail: bad pkt-line length %q at offset %d", data[offset:offset+4], offset)
		}
		length := int(length64)
		if length == 0 {
			break // flush-pkt ends the stream
		}
		if offset+length > len(data) {
			t.Fatalf("fetchPackfile would fail: pkt-line overruns response (len %d at offset %d, body %d)", length, offset, len(data))
		}
		switch data[offset+4] {
		case 1:
			pack = append(pack, data[offset+5:offset+length]...)
		case 2:
			// progress message, ignored like packs.ts
		case 3:
			t.Fatalf("fetchPackfile would return garbage: server error on side-band 3: %q", data[offset+5:offset+length])
		default:
			// packs.ts silently drops unknown bands; that is data loss.
			t.Fatalf("fetchPackfile would drop data: unknown side-band %d", data[offset+4])
		}
		offset += length
	}
	return pack
}

func clip(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// unpackObjects indexes a raw packfile into a scratch repository so object
// presence/content can be asserted with cat-file. A pack git cannot unpack
// would equally break parsePackfile on the client.
func (e *naturalGitEnv) unpackObjects(t *testing.T, pack []byte) string {
	t.Helper()
	if len(pack) < 12 || string(pack[:4]) != "PACK" {
		t.Fatalf("parsePackfile would fail: invalid packfile header %q", clip(pack, 8))
	}
	if version := uint32(pack[4])<<24 | uint32(pack[5])<<16 | uint32(pack[6])<<8 | uint32(pack[7]); version != 2 {
		t.Fatalf("parsePackfile would fail: unsupported packfile version %d", version)
	}

	dir := t.TempDir()
	e.git(t, dir, "init", "-q")
	cmd := exec.Command(e.gitBin, "unpack-objects", "-q")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	cmd.Stdin = bytes.NewReader(pack)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git unpack-objects rejected the returned pack: %v\n%s", err, out)
	}
	return dir
}

// hasObject reports whether sha exists in the scratch repository dir.
func (e *naturalGitEnv) hasObject(dir, sha string) bool {
	cmd := exec.Command(e.gitBin, "cat-file", "-e", sha)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	return cmd.Run() == nil
}

// --- the conformance tests -------------------------------------------------

// Behavior 1: GET info/refs?service=git-upload-pack returns a protocol-v0
// pkt-line advertisement that refs.ts getInfoRefs parses, advertising every
// capability the natural-api client checks or echoes.
func TestNaturalAPIInfoRefsAdvertisement(t *testing.T) {
	env := newNaturalGitEnv(t)

	req := httptest.NewRequest(http.MethodGet, env.repoPath+"/info/refs?service=git-upload-pack", nil)
	w := env.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("getInfoRefs would fail: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	assertGitHTTPCORS(t, w.Result().Header)
	if ct := w.Result().Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("smart-http advertisement Content-Type = %q, want application/x-git-upload-pack-advertisement", ct)
	}

	body := w.Body.String()
	if !strings.HasPrefix(body, "001e# service=git-upload-pack\n") {
		t.Errorf("getInfoRefs expects a smart advertisement starting with the service pkt-line, got %q", clip([]byte(body), 40))
	}

	info := parseInfoRefsLikeRefsTS(body)

	if got := info.refs["HEAD"]; got != env.headCommit {
		t.Errorf("getInfoRefs would resolve HEAD to %q, want %q", got, env.headCommit)
	}
	if got := info.refs["refs/heads/main"]; got != env.headCommit {
		t.Errorf("getInfoRefs would resolve refs/heads/main to %q, want %q", got, env.headCommit)
	}
	if got := info.symrefs["HEAD"]; got != "refs/heads/main" {
		t.Errorf("getInfoRefs would resolve symref HEAD to %q, want refs/heads/main (clients use it to find the default branch)", got)
	}

	// necessaryCapabilities: fetchPackfile callers throw MissingCapability
	// without these.
	for _, cap := range naturalNecessaryCaps {
		if !info.hasCapability(cap) {
			t.Errorf("missing capability %q: getObject/fetchCommitsOnly/getDirectoryTreeAt would throw MissingCapability", cap)
		}
	}
	// requiredCapabilities: checked in the advertisement before any fetch.
	for _, cap := range naturalRequiredCaps {
		if !info.hasCapability(cap) {
			t.Errorf("missing capability %q: getObject/fetchCommitsOnly/getDirectoryTreeAt would throw MissingCapability", cap)
		}
	}
	// defaultCapabilities: echoed when advertised; their absence changes the
	// request shape the server has been validated against.
	for _, cap := range naturalDefaultCaps {
		if !info.hasCapability(cap) {
			t.Errorf("missing capability %q: natural-api clients would negotiate without it", cap)
		}
	}
	// filter: required by fetchCommitsOnly and getDirectoryTreeAt
	// (uploadpack.allowFilter from hooks.Installer).
	if !info.hasCapability("filter") {
		t.Error("missing capability \"filter\": fetchCommitsOnly and getDirectoryTreeAt would throw MissingCapability")
	}
	// uploadpack.allowTipSHA1InWant / allowReachableSHA1InWant /
	// allowAnySHA1InWant. Protocol v0 has no allow-any-sha1-in-want token:
	// allowAnySHA1InWant is advertised as tip+reachable and proven
	// behaviorally by TestNaturalAPIWantArbitraryBlob.
	for _, cap := range []string{"allow-tip-sha1-in-want", "allow-reachable-sha1-in-want"} {
		if !info.hasCapability(cap) {
			t.Errorf("missing capability %q: getObject wants of non-tip SHAs would be refused (not our ref)", cap)
		}
	}
}

// Behavior 2: POST git-upload-pack with the exact packs.ts request shape —
// want + deepen 1 + filter blob:none, flush, done — answers NAK plus a
// side-band-64k packfile containing the commit and its trees but no blobs
// and no parent commit. This is getDirectoryTreeAt's request.
func TestNaturalAPIUploadPackDeepenFilterBlobNone(t *testing.T) {
	env := newNaturalGitEnv(t)

	// getDirectoryTreeAt: defaults + necessary + filter on the want line.
	caps := append(append([]string{}, naturalDefaultCaps...), naturalNecessaryCaps...)
	caps = append(caps, "filter")
	body := naturalWantRequest(env.headCommit, caps, 1, "blob:none")

	req := httptest.NewRequest(http.MethodPost, env.repoPath+"/git-upload-pack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	w := env.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fetchPackfile would fail: expected 200 from git-upload-pack, got %d: %s", w.Code, w.Body.String())
	}
	assertGitHTTPCORS(t, w.Result().Header)

	pack := demuxUploadPackLikePacksTS(t, w.Body.Bytes())
	dir := env.unpackObjects(t, pack)

	if !env.hasObject(dir, env.headCommit) {
		t.Errorf("getDirectoryTreeAt would fail: wanted commit %s missing from pack", env.headCommit)
	}
	if !env.hasObject(dir, env.rootTree) {
		t.Errorf("getDirectoryTreeAt would fail: root tree %s missing from pack", env.rootTree)
	}
	if !env.hasObject(dir, env.subTree) {
		t.Errorf("getDirectoryTreeAt would fail: nested tree %s missing from pack", env.subTree)
	}
	if env.hasObject(dir, env.blobSHA) {
		t.Errorf("filter blob:none not honored: blob %s present in pack (allowFilter misconfigured?)", env.blobSHA)
	}
	if env.hasObject(dir, env.parentCommit) {
		t.Errorf("deepen 1 not honored: parent commit %s present in pack", env.parentCommit)
	}
}

// Behavior 2b: fetchCommitsOnly uses filter tree:0 — commits only.
func TestNaturalAPIUploadPackFilterTreeZero(t *testing.T) {
	env := newNaturalGitEnv(t)

	caps := append(append([]string{}, naturalDefaultCaps...), naturalNecessaryCaps...)
	caps = append(caps, "filter")
	body := naturalWantRequest(env.headCommit, caps, 1, "tree:0")

	req := httptest.NewRequest(http.MethodPost, env.repoPath+"/git-upload-pack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	w := env.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fetchCommitsOnly would fail: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	pack := demuxUploadPackLikePacksTS(t, w.Body.Bytes())
	dir := env.unpackObjects(t, pack)

	if !env.hasObject(dir, env.headCommit) {
		t.Errorf("fetchCommitsOnly would fail: wanted commit %s missing from pack", env.headCommit)
	}
	if env.hasObject(dir, env.rootTree) {
		t.Errorf("filter tree:0 not honored: tree %s present in pack", env.rootTree)
	}
	if env.hasObject(dir, env.blobSHA) {
		t.Errorf("filter tree:0 not honored: blob %s present in pack", env.blobSHA)
	}
}

// Behavior 3: a want of an arbitrary reachable blob (not a ref tip) succeeds
// and returns that blob. This is getObject's request shape (deepen 1, no
// filter). Note: modern git serves reachable non-tip wants over stateless
// RPC unconditionally; uploadpack.allowTip/Reachable/AnySHA1InWant (set by
// hooks.Installer, pinned by its unit tests) make this explicit and keep it
// working on older git versions.
func TestNaturalAPIWantArbitraryBlob(t *testing.T) {
	env := newNaturalGitEnv(t)

	caps := append(append([]string{}, naturalDefaultCaps...), naturalNecessaryCaps...)
	body := naturalWantRequest(env.blobSHA, caps, 1, "")

	req := httptest.NewRequest(http.MethodPost, env.repoPath+"/git-upload-pack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	w := env.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("getObject would fail: expected 200 for blob want (allowAnySHA1InWant), got %d: %s", w.Code, w.Body.String())
	}
	assertGitHTTPCORS(t, w.Result().Header)

	pack := demuxUploadPackLikePacksTS(t, w.Body.Bytes())
	dir := env.unpackObjects(t, pack)

	if !env.hasObject(dir, env.blobSHA) {
		t.Fatalf("getObject would return undefined: wanted blob %s missing from pack", env.blobSHA)
	}
	cmd := exec.Command(env.gitBin, "cat-file", "-p", env.blobSHA)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cat-file blob: %v", err)
	}
	if string(out) != env.blobContent {
		t.Errorf("getObject would return wrong content: got %q, want %q", out, env.blobContent)
	}
}

// Behavior 3b: a want of a dangling blob — in the object database but
// reachable from no ref — also succeeds and returns the blob
// (uploadpack.allowAnySHA1InWant territory: nostr events can reference
// objects before any ref advertises them).
func TestNaturalAPIWantDanglingBlob(t *testing.T) {
	env := newNaturalGitEnv(t)

	caps := append(append([]string{}, naturalDefaultCaps...), naturalNecessaryCaps...)
	body := naturalWantRequest(env.danglingBlobSHA, caps, 1, "")

	req := httptest.NewRequest(http.MethodPost, env.repoPath+"/git-upload-pack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	w := env.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("getObject would fail: expected 200 for dangling-blob want (allowAnySHA1InWant), got %d: %s", w.Code, w.Body.String())
	}

	pack := demuxUploadPackLikePacksTS(t, w.Body.Bytes())
	dir := env.unpackObjects(t, pack)

	if !env.hasObject(dir, env.danglingBlobSHA) {
		t.Fatalf("getObject would return undefined: wanted dangling blob %s missing from pack", env.danglingBlobSHA)
	}
}

// Behavior 4: browser-based discovery clients need CORS on both endpoints
// and a 204 preflight. Without these every natural-api call fails in a
// browser before git protocol parsing even starts.
func TestNaturalAPICORSAndPreflight(t *testing.T) {
	env := newNaturalGitEnv(t)

	for _, path := range []string{
		env.repoPath + "/info/refs?service=git-upload-pack",
		env.repoPath + "/git-upload-pack",
	} {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", "https://gitworkshop.dev")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		w := env.do(t, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("browser preflight for %s: expected 204, got %d (fetch() in getInfoRefs/fetchPackfile would be blocked)", path, w.Code)
		}
		assertGitHTTPCORS(t, w.Result().Header)
	}
}

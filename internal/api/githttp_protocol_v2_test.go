// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Git wire protocol v2 opt-in conformance (phase1-7g2).
//
// A client that sends "Git-Protocol: version=2" on the npub git smart-HTTP
// surface gets the protocol v2 capability advertisement and can drive v2
// ls-refs and fetch; clients that do not send the header — the
// git-natural-api reference client never does — keep receiving the
// byte-identical protocol v0 advertisement pinned by
// githttp_natural_api_test.go.
//
// The stack is the same real pipeline as the natural-api suite: a bare
// repository behind `git http-backend` (CGI) fronted by the giteaproxy.
// Go's net/http/cgi host maps the Git-Protocol request header to the
// HTTP_GIT_PROTOCOL CGI variable, and git http-backend (>= 2.18) promotes
// HTTP_GIT_PROTOCOL to GIT_PROTOCOL for upload-pack — the same contract a
// production web server (or Gitea's built-in git HTTP route) implements.
package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// parsePktLines splits a pkt-line stream into content strings with the
// trailing newline trimmed. Flush and delim packets are kept literally as
// "0000" and "0001".
func parsePktLines(t *testing.T, data []byte) []string {
	t.Helper()
	var lines []string
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			t.Fatalf("truncated pkt-line header at offset %d", off)
		}
		n, err := strconv.ParseInt(string(data[off:off+4]), 16, 32)
		if err != nil {
			t.Fatalf("bad pkt-line length %q at offset %d", data[off:off+4], off)
		}
		length := int(n)
		switch {
		case length == 0:
			lines = append(lines, "0000")
			off += 4
		case length == 1:
			lines = append(lines, "0001")
			off += 4
		case length < 4 || off+length > len(data):
			t.Fatalf("pkt-line length %d overruns body (offset %d, body %d)", length, off, len(data))
		default:
			lines = append(lines, strings.TrimSuffix(string(data[off+4:off+length]), "\n"))
			off += length
		}
	}
	return lines
}

// hasV2Capability reports whether a v2 capability advertisement lists the
// capability, bare or with a value ("fetch" matches "fetch=shallow filter").
func hasV2Capability(lines []string, capability string) bool {
	for _, l := range lines {
		if l == capability || strings.HasPrefix(l, capability+"=") {
			return true
		}
	}
	return false
}

// advertise fetches info/refs?service=git-upload-pack, optionally with a
// Git-Protocol header value, and requires a 200.
func (e *naturalGitEnv) advertise(t *testing.T, gitProtocol string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, e.repoPath+"/info/refs?service=git-upload-pack", nil)
	if gitProtocol != "" {
		req.Header.Set("Git-Protocol", gitProtocol)
	}
	w := e.do(t, req)
	if w.Code != http.StatusOK {
		t.Fatalf("info/refs (Git-Protocol=%q): expected 200, got %d: %s", gitProtocol, w.Code, w.Body.String())
	}
	return w
}

// v2UploadPack POSTs a protocol v2 command to git-upload-pack.
func (e *naturalGitEnv) v2UploadPack(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, e.repoPath+"/git-upload-pack", strings.NewReader(body))
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	return e.do(t, req)
}

// Behavior: a request WITH "Git-Protocol: version=2" gets the protocol v2
// capability advertisement (no "# service=" preamble, opens with a
// "version 2" pkt, lists ls-refs and fetch).
func TestGitProtocolV2AdvertisementOptIn(t *testing.T) {
	env := newNaturalGitEnv(t)

	w := env.advertise(t, "version=2")
	assertGitHTTPCORS(t, w.Result().Header)
	if ct := w.Result().Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("v2 advertisement Content-Type = %q, want application/x-git-upload-pack-advertisement", ct)
	}

	body := w.Body.Bytes()
	if strings.HasPrefix(string(body), "001e# service=git-upload-pack\n") {
		t.Fatalf("v2 opt-in still answered the v0 '# service=' preamble; GIT_PROTOCOL is not reaching upload-pack: %q", clip(body, 64))
	}
	lines := parsePktLines(t, body)
	if len(lines) == 0 || lines[0] != "version 2" {
		t.Fatalf("expected the v2 advertisement to open with a \"version 2\" pkt, got %q", clip(body, 64))
	}
	for _, capability := range []string{"ls-refs", "fetch", "object-format"} {
		if !hasV2Capability(lines, capability) {
			t.Errorf("v2 advertisement missing capability %q in %q", capability, lines)
		}
	}
	// fetch must carry filter (uploadpack.allowFilter from hooks.Installer)
	// so v2 partial fetches keep working like their v0 counterparts.
	for _, l := range lines {
		if strings.HasPrefix(l, "fetch=") && !strings.Contains(l, "filter") {
			t.Errorf("v2 fetch capability %q does not advertise filter (uploadpack.allowFilter lost?)", l)
		}
	}
}

// Behavior: a request WITHOUT the header keeps the exact protocol v0
// advertisement — byte-identical to an explicit "version=0" request and
// still parseable by the refs.ts replica. This is the git-natural-api
// client's request shape; it must never observe v2.
func TestGitProtocolAbsentHeaderKeepsV0Advertisement(t *testing.T) {
	env := newNaturalGitEnv(t)

	noHeader := append([]byte(nil), env.advertise(t, "").Body.Bytes()...)
	explicitV0 := env.advertise(t, "version=0").Body.Bytes()

	if !bytes.Equal(noHeader, explicitV0) {
		t.Errorf("advertisement without Git-Protocol differs from explicit version=0: %q vs %q", clip(noHeader, 96), clip(explicitV0, 96))
	}
	if !strings.HasPrefix(string(noHeader), "001e# service=git-upload-pack\n") {
		t.Fatalf("v0 advertisement lost its service pkt-line preamble: %q", clip(noHeader, 64))
	}
	if bytes.Contains(noHeader, []byte("version 2")) {
		t.Fatalf("v0 advertisement leaked protocol v2 content: %q", clip(noHeader, 96))
	}

	info := parseInfoRefsLikeRefsTS(string(noHeader))
	if got := info.refs["refs/heads/main"]; got != env.headCommit {
		t.Errorf("getInfoRefs would resolve refs/heads/main to %q, want %q", got, env.headCommit)
	}
	if got := info.symrefs["HEAD"]; got != "refs/heads/main" {
		t.Errorf("getInfoRefs would resolve symref HEAD to %q, want refs/heads/main", got)
	}
}

// Behavior: protocol v2 ls-refs works end to end through the proxy.
func TestGitProtocolV2LsRefs(t *testing.T) {
	env := newNaturalGitEnv(t)

	var b strings.Builder
	b.WriteString(pktEncode("command=ls-refs\n"))
	b.WriteString("0001") // delim-pkt
	b.WriteString(pktEncode("peel\n"))
	b.WriteString(pktEncode("symrefs\n"))
	b.WriteString(pktEncode("ref-prefix refs/heads/\n"))
	b.WriteString("0000")

	w := env.v2UploadPack(t, b.String())
	if w.Code != http.StatusOK {
		t.Fatalf("v2 ls-refs: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	assertGitHTTPCORS(t, w.Result().Header)

	lines := parsePktLines(t, w.Body.Bytes())
	want := env.headCommit + " refs/heads/main"
	found := false
	for _, l := range lines {
		if l == want {
			found = true
		}
	}
	if !found {
		t.Errorf("v2 ls-refs response %q missing %q", lines, want)
	}
}

// Behavior: protocol v2 fetch honors the per-repo uploadpack configuration
// installed by hooks.Installer — filter blob:none returns the commit and
// trees but no blobs.
func TestGitProtocolV2FetchFilterBlobNone(t *testing.T) {
	env := newNaturalGitEnv(t)

	var b strings.Builder
	b.WriteString(pktEncode("command=fetch\n"))
	b.WriteString("0001") // delim-pkt
	b.WriteString(pktEncode("want " + env.headCommit + "\n"))
	b.WriteString(pktEncode("filter blob:none\n"))
	b.WriteString(pktEncode("no-progress\n"))
	b.WriteString(pktEncode("done\n"))
	b.WriteString("0000")

	w := env.v2UploadPack(t, b.String())
	if w.Code != http.StatusOK {
		t.Fatalf("v2 fetch: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Demux the v2 fetch response: pkt-line sections until "packfile",
	// then side-band pkts (band 1 = pack data).
	data := w.Body.Bytes()
	var pack []byte
	inPack := false
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			t.Fatalf("truncated pkt-line header at offset %d", off)
		}
		n, err := strconv.ParseInt(string(data[off:off+4]), 16, 32)
		if err != nil {
			t.Fatalf("bad pkt-line length %q at offset %d", data[off:off+4], off)
		}
		length := int(n)
		if length <= 1 { // flush-pkt or delim-pkt
			off += 4
			continue
		}
		content := data[off+4 : off+length]
		if !inPack {
			if string(content) == "packfile\n" {
				inPack = true
			}
		} else {
			switch content[0] {
			case 1:
				pack = append(pack, content[1:]...)
			case 2:
				// progress, ignored
			case 3:
				t.Fatalf("v2 fetch server error on side-band 3: %q", content[1:])
			default:
				t.Fatalf("v2 fetch unknown side-band %d", content[0])
			}
		}
		off += length
	}
	if !inPack {
		t.Fatalf("v2 fetch response has no packfile section: %q", clip(data, 96))
	}

	dir := env.unpackObjects(t, pack)
	if !env.hasObject(dir, env.headCommit) {
		t.Errorf("v2 fetch: wanted commit %s missing from pack", env.headCommit)
	}
	if !env.hasObject(dir, env.rootTree) {
		t.Errorf("v2 fetch: root tree %s missing from pack", env.rootTree)
	}
	if env.hasObject(dir, env.blobSHA) {
		t.Errorf("v2 fetch filter blob:none not honored: blob %s present in pack (uploadpack.allowFilter misconfigured?)", env.blobSHA)
	}
}

// Behavior: a browser preflight naming Git-Protocol succeeds — the fixed
// CORS allow-list must include it or fetch() would strip the opt-in header
// and every browser client would silently fall back to v0.
func TestGitProtocolCORSPreflightAllowsHeader(t *testing.T) {
	env := newNaturalGitEnv(t)

	for _, path := range []string{
		env.repoPath + "/info/refs?service=git-upload-pack",
		env.repoPath + "/git-upload-pack",
	} {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", "https://gitworkshop.dev")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Git-Protocol")
		w := env.do(t, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("preflight for %s: expected 204, got %d", path, w.Code)
		}
		allow := w.Result().Header.Get("Access-Control-Allow-Headers")
		if !strings.Contains(allow, "Git-Protocol") {
			t.Errorf("preflight for %s: Access-Control-Allow-Headers %q does not allow Git-Protocol", path, allow)
		}
	}
}

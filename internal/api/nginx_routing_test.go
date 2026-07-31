// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/giteaproxy"
)

// The full-proxy nginx config decides which traffic reaches the bridge and
// which internal headers are cleared. A regex or ordering mistake there
// silently routes requests to the wrong place or leaves a header forgeable,
// and nginx is not available in unit tests. These tests model nginx's
// location-selection rules and assert the deployed config routes as intended.
//
// nginx selects a location by: exact (=) match first; then the longest prefix
// match is remembered; then regex locations are tried in file order and the
// first match wins; otherwise the remembered prefix is used.

const fullProxyConfPath = "../../deploy/nginx/gitea-vhost.conf.example"
const legacyConfPath = "../../deploy/nginx/gitea-vhost.legacy.conf.example"

type nginxLocation struct {
	kind    string // "exact", "regex", "prefix", "named"
	pattern string
	re      *regexp.Regexp
	body    string
}

// parseNginxLocations extracts top-level location blocks in file order.
func parseNginxLocations(t *testing.T, path string) []nginxLocation {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)

	header := regexp.MustCompile(`(?m)^\s*location\s+(=\s*|~\*?\s*|\^~\s*)?(\S+)\s*\{`)
	matches := header.FindAllStringSubmatchIndex(text, -1)
	locations := make([]nginxLocation, 0, len(matches))

	for _, m := range matches {
		// The modifier group is optional; an unmatched group has index -1.
		modifier := ""
		if m[2] >= 0 {
			modifier = strings.TrimSpace(text[m[2]:m[3]])
		}
		pattern := text[m[4]:m[5]]

		// Capture the block body by brace balancing from the opening brace.
		depth, end := 0, -1
		for i := m[1] - 1; i < len(text); i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("unbalanced braces for location %q", pattern)
		}
		body := text[m[1]:end]

		loc := nginxLocation{pattern: pattern, body: body}
		switch {
		case strings.HasPrefix(pattern, "@"):
			loc.kind = "named"
		case modifier == "=":
			loc.kind = "exact"
		case strings.HasPrefix(modifier, "~"):
			loc.kind = "regex"
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("location regex %q does not compile: %v", pattern, err)
			}
			loc.re = re
		default:
			loc.kind = "prefix"
		}
		locations = append(locations, loc)
	}
	if len(locations) == 0 {
		t.Fatalf("no locations parsed from %s", path)
	}
	return locations
}

// selectLocation mimics nginx location selection for a URI.
func selectLocation(locs []nginxLocation, uri string) *nginxLocation {
	for i := range locs {
		if locs[i].kind == "exact" && locs[i].pattern == uri {
			return &locs[i]
		}
	}
	var prefix *nginxLocation
	for i := range locs {
		if locs[i].kind != "prefix" || !strings.HasPrefix(uri, locs[i].pattern) {
			continue
		}
		if prefix == nil || len(locs[i].pattern) > len(prefix.pattern) {
			prefix = &locs[i]
		}
	}
	for i := range locs {
		if locs[i].kind == "regex" && locs[i].re.MatchString(uri) {
			return &locs[i]
		}
	}
	return prefix
}

func upstreamOf(loc *nginxLocation) string {
	if loc == nil {
		return ""
	}
	m := regexp.MustCompile(`proxy_pass\s+http://([a-zA-Z0-9_]+)`).FindStringSubmatch(loc.body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func TestFullProxyConfigRoutesEverythingToTheBridge(t *testing.T) {
	locs := parseNginxLocations(t, fullProxyConfPath)

	cases := []struct {
		uri  string
		what string
	}{
		{"/", "Gitea UI root"},
		{"/explore/repos", "Gitea UI"},
		{"/api/v1/user", "Gitea REST API"},
		{"/api/packages/owner/npm/pkg", "package registry"},
		{"/v2/owner/image/blobs/uploads/", "container registry"},
		{"/owner/repo.git/info/refs", "conventional git"},
		{"/owner/repo.git/git-receive-pack", "conventional git push"},
		{"/owner/repo.git/info/lfs/objects/batch", "git LFS"},
		{"/npub1abc/repo.git/info/refs", "canonical npub git"},
		{"/npub1abc/repo.git/git-receive-pack", "public GRASP push"},
		{"/auth/token", "token minting"},
		{"/auth/tokens/abc123", "token management"},
		{"/user/login", "Gitea login page"},
		{"/assets/img/logo.svg", "static asset"},
	}

	for _, tc := range cases {
		loc := selectLocation(locs, tc.uri)
		if loc == nil {
			t.Errorf("%s (%s): no location matched", tc.uri, tc.what)
			continue
		}
		if got := upstreamOf(loc); got != "grasp_bridge_backend" {
			t.Errorf("%s (%s): routed to %q via location %q, want grasp_bridge_backend",
				tc.uri, tc.what, got, loc.pattern)
		}
	}
}

// After the cutover no location may contact Gitea directly: that path would
// bypass every bridge scope check.
func TestFullProxyConfigNeverProxiesDirectlyToGitea(t *testing.T) {
	raw, err := os.ReadFile(fullProxyConfPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "proxy_pass http://gitea_backend") {
		t.Error("full-proxy config still proxies to gitea_backend")
	}
	if regexp.MustCompile(`(?m)^\s*upstream\s+gitea_backend`).MatchString(text) {
		t.Error("full-proxy config still declares a gitea_backend upstream")
	}
}

// Every internal header must be cleared on every location that forwards
// public traffic. The expected set comes from giteaproxy.InternalHeaders, so
// adding a header there without updating nginx fails this test rather than
// silently leaving it forgeable at the edge.
func TestFullProxyConfigClearsInternalHeadersEverywhere(t *testing.T) {
	locs := parseNginxLocations(t, fullProxyConfPath)

	// The two handoff locations legitimately set a few of these; every other
	// header must still be cleared there.
	allowedToSet := map[string]map[string]bool{
		"/auth/session/handoff": {
			"X-Grasp-Session-Proxy": true,
			"X-Grasp-Auth-User":     true,
			"X-Grasp-Edge-Secret":   true,
		},
		"/_grasp_session_handoff_consume": {
			"X-Grasp-Internal-Handoff": true,
			"X-Grasp-Handoff-Token":    true,
			"X-Grasp-Handoff-Audience": true,
		},
	}

	for i := range locs {
		loc := &locs[i]
		if loc.kind == "named" || upstreamOf(loc) == "" {
			continue
		}
		// The relay upstream is not Gitea and carries no Gitea identity.
		if upstreamOf(loc) == "grasp_relay_backend" {
			continue
		}
		exempt := allowedToSet[loc.pattern]
		for _, header := range giteaproxy.InternalHeaders {
			if exempt[header] {
				continue
			}
			cleared := regexp.MustCompile(`proxy_set_header\s+` + regexp.QuoteMeta(header) + `\s+""`)
			if !cleared.MatchString(loc.body) {
				t.Errorf("location %q does not clear %s; a client could forge it", loc.pattern, header)
			}
		}
	}
}

// Client-controlled Host must not reach redirects or the handoff audience.
func TestFullProxyConfigDoesNotTrustClientHost(t *testing.T) {
	raw, err := os.ReadFile(fullProxyConfPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(raw)

	if regexp.MustCompile(`return\s+301\s+https://\$host`).MatchString(text) {
		t.Error("HTTP redirect uses $host; a forged Host becomes an open redirect")
	}
	if regexp.MustCompile(`X-Grasp-Handoff-Audience\s+"\$scheme://\$host"`).MatchString(text) {
		t.Error("handoff audience is built from client-supplied Host")
	}
	if !regexp.MustCompile(`(?m)^\s*server_name\s+_;`).MatchString(text) {
		t.Error("no default server rejecting unknown hostnames")
	}
}

// Only the handoff continuation may present the edge secret and trusted user.
func TestFullProxyConfigSetsTrustedIdentityOnlyOnHandoff(t *testing.T) {
	locs := parseNginxLocations(t, fullProxyConfPath)

	setsIdentity := regexp.MustCompile(`proxy_set_header\s+X-Grasp-Session-Proxy\s+"1"`)
	setsSecret := regexp.MustCompile(`proxy_set_header\s+X-Grasp-Edge-Secret\s+"[^"]+"`)

	for i := range locs {
		loc := &locs[i]
		if loc.pattern == "/auth/session/handoff" {
			if !setsIdentity.MatchString(loc.body) || !setsSecret.MatchString(loc.body) {
				t.Error("the handoff location must set X-Grasp-Session-Proxy and the edge secret")
			}
			continue
		}
		if setsIdentity.MatchString(loc.body) || setsSecret.MatchString(loc.body) {
			t.Errorf("location %q sets trusted session headers; only the handoff continuation may", loc.pattern)
		}
	}
}

// Streaming surfaces must not buffer: buffering breaks pack negotiation and
// can exhaust disk on large uploads.
func TestFullProxyConfigDisablesBufferingOnStreamingSurfaces(t *testing.T) {
	locs := parseNginxLocations(t, fullProxyConfPath)

	for _, uri := range []string{
		"/npub1abc/repo.git/git-receive-pack",
		"/owner/repo.git/git-upload-pack",
		"/api/packages/owner/generic/file",
		"/v2/owner/image/blobs/uploads/abc",
	} {
		loc := selectLocation(locs, uri)
		if loc == nil {
			t.Errorf("%s: no location matched", uri)
			continue
		}
		if !strings.Contains(loc.body, "proxy_request_buffering off") {
			t.Errorf("%s (location %q): request buffering is not disabled", uri, loc.pattern)
		}
		if !strings.Contains(loc.body, "proxy_buffering off") {
			t.Errorf("%s (location %q): response buffering is not disabled", uri, loc.pattern)
		}
	}
}

// Public GRASP pushes must keep their rate and connection limits.
func TestFullProxyConfigPreservesPublicPushLimits(t *testing.T) {
	locs := parseNginxLocations(t, fullProxyConfPath)
	loc := selectLocation(locs, "/npub1abc/repo.git/git-receive-pack")
	if loc == nil {
		t.Fatal("no location matched the public push path")
	}
	for _, directive := range []string{
		"limit_req zone=grasp_push_ip",
		"limit_req zone=grasp_push_repo",
		"limit_conn grasp_push_connections",
	} {
		if !strings.Contains(loc.body, directive) {
			t.Errorf("public push location is missing %q", directive)
		}
	}
}

// The rollback config must remain a working pre-cutover topology.
func TestLegacyConfigRemainsAvailableForRollback(t *testing.T) {
	locs := parseNginxLocations(t, legacyConfPath)

	loc := selectLocation(locs, "/explore/repos")
	if got := upstreamOf(loc); got != "gitea_backend" {
		t.Fatalf("legacy config routes ordinary traffic to %q, want gitea_backend", got)
	}
	loc = selectLocation(locs, "/npub1abc/repo.git/info/refs")
	if got := upstreamOf(loc); got != "grasp_bridge_backend" {
		t.Fatalf("legacy config routes npub git to %q, want grasp_bridge_backend", got)
	}

	raw, err := os.ReadFile(legacyConfPath)
	if err != nil {
		t.Fatalf("read legacy config: %v", err)
	}
	// Rolling back without disabling tokens would leave scopes unenforced on
	// the surfaces that bypass the bridge.
	if !strings.Contains(string(raw), "BRIDGE_TOKENS_ENABLED=false") {
		t.Error("legacy config must document disabling BRIDGE_TOKENS_ENABLED on rollback")
	}
}

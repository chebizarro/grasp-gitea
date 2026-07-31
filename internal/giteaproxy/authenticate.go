// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

// InternalHeaders are bridge-internal headers a public client must never be
// able to set. nginx clears them at the edge; the proxy clears them again so
// a misconfigured or bypassed edge cannot forge an identity. It is exported
// so the deployment-config tests can assert nginx clears exactly this set.
var InternalHeaders = []string{
	"X-Grasp-Auth-User",
	"X-Grasp-Auth-Redirect",
	"X-Grasp-Session-Proxy",
	"X-Grasp-Internal-Handoff",
	"X-Grasp-Handoff-Token",
	"X-Grasp-Handoff-Audience",
	"X-Grasp-Edge-Secret",
	"X-WEBAUTH-USER",
	"X-Forwarded-User",
	"Proxy-Authorization",
}

// maxBasicHeaderBytes bounds the base64 blob we are willing to decode.
const maxBasicHeaderBytes = 8 << 10

const browserSessionCookie = "__Host-grasp-session"

type browserSessionClaims struct {
	User      string `json:"u"`
	ExpiresAt int64  `json:"e"`
}

// nugetAPIKeyHeader is where NuGet clients (`dotnet nuget push --api-key`)
// present the credential instead of Authorization.
const nugetAPIKeyHeader = "X-NuGet-ApiKey"

// credentialKind is how a caller presented itself.
type credentialKind int

const (
	// credentialNone: no usable credential; the request proceeds anonymously.
	credentialNone credentialKind = iota
	// credentialBridgeToken: a grasp_v1_ token in Basic or Bearer.
	credentialBridgeToken
	// credentialBridgeMalformed: something claiming the bridge prefix that
	// failed parsing. It must fail locally, never reach Gitea.
	credentialBridgeMalformed
	// credentialSessionProxy: nginx-verified session handoff continuation.
	credentialSessionProxy
	// credentialPassthrough: an ordinary Gitea credential (PAT, password,
	// cookie, registry token) that is forwarded unchanged.
	credentialPassthrough
	// credentialUnsupported: a credential form the bridge recognizes but does
	// not accept, or an ambiguous multi-valued Authorization header.
	// Rejected locally.
	credentialUnsupported
	// credentialNostrProof: a direct per-request NIP-98 proof
	// (Authorization: Nostr <base64 event>), verified by the proxy on
	// bounded requests.
	credentialNostrProof
)

// credential is the parsed caller credential.
type credential struct {
	kind credentialKind
	// token is the bridge token plaintext for credentialBridgeToken.
	token string
	// username is the Basic username presented alongside a bridge token; it
	// must identify the token's subject.
	username string
	// sessionUser is the trusted Gitea login for credentialSessionProxy.
	sessionUser string
}

// extractCredential applies the fixed precedence: trusted session handoff,
// then bridge token (Basic then Bearer), then ordinary Gitea credentials,
// then anonymous.
func (p *Proxy) extractCredential(r *http.Request) credential {
	if cred, ok := p.trustedSessionCredential(r); ok {
		return cred
	}
	if cred, ok := p.browserSessionCredential(r); ok {
		return cred
	}

	// A bridge token in the NuGet API-key header must resolve locally like
	// any other shape claiming the prefix. Presenting it alongside an
	// Authorization header is ambiguous and rejected. A non-bridge API key
	// is an ordinary Gitea credential and passes through below.
	if apiKey := strings.TrimSpace(r.Header.Get(nugetAPIKeyHeader)); auth.HasBridgeTokenPrefix(apiKey) {
		if len(r.Header.Values("Authorization")) > 0 {
			return credential{kind: credentialUnsupported}
		}
		return classifyBridgeSecret(apiKey, "")
	}

	values := r.Header.Values("Authorization")
	if len(values) > 1 {
		// Multiple Authorization headers are ambiguous: the bridge and Gitea
		// could disagree about which one counts.
		return credential{kind: credentialUnsupported}
	}
	if len(values) == 0 {
		return credential{kind: credentialNone}
	}
	authHeader := strings.TrimSpace(values[0])
	if authHeader == "" {
		return credential{kind: credentialNone}
	}

	scheme, rest, found := strings.Cut(authHeader, " ")
	rest = strings.TrimSpace(rest)
	if !found {
		// A bare value with no scheme: some registry clients send the token
		// alone. Claiming the bridge prefix here must still fail locally.
		return classifyBridgeSecret(authHeader, "")
	}

	switch {
	case strings.EqualFold(scheme, "Basic"):
		username, password, ok := decodeBasic(rest)
		if !ok {
			// Undecodable Basic is not a bridge credential; let Gitea judge it.
			return credential{kind: credentialPassthrough}
		}
		// Git sends the token as the password, but several tools put it in the
		// username with an empty password. Check both components.
		if auth.HasBridgeTokenPrefix(password) {
			return classifyBridgeSecret(password, username)
		}
		if auth.HasBridgeTokenPrefix(username) {
			return classifyBridgeSecret(username, "")
		}
		return credential{kind: credentialPassthrough}

	case strings.EqualFold(scheme, "Bearer"), strings.EqualFold(scheme, "token"):
		if !auth.HasBridgeTokenPrefix(rest) {
			return credential{kind: credentialPassthrough}
		}
		return classifyBridgeSecret(rest, "")

	case strings.EqualFold(scheme, "Nostr"):
		// Direct per-request NIP-98. Verification happens in the serve path
		// where the body can be bounded and read; it is never forwarded —
		// Gitea would ignore it and serve the request anonymously, silently
		// downgrading the caller's intent.
		return credential{kind: credentialNostrProof}
	}

	// An unrecognized scheme carrying a bridge token must not reach Gitea.
	if auth.HasBridgeTokenPrefix(rest) || auth.HasBridgeTokenPrefix(authHeader) {
		return credential{kind: credentialBridgeMalformed}
	}
	return credential{kind: credentialPassthrough}
}

func (p *Proxy) browserSessionCredential(r *http.Request) (credential, bool) {
	if p.edgeSecret == "" {
		return credential{}, false
	}
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return credential{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return credential{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return credential{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return credential{}, false
	}
	mac := hmac.New(sha256.New, []byte(p.edgeSecret))
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return credential{}, false
	}
	var claims browserSessionClaims
	if json.Unmarshal(payload, &claims) != nil || claims.ExpiresAt <= time.Now().Unix() || validateSessionUsername(claims.User) != nil {
		return credential{}, false
	}
	return credential{kind: credentialSessionProxy, sessionUser: claims.User}, true
}

func (p *Proxy) mintBrowserSession(user string, expiresAt time.Time) (string, error) {
	if err := validateSessionUsername(user); err != nil {
		return "", err
	}
	payload, err := json.Marshal(browserSessionClaims{User: user, ExpiresAt: expiresAt.Unix()})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(p.edgeSecret))
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func validateSessionUsername(user string) error {
	if user == "" || len(user) > 70 || strings.ContainsAny(user, "\r\n\t ") {
		return errors.New("unsafe session username")
	}
	return nil
}

// classifyBridgeSecret validates a value already known to carry the bridge
// prefix. Anything malformed fails locally and never reaches Gitea.
func classifyBridgeSecret(secret, username string) credential {
	if !auth.ValidBridgeTokenFormat(secret) {
		return credential{kind: credentialBridgeMalformed}
	}
	return credential{kind: credentialBridgeToken, token: secret, username: username}
}

// trustedSessionCredential accepts the nginx session-handoff continuation
// only when the edge shared secret matches in constant time. Without a
// configured secret the marker is never honored.
func (p *Proxy) trustedSessionCredential(r *http.Request) (credential, bool) {
	if r.Header.Get("X-Grasp-Session-Proxy") != "1" {
		return credential{}, false
	}
	if p.edgeSecret == "" {
		return credential{}, false
	}
	presented := r.Header.Get("X-Grasp-Edge-Secret")
	if subtle.ConstantTimeCompare([]byte(presented), []byte(p.edgeSecret)) != 1 {
		return credential{}, false
	}
	user := strings.TrimSpace(r.Header.Get("X-Grasp-Auth-User"))
	if user == "" {
		return credential{}, false
	}
	return credential{kind: credentialSessionProxy, sessionUser: user}, true
}

func decodeBasic(encoded string) (username, password string, ok bool) {
	if len(encoded) == 0 || len(encoded) > maxBasicHeaderBytes {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	username, password, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return username, password, true
}

// stripInternalHeaders removes bridge-internal headers from a request.
func stripInternalHeaders(h http.Header) {
	for _, name := range InternalHeaders {
		h.Del(name)
	}
}

// stripCallerCredentials removes all caller authentication material. The
// public GRASP npub surface forwards none of it: push authorization comes
// from signed repository-state events enforced by the pre-receive hook.
func stripCallerCredentials(h http.Header) {
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
	h.Del("Cookie")
	h.Del(nugetAPIKeyHeader)
}

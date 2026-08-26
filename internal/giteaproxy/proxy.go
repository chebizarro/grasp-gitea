// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// Authenticator resolves bridge tokens and their hidden downstream
// credentials. *auth.TokenService satisfies it.
type Authenticator interface {
	Enabled() bool
	Authenticate(ctx context.Context, token string) (auth.TokenPrincipal, error)
	// DownstreamPAT returns the hidden credential for a user, lazily
	// upgrading its Gitea scopes to cover the presented bridge scope. The
	// scope is the classification's requirement, so a PAT only ever gains
	// the authority a permitted request actually needs.
	DownstreamPAT(ctx context.Context, giteaUserID int64, bridgeScope string) (login string, pat string, err error)
}

// RepositoryInspector reports current repository metadata. *gitea.Client
// satisfies it. Visibility is read live: a cached value could expose a
// repository in the window after it is made private.
type RepositoryInspector interface {
	GetRepo(ctx context.Context, org string, repo string) (gitea.Repository, error)
}

// NostrVerifier verifies a direct per-request NIP-98 proof against the
// canonical public URL and exact body, with replay protection.
// *auth.ProxyNIP98Verifier satisfies it.
type NostrVerifier interface {
	VerifyProxyNIP98(ctx context.Context, r *http.Request, body []byte) (auth.TokenPrincipal, error)
}

// maxNIP98ProxyBody bounds the body a direct NIP-98 request may carry: the
// payload tag binds the exact bytes, so the proxy must buffer them.
// Streaming shapes (chunked, unknown length, 100-continue) are rejected —
// their bytes cannot be bound before forwarding begins.
const maxNIP98ProxyBody = 1 << 20

// Auditor records authorization outcomes. *store.SQLiteStore satisfies it.
type Auditor interface {
	InsertAuthAuditEvent(ctx context.Context, ev store.AuthAuditEvent) error
}

// Config configures the proxy.
type Config struct {
	// GiteaURL is the fixed upstream origin. It is parsed once at startup and
	// is never derived from request headers, redirects, or query values.
	GiteaURL string
	// PublicURL is the canonical public origin used to rewrite backend-origin
	// URLs in responses.
	PublicURL string
	// EdgeSharedSecret authenticates nginx-supplied session-handoff headers.
	EdgeSharedSecret string
	// GitBackendUser/Password is the narrow service identity used for
	// anonymous access to public mapped npub repositories.
	GitBackendUser     string
	GitBackendPassword string
	// FullProxy enables the generic Gitea fallback for unmatched paths.
	FullProxy bool
}

// Proxy is the single streaming reverse proxy toward Gitea.
type Proxy struct {
	target *url.URL
	// publicURL/publicScheme/publicHost describe the canonical external
	// origin used for forwarded headers and response-origin rewriting.
	publicURL    string
	publicScheme string
	publicHost   string
	edgeSecret   string

	serviceUser     string
	servicePassword string
	fullProxy       bool
	policy          *policy.Store

	proxy   *httputil.ReverseProxy
	tokens  Authenticator
	nostr   NostrVerifier
	repos   RepositoryInspector
	auditor Auditor
	logger  *slog.Logger
}

// WithNostrVerifier enables direct NIP-98 authentication on proxied
// endpoints. Without it, Authorization: Nostr is rejected locally.
func (p *Proxy) WithNostrVerifier(v NostrVerifier) *Proxy {
	p.nostr = v
	return p
}

// disabledAuthenticator stands in when bridge tokens are not configured.
type disabledAuthenticator struct{}

func (disabledAuthenticator) Enabled() bool { return false }

func (disabledAuthenticator) Authenticate(context.Context, string) (auth.TokenPrincipal, error) {
	return auth.TokenPrincipal{}, auth.ErrTokenUnauthorized
}

func (disabledAuthenticator) DownstreamPAT(context.Context, int64, string) (string, string, error) {
	return "", "", auth.ErrTokenUnauthorized
}

// planKey carries the per-request decision into the shared proxy without
// mutating shared state.
type planKey struct{}

// plan is the per-request routing and credential decision.
type plan struct {
	// backendPath, when non-empty, replaces the outgoing path.
	backendPath string
	cred        credential
	class       Classification
	principal   *auth.TokenPrincipal
	// downstreamUser/PAT is the hidden credential to inject, if any.
	downstreamUser string
	downstreamPAT  string
	// npubSurface marks the public GRASP path: strip caller credentials,
	// add CORS, and never surface a Gitea auth challenge.
	npubSurface bool
	// injectedHidden records that the bridge supplied the credential, so a
	// downstream 401 is a bridge fault rather than a caller fault.
	injectedHidden bool
}

// New builds the proxy. The upstream origin is validated here so a malformed
// GiteaURL fails at startup rather than per request.
func New(cfg Config, tokens Authenticator, repos RepositoryInspector, auditor Auditor, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	target, err := url.Parse(strings.TrimRight(cfg.GiteaURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse gitea url: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("gitea url must be http or https, got %q", target.Scheme)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("gitea url must include a host")
	}

	if tokens == nil {
		// A disabled authenticator rejects every bridge credential rather
		// than panicking or silently allowing one through.
		tokens = disabledAuthenticator{}
	}

	publicURL := strings.TrimRight(cfg.PublicURL, "/")
	var publicScheme, publicHost string
	if publicURL != "" {
		public, err := url.Parse(publicURL)
		if err != nil || !public.IsAbs() || public.Host == "" {
			return nil, fmt.Errorf("public url must be an absolute URL with a host, got %q", cfg.PublicURL)
		}
		publicScheme, publicHost = public.Scheme, public.Host
	}

	p := &Proxy{
		target:          target,
		publicURL:       publicURL,
		publicScheme:    publicScheme,
		publicHost:      publicHost,
		edgeSecret:      cfg.EdgeSharedSecret,
		serviceUser:     cfg.GitBackendUser,
		servicePassword: cfg.GitBackendPassword,
		fullProxy:       cfg.FullProxy,
		tokens:          tokens,
		repos:           repos,
		auditor:         auditor,
		logger:          logger.With("component", "giteaproxy"),
	}

	p.proxy = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.handleProxyError,
		// Immediate flushing: git pack negotiation and registry uploads are
		// interactive streams that must not sit in a buffer.
		FlushInterval: -1,
		Transport:     newTransport(),
	}
	return p, nil
}

// newTransport builds the streaming transport. It deliberately omits any
// whole-request timeout: git clones and blob uploads legitimately run for
// minutes. Environment proxies are disabled so the upstream can never be
// redirected by ambient configuration.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

// FullProxyEnabled reports whether unmatched paths are proxied to Gitea.
func (p *Proxy) FullProxyEnabled() bool {
	if p == nil {
		return false
	}
	if snapshot := p.policy.Current(); snapshot != nil {
		return snapshot.FullProxyEnabled
	}
	return p.fullProxy
}

func (p *Proxy) SetPolicyStore(store *policy.Store) {
	if p != nil {
		p.policy = store
	}
}

// ServeHTTP proxies an ordinary Gitea request: UI, REST, packages, LFS, and
// conventional /<owner>/<repo>.git Git paths.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	class := Classify(r)
	cred := p.extractCredential(r)

	// The LFS batch endpoint's read-vs-write nature lives in its JSON body.
	// Resolve it only when a bridge credential needs authorizing; anonymous
	// and ordinary-credential batches stream through untouched.
	if cred.kind == credentialBridgeToken && class.Surface == SurfaceLFS && IsLFSBatchPath(r.URL.Path) {
		scope, ok := resolveLFSBatchScope(r)
		if !ok {
			p.rejectUnauthorized(w, r, class, "unresolvable LFS batch operation")
			return
		}
		class.Scope = scope
	}

	pl := plan{cred: cred, class: class}

	switch cred.kind {
	case credentialBridgeMalformed:
		// Prefixed but unusable: never fall through to Gitea or anonymous.
		p.rejectUnauthorized(w, r, class, "malformed bridge credential")
		return

	case credentialUnsupported:
		p.rejectUnauthorized(w, r, class, "unsupported authorization")
		return

	case credentialNostrProof:
		if !p.serveNostrProof(w, r, class, &pl) {
			return
		}

	case credentialBridgeToken:
		if !p.tokens.Enabled() {
			p.rejectUnauthorized(w, r, class, "bridge tokens are not enabled")
			return
		}
		if !class.BridgeTokensSupported() {
			// A valid token on a surface whose adapter has not landed must
			// fail loudly rather than leak the hidden PAT's full authority.
			p.rejectForbidden(w, r, class,
				fmt.Sprintf("bridge tokens are not supported on the %s surface yet", class.Surface))
			return
		}
		principal, err := p.tokens.Authenticate(r.Context(), cred.token)
		if err != nil {
			p.rejectUnauthorized(w, r, class, "invalid bridge token")
			return
		}
		if cred.username != "" && !principal.PermitsUsername(cred.username) {
			// Never authenticate by password alone: the presented username
			// must identify the token's subject.
			p.rejectUnauthorized(w, r, class, "username does not match token subject")
			return
		}
		if !principal.HasScope(class.Scope) {
			p.rejectForbidden(w, r, class, "token is missing scope "+class.Scope)
			return
		}
		login, pat, err := p.tokens.DownstreamPAT(r.Context(), principal.GiteaUserID, class.Scope)
		if err != nil {
			p.logger.Error("downstream credential unavailable",
				"gitea_user_id", principal.GiteaUserID, "error", err)
			p.audit(r, class, "credential_fault", principal.TokenID, principal.Pubkey)
			http.Error(w, "downstream credential unavailable", http.StatusBadGateway)
			return
		}
		pl.principal = &principal
		pl.downstreamUser, pl.downstreamPAT = login, pat
		pl.injectedHidden = true
		p.audit(r, class, "allowed", principal.TokenID, principal.Pubkey)
	}

	p.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), planKey{}, &pl)))
}

// serveNostrProof authenticates a direct NIP-98 request in place. It
// returns false when the request has been fully handled (rejected); on true
// the plan carries the hidden downstream credential and the body has been
// rewound for forwarding.
func (p *Proxy) serveNostrProof(w http.ResponseWriter, r *http.Request, class Classification, pl *plan) bool {
	if p.nostr == nil || !p.tokens.Enabled() {
		p.rejectUnauthorized(w, r, class, "direct NIP-98 authentication is not enabled")
		return false
	}
	if class.Surface == SurfaceLFS {
		// LFS transfers are object streams; git-lfs cannot produce
		// per-request proofs and a payload-bound signature cannot cover a
		// stream. Use a bridge token.
		p.rejectForbidden(w, r, class, "NIP-98 authentication is not supported on the lfs surface; use a bridge token")
		return false
	}
	if !class.BridgeTokensSupported() {
		p.rejectForbidden(w, r, class,
			fmt.Sprintf("NIP-98 authentication is not supported on the %s surface", class.Surface))
		return false
	}

	// The payload tag binds exact bytes, so only bounded, fully-buffered
	// bodies are verifiable. Anything streaming-shaped fails closed.
	var body []byte
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// No payload binding needed; any body on these methods is rejected
		// below by the same bounds.
		fallthrough
	default:
		if len(r.TransferEncoding) > 0 {
			p.rejectUnauthorized(w, r, class, "NIP-98 requires a known Content-Length, not chunked encoding")
			return false
		}
		if r.Header.Get("Expect") != "" {
			p.rejectUnauthorized(w, r, class, "NIP-98 does not support Expect: 100-continue")
			return false
		}
		if r.ContentLength < 0 {
			p.rejectUnauthorized(w, r, class, "NIP-98 requires a known Content-Length")
			return false
		}
		if r.ContentLength > maxNIP98ProxyBody {
			p.rejectUnauthorized(w, r, class,
				fmt.Sprintf("NIP-98 request bodies are limited to %d bytes; use a bridge token", maxNIP98ProxyBody))
			return false
		}
		if r.ContentLength > 0 {
			data, err := io.ReadAll(io.LimitReader(r.Body, maxNIP98ProxyBody+1))
			if err != nil || int64(len(data)) != r.ContentLength {
				p.rejectUnauthorized(w, r, class, "request body did not match its Content-Length")
				return false
			}
			body = data
		}
	}

	principal, err := p.nostr.VerifyProxyNIP98(r.Context(), r, body)
	if err != nil {
		// Infrastructure faults are not invalid signatures: reporting them
		// as 401 would hide an outage behind pointless re-signing.
		switch {
		case errors.Is(err, auth.ErrNIP98StoreUnavailable):
			p.logger.Error("NIP-98 replay ledger unavailable", "error", err)
			p.audit(r, class, "nip98_fault", "", "")
			http.Error(w, "authorization ledger unavailable", http.StatusServiceUnavailable)
		case errors.Is(err, auth.ErrPATProvisioning):
			p.logger.Error("downstream credential provisioning failed", "error", err)
			p.audit(r, class, "credential_fault", "", "")
			http.Error(w, "downstream credential unavailable", http.StatusBadGateway)
		default:
			p.logger.Info("direct NIP-98 rejected", "path", r.URL.Path, "error", err)
			p.audit(r, class, "denied_nip98", "", "")
			w.Header().Set("WWW-Authenticate", "Nostr")
			http.Error(w, "invalid NIP-98 authorization", http.StatusUnauthorized)
		}
		return false
	}
	if !principal.HasScope(class.Scope) {
		p.rejectForbidden(w, r, class, "NIP-98 authentication does not grant scope "+class.Scope)
		return false
	}
	login, pat, err := p.tokens.DownstreamPAT(r.Context(), principal.GiteaUserID, class.Scope)
	if err != nil {
		p.logger.Error("downstream credential unavailable",
			"gitea_user_id", principal.GiteaUserID, "error", err)
		p.audit(r, class, "credential_fault", "", principal.Pubkey)
		http.Error(w, "downstream credential unavailable", http.StatusBadGateway)
		return false
	}

	// Rewind the verified bytes for forwarding.
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	pl.principal = &principal
	pl.downstreamUser, pl.downstreamPAT = login, pat
	pl.injectedHidden = true
	p.audit(r, class, "allowed_nip98", "", principal.Pubkey)
	return true
}

// MappedRepo identifies the Gitea repository behind a canonical npub
// coordinate. ExpectedID pins the mapping to the exact repository that was
// provisioned, so a deleted-and-recreated repository at the same path is
// never served under the original NIP-34 coordinate.
type MappedRepo struct {
	Owner      string
	Name       string
	ExpectedID int64
}

// ServeMappedGit proxies a canonical npub git path to its mapped Gitea
// repository. A valid bridge token grants the caller's own access; otherwise
// the request is anonymous and only permitted while the repository is
// publicly readable. Either way the live repository identity is verified, so
// the bridge never pushes into a repository that is not the mapped one.
func (p *Proxy) ServeMappedGit(w http.ResponseWriter, r *http.Request, mapped MappedRepo, gitSubpath string) {
	owner, repoName := mapped.Owner, mapped.Name
	class := Classify(r)
	// A canonical npub .git/ path carries either git smart-HTTP or LFS
	// (batch, object transfer, locks): git-lfs derives its endpoint from the
	// clone URL, so it requests /<npub>/<repo>.git/info/lfs/... too.
	if class.Surface != SurfaceGit && class.Surface != SurfaceLFS {
		setGitHTTPCORS(w.Header())
		http.Error(w, "unsupported git request", http.StatusBadRequest)
		return
	}

	backendPath := "/" + owner + "/" + repoName + ".git/" + gitSubpath
	pl := plan{backendPath: backendPath, class: class, npubSurface: true}
	cred := p.extractCredential(r)
	pl.cred = cred

	// The LFS batch operation lives in the body; resolve its scope for every
	// credential kind, not just bridge tokens. Anonymous callers must never
	// reach an upload batch via the write-capable service identity — unlike
	// git-receive-pack, LFS mutations are not guarded by the pre-receive
	// hook.
	if class.Surface == SurfaceLFS && IsLFSBatchPath(r.URL.Path) {
		scope, ok := resolveLFSBatchScope(r)
		if !ok {
			setGitHTTPCORS(w.Header())
			p.rejectUnauthorized(w, r, class, "unresolvable LFS batch operation")
			return
		}
		class.Scope = scope
		pl.class = class
	}

	// The mapped repository must still be the one that was provisioned. A
	// recreated repository at the same owner/name lacks the GRASP pre-receive
	// hook, so serving it would bypass Nostr authority enforcement entirely.
	repo, err := p.lookupMappedRepo(r.Context(), owner, repoName, mapped.ExpectedID)
	if err != nil {
		setGitHTTPCORS(w.Header())
		p.logger.Error("mapped repository verification failed",
			"owner", owner, "repo", repoName, "expected_id", mapped.ExpectedID, "error", err)
		p.audit(r, class, "denied_mapping", "", "")
		http.Error(w, "git backend unavailable", http.StatusBadGateway)
		return
	}

	switch cred.kind {
	case credentialBridgeMalformed, credentialUnsupported, credentialNostrProof:
		// Direct NIP-98 is not offered on the mapped npub surface: git
		// clients cannot produce per-request proofs, and treating one as
		// anonymous would silently downgrade the caller's intent.
		setGitHTTPCORS(w.Header())
		p.rejectUnauthorized(w, r, class, "unusable credential")
		return

	case credentialBridgeToken:
		if !p.tokens.Enabled() {
			setGitHTTPCORS(w.Header())
			p.rejectUnauthorized(w, r, class, "bridge tokens are not enabled")
			return
		}
		principal, err := p.tokens.Authenticate(r.Context(), cred.token)
		if err != nil {
			setGitHTTPCORS(w.Header())
			p.rejectUnauthorized(w, r, class, "invalid bridge token")
			return
		}
		if cred.username != "" && !principal.PermitsUsername(cred.username) {
			setGitHTTPCORS(w.Header())
			p.rejectUnauthorized(w, r, class, "username does not match token subject")
			return
		}
		if !principal.HasScope(class.Scope) {
			setGitHTTPCORS(w.Header())
			p.rejectForbidden(w, r, class, "token is missing scope "+class.Scope)
			return
		}
		login, pat, err := p.tokens.DownstreamPAT(r.Context(), principal.GiteaUserID, class.Scope)
		if err != nil {
			setGitHTTPCORS(w.Header())
			p.logger.Error("downstream credential unavailable",
				"gitea_user_id", principal.GiteaUserID, "error", err)
			http.Error(w, "downstream credential unavailable", http.StatusBadGateway)
			return
		}
		pl.principal = &principal
		pl.downstreamUser, pl.downstreamPAT = login, pat
		pl.injectedHidden = true
		p.audit(r, class, "allowed", principal.TokenID, principal.Pubkey)

	default:
		// Anonymous (or ordinary-credential, which this surface strips):
		// permitted only for reads while the mapped repository is publicly
		// readable. Any write — an LFS object PUT, a lock mutation, or an
		// upload batch — requires a bridge credential: the service identity
		// is write-capable and LFS mutations bypass the pre-receive hook.
		// Keyed on the resolved LFS scope, not the HTTP method: a download
		// batch is a POST but needs only lfs:read. Git pushes are exempt —
		// git-receive-pack authority is enforced by the grasp-pre-receive
		// hook, which LFS has no equivalent of.
		if class.Surface == SurfaceLFS && class.Scope == auth.ScopeLFSWrite {
			setGitHTTPCORS(w.Header())
			p.audit(r, class, "denied_anonymous_write", "", "")
			p.writeGitAuthRequired(w)
			return
		}
		// Internal repositories (public repo, private owner org) are not
		// anonymously readable.
		if !repo.PubliclyReadable() {
			setGitHTTPCORS(w.Header())
			p.audit(r, class, "denied_private", "", "")
			p.writeGitAuthRequired(w)
			return
		}
		pl.injectedHidden = p.serviceUser != "" || p.servicePassword != ""
	}

	p.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), planKey{}, &pl)))
}

// lookupMappedRepo reads the live repository and verifies it is the exact one
// the mapping was provisioned against. Visibility is read fresh on every
// request: a cached value could serve a repository in the window after it is
// made private.
func (p *Proxy) lookupMappedRepo(ctx context.Context, owner, repoName string, expectedID int64) (gitea.Repository, error) {
	if p.repos == nil {
		return gitea.Repository{}, fmt.Errorf("repository inspector is not configured")
	}
	repo, err := p.repos.GetRepo(ctx, owner, repoName)
	if err != nil {
		return gitea.Repository{}, err
	}
	if expectedID != 0 && repo.ID != expectedID {
		return gitea.Repository{}, fmt.Errorf(
			"mapped repository id changed: found %d, expected %d", repo.ID, expectedID)
	}
	return repo, nil
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	pl, _ := pr.In.Context().Value(planKey{}).(*plan)

	pr.SetURL(p.target)

	// ReverseProxy strips X-Forwarded-* from Out before Rewrite runs, so the
	// chain nginx built is already gone. Restore it when the immediate peer is
	// a trusted private address (our own edge); otherwise Gitea's audit log
	// and any IP-based control would only ever see the bridge. A non-private
	// peer is untrusted because it could forge the chain.
	if prior := pr.In.Header.Get("X-Forwarded-For"); prior != "" && trustedPeer(pr.In.RemoteAddr) {
		pr.Out.Header.Set("X-Forwarded-For", prior)
	}
	// Appends this hop to whatever chain survived above, and gives Gitea the
	// canonical external identity rather than a client-controlled Host.
	pr.SetXForwarded()
	if p.publicHost != "" {
		pr.Out.Host = p.publicHost
		pr.Out.Header.Set("X-Forwarded-Host", p.publicHost)
		pr.Out.Header.Set("X-Forwarded-Proto", p.publicScheme)
	} else {
		pr.Out.Host = p.target.Host
	}
	if pl != nil && pl.backendPath != "" {
		pr.Out.URL.Path = singleJoiningSlash(p.target.Path, pl.backendPath)
		pr.Out.URL.RawPath = ""
		pr.Out.URL.RawQuery = joinRawQuery(p.target.RawQuery, pr.In.URL.RawQuery)
	}

	// Defense in depth: no client-supplied internal header ever reaches Gitea.
	stripInternalHeaders(pr.Out.Header)

	if pl == nil {
		stripCallerCredentials(pr.Out.Header)
		return
	}

	switch {
	case pl.npubSurface && pl.downstreamPAT == "":
		// Public GRASP surface, anonymous: forward no caller credentials and
		// authenticate as the narrow service identity.
		stripCallerCredentials(pr.Out.Header)
		if p.serviceUser != "" || p.servicePassword != "" {
			pr.Out.SetBasicAuth(p.serviceUser, p.servicePassword)
		}

	case pl.downstreamPAT != "":
		// Replace the caller credential with the hidden PAT; never leave both.
		stripCallerCredentials(pr.Out.Header)
		pr.Out.SetBasicAuth(pl.downstreamUser, pl.downstreamPAT)

	case pl.cred.kind == credentialSessionProxy:
		// Trusted browser session continuation: Gitea's reverse-proxy auth
		// header is the only identity, and it is set by the bridge alone.
		stripCallerCredentials(pr.Out.Header)
		pr.Out.Header.Set("X-Grasp-Auth-User", pl.cred.sessionUser)

	default:
		// Ordinary Gitea credentials (or none) pass through unchanged.
	}
}

// trustedPeer reports whether the immediate TCP peer may be believed about
// the forwarding chain. In the documented topology the bridge is reachable
// only from nginx on the private container network, so loopback and private
// ranges are the edge; anything else is a client that could forge headers.
func trustedPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	pl, _ := resp.Request.Context().Value(planKey{}).(*plan)

	if pl != nil && pl.cred.kind == credentialSessionProxy {
		if resp.Request.URL.Path == "/user/logout" {
			resp.Header.Add("Set-Cookie", browserSessionCookie+"=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
		} else if token, err := p.mintBrowserSession(pl.cred.sessionUser, time.Now().Add(12*time.Hour)); err == nil {
			resp.Header.Add("Set-Cookie", browserSessionCookie+"="+token+"; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax")
		}
	}

	if pl != nil && pl.npubSurface {
		setGitHTTPCORS(resp.Header)
		sanitizeGitBackendResponse(resp)
		// A mapped LFS batch response carries transfer hrefs pointing at the
		// backend origin; rewrite them so the private address never reaches
		// a public client.
		if pl.class.Surface == SurfaceLFS && IsLFSBatchPath(resp.Request.URL.Path) &&
			resp.StatusCode == http.StatusOK {
			p.rewriteLFSBatchBody(resp)
		}
		// Mapped responses can still carry backend-origin redirects, which
		// would leak the private Gitea address to public clients.
		p.rewriteBackendOrigin(resp)
		return nil
	}

	if pl != nil && pl.injectedHidden &&
		(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired) {
		// The bridge supplied this credential, so a challenge is a bridge
		// fault. Never relay it: the caller cannot act on it, and it would
		// invite them to retry with Gitea credentials.
		p.logger.Error("downstream rejected bridge-injected credential",
			"path", resp.Request.URL.Path, "status", resp.StatusCode)
		replaceWithPlainText(resp, http.StatusBadGateway, "downstream credential rejected\n")
		return nil
	}

	if pl != nil && pl.class.Surface == SurfaceLFS && IsLFSBatchPath(resp.Request.URL.Path) &&
		resp.StatusCode == http.StatusOK {
		p.rewriteLFSBatchBody(resp)
	}

	p.rewriteBackendOrigin(resp)
	p.rewriteBearerChallengeRealm(resp)
	return nil
}

// rewriteBearerChallengeRealm rewrites the realm URL in a Bearer challenge
// (docker's token-endpoint discovery) from the private Gitea origin to the
// public origin. Only a realm whose scheme and host exactly equal the
// configured upstream is rewritten: anything else is either already public
// or a value the bridge must not vouch for.
func (p *Proxy) rewriteBearerChallengeRealm(resp *http.Response) {
	if p.publicURL == "" {
		return
	}
	values := resp.Header.Values("WWW-Authenticate")
	if len(values) == 0 {
		return
	}
	rewritten := make([]string, 0, len(values))
	changed := false
	for _, challenge := range values {
		if out, ok := p.rewriteOneBearerRealm(challenge); ok {
			rewritten = append(rewritten, out)
			changed = true
		} else {
			rewritten = append(rewritten, challenge)
		}
	}
	if !changed {
		return
	}
	resp.Header.Del("WWW-Authenticate")
	for _, v := range rewritten {
		resp.Header.Add("WWW-Authenticate", v)
	}
}

// rewriteOneBearerRealm rewrites a single challenge value. Scheme and
// parameter names are matched case-insensitively per RFC 9110.
func (p *Proxy) rewriteOneBearerRealm(challenge string) (string, bool) {
	if len(challenge) < len("bearer ") || !strings.EqualFold(challenge[:len("bearer ")], "bearer ") {
		return "", false
	}
	lower := strings.ToLower(challenge)
	const marker = `realm="`
	start := strings.Index(lower, marker)
	if start < 0 {
		return "", false
	}
	valueStart := start + len(marker)
	end := strings.Index(challenge[valueStart:], `"`)
	if end < 0 {
		return "", false
	}
	realm := challenge[valueStart : valueStart+end]
	parsed, err := url.Parse(realm)
	if err != nil || !parsed.IsAbs() {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, p.target.Scheme) ||
		!strings.EqualFold(parsed.Host, p.target.Host) {
		return "", false
	}
	parsed.Scheme = p.publicScheme
	parsed.Host = p.publicHost
	return challenge[:valueStart] + parsed.String() + challenge[valueStart+end:], true
}

// rewriteBackendOrigin replaces the private Gitea origin with the public
// origin in redirect targets. The URL is parsed and its scheme/host compared
// exactly: a prefix match would also rewrite hostile look-alikes such as
// http://gitea:3000.evil.example/.
func (p *Proxy) rewriteBackendOrigin(resp *http.Response) {
	if p.publicURL == "" {
		return
	}
	for _, header := range []string{"Location", "Content-Location"} {
		value := resp.Header.Get(header)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() {
			continue
		}
		if !strings.EqualFold(parsed.Scheme, p.target.Scheme) ||
			!strings.EqualFold(parsed.Host, p.target.Host) {
			continue
		}
		parsed.Scheme = p.publicScheme
		parsed.Host = p.publicHost
		resp.Header.Set(header, parsed.String())
	}
}

func (p *Proxy) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	pl, _ := r.Context().Value(planKey{}).(*plan)
	if pl != nil && pl.npubSurface {
		setGitHTTPCORS(w.Header())
	}
	if r.Context().Err() != nil {
		// Client went away mid-stream; nothing useful to report.
		p.logger.Debug("proxy request cancelled", "path", r.URL.Path)
		return
	}
	p.logger.Error("gitea proxy failed", "path", r.URL.Path, "error", err)
	http.Error(w, "git backend unavailable", http.StatusBadGateway)
}

// writeGitAuthRequired asks a git client for credentials. Git only retries
// with a helper-supplied credential after a 401 carrying a Basic challenge.
func (p *Proxy) writeGitAuthRequired(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="GRASP"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (p *Proxy) rejectUnauthorized(w http.ResponseWriter, r *http.Request, class Classification, reason string) {
	p.logger.Info("proxy rejected credential", "path", r.URL.Path, "surface", class.Surface, "reason", reason)
	p.audit(r, class, "denied_unauthorized", "", "")
	w.Header().Set("WWW-Authenticate", `Basic realm="GRASP"`)
	http.Error(w, reason, http.StatusUnauthorized)
}

func (p *Proxy) rejectForbidden(w http.ResponseWriter, r *http.Request, class Classification, reason string) {
	p.logger.Info("proxy denied scope", "path", r.URL.Path, "surface", class.Surface, "reason", reason)
	p.audit(r, class, "denied_scope", "", "")
	http.Error(w, reason, http.StatusForbidden)
}

// audit records an authorization outcome. It never stores credentials, and a
// failure to audit must not fail the request.
func (p *Proxy) audit(r *http.Request, class Classification, outcome, tokenID, pubkey string) {
	if p.auditor == nil {
		return
	}
	err := p.auditor.InsertAuthAuditEvent(r.Context(), store.AuthAuditEvent{
		EventType: "proxy_request",
		Pubkey:    pubkey,
		TokenID:   tokenID,
		Surface:   string(class.Surface),
		Action:    string(class.Action),
		Outcome:   outcome,
	})
	if err != nil {
		p.logger.Warn("proxy audit insert failed", "error", err)
	}
}

// sanitizeGitBackendResponse guarantees the public GRASP surface never emits a
// Gitea authentication challenge or session state.
func sanitizeGitBackendResponse(resp *http.Response) {
	resp.Header.Del("WWW-Authenticate")
	resp.Header.Del("Proxy-Authenticate")
	resp.Header.Del("Set-Cookie")

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired {
		replaceWithPlainText(resp, http.StatusBadGateway, "git backend unavailable\n")
	}
}

func replaceWithPlainText(resp *http.Response, status int, body string) {
	if resp.Body != nil {
		resp.Body.Close()
	}
	resp.StatusCode = status
	resp.Status = http.StatusText(status)
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Del("WWW-Authenticate")
	resp.Header.Del("Proxy-Authenticate")
}

func setGitHTTPCORS(h http.Header) {
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

func joinRawQuery(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "&" + b
	}
}

package api

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

const (
	gitHTTPCORSAllowOrigin  = "*"
	gitHTTPCORSAllowMethods = "GET, POST"
	gitHTTPCORSAllowHeaders = "Content-Type"
)

// gitHTTPNpubProxy serves the GRASP-01 git smart-HTTP npub path:
// /<npub>/<percent-encoded-repo-id>.git/{info/refs,git-upload-pack,git-receive-pack}.
// The bridge stores repositories under their Gitea owner/org name, so this
// handler resolves (npub, repo-id) through the mapping store and reverse-proxies
// the smart-HTTP request to /<owner>/<repo>.git/<git-smart-http-subpath>.
func (s *Server) gitHTTPNpubProxy(w http.ResponseWriter, r *http.Request) {
	// GRASP-01: the service root is the relay endpoint — WebSocket upgrades
	// and NIP-11 (Accept: application/nostr+json) negotiate there, while
	// /<npub>/<identifier>.git paths remain the git surface.
	if s.rootRelayHandler != nil && r.URL.Path == "/" {
		s.rootRelayHandler.ServeHTTP(w, r)
		return
	}

	npub, repoID, gitSubpath, ok, err := parseNpubGitHTTPPath(r)
	if err != nil {
		setGitHTTPCORS(w.Header())
		http.Error(w, "bad git smart-http path", http.StatusBadRequest)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	setGitHTTPCORS(w.Header())
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		http.NotFound(w, r)
		return
	}

	mapping, err := s.store.GetMapping(r.Context(), npub, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		if gitSubpath == "" {
			s.serveRepoLandingPage(w, r, npub, repoID, false)
			return
		}
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Error("git smart-http mapping lookup failed", "npub", npub, "repo_id", repoID, "error", err)
		}
		http.Error(w, "mapping lookup failed", http.StatusInternalServerError)
		return
	}

	target, err := url.Parse(strings.TrimRight(s.giteaURL, "/"))
	if err != nil || target.Scheme == "" || target.Host == "" {
		if s.logger != nil {
			s.logger.Error("invalid Gitea URL for git smart-http proxy", "gitea_url", s.giteaURL, "error", err)
		}
		http.Error(w, "git backend unavailable", http.StatusBadGateway)
		return
	}

	if gitSubpath == "" {
		s.serveRepoLandingPage(w, r, npub, repoID, true)
		return
	}

	backendPath := "/" + mapping.Owner + "/" + mapping.RepoName + ".git/" + gitSubpath
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.URL.Path = singleJoiningSlash(target.Path, backendPath)
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = joinRawQuery(target.RawQuery, pr.In.URL.RawQuery)
			// GRASP-01: the public interface is unauthenticated and caller
			// credentials must never reach Gitea. Push authorization comes from
			// signed repository-state events enforced by the pre-receive hook,
			// so the bridge authenticates to Gitea with its own scoped service
			// identity, injected only after the npub/identifier mapping resolved.
			stripCallerCredentials(pr.Out.Header)
			if s.gitBackendUser != "" || s.gitBackendPassword != "" {
				pr.Out.SetBasicAuth(s.gitBackendUser, s.gitBackendPassword)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			setGitHTTPCORS(resp.Header)
			sanitizeGitBackendResponse(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			setGitHTTPCORS(w.Header())
			if s.logger != nil {
				s.logger.Error("git smart-http proxy failed", "npub", npub, "repo_id", repoID, "error", err)
			}
			http.Error(w, "git backend unavailable", http.StatusBadGateway)
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, r)
}

func parseNpubGitHTTPPath(r *http.Request) (npub string, repoID string, gitSubpath string, ok bool, err error) {
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		return "", "", "", false, nil
	}

	rest := strings.TrimPrefix(path, "/")
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", "", false, nil
	}

	encodedNpub := rest[:slash]
	if !strings.HasPrefix(encodedNpub, "npub1") {
		return "", "", "", false, nil
	}

	repoAndGitPath := rest[slash+1:]
	gitMarker := ".git/"
	marker := strings.Index(repoAndGitPath, gitMarker)
	var encodedRepoID string
	if marker <= 0 {
		// GRASP-01 recommends a human-facing page at the bare
		// /<npub>/<identifier>.git path itself.
		trimmed := strings.TrimSuffix(repoAndGitPath, "/")
		if !strings.HasSuffix(trimmed, ".git") || len(trimmed) <= len(".git") {
			return "", "", "", false, nil
		}
		encodedRepoID = strings.TrimSuffix(trimmed, ".git")
		gitSubpath = ""
	} else {
		encodedRepoID = repoAndGitPath[:marker]
		gitSubpath = repoAndGitPath[marker+len(gitMarker):]
		if !isGitSmartHTTPSubpath(gitSubpath) {
			return "", "", "", false, nil
		}
	}

	npub, err = url.PathUnescape(encodedNpub)
	if err != nil {
		return "", "", "", true, err
	}
	if !strings.HasPrefix(npub, "npub1") {
		return "", "", "", false, nil
	}

	repoID, err = url.PathUnescape(encodedRepoID)
	if err != nil {
		return "", "", "", true, err
	}
	if repoID == "" {
		return "", "", "", false, nil
	}

	return npub, repoID, gitSubpath, true, nil
}

// serveRepoLandingPage renders the human-facing page GRASP-01 recommends at
// /<npub>/<identifier>.git: a pointer to the clone URL and a Nostr git
// browser for known repositories, and a useful 404 for unknown ones.
func (s *Server) serveRepoLandingPage(w http.ResponseWriter, r *http.Request, npub string, repoID string, known bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	cloneURL := "https://" + r.Host + "/" + url.PathEscape(npub) + "/" + url.PathEscape(repoID) + ".git"
	naddr := url.PathEscape(npub) + "/" + url.PathEscape(repoID)
	if !known {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `<!doctype html><html><head><title>repository not found</title></head><body>
<h1>Repository not found</h1>
<p>No GRASP repository is mapped for <code>%s</code>.</p>
<p>Repositories appear here after an owner-signed NIP-34 announcement
(kind 30617) naming this service in both <code>clone</code> and
<code>relays</code> tags is accepted.</p>
</body></html>`, template.HTMLEscapeString(naddr))
		return
	}
	fmt.Fprintf(w, `<!doctype html><html><head><title>%[1]s</title></head><body>
<h1><code>%[1]s</code></h1>
<p>This is a GRASP-01 git repository. Clone it without credentials:</p>
<pre>git clone %[2]s</pre>
<p>Browse it on <a href="https://gitworkshop.dev/%[3]s">gitworkshop.dev</a>.</p>
</body></html>`,
		template.HTMLEscapeString(repoID),
		template.HTMLEscapeString(cloneURL),
		template.HTMLEscapeString(naddr))
}

func isGitSmartHTTPSubpath(subpath string) bool {
	switch subpath {
	case "info/refs", "git-upload-pack", "git-receive-pack":
		return true
	default:
		return false
	}
}

// stripCallerCredentials removes any caller-supplied authentication material
// before the request is forwarded to Gitea. GRASP-01 git smart-HTTP is public;
// forwarding these headers would let Gitea authenticate (or challenge) the
// caller, which must never happen on this path.
func stripCallerCredentials(h http.Header) {
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
	h.Del("Cookie")
}

// sanitizeGitBackendResponse guarantees the public GRASP surface never emits a
// Gitea authentication challenge or session state. A backend 401/407 means the
// bridge's own service identity is missing or misconfigured, which is an
// operator error — report it as a backend failure, not an auth challenge.
func sanitizeGitBackendResponse(resp *http.Response) {
	resp.Header.Del("WWW-Authenticate")
	resp.Header.Del("Proxy-Authenticate")
	resp.Header.Del("Set-Cookie")

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired {
		body := "git backend unavailable\n"
		if resp.Body != nil {
			resp.Body.Close()
		}
		resp.StatusCode = http.StatusBadGateway
		resp.Status = http.StatusText(http.StatusBadGateway)
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}
}

func setGitHTTPCORS(h http.Header) {
	h.Set("Access-Control-Allow-Origin", gitHTTPCORSAllowOrigin)
	h.Set("Access-Control-Allow-Methods", gitHTTPCORSAllowMethods)
	h.Set("Access-Control-Allow-Headers", gitHTTPCORSAllowHeaders)
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

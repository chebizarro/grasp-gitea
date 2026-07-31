package api

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/giteaproxy"
)

const (
	gitHTTPCORSAllowOrigin  = "*"
	gitHTTPCORSAllowMethods = "GET, POST"
	gitHTTPCORSAllowHeaders = "Content-Type"
)

// rootHandler is the catch-all. It dispatches, in order: the GRASP-01 relay
// at the service root, canonical npub git paths, and — in full-proxy mode —
// every remaining Gitea request.
func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && s.rootRelayHandler != nil && s.isRelayRootRequest(r) {
		s.rootRelayHandler.ServeHTTP(w, r)
		return
	}

	npub, repoID, gitSubpath, ok, err := parseNpubGitHTTPPath(r)
	if err != nil {
		setGitHTTPCORS(w.Header())
		http.Error(w, "bad git smart-http path", http.StatusBadRequest)
		return
	}
	if ok {
		s.gitHTTPNpubProxy(w, r, npub, repoID, gitSubpath)
		return
	}

	// Full-proxy mode: the bridge fronts all of Gitea.
	if s.giteaProxy != nil && s.giteaProxy.FullProxyEnabled() {
		s.giteaProxy.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// isRelayRootRequest reports whether a request to "/" is relay traffic.
//
// While nginx still routes ordinary Gitea traffic directly, everything the
// bridge sees at "/" is relay traffic. Once the bridge fronts all of Gitea,
// browsers reach "/" too, so the relay is selected only by an actual
// WebSocket upgrade or NIP-11 content negotiation.
func (s *Server) isRelayRootRequest(r *http.Request) bool {
	if s.giteaProxy == nil || !s.giteaProxy.FullProxyEnabled() {
		return true
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/nostr+json")
}

// gitHTTPNpubProxy serves the GRASP-01 git smart-HTTP npub path:
// /<npub>/<percent-encoded-repo-id>.git/{info/refs,git-upload-pack,git-receive-pack}.
// The bridge stores repositories under their Gitea owner/org name, so this
// handler resolves (npub, repo-id) through the mapping store and hands the
// request to the shared streaming proxy, which decides credentials.
func (s *Server) gitHTTPNpubProxy(w http.ResponseWriter, r *http.Request, npub, repoID, gitSubpath string) {
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
	if err == nil && !mapping.HookInstalled {
		// Provisioning did not finish, so grasp-pre-receive is not installed.
		// Serving it would let a push bypass Nostr authority enforcement.
		if s.logger != nil {
			s.logger.Warn("refusing git smart-http for repository without the GRASP hook",
				"npub", npub, "repo_id", repoID)
		}
		err = sql.ErrNoRows
	}
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

	if gitSubpath == "" {
		s.serveRepoLandingPage(w, r, npub, repoID, true)
		return
	}

	if s.giteaProxy == nil {
		if s.logger != nil {
			s.logger.Error("git smart-http proxy is not configured")
		}
		http.Error(w, "git backend unavailable", http.StatusBadGateway)
		return
	}
	s.giteaProxy.ServeMappedGit(w, r, giteaproxy.MappedRepo{
		Owner:      mapping.Owner,
		Name:       mapping.RepoName,
		ExpectedID: mapping.GiteaRepoID,
	}, gitSubpath)
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
		if !giteaproxy.IsGitSmartHTTPSubpath(gitSubpath) {
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

func setGitHTTPCORS(h http.Header) {
	h.Set("Access-Control-Allow-Origin", gitHTTPCORSAllowOrigin)
	h.Set("Access-Control-Allow-Methods", gitHTTPCORSAllowMethods)
	h.Set("Access-Control-Allow-Headers", gitHTTPCORSAllowHeaders)
}

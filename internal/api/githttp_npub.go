package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	backendPath := "/" + mapping.Owner + "/" + mapping.RepoName + ".git/" + gitSubpath
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.URL.Path = singleJoiningSlash(target.Path, backendPath)
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = joinRawQuery(target.RawQuery, pr.In.URL.RawQuery)
		},
		ModifyResponse: func(resp *http.Response) error {
			setGitHTTPCORS(resp.Header)
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
	if marker <= 0 {
		return "", "", "", false, nil
	}

	encodedRepoID := repoAndGitPath[:marker]
	gitSubpath = repoAndGitPath[marker+len(gitMarker):]
	if !isGitSmartHTTPSubpath(gitSubpath) {
		return "", "", "", false, nil
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

func isGitSmartHTTPSubpath(subpath string) bool {
	switch subpath {
	case "info/refs", "git-upload-pack", "git-receive-pack":
		return true
	default:
		return false
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

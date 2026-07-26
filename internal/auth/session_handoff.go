// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
)

const (
	sessionHandoffTTL       = 30 * time.Second
	nip46BindingTTL         = 3 * time.Minute
	maxSessionHandoffs      = 4096
	maxNIP46Bindings        = 4096
	maxSessionExchangeBytes = 4 << 10
	handoffBindingCookie    = "__Host-grasp-handoff-bind"
	nip46BindingCookie      = "__Host-grasp-nip46-bind"
	handoffAudienceSuffix   = "/gitea-session-v1"
)

var (
	ErrInvalidRedirectURI = errors.New("invalid redirect_uri")
	errInvalidHandoff     = errors.New("invalid or expired session handoff")
)

type sessionHandoffRecord struct {
	GiteaUser   string
	RedirectURI string
	Audience    string
	BinderHash  [sha256.Size]byte
	ExpiresAt   time.Time
}

type sessionHandoff struct {
	URL       string
	Binder    string
	ExpiresAt time.Time
}

type nip46BindingRecord struct {
	RedirectURI string
	BinderHash  [sha256.Size]byte
	ExpiresAt   time.Time
}

type nip46Binding struct {
	RedirectURI string
	Binder      string
	ExpiresAt   time.Time
}

type SessionHandoffHandler struct {
	authService *Service
}

func NewSessionHandoffHandler(authService *Service) *SessionHandoffHandler {
	return &SessionHandoffHandler{authService: authService}
}

func (h *SessionHandoffHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/session/nip46/bind", corsMethodGuard(http.MethodPost, h.writeJSON, h.handleNIP46Bind))
	mux.HandleFunc("/auth/session/nip46/status", corsMethodGuard(http.MethodGet, h.writeJSON, h.handleNIP46Status))
	mux.HandleFunc("/auth/session/nip46/exchange", corsMethodGuard(http.MethodPost, h.writeJSON, h.handleNIP46Exchange))
	mux.HandleFunc("/auth/session/handoff/consume", corsMethodGuard(http.MethodGet, h.writeJSON, h.handleConsume))
}

func normalizeRedirectURI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/", nil
	}
	if strings.ContainsRune(raw, '\\') || strings.IndexFunc(raw, unicode.IsControl) >= 0 ||
		!strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", fmt.Errorf("%w: must be a same-origin absolute path", ErrInvalidRedirectURI)
	}

	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: must not contain an origin or fragment", ErrInvalidRedirectURI)
	}
	decodedPath, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.ContainsRune(decodedPath, '\\') || strings.IndexFunc(decodedPath, unicode.IsControl) >= 0 ||
		!strings.HasPrefix(decodedPath, "/") || strings.HasPrefix(decodedPath, "//") {
		return "", fmt.Errorf("%w: malformed path", ErrInvalidRedirectURI)
	}

	cleaned := path.Clean(decodedPath)
	if cleaned == "." {
		cleaned = "/"
	}
	if strings.HasSuffix(decodedPath, "/") && cleaned != "/" {
		cleaned += "/"
	}
	if cleaned == "/auth/session/handoff" || strings.HasPrefix(cleaned, "/auth/session/handoff/") {
		return "", fmt.Errorf("%w: handoff redirect loop", ErrInvalidRedirectURI)
	}
	u.Path = cleaned
	u.RawPath = ""
	u.Fragment = ""
	return u.EscapedPath() + querySuffix(u), nil
}

func querySuffix(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.ForceQuery && u.RawQuery == "" {
		return "?"
	}
	if u.RawQuery != "" {
		return "?" + u.RawQuery
	}
	return ""
}

func canonicalSessionAudience(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid handoff audience")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + handoffAudienceSuffix, nil
}

func validateGiteaUsername(username string) error {
	if username == "" || len(username) > 70 || strings.IndexFunc(username, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return fmt.Errorf("unsafe Gitea username")
	}
	return nil
}

func randomURLToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func tokenDigest(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func (s *Service) mintSessionHandoff(giteaUser, redirectURI string) (sessionHandoff, error) {
	if err := validateGiteaUsername(giteaUser); err != nil {
		return sessionHandoff{}, err
	}
	redirectURI, err := normalizeRedirectURI(redirectURI)
	if err != nil {
		return sessionHandoff{}, err
	}
	audience, err := canonicalSessionAudience(s.publicURL)
	if err != nil {
		return sessionHandoff{}, err
	}
	token, err := randomURLToken()
	if err != nil {
		return sessionHandoff{}, fmt.Errorf("generate handoff token: %w", err)
	}
	binder, err := randomURLToken()
	if err != nil {
		return sessionHandoff{}, fmt.Errorf("generate handoff binder: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(sessionHandoffTTL)
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	s.cleanupHandoffsLocked(now)
	if len(s.handoffs) >= maxSessionHandoffs {
		return sessionHandoff{}, fmt.Errorf("too many active session handoffs")
	}
	tokenHash := tokenDigest(token)
	s.handoffs[string(tokenHash[:])] = sessionHandoffRecord{
		GiteaUser:   giteaUser,
		RedirectURI: redirectURI,
		Audience:    audience,
		BinderHash:  tokenDigest(binder),
		ExpiresAt:   expiresAt,
	}
	return sessionHandoff{
		URL:       strings.TrimRight(s.publicURL, "/") + "/auth/session/handoff?token=" + url.QueryEscape(token),
		Binder:    binder,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) cleanupHandoffsLocked(now time.Time) {
	for key, record := range s.handoffs {
		if !record.ExpiresAt.After(now) {
			delete(s.handoffs, key)
		}
	}
	for key, record := range s.nip46Bindings {
		if !record.ExpiresAt.After(now) {
			delete(s.nip46Bindings, key)
		}
	}
}

func (s *Service) consumeSessionHandoff(token, binder, audienceOrigin string) (sessionHandoffRecord, error) {
	audience, err := canonicalSessionAudience(audienceOrigin)
	if err != nil {
		return sessionHandoffRecord{}, errInvalidHandoff
	}
	digest := tokenDigest(token)
	binderDigest := tokenDigest(binder)
	now := time.Now().UTC()

	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	s.cleanupHandoffsLocked(now)
	record, ok := s.handoffs[string(digest[:])]
	if !ok || record.Audience != audience ||
		subtle.ConstantTimeCompare(record.BinderHash[:], binderDigest[:]) != 1 {
		return sessionHandoffRecord{}, errInvalidHandoff
	}
	delete(s.handoffs, string(digest[:]))
	return record, nil
}

func (s *Service) mintNIP46Binding(redirectURI string) (nip46Binding, error) {
	redirectURI, err := normalizeRedirectURI(redirectURI)
	if err != nil {
		return nip46Binding{}, err
	}
	token, err := randomURLToken()
	if err != nil {
		return nip46Binding{}, fmt.Errorf("generate NIP-46 binding token: %w", err)
	}
	binder, err := randomURLToken()
	if err != nil {
		return nip46Binding{}, fmt.Errorf("generate NIP-46 binding cookie: %w", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(nip46BindingTTL)
	tokenHash := tokenDigest(token)

	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	s.cleanupHandoffsLocked(now)
	if len(s.nip46Bindings) >= maxNIP46Bindings {
		return nip46Binding{}, fmt.Errorf("too many active NIP-46 bindings")
	}
	s.nip46Bindings[string(tokenHash[:])] = nip46BindingRecord{
		RedirectURI: redirectURI,
		BinderHash:  tokenDigest(binder),
		ExpiresAt:   expiresAt,
	}
	return nip46Binding{
		RedirectURI: "/auth/session/nip46/bound?token=" + url.QueryEscape(token),
		Binder:      binder,
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *Service) consumeNIP46Binding(boundRedirect, binder string) (string, error) {
	normalized, err := normalizeRedirectURI(boundRedirect)
	if err != nil {
		return "", errInvalidHandoff
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Path != "/auth/session/nip46/bound" || len(u.Query()) != 1 {
		return "", errInvalidHandoff
	}
	token := u.Query().Get("token")
	if token == "" {
		return "", errInvalidHandoff
	}
	tokenHash := tokenDigest(token)
	binderHash := tokenDigest(binder)
	now := time.Now().UTC()

	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	s.cleanupHandoffsLocked(now)
	record, ok := s.nip46Bindings[string(tokenHash[:])]
	if !ok || subtle.ConstantTimeCompare(record.BinderHash[:], binderHash[:]) != 1 {
		return "", errInvalidHandoff
	}
	delete(s.nip46Bindings, string(tokenHash[:]))
	return record.RedirectURI, nil
}

func (s *Service) exchangeNIP46Session(r *http.Request, sessionToken string) (sessionHandoff, error) {
	if sessionToken == "" || len(sessionToken) > 256 {
		return sessionHandoff{}, errInvalidHandoff
	}
	sess, err := s.store.GetNIP46Session(r.Context(), sessionToken)
	if err != nil || sess.State != "complete" || sess.ResultPubkey == "" || !sess.ExpiresAt.After(time.Now().UTC()) {
		return sessionHandoff{}, errInvalidHandoff
	}
	link, err := s.store.GetIdentityLinkByPubkey(r.Context(), sess.ResultPubkey)
	if err != nil {
		return sessionHandoff{}, errInvalidHandoff
	}

	bindingCookie, err := r.Cookie(nip46BindingCookie)
	if err != nil {
		return sessionHandoff{}, errInvalidHandoff
	}
	redirectURI, err := s.consumeNIP46Binding(sess.RedirectURI, bindingCookie.Value)
	if err != nil {
		return sessionHandoff{}, errInvalidHandoff
	}
	return s.mintSessionHandoff(link.GiteaUser, redirectURI)
}

func (h *SessionHandoffHandler) handleNIP46Bind(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSessionExchangeBytes)
	var req ChallengeRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	binding, err := h.authService.mintNIP46Binding(req.RedirectURI)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrInvalidRedirectURI) {
			status = http.StatusBadRequest
		}
		h.writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	h.setNIP46BindingCookie(w, binding)
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": binding.RedirectURI,
		"expires_at":   binding.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *SessionHandoffHandler) handleNIP46Status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := r.URL.Query().Get("session")
	if token == "" || len(token) > 256 {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}
	sess, err := h.authService.store.GetNIP46Session(r.Context(), token)
	if errors.Is(err, sql.ErrNoRows) {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !sess.ExpiresAt.After(time.Now().UTC()) && sess.State == "pending" {
		h.writeJSON(w, http.StatusOK, map[string]string{"status": "error", "error": "session expired"})
		return
	}
	response := map[string]any{"status": sess.State}
	switch sess.State {
	case "complete":
		link, err := h.authService.store.GetIdentityLinkByPubkey(r.Context(), sess.ResultPubkey)
		if err != nil {
			response["status"] = "error"
			response["error"] = "identity resolution failed"
		} else {
			response["identity"] = ResolvedIdentity{
				Pubkey:      link.Pubkey,
				Npub:        link.Npub,
				GiteaUserID: link.GiteaUserID,
				GiteaUser:   link.GiteaUser,
				NIP05:       link.NIP05,
			}
		}
	case "error":
		response["error"] = sess.Error
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *SessionHandoffHandler) handleNIP46Exchange(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSessionExchangeBytes)
	var req struct {
		SessionToken string `json:"session_token"`
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	handoff, err := h.authService.exchangeNIP46Session(r, req.SessionToken)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	h.setBindingCookie(w, handoff)
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, map[string]string{
		"handoff_url": handoff.URL,
		"expires_at":  handoff.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *SessionHandoffHandler) handleConsume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("X-Grasp-Internal-Handoff") != "1" {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	cookie, err := r.Cookie(handoffBindingCookie)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session handoff"})
		return
	}
	record, err := h.authService.consumeSessionHandoff(
		r.Header.Get("X-Grasp-Handoff-Token"),
		cookie.Value,
		r.Header.Get("X-Grasp-Handoff-Audience"),
	)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session handoff"})
		return
	}
	w.Header().Set("X-Grasp-Auth-User", record.GiteaUser)
	w.Header().Set("X-Grasp-Auth-Redirect", record.RedirectURI)
	w.WriteHeader(http.StatusNoContent)
}

func (h *SessionHandoffHandler) setNIP46BindingCookie(w http.ResponseWriter, binding nip46Binding) {
	publicURL, _ := url.Parse(h.authService.publicURL)
	http.SetCookie(w, &http.Cookie{
		Name:     nip46BindingCookie,
		Value:    binding.Binder,
		Path:     "/",
		Secure:   publicURL != nil && publicURL.Scheme == "https",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  binding.ExpiresAt,
		MaxAge:   int(time.Until(binding.ExpiresAt).Seconds()),
	})
}

func (h *SessionHandoffHandler) setBindingCookie(w http.ResponseWriter, handoff sessionHandoff) {
	publicURL, _ := url.Parse(h.authService.publicURL)
	http.SetCookie(w, &http.Cookie{
		Name:     handoffBindingCookie,
		Value:    handoff.Binder,
		Path:     "/",
		Secure:   publicURL != nil && publicURL.Scheme == "https",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  handoff.ExpiresAt,
		MaxAge:   int(time.Until(handoff.ExpiresAt).Seconds()),
	})
}

func (h *SessionHandoffHandler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

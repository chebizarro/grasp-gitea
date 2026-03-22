package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/nip46"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	authCodeTTL   = 60 * time.Second
	accessTokenTTL = time.Hour
)

// Config holds OAuth2 provider settings.
type Config struct {
	ClientID        string
	ClientSecret    string
	BridgePublicURL string // e.g. "https://git.sharegap.net/auth-bridge" (no trailing slash)
	RelayURL        string // relay used for NIP-05 resolution during user provisioning
}

// Provider implements a minimal OAuth2 authorization server backed by NIP-98 auth.
type Provider struct {
	cfg     Config
	auth    *auth.Service
	store   *store.SQLiteStore
	gitea   *gitea.Client
	logger  *slog.Logger
}

// New creates a Provider.
func New(cfg Config, authSvc *auth.Service, st *store.SQLiteStore, gc *gitea.Client, logger *slog.Logger) *Provider {
	return &Provider{
		cfg:    cfg,
		auth:   authSvc,
		store:  st,
		gitea:  gc,
		logger: logger,
	}
}

// verifyURL returns the public verify endpoint URL.
func (p *Provider) verifyURL() string {
	return strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip07/verify"
}

// HandleAuthorize serves the OAuth2 authorization endpoint.
// Gitea redirects here; we serve the NIP-07 sign-in page.
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")

	if clientID != p.cfg.ClientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	challenge, err := p.auth.IssueChallenge(r.Context(), state, redirectURI, p.verifyURL())
	if err != nil {
		p.logger.Error("issue challenge failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	metrics.IncNIP07ChallengesIssued()

	// Embed challenge data into the sign-in page.
	challengeJSON, _ := json.Marshal(challenge)
	page := strings.ReplaceAll(signinPageTemplate, "__CHALLENGE_DATA__", string(challengeJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

// HandleVerify processes the NIP-98 signed event from the browser.
// Returns JSON with a redirect_url on success.
func (p *Provider) HandleVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challenge_id"`
		SignedEvent string `json:"signed_event"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.ChallengeID == "" || body.SignedEvent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id and signed_event required"})
		return
	}

	// Consume the challenge (validates it exists, is not expired, not replayed).
	challenge, err := p.store.ConsumeChallenge(r.Context(), body.ChallengeID)
	if err != nil {
		metrics.IncNIP07ReplayRejected()
		p.logger.Warn("challenge consume failed", "challenge_id", body.ChallengeID, "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired challenge"})
		return
	}

	// Verify NIP-98 event.
	result, err := auth.VerifyNIP98(auth.VerifyRequest{
		SignedEventJSON: body.SignedEvent,
		ExpectedURL:     p.verifyURL(),
		ExpectedMethod:  "POST",
	})
	if err != nil {
		metrics.IncNIP07VerifyFailure()
		p.logger.Warn("NIP-98 verification failed", "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verification failed: " + err.Error()})
		return
	}

	// Resolve or create the Gitea user for this pubkey.
	giteaUser, err := p.resolveGiteaUser(r.Context(), result.Pubkey, result.Npub)
	if err != nil {
		metrics.IncNIP07VerifyFailure()
		p.logger.Error("gitea user resolution failed", "pubkey", result.Pubkey, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user provisioning failed"})
		return
	}

	// Issue OAuth2 auth code.
	code, err := store.GenerateToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := p.store.CreateAuthCode(r.Context(), code, result.Pubkey, result.Npub, challenge.RedirectURI, time.Now().Add(authCodeTTL)); err != nil {
		p.logger.Error("create auth code failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	metrics.IncNIP07VerifySuccess()
	p.logger.Info("NIP-07 login success", "pubkey", result.Pubkey, "gitea_user", giteaUser.Username)

	// Build redirect URL back to Gitea.
	sep := "?"
	if strings.Contains(challenge.RedirectURI, "?") {
		sep = "&"
	}
	redirectURL := challenge.RedirectURI + sep + "code=" + code
	if challenge.OAuth2State != "" {
		redirectURL += "&state=" + challenge.OAuth2State
	}

	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": redirectURL})
}

// HandleToken handles OAuth2 token exchange (authorization_code grant).
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Also accept HTTP Basic auth.
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	if clientID != p.cfg.ClientID || clientSecret != p.cfg.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	code := r.FormValue("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code required"})
		return
	}

	ac, err := p.store.ConsumeAuthCode(r.Context(), code)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant"})
		return
	}

	token, err := store.GenerateToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := p.store.CreateAccessToken(r.Context(), token, ac.Pubkey, time.Now().Add(accessTokenTTL)); err != nil {
		p.logger.Error("create access token failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	metrics.IncOAuth2TokenExchanges()

	// Resolve identity for id_token claims.
	link, found, _ := p.store.GetIdentityLinkByPubkey(r.Context(), ac.Pubkey)
	username := ac.Npub
	if found {
		username = link.GiteaUsername
	}
	email := username + "@nostr.local"

	idToken, err := mintIDToken(p.cfg, ac.Pubkey, username, email, accessTokenTTL)
	if err != nil {
		p.logger.Warn("mint id_token failed", "error", err)
	}

	resp := map[string]any{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// HandleUserInfo serves OIDC userinfo for a valid access token.
func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="grasp-bridge"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}

	at, err := p.store.GetAccessToken(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="grasp-bridge", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	link, found, err := p.store.GetIdentityLinkByPubkey(r.Context(), at.Pubkey)
	if err != nil || !found {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                link.Pubkey,
		"preferred_username": link.GiteaUsername,
		"name":               link.GiteaUsername,
		"email":              link.GiteaUsername + "@nostr.local",
	})
}

// --- NIP-46 (remote signing / bunker) ---

// HandleNIP46Init starts a NIP-46 session. The browser posts the bunker URI
// and OAuth2 params; this kicks off a background connection to the bunker and
// returns a session token for polling.
func (p *Provider) HandleNIP46Init(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BunkerURI   string `json:"bunker_uri"`
		OAuth2State string `json:"state"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.BunkerURI == "" || body.RedirectURI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bunker_uri and redirect_uri required"})
		return
	}

	sessionToken, err := store.GenerateToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	sess := store.NIP46Session{
		SessionToken: sessionToken,
		OAuth2State:  body.OAuth2State,
		RedirectURI:  body.RedirectURI,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(nip46.SessionTimeout),
	}
	if err := p.store.CreateNIP46Session(r.Context(), sess); err != nil {
		p.logger.Error("create nip46 session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	metrics.IncNIP46SessionsInitiated()

	// Run the bunker handshake in the background.
	challengeURL := strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip46/verify"
	resultCh := nip46.RunSession(context.Background(), p.logger, body.BunkerURI, challengeURL, "POST")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), nip46.SessionTimeout)
		defer cancel()
		_ = ctx

		result := <-resultCh
		if result.Err != nil {
			p.logger.Warn("nip46 session failed", "session", sessionToken, "error", result.Err)
			metrics.IncNIP46SessionsFailed()
			_ = p.store.FailNIP46Session(context.Background(), sessionToken, result.Err.Error())
			return
		}

		// Verify signed event.
		evJSON, _ := json.Marshal(result.SignedEvent)
		vr, err := auth.VerifyNIP98(auth.VerifyRequest{
			SignedEventJSON: string(evJSON),
			ExpectedURL:     challengeURL,
			ExpectedMethod:  "POST",
		})
		if err != nil {
			p.logger.Warn("nip46 nip98 verify failed", "session", sessionToken, "error", err)
			metrics.IncNIP46SessionsFailed()
			_ = p.store.FailNIP46Session(context.Background(), sessionToken, "signature verification failed: "+err.Error())
			return
		}

		// Resolve/create Gitea user.
		giteaUser, err := p.resolveGiteaUser(context.Background(), vr.Pubkey, vr.Npub)
		if err != nil {
			p.logger.Error("nip46 user resolve failed", "pubkey", vr.Pubkey, "error", err)
			metrics.IncNIP46SessionsFailed()
			_ = p.store.FailNIP46Session(context.Background(), sessionToken, "user provisioning failed")
			return
		}

		// Issue auth code.
		code, err := store.GenerateToken()
		if err != nil {
			_ = p.store.FailNIP46Session(context.Background(), sessionToken, "internal error")
			return
		}
		if err := p.store.CreateAuthCode(context.Background(), code, vr.Pubkey, vr.Npub, sess.RedirectURI, time.Now().Add(authCodeTTL)); err != nil {
			_ = p.store.FailNIP46Session(context.Background(), sessionToken, "internal error")
			return
		}

		_ = p.store.CompleteNIP46Session(context.Background(), sessionToken, code)
		metrics.IncNIP46SessionsCompleted()
		p.logger.Info("nip46 login success", "pubkey", vr.Pubkey, "gitea_user", giteaUser.Username)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{
		"session_token": sessionToken,
		"poll_url":      strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip46/status",
		"expires_at":    sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleNIP46Status polls the status of a NIP-46 session.
// Returns { status, redirect_url } where status is "pending" | "complete" | "error".
func (p *Provider) HandleNIP46Status(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("session")
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session required"})
		return
	}

	sess, err := p.store.GetNIP46Session(r.Context(), token)
	if err == store.ErrNotFound {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if err == store.ErrExpired {
		writeJSON(w, http.StatusOK, map[string]string{"status": "error", "error": "session expired"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	resp := map[string]string{"status": sess.Status}
	if sess.Status == "complete" {
		sep := "?"
		if strings.Contains(sess.RedirectURI, "?") {
			sep = "&"
		}
		redirectURL := sess.RedirectURI + sep + "code=" + sess.AuthCode
		if sess.OAuth2State != "" {
			redirectURL += "&state=" + sess.OAuth2State
		}
		resp["redirect_url"] = redirectURL
	}
	if sess.Status == "error" {
		resp["error"] = sess.ErrorMsg
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- NIP-55 (Android signer) ---

const nip55SessionTimeout = 10 * time.Minute

// HandleNIP55Challenge issues a NIP-55 challenge.
// Returns a nostrsigner: URI the user can open with an Android signer app, plus a
// session token for polling (reuses the NIP-46 poll endpoint).
func (p *Provider) HandleNIP55Challenge(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	oauth2State := q.Get("state")
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redirect_uri required"})
		return
	}

	sessionToken, err := store.GenerateToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	callbackURL := strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip55/callback?session=" + sessionToken

	// Build an unsigned NIP-98 challenge event. The signer app fills in pubkey + sig.
	evt := nostr.Event{
		Kind:      27235,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", callbackURL},
			{"method", "POST"},
		},
	}
	evtJSON, _ := json.Marshal(evt)

	nostrsignerURI := "nostrsigner:" + url.QueryEscape(string(evtJSON)) +
		"?compressionType=none&returnType=event&callbackUrl=" + url.QueryEscape(callbackURL)

	sess := store.NIP46Session{
		SessionToken: sessionToken,
		OAuth2State:  oauth2State,
		RedirectURI:  redirectURI,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(nip55SessionTimeout),
	}
	if err := p.store.CreateNIP46Session(r.Context(), sess); err != nil {
		p.logger.Error("create nip55 session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	metrics.IncNIP55ChallengesIssued()

	writeJSON(w, http.StatusOK, map[string]string{
		"session_token":   sessionToken,
		"nostrsigner_uri": nostrsignerURI,
		"callback_url":    callbackURL,
		"poll_url":        strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip46/status",
		"expires_at":      sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleNIP55Callback receives the signed event from the Android signer app.
func (p *Provider) HandleNIP55Callback(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.URL.Query().Get("session")
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session required"})
		return
	}

	sess, err := p.store.GetNIP46Session(r.Context(), sessionToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	if sess.Status != "pending" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "session already completed"})
		return
	}

	// Accept signed event either as JSON body or form field "event".
	var evtJSON string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			Event string `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			evtJSON = body.Event
		}
	}
	if evtJSON == "" {
		_ = r.ParseForm()
		evtJSON = r.FormValue("event")
	}
	if evtJSON == "" {
		metrics.IncNIP55VerifyFailure()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event required"})
		return
	}

	callbackURL := strings.TrimRight(p.cfg.BridgePublicURL, "/") + "/auth/nip55/callback"
	vr, err := auth.VerifyNIP98(auth.VerifyRequest{
		SignedEventJSON: evtJSON,
		ExpectedURL:     callbackURL,
		ExpectedMethod:  "POST",
	})
	if err != nil {
		metrics.IncNIP55VerifyFailure()
		p.logger.Warn("nip55 verify failed", "session", sessionToken, "error", err)
		_ = p.store.FailNIP46Session(r.Context(), sessionToken, "signature verification failed: "+err.Error())
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verification failed"})
		return
	}

	giteaUser, err := p.resolveGiteaUser(r.Context(), vr.Pubkey, vr.Npub)
	if err != nil {
		metrics.IncNIP55VerifyFailure()
		_ = p.store.FailNIP46Session(r.Context(), sessionToken, "user provisioning failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user provisioning failed"})
		return
	}

	code, err := store.GenerateToken()
	if err != nil {
		_ = p.store.FailNIP46Session(r.Context(), sessionToken, "internal error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := p.store.CreateAuthCode(r.Context(), code, vr.Pubkey, vr.Npub, sess.RedirectURI, time.Now().Add(authCodeTTL)); err != nil {
		_ = p.store.FailNIP46Session(r.Context(), sessionToken, "internal error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	_ = p.store.CompleteNIP46Session(r.Context(), sessionToken, code)
	metrics.IncNIP55VerifySuccess()
	p.logger.Info("nip55 login success", "pubkey", vr.Pubkey, "gitea_user", giteaUser.Username)

	writeJSON(w, http.StatusOK, map[string]string{"status": "complete"})
}

// resolveGiteaUser looks up an existing identity link or provisions a new Gitea user.
func (p *Provider) resolveGiteaUser(ctx context.Context, pubkey, npub string) (gitea.User, error) {
	// Check existing link.
	link, found, err := p.store.GetIdentityLinkByPubkey(ctx, pubkey)
	if err != nil {
		return gitea.User{}, fmt.Errorf("identity link lookup: %w", err)
	}

	var username string
	if found {
		username = link.GiteaUsername
	} else {
		// Resolve NIP-05 for a human-readable username.
		username = p.resolveUsername(ctx, pubkey)
		metrics.IncNIP07UsersAutoProvisioned()
	}

	email := username + "@nostr.local"
	user, err := p.gitea.EnsureUser(ctx, username, email)
	if err != nil {
		return gitea.User{}, fmt.Errorf("ensure gitea user: %w", err)
	}

	// Upsert identity link.
	newLink := store.IdentityLink{
		Pubkey:        pubkey,
		Npub:          npub,
		GiteaUserID:   user.ID,
		GiteaUsername: user.Username,
		CreatedAt:     time.Now(),
		LastLoginAt:   time.Now(),
	}
	if found {
		newLink.NIP05 = link.NIP05
		newLink.CreatedAt = link.CreatedAt
	}
	if err := p.store.UpsertIdentityLink(ctx, newLink); err != nil {
		p.logger.Warn("upsert identity link failed", "pubkey", pubkey, "error", err)
		// Non-fatal: user is provisioned, just the link didn't persist.
	}

	return user, nil
}

// resolveUsername derives a Gitea-safe username from a pubkey.
// Tries NIP-05 via the configured relay; falls back to hex prefix.
func (p *Provider) resolveUsername(ctx context.Context, pubkey string) string {
	if p.cfg.RelayURL != "" {
		if name := nip05resolve.OrgName(ctx, pubkey, p.cfg.RelayURL); name != "" && name != pubkey[:min(39, len(pubkey))] {
			return name
		}
	}
	if len(pubkey) >= 39 {
		return pubkey[:39]
	}
	return pubkey
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

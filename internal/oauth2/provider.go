package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
	})
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

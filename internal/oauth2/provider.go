package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type Config struct{ ClientID, ClientSecret, PublicURL, RedirectURI string }
type Provider struct {
	cfg        Config
	auth       *auth.Service
	identities *auth.IdentityService
	store      *store.SQLiteStore
	logger     *slog.Logger
}

func New(cfg Config, a *auth.Service, ids *auth.IdentityService, st *store.SQLiteStore, logger *slog.Logger) *Provider {
	return &Provider{cfg: cfg, auth: a, identities: ids, store: st, logger: logger.With("component", "oauth2")}
}

func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/auth/oauth2/authorize", p.authorize)
	mux.HandleFunc("/auth/oauth2/verify", p.verify)
	mux.HandleFunc("/auth/oauth2/nip46/status", p.nip46Status)
	mux.HandleFunc("/auth/oauth2/token", p.token)
	mux.HandleFunc("/auth/oauth2/userinfo", p.userinfo)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	b := p.cfg.PublicURL
	writeJSON(w, 200, map[string]any{"issuer": b, "authorization_endpoint": b + "/auth/oauth2/authorize", "token_endpoint": b + "/auth/oauth2/token", "userinfo_endpoint": b + "/auth/oauth2/userinfo", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"HS256"}, "scopes_supported": []string{"openid", "profile", "email"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.cfg.ClientID || q.Get("response_type") != "code" || q.Get("redirect_uri") != p.cfg.RedirectURI {
		http.Error(w, "invalid OAuth request", 400)
		return
	}
	// The challenge redirect carries both callback and state and is never sent to a third party.
	packed, _ := json.Marshal(map[string]string{"redirect_uri": q.Get("redirect_uri"), "state": q.Get("state")})
	c, err := p.auth.IssueChallenge(r.Context(), auth.ChallengeRequest{RedirectURI: string(packed)})
	if err != nil {
		http.Error(w, "challenge failed", 500)
		return
	}
	data, _ := json.Marshal(map[string]any{"nonce": c.Nonce, "url": p.cfg.PublicURL + "/auth/oauth2/verify", "method": "POST", "expires_at": c.ExpiresAt.Unix(), "flow": string(packed)})
	page := strings.Replace(signinPage, "__CHALLENGE__", string(data), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(page))
}

func (p *Provider) nip46Status(w http.ResponseWriter, r *http.Request) {
	sess, err := p.store.GetNIP46Session(r.Context(), r.URL.Query().Get("session"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "session not found"})
		return
	}
	if sess.State == "pending" {
		writeJSON(w, 200, map[string]string{"status": sess.State, "error": sess.Error})
		return
	}
	if sess.State != "complete" {
		writeJSON(w, 200, map[string]string{"status": "error", "error": "session is not available"})
		return
	}
	identity, err := p.identities.ResolveOrCreate(r.Context(), sess.ResultPubkey, nil)
	if err != nil {
		writeJSON(w, 500, map[string]string{"status": "error", "error": "identity resolution failed"})
		return
	}
	var flow map[string]string
	if json.Unmarshal([]byte(sess.RedirectURI), &flow) != nil {
		writeJSON(w, 500, map[string]string{"status": "error", "error": "invalid flow state"})
		return
	}
	code, err := store.GenerateToken()
	if err != nil || p.store.CreateAuthCode(r.Context(), code, identity.Pubkey, flow["redirect_uri"], time.Now().Add(time.Minute)) != nil {
		writeJSON(w, 500, map[string]string{"status": "error", "error": "code issuance failed"})
		return
	}
	if err := p.store.UpdateNIP46SessionState(r.Context(), sess.SessionToken, "oauth_complete", sess.ResultPubkey, ""); err != nil {
		writeJSON(w, 500, map[string]string{"status": "error", "error": "session finalization failed"})
		return
	}
	sep := "?"
	if strings.Contains(flow["redirect_uri"], "?") {
		sep = "&"
	}
	location := flow["redirect_uri"] + sep + "code=" + url.QueryEscape(code)
	if flow["state"] != "" {
		location += "&state=" + url.QueryEscape(flow["state"])
	}
	writeJSON(w, 200, map[string]string{"status": "complete", "redirect_url": location})
}

func (p *Provider) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		SignedEvent *nostr.Event `json:"signed_event"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.SignedEvent == nil {
		writeJSON(w, 400, map[string]string{"error": "signed_event required"})
		return
	}
	ev := req.SignedEvent
	if nostrverify.ValidateEventIDAndSignature(ev) != nil || ev.Kind != 27235 || tag(ev.Tags, "u") != p.cfg.PublicURL+"/auth/oauth2/verify" || tag(ev.Tags, "method") != "POST" || time.Since(time.Unix(int64(ev.CreatedAt), 0)).Abs() > 60*time.Second {
		writeJSON(w, 401, map[string]string{"error": "invalid NIP-98 proof"})
		return
	}
	nonce := tag(ev.Tags, "nonce")
	ch, err := p.auth.ValidateChallenge(r.Context(), nonce)
	if err != nil || p.auth.ConsumeChallenge(r.Context(), nonce) != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid or replayed challenge"})
		return
	}
	identity, err := p.identities.ResolveOrCreate(r.Context(), ev.PubKey, nil)
	if err != nil {
		p.logger.Error("identity resolution failed", "error", err)
		writeJSON(w, 500, map[string]string{"error": "identity resolution failed"})
		return
	}
	var flow map[string]string
	if json.Unmarshal([]byte(ch.RedirectURI), &flow) != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid flow state"})
		return
	}
	code, err := store.GenerateToken()
	if err != nil || p.store.CreateAuthCode(r.Context(), code, identity.Pubkey, flow["redirect_uri"], time.Now().Add(time.Minute)) != nil {
		writeJSON(w, 500, map[string]string{"error": "code issuance failed"})
		return
	}
	sep := "?"
	if strings.Contains(flow["redirect_uri"], "?") {
		sep = "&"
	}
	location := flow["redirect_uri"] + sep + "code=" + url.QueryEscape(code)
	if flow["state"] != "" {
		location += "&state=" + url.QueryEscape(flow["state"])
	}
	writeJSON(w, 200, map[string]string{"redirect_url": location})
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	_ = r.ParseForm()
	id, secret := r.FormValue("client_id"), r.FormValue("client_secret")
	if id == "" {
		id, secret, _ = r.BasicAuth()
	}
	if id != p.cfg.ClientID || !hmac.Equal([]byte(secret), []byte(p.cfg.ClientSecret)) {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	ac, err := p.store.ConsumeAuthCode(r.Context(), r.FormValue("code"))
	if err != nil || r.FormValue("redirect_uri") != ac.RedirectURI || ac.RedirectURI != p.cfg.RedirectURI {
		writeJSON(w, 401, map[string]string{"error": "invalid_grant"})
		return
	}
	tok, _ := store.GenerateToken()
	ttl := time.Hour
	if p.store.CreateAccessToken(r.Context(), tok, ac.Pubkey, time.Now().Add(ttl)) != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	link, err := p.store.GetIdentityLinkByPubkey(r.Context(), ac.Pubkey)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	email := link.GiteaUser + "@nostr.local"
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "bearer", "expires_in": int(ttl.Seconds()), "id_token": p.idToken(ac.Pubkey, link.GiteaUser, email, ttl)})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	at, err := p.store.GetAccessToken(r.Context(), h)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	link, err := p.store.GetIdentityLinkByPubkey(r.Context(), at.Pubkey)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, 200, map[string]string{"sub": link.Pubkey, "preferred_username": link.GiteaUser, "name": link.GiteaUser, "email": link.GiteaUser + "@nostr.local"})
}

func (p *Provider) idToken(pubkey, user, email string, ttl time.Duration) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	now := time.Now().Unix()
	b, _ := json.Marshal(map[string]any{"iss": p.cfg.PublicURL, "sub": pubkey, "aud": p.cfg.ClientID, "iat": now, "exp": now + int64(ttl.Seconds()), "preferred_username": user, "name": user, "email": email})
	in := enc(h) + "." + enc(b)
	mac := hmac.New(sha256.New, []byte(p.cfg.ClientSecret))
	_, _ = mac.Write([]byte(in))
	return in + "." + enc(mac.Sum(nil))
}
func tag(tags nostr.Tags, key string) string {
	for _, t := range tags {
		if len(t) > 1 && t[0] == key {
			return t[1]
		}
	}
	return ""
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

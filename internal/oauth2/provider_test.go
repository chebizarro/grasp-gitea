package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/markbates/goth/providers/openidConnect"
	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func testProvider() *Provider {
	return New(Config{
		ClientID: "gitea-nostr", ClientSecret: "secret",
		PublicURL: "https://bridge.example", RedirectURI: "https://git.example/user/oauth2/nostr/callback",
	}, nil, nil, nil, slog.Default())
}

func TestDiscovery(t *testing.T) {
	rr := httptest.NewRecorder()
	testProvider().discovery(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"authorization_endpoint":"https://bridge.example/auth/oauth2/authorize"`) {
		t.Fatalf("unexpected discovery response: %d %s", rr.Code, rr.Body.String())
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?client_id=gitea-nostr&response_type=code&redirect_uri=https://attacker.example/callback", nil)
	testProvider().authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTokenRejectsBadClientBeforeStore(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth2/token", strings.NewReader("client_id=wrong&client_secret=wrong&code=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testProvider().token(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestGitea126GothOIDCCompatibility(t *testing.T) {
	const (
		clientID     = "gitea-nostr"
		clientSecret = "test-client-secret"
		callbackURL  = "https://git.example/user/oauth2/nostr/callback"
		state        = "gitea-state"
		username     = "nostr-user"
	)

	st, err := store.Open(t.TempDir() + "/oidc.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	secretKey := nostr.GeneratePrivateKey()
	pubkey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertIdentityLink(context.Background(), store.NostrIdentityLink{
		Pubkey: pubkey, Npub: "test-npub", GiteaUserID: 42, GiteaUser: username, LastLoginAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	logger := slog.Default()
	authSvc := auth.NewService(config.Config{
		AuthEnabled: true, BridgePublicURL: server.URL, ChallengeTTL: time.Minute,
	}, st, logger)
	identitySvc := auth.NewIdentityService(st, nil, nil, logger)
	provider := New(Config{
		ClientID: clientID, ClientSecret: clientSecret, PublicURL: server.URL, RedirectURI: callbackURL,
	}, authSvc, identitySvc, st, logger)
	provider.RegisterRoutes(mux)

	// Gitea 1.26.1 uses Goth v1.82.0's OpenID Connect provider. Exercise that
	// exact client against our discovery, token, ID-token, and userinfo surfaces.
	giteaClient, err := openidConnect.New(clientID, clientSecret, callbackURL, server.URL+"/.well-known/openid-configuration", "openid", "profile", "email")
	if err != nil {
		t.Fatal(err)
	}
	session, err := giteaClient.BeginAuth(state)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := session.GetAuthURL()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("authorization page: status=%d error=%v", resp.StatusCode, err)
	}

	match := regexp.MustCompile(`const C=(\{.*?\});function show`).FindSubmatch(page)
	if len(match) != 2 {
		t.Fatal("authorization page did not contain a challenge payload")
	}
	var challenge struct {
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(match[1], &challenge); err != nil {
		t.Fatal(err)
	}
	event := &nostr.Event{
		Kind: 27235, CreatedAt: nostr.Now(),
		Tags: nostr.Tags{{"u", challenge.URL}, {"method", "POST"}, {"nonce", challenge.Nonce}},
	}
	if err := event.Sign(secretKey); err != nil {
		t.Fatal(err)
	}
	requestBody, _ := json.Marshal(map[string]any{"signed_event": event})
	resp, err = http.Post(server.URL+"/auth/oauth2/verify", "application/json", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	var verified struct {
		RedirectURL string `json:"redirect_url"`
	}
	err = json.NewDecoder(resp.Body).Decode(&verified)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("NIP-07 verification: status=%d error=%v", resp.StatusCode, err)
	}
	redirect, err := url.Parse(verified.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Query().Get("state") != state || redirect.Query().Get("code") == "" {
		t.Fatalf("invalid authorization redirect: %s", verified.RedirectURL)
	}

	if _, err := session.Authorize(giteaClient, url.Values{"code": {redirect.Query().Get("code")}}); err != nil {
		t.Fatalf("Gitea Goth token exchange failed: %v", err)
	}
	user, err := giteaClient.FetchUser(session)
	if err != nil {
		t.Fatalf("Gitea Goth user fetch failed: %v", err)
	}
	if user.UserID != pubkey || user.NickName != username || user.Email != username+"@nostr.local" {
		t.Fatalf("unexpected Gitea identity: id=%q nickname=%q email=%q", user.UserID, user.NickName, user.Email)
	}
}

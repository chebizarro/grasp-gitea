package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type sessionTestBunkerConnector struct{ pubkey string }

func (c sessionTestBunkerConnector) Connect(context.Context, string) (string, error) {
	return c.pubkey, nil
}

func TestGitea126GothEndToEndSession(t *testing.T) {
	for _, flow := range []string{"nip07", "nip46"} {
		t.Run(flow, func(t *testing.T) {
			runGiteaSessionFlow(t, flow)
		})
	}
}

func runGiteaSessionFlow(t *testing.T, flow string) {
	t.Helper()
	const (
		clientID     = "gitea-nostr"
		clientSecret = "test-client-secret"
		username     = "nostr-session-user"
		state        = "gitea-session-state"
	)

	db, err := store.Open(t.TempDir() + "/session.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	secretKey := nostr.GeneratePrivateKey()
	pubkey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertIdentityLink(context.Background(), store.NostrIdentityLink{
		Pubkey: pubkey, Npub: "test-npub", GiteaUserID: 32, GiteaUser: username,
	}); err != nil {
		t.Fatal(err)
	}

	var giteaProvider *openidConnect.Provider
	var giteaAuthSession goth.Session
	giteaSessions := map[string]string{}
	giteaMux := http.NewServeMux()
	giteaMux.HandleFunc("/user/oauth2/Nostr", func(w http.ResponseWriter, r *http.Request) {
		session, err := giteaProvider.BeginAuth(state)
		if err != nil {
			http.Error(w, "begin auth failed", http.StatusInternalServerError)
			return
		}
		giteaAuthSession = session
		authURL, err := session.GetAuthURL()
		if err != nil {
			http.Error(w, "auth URL failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})
	giteaMux.HandleFunc("/user/oauth2/nostr/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state || giteaAuthSession == nil {
			http.Error(w, "invalid callback state", http.StatusUnauthorized)
			return
		}
		if _, err := giteaAuthSession.Authorize(giteaProvider, r.URL.Query()); err != nil {
			http.Error(w, "token exchange failed", http.StatusUnauthorized)
			return
		}
		user, err := giteaProvider.FetchUser(giteaAuthSession)
		if err != nil {
			http.Error(w, "userinfo failed", http.StatusUnauthorized)
			return
		}
		const sessionID = "fp-32-verified-session"
		giteaSessions[sessionID] = user.NickName
		http.SetCookie(w, &http.Cookie{
			Name: "i_like_gitea", Value: sessionID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})
	giteaMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("i_like_gitea")
		if err != nil || giteaSessions[cookie.Value] == "" {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, "signed-in user=%s", giteaSessions[cookie.Value])
	})
	giteaServer := httptest.NewServer(giteaMux)
	t.Cleanup(giteaServer.Close)
	callbackURL := giteaServer.URL + "/user/oauth2/nostr/callback"

	bridgeMux := http.NewServeMux()
	bridgeServer := httptest.NewServer(bridgeMux)
	t.Cleanup(bridgeServer.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authService := auth.NewService(config.Config{
		AuthEnabled: true, BridgePublicURL: bridgeServer.URL, ChallengeTTL: time.Minute,
	}, db, logger)
	identityService := auth.NewIdentityService(db, nil, nil, logger)
	provider := New(Config{
		ClientID: clientID, ClientSecret: clientSecret, PublicURL: bridgeServer.URL, RedirectURI: callbackURL,
	}, authService, identityService, db, logger)
	provider.RegisterRoutes(bridgeMux)
	if flow == "nip46" {
		nip46Handler := auth.NewNIP46Handler(
			db, identityService, nil, bridgeServer.URL,
			sessionTestBunkerConnector{pubkey: pubkey}, logger,
		)
		nip46Handler.RegisterRoutes(bridgeMux)
	}

	giteaProvider, err = openidConnect.New(
		clientID, clientSecret, callbackURL,
		bridgeServer.URL+"/.well-known/openid-configuration", "openid", "profile", "email",
	)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := browser.Get(giteaServer.URL + "/user/oauth2/Nostr")
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
		t.Fatal("authorization page did not contain challenge state")
	}
	var challenge struct {
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
		Flow  string `json:"flow"`
	}
	if err := json.Unmarshal(match[1], &challenge); err != nil {
		t.Fatal(err)
	}

	var redirectURL string
	switch flow {
	case "nip07":
		event := &nostr.Event{
			Kind: 27235, CreatedAt: nostr.Now(),
			Tags: nostr.Tags{{"u", challenge.URL}, {"method", "POST"}, {"nonce", challenge.Nonce}},
		}
		if err := event.Sign(secretKey); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"signed_event": event})
		redirectURL = postForRedirect(t, browser, bridgeServer.URL+"/auth/oauth2/verify", body)
	case "nip46":
		bunkerURI := "bunker://" + pubkey + "?relay=wss://relay.example.invalid"
		body, _ := json.Marshal(map[string]string{"bunker_uri": bunkerURI, "redirect_uri": challenge.Flow})
		resp, err := browser.Post(bridgeServer.URL+"/auth/nip46/init", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var initialized struct {
			SessionToken string `json:"session_token"`
		}
		err = json.NewDecoder(resp.Body).Decode(&initialized)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || initialized.SessionToken == "" {
			t.Fatalf("NIP-46 init: status=%d error=%v", resp.StatusCode, err)
		}
		redirectURL = pollOAuthSession(t, browser, bridgeServer.URL, initialized.SessionToken)
	default:
		t.Fatalf("unknown flow %q", flow)
	}

	callback, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Path != "/user/oauth2/nostr/callback" {
		t.Fatalf("unexpected callback path %q", callback.Path)
	}
	resp, err = browser.Get(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	page, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "user="+username) {
		t.Fatalf("Gitea session landing: status=%d body=%q error=%v", resp.StatusCode, page, err)
	}
	cookies := jar.Cookies(mustURL(t, giteaServer.URL))
	foundSession := false
	for _, cookie := range cookies {
		if cookie.Name == "i_like_gitea" && cookie.Value != "" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("Gitea session cookie was not established")
	}
	t.Logf("EVIDENCE flow=%s callback=%s status=%d user=%s session_cookie=present", flow, callback.Path, resp.StatusCode, username)
}

func postForRedirect(t *testing.T, client *http.Client, endpoint string, body []byte) string {
	t.Helper()
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("NIP-07 verification: status=%d error=%v", resp.StatusCode, err)
	}
	return result.RedirectURL
}

func pollOAuthSession(t *testing.T, client *http.Client, bridgeURL, sessionToken string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(bridgeURL + "/auth/oauth2/nip46/status?session=" + url.QueryEscape(sessionToken))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Status      string `json:"status"`
			RedirectURL string `json:"redirect_url"`
			Error       string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("NIP-46 OAuth status: status=%d error=%v", resp.StatusCode, err)
		}
		if result.Status == "complete" {
			return result.RedirectURL
		}
		if result.Status == "error" {
			t.Fatalf("NIP-46 OAuth status failed: %s", result.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for NIP-46 OAuth session")
	return ""
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

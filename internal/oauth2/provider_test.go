package oauth2

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

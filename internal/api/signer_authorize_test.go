package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/signer"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeSignerAuthorizer struct {
	enabled   bool
	bunkerURI string
	grant     signer.GrantInfo
	err       error
}

func (f *fakeSignerAuthorizer) Enabled() bool { return f.enabled }

func (f *fakeSignerAuthorizer) CreateGrant(_ context.Context, bunkerURI string) (signer.GrantInfo, error) {
	f.bunkerURI = bunkerURI
	if f.err != nil {
		return signer.GrantInfo{}, f.err
	}
	return f.grant, nil
}

func TestSignerAuthorizeCreatesGrant(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	fake := &fakeSignerAuthorizer{
		enabled: true,
		grant: signer.GrantInfo{
			Pubkey:       "owner-pubkey",
			ClientPubkey: "client-pubkey",
			Relays:       []string{"wss://relay.example"},
			GrantedAt:    time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		},
	}
	srv := New(config.Config{AdminAPIToken: "secret"}, nil, nil, st, nil)
	srv.SetSignerAuthorizer(fake)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/signer/authorize", strings.NewReader(`{"bunker_uri":" bunker://owner?relay=wss://relay.example "}`))
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if fake.bunkerURI != "bunker://owner?relay=wss://relay.example" {
		t.Fatalf("CreateGrant bunker URI = %q", fake.bunkerURI)
	}
	var body struct {
		OK           bool     `json:"ok"`
		Pubkey       string   `json:"pubkey"`
		ClientPubkey string   `json:"client_pubkey"`
		Relays       []string `json:"relays"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.Pubkey != "owner-pubkey" || body.ClientPubkey != "client-pubkey" || len(body.Relays) != 1 || body.Relays[0] != "wss://relay.example" {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestSignerAuthorizeRequiresAdminAuth(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(config.Config{AdminAPIToken: "secret"}, nil, nil, st, nil)
	srv.SetSignerAuthorizer(&fakeSignerAuthorizer{enabled: true})
	req := httptest.NewRequest(http.MethodPost, "/signer/authorize", strings.NewReader(`{"bunker_uri":"bunker://owner"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without admin auth, got %d", w.Code)
	}
}

func TestSignerAuthorizeDisabled(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(config.Config{}, nil, nil, st, nil)
	req := httptest.NewRequest(http.MethodPost, "/signer/authorize", strings.NewReader(`{"bunker_uri":"bunker://owner"}`))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when signer is disabled, got %d", w.Code)
	}
}

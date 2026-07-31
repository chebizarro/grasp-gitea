// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// fakeTokenGitea mocks the Gitea endpoints the token service needs: user
// lookup/creation plus admin PAT lifecycle.
type fakeTokenGitea struct {
	mu           sync.Mutex
	users        map[string]gitea.User
	nextUserID   int64
	nextTokenID  int64
	tokenCreates int
	lastScopes   []string
	lastBasic    bool
	issuedPATs   map[int64]string // token id -> plaintext
	deletedPATs  []string
	failCreate   bool
}

func newFakeTokenGitea() *fakeTokenGitea {
	return &fakeTokenGitea{
		users:       make(map[string]gitea.User),
		nextUserID:  100,
		nextTokenID: 9000,
		issuedPATs:  make(map[int64]string),
	}
}

func (f *fakeTokenGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := r.URL.Path
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/tokens"):
		_, _, f.lastBasic = r.BasicAuth()
		if f.failCreate {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.tokenCreates++
		f.lastScopes = req.Scopes
		id := f.nextTokenID
		f.nextTokenID++
		plaintext := fmt.Sprintf("fakepat-%d", id)
		f.issuedPATs[id] = plaintext
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "name": req.Name, "sha1": plaintext,
			"token_last_eight": plaintext[len(plaintext)-8:], "scopes": req.Scopes,
		})
	case r.Method == http.MethodDelete && strings.Contains(path, "/tokens/"):
		f.deletedPATs = append(f.deletedPATs, path)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/users/"):
		login := strings.TrimPrefix(path, "/api/v1/users/")
		user, ok := f.users[login]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(user)
	case r.Method == http.MethodPost && path == "/api/v1/admin/users":
		var req struct {
			Login string `json:"login"`
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		user := gitea.User{ID: f.nextUserID, Login: req.Login, Email: req.Email}
		f.nextUserID++
		f.users[req.Login] = user
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(user)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type tokenTestEnv struct {
	svc   *TokenService
	store *store.SQLiteStore
	fake  *fakeTokenGitea
	keys  []config.CredentialKey
}

func newTokenTestEnv(t *testing.T) *tokenTestEnv {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/tokens.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	fake := newFakeTokenGitea()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	gc := gitea.NewClient(srv.URL, "admin-token").WithAdminUser("grasp-admin")
	identitySvc := NewIdentityService(st, gc, &stubOrgResolver{names: map[string]string{}}, logger)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	cfg := config.Config{
		BridgeTokensEnabled: true,
		CredentialKeys:      []config.CredentialKey{{ID: "test", Key: key}},
		TokenTTLDefault:     30 * 24 * time.Hour,
		TokenTTLMin:         time.Hour,
		TokenTTLMax:         90 * 24 * time.Hour,
		AuthAuditRetention:  90 * 24 * time.Hour,
	}
	svc, err := NewTokenService(cfg, st, identitySvc, gc, logger)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	if !svc.Enabled() {
		t.Fatal("token service disabled")
	}
	return &tokenTestEnv{svc: svc, store: st, fake: fake, keys: cfg.CredentialKeys}
}

func TestMintProvisionsIdentityAndPATOnce(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	first, err := env.svc.Mint(ctx, testPubkey, "event-1", MintRequest{Name: "laptop", Scopes: []string{ScopeGitRead, ScopeGitWrite}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !ValidBridgeTokenFormat(first.Token) {
		t.Fatalf("minted token %q fails format validation", first.Token)
	}
	if len(first.Scopes) != 2 {
		t.Fatalf("scopes = %v", first.Scopes)
	}

	second, err := env.svc.Mint(ctx, testPubkey, "event-2", MintRequest{Name: "ci"})
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if second.Scopes[0] != ScopeGitRead || len(second.Scopes) != 1 {
		t.Fatalf("default scopes = %v, want [git:read]", second.Scopes)
	}

	env.fake.mu.Lock()
	creates, basic, scopes := env.fake.tokenCreates, env.fake.lastBasic, env.fake.lastScopes
	env.fake.mu.Unlock()
	if creates != 1 {
		t.Fatalf("gitea PAT creates = %d, want 1 (one hidden PAT per user)", creates)
	}
	if !basic {
		t.Fatal("PAT creation did not use Basic auth")
	}
	if len(scopes) != 1 || scopes[0] != "write:repository" {
		t.Fatalf("PAT scopes = %v, want [write:repository]", scopes)
	}

	// Both tokens authenticate to the same subject.
	p1, err := env.svc.Authenticate(ctx, first.Token)
	if err != nil {
		t.Fatalf("authenticate first: %v", err)
	}
	p2, err := env.svc.Authenticate(ctx, second.Token)
	if err != nil {
		t.Fatalf("authenticate second: %v", err)
	}
	if p1.GiteaUserID != p2.GiteaUserID || p1.Pubkey != testPubkey {
		t.Fatalf("principals = %+v / %+v", p1, p2)
	}
	if !p1.HasScope(ScopeGitWrite) || p2.HasScope(ScopeGitWrite) {
		t.Fatalf("scope propagation broken: %+v / %+v", p1.Scopes, p2.Scopes)
	}

	// The hidden PAT decrypts to exactly what Gitea issued.
	login, pat, err := env.svc.DownstreamPAT(ctx, p1.GiteaUserID)
	if err != nil {
		t.Fatalf("DownstreamPAT: %v", err)
	}
	env.fake.mu.Lock()
	issued := env.fake.issuedPATs[9000]
	env.fake.mu.Unlock()
	if pat != issued {
		t.Fatalf("decrypted PAT = %q, want %q", pat, issued)
	}
	if login == "" {
		t.Fatal("missing gitea login")
	}
}

func TestAuthenticateRejectsUnusableTokens(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	for _, bad := range []string{
		"",
		"grasp_v1_short",
		"wrongprefix_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		BridgeTokenPrefix + strings.Repeat("!", 43),
		BridgeTokenPrefix + strings.Repeat("A", 43), // valid shape, unknown
	} {
		if _, err := env.svc.Authenticate(ctx, bad); !errors.Is(err, ErrTokenUnauthorized) {
			t.Errorf("Authenticate(%q) error = %v, want ErrTokenUnauthorized", bad, err)
		}
	}

	minted, err := env.svc.Mint(ctx, testPubkey, "event-1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := env.svc.Revoke(ctx, testPubkey, minted.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := env.svc.Authenticate(ctx, minted.Token); !errors.Is(err, ErrTokenUnauthorized) {
		t.Fatalf("revoked token error = %v, want ErrTokenUnauthorized", err)
	}

	expiring, err := env.svc.Mint(ctx, testPubkey, "event-2", MintRequest{Name: "shortlived", TTLSeconds: 3600})
	if err != nil {
		t.Fatalf("mint expiring: %v", err)
	}
	env.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := env.svc.Authenticate(ctx, expiring.Token); !errors.Is(err, ErrTokenUnauthorized) {
		t.Fatalf("expired token error = %v, want ErrTokenUnauthorized", err)
	}
}

func TestMintValidation(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	cases := []MintRequest{
		{Name: ""},
		{Name: strings.Repeat("n", maxTokenNameLen+1)},
		{Name: "ok", Scopes: []string{"packages:read"}}, // not enabled in phase 1
		{Name: "ok", Scopes: []string{"bogus"}},
		{Name: "ok", TTLSeconds: 1},                  // below min
		{Name: "ok", TTLSeconds: 366 * 24 * 60 * 60}, // above max
	}
	for i, req := range cases {
		if _, err := env.svc.Mint(ctx, testPubkey, "ev", req); !errors.Is(err, ErrInvalidTokenRequest) {
			t.Errorf("case %d error = %v, want ErrInvalidTokenRequest", i, err)
		}
	}
}

func TestMintPATCreationFailureRecordsError(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()
	env.fake.mu.Lock()
	env.fake.failCreate = true
	env.fake.mu.Unlock()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev", MintRequest{Name: "laptop"}); !errors.Is(err, ErrPATProvisioning) {
		t.Fatalf("error = %v, want ErrPATProvisioning", err)
	}
	rows, err := env.store.ListPATCredentialsByState(ctx, store.PATStateError, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("error rows = %+v err=%v, want 1", rows, err)
	}

	// Recovery: a later mint succeeds with a fresh generation.
	env.fake.mu.Lock()
	env.fake.failCreate = false
	env.fake.mu.Unlock()
	minted, err := env.svc.Mint(ctx, testPubkey, "ev2", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("recovery mint: %v", err)
	}
	if _, err := env.svc.Authenticate(ctx, minted.Token); err != nil {
		t.Fatalf("authenticate after recovery: %v", err)
	}
}

func TestRotateReplacesToken(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	orig, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop", Scopes: []string{ScopeGitRead, ScopeGitWrite}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rotated, err := env.svc.Rotate(ctx, testPubkey, orig.ID, "ev2", MintRequest{Name: "laptop", Scopes: []string{ScopeGitRead}})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.ID == orig.ID || rotated.Token == orig.Token {
		t.Fatal("rotation did not produce a new token")
	}
	if _, err := env.svc.Authenticate(ctx, orig.Token); !errors.Is(err, ErrTokenUnauthorized) {
		t.Fatalf("old token after rotation error = %v, want ErrTokenUnauthorized", err)
	}
	principal, err := env.svc.Authenticate(ctx, rotated.Token)
	if err != nil {
		t.Fatalf("authenticate rotated: %v", err)
	}
	if principal.Pubkey != testPubkey || principal.HasScope(ScopeGitWrite) {
		t.Fatalf("rotated principal = %+v", principal)
	}

	// Rotating an unknown/foreign token 404s.
	if _, err := env.svc.Rotate(ctx, "someone-else", rotated.ID, "ev3", MintRequest{Name: "x"}); !errors.Is(err, store.ErrBridgeTokenNotFound) {
		t.Fatalf("foreign rotate error = %v, want ErrBridgeTokenNotFound", err)
	}
}

func TestMintRejectsRelinkedGiteaAccount(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	minted, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	principal, err := env.svc.Authenticate(ctx, minted.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// Simulate: the Gitea account was deleted and the same login recreated,
	// so the login now resolves to a different user ID.
	env.fake.mu.Lock()
	user := env.fake.users[principal.GiteaUser]
	user.ID += 500
	env.fake.users[principal.GiteaUser] = user
	env.fake.mu.Unlock()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev2", MintRequest{Name: "second"}); !errors.Is(err, ErrIdentityLinkRepair) {
		t.Fatalf("mint against relinked account error = %v, want ErrIdentityLinkRepair", err)
	}

	// Quarantine must orphan the PAT and revoke outstanding tokens.
	orphaned, err := env.store.ListPATCredentialsByState(ctx, store.PATStateOrphaned, 10)
	if err != nil || len(orphaned) != 1 {
		t.Fatalf("orphaned = %+v err=%v, want 1", orphaned, err)
	}
	if _, err := env.svc.Authenticate(ctx, minted.Token); !errors.Is(err, ErrTokenUnauthorized) {
		t.Fatalf("token after quarantine error = %v, want ErrTokenUnauthorized", err)
	}
}

func TestMintRejectsDeletedGiteaAccount(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	env.fake.mu.Lock()
	env.fake.users = map[string]gitea.User{}
	env.fake.mu.Unlock()

	if _, err := env.svc.Mint(ctx, testPubkey, "ev2", MintRequest{Name: "second"}); !errors.Is(err, ErrIdentityLinkRepair) {
		t.Fatalf("mint after user deletion error = %v, want ErrIdentityLinkRepair", err)
	}
}

func TestPrincipalPermitsOnlyLinkedUsernames(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	minted, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	principal, err := env.svc.Authenticate(ctx, minted.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.Npub == "" || !strings.HasPrefix(principal.Npub, "npub1") {
		t.Fatalf("Npub = %q, want canonical npub (PR 1C Basic username check needs it)", principal.Npub)
	}
	if principal.GiteaUser == "" {
		t.Fatal("GiteaUser is empty; proxy cannot validate Basic usernames")
	}
	if !principal.PermitsUsername(principal.Npub) || !principal.PermitsUsername(strings.ToUpper(principal.GiteaUser)) {
		t.Fatal("linked usernames rejected")
	}
	for _, bad := range []string{"", "someone-else", "npub1nonsense"} {
		if principal.PermitsUsername(bad) {
			t.Errorf("PermitsUsername(%q) = true", bad)
		}
	}
}

func TestRetireIdlePATsAfterGrace(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	minted, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	principal, err := env.svc.Authenticate(ctx, minted.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if err := env.svc.Revoke(ctx, testPubkey, minted.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Inside the grace period the PAT survives.
	env.svc.retireIdlePATs(ctx)
	if _, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID); err != nil {
		t.Fatalf("PAT retired inside grace period: %v", err)
	}

	// Past the grace period it is retired and deleted from Gitea.
	env.svc.now = func() time.Time { return time.Now().Add(patRetirementGrace + time.Hour) }
	env.svc.retireIdlePATs(ctx)
	if _, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("active PAT after grace = %v, want sql.ErrNoRows", err)
	}
	env.fake.mu.Lock()
	deleted := append([]string(nil), env.fake.deletedPATs...)
	env.fake.mu.Unlock()
	if len(deleted) != 1 || !strings.HasSuffix(deleted[0], "/tokens/9000") {
		t.Fatalf("deleted PATs = %v, want deletion by numeric id", deleted)
	}
	pending, err := env.store.ListPATCredentialsPendingDeletion(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after retirement = %+v err=%v", pending, err)
	}

	// A new mint provisions a fresh PAT generation.
	env.svc.now = time.Now
	if _, err := env.svc.Mint(ctx, testPubkey, "ev2", MintRequest{Name: "again"}); err != nil {
		t.Fatalf("mint after retirement: %v", err)
	}
	if _, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID); err != nil {
		t.Fatalf("no active PAT after re-mint: %v", err)
	}
}

func TestDownstreamPATResealsUnderActiveKey(t *testing.T) {
	env := newTokenTestEnv(t)
	ctx := context.Background()

	minted, err := env.svc.Mint(ctx, testPubkey, "ev1", MintRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	principal, err := env.svc.Authenticate(ctx, minted.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	before, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID)
	if err != nil {
		t.Fatalf("load credential: %v", err)
	}

	// Rotate the key ring: the old key stays decrypt-only.
	oldKey := env.keys[0]
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	cipher, err := NewCredentialCipher([]config.CredentialKey{{ID: "new", Key: newKey}, oldKey})
	if err != nil {
		t.Fatalf("rotated cipher: %v", err)
	}
	env.svc.cipher = cipher

	_, pat, err := env.svc.DownstreamPAT(ctx, principal.GiteaUserID)
	if err != nil {
		t.Fatalf("DownstreamPAT: %v", err)
	}
	env.fake.mu.Lock()
	issued := env.fake.issuedPATs[9000]
	env.fake.mu.Unlock()
	if pat != issued {
		t.Fatalf("decrypted PAT = %q, want %q", pat, issued)
	}

	after, err := env.store.GetActivePATCredential(ctx, principal.GiteaUserID)
	if err != nil {
		t.Fatalf("reload credential: %v", err)
	}
	if after.KeyID != "new" {
		t.Fatalf("key_id = %q, want new (lazy reseal must run)", after.KeyID)
	}
	if string(after.Ciphertext) == string(before.Ciphertext) {
		t.Fatal("ciphertext unchanged after reseal")
	}

	// The resealed row still decrypts, now under the active key alone.
	onlyNew, err := NewCredentialCipher([]config.CredentialKey{{ID: "new", Key: newKey}})
	if err != nil {
		t.Fatalf("new-only cipher: %v", err)
	}
	env.svc.cipher = onlyNew
	if _, pat, err = env.svc.DownstreamPAT(ctx, principal.GiteaUserID); err != nil {
		t.Fatalf("DownstreamPAT after key retirement: %v", err)
	}
	if pat != issued {
		t.Fatalf("post-rotation PAT = %q, want %q", pat, issued)
	}
}

func TestValidBridgeTokenFormat(t *testing.T) {
	good := BridgeTokenPrefix + strings.Repeat("a", 43)
	if !ValidBridgeTokenFormat(good) {
		t.Fatal("valid shape rejected")
	}
	for _, bad := range []string{
		"", BridgeTokenPrefix,
		BridgeTokenPrefix + strings.Repeat("a", 42),
		BridgeTokenPrefix + strings.Repeat("a", 44),
		"grasp_v2_" + strings.Repeat("a", 43),
		BridgeTokenPrefix + strings.Repeat("a", 42) + "=",
	} {
		if ValidBridgeTokenFormat(bad) {
			t.Errorf("ValidBridgeTokenFormat(%q) = true", bad)
		}
	}
	if !HasBridgeTokenPrefix(BridgeTokenPrefix+"junk") || HasBridgeTokenPrefix("token abc") {
		t.Fatal("HasBridgeTokenPrefix misclassifies")
	}
}

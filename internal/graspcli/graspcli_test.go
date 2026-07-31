// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gonostr "fiatjaf.com/nostr"
	"fiatjaf.com/nostr/keyer"
	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"
)

// fakeKeyring is an in-memory Keyring.
type fakeKeyring struct {
	data map[string]string
	fail bool
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{data: map[string]string{}} }

func (f *fakeKeyring) key(service, user string) string { return service + "\x00" + user }

func (f *fakeKeyring) Set(service, user, secret string) error {
	if f.fail {
		return errors.New("keyring unavailable")
	}
	f.data[f.key(service, user)] = secret
	return nil
}

func (f *fakeKeyring) Get(service, user string) (string, error) {
	if f.fail {
		return "", errors.New("keyring unavailable")
	}
	secret, ok := f.data[f.key(service, user)]
	if !ok {
		return "", errors.New("not found")
	}
	return secret, nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	delete(f.data, f.key(service, user))
	return nil
}

func testStore(t *testing.T, ring Keyring) *Store {
	t.Helper()
	st, err := NewStore(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if ring != nil {
		st.WithKeyring(ring)
	}
	return st
}

func testCred(token string) Credential {
	return Credential{
		Server: "https://git.example.com", Npub: "npub1owner",
		TokenID: "tok1", Name: "laptop",
		Scopes: []string{"git:read"}, Token: token,
	}
}

func TestStoreKeychainRoundtrip(t *testing.T) {
	ring := newFakeKeyring()
	st := testStore(t, ring)

	used, err := st.Put(testCred("grasp_v1_secret"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !used {
		t.Fatal("expected keychain to be used")
	}

	// The metadata file must not contain the secret.
	data, err := os.ReadFile(st.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if strings.Contains(string(data), "grasp_v1_secret") {
		t.Fatal("secret leaked into the metadata file despite keychain storage")
	}

	cred, found, err := st.Get("git.example.com")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if cred.Token != "grasp_v1_secret" {
		t.Fatalf("token = %q", cred.Token)
	}

	if err := st.Delete("git.example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(ring.data) != 0 {
		t.Fatal("keychain entry not removed on delete")
	}
	if _, found, _ := st.Get("git.example.com"); found {
		t.Fatal("credential still present after delete")
	}
}

func TestStoreFileFallbackIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are POSIX-only")
	}
	// Explicit opt-out (--no-keychain) is the sanctioned path to file storage.
	st := testStore(t, nil)

	used, err := st.Put(testCred("grasp_v1_secret"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if used {
		t.Fatal("keychain reported used while disabled")
	}
	info, err := os.Stat(st.path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials file mode = %o, want 600", perm)
	}
	cred, found, err := st.Get("git.example.com")
	if err != nil || !found || cred.Token != "grasp_v1_secret" {
		t.Fatalf("fallback get = (%q, %v, %v)", cred.Token, found, err)
	}
}

// TestStoreRefusesSilentDowngrade: a keychain that exists but fails must not
// silently demote the secret to file storage.
func TestStoreRefusesSilentDowngrade(t *testing.T) {
	ring := newFakeKeyring()
	ring.fail = true
	st := testStore(t, ring)
	if _, err := st.Put(testCred("grasp_v1_secret")); err == nil {
		t.Fatal("failing keychain silently fell back to file storage")
	}
	if _, found, _ := st.Get("git.example.com"); found {
		t.Fatal("credential stored despite keychain failure")
	}
}

func TestStoreReplacesPerHost(t *testing.T) {
	st := testStore(t, newFakeKeyring())
	if _, err := st.Put(testCred("first")); err != nil {
		t.Fatal(err)
	}
	second := testCred("second")
	second.TokenID = "tok2"
	if _, err := st.Put(second); err != nil {
		t.Fatal(err)
	}
	creds, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].TokenID != "tok2" {
		t.Fatalf("creds = %+v, want single tok2 entry", creds)
	}
}

func TestGitCredentialGet(t *testing.T) {
	st := testStore(t, newFakeKeyring())
	if _, err := st.Put(testCred("grasp_v1_secret")); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	input := "protocol=https\nhost=git.example.com\npath=owner/repo.git\n\n"
	if err := GitCredential("get", strings.NewReader(input), &out, st); err != nil {
		t.Fatalf("get: %v", err)
	}
	want := "username=npub1owner\npassword=grasp_v1_secret\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}

	// Unknown host: stay silent so git tries other helpers.
	out.Reset()
	if err := GitCredential("get", strings.NewReader("protocol=https\nhost=other.example.com\n\n"), &out, st); err != nil {
		t.Fatalf("get other: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("unexpected output for unknown host: %q", out.String())
	}

	// Explicit different username: not our credential.
	out.Reset()
	if err := GitCredential("get", strings.NewReader("protocol=https\nhost=git.example.com\nusername=alice\n\n"), &out, st); err != nil {
		t.Fatalf("get mismatched user: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("credential offered to mismatched username: %q", out.String())
	}

	// An https credential must never be disclosed over plaintext http.
	out.Reset()
	if err := GitCredential("get", strings.NewReader("protocol=http\nhost=git.example.com\n\n"), &out, st); err != nil {
		t.Fatalf("get http: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("https credential disclosed over http: %q", out.String())
	}

	// Non-http protocols are not ours.
	out.Reset()
	if err := GitCredential("get", strings.NewReader("protocol=ssh\nhost=git.example.com\n\n"), &out, st); err != nil {
		t.Fatalf("get ssh: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("credential offered for ssh: %q", out.String())
	}
}

func TestGitCredentialEraseOnlyMatching(t *testing.T) {
	st := testStore(t, newFakeKeyring())
	if _, err := st.Put(testCred("grasp_v1_secret")); err != nil {
		t.Fatal(err)
	}

	// A failure with a DIFFERENT credential must not destroy ours.
	input := "protocol=https\nhost=git.example.com\nusername=npub1owner\npassword=other-secret\n\n"
	if err := GitCredential("erase", strings.NewReader(input), &strings.Builder{}, st); err != nil {
		t.Fatalf("erase mismatch: %v", err)
	}
	if _, found, _ := st.Get("git.example.com"); !found {
		t.Fatal("credential erased on password mismatch")
	}

	// A failure with OUR credential erases it.
	input = "protocol=https\nhost=git.example.com\nusername=npub1owner\npassword=grasp_v1_secret\n\n"
	if err := GitCredential("erase", strings.NewReader(input), &strings.Builder{}, st); err != nil {
		t.Fatalf("erase match: %v", err)
	}
	if _, found, _ := st.Get("git.example.com"); found {
		t.Fatal("credential not erased for matching password")
	}

	// store is a no-op and must not error.
	if err := GitCredential("store", strings.NewReader("host=x\n\n"), &strings.Builder{}, st); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := GitCredential("bogus", strings.NewReader(""), &strings.Builder{}, st); err == nil {
		t.Fatal("unknown op accepted")
	}
}

// TestClientMintSignsVerifiableNIP98 drives the real client against a server
// that verifies the proof with the same shared verifier the bridge uses:
// binding to method, exact URL, and body payload, single-use enforced.
func TestClientMintSignsVerifiableNIP98(t *testing.T) {
	signer := keyer.NewPlainKeySigner(gonostr.Generate())
	verifier := sharednip98.NewVerifier(5 * time.Minute)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := verifier.Verify(r)
		if err != nil {
			t.Errorf("NIP-98 verify failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if principal.PubKey == "" {
			t.Error("empty principal pubkey")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/token":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(TokenMint{
				ID: "tok1", Token: "grasp_v1_secret", Name: "laptop",
				Scopes: []string{"git:read"}, ExpiresAt: time.Now().Add(time.Hour),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/tokens":
			fmt.Fprint(w, `{"tokens":[{"id":"tok1","name":"laptop","state":"active"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/auth/tokens/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, signer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	minted, err := client.Mint(ctx, MintRequest{Name: "laptop", Scopes: []string{"git:read"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if minted.Token != "grasp_v1_secret" || minted.ID != "tok1" {
		t.Fatalf("minted = %+v", minted)
	}

	tokens, err := client.List(ctx)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("list = %v, %v", tokens, err)
	}
	if err := client.Revoke(ctx, "tok1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestClientSurfacesAPIErrors(t *testing.T) {
	signer := keyer.NewPlainKeySigner(gonostr.Generate())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"active token limit reached"}`)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Mint(context.Background(), MintRequest{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "active token limit reached") {
		t.Fatalf("error = %v, want the bridge message", err)
	}
}

// TestClientRefusesRedirects: NIP-98 proofs are URL-bound, so a redirecting
// --server is a configuration error, never something to follow.
func TestClientRefusesRedirects(t *testing.T) {
	signer := keyer.NewPlainKeySigner(gonostr.Generate())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/auth/token", http.StatusMovedPermanently)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Mint(context.Background(), MintRequest{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "canonical public URL") {
		t.Fatalf("error = %v, want redirect refusal", err)
	}
}

func TestClientRejectsDirtyServerURL(t *testing.T) {
	signer := keyer.NewPlainKeySigner(gonostr.Generate())
	for _, bad := range []string{
		"https://user:pass@git.example.com",
		"https://git.example.com/?x=1",
		"https://git.example.com/#frag",
		"ftp://git.example.com",
	} {
		if _, err := NewClient(bad, signer); err == nil {
			t.Errorf("NewClient accepted %q", bad)
		}
	}
}

func TestSetupSnippetsHideTokenByDefault(t *testing.T) {
	cred := testCred("")
	for _, kind := range []string{"npm", "pypi", "cargo", "docker", "nuget"} {
		var out strings.Builder
		if err := SetupSnippet(kind, cred, "myorg", false, &out); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		text := out.String()
		if strings.Contains(text, "grasp_v1_") {
			t.Fatalf("%s snippet leaked a token:\n%s", kind, text)
		}
		if !strings.Contains(text, "git.example.com") {
			t.Fatalf("%s snippet missing host:\n%s", kind, text)
		}
		if kind != "docker" && !strings.Contains(text, "myorg") {
			t.Fatalf("%s snippet missing owner:\n%s", kind, text)
		}
	}
	if err := SetupSnippet("bogus", cred, "", false, &strings.Builder{}); err == nil {
		t.Fatal("unknown setup target accepted")
	}
}

func TestSignerFileRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are POSIX-only")
	}
	path := filepath.Join(t.TempDir(), "signer")
	if err := os.WriteFile(path, []byte("nsec1whatever\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := signerInput(path, &strings.Builder{}); err == nil {
		t.Fatal("world-readable signer file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := signerInput(path, &strings.Builder{})
	if err != nil || input != "nsec1whatever" {
		t.Fatalf("signer input = (%q, %v)", input, err)
	}
}

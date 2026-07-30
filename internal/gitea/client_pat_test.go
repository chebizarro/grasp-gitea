// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package gitea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateUserAccessTokenUsesAdminBasicAuth(t *testing.T) {
	var gotAuthHeader string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/users/npub1alice/tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "grasp-admin" || pass != "admin-secret" {
			t.Errorf("basic auth = %q/%q ok=%v; PAT admin endpoints require Basic (reqBasicOrRevProxyAuth)", user, pass, ok)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":               42,
			"name":             "grasp-bridge-11-1",
			"sha1":             "plaintextpat",
			"token_last_eight": "textpat0",
			"scopes":           []string{"write:repository"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "admin-secret").WithAdminUser("grasp-admin")
	if !c.PATAdministrationEnabled() {
		t.Fatal("PATAdministrationEnabled = false")
	}
	tok, err := c.CreateUserAccessToken(context.Background(), "npub1alice", "grasp-bridge-11-1", []string{"write:repository"})
	if err != nil {
		t.Fatalf("CreateUserAccessToken: %v", err)
	}
	if tok.ID != 42 || tok.Token != "plaintextpat" || tok.Name != "grasp-bridge-11-1" {
		t.Fatalf("token = %+v", tok)
	}
	if gotBody["name"] != "grasp-bridge-11-1" {
		t.Fatalf("body name = %v", gotBody["name"])
	}
	if scopes, ok := gotBody["scopes"].([]any); !ok || len(scopes) != 1 {
		t.Fatalf("body scopes = %v", gotBody["scopes"])
	}
	if gotAuthHeader == "token admin-secret" {
		t.Fatal("token header used; endpoint requires Basic auth")
	}
}

func TestCreateUserAccessTokenRequiresConfigAndScopes(t *testing.T) {
	c := NewClient("http://gitea.invalid", "tok")
	if _, err := c.CreateUserAccessToken(context.Background(), "u", "n", []string{"write:repository"}); err == nil {
		t.Fatal("missing admin user accepted")
	}
	c = c.WithAdminUser("admin")
	if _, err := c.CreateUserAccessToken(context.Background(), "u", "n", nil); err == nil {
		t.Fatal("empty scopes accepted; Gitea rejects tokens without scope")
	}
}

func TestCreateUserAccessTokenRejectsMissingPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "name": "n"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok").WithAdminUser("admin")
	if _, err := c.CreateUserAccessToken(context.Background(), "u", "n", []string{"write:repository"}); err == nil {
		t.Fatal("response without plaintext accepted")
	}
}

func TestDeleteUserAccessToken(t *testing.T) {
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/users/npub1alice/tokens/42" {
			if _, _, ok := r.BasicAuth(); !ok {
				t.Error("delete must use Basic auth")
			}
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok").WithAdminUser("admin")
	if err := c.DeleteUserAccessToken(context.Background(), "npub1alice", "42"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleted {
		t.Fatal("delete request not observed")
	}

	// Missing tokens surface as 404 so callers can treat them as cleaned up.
	err := c.DeleteUserAccessToken(context.Background(), "npub1alice", "43")
	if err == nil || !IsNotFound(err) {
		t.Fatalf("missing token error = %v, want IsNotFound", err)
	}

	if err := c.DeleteUserAccessToken(context.Background(), "npub1alice", " "); err == nil {
		t.Fatal("blank token ref accepted")
	}
	if err := NewClient(srv.URL, "tok").DeleteUserAccessToken(context.Background(), "u", "42"); err == nil {
		t.Fatal("missing admin user accepted")
	}
}

func TestParseRepoDecodesPrivate(t *testing.T) {
	repo, err := parseRepo([]byte(`{"id":9,"name":"secret","private":true,"owner":{"username":"org"}}`))
	if err != nil {
		t.Fatalf("parseRepo: %v", err)
	}
	if !repo.Private {
		t.Fatal("Private not decoded; anonymous npub proxying would expose private repos")
	}
	repo, err = parseRepo([]byte(`{"id":10,"name":"open","owner":{"username":"org"}}`))
	if err != nil {
		t.Fatalf("parseRepo public: %v", err)
	}
	if repo.Private {
		t.Fatal("public repo decoded as private")
	}
}

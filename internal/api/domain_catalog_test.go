// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type catalogRepoInspector struct {
	repos map[string]gitea.Repository
	calls int
}

func (s *catalogRepoInspector) GetRepo(_ context.Context, org, repo string) (gitea.Repository, error) {
	s.calls++
	result, ok := s.repos[org+"/"+repo]
	if !ok {
		return gitea.Repository{}, errors.New("not found")
	}
	return result, nil
}

func TestDomainCatalogListsOnlyExactHostVerifiedPublicRepositories(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/catalog.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	for _, affiliation := range []store.DomainAffiliation{
		{CanonicalIdentifier: "alice@team.example.com", LocalPart: "alice", Host: "team.example.com", Pubkey: "pub-team", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified},
		{CanonicalIdentifier: "bob@example.com", LocalPart: "bob", Host: "example.com", Pubkey: "pub-parent", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified},
		{CanonicalIdentifier: "stale@team.example.com", LocalPart: "stale", Host: "team.example.com", Pubkey: "pub-stale", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationStale, FailureClass: store.DomainFailureIndeterminate},
		{CanonicalIdentifier: "private@team.example.com", LocalPart: "private", Host: "team.example.com", Pubkey: "pub-private", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified},
		{CanonicalIdentifier: "missing@team.example.com", LocalPart: "missing", Host: "team.example.com", Pubkey: "pub-missing", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified},
		{CanonicalIdentifier: "expired@team.example.com", LocalPart: "expired", Host: "team.example.com", Pubkey: "pub-expired", VerifiedAt: now.Add(-25 * time.Hour), CheckedAt: now.Add(-25 * time.Hour), Status: store.DomainAffiliationVerified},
		{CanonicalIdentifier: "recreated@team.example.com", LocalPart: "recreated", Host: "team.example.com", Pubkey: "pub-recreated", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified},
	} {
		if err := st.UpsertDomainAffiliation(t.Context(), affiliation); err != nil {
			t.Fatal(err)
		}
	}
	for _, mapping := range []store.Mapping{
		{Npub: "npub1team", RepoID: "repo/one", Pubkey: "pub-team", Owner: "unchanged-owner", RepoName: "unchanged-repo", GiteaRepoID: 1, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1parent", RepoID: "parent", Pubkey: "pub-parent", Owner: "parent-owner", RepoName: "parent-repo", GiteaRepoID: 2, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1stale", RepoID: "stale", Pubkey: "pub-stale", Owner: "stale-owner", RepoName: "stale-repo", GiteaRepoID: 3, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1private", RepoID: "private", Pubkey: "pub-private", Owner: "private-owner", RepoName: "private-repo", GiteaRepoID: 4, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1missing", RepoID: "missing", Pubkey: "pub-missing", Owner: "missing-owner", RepoName: "missing-repo", GiteaRepoID: 5, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1expired", RepoID: "expired", Pubkey: "pub-expired", Owner: "expired-owner", RepoName: "expired-repo", GiteaRepoID: 6, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
		{Npub: "npub1recreated", RepoID: "recreated", Pubkey: "pub-recreated", Owner: "recreated-owner", RepoName: "recreated-repo", GiteaRepoID: 7, CloneURL: "internal", SourceEvent: "event", HookInstalled: true},
	} {
		if err := st.UpsertMapping(t.Context(), mapping); err != nil {
			t.Fatal(err)
		}
	}

	inspector := &catalogRepoInspector{repos: map[string]gitea.Repository{
		"unchanged-owner/unchanged-repo": {ID: 1},
		"private-owner/private-repo":     {ID: 4, Private: true},
		"expired-owner/expired-repo":     {ID: 6},
		"recreated-owner/recreated-repo": {ID: 8},
	}}
	srv := New(config.Config{}, nil, nil, st, nil)
	srv.SetRepositoryInspector(inspector)
	handler := srv.Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/domains/TEAM.EXAMPLE.COM/repositories", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"host":"team.example.com"`) || !strings.Contains(body, `"url":"/npub1team/repo%2Fone.git"`) {
		t.Fatalf("catalog missing canonical host/url: %s", body)
	}
	if strings.Contains(body, "npub1parent") || strings.Contains(body, "npub1stale") || strings.Contains(body, "npub1private") || strings.Contains(body, "npub1missing") || strings.Contains(body, "npub1expired") || strings.Contains(body, "npub1recreated") || strings.Contains(body, "unchanged-owner") {
		t.Fatalf("catalog crossed host/freshness/visibility boundary or exposed placement: %s", body)
	}

	callsBefore := inspector.calls
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/domains/bogus.example/repositories", nil))
	if w.Code != http.StatusOK || inspector.calls != callsBefore || !strings.Contains(w.Body.String(), `"repositories":[]`) {
		t.Fatalf("empty host lookup did not return early: status=%d calls=%d body=%s", w.Code, inspector.calls-callsBefore, w.Body.String())
	}
}

func TestVerifiedBadgeReflectsFreshAndStaleState(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/badge.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	a := store.DomainAffiliation{CanonicalIdentifier: "alice@example.com", LocalPart: "alice", Host: "example.com", Pubkey: "abc123", VerifiedAt: now, CheckedAt: now, Status: store.DomainAffiliationVerified, FailureDetail: "wss://private-relay.example: TLS handshake timeout"}
	if err := st.UpsertDomainAffiliation(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	handler := New(config.Config{}, nil, nil, st, nil).Handler()

	request := func() map[string]any {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verified-badges/ABC123", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	fresh := request()
	if verified, _ := fresh["verified"].(bool); !verified {
		t.Fatal("fresh affiliation did not receive badge")
	}
	encoded, _ := json.Marshal(fresh)
	if strings.Contains(string(encoded), "failure_detail") || strings.Contains(string(encoded), "private-relay") || strings.Contains(string(encoded), "failure_class") {
		t.Fatalf("badge exposed internal affiliation diagnostics: %s", encoded)
	}
	a.Status = store.DomainAffiliationStale
	a.CheckedAt = now.Add(time.Minute)
	a.FailureClass = store.DomainFailureIndeterminate
	a.FailureCode = "transport"
	if err := st.UpsertDomainAffiliation(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if verified, _ := request()["verified"].(bool); verified {
		t.Fatal("stale affiliation retained verified badge")
	}

	expired := a
	expired.Pubkey = "expired"
	expired.Status = store.DomainAffiliationVerified
	expired.CheckedAt = now.Add(-25 * time.Hour)
	if err := st.UpsertDomainAffiliation(t.Context(), expired); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verified-badges/expired", nil))
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if verified, _ := payload["verified"].(bool); verified {
		t.Fatal("expired persisted verification retained verified badge")
	}
	affiliation, _ := payload["affiliation"].(map[string]any)
	if affiliation["status"] != store.DomainAffiliationStale {
		t.Fatalf("expired verification status = %v, want stale", affiliation["status"])
	}
}

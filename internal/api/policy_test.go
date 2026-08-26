package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/policy"
)

func TestPolicyAdminGetPutRequiresAuthAndHotApplies(t *testing.T) {
	policies, err := policy.Open(filepath.Join(t.TempDir(), "config.json"), config.Config{
		RelayURLs: []string{"wss://relay.example"}, HookRelayURL: "wss://hook.example",
		ProfileSyncInterval: 10 * time.Minute, ProfileSyncWorkers: 4, HiveCIJobTimeoutMinutes: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.Config{AdminAPIToken: "admin-token"}, nil, nil, nil, testLogger())
	srv.SetPolicyStore(policies)
	h := srv.Handler()

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/admin/policy/ci", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	req := httptest.NewRequest(http.MethodPut, "/admin/policy/ci", strings.NewReader(`{"enabled":true,"trigger_repos":["owner/repo"]}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT status = %d body=%s", resp.Code, resp.Body.String())
	}
	got := policies.Current()
	if !got.CIEnabled || len(got.CITriggerRepos) != 1 || got.CITriggerRepos[0] != "owner/repo" {
		t.Fatalf("policy not hot-applied: %#v", got)
	}

	get := httptest.NewRequest(http.MethodGet, "/admin/policy/ci", nil)
	get.Header.Set("Authorization", "Bearer admin-token")
	getResp := httptest.NewRecorder()
	h.ServeHTTP(getResp, get)
	if getResp.Code != http.StatusOK || !strings.Contains(getResp.Body.String(), "owner/repo") {
		t.Fatalf("GET response = %d %s", getResp.Code, getResp.Body.String())
	}
}

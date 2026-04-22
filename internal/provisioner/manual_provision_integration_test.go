package provisioner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"log/slog"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestManualProvisionInstallsHookSelfContained(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	reposDir := filepath.Join(tempDir, "git", "repositories")
	if err := os.MkdirAll(reposDir, 0o755); err != nil {
		t.Fatalf("mkdir repos: %v", err)
	}

	type repoRecord struct {
		ID   int64
		Name string
		Org  string
	}
	var (
		mu     sync.Mutex
		orgs         = map[string]bool{}
		repos        = map[string]repoRecord{}
		nextID int64 = 1
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/orgs/"):
			org := strings.TrimPrefix(path, "/api/v1/orgs/")
			if !orgs[org] {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"username": org})
		case r.Method == http.MethodPost && path == "/api/v1/orgs":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			org, _ := body["username"].(string)
			orgs[org] = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"username": org})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/repos/"):
			parts := strings.Split(strings.TrimPrefix(path, "/api/v1/repos/"), "/")
			if len(parts) != 2 {
				http.NotFound(w, r)
				return
			}
			key := parts[0] + "/" + parts[1]
			repo, ok := repos[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   repo.ID,
				"name": repo.Name,
				"owner": map[string]any{
					"username": repo.Org,
				},
			})
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/orgs/") && strings.HasSuffix(path, "/repos"):
			org := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/orgs/"), "/repos")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			name, _ := body["name"].(string)
			key := org + "/" + name
			repos[key] = repoRecord{ID: nextID, Name: name, Org: org}
			nextID++
			repoPath := filepath.Join(reposDir, org, name+".git", "hooks")
			_ = os.MkdirAll(repoPath, 0o755)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":   repos[key].ID,
				"name": name,
				"owner": map[string]any{
					"username": org,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	st, err := store.Open(filepath.Join(tempDir, "mappings.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	cfg := config.Config{
		ClonePrefix: "https://git.sharegap.net",
	}
	giteaClient := gitea.NewClient(srv.URL, "test-token")
	hookInstaller := hooks.NewInstaller(reposDir, "/usr/local/bin/grasp-pre-receive", "ws://localhost:3334")
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	nip05Resolver := nip05resolve.NewResolver(5 * time.Minute)
	svc := New(cfg, st, giteaClient, hookInstaller, nip05Resolver, logger)

	result, err := svc.ManualProvision(ctx, "npub-test-owner", "owner-pubkey-hex", "repo1")
	if err != nil {
		t.Fatalf("manual provision failed: %v", err)
	}

	// orgName is the NIP-05 local-part or hex fallback (since no relay in test, falls back to pubkey prefix).
	orgName := result.Owner
	if orgName == "" {
		orgName = "owner-pubkey-hex" // test fallback: pubkey is short enough to use as-is
	}

	hookPath := filepath.Join(reposDir, orgName, "repo1.git", "hooks", "pre-receive")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("expected hook file at %s: %v", hookPath, err)
	}
	if !strings.Contains(string(content), "GRASP_REPO_ID='repo1'") {
		t.Fatalf("hook content missing repo id env: %s", string(content))
	}
	// The hook script must still use the full npub for state lookups.
	if !strings.Contains(string(content), "GRASP_REPO_NPUB='npub-test-owner'") {
		t.Fatalf("hook content missing npub env: %s", string(content))
	}
}

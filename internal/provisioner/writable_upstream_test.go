package provisioner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type upstreamTestGitea struct {
	mu                                          sync.Mutex
	reposDir                                    string
	targetExists, targetPrivate, targetArchived bool
	targetRef                                   string
	targetDescription                           string
}

func newWritableUpstreamService(t *testing.T) (*Service, *store.SQLiteStore, *upstreamTestGitea, store.Mapping) {
	t.Helper()
	root := t.TempDir()
	state := &upstreamTestGitea{reposDir: filepath.Join(root, "repositories"), targetRef: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	initBareTestRepo(t, filepath.Join(state.reposDir, "cascadia", "bahia.git"))
	server := httptest.NewServer(http.HandlerFunc(state.serveHTTP))
	t.Cleanup(server.Close)
	st, err := store.Open(filepath.Join(root, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mapping := store.Mapping{Npub: "npub1owner", RepoID: "bahia", Pubkey: strings.Repeat("a", 64), Owner: "cascadia", RepoName: "bahia", GiteaRepoID: 21, CloneURL: server.URL + "/cascadia/bahia.git", SourceEvent: "owner-announcement", HookInstalled: true}
	if err := st.UpsertMapping(context.Background(), mapping); err != nil {
		t.Fatal(err)
	}
	client := gitea.NewClient(server.URL, "admin-token")
	installer := hooks.NewInstaller(state.reposDir, "/usr/local/bin/grasp-pre-receive", "wss://relay.example")
	svc := New(config.Config{ClonePrefix: server.URL, HookRelayURL: "wss://relay.example"}, st, st, nil, client, installer, nil, slog.New(slog.DiscardHandler))
	return svc, st, state, mapping
}

func (s *upstreamTestGitea) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path
	if r.Method == http.MethodPost && path == "/api/v1/repos/migrate" {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["mirror"] != false || body["private"] != true || body["repo_name"] != "bahia-grasp-upstream" {
			http.Error(w, "bad migrate request", 400)
			return
		}
		s.targetExists, s.targetPrivate = true, true
		s.targetDescription, _ = body["description"].(string)
		targetPath := filepath.Join(s.reposDir, "cascadia", "bahia-grasp-upstream.git")
		_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
		_ = exec.Command("git", "init", "--bare", targetPath).Run()
		s.writeRepo(w, 57, "bahia-grasp-upstream", false)
		return
	}
	if strings.HasSuffix(path, "/git/refs") && r.Method == http.MethodGet {
		sha := strings.Repeat("a", 40)
		if strings.Contains(path, "bahia-grasp-upstream") {
			sha = s.targetRef
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"ref": "refs/heads/master", "object": map[string]string{"sha": sha}}})
		return
	}
	if strings.HasPrefix(path, "/api/v1/repos/cascadia/") {
		name := strings.TrimPrefix(path, "/api/v1/repos/cascadia/")
		if strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			if name == "bahia" {
				s.writeRepo(w, 21, name, true)
				return
			}
			if name == "bahia-grasp-upstream" && s.targetExists {
				s.writeRepo(w, 57, name, false)
				return
			}
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPatch && name == "bahia-grasp-upstream" && s.targetExists {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["private"].(bool); ok {
				s.targetPrivate = v
			}
			if v, ok := body["archived"].(bool); ok {
				s.targetArchived = v
			}
			s.writeRepo(w, 57, name, false)
			return
		}
	}
	http.NotFound(w, r)
}

func initBareTestRepo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", path).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
}

func (s *upstreamTestGitea) writeRepo(w http.ResponseWriter, id int64, name string, mirror bool) {
	private, archived := false, false
	if id == 57 {
		private, archived = s.targetPrivate, s.targetArchived
	}
	description := ""
	if id == 57 {
		description = s.targetDescription
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": name, "clone_url": "https://git.example/cascadia/" + name + ".git", "private": private, "archived": archived, "mirror": mirror, "description": description, "owner": map[string]string{"username": "cascadia"}})
}

func TestMigrateWritableUpstreamSuccessReplayAndRollback(t *testing.T) {
	svc, st, state, original := newWritableUpstreamService(t)
	got, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream")
	if err != nil {
		t.Fatal(err)
	}
	if got.GiteaRepoID != 57 || got.RepoName != "bahia-grasp-upstream" {
		t.Fatalf("mapping=%+v", got)
	}
	state.mu.Lock()
	private, archived := state.targetPrivate, state.targetArchived
	state.mu.Unlock()
	if private || archived {
		t.Fatalf("activated target private=%v archived=%v", private, archived)
	}
	if _, err = svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream"); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	got, err = svc.RollbackWritableUpstream(t.Context(), original.Npub, original.RepoID, 57)
	if err != nil {
		t.Fatal(err)
	}
	if got.GiteaRepoID != 21 || got.RepoName != "bahia" {
		t.Fatalf("rollback mapping=%+v", got)
	}
	journal, err := st.GetWritableUpstreamMigration(t.Context(), original.Npub, original.RepoID)
	if err != nil || journal.Active {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	if _, err := svc.RollbackWritableUpstream(t.Context(), original.Npub, original.RepoID, 57); err != nil {
		t.Fatalf("idempotent rollback cleanup: %v", err)
	}
}

func TestMigrateWritableUpstreamRejectsRefDivergence(t *testing.T) {
	svc, st, state, original := newWritableUpstreamService(t)
	state.targetRef = strings.Repeat("b", 40)
	_, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream")
	if !errors.Is(err, ErrWritableUpstreamPreflight) {
		t.Fatalf("error=%v", err)
	}
	got, getErr := st.GetMapping(t.Context(), original.Npub, original.RepoID)
	if getErr != nil || got.GiteaRepoID != 21 {
		t.Fatalf("mapping=%+v err=%v", got, getErr)
	}
}

func TestMigrateWritableUpstreamResumesAfterPreActivationCrash(t *testing.T) {
	svc, _, state, original := newWritableUpstreamService(t)
	crash := errors.New("simulated crash")
	svc.migrationStepHook = func(step string) error {
		if step == "writable_target_created" {
			return crash
		}
		return nil
	}
	if _, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream"); !errors.Is(err, crash) {
		t.Fatalf("error=%v", err)
	}
	state.mu.Lock()
	exists, private, archived := state.targetExists, state.targetPrivate, state.targetArchived
	state.mu.Unlock()
	if !exists || !private || !archived {
		t.Fatalf("crash target exists=%v private=%v archived=%v", exists, private, archived)
	}
	svc.migrationStepHook = nil
	if _, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream"); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateWritableUpstreamRejectsPreparedTargetWithWrongMarker(t *testing.T) {
	svc, st, state, original := newWritableUpstreamService(t)
	current, err := st.GetMapping(t.Context(), original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PrepareWritableUpstream(t.Context(), store.WritableUpstreamMigration{
		Npub: current.Npub, RepoID: current.RepoID,
		OldOwner: current.Owner, OldRepoName: current.RepoName, OldGiteaRepoID: current.GiteaRepoID, OldCloneURL: current.CloneURL,
		NewOwner: current.Owner, NewRepoName: "bahia-grasp-upstream", TargetMarker: "expected-marker", ExpectedMappingUpdatedAt: current.UpdatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.targetExists, state.targetPrivate, state.targetArchived = true, true, true
	state.targetDescription = "unrelated-repository"
	state.mu.Unlock()
	initBareTestRepo(t, filepath.Join(state.reposDir, "cascadia", "bahia-grasp-upstream.git"))
	_, err = svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream")
	if !errors.Is(err, ErrWritableUpstreamPreflight) || !strings.Contains(err.Error(), "identity or repository mode mismatch") {
		t.Fatalf("error=%v", err)
	}
}

func TestMigrateWritableUpstreamRejectsWrongMappingRevision(t *testing.T) {
	svc, _, _, original := newWritableUpstreamService(t)
	_, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 999, "bahia-grasp-upstream")
	if !errors.Is(err, ErrWritableUpstreamPreflight) {
		t.Fatalf("error=%v", err)
	}
}

func TestMigrateWritableUpstreamRefusesUnjournaledExistingTarget(t *testing.T) {
	svc, st, state, original := newWritableUpstreamService(t)
	state.mu.Lock()
	state.targetExists, state.targetPrivate, state.targetArchived = true, false, false
	state.mu.Unlock()
	initBareTestRepo(t, filepath.Join(state.reposDir, "cascadia", "bahia-grasp-upstream.git"))
	_, err := svc.MigrateWritableUpstream(t.Context(), original.Npub, original.RepoID, 21, "bahia-grasp-upstream")
	if !errors.Is(err, ErrWritableUpstreamPreflight) || !strings.Contains(err.Error(), "without a matching preparation") {
		t.Fatalf("error=%v", err)
	}
	if _, getErr := st.GetWritableUpstreamMigration(t.Context(), original.Npub, original.RepoID); !errors.Is(getErr, sql.ErrNoRows) {
		t.Fatalf("unexpected preparation record: %v", getErr)
	}
}

package repoownership

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type testMappings []store.Mapping

func (m testMappings) ListMappings(context.Context) ([]store.Mapping, error) {
	return append([]store.Mapping(nil), m...), nil
}

func initBareRepo(t *testing.T) (string, store.Mapping, string) {
	t.Helper()
	root := t.TempDir()
	mapping := store.Mapping{Pubkey: strings.Repeat("a", 64), RepoID: "project", Owner: "org", RepoName: "hosted"}
	repoPath := filepath.Join(root, "org", "hosted.git")
	if out, err := exec.Command("git", "init", "--bare", repoPath).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	return root, mapping, repoPath
}

func TestMonitorDetectsManagedRepositoryOwnershipDriftAndRechecks(t *testing.T) {
	root, mapping, repoPath := initBareRepo(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	var logs bytes.Buffer
	monitor := newMonitor(root, testMappings{mapping}, slog.New(slog.NewTextHandler(&logs, nil)), uid, gid)
	if err := monitor.Scan(t.Context()); err != nil {
		t.Fatalf("clean Scan: %v", err)
	}

	head := filepath.Join(repoPath, "HEAD")
	if err := os.Chmod(head, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Scan(t.Context()); err == nil {
		t.Fatal("drifted Scan succeeded")
	}
	if err := monitor.Check(t.Context()); err == nil || !strings.Contains(err.Error(), "unsafe managed repository") {
		t.Fatalf("drifted Check = %v", err)
	}
	for _, want := range []string{"repo_address=30617:" + mapping.Pubkey + ":project", "repo_path=" + repoPath, "offending_path=" + head, "reason=", "repair_command="} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("preflight log missing %q:\n%s", want, logs.String())
		}
	}
	if err := os.Chmod(head, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Scan(t.Context()); err != nil {
		t.Fatalf("repaired Scan: %v", err)
	}
	if err := monitor.Check(t.Context()); err != nil {
		t.Fatalf("repaired Check: %v", err)
	}
}

func TestFindMismatchesCoversBareRepositoryWritePathsAndModes(t *testing.T) {
	_, _, repoPath := initBareRepo(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	paths := []struct {
		name string
		dir  bool
	}{
		{"packed-refs", false}, {"HEAD", false}, {"config", false},
		{"hooks", true}, {"hooks/grasp", false}, {"info", true}, {"info/marker", false},
		{"refs", true}, {"refs/heads", true}, {"refs/heads/main", false},
		{"objects", true}, {"objects/info", true}, {"objects/info/commit-graph", false},
		{"worktrees", true}, {"worktrees/bridge", true}, {"worktrees/bridge/gitdir", false},
		{"grasp-migrating", false},
	}
	for _, item := range paths {
		path := filepath.Join(repoPath, item.name)
		if item.dir {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, item := range paths {
		t.Run(strings.ReplaceAll(item.name, "/", "_"), func(t *testing.T) {
			path := filepath.Join(repoPath, item.name)
			badMode := os.FileMode(0o500)
			goodMode := os.FileMode(0o700)
			if !item.dir {
				badMode, goodMode = 0o400, 0o600
			}
			if err := os.Chmod(path, badMode); err != nil {
				t.Fatal(err)
			}
			mismatches, err := findMismatches(repoPath, uid, gid)
			if err != nil {
				t.Fatalf("findMismatches: %v", err)
			}
			found := false
			for _, mismatch := range mismatches {
				if mismatch.Path == path && strings.Contains(mismatch.Reason, "lacks owner") {
					found = true
				}
			}
			if !found {
				t.Fatalf("writability mismatch not reported for %s: %+v", path, mismatches)
			}
			if err := os.Chmod(path, goodMode); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFindMismatchesRejectsSymlinkedRefs(t *testing.T) {
	_, _, repoPath := initBareRepo(t)
	if err := os.RemoveAll(filepath.Join(repoPath, "refs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(repoPath, "refs")); err != nil {
		t.Fatal(err)
	}
	_, err := findMismatches(repoPath, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("findMismatches error = %v, want symlink rejection", err)
	}
}

func TestFindMismatchesValidatesAlternatesWithoutScanningTarget(t *testing.T) {
	_, _, repoPath := initBareRepo(t)
	alternate := t.TempDir()
	if err := os.Chmod(alternate, 0o500); err != nil {
		t.Fatal(err)
	}
	alternates := filepath.Join(repoPath, "objects", "info", "alternates")
	if err := os.WriteFile(alternates, []byte(alternate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mismatches, err := findMismatches(repoPath, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatalf("readable alternate rejected: %v", err)
	}
	for _, mismatch := range mismatches {
		if strings.HasPrefix(mismatch.Path, alternate) {
			t.Fatalf("alternate target was scanned: %+v", mismatch)
		}
	}
	if err := os.WriteFile(alternates, []byte(filepath.Join(t.TempDir(), "missing")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findMismatches(repoPath, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing alternate error = %v", err)
	}
}

func TestFindMismatchesAllowsReadOnlyLooseObjectsAndPacks(t *testing.T) {
	// Git creates loose objects (objects/<hex>/<hex>...) and packfiles
	// (objects/pack/*.pack, .idx, .rev, .mtimes, .bitmap) with mode 0444 by
	// design; they are content-addressed and intentionally immutable. The
	// monitor must NOT report those files as writability drift or every
	// normal Git repository would fail readiness — the Track B regression
	// on 2026-09-06 that rolled back the deploy.
	_, _, repoPath := initBareRepo(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())

	looseDir := filepath.Join(repoPath, "objects", "ab")
	if err := os.MkdirAll(looseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(looseDir, "cdef0123456789")
	if err := os.WriteFile(loose, []byte("loose-content"), 0o444); err != nil {
		t.Fatal(err)
	}
	packDir := filepath.Join(repoPath, "objects", "pack")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"pack-deadbeef.pack", "pack-deadbeef.idx", "pack-deadbeef.rev",
		"pack-deadbeef.mtimes", "pack-deadbeef.bitmap",
	} {
		if err := os.WriteFile(filepath.Join(packDir, name), []byte("pack"), 0o444); err != nil {
			t.Fatal(err)
		}
	}

	mismatches, err := findMismatches(repoPath, uid, gid)
	if err != nil {
		t.Fatalf("findMismatches: %v", err)
	}
	for _, m := range mismatches {
		t.Errorf("read-only content-addressed path unexpectedly flagged: %+v", m)
	}

	// Sanity: HEAD at 0400 must still be flagged (it needs owner write).
	head := filepath.Join(repoPath, "HEAD")
	if err := os.Chmod(head, 0o400); err != nil {
		t.Fatal(err)
	}
	mismatches, err = findMismatches(repoPath, uid, gid)
	if err != nil {
		t.Fatalf("findMismatches after chmod HEAD: %v", err)
	}
	var sawHEAD bool
	for _, m := range mismatches {
		if m.Path == head && strings.Contains(m.Reason, "read+write") {
			sawHEAD = true
		}
	}
	if !sawHEAD {
		t.Fatalf("HEAD at 0400 must be flagged as needing read+write; got %+v", mismatches)
	}
}

func TestRequiresOwnerWriteClassification(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"HEAD", true}, {"packed-refs", true}, {"config", true}, {"description", true},
		{"grasp-migrating", true},
		{"refs/heads/main", true}, {"refs/nostr/abc", true},
		{"hooks/pre-receive", true}, {"info/exclude", true}, {"logs/HEAD", true},
		{"objects/info/packed-refs", true}, {"objects/info/commit-graph", true},
		{"objects/info/alternates", true},
		{"refs/heads/main.lock", true}, {"HEAD.lock", true},
		{"objects/ab/cdef0123456789", false},
		{"objects/pack/pack-deadbeef.pack", false},
		{"objects/pack/pack-deadbeef.idx", false},
		{"objects/pack/pack-deadbeef.bitmap", false},
	}
	for _, tc := range cases {
		if got := requiresOwnerWrite(tc.rel); got != tc.want {
			t.Errorf("requiresOwnerWrite(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

func TestRepairCommandShellQuotesRepositoryPath(t *testing.T) {
	got := RepairCommand("/gitea-data/git/repositories/acme team/repo's.git", 1000, 1000)
	if !strings.Contains(got, "chown -R 1000:1000") || !strings.Contains(got, "repo'\"'\"'s.git") || !strings.Contains(got, "chmod -R u+rwX") {
		t.Fatalf("RepairCommand() = %q", got)
	}
}

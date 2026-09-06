package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestBridgeEntrypointRejectsUnsafeUIDGIDValues(t *testing.T) {
	script := filepath.Join("grasp-bridge-entrypoint.sh")
	tests := []struct {
		name string
		uid  *string
		gid  *string
	}{
		{name: "missing uid", gid: ptr("1000")},
		{name: "missing gid", uid: ptr("1000")},
		{name: "empty uid", uid: ptr(""), gid: ptr("1000")},
		{name: "empty gid", uid: ptr("1000"), gid: ptr("")},
		{name: "root uid", uid: ptr("0"), gid: ptr("1000")},
		{name: "root gid", uid: ptr("1000"), gid: ptr("0")},
		{name: "oversized uid", uid: ptr("2147483648"), gid: ptr("1000")},
		{name: "oversized gid", uid: ptr("1000"), gid: ptr("2147483648")},
		{name: "nonnumeric uid", uid: ptr("1x"), gid: ptr("1000")},
		{name: "nonnumeric gid", uid: ptr("1000"), gid: ptr("1x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("sh", script, "true")
			cmd.Env = withoutEntrypointEnv(os.Environ())
			if tt.uid != nil {
				cmd.Env = append(cmd.Env, "USER_UID="+*tt.uid)
			}
			if tt.gid != nil {
				cmd.Env = append(cmd.Env, "USER_GID="+*tt.gid)
			}
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("unsafe identity accepted: %s", out)
			}
			if !strings.Contains(string(out), "USER_UID") && !strings.Contains(string(out), "USER_GID") {
				t.Fatalf("missing actionable identity diagnostic: %s", out)
			}
		})
	}
}

func TestBridgeEntrypointRefusesSecretSymlink(t *testing.T) {
	h := newEntrypointHarness(t)
	target := filepath.Join(h.root, "target")
	mustWriteFile(t, target, "secret", 0o600)
	link := filepath.Join(h.root, "secret-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	out, err := h.run("GRASP_SECRET_FILES=" + link)
	if err == nil {
		t.Fatalf("secret symlink accepted: %s", out)
	}
	if !strings.Contains(out, "secret is a symlink: "+link) {
		t.Fatalf("missing symlink diagnostic with path: %s", out)
	}
}

func TestBridgeEntrypointRefusesNonRegularSecret(t *testing.T) {
	h := newEntrypointHarness(t)
	directory := filepath.Join(h.root, "secret-directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	out, err := h.run("GRASP_SECRET_FILES=" + directory)
	if err == nil {
		t.Fatalf("non-regular secret accepted: %s", out)
	}
	if !strings.Contains(out, "secret is not a regular file: "+directory) {
		t.Fatalf("missing non-regular diagnostic with path: %s", out)
	}
}

func TestBridgeEntrypointRefusesMissingEnvListedSecret(t *testing.T) {
	h := newEntrypointHarness(t)
	missing := filepath.Join(h.root, "missing-secret")

	out, err := h.run("GRASP_SECRET_FILES=" + missing)
	if err == nil {
		t.Fatalf("missing env-listed secret accepted: %s", out)
	}
	if !strings.Contains(out, "secret is not a regular file: "+missing) {
		t.Fatalf("missing source diagnostic with path: %s", out)
	}
}

func TestBridgeEntrypointAllowsEnvListedSecretOutsideRunSecrets(t *testing.T) {
	h := newEntrypointHarness(t)
	secret := filepath.Join(h.root, "alternative-secret-root", "token")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, secret, "secret", 0o600)

	out, err := h.run("GRASP_SECRET_FILES=" + secret)
	if err != nil {
		t.Fatalf("env-listed alternative secret rejected: %v\n%s", err, out)
	}
	assertPrivateSecretCopy(t, h, secret, "secret")
}

func TestBridgeEntrypointCopiesDefaultMatchingSecretFiles(t *testing.T) {
	h := newEntrypointHarness(t)
	if err := os.MkdirAll(h.defaultSecretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(h.defaultSecretRoot, "grasp-admin-api-token")
	second := filepath.Join(h.defaultSecretRoot, "grasp-edge-shared-secret")
	ignored := filepath.Join(h.defaultSecretRoot, "unrelated")
	mustWriteFile(t, first, "admin", 0o400)
	mustWriteFile(t, second, "edge", 0o600)
	mustWriteFile(t, ignored, "ignored", 0o600)
	firstBefore := mustStat(t, first)
	secondBefore := mustStat(t, second)

	out, err := h.run()
	if err != nil {
		t.Fatalf("default secret copy failed: %v\n%s", err, out)
	}
	assertPrivateSecretCopy(t, h, first, "admin")
	assertPrivateSecretCopy(t, h, second, "edge")
	if _, err := os.Stat(filepath.Join(h.secretCopyRoot, filepath.Base(ignored))); !os.IsNotExist(err) {
		t.Fatalf("non-matching secret was copied: %v", err)
	}
	assertSourceUnchanged(t, first, firstBefore, "admin")
	assertSourceUnchanged(t, second, secondBefore, "edge")
}

func TestBridgeEntrypointMissingDefaultSecretDirectoryIsNoOp(t *testing.T) {
	h := newEntrypointHarness(t)

	out, err := h.run()
	if err != nil {
		t.Fatalf("missing default secret directory failed startup: %v\n%s", err, out)
	}
	info := mustStat(t, h.secretCopyRoot)
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("private secret directory mode = %04o, want 0750", info.Mode().Perm())
	}
	entries, err := os.ReadDir(h.secretCopyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("missing default glob produced private copies: %v", entries)
	}
}

func TestBridgeEntrypointSecretCopyFailuresFailStartup(t *testing.T) {
	tests := []struct {
		name       string
		failureEnv string
		diagnostic string
		targetPath bool
	}{
		{name: "copy", failureEnv: "TEST_CP_FAIL_PATH", diagnostic: "copy failed"},
		{name: "chown", failureEnv: "TEST_CHOWN_FAIL_PATH", diagnostic: "chown failed", targetPath: true},
		{name: "chmod", failureEnv: "TEST_CHMOD_FAIL_PATH", diagnostic: "chmod failed", targetPath: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newEntrypointHarness(t)
			secret := filepath.Join(h.root, "secret")
			mustWriteFile(t, secret, "secret", 0o600)
			failurePath := secret
			if tt.targetPath {
				failurePath = filepath.Join(h.secretCopyRoot, filepath.Base(secret))
			}

			out, err := h.run("GRASP_SECRET_FILES="+secret, tt.failureEnv+"="+failurePath)
			if err == nil {
				t.Fatalf("%s failure did not fail startup: %s", tt.name, out)
			}
			if !strings.Contains(out, tt.diagnostic+": "+failurePath) {
				t.Fatalf("missing %s diagnostic with path: %s", tt.name, out)
			}
		})
	}
}

type entrypointHarness struct {
	t                 *testing.T
	root              string
	script            string
	bin               string
	defaultSecretRoot string
	secretCopyRoot    string
	uid               int
	gid               int
	realChown         string
	realCP            string
	realChmod         string
	realMkdir         string
}

func newEntrypointHarness(t *testing.T) *entrypointHarness {
	t.Helper()
	root := t.TempDir()
	original, err := os.ReadFile(filepath.Join("grasp-bridge-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	defaultSecretRoot := filepath.Join(root, "run", "secrets")
	secretCopyRoot := filepath.Join(root, "run", "grasp-secrets")
	patched := strings.ReplaceAll(string(original), "/run/grasp-secrets", secretCopyRoot)
	patched = strings.ReplaceAll(patched, "/run/secrets", defaultSecretRoot)
	script := filepath.Join(root, "grasp-bridge-entrypoint.sh")
	mustWriteExecutable(t, script, patched)

	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 1234, 2345
	}
	realChown := mustLookPath(t, "chown")
	realCP := mustLookPath(t, "cp")
	realChmod := mustLookPath(t, "chmod")
	realMkdir := mustLookPath(t, "mkdir")

	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteExecutable(t, filepath.Join(bin, "id"), `#!/bin/sh
case "$1" in
	-u|-g) echo 0 ;;
	*) exit 1 ;;
esac
`)
	mustWriteExecutable(t, filepath.Join(bin, "mkdir"), `#!/bin/sh
last=
for arg do last=$arg; done
if [ "$last" = /data ]; then
  exit 0
fi
exec "$TEST_REAL_MKDIR" "$@"
`)
	mustWriteExecutable(t, filepath.Join(bin, "chown"), `#!/bin/sh
last=
for arg do last=$arg; done
if [ "$last" = /data ] || [ "$last" = "$TEST_SECRET_COPY_ROOT" ]; then
	exit 0
fi
if [ -n "${TEST_CHOWN_FAIL_PATH:-}" ] && [ "$last" = "$TEST_CHOWN_FAIL_PATH" ]; then
	exit 1
fi
exec "$TEST_REAL_CHOWN" "$@"
`)
	mustWriteExecutable(t, filepath.Join(bin, "cp"), `#!/bin/sh
if [ -n "${TEST_CP_FAIL_PATH:-}" ] && [ "$1" = "$TEST_CP_FAIL_PATH" ]; then
	exit 1
fi
exec "$TEST_REAL_CP" "$@"
`)
	mustWriteExecutable(t, filepath.Join(bin, "chmod"), `#!/bin/sh
last=
for arg do last=$arg; done
if [ -n "${TEST_CHMOD_FAIL_PATH:-}" ] && [ "$last" = "$TEST_CHMOD_FAIL_PATH" ]; then
	exit 1
fi
exec "$TEST_REAL_CHMOD" "$@"
`)
	mustWriteExecutable(t, filepath.Join(bin, "su-exec"), "#!/bin/sh\nshift\nexec \"$@\"\n")

	return &entrypointHarness{
		t:                 t,
		root:              root,
		script:            script,
		bin:               bin,
		defaultSecretRoot: defaultSecretRoot,
		secretCopyRoot:    secretCopyRoot,
		uid:               uid,
		gid:               gid,
		realChown:         realChown,
		realCP:            realCP,
		realChmod:         realChmod,
		realMkdir:         realMkdir,
	}
}

func (h *entrypointHarness) run(extraEnv ...string) (string, error) {
	h.t.Helper()
	cmd := exec.Command("sh", h.script, "true")
	cmd.Env = append(withoutEntrypointEnv(os.Environ()),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"USER_UID="+strconv.Itoa(h.uid),
		"USER_GID="+strconv.Itoa(h.gid),
		"TEST_SECRET_COPY_ROOT="+h.secretCopyRoot,
		"TEST_REAL_CHOWN="+h.realChown,
		"TEST_REAL_CP="+h.realCP,
		"TEST_REAL_CHMOD="+h.realChmod,
		"TEST_REAL_MKDIR="+h.realMkdir,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func assertPrivateSecretCopy(t *testing.T, h *entrypointHarness, source, contents string) {
	t.Helper()
	target := filepath.Join(h.secretCopyRoot, filepath.Base(source))
	if got := readFile(t, target); got != contents {
		t.Fatalf("private secret contents = %q, want %q", got, contents)
	}
	info := mustStat(t, target)
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("private secret mode = %04o, want 0400", info.Mode().Perm())
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != h.uid || int(stat.Gid) != h.gid {
		t.Fatalf("private secret owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, h.uid, h.gid)
	}
}

func assertSourceUnchanged(t *testing.T, path string, before os.FileInfo, contents string) {
	t.Helper()
	if got := readFile(t, path); got != contents {
		t.Fatalf("source secret contents changed: got %q, want %q", got, contents)
	}
	after := mustStat(t, path)
	beforeStat := before.Sys().(*syscall.Stat_t)
	afterStat := after.Sys().(*syscall.Stat_t)
	if after.Mode().Perm() != before.Mode().Perm() || afterStat.Uid != beforeStat.Uid || afterStat.Gid != beforeStat.Gid {
		t.Fatalf("source secret metadata changed: before mode/owner %04o %d:%d, after %04o %d:%d",
			before.Mode().Perm(), beforeStat.Uid, beforeStat.Gid,
			after.Mode().Perm(), afterStat.Uid, afterStat.Gid)
	}
}

func mustWriteFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func mustWriteExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func ptr(value string) *string { return &value }

func withoutEntrypointEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, value := range env {
		name, _, _ := strings.Cut(value, "=")
		switch name {
		case "USER_UID", "USER_GID", "GRASP_SECRET_FILES", "GITEA_REPO_OWNERSHIP_AUTO_REPAIR",
			"TEST_SECRET_COPY_ROOT", "TEST_REAL_CHOWN", "TEST_REAL_CP", "TEST_REAL_CHMOD", "TEST_REAL_MKDIR",
			"TEST_CP_FAIL_PATH", "TEST_CHOWN_FAIL_PATH", "TEST_CHMOD_FAIL_PATH":
			continue
		}
		out = append(out, value)
	}
	return out
}

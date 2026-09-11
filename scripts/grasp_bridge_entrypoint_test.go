package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeEntrypointRejectsUnsafeIdentity(t *testing.T) {
	script := filepath.Join("grasp-bridge-entrypoint.sh")
	for _, env := range [][]string{
		{"USER_GID=1000"},
		{"USER_UID=1000"},
		{"USER_UID=0", "USER_GID=1000"},
		{"USER_UID=1000", "USER_GID=0"},
		{"USER_UID=not-a-number", "USER_GID=1000"},
	} {
		cmd := exec.Command("sh", script, "true")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("unsafe identity accepted with env %v", env)
		}
		if !strings.Contains(string(out), "USER_UID") && !strings.Contains(string(out), "USER_GID") {
			t.Fatalf("missing safe identity diagnostic: %s", out)
		}
	}
}

func TestBridgeEntrypointRejectsSymlinkCredential(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("entrypoint privilege-drop harness requires root")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "grasp-bridge-entrypoint.sh", "true")
	cmd.Env = append(os.Environ(), "USER_UID=1234", "USER_GID=1234", "GRASP_SECRET_FILES="+link)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("symlink credential accepted")
	}
	if !strings.Contains(string(out), "secret is a symlink") {
		t.Fatalf("missing safe symlink diagnostic: %s", out)
	}
}

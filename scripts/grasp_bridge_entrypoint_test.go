package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
			cmd.Env = withoutIdentityEnv(os.Environ())
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

func ptr(value string) *string { return &value }

func withoutIdentityEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, value := range env {
		if strings.HasPrefix(value, "USER_UID=") || strings.HasPrefix(value, "USER_GID=") {
			continue
		}
		out = append(out, value)
	}
	return out
}

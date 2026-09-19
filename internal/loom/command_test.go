package loom

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildWorkerCommandDefaultsToLoomCIExecutable(t *testing.T) {
	req := DispatchRequest{
		CloneURL: "https://git.example/org/repo.git", CommitSHA: strings.Repeat("a", 40),
		WorkflowPath: ".gitea/workflows/ci.yml", Trigger: "push", TriggeredBy: strings.Repeat("b", 64),
	}
	cmd, args, err := buildWorkerCommand("", req)
	if err != nil {
		t.Fatalf("buildWorkerCommand() error = %v", err)
	}
	if cmd != "loom-ci" {
		t.Fatalf("cmd = %q, want loom-ci", cmd)
	}
	want := []string{
		"run", "--repo", "https://git.example/org/repo.git", "--ref", strings.Repeat("a", 40),
		"--workflow", ".gitea/workflows/ci.yml", "--event", "push", "--actor", strings.Repeat("b", 64),
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
}

func TestBuildWorkerCommandTemplateOverrideStillApplies(t *testing.T) {
	req := DispatchRequest{CloneURL: "https://git.example/org/repo.git", CommitSHA: strings.Repeat("c", 40), WorkflowPath: "wf.yml", Trigger: "push"}
	cmd, args, err := buildWorkerCommand(`["sh","-c","echo {commit}"]`, req)
	if err != nil || cmd != "sh" || !reflect.DeepEqual(args, []string{"-c", "echo " + strings.Repeat("c", 40)}) {
		t.Fatalf("template override = (%q, %q, %v)", cmd, args, err)
	}
}

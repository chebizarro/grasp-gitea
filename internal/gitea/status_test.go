package gitea

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateCommitStatusPOST(t *testing.T) {
	var got CommitStatus
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/repos/alice/project/statuses/0123456789abcdef" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "token secret" {
			t.Errorf("authorization = %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "secret")
	want := CommitStatus{
		State:       "pending",
		TargetURL:   "https://bridge.example/jobs/1",
		Description: "hive-ci: workflow queued",
		Context:     "hive-ci/.gitea/workflows/ci.yml",
	}
	if err := client.CreateCommitStatus(context.Background(), "alice", "project", "0123456789abcdef", want); err != nil {
		t.Fatalf("CreateCommitStatus() error = %v", err)
	}
	if got != want {
		t.Fatalf("body = %#v, want %#v", got, want)
	}
}

func TestCreateCommitStatusRejectsInvalidState(t *testing.T) {
	client := NewClient("http://127.0.0.1", "secret")
	err := client.CreateCommitStatus(context.Background(), "alice", "project", "abc", CommitStatus{
		State: "cancelled", Context: "hive-ci/test",
	})
	if err == nil {
		t.Fatal("expected invalid-state error")
	}
}

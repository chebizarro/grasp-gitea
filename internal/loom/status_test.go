package loom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestDurableStatusSinkRetriesMissingCommitWithoutReexecution(t *testing.T) {
	var requests atomic.Int32
	var available atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !available.Load() {
			http.Error(w, "commit not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "loom.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sink := NewDurableStatusSink(st, gitea.NewClient(server.URL, "token"), time.Hour, 10, nil)
	status := Status{
		Ref: Ref{WorkflowRunID: "local:one", Owner: "alice", RepoName: "repo", RepoID: "r",
			CommitSHA: "abc", WorkflowPath: "ci.yml"},
		State: store.LoomStatusPending, Context: "hive-ci/ci.yml", Source: store.LoomSourceLocal,
		ProtocolEventID: "local:one:pending",
	}
	if err := sink.Set(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	sink.deliverDue(context.Background())
	if requests.Load() != 1 {
		t.Fatalf("requests = %d", requests.Load())
	}
	job, err := st.GetLoomJobByWorkflowRunID(context.Background(), "local:one")
	if err != nil {
		t.Fatal(err)
	}
	if job.DeliveryState != "awaiting_git_object" {
		t.Fatalf("delivery state = %q", job.DeliveryState)
	}

	// Release the same durable delivery; no producer/CI callback is invoked again.
	available.Store(true)
	if err := st.MarkLoomStatusRetry(context.Background(), "local:one", "local:one:pending",
		time.Now().Add(-time.Second), "retry now", false); err != nil {
		t.Fatal(err)
	}
	sink.deliverDue(context.Background())
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want independent retry", requests.Load())
	}
	job, err = st.GetLoomJobByWorkflowRunID(context.Background(), "local:one")
	if err != nil {
		t.Fatal(err)
	}
	if job.DeliveryState != "delivered" {
		t.Fatalf("delivery state = %q", job.DeliveryState)
	}
}

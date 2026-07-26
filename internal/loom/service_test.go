package loom

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

func TestMapResultTerminalStates(t *testing.T) {
	tests := []struct {
		name    string
		kind    nostr.Kind
		tags    nostr.Tags
		content string
		want    string
	}{
		{"running", relay.KindLoomJobStatus, nostr.Tags{{"status", "running"}}, "", store.LoomStatusPending},
		{"timeout", relay.KindLoomJobStatus, nostr.Tags{{"status", "timeout"}}, "", store.LoomStatusError},
		{"cancelled", relay.KindLoomJobStatus, nil, `{"status":"cancelled"}`, store.LoomStatusError},
		{"workflow success", relay.KindHiveWorkflowResult, nil, `{"status":"success"}`, store.LoomStatusSuccess},
		{"workflow failure", relay.KindHiveWorkflowResult, nostr.Tags{{"status", "failure"}}, "", store.LoomStatusFailure},
		{"job success", relay.KindLoomJobResult, nil, `{"success":true,"exit_code":0}`, store.LoomStatusSuccess},
		{"job failure", relay.KindLoomJobResult, nil, `{"success":false,"exit_code":7}`, store.LoomStatusFailure},
		{"malformed terminal", relay.KindHiveWorkflowResult, nil, `{}`, store.LoomStatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := MapResult(tt.kind, tt.tags, tt.content)
			if err != nil {
				t.Fatalf("MapResult() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("state = %q, want %q", got, tt.want)
			}
		})
	}
}

type captureSink struct{ statuses []Status }

func (s *captureSink) Claim(_ context.Context, status Status) (bool, error) {
	s.statuses = append(s.statuses, status)
	return true, nil
}
func (s *captureSink) Set(_ context.Context, status Status) error {
	s.statuses = append(s.statuses, status)
	return nil
}

type fixedJobStore struct{ job store.LoomJob }

func (s fixedJobStore) GetLoomJobByWorkflowRunID(context.Context, string) (store.LoomJob, error) {
	return s.job, nil
}
func (s fixedJobStore) GetLoomJobByRequestID(context.Context, string) (store.LoomJob, error) {
	return s.job, nil
}

func TestProcessEventAnchorsAuthorityToDispatch(t *testing.T) {
	worker := nostr.Generate()
	publisher := nostr.Generate()
	attacker := nostr.Generate()
	job := store.LoomJob{WorkflowRunID: "run", JobRequestID: "request",
		WorkerPub: worker.Public().Hex(), PublisherPub: publisher.Public().Hex(),
		Owner: "alice", RepoName: "repo", RepoID: "r", CommitSHA: "abc", WorkflowPath: "ci.yml"}
	sink := &captureSink{}
	svc := New(Config{Enabled: true}, fixedJobStore{job}, sink, nil)
	ev := &nostr.Event{PubKey: attacker.Public(), Kind: relay.KindLoomJobResult,
		CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: nostr.Tags{{"e", "request"}},
		Content: `{"success":true}`}
	if err := svc.processEvent(context.Background(), ev); err == nil {
		t.Fatal("attacker-authored result was accepted")
	}
	if len(sink.statuses) != 0 {
		t.Fatal("attacker changed status")
	}

	ev.PubKey = worker.Public()
	ev.ID = nostr.ID{1}
	if err := svc.processEvent(context.Background(), ev); err != nil {
		t.Fatalf("worker result: %v", err)
	}
	if len(sink.statuses) != 1 || sink.statuses[0].Ref.CommitSHA != "abc" {
		t.Fatalf("status was not anchored to dispatch: %#v", sink.statuses)
	}
}

func TestProcessEventVerifiesWorkflowPublisherAndRequesterEcho(t *testing.T) {
	worker := nostr.Generate()
	publisher := nostr.Generate()
	operator := nostr.Generate()
	attacker := nostr.Generate()
	request := nostr.Event{Kind: relay.KindLoomJobRequest, CreatedAt: nostr.Now(),
		Tags: nostr.Tags{{"p", worker.Public().Hex()}, {"cmd", "act"}}}
	if err := request.Sign(operator); err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	job := store.LoomJob{WorkflowRunID: "run", JobRequestID: request.ID.Hex(),
		WorkerPub: worker.Public().Hex(), PublisherPub: publisher.Public().Hex(),
		Owner: "alice", RepoName: "repo", RepoID: "r", CommitSHA: "abc", WorkflowPath: "ci.yml",
		JobRequestEvent: string(requestJSON)}
	sink := &captureSink{}
	svc := New(Config{Enabled: true}, fixedJobStore{job}, sink, nil)

	result := &nostr.Event{PubKey: worker.Public(), ID: nostr.ID{3}, Kind: relay.KindLoomJobResult,
		CreatedAt: nostr.Now(), Tags: nostr.Tags{{"e", request.ID.Hex()}, {"p", attacker.Public().Hex()}},
		Content: `{"success":true}`}
	if err := svc.processEvent(context.Background(), result); err == nil {
		t.Fatal("worker result with wrong requester echo accepted")
	}
	result.Tags[1][1] = operator.Public().Hex()
	result.Tags = append(result.Tags, nostr.Tag{"commit", "different"})
	if err := svc.processEvent(context.Background(), result); err == nil {
		t.Fatal("worker result with mismatched dispatch field accepted")
	}
	result.Tags = result.Tags[:2]
	if err := svc.processEvent(context.Background(), result); err != nil {
		t.Fatalf("valid worker result rejected: %v", err)
	}

	workflow := &nostr.Event{PubKey: attacker.Public(), ID: nostr.ID{4}, Kind: relay.KindHiveWorkflowResult,
		CreatedAt: nostr.Now(), Tags: nostr.Tags{{"e", "run"}, {"status", "success"}}}
	if err := svc.processEvent(context.Background(), workflow); err == nil {
		t.Fatal("workflow result from non-publisher accepted")
	}
	workflow.PubKey = publisher.Public()
	workflow.ID = nostr.ID{5}
	workflow.Tags = append(workflow.Tags, nostr.Tag{"workflow", "other.yml"})
	if err := svc.processEvent(context.Background(), workflow); err == nil {
		t.Fatal("workflow result with mismatched dispatch field accepted")
	}
	workflow.Tags = workflow.Tags[:2]
	if err := svc.processEvent(context.Background(), workflow); err != nil {
		t.Fatalf("delegated publisher result rejected: %v", err)
	}
	if len(sink.statuses) != 2 {
		t.Fatalf("accepted statuses = %d, want 2", len(sink.statuses))
	}
}

func TestProcessEventRejectsFutureStatus(t *testing.T) {
	worker := nostr.Generate()
	job := store.LoomJob{WorkflowRunID: "run", JobRequestID: "request", WorkerPub: worker.Public().Hex(),
		Owner: "alice", RepoName: "repo", RepoID: "r", CommitSHA: "abc", WorkflowPath: "ci.yml"}
	sink := &captureSink{}
	svc := New(Config{Enabled: true, FutureSkew: time.Minute}, fixedJobStore{job}, sink, nil)
	ev := &nostr.Event{PubKey: worker.Public(), ID: nostr.ID{2}, Kind: relay.KindLoomJobStatus,
		CreatedAt: nostr.Timestamp(time.Now().Add(2 * time.Minute).Unix()),
		Tags:      nostr.Tags{{"d", "request"}, {"status", "running"}}}
	if err := svc.processEvent(context.Background(), ev); err == nil {
		t.Fatal("future event accepted")
	}
	if len(sink.statuses) != 0 {
		t.Fatal("future event changed status")
	}
}

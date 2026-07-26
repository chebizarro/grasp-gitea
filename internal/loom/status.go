// Package loom consumes canonical Loom/Hive-CI results and reflects them as native Gitea commit statuses.
package loom

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	DefaultContextPrefix = "hive-ci"
	defaultRetryInterval = 5 * time.Second
	maxRetryInterval     = 5 * time.Minute
)

type Ref struct {
	DispatchKey                                              string
	WorkflowRunID, JobRequestID, PublisherPub, WorkerPub     string
	Owner, RepoName, RepoID, CommitSHA, WorkflowPath, Branch string
	WorkflowRunEvent, JobRequestEvent                        string
}

type Status struct {
	Ref                                    Ref
	State, Description, Context, TargetURL string
	Source, ProtocolEventID                string
	EventCreatedAt                         int64
	AvailableAt                            time.Time
}

// StatusSink lets CI producers persist status intent without depending on Gitea delivery.
type StatusSink interface {
	// Claim atomically records the first status and returns whether the caller owns execution.
	Claim(context.Context, Status) (bool, error)
	Set(context.Context, Status) error
}

type StatusStore interface {
	SaveLoomJob(context.Context, store.LoomJob, time.Time, time.Duration, int) error
	ClaimLoomJobStatus(context.Context, store.LoomJob, store.LoomStatusUpdate, time.Time, time.Duration, int) (bool, error)
	ApplyLoomStatus(context.Context, string, store.LoomStatusUpdate, time.Time) (bool, error)
	ListDueLoomStatusDeliveries(context.Context, time.Time, int) ([]store.LoomStatusDelivery, error)
	MarkLoomStatusDelivered(context.Context, string, string, time.Time) error
	MarkLoomStatusRetry(context.Context, string, string, time.Time, string, bool) error
}

type CommitStatusWriter interface {
	CreateCommitStatus(context.Context, string, string, string, gitea.CommitStatus) error
}

// DurableStatusSink persists transitions before a bounded worker publishes them.
type DurableStatusSink struct {
	store         StatusStore
	writer        CommitStatusWriter
	ttl           time.Duration
	maxJobs       int
	retryInterval time.Duration
	logger        *slog.Logger
	wake          chan struct{}
}

func NewDurableStatusSink(st StatusStore, writer CommitStatusWriter, ttl time.Duration, maxJobs int, logger *slog.Logger) *DurableStatusSink {
	if ttl <= 0 {
		ttl = store.DefaultLoomJobTTL
	}
	if maxJobs <= 0 {
		maxJobs = store.DefaultLoomJobCap
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DurableStatusSink{store: st, writer: writer, ttl: ttl, maxJobs: maxJobs,
		retryInterval: defaultRetryInterval, logger: logger, wake: make(chan struct{}, 1)}
}

// Claim atomically persists a new attempt and pending delivery before CI starts.
func (s *DurableStatusSink) Claim(ctx context.Context, status Status) (bool, error) {
	if s == nil || s.store == nil {
		return false, fmt.Errorf("Loom status store is not configured")
	}
	now := time.Now().UTC()
	job, update := persistedStatus(status)
	claimed, err := s.store.ClaimLoomJobStatus(ctx, job, update, now, s.ttl, s.maxJobs)
	if err != nil {
		return false, fmt.Errorf("claim Loom dispatch: %w", err)
	}
	if claimed {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return claimed, nil
}

// Set records the immutable attempt before enqueueing its desired status.
func (s *DurableStatusSink) Set(ctx context.Context, status Status) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("Loom status store is not configured")
	}
	now := time.Now().UTC()
	job, update := persistedStatus(status)
	if err := s.store.SaveLoomJob(ctx, job, now, s.ttl, s.maxJobs); err != nil {
		return fmt.Errorf("persist Loom dispatch: %w", err)
	}
	if _, err := s.store.ApplyLoomStatus(ctx, status.Ref.WorkflowRunID, update, now); err != nil {
		return fmt.Errorf("enqueue Loom status: %w", err)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func persistedStatus(status Status) (store.LoomJob, store.LoomStatusUpdate) {
	return store.LoomJob{
			DispatchKey: status.Ref.DispatchKey, WorkflowRunID: status.Ref.WorkflowRunID, JobRequestID: status.Ref.JobRequestID,
			PublisherPub: status.Ref.PublisherPub, WorkerPub: status.Ref.WorkerPub,
			Owner: status.Ref.Owner, RepoName: status.Ref.RepoName, RepoID: status.Ref.RepoID,
			CommitSHA: status.Ref.CommitSHA, WorkflowPath: status.Ref.WorkflowPath, Branch: status.Ref.Branch,
			WorkflowRunEvent: status.Ref.WorkflowRunEvent, JobRequestEvent: status.Ref.JobRequestEvent,
		}, store.LoomStatusUpdate{
			State: status.State, Description: bounded(status.Description, 255),
			Context: bounded(status.Context, 255), TargetURL: bounded(status.TargetURL, 2048),
			Source: status.Source, ProtocolEventID: status.ProtocolEventID,
			EventCreatedAt: status.EventCreatedAt, AvailableAt: status.AvailableAt,
		}
}

// Run retries Gitea delivery independently of CI execution.
func (s *DurableStatusSink) Run(ctx context.Context) {
	if s == nil || s.store == nil || s.writer == nil {
		return
	}
	ticker := time.NewTicker(s.retryInterval)
	defer ticker.Stop()
	for {
		s.deliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

func (s *DurableStatusSink) deliverDue(ctx context.Context) {
	now := time.Now().UTC()
	deliveries, err := s.store.ListDueLoomStatusDeliveries(ctx, now, 25)
	if err != nil {
		s.logger.Warn("Loom status outbox query failed", "error", err)
		return
	}
	for _, d := range deliveries {
		if ctx.Err() != nil {
			return
		}
		err := s.writer.CreateCommitStatus(ctx, d.Owner, d.RepoName, d.CommitSHA, gitea.CommitStatus{
			State: d.State, TargetURL: d.TargetURL, Description: d.Description, Context: d.Context,
		})
		if err == nil {
			if e := s.store.MarkLoomStatusDelivered(ctx, d.WorkflowRunID, d.ProtocolEventID, now); e != nil {
				s.logger.Warn("Loom status completion was not persisted", "job", d.WorkflowRunID, "error", e)
			}
			continue
		}
		var httpErr *gitea.HTTPError
		awaiting := errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
		next := now.Add(retryBackoff(d.Attempts))
		if e := s.store.MarkLoomStatusRetry(ctx, d.WorkflowRunID, d.ProtocolEventID, next, err.Error(), awaiting); e != nil {
			s.logger.Warn("Loom status retry was not persisted", "job", d.WorkflowRunID, "error", e)
		}
		s.logger.Warn("Gitea commit status delivery failed", "job", d.WorkflowRunID,
			"awaiting_git_object", awaiting, "retry_at", next, "error", err)
	}
}

func retryBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	d := defaultRetryInterval
	for i := 0; i < attempts && d < maxRetryInterval; i++ {
		d *= 2
	}
	if d > maxRetryInterval {
		return maxRetryInterval
	}
	return d
}

func Context(prefix, workflow string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		prefix = DefaultContextPrefix
	}
	return bounded(prefix+"/"+strings.TrimPrefix(strings.TrimSpace(workflow), "/"), 255)
}

func bounded(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	return v[:n]
}

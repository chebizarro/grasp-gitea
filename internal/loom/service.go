package loom

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/cashu"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	defaultFutureSkew  = 5 * time.Minute
	defaultResultGrace = 30 * time.Second
	defaultQueueSize   = 256
)

type Config struct {
	Enabled       bool
	ContextPrefix string
	FutureSkew    time.Duration
	ResultGrace   time.Duration
	QueueSize     int
	LogFetcher    LogFetcher
	Wallet        cashu.Wallet
}

type JobStore interface {
	GetLoomJobByWorkflowRunID(context.Context, string) (store.LoomJob, error)
	GetLoomJobByRequestID(context.Context, string) (store.LoomJob, error)
}

type CashuChangeStore interface {
	ClaimLoomCashuChange(context.Context, string, string, string, time.Time) (bool, error)
	MarkLoomCashuChangeRedeemed(context.Context, string, string, uint64, time.Time) error
}

type Service struct {
	enabled                 bool
	store                   JobStore
	sink                    StatusSink
	contextPrefix           string
	futureSkew, resultGrace time.Duration
	logger                  *slog.Logger
	queue                   chan nostr.Event
	logs                    LogFetcher
	wallet                  cashu.Wallet
	changeStore             CashuChangeStore
}

func New(cfg Config, st JobStore, sink StatusSink, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.FutureSkew <= 0 {
		cfg.FutureSkew = defaultFutureSkew
	}
	if cfg.ResultGrace < 0 {
		cfg.ResultGrace = 0
	} else if cfg.ResultGrace == 0 {
		cfg.ResultGrace = defaultResultGrace
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if strings.TrimSpace(cfg.ContextPrefix) == "" {
		cfg.ContextPrefix = DefaultContextPrefix
	}
	changeStore, _ := st.(CashuChangeStore)
	return &Service{
		enabled: cfg.Enabled && st != nil && sink != nil, store: st, sink: sink,
		contextPrefix: cfg.ContextPrefix, futureSkew: cfg.FutureSkew,
		resultGrace: cfg.ResultGrace, logger: logger, queue: make(chan nostr.Event, cfg.QueueSize),
		logs: cfg.LogFetcher, wallet: cfg.Wallet, changeStore: changeStore,
	}
}

func (s *Service) Enabled() bool { return s != nil && s.enabled }

// HandleEvent validates and enqueues without blocking on Gitea. The relay
// subscriber is allowed to apply backpressure here; dropping terminal result
// events would strand otherwise-complete workflow runs.
func (s *Service) HandleEvent(ctx context.Context, ev *nostr.Event, _ string) error {
	if !s.Enabled() || ev == nil || !isInboundKind(ev.Kind) {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return nil
	}
	copyEvent := *ev
	copyEvent.Tags = cloneTags(ev.Tags)
	select {
	case s.queue <- copyEvent:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run starts the bounded inbound consumer.
func (s *Service) Run(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-s.queue:
				if err := s.processEvent(ctx, &ev); err != nil {
					s.logger.Warn("Loom inbound event rejected", "event", ev.ID.Hex(), "kind", ev.Kind, "error", err)
				}
			}
		}
	}()
}

func (s *Service) processEvent(ctx context.Context, ev *nostr.Event) error {
	if time.Unix(int64(ev.CreatedAt), 0).After(time.Now().UTC().Add(s.futureSkew)) {
		return fmt.Errorf("event created_at exceeds future-skew guard")
	}
	var job store.LoomJob
	var err error
	switch ev.Kind {
	case relay.KindLoomJobStatus, relay.KindLoomJobResult:
		ref := tagValue(ev.Tags, "d")
		if ev.Kind == relay.KindLoomJobResult {
			ref = tagValue(ev.Tags, "e")
		} else if ref == "" {
			ref = tagValue(ev.Tags, "e")
		}
		if ref == "" {
			return fmt.Errorf("missing Loom job request reference")
		}
		job, err = s.store.GetLoomJobByRequestID(ctx, ref)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if ev.PubKey.Hex() != job.WorkerPub {
			return fmt.Errorf("event author is not selected worker")
		}
		if ev.Kind == relay.KindLoomJobStatus {
			if tagValue(ev.Tags, "d") != job.JobRequestID || tagValue(ev.Tags, "e") != job.JobRequestID {
				return fmt.Errorf("job status references do not match dispatch")
			}
		} else if tagValue(ev.Tags, "e") != job.JobRequestID {
			return fmt.Errorf("job result reference does not match dispatch")
		} else if d := tagValue(ev.Tags, "d"); d != "" && d != job.JobRequestID {
			return fmt.Errorf("job result d reference does not match dispatch")
		}
		if err := validateRequesterEcho(job, ev.Tags); err != nil {
			return err
		}
	case relay.KindHiveWorkflowResult:
		ref := tagValue(ev.Tags, "e")
		if ref == "" {
			return fmt.Errorf("missing Hive workflow run reference")
		}
		job, err = s.store.GetLoomJobByWorkflowRunID(ctx, ref)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if ev.PubKey.Hex() != job.PublisherPub {
			return fmt.Errorf("event author is not delegated publisher")
		}
		if loomJobID := tagValue(ev.Tags, "loom_job_id"); loomJobID != "" && loomJobID != job.JobRequestID {
			return fmt.Errorf("workflow result Loom job reference does not match dispatch")
		}
	default:
		return nil
	}
	if err := validateEchoedIdentity(job, ev.Tags); err != nil {
		return err
	}
	state, description, err := MapResult(ev.Kind, ev.Tags, ev.Content)
	if err != nil {
		return err
	}
	if ev.Kind == relay.KindLoomJobResult && s.wallet != nil && s.changeStore != nil {
		if change := tagValue(ev.Tags, "change"); change != "" {
			if err := s.redeemChange(ctx, job, ev.ID.Hex(), change); err != nil {
				s.logger.Warn("Loom Cashu change redemption failed", "event", ev.ID.Hex(), "job", job.JobRequestID, "error", err)
			}
		}
	}
	if rawLogURL := resultLogURL(ev.Kind, ev.Tags); rawLogURL != "" && s.logs != nil {
		artifact, fetchErr := s.logs.Fetch(ctx, rawLogURL)
		if fetchErr != nil {
			state, description = store.LoomStatusError, "hive-ci: log artifact rejected"
		} else {
			if artifact.Tail != "" {
				description = description + " — log: " + artifact.Tail
			}
		}
	}
	availableAt := time.Now().UTC()
	if ev.Kind == relay.KindLoomJobResult {
		availableAt = availableAt.Add(s.resultGrace)
	}
	return s.sink.Set(ctx, Status{
		Ref: Ref{
			DispatchKey: job.DispatchKey, WorkflowRunID: job.WorkflowRunID, JobRequestID: job.JobRequestID,
			PublisherPub: job.PublisherPub, WorkerPub: job.WorkerPub,
			Owner: job.Owner, RepoName: job.RepoName, RepoID: job.RepoID,
			CommitSHA: job.CommitSHA, WorkflowPath: job.WorkflowPath, Branch: job.Branch,
			WorkflowRunEvent: job.WorkflowRunEvent, JobRequestEvent: job.JobRequestEvent,
		},
		State: state, Description: description, Context: Context(s.contextPrefix, job.WorkflowPath),
		Source: sourceForKind(ev.Kind), ProtocolEventID: ev.ID.Hex(),
		EventCreatedAt: int64(ev.CreatedAt), AvailableAt: availableAt,
	})
}

func (s *Service) redeemChange(ctx context.Context, job store.LoomJob, eventID, token string) error {
	claimed, err := s.changeStore.ClaimLoomCashuChange(ctx, job.DispatchKey, eventID, token, time.Now().UTC())
	if err != nil || !claimed {
		return err
	}
	amount, err := s.wallet.RedeemChange(ctx, token)
	if err != nil {
		return err
	}
	return s.changeStore.MarkLoomCashuChangeRedeemed(ctx, job.DispatchKey, eventID, amount, time.Now().UTC())
}

func resultLogURL(kind nostr.Kind, tags nostr.Tags) string {
	if kind == relay.KindHiveWorkflowResult {
		return tagValue(tags, "log_url")
	}
	if kind == relay.KindLoomJobResult {
		if stdout := tagValue(tags, "stdout"); stdout != "" {
			return stdout
		}
		return tagValue(tags, "stderr")
	}
	return ""
}

// MapResult maps canonical 30100/5101/5402 payloads to Gitea states.
func MapResult(kind nostr.Kind, tags nostr.Tags, content string) (string, string, error) {
	payload := map[string]any{}
	if strings.TrimSpace(content) != "" {
		if err := json.Unmarshal([]byte(content), &payload); err != nil {
			return "", "", fmt.Errorf("decode Loom result content: %w", err)
		}
	}
	value := func(key string) string {
		if v := strings.TrimSpace(tagValue(tags, key)); v != "" {
			return strings.ToLower(v)
		}
		if raw, ok := payload[key]; ok {
			return strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
		}
		return ""
	}
	switch kind {
	case relay.KindLoomJobStatus:
		switch status := value("status"); status {
		case "queued":
			return store.LoomStatusPending, "hive-ci: job queued", nil
		case "running":
			return store.LoomStatusPending, "hive-ci: job running", nil
		case "completed":
			return store.LoomStatusPending, "hive-ci: job completed; awaiting result", nil
		case "failed":
			return store.LoomStatusError, "hive-ci: Loom job failed", nil
		case "timeout", "timed_out":
			return store.LoomStatusError, "hive-ci: Loom job timed out", nil
		case "cancelled", "canceled":
			return store.LoomStatusError, "hive-ci: Loom job cancelled", nil
		default:
			return "", "", fmt.Errorf("unknown Loom job status %q", status)
		}
	case relay.KindHiveWorkflowResult:
		switch value("status") {
		case "success", "succeeded", "passed":
			return store.LoomStatusSuccess, "hive-ci: workflow passed", nil
		case "failure", "failed":
			return store.LoomStatusFailure, "hive-ci: workflow failed", nil
		default:
			return store.LoomStatusError, "hive-ci: malformed workflow result", nil
		}
	case relay.KindLoomJobResult:
		switch value("success") {
		case "true", "1":
			return store.LoomStatusSuccess, "hive-ci: Loom job passed", nil
		case "false", "0":
			return store.LoomStatusFailure, "hive-ci: Loom job failed", nil
		}
		if code, err := strconv.Atoi(value("exit_code")); err == nil {
			if code == 0 {
				return store.LoomStatusSuccess, "hive-ci: Loom job passed", nil
			}
			return store.LoomStatusFailure, "hive-ci: Loom job failed", nil
		}
		return store.LoomStatusError, "hive-ci: malformed Loom job result", nil
	default:
		return "", "", fmt.Errorf("unsupported Loom result kind %d", kind)
	}
}

func validateRequesterEcho(job store.LoomJob, tags nostr.Tags) error {
	if strings.TrimSpace(job.JobRequestEvent) == "" {
		return nil
	}
	var request nostr.Event
	if err := json.Unmarshal([]byte(job.JobRequestEvent), &request); err != nil {
		return fmt.Errorf("stored job request is malformed")
	}
	if p := tagValue(tags, "p"); p == "" || p != request.PubKey.Hex() {
		return fmt.Errorf("result requester does not match dispatch")
	}
	return nil
}

func validateEchoedIdentity(job store.LoomJob, tags nostr.Tags) error {
	if v := tagValue(tags, "commit"); v != "" && v != job.CommitSHA {
		return fmt.Errorf("result commit does not match dispatch")
	}
	if v := tagValue(tags, "workflow"); v != "" && v != job.WorkflowPath {
		return fmt.Errorf("result workflow does not match dispatch")
	}
	if v := tagValue(tags, "repo_id"); v != "" && v != job.RepoID {
		return fmt.Errorf("result repository id does not match dispatch")
	}
	if v := tagValue(tags, "repository"); v != "" && v != job.Owner+"/"+job.RepoName {
		return fmt.Errorf("result repository does not match dispatch")
	}
	return nil
}

func sourceForKind(kind nostr.Kind) string {
	switch kind {
	case relay.KindLoomJobStatus:
		return store.LoomSourceJobStatus
	case relay.KindLoomJobResult:
		return store.LoomSourceJobResult
	case relay.KindHiveWorkflowResult:
		return store.LoomSourceWorkflowResult
	default:
		return ""
	}
}

func isInboundKind(kind nostr.Kind) bool {
	return kind == relay.KindLoomJobStatus || kind == relay.KindLoomJobResult || kind == relay.KindHiveWorkflowResult
}

func tagValue(tags nostr.Tags, key string) string {
	tag := tags.Find(key)
	if tag == nil || len(tag) < 2 {
		return ""
	}
	return strings.TrimSpace(tag[1])
}

func cloneTags(tags nostr.Tags) nostr.Tags {
	out := make(nostr.Tags, len(tags))
	for i := range tags {
		out[i] = append(nostr.Tag(nil), tags[i]...)
	}
	return out
}

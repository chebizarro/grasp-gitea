package loom

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const defaultDispatchRetry = 5 * time.Second

// DispatchRequest is an already-authorized workflow trigger from the shared
// Hive-CI detector. TriggeredBy is the Nostr signer authorized by Resolver.
type DispatchRequest struct {
	SourceEventID string
	OwnerPubkey   string
	Owner         string
	RepoName      string
	RepoID        string
	CloneURL      string
	CommitSHA     string
	WorkflowPath  string
	Branch        string
	Trigger       string
	TriggeredBy   string
}

// DispatchSigner signs as the bridge and performs NIP-44 as that same author.
// The worker derives the conversation key from the kind-5100 event author.
type DispatchSigner interface {
	PublicKey() string
	SignEvent(context.Context, *nostr.Event) error
	NIP44Encrypt(context.Context, nostr.PubKey, string) (string, error)
}

type DispatchStore interface {
	GetLoomJobByDispatchKey(context.Context, string) (store.LoomJob, error)
	ClaimLoomOutbound(context.Context, store.LoomJob, store.LoomStatusUpdate, time.Time, time.Duration, int) (store.LoomJob, bool, error)
	ListDueLoomDispatches(context.Context, time.Time, int) ([]store.LoomJob, error)
	MarkLoomDispatchPublished(context.Context, string, time.Time) error
	MarkLoomDispatchRetry(context.Context, string, time.Time, string) error
}

type DispatcherConfig struct {
	Enabled            bool
	MaxDuration        time.Duration
	CommandTemplate    string
	StaticPaymentToken string
	ContextPrefix      string
	RelayURLs          []string
	JobTTL             time.Duration
	MaxJobs            int
}

type Dispatcher struct {
	enabled         bool
	maxDuration     time.Duration
	commandTemplate string
	paymentToken    string
	contextPrefix   string
	relayURLs       []string
	ttl             time.Duration
	maxJobs         int
	pool            *WorkerPool
	store           DispatchStore
	signer          DispatchSigner
	logger          *slog.Logger
	publish         func(context.Context, *nostr.Event) error
	wake            chan struct{}
}

func NewDispatcher(cfg DispatcherConfig, pool *WorkerPool, st DispatchStore, signer DispatchSigner, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 15 * time.Minute
	}
	if cfg.JobTTL <= 0 {
		cfg.JobTTL = store.DefaultLoomJobTTL
	}
	if cfg.MaxJobs <= 0 {
		cfg.MaxJobs = store.DefaultLoomJobCap
	}
	if strings.TrimSpace(cfg.ContextPrefix) == "" {
		cfg.ContextPrefix = DefaultContextPrefix
	}
	d := &Dispatcher{
		enabled:     cfg.Enabled && pool != nil && st != nil && signer != nil && len(cfg.RelayURLs) > 0,
		maxDuration: cfg.MaxDuration, commandTemplate: strings.TrimSpace(cfg.CommandTemplate),
		paymentToken: strings.TrimSpace(cfg.StaticPaymentToken), contextPrefix: cfg.ContextPrefix,
		relayURLs: append([]string(nil), cfg.RelayURLs...), ttl: cfg.JobTTL, maxJobs: cfg.MaxJobs,
		pool: pool, store: st, signer: signer, logger: logger, wake: make(chan struct{}, 1),
	}
	d.publish = d.publishToRelays
	return d
}

func (d *Dispatcher) Enabled() bool { return d != nil && d.enabled }

// Dispatch persists a single immutable attempt before publishing. The bool says
// whether remote execution owns the workflow; once persisted it remains true
// even if relay delivery needs retry, preventing local double execution.
func (d *Dispatcher) Dispatch(ctx context.Context, req DispatchRequest) (bool, error) {
	if !d.Enabled() {
		return false, nil
	}
	key, err := dispatchKey(req)
	if err != nil {
		return false, err
	}
	if existing, err := d.store.GetLoomJobByDispatchKey(ctx, key); err == nil {
		if existing.DispatchState == "published" {
			return true, nil
		}
		return true, d.publishAttempt(ctx, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	now := time.Now().UTC()
	worker, ok := d.pool.Select(now, d.maxDuration, d.paymentToken != "")
	if !ok {
		return false, nil
	}
	job, err := d.buildAttempt(ctx, req, key, worker.Event.PubKey.Hex(), now)
	if err != nil {
		return false, err
	}
	update := store.LoomStatusUpdate{
		State: store.LoomStatusPending, Description: "hive-ci: remote workflow queued",
		Context: Context(d.contextPrefix, req.WorkflowPath), Source: store.LoomSourceLocal,
		ProtocolEventID: job.WorkflowRunID + ":pending", AvailableAt: now,
	}
	stored, _, err := d.store.ClaimLoomOutbound(ctx, job, update, now, d.ttl, d.maxJobs)
	if err != nil {
		return false, err
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return true, d.publishAttempt(ctx, stored)
}

func (d *Dispatcher) buildAttempt(ctx context.Context, req DispatchRequest, key, workerPub string, now time.Time) (store.LoomJob, error) {
	bridgePub, err := nostr.PubKeyFromHex(strings.TrimSpace(d.signer.PublicKey()))
	if err != nil {
		return store.LoomJob{}, fmt.Errorf("invalid Loom operator pubkey: %w", err)
	}
	worker, err := nostr.PubKeyFromHex(workerPub)
	if err != nil {
		return store.LoomJob{}, fmt.Errorf("invalid selected worker pubkey: %w", err)
	}
	ephemeral := nostr.Generate()
	nsec := nip19.EncodeNsec(ephemeral)
	encrypted, err := d.signer.NIP44Encrypt(ctx, worker, nsec)
	if err != nil {
		return store.LoomJob{}, fmt.Errorf("NIP-44 encrypt HIVE_CI_NSEC: %w", err)
	}
	run := &nostr.Event{
		PubKey: bridgePub, CreatedAt: nostr.Timestamp(now.Unix()), Kind: relay.KindHiveWorkflowRun,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, req.OwnerPubkey, req.RepoID)},
			{"commit", req.CommitSHA}, {"branch", req.Branch}, {"trigger", req.Trigger},
			{"triggered-by", req.TriggeredBy}, {"workflow", req.WorkflowPath},
			{"publisher", ephemeral.Public().Hex()}, {"t", "hive-ci"},
		},
		Content: "",
	}
	if err := d.signer.SignEvent(ctx, run); err != nil {
		return store.LoomJob{}, fmt.Errorf("sign Hive workflow run: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(run); err != nil {
		return store.LoomJob{}, fmt.Errorf("operator returned invalid workflow signature: %w", err)
	}
	cmd, args, err := buildWorkerCommand(d.commandTemplate, req)
	if err != nil {
		return store.LoomJob{}, err
	}
	tags := nostr.Tags{
		{"p", workerPub}, {"cmd", cmd}, append(nostr.Tag{"args"}, args...),
		{"e", run.ID.Hex()}, {"secret", "HIVE_CI_NSEC", encrypted},
	}
	if d.paymentToken != "" {
		tags = append(tags, nostr.Tag{"payment", d.paymentToken})
	}
	request := &nostr.Event{
		PubKey: bridgePub, CreatedAt: nostr.Timestamp(now.Unix()), Kind: relay.KindLoomJobRequest,
		Tags: tags, Content: "",
	}
	if err := d.signer.SignEvent(ctx, request); err != nil {
		return store.LoomJob{}, fmt.Errorf("sign Loom job request: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(request); err != nil {
		return store.LoomJob{}, fmt.Errorf("operator returned invalid job signature: %w", err)
	}
	runBytes, err := json.Marshal(run)
	if err != nil {
		return store.LoomJob{}, err
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return store.LoomJob{}, err
	}
	return store.LoomJob{
		DispatchKey: key, WorkflowRunID: run.ID.Hex(), JobRequestID: request.ID.Hex(),
		PublisherPub: ephemeral.Public().Hex(), WorkerPub: workerPub,
		Owner: req.Owner, RepoName: req.RepoName, RepoID: req.RepoID,
		CommitSHA: req.CommitSHA, WorkflowPath: req.WorkflowPath,
		WorkflowRunEvent: string(runBytes), JobRequestEvent: string(requestBytes),
		CreatedAt: now,
	}, nil
}

func (d *Dispatcher) publishAttempt(ctx context.Context, job store.LoomJob) error {
	var run, request nostr.Event
	if err := json.Unmarshal([]byte(job.WorkflowRunEvent), &run); err != nil {
		return fmt.Errorf("decode persisted workflow event: %w", err)
	}
	if err := json.Unmarshal([]byte(job.JobRequestEvent), &request); err != nil {
		return fmt.Errorf("decode persisted job event: %w", err)
	}
	if run.ID.Hex() != job.WorkflowRunID || request.ID.Hex() != job.JobRequestID {
		return fmt.Errorf("persisted Loom event IDs do not match dispatch record")
	}
	if err := nostrverify.ValidateEventIDAndSignature(&run); err != nil {
		return fmt.Errorf("persisted workflow event is invalid: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(&request); err != nil {
		return fmt.Errorf("persisted job event is invalid: %w", err)
	}
	errRun := d.publish(ctx, &run)
	errRequest := d.publish(ctx, &request)
	if errRun == nil && errRequest == nil {
		if err := d.store.MarkLoomDispatchPublished(ctx, job.WorkflowRunID, time.Now().UTC()); err != nil {
			return fmt.Errorf("mark Loom dispatch published: %w", err)
		}
		return nil
	}
	publishErr := errors.Join(errRun, errRequest)
	next := time.Now().UTC().Add(dispatchRetryBackoff(job.DispatchAttempts))
	if err := d.store.MarkLoomDispatchRetry(ctx, job.WorkflowRunID, next, publishErr.Error()); err != nil {
		return errors.Join(publishErr, err)
	}
	return publishErr
}

// Run republishes exact persisted events after process or relay failures.
func (d *Dispatcher) Run(ctx context.Context) {
	if !d.Enabled() {
		return
	}
	ticker := time.NewTicker(defaultDispatchRetry)
	defer ticker.Stop()
	for {
		d.publishDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.wake:
		}
	}
}

func (d *Dispatcher) publishDue(ctx context.Context) {
	jobs, err := d.store.ListDueLoomDispatches(ctx, time.Now().UTC(), 25)
	if err != nil {
		d.logger.Warn("Loom dispatch outbox query failed", "error", err)
		return
	}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		if err := d.publishAttempt(ctx, job); err != nil {
			d.logger.Warn("Loom dispatch publish failed", "workflow_run", job.WorkflowRunID, "error", err)
		}
	}
}

func (d *Dispatcher) publishToRelays(ctx context.Context, ev *nostr.Event) error {
	var accepted int
	for _, url := range d.relayURLs {
		pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := nostr.RelayConnect(pubCtx, url, nostr.RelayOptions{})
		if err == nil {
			err = conn.Publish(pubCtx, *ev)
			conn.Close()
		}
		cancel()
		if err != nil {
			d.logger.Warn("Loom relay publish failed", "relay", url, "event", ev.ID.Hex(), "error", err)
			continue
		}
		accepted++
	}
	if accepted == 0 {
		return fmt.Errorf("event %s rejected by all %d Loom relays", ev.ID.Hex(), len(d.relayURLs))
	}
	return nil
}

func dispatchKey(req DispatchRequest) (string, error) {
	if strings.TrimSpace(req.CloneURL) == "" {
		return "", fmt.Errorf("Loom dispatch clone URL is required")
	}
	fields := []string{req.SourceEventID, req.OwnerPubkey, req.Owner, req.RepoName, req.RepoID,
		req.CommitSHA, req.WorkflowPath, req.Branch, req.Trigger, req.TriggeredBy}
	for _, field := range fields {
		if strings.TrimSpace(field) == "" {
			return "", fmt.Errorf("complete Loom dispatch request is required")
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return "loom:" + hex.EncodeToString(sum[:]), nil
}

func buildWorkerCommand(template string, req DispatchRequest) (string, []string, error) {
	if strings.TrimSpace(template) == "" {
		return "sh", []string{"-c",
			`git clone --no-checkout "$1" repo && git -C repo checkout --detach "$2" && cd repo && act "$3" -W "$4" --rm`,
			"hive-ci", req.CloneURL, req.CommitSHA, req.Trigger, req.WorkflowPath}, nil
	}
	var words []string
	if strings.HasPrefix(strings.TrimSpace(template), "[") {
		if err := json.Unmarshal([]byte(template), &words); err != nil {
			return "", nil, fmt.Errorf("decode LOOM_JOB_CMD_TEMPLATE JSON: %w", err)
		}
	} else {
		words = strings.Fields(template)
	}
	if len(words) == 0 {
		return "", nil, fmt.Errorf("LOOM_JOB_CMD_TEMPLATE is empty")
	}
	replacements := map[string]string{
		"{clone_url}": req.CloneURL, "{commit}": req.CommitSHA, "{trigger}": req.Trigger,
		"{workflow}": req.WorkflowPath, "{branch}": req.Branch,
		"{repository}": req.Owner + "/" + req.RepoName, "{repo_id}": req.RepoID,
	}
	for i := range words {
		for old, replacement := range replacements {
			words[i] = strings.ReplaceAll(words[i], old, replacement)
		}
	}
	if strings.TrimSpace(words[0]) == "" {
		return "", nil, fmt.Errorf("LOOM_JOB_CMD_TEMPLATE has empty executable")
	}
	return words[0], words[1:], nil
}

func dispatchRetryBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	d := defaultDispatchRetry
	for i := 0; i < attempts && d < 5*time.Minute; i++ {
		d *= 2
	}
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	return d
}

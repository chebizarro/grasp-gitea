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
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/cashu"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const defaultDispatchRetry = 5 * time.Second

var errNoLoomWorker = errors.New("no eligible Loom worker")

// DispatchRequest is an already-authorized workflow trigger from the shared
// Hive-CI detector. TriggeredBy is the Nostr signer authorized by Resolver.
type DispatchRequest struct {
	SourceEventID       string
	TriggerEnvelopeID   string
	TriggerSource       string
	TriggerID           string
	Actor               string
	EvidenceJSON        string
	PREventID           string
	StatusEventID       string
	SourceCommit        string
	SourceTree          string
	PatchDigest         string
	RepoAddress         string
	PolicyVersion       string
	ReviewEventID       string
	AuditEventID        string
	ReviewerPubkey      string
	ReviewRootEventID   string
	ReviewBaseCommit    string
	ReviewPolicyVersion string
	ReviewPolicySHA256  string
	CommitTree          string
	WorkflowDigest      string
	SourceProvenanceRef string
	SourceRepoIdentity  string
	OwnerPubkey         string
	Owner               string
	RepoName            string
	RepoID              string
	CloneURL            string
	CommitSHA           string
	WorkflowPath        string
	Branch              string
	Trigger             string
	TriggeredBy         string
}

// DispatchSigner signs as the bridge and performs NIP-44 as that same author.
// The worker derives the conversation key from the kind-5100 event author.
type DispatchSigner interface {
	PublicKey() string
	SignEvent(context.Context, *nostr.Event) error
	NIP44Encrypt(context.Context, nostr.PubKey, string) (string, error)
}

// DispatchRevalidator is the fail-closed policy boundary around every durable
// dispatch. The request check runs before reservation, payment, signing, or
// status creation. The persisted check runs immediately before every outbox
// publication, including crash/retry recovery.
type DispatchRevalidator interface {
	ValidateDispatchRequest(context.Context, DispatchRequest) error
	RevalidateDispatch(context.Context, store.LoomJob) error
}

type DispatchStore interface {
	GetLoomJobByWorkflowRunID(context.Context, string) (store.LoomJob, error)
	GetLoomJobByDispatchKey(context.Context, string) (store.LoomJob, error)
	GetLoomJobByTriggerEnvelope(context.Context, string, string) (store.LoomJob, error)
	ClaimLoomDispatchReservation(context.Context, string, string, string, time.Time) (bool, error)
	ClaimLoomOutbound(context.Context, store.LoomJob, store.LoomStatusUpdate, time.Time, time.Duration, int) (store.LoomJob, bool, error)
	ListDueLoomDispatches(context.Context, time.Time, int) ([]store.LoomJob, error)
	MarkLoomDispatchPublished(context.Context, string, time.Time) error
	MarkLoomDispatchRetry(context.Context, string, time.Time, string) error
	ReserveLoomCashuSpend(context.Context, store.LoomCashuSpend, time.Time) (store.LoomCashuSpend, bool, error)
	CompleteLoomCashuSpend(context.Context, string, string, string, time.Time) (store.LoomCashuSpend, error)
	GetLoomCashuSpend(context.Context, string) (store.LoomCashuSpend, error)
	AttachLoomCashuSpend(context.Context, string, string, time.Time) error
	ListSupersededLoomJobs(context.Context, store.LoomJob, int) ([]store.LoomJob, error)
	ClaimLoomCancellation(context.Context, string, string, string, string, time.Time) (store.LoomJob, bool, error)
	ListDueLoomCancellations(context.Context, time.Time, int) ([]store.LoomJob, error)
	MarkLoomCancellationPublished(context.Context, string, time.Time) error
	MarkLoomCancellationRetry(context.Context, string, time.Time, string) error
}

type DispatcherConfig struct {
	Enabled            bool
	MaxDuration        time.Duration
	CommandTemplate    string
	StaticPaymentToken string
	PaymentMode        string
	MintURL            string
	MaxPayment         uint64
	ContextPrefix      string
	RelayURLs          []string
	JobTTL             time.Duration
	MaxJobs            int
	// Publish, when set, replaces relay publication. It is primarily a test and
	// embedding seam; production leaves it nil and uses RelayURLs.
	Publish func(context.Context, *nostr.Event) error
}

type Dispatcher struct {
	enabled         bool
	maxDuration     time.Duration
	commandTemplate string
	paymentToken    string
	paymentMode     string
	mintURL         string
	maxPayment      uint64
	wallet          cashu.Wallet
	contextPrefix   string
	relayURLs       []string
	ttl             time.Duration
	maxJobs         int
	pool            *WorkerPool
	store           DispatchStore
	signer          DispatchSigner
	revalidator     DispatchRevalidator
	logger          *slog.Logger
	publish         func(context.Context, *nostr.Event) error
	wake            chan struct{}
}

func NewDispatcher(cfg DispatcherConfig, pool *WorkerPool, st DispatchStore, signer DispatchSigner, logger *slog.Logger, wallets ...cashu.Wallet) *Dispatcher {
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
	mode := strings.ToLower(strings.TrimSpace(cfg.PaymentMode))
	if mode == "" {
		mode = "trusted"
	}
	var wallet cashu.Wallet
	if len(wallets) > 0 {
		wallet = wallets[0]
	}
	d := &Dispatcher{
		enabled:     cfg.Enabled && pool != nil && st != nil && signer != nil && len(cfg.RelayURLs) > 0,
		maxDuration: cfg.MaxDuration, commandTemplate: strings.TrimSpace(cfg.CommandTemplate),
		paymentToken: strings.TrimSpace(cfg.StaticPaymentToken), contextPrefix: cfg.ContextPrefix,
		paymentMode: mode, mintURL: strings.TrimSpace(cfg.MintURL), maxPayment: cfg.MaxPayment, wallet: wallet,
		relayURLs: append([]string(nil), cfg.RelayURLs...), ttl: cfg.JobTTL, maxJobs: cfg.MaxJobs,
		pool: pool, store: st, signer: signer, logger: logger, wake: make(chan struct{}, 1),
	}
	d.publish = d.publishToRelays
	if cfg.Publish != nil {
		d.publish = cfg.Publish
	}
	if d.paymentMode == "cashu" && (d.wallet == nil || d.mintURL == "" || d.maxPayment == 0) {
		d.enabled = false
	}
	return d
}

func (d *Dispatcher) Enabled() bool { return d != nil && d.enabled }

// SetDispatchRevalidator installs the current review/policy/Git-lineage gate.
// Dispatch remains enabled for composition ordering, but no attempt can cross
// the side-effect boundary until this dependency is installed.
func (d *Dispatcher) SetDispatchRevalidator(revalidator DispatchRevalidator) {
	if d != nil {
		d.revalidator = revalidator
	}
}

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
	if d.revalidator == nil {
		return false, fmt.Errorf("HiveCI dispatch policy revalidator is unavailable")
	}
	if err := d.revalidator.ValidateDispatchRequest(ctx, req); err != nil {
		return false, err
	}
	if req.TriggerEnvelopeID != "" {
		if existing, err := d.store.GetLoomJobByTriggerEnvelope(ctx, req.TriggerEnvelopeID, req.WorkflowPath); err == nil {
			if existing.DispatchKey != key {
				return true, &store.TriggerConflictError{Source: req.TriggerSource, TriggerID: req.TriggerID}
			}
			if store.LoomJobTerminal(existing) {
				return true, &store.TriggerConflictError{Source: req.TriggerSource, TriggerID: req.TriggerID}
			}
			if existing.DispatchState == "published" {
				d.ensureSupersededCancellations(ctx, existing)
				return true, nil
			}
			return true, d.publishAttempt(ctx, existing)
		} else if errors.Is(err, store.ErrTriggerConflict) {
			return true, err
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	if existing, err := d.store.GetLoomJobByDispatchKey(ctx, key); err == nil {
		if store.LoomJobTerminal(existing) {
			return true, &store.TriggerConflictError{Source: req.TriggerSource, TriggerID: req.TriggerID}
		}
		if existing.DispatchState == "published" {
			d.ensureSupersededCancellations(ctx, existing)
			return true, nil
		}
		return true, d.publishAttempt(ctx, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	now := time.Now().UTC()
	workerAd, ok := d.selectWorker(now)
	if !ok {
		return false, nil
	}
	reserved, err := d.store.ClaimLoomDispatchReservation(ctx, req.TriggerEnvelopeID, req.WorkflowPath, key, now)
	if err != nil {
		return false, err
	}
	if !reserved {
		return true, &store.TriggerConflictError{Source: req.TriggerSource, TriggerID: req.TriggerID}
	}
	paymentToken, err := d.preparePayment(ctx, key, workerAd, now)
	if err != nil {
		return true, err
	}
	job, err := d.buildAttempt(ctx, req, key, workerAd, paymentToken, now)
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
	if d.paymentMode == "cashu" {
		if err := d.store.AttachLoomCashuSpend(ctx, key, stored.WorkflowRunID, now); err != nil {
			return true, err
		}
	}
	if store.LoomJobTerminal(stored) {
		return true, &store.TriggerConflictError{Source: req.TriggerSource, TriggerID: req.TriggerID}
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return true, d.publishAttempt(ctx, stored)
}

func (d *Dispatcher) selectWorker(now time.Time) (WorkerAd, bool) {
	if d.paymentMode != "cashu" {
		return d.pool.Select(now, d.maxDuration, d.paymentToken != "")
	}
	return d.pool.SelectForMint(now, d.maxDuration, d.mintURL)
}

func (d *Dispatcher) preparePayment(ctx context.Context, key string, worker WorkerAd, now time.Time) (string, error) {
	if d.paymentMode != "cashu" {
		if _, ok := d.pool.Revalidate(worker.Event.PubKey.Hex(), worker.Event.ID.Hex(), now,
			d.maxDuration, d.paymentToken != "", ""); !ok {
			return "", errNoLoomWorker
		}
		return d.paymentToken, nil
	}

	if spend, err := d.store.GetLoomCashuSpend(ctx, key); err == nil {
		if spend.State != "ready" || spend.Token == "" {
			return "", fmt.Errorf("Cashu spend %s is reserved without a durable token; refusing a second payment", key)
		}
		if spend.WorkerPub != worker.Event.PubKey.Hex() || spend.WorkerAdID != worker.Event.ID.Hex() {
			return "", fmt.Errorf("Cashu spend %s worker advertisement changed", key)
		}
		return spend.Token, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	price := worker.Prices[mustNormalizeMint(d.mintURL)]
	amount, err := cashu.PaymentAmount(price, d.maxDuration)
	if err != nil {
		return "", err
	}
	if amount > d.maxPayment {
		return "", fmt.Errorf("Cashu payment %d exceeds configured per-job maximum %d", amount, d.maxPayment)
	}
	spend, claimed, err := d.store.ReserveLoomCashuSpend(ctx, store.LoomCashuSpend{
		DispatchKey: key, WorkerPub: worker.Event.PubKey.Hex(), WorkerAdID: worker.Event.ID.Hex(), MintURL: mustNormalizeMint(d.mintURL),
		Amount: amount, PricePerSecond: price, DurationSeconds: int64(d.maxDuration / time.Second),
	}, now)
	if err != nil {
		return "", err
	}
	if !claimed {
		if spend.State == "ready" && spend.Token != "" {
			if spend.WorkerPub != worker.Event.PubKey.Hex() || spend.WorkerAdID != worker.Event.ID.Hex() {
				return "", fmt.Errorf("Cashu spend %s worker advertisement changed", key)
			}
			return spend.Token, nil
		}
		return "", fmt.Errorf("Cashu spend %s is already reserved without a durable token; refusing a second payment", key)
	}
	if _, ok := d.pool.Revalidate(worker.Event.PubKey.Hex(), worker.Event.ID.Hex(), time.Now().UTC(),
		d.maxDuration, true, d.mintURL); !ok {
		return "", errNoLoomWorker
	}
	payment, err := d.wallet.CreatePayment(ctx, cashu.PaymentRequest{
		Amount: amount, MintURL: spend.MintURL, WorkerPubkey: spend.WorkerPub,
	})
	if err != nil {
		return "", err
	}
	if payment.Amount != amount {
		return "", fmt.Errorf("Cashu wallet returned amount %d, want %d", payment.Amount, amount)
	}
	ready, err := d.store.CompleteLoomCashuSpend(ctx, key, payment.QuoteID, payment.Token, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return ready.Token, nil
}

func mustNormalizeMint(raw string) string {
	value, _ := cashu.NormalizeMintURL(raw)
	return value
}

func (d *Dispatcher) buildAttempt(ctx context.Context, req DispatchRequest, key string, workerAd WorkerAd, paymentToken string, now time.Time) (store.LoomJob, error) {
	workerPub, workerAdID := workerAd.Event.PubKey.Hex(), workerAd.Event.ID.Hex()
	mintURL := ""
	if d.paymentMode == "cashu" {
		mintURL = d.mintURL
	}
	if _, ok := d.pool.Revalidate(workerPub, workerAdID, now, d.maxDuration,
		d.paymentToken != "" || d.paymentMode == "cashu", mintURL); !ok {
		return store.LoomJob{}, errNoLoomWorker
	}
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
			{"pr", req.PREventID}, {"review", req.ReviewEventID}, {"audit", req.AuditEventID},
			{"reviewer", req.ReviewerPubkey}, {"review-root", req.ReviewRootEventID},
			{"review-base", req.ReviewBaseCommit}, {"tree", req.CommitTree},
			{"workflow-digest", req.WorkflowDigest}, {"source-provenance", req.SourceProvenanceRef},
			{"source-repo", req.SourceRepoIdentity}, {"source-clone", req.CloneURL}, {"requester", req.Actor},
			{"idempotency", req.TriggerEnvelopeID}, {"worker-ad", workerAdID},
			{"review-policy", req.ReviewPolicyVersion}, {"policy-digest", req.ReviewPolicySHA256},
		},
		Content: "",
	}
	if req.TriggerEnvelopeID != "" {
		evidenceDigest := sha256.Sum256([]byte(req.EvidenceJSON))
		run.Tags = append(run.Tags,
			nostr.Tag{"trigger-envelope", req.TriggerEnvelopeID},
			nostr.Tag{"trigger-source", req.TriggerSource},
			nostr.Tag{"trigger-id", req.TriggerID},
			nostr.Tag{"actor", req.Actor},
			nostr.Tag{"evidence-digest", hex.EncodeToString(evidenceDigest[:])},
			nostr.Tag{"pr-event", req.PREventID},
			nostr.Tag{"status-event", req.StatusEventID},
			nostr.Tag{"source-commit", req.SourceCommit},
			nostr.Tag{"source-tree", req.SourceTree},
			nostr.Tag{"patch-digest", req.PatchDigest},
			nostr.Tag{"repo-address", req.RepoAddress},
			nostr.Tag{"policy", req.PolicyVersion},
		)
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
	if paymentToken != "" {
		tags = append(tags, nostr.Tag{"payment", paymentToken})
	}
	if d.paymentMode == "cashu" && d.wallet.ReceivePubkey() != "" {
		tags = append(tags, nostr.Tag{"cashu_pubkey", d.wallet.ReceivePubkey()})
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
		DispatchKey: key, TriggerEnvelopeID: req.TriggerEnvelopeID,
		WorkflowRunID: run.ID.Hex(), JobRequestID: request.ID.Hex(),
		PublisherPub: ephemeral.Public().Hex(), WorkerPub: workerPub, WorkerAdID: workerAdID,
		Owner: req.Owner, RepoName: req.RepoName, RepoID: req.RepoID,
		CommitSHA: req.CommitSHA, WorkflowPath: req.WorkflowPath,
		Branch:           req.Branch,
		WorkflowRunEvent: string(runBytes), JobRequestEvent: string(requestBytes),
		CreatedAt: now,
	}, nil
}

func (d *Dispatcher) publishAttempt(ctx context.Context, job store.LoomJob) error {
	current, err := d.store.GetLoomJobByWorkflowRunID(ctx, job.WorkflowRunID)
	if err != nil {
		return fmt.Errorf("reload Loom dispatch before publish: %w", err)
	}
	if store.LoomJobTerminal(current) {
		return &store.TriggerConflictError{Source: "loom-terminal", TriggerID: current.WorkflowRunID}
	}
	if current.DispatchKey != job.DispatchKey || current.WorkerPub != job.WorkerPub ||
		current.WorkerAdID != job.WorkerAdID || current.WorkflowRunEvent != job.WorkflowRunEvent ||
		current.JobRequestEvent != job.JobRequestEvent {
		return fmt.Errorf("persisted Loom dispatch changed before publication")
	}
	if d.revalidator == nil {
		return fmt.Errorf("HiveCI dispatch policy revalidator is unavailable")
	}
	if err := d.revalidator.RevalidateDispatch(ctx, current); err != nil {
		return fmt.Errorf("revalidate persisted HiveCI dispatch: %w", err)
	}
	mintURL := ""
	if d.paymentMode == "cashu" {
		mintURL = d.mintURL
	}
	if _, ok := d.pool.Revalidate(job.WorkerPub, job.WorkerAdID, time.Now().UTC(), d.maxDuration,
		d.paymentToken != "" || d.paymentMode == "cashu", mintURL); !ok {
		return fmt.Errorf("%w: selected worker advertisement is stale, replaced, or no longer capable", errNoLoomWorker)
	}
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
	if run.Kind != relay.KindHiveWorkflowRun || request.Kind != relay.KindLoomJobRequest ||
		run.PubKey != request.PubKey || tagValue(request.Tags, "e") != run.ID.Hex() ||
		tagValue(request.Tags, "p") != job.WorkerPub || tagValue(run.Tags, "publisher") != job.PublisherPub ||
		tagValue(run.Tags, "worker-ad") != job.WorkerAdID {
		return fmt.Errorf("persisted Loom request lineage does not match dispatch record")
	}
	errRun := d.publish(ctx, &run)
	errRequest := d.publish(ctx, &request)
	if errRun == nil && errRequest == nil {
		if err := d.store.MarkLoomDispatchPublished(ctx, job.WorkflowRunID, time.Now().UTC()); err != nil {
			return fmt.Errorf("mark Loom dispatch published: %w", err)
		}
		d.ensureSupersededCancellations(ctx, current)
		return nil
	}
	publishErr := errors.Join(errRun, errRequest)
	next := time.Now().UTC().Add(dispatchRetryBackoff(job.DispatchAttempts))
	if err := d.store.MarkLoomDispatchRetry(ctx, job.WorkflowRunID, next, publishErr.Error()); err != nil {
		return errors.Join(publishErr, err)
	}
	return publishErr
}

func (d *Dispatcher) ensureSupersededCancellations(ctx context.Context, newer store.LoomJob) {
	jobs, err := d.store.ListSupersededLoomJobs(ctx, newer, 100)
	if err != nil {
		d.logger.Warn("Loom supersession query failed", "workflow_run", newer.WorkflowRunID, "error", err)
		return
	}
	for _, old := range jobs {
		if old.CancelState != "" {
			continue
		}
		now := time.Now().UTC()
		pub, err := nostr.PubKeyFromHex(strings.TrimSpace(d.signer.PublicKey()))
		if err != nil {
			d.logger.Warn("Loom cancellation signer is invalid", "error", err)
			return
		}
		var original nostr.Event
		if err := json.Unmarshal([]byte(old.JobRequestEvent), &original); err != nil || original.PubKey != pub {
			d.logger.Warn("Loom cancellation signer no longer matches original requester", "job", old.JobRequestID)
			continue
		}
		ev := &nostr.Event{PubKey: pub, CreatedAt: nostr.Timestamp(now.Unix()), Kind: relay.KindLoomJobCancel,
			Tags: nostr.Tags{{"e", old.JobRequestID}, {"p", old.WorkerPub}}, Content: ""}
		if err := d.signer.SignEvent(ctx, ev); err != nil {
			d.logger.Warn("sign Loom cancellation failed", "job", old.JobRequestID, "error", err)
			continue
		}
		if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
			d.logger.Warn("invalid signed Loom cancellation", "job", old.JobRequestID, "error", err)
			continue
		}
		encoded, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		persisted, claimed, claimErr := d.store.ClaimLoomCancellation(ctx, old.WorkflowRunID,
			newer.WorkflowRunID, ev.ID.Hex(), string(encoded), now)
		if claimErr != nil {
			d.logger.Warn("persist Loom cancellation failed", "job", old.JobRequestID, "error", claimErr)
			continue
		}
		if claimed {
			if err := d.publishCancellation(ctx, persisted); err != nil {
				d.logger.Warn("publish Loom cancellation failed", "job", old.JobRequestID, "error", err)
			}
		}
	}
}

func (d *Dispatcher) publishCancellation(ctx context.Context, job store.LoomJob) error {
	var ev nostr.Event
	if err := json.Unmarshal([]byte(job.CancelEvent), &ev); err != nil {
		return fmt.Errorf("decode persisted cancellation: %w", err)
	}
	var original nostr.Event
	if err := json.Unmarshal([]byte(job.JobRequestEvent), &original); err != nil {
		return fmt.Errorf("decode original persisted job request: %w", err)
	}
	if err := nostrverify.ValidateEventIDAndSignature(&original); err != nil || original.ID.Hex() != job.JobRequestID {
		return fmt.Errorf("original persisted job request is invalid")
	}
	if ev.Kind != relay.KindLoomJobCancel || ev.ID.Hex() != job.CancelEventID || ev.PubKey != original.PubKey ||
		tagValue(ev.Tags, "e") != job.JobRequestID || tagValue(ev.Tags, "p") != job.WorkerPub {
		return fmt.Errorf("persisted Loom cancellation does not match dispatch")
	}
	if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
		return fmt.Errorf("persisted Loom cancellation is invalid: %w", err)
	}
	if err := d.publish(ctx, &ev); err != nil {
		next := time.Now().UTC().Add(dispatchRetryBackoff(job.CancelAttempts))
		if markErr := d.store.MarkLoomCancellationRetry(ctx, job.WorkflowRunID, next, err.Error()); markErr != nil {
			return errors.Join(err, markErr)
		}
		return err
	}
	return d.store.MarkLoomCancellationPublished(ctx, job.WorkflowRunID, time.Now().UTC())
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
	cancellations, err := d.store.ListDueLoomCancellations(ctx, time.Now().UTC(), 25)
	if err != nil {
		d.logger.Warn("Loom cancellation outbox query failed", "error", err)
		return
	}
	for _, job := range cancellations {
		if ctx.Err() != nil {
			return
		}
		if err := d.publishCancellation(ctx, job); err != nil {
			d.logger.Warn("Loom cancellation publish failed", "workflow_run", job.WorkflowRunID, "error", err)
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
	if err := validateTriggerEnvelopeRequest(req); err != nil {
		return "", err
	}
	fields := []string{req.SourceEventID, req.OwnerPubkey, req.Owner, req.RepoName, req.RepoID,
		req.CloneURL, req.CommitSHA, req.WorkflowPath, req.Branch, req.Trigger, req.TriggeredBy}
	for _, field := range fields {
		if strings.TrimSpace(field) == "" {
			return "", fmt.Errorf("complete Loom dispatch request is required")
		}
	}
	fields = append(fields, req.TriggerEnvelopeID, req.TriggerSource, req.TriggerID,
		req.Actor, req.EvidenceJSON, req.PREventID, req.StatusEventID,
		req.SourceCommit, req.SourceTree, req.PatchDigest, req.RepoAddress, req.PolicyVersion,
		req.ReviewEventID, req.AuditEventID, req.ReviewerPubkey, req.ReviewRootEventID,
		req.ReviewBaseCommit, req.ReviewPolicyVersion, req.ReviewPolicySHA256,
		req.CommitTree, req.WorkflowDigest, req.SourceProvenanceRef, req.SourceRepoIdentity)
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return "loom:" + hex.EncodeToString(sum[:]), nil
}

func validateTriggerEnvelopeRequest(req DispatchRequest) error {
	binding := []string{req.TriggerEnvelopeID, req.TriggerSource, req.TriggerID, req.Actor,
		req.EvidenceJSON, req.PREventID, req.SourceCommit, req.SourceTree, req.PatchDigest,
		req.RepoAddress, req.PolicyVersion, req.ReviewEventID, req.AuditEventID,
		req.ReviewerPubkey, req.ReviewRootEventID, req.ReviewBaseCommit,
		req.ReviewPolicyVersion, req.ReviewPolicySHA256, req.CommitTree, req.WorkflowDigest,
		req.SourceProvenanceRef, req.SourceRepoIdentity}
	for _, field := range binding {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("complete reviewed trigger authorization is required")
		}
	}
	if !json.Valid([]byte(req.EvidenceJSON)) || !validHexLength(req.TriggerEnvelopeID, 64) ||
		!validHexLength(req.PatchDigest, 64) || !validHexLength(req.PREventID, 64) ||
		!validHexLength(req.ReviewEventID, 64) || !validHexLength(req.AuditEventID, 64) ||
		!validHexLength(req.ReviewerPubkey, 64) || !validHexLength(req.ReviewRootEventID, 64) ||
		!validHexLength(req.ReviewPolicySHA256, 64) || !validHexLength(req.WorkflowDigest, 64) ||
		!validSourceProvenanceRef(req.SourceProvenanceRef) ||
		(!validHexLength(req.SourceCommit, 40) && !validHexLength(req.SourceCommit, 64)) ||
		(!validHexLength(req.SourceTree, 40) && !validHexLength(req.SourceTree, 64)) ||
		(!validHexLength(req.ReviewBaseCommit, 40) && !validHexLength(req.ReviewBaseCommit, 64)) ||
		(!validHexLength(req.CommitTree, 40) && !validHexLength(req.CommitTree, 64)) {
		return fmt.Errorf("trigger envelope contains invalid evidence or an invalid identifier")
	}
	if strings.TrimSpace(req.Actor) != strings.TrimSpace(req.TriggeredBy) {
		return fmt.Errorf("trigger envelope actor does not match dispatch actor")
	}
	if req.TriggerSource == store.TriggerSourceNIP34MergeStatus {
		if !validHexLength(req.PREventID, 64) || !validHexLength(req.StatusEventID, 64) ||
			req.TriggerID != req.StatusEventID ||
			!strings.EqualFold(strings.TrimSpace(req.SourceEventID), strings.TrimSpace(req.StatusEventID)) {
			return fmt.Errorf("NIP-34 merge-trigger linkage is invalid")
		}
	}
	identity, err := store.SanitizeSourceRepoIdentity(req.SourceRepoIdentity)
	if err != nil || identity != req.SourceRepoIdentity {
		return fmt.Errorf("source provenance repository identity is invalid")
	}
	if err := validateCredentialFreeCloneURL(req.CloneURL); err != nil {
		return err
	}
	wantRepo := fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement,
		strings.TrimSpace(req.OwnerPubkey), strings.TrimSpace(req.RepoID))
	if strings.TrimSpace(req.RepoAddress) != wantRepo {
		return fmt.Errorf("merge-trigger repository address does not match dispatch target")
	}
	return nil
}

func validSourceProvenanceRef(value string) bool {
	return strings.HasPrefix(value, store.SourceProvenanceReferencePrefix) &&
		validHexLength(strings.TrimPrefix(value, store.SourceProvenanceReferencePrefix), 64)
}

func validateCredentialFreeCloneURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n\t") {
		return fmt.Errorf("credential-free immutable clone URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("credential-free immutable clone URL is required")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" || u.Path == "" || u.Path == "/" {
			return fmt.Errorf("credential-free immutable clone URL is required")
		}
	case "file":
		if u.Host != "" || !filepath.IsAbs(u.Path) {
			return fmt.Errorf("credential-free immutable clone URL is required")
		}
	default:
		return fmt.Errorf("credential-free immutable clone URL is required")
	}
	return nil
}

func validHexLength(value string, size int) bool {
	value = strings.TrimSpace(value)
	if len(value) != size {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
		"{workflow}":   req.WorkflowPath,
		"{repository}": req.Owner + "/" + req.RepoName, "{repo_id}": req.RepoID,
	}
	for i, word := range words {
		if strings.Contains(word, "{branch}") {
			return "", nil, fmt.Errorf("LOOM_JOB_CMD_TEMPLATE may not use mutable branch identity")
		}
		for placeholder := range replacements {
			if strings.Contains(word, placeholder) && word != placeholder {
				return "", nil, fmt.Errorf("LOOM_JOB_CMD_TEMPLATE request placeholders must be complete argv elements")
			}
		}
		if replacement, ok := replacements[word]; ok {
			words[i] = replacement
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

package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	DefaultLoomJobTTL = 7 * 24 * time.Hour
	DefaultLoomJobCap = 4096

	LoomStatusPending = "pending"
	LoomStatusSuccess = "success"
	LoomStatusFailure = "failure"
	LoomStatusError   = "error"

	LoomSourceLocal          = "local"
	LoomSourceJobStatus      = "30100"
	LoomSourceJobResult      = "5101"
	LoomSourceWorkflowResult = "5402"
)

// LoomJob is an immutable correlation record created before work is dispatched.
type LoomJob struct {
	DispatchKey          string
	TriggerEnvelopeID    string
	WorkflowRunID        string
	JobRequestID         string
	PublisherPub         string
	WorkerPub            string
	Owner                string
	RepoName             string
	RepoID               string
	CommitSHA            string
	WorkflowPath         string
	Branch               string
	WorkflowRunEvent     string
	JobRequestEvent      string
	Status               string
	TerminalSource       string
	LastProtocolEventID  string
	StatusEventCreatedAt int64
	StatusEventID        string
	DeliveryState        string
	DispatchState        string
	DispatchAttempts     int
	DispatchNextAttempt  time.Time
	DispatchLastError    string
	PublishedAt          time.Time
	CancelEvent          string
	CancelEventID        string
	CancelState          string
	CancelAttempts       int
	CancelNextAttempt    time.Time
	CancelLastError      string
	CancelledBy          string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// LoomCashuSpend is the durable single-use payment/change state for one logical dispatch.
type LoomCashuSpend struct {
	DispatchKey, WorkflowRunID, WorkerPub, WorkerAdID, MintURL string
	QuoteID, Token, State                                      string
	Amount, PricePerSecond                                     uint64
	DurationSeconds                                            int64
	ChangeEventID, ChangeToken, ChangeState                    string
	ChangeAmount                                               uint64
	CreatedAt, UpdatedAt                                       time.Time
}

// LoomStatusUpdate is a validated desired Gitea status.
type LoomStatusUpdate struct {
	State           string
	Description     string
	Context         string
	TargetURL       string
	Source          string
	ProtocolEventID string
	EventCreatedAt  int64
	AvailableAt     time.Time
}

// LoomStatusDelivery is a durable, independently retryable Gitea write.
type LoomStatusDelivery struct {
	WorkflowRunID   string
	Owner           string
	RepoName        string
	CommitSHA       string
	State           string
	Description     string
	Context         string
	TargetURL       string
	ProtocolEventID string
	Attempts        int
	NextAttemptAt   time.Time
	LastError       string
}

// EnsureLoomTables initializes Phase-1 Loom correlation and status-outbox tables.
func (s *SQLiteStore) EnsureLoomTables(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store is not configured")
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS loom_jobs (
			workflow_run_id TEXT PRIMARY KEY,
			dispatch_key TEXT NOT NULL DEFAULT '',
			job_request_id TEXT NOT NULL DEFAULT '',
			publisher_pub TEXT NOT NULL DEFAULT '',
			worker_pub TEXT NOT NULL DEFAULT '',
			owner TEXT NOT NULL,
			repo_name TEXT NOT NULL,
			repo_id TEXT NOT NULL,
			commit_sha TEXT NOT NULL,
			workflow_path TEXT NOT NULL,
			branch TEXT NOT NULL DEFAULT '',
			workflow_run_event TEXT NOT NULL DEFAULT '',
			job_request_event TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			terminal_source TEXT NOT NULL DEFAULT '',
			last_protocol_event_id TEXT NOT NULL DEFAULT '',
			status_event_created_at INTEGER NOT NULL DEFAULT 0,
			status_event_id TEXT NOT NULL DEFAULT '',
			delivery_state TEXT NOT NULL DEFAULT 'pending',
			dispatch_state TEXT NOT NULL DEFAULT '',
			dispatch_attempts INTEGER NOT NULL DEFAULT 0,
			dispatch_next_attempt_at INTEGER NOT NULL DEFAULT 0,
			dispatch_last_error TEXT NOT NULL DEFAULT '',
			published_at INTEGER NOT NULL DEFAULT 0,
			cancel_event TEXT NOT NULL DEFAULT '',
			cancel_event_id TEXT NOT NULL DEFAULT '',
			cancel_state TEXT NOT NULL DEFAULT '',
			cancel_attempts INTEGER NOT NULL DEFAULT 0,
			cancel_next_attempt_at INTEGER NOT NULL DEFAULT 0,
			cancel_last_error TEXT NOT NULL DEFAULT '',
			cancelled_by TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_loom_jobs_request
			ON loom_jobs(job_request_id) WHERE job_request_id != ''`,
		`CREATE INDEX IF NOT EXISTS idx_loom_jobs_updated
			ON loom_jobs(updated_at, workflow_run_id)`,
		`CREATE TABLE IF NOT EXISTS loom_job_events (
			event_id TEXT PRIMARY KEY,
			workflow_run_id TEXT NOT NULL,
			seen_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_loom_job_events_job
			ON loom_job_events(workflow_run_id, seen_at)`,
		`CREATE TABLE IF NOT EXISTS loom_trigger_runs (
			trigger_envelope_id TEXT NOT NULL,
			workflow_path TEXT NOT NULL,
			dispatch_key TEXT NOT NULL UNIQUE,
			workflow_run_id TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(trigger_envelope_id, workflow_path)
		)`,
		`CREATE TABLE IF NOT EXISTS loom_status_deliveries (
			workflow_run_id TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			context TEXT NOT NULL,
			target_url TEXT NOT NULL DEFAULT '',
			protocol_event_id TEXT NOT NULL DEFAULT '',
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at INTEGER NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_loom_status_due
			ON loom_status_deliveries(next_attempt_at, workflow_run_id)`,
		`CREATE TABLE IF NOT EXISTS loom_cashu_spends (
			dispatch_key TEXT PRIMARY KEY,
			workflow_run_id TEXT NOT NULL DEFAULT '',
			worker_pub TEXT NOT NULL,
			worker_ad_id TEXT NOT NULL DEFAULT '',
			mint_url TEXT NOT NULL,
			quote_id TEXT NOT NULL DEFAULT '',
			token TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL,
			amount INTEGER NOT NULL,
			price_per_second INTEGER NOT NULL,
			duration_seconds INTEGER NOT NULL,
			change_event_id TEXT NOT NULL DEFAULT '',
			change_token TEXT NOT NULL DEFAULT '',
			change_state TEXT NOT NULL DEFAULT '',
			change_amount INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_loom_cashu_workflow ON loom_cashu_spends(workflow_run_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize Loom persistence: %w", err)
		}
	}
	// Phase 2 adds durable outbound delivery fields to Phase 1 databases.
	for column, definition := range map[string]string{
		"dispatch_key":             "TEXT NOT NULL DEFAULT ''",
		"dispatch_state":           "TEXT NOT NULL DEFAULT ''",
		"dispatch_attempts":        "INTEGER NOT NULL DEFAULT 0",
		"dispatch_next_attempt_at": "INTEGER NOT NULL DEFAULT 0",
		"dispatch_last_error":      "TEXT NOT NULL DEFAULT ''",
		"published_at":             "INTEGER NOT NULL DEFAULT 0",
		"branch":                   "TEXT NOT NULL DEFAULT ''",
		"cancel_event":             "TEXT NOT NULL DEFAULT ''",
		"cancel_event_id":          "TEXT NOT NULL DEFAULT ''",
		"cancel_state":             "TEXT NOT NULL DEFAULT ''",
		"cancel_attempts":          "INTEGER NOT NULL DEFAULT 0",
		"cancel_next_attempt_at":   "INTEGER NOT NULL DEFAULT 0",
		"cancel_last_error":        "TEXT NOT NULL DEFAULT ''",
		"cancelled_by":             "TEXT NOT NULL DEFAULT ''",
		"worker_ad_id":             "TEXT NOT NULL DEFAULT ''",
	} {
		table := "loom_jobs"
		if column == "worker_ad_id" {
			table = "loom_cashu_spends"
		}
		if err := ensureSQLiteColumn(s.db, table, column, definition); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return fmt.Errorf("migrate Loom %s: %w", column, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_loom_jobs_dispatch
		ON loom_jobs(dispatch_key) WHERE dispatch_key != ''`); err != nil {
		return fmt.Errorf("initialize Loom dispatch index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_loom_dispatch_due
		ON loom_jobs(dispatch_state, dispatch_next_attempt_at, workflow_run_id)`); err != nil {
		return fmt.Errorf("initialize Loom dispatch due index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_loom_cancel_due
		ON loom_jobs(cancel_state, cancel_next_attempt_at, workflow_run_id)`); err != nil {
		return fmt.Errorf("initialize Loom cancellation due index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_loom_ref_active
		ON loom_jobs(owner, repo_name, repo_id, workflow_path, branch, status)`); err != nil {
		return fmt.Errorf("initialize Loom supersession index: %w", err)
	}
	return nil
}

// SaveLoomJob persists an immutable attempt and bounds the table by TTL and row cap.
func (s *SQLiteStore) SaveLoomJob(ctx context.Context, job LoomJob, now time.Time, ttl time.Duration, maxRows int) error {
	normalizeLoomJob(&job)
	if err := validateLoomJob(job); err != nil {
		return err
	}
	now, ttl, maxRows = normalizeLoomBounds(now, ttl, maxRows)
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	if err := s.EnsureLoomTables(ctx); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO loom_jobs(
			workflow_run_id, job_request_id, publisher_pub, worker_pub, owner, repo_name, repo_id,
			commit_sha, workflow_path, branch, workflow_run_event, job_request_event, status, delivery_state,
			created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
	`, job.WorkflowRunID, job.JobRequestID, job.PublisherPub, job.WorkerPub, job.Owner, job.RepoName,
		job.RepoID, job.CommitSHA, job.WorkflowPath, job.Branch, job.WorkflowRunEvent, job.JobRequestEvent,
		LoomStatusPending, job.CreatedAt.UTC().Unix(), now.Unix())
	if err != nil {
		return fmt.Errorf("save Loom job: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		existing, err := getLoomJobTx(ctx, tx, "workflow_run_id", job.WorkflowRunID)
		if err != nil {
			return err
		}
		if !sameLoomIdentity(existing, job) {
			return fmt.Errorf("Loom workflow run %q immutable identity mismatch", job.WorkflowRunID)
		}
	}
	if err := sweepLoomJobsTx(ctx, tx, now, ttl, maxRows); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimLoomJobStatus atomically inserts a new immutable local attempt and its
// first status outbox row. It returns false for an already-claimed identical
// attempt, so relay replay and Nostr/Gitea delivery failures cannot re-run CI.
func (s *SQLiteStore) ClaimLoomJobStatus(ctx context.Context, job LoomJob, update LoomStatusUpdate, now time.Time, ttl time.Duration, maxRows int) (bool, error) {
	normalizeLoomJob(&job)
	normalizeLoomStatus(&update)
	if err := validateLoomJob(job); err != nil {
		return false, err
	}
	if !validLoomState(update.State) || update.Context == "" {
		return false, fmt.Errorf("complete initial Loom status is required")
	}
	now, ttl, maxRows = normalizeLoomBounds(now, ttl, maxRows)
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if update.AvailableAt.IsZero() {
		update.AvailableAt = now
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	existing, err := getLoomJobTx(ctx, tx, "workflow_run_id", job.WorkflowRunID)
	if err == nil {
		if !sameLoomIdentity(existing, job) {
			return false, fmt.Errorf("Loom workflow run %q immutable identity mismatch", job.WorkflowRunID)
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	if err := sweepLoomJobsTx(ctx, tx, now, ttl, maxRows-1); err != nil {
		return false, err
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO loom_jobs(
			workflow_run_id, job_request_id, publisher_pub, worker_pub, owner, repo_name, repo_id,
			commit_sha, workflow_path, branch, workflow_run_event, job_request_event, status, terminal_source,
			last_protocol_event_id, delivery_state, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
	`, job.WorkflowRunID, job.JobRequestID, job.PublisherPub, job.WorkerPub, job.Owner, job.RepoName,
		job.RepoID, job.CommitSHA, job.WorkflowPath, job.Branch, job.WorkflowRunEvent, job.JobRequestEvent,
		update.State, "", update.ProtocolEventID, job.CreatedAt.UTC().Unix(), now.Unix())
	if err != nil {
		return false, fmt.Errorf("claim Loom job: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if inserted == 0 {
		return false, fmt.Errorf("Loom dispatch identity conflicts with an existing job request")
	}
	if update.ProtocolEventID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO loom_job_events(event_id, workflow_run_id, seen_at) VALUES(?, ?, ?)`,
			update.ProtocolEventID, job.WorkflowRunID, now.Unix()); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loom_status_deliveries(
			workflow_run_id, state, description, context, target_url, protocol_event_id,
			attempts, next_attempt_at, last_error, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, 0, ?, '', ?)
	`, job.WorkflowRunID, update.State, update.Description, update.Context, update.TargetURL,
		update.ProtocolEventID, update.AvailableAt.Unix(), now.Unix()); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ClaimLoomOutbound atomically persists an immutable outbound attempt, its exact
// signed events, and the initial pending Gitea status before any relay publish.
// A duplicate logical dispatch returns the previously stored attempt so callers
// can republish the same event IDs instead of minting a second job.
func (s *SQLiteStore) ClaimLoomOutbound(ctx context.Context, job LoomJob, update LoomStatusUpdate, now time.Time, ttl time.Duration, maxRows int) (LoomJob, bool, error) {
	normalizeLoomJob(&job)
	normalizeLoomStatus(&update)
	if err := validateLoomJob(job); err != nil {
		return LoomJob{}, false, err
	}
	if job.DispatchKey == "" || job.JobRequestID == "" || job.PublisherPub == "" || job.WorkerPub == "" ||
		job.WorkflowRunEvent == "" || job.JobRequestEvent == "" {
		return LoomJob{}, false, fmt.Errorf("complete outbound Loom dispatch is required")
	}
	if !validLoomState(update.State) || update.Context == "" {
		return LoomJob{}, false, fmt.Errorf("complete initial Loom status is required")
	}
	now, ttl, maxRows = normalizeLoomBounds(now, ttl, maxRows)
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if update.AvailableAt.IsZero() {
		update.AvailableAt = now
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoomJob{}, false, err
	}
	defer tx.Rollback()
	existing, lookupErr := getLoomJobTx(ctx, tx, "dispatch_key", job.DispatchKey)
	if lookupErr == nil {
		if err := claimLoomTriggerRunTx(ctx, tx, job, existing, now); err != nil {
			return LoomJob{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return LoomJob{}, false, err
		}
		return existing, false, nil
	}
	if lookupErr != sql.ErrNoRows {
		return LoomJob{}, false, lookupErr
	}
	if err := sweepLoomJobsTx(ctx, tx, now, ttl, maxRows-1); err != nil {
		return LoomJob{}, false, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO loom_jobs(
			workflow_run_id, dispatch_key, job_request_id, publisher_pub, worker_pub, owner, repo_name, repo_id,
			commit_sha, workflow_path, branch, workflow_run_event, job_request_event, status, terminal_source,
			last_protocol_event_id, delivery_state, dispatch_state, dispatch_next_attempt_at, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, 'pending', 'pending', ?, ?, ?)
	`, job.WorkflowRunID, job.DispatchKey, job.JobRequestID, job.PublisherPub, job.WorkerPub,
		job.Owner, job.RepoName, job.RepoID, job.CommitSHA, job.WorkflowPath, job.Branch,
		job.WorkflowRunEvent, job.JobRequestEvent, update.State, update.ProtocolEventID,
		now.Unix(), job.CreatedAt.UTC().Unix(), now.Unix())
	if err != nil {
		return LoomJob{}, false, fmt.Errorf("claim outbound Loom job: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return LoomJob{}, false, err
	}
	if inserted == 0 {
		existing, lookupErr := getLoomJobTx(ctx, tx, "dispatch_key", job.DispatchKey)
		if lookupErr != nil {
			return LoomJob{}, false, fmt.Errorf("Loom dispatch identity conflicts with an existing attempt: %w", lookupErr)
		}
		if err := tx.Commit(); err != nil {
			return LoomJob{}, false, err
		}
		return existing, false, nil
	}
	if err := claimLoomTriggerRunTx(ctx, tx, job, job, now); err != nil {
		return LoomJob{}, false, err
	}
	if update.ProtocolEventID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO loom_job_events(event_id, workflow_run_id, seen_at) VALUES(?, ?, ?)`,
			update.ProtocolEventID, job.WorkflowRunID, now.Unix()); err != nil {
			return LoomJob{}, false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loom_status_deliveries(
			workflow_run_id, state, description, context, target_url, protocol_event_id,
			attempts, next_attempt_at, last_error, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, 0, ?, '', ?)
	`, job.WorkflowRunID, update.State, update.Description, update.Context, update.TargetURL,
		update.ProtocolEventID, update.AvailableAt.Unix(), now.Unix()); err != nil {
		return LoomJob{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return LoomJob{}, false, err
	}
	job.Status = update.State
	job.DeliveryState = "pending"
	job.DispatchState = "pending"
	job.DispatchNextAttempt = now
	job.UpdatedAt = now
	return job, true, nil
}

// ReserveLoomCashuSpend durably fixes worker, mint, price, duration, and amount
// before the wallet is asked to spend. A reserved row without a token is an
// ambiguous crash state and must never be paid again automatically.
func (s *SQLiteStore) ReserveLoomCashuSpend(ctx context.Context, spend LoomCashuSpend, now time.Time) (LoomCashuSpend, bool, error) {
	normalizeLoomCashuSpend(&spend)
	if spend.DispatchKey == "" || spend.WorkerPub == "" || spend.WorkerAdID == "" || spend.MintURL == "" || spend.Amount == 0 ||
		spend.Amount > math.MaxInt64 || spend.PricePerSecond == 0 || spend.PricePerSecond > math.MaxInt64 || spend.DurationSeconds <= 0 {
		return LoomCashuSpend{}, false, fmt.Errorf("complete bounded Loom Cashu spend is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomCashuSpend{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoomCashuSpend{}, false, err
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `DELETE FROM loom_cashu_spends WHERE updated_at < ?`, now.Add(-DefaultLoomJobTTL).Unix())
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO loom_cashu_spends(
			dispatch_key, worker_pub, worker_ad_id, mint_url, state, amount, price_per_second,
			duration_seconds, created_at, updated_at
		) VALUES(?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?)
	`, spend.DispatchKey, spend.WorkerPub, spend.WorkerAdID, spend.MintURL, spend.Amount, spend.PricePerSecond,
		spend.DurationSeconds, now.Unix(), now.Unix())
	if err != nil {
		return LoomCashuSpend{}, false, fmt.Errorf("reserve Loom Cashu spend: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return LoomCashuSpend{}, false, err
	}
	stored, err := getLoomCashuSpendTx(ctx, tx, spend.DispatchKey)
	if err != nil {
		return LoomCashuSpend{}, false, err
	}
	if !sameLoomCashuSpend(stored, spend) {
		return LoomCashuSpend{}, false, fmt.Errorf("Loom Cashu spend identity mismatch")
	}
	if err := tx.Commit(); err != nil {
		return LoomCashuSpend{}, false, err
	}
	return stored, inserted > 0, nil
}

// CompleteLoomCashuSpend persists the exact token before any dispatch publish.
func (s *SQLiteStore) CompleteLoomCashuSpend(ctx context.Context, dispatchKey, quoteID, token string, now time.Time) (LoomCashuSpend, error) {
	dispatchKey, quoteID, token = strings.TrimSpace(dispatchKey), strings.TrimSpace(quoteID), strings.TrimSpace(token)
	if dispatchKey == "" || quoteID == "" || token == "" {
		return LoomCashuSpend{}, fmt.Errorf("complete Loom Cashu token state is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomCashuSpend{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoomCashuSpend{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE loom_cashu_spends SET quote_id = ?, token = ?, state = 'ready', updated_at = ?
		WHERE dispatch_key = ? AND state = 'reserved' AND token = ''`, quoteID, token, now.Unix(), dispatchKey)
	if err != nil {
		return LoomCashuSpend{}, err
	}
	stored, err := getLoomCashuSpendTx(ctx, tx, dispatchKey)
	if err != nil {
		return LoomCashuSpend{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 && (stored.State != "ready" || stored.QuoteID != quoteID || stored.Token != token) {
		return LoomCashuSpend{}, fmt.Errorf("Loom Cashu spend was not in a completable state")
	}
	if err := tx.Commit(); err != nil {
		return LoomCashuSpend{}, err
	}
	return stored, nil
}

func (s *SQLiteStore) GetLoomCashuSpend(ctx context.Context, dispatchKey string) (LoomCashuSpend, error) {
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomCashuSpend{}, err
	}
	return scanLoomCashuSpend(s.db.QueryRowContext(ctx, loomCashuSelectSQL()+" WHERE dispatch_key = ?", strings.TrimSpace(dispatchKey)))
}

func (s *SQLiteStore) AttachLoomCashuSpend(ctx context.Context, dispatchKey, workflowRunID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE loom_cashu_spends SET workflow_run_id = ?, updated_at = ?
		WHERE dispatch_key = ? AND state = 'ready' AND (workflow_run_id = '' OR workflow_run_id = ?)`,
		strings.TrimSpace(workflowRunID), now.Unix(), strings.TrimSpace(dispatchKey), strings.TrimSpace(workflowRunID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("ready Loom Cashu spend not found")
	}
	return nil
}

// ClaimLoomCashuChange makes redemption event-idempotent. A duplicate or an
// ambiguous redeeming state is never submitted to the mint a second time.
func (s *SQLiteStore) ClaimLoomCashuChange(ctx context.Context, dispatchKey, eventID, token string, now time.Time) (bool, error) {
	dispatchKey, eventID, token = strings.TrimSpace(dispatchKey), strings.TrimSpace(eventID), strings.TrimSpace(token)
	if dispatchKey == "" || eventID == "" || token == "" {
		return false, fmt.Errorf("complete Loom Cashu change is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	spend, err := getLoomCashuSpendTx(ctx, tx, dispatchKey)
	if err != nil {
		return false, err
	}
	if spend.State != "ready" {
		return false, fmt.Errorf("Loom Cashu spend is not ready")
	}
	if spend.ChangeEventID != "" {
		if spend.ChangeEventID != eventID || spend.ChangeToken != token {
			return false, fmt.Errorf("Loom Cashu change identity mismatch")
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE loom_cashu_spends SET change_event_id = ?, change_token = ?,
		change_state = 'redeeming', updated_at = ? WHERE dispatch_key = ? AND change_event_id = ''`,
		eventID, token, now.Unix(), dispatchKey)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) MarkLoomCashuChangeRedeemed(ctx context.Context, dispatchKey, eventID string, amount uint64, now time.Time) error {
	if amount > math.MaxInt64 {
		return fmt.Errorf("Cashu change amount exceeds persistence bound")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE loom_cashu_spends SET change_state = 'redeemed', change_amount = ?, updated_at = ?
		WHERE dispatch_key = ? AND change_event_id = ? AND change_state = 'redeeming'`,
		amount, now.Unix(), strings.TrimSpace(dispatchKey), strings.TrimSpace(eventID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("redeeming Loom Cashu change not found")
	}
	return nil
}

// GetLoomJobByWorkflowRunID resolves a 5402 or local run.
func (s *SQLiteStore) GetLoomJobByWorkflowRunID(ctx context.Context, id string) (LoomJob, error) {
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, err
	}
	return getLoomJobRow(s.db.QueryRowContext(ctx, loomJobSelectSQL()+" WHERE workflow_run_id = ?", strings.TrimSpace(id)))
}

// GetLoomJobByRequestID resolves a 30100/5101 job request.
func (s *SQLiteStore) GetLoomJobByRequestID(ctx context.Context, id string) (LoomJob, error) {
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, err
	}
	return getLoomJobRow(s.db.QueryRowContext(ctx, loomJobSelectSQL()+" WHERE job_request_id = ?", strings.TrimSpace(id)))
}

// GetLoomJobByDispatchKey resolves a logical trigger to its immutable signed events.
func (s *SQLiteStore) GetLoomJobByDispatchKey(ctx context.Context, key string) (LoomJob, error) {
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, err
	}
	return getLoomJobRow(s.db.QueryRowContext(ctx, loomJobSelectSQL()+" WHERE dispatch_key = ?", strings.TrimSpace(key)))
}

// GetLoomJobByTriggerEnvelope resolves the one durable run correlated to an
// immutable trigger identity and exact workflow. Retry ingestion uses this to
// observe terminal state without deriving a new dispatch key.
func (s *SQLiteStore) GetLoomJobByTriggerEnvelope(ctx context.Context, envelopeID, workflowPath string) (LoomJob, error) {
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, err
	}
	envelopeID, workflowPath = strings.TrimSpace(envelopeID), strings.TrimSpace(workflowPath)
	var workflowRunID string
	err := s.db.QueryRowContext(ctx, `SELECT workflow_run_id FROM loom_trigger_runs
		WHERE trigger_envelope_id = ? AND workflow_path = ?`, envelopeID, workflowPath).Scan(&workflowRunID)
	if err != nil {
		return LoomJob{}, err
	}
	job, err := getLoomJobRow(s.db.QueryRowContext(ctx, loomJobSelectSQL()+
		" WHERE workflow_run_id = ?", workflowRunID))
	if err != nil {
		return LoomJob{}, err
	}
	job.TriggerEnvelopeID = envelopeID
	return job, nil
}

// ListDueLoomDispatches returns persisted signed events that still need relay acceptance.
func (s *SQLiteStore) ListDueLoomDispatches(ctx context.Context, now time.Time, limit int) ([]LoomJob, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, loomJobSelectSQL()+
		" WHERE dispatch_state != '' AND dispatch_state != 'published' AND dispatch_next_attempt_at <= ?"+
		" ORDER BY dispatch_next_attempt_at, workflow_run_id LIMIT ?", now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LoomJob, 0)
	for rows.Next() {
		job, err := getLoomJobRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// MarkLoomDispatchPublished records that both exact signed events reached a relay.
func (s *SQLiteStore) MarkLoomDispatchPublished(ctx context.Context, workflowRunID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE loom_jobs SET dispatch_state = 'published', dispatch_last_error = '',
			published_at = ?, updated_at = ? WHERE workflow_run_id = ?
	`, now.Unix(), now.Unix(), strings.TrimSpace(workflowRunID))
	return err
}

// MarkLoomDispatchRetry records a publish failure without changing signed bytes.
func (s *SQLiteStore) MarkLoomDispatchRetry(ctx context.Context, workflowRunID string, next time.Time, lastErr string) error {
	if next.IsZero() {
		next = time.Now().UTC()
	}
	if len(lastErr) > 1000 {
		lastErr = lastErr[:1000]
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE loom_jobs SET dispatch_state = 'retrying', dispatch_attempts = dispatch_attempts + 1,
			dispatch_next_attempt_at = ?, dispatch_last_error = ?, updated_at = ?
		WHERE workflow_run_id = ? AND dispatch_state != 'published'
	`, next.Unix(), lastErr, time.Now().UTC().Unix(), strings.TrimSpace(workflowRunID))
	return err
}

// ListSupersededLoomJobs returns older, non-terminal outbound runs for the same ref.
func (s *SQLiteStore) ListSupersededLoomJobs(ctx context.Context, newer LoomJob, limit int) ([]LoomJob, error) {
	normalizeLoomJob(&newer)
	if newer.WorkflowRunID == "" || newer.Owner == "" || newer.RepoName == "" || newer.RepoID == "" ||
		newer.WorkflowPath == "" || newer.Branch == "" {
		return nil, fmt.Errorf("complete Loom supersession identity is required")
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, loomJobSelectSQL()+`
		WHERE workflow_run_id != ? AND dispatch_key != '' AND owner = ? AND repo_name = ? AND repo_id = ?
			AND workflow_path = ? AND branch = ? AND status = ?
			AND rowid < (SELECT rowid FROM loom_jobs WHERE workflow_run_id = ?)
		ORDER BY created_at, workflow_run_id LIMIT ?`, newer.WorkflowRunID, newer.Owner, newer.RepoName,
		newer.RepoID, newer.WorkflowPath, newer.Branch, LoomStatusPending, newer.WorkflowRunID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []LoomJob
	for rows.Next() {
		job, err := getLoomJobRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ClaimLoomCancellation persists the exact signed kind-5102 before publishing it.
func (s *SQLiteStore) ClaimLoomCancellation(ctx context.Context, workflowRunID, cancelledBy, eventID, eventJSON string, now time.Time) (LoomJob, bool, error) {
	workflowRunID, cancelledBy = strings.TrimSpace(workflowRunID), strings.TrimSpace(cancelledBy)
	eventID, eventJSON = strings.TrimSpace(eventID), strings.TrimSpace(eventJSON)
	if workflowRunID == "" || cancelledBy == "" || eventID == "" || eventJSON == "" {
		return LoomJob{}, false, fmt.Errorf("complete Loom cancellation is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return LoomJob{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoomJob{}, false, err
	}
	defer tx.Rollback()
	job, err := getLoomJobTx(ctx, tx, "workflow_run_id", workflowRunID)
	if err != nil {
		return LoomJob{}, false, err
	}
	if isLoomTerminal(job.Status) {
		if err := tx.Commit(); err != nil {
			return LoomJob{}, false, err
		}
		return job, false, nil
	}
	if job.CancelState != "" {
		if job.CancelledBy != cancelledBy || job.CancelEventID != eventID || job.CancelEvent != eventJSON {
			return LoomJob{}, false, fmt.Errorf("Loom cancellation identity mismatch")
		}
		if err := tx.Commit(); err != nil {
			return LoomJob{}, false, err
		}
		return job, false, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE loom_jobs SET cancel_event = ?, cancel_event_id = ?, cancel_state = 'pending',
		cancel_next_attempt_at = ?, cancelled_by = ?, updated_at = ? WHERE workflow_run_id = ? AND cancel_state = ''`,
		eventJSON, eventID, now.Unix(), cancelledBy, now.Unix(), workflowRunID)
	if err != nil {
		return LoomJob{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return LoomJob{}, false, err
	}
	job.CancelEvent, job.CancelEventID, job.CancelState = eventJSON, eventID, "pending"
	job.CancelNextAttempt, job.CancelledBy = now, cancelledBy
	return job, true, nil
}

func (s *SQLiteStore) ListDueLoomCancellations(ctx context.Context, now time.Time, limit int) ([]LoomJob, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, loomJobSelectSQL()+`
		WHERE cancel_state != '' AND cancel_state != 'published' AND cancel_next_attempt_at <= ?
		ORDER BY cancel_next_attempt_at, workflow_run_id LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []LoomJob
	for rows.Next() {
		job, err := getLoomJobRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *SQLiteStore) MarkLoomCancellationPublished(ctx context.Context, workflowRunID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE loom_jobs SET cancel_state = 'published', cancel_last_error = '',
		updated_at = ? WHERE workflow_run_id = ?`, now.Unix(), strings.TrimSpace(workflowRunID))
	return err
}

func (s *SQLiteStore) MarkLoomCancellationRetry(ctx context.Context, workflowRunID string, next time.Time, lastErr string) error {
	if next.IsZero() {
		next = time.Now().UTC()
	}
	if len(lastErr) > 1000 {
		lastErr = lastErr[:1000]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE loom_jobs SET cancel_state = 'retrying',
		cancel_attempts = cancel_attempts + 1, cancel_next_attempt_at = ?, cancel_last_error = ?, updated_at = ?
		WHERE workflow_run_id = ? AND cancel_state != 'published'`, next.Unix(), lastErr,
		time.Now().UTC().Unix(), strings.TrimSpace(workflowRunID))
	return err
}

// ApplyLoomStatus atomically enforces deduplication, replaceable ordering,
// terminal precedence, and durable status enqueueing.
func (s *SQLiteStore) ApplyLoomStatus(ctx context.Context, workflowRunID string, update LoomStatusUpdate, now time.Time) (bool, error) {
	workflowRunID = strings.TrimSpace(workflowRunID)
	normalizeLoomStatus(&update)
	if workflowRunID == "" || !validLoomState(update.State) || update.Context == "" {
		return false, fmt.Errorf("complete Loom status update is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if update.AvailableAt.IsZero() {
		update.AvailableAt = now
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	job, err := getLoomJobTx(ctx, tx, "workflow_run_id", workflowRunID)
	if err != nil {
		return false, err
	}
	if update.ProtocolEventID != "" {
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO loom_job_events(event_id, workflow_run_id, seen_at) VALUES(?, ?, ?)`,
			update.ProtocolEventID, workflowRunID, now.Unix())
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
	}

	if update.Source == LoomSourceJobStatus && job.StatusEventID != "" {
		if update.EventCreatedAt < job.StatusEventCreatedAt ||
			(update.EventCreatedAt == job.StatusEventCreatedAt && update.ProtocolEventID >= job.StatusEventID) {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			return false, nil
		}
	}

	currentTerminal := isLoomTerminal(job.Status)
	incomingTerminal := isLoomTerminal(update.State)
	if currentTerminal {
		if !incomingTerminal || loomTerminalRank(update.Source) <= loomTerminalRank(job.TerminalSource) {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			return false, nil
		}
	}

	terminalSource := job.TerminalSource
	if incomingTerminal {
		terminalSource = update.Source
	}
	statusCreatedAt, statusEventID := job.StatusEventCreatedAt, job.StatusEventID
	if update.Source == LoomSourceJobStatus {
		statusCreatedAt, statusEventID = update.EventCreatedAt, update.ProtocolEventID
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE loom_jobs SET status = ?, terminal_source = ?, last_protocol_event_id = ?,
			status_event_created_at = ?, status_event_id = ?, delivery_state = 'pending', updated_at = ?
		WHERE workflow_run_id = ?
	`, update.State, terminalSource, update.ProtocolEventID, statusCreatedAt, statusEventID, now.Unix(), workflowRunID)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO loom_status_deliveries(
			workflow_run_id, state, description, context, target_url, protocol_event_id,
			attempts, next_attempt_at, last_error, updated_at
		) VALUES(?, ?, ?, ?, ?, ?, 0, ?, '', ?)
		ON CONFLICT(workflow_run_id) DO UPDATE SET
			state = excluded.state, description = excluded.description, context = excluded.context,
			target_url = excluded.target_url, protocol_event_id = excluded.protocol_event_id,
			attempts = 0, next_attempt_at = excluded.next_attempt_at, last_error = '', updated_at = excluded.updated_at
	`, workflowRunID, update.State, update.Description, update.Context, update.TargetURL,
		update.ProtocolEventID, update.AvailableAt.Unix(), now.Unix())
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ListDueLoomStatusDeliveries returns retryable status writes without running CI.
func (s *SQLiteStore) ListDueLoomStatusDeliveries(ctx context.Context, now time.Time, limit int) ([]LoomStatusDelivery, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.workflow_run_id, j.owner, j.repo_name, j.commit_sha, d.state, d.description,
			d.context, d.target_url, d.protocol_event_id, d.attempts, d.next_attempt_at, d.last_error
		FROM loom_status_deliveries d JOIN loom_jobs j USING(workflow_run_id)
		WHERE d.next_attempt_at <= ?
		ORDER BY d.next_attempt_at, d.workflow_run_id LIMIT ?
	`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoomStatusDelivery
	for rows.Next() {
		var d LoomStatusDelivery
		var next int64
		if err := rows.Scan(&d.WorkflowRunID, &d.Owner, &d.RepoName, &d.CommitSHA, &d.State,
			&d.Description, &d.Context, &d.TargetURL, &d.ProtocolEventID, &d.Attempts, &next, &d.LastError); err != nil {
			return nil, err
		}
		d.NextAttemptAt = time.Unix(next, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkLoomStatusDelivered removes exactly the delivered outbox version.
func (s *SQLiteStore) MarkLoomStatusDelivered(ctx context.Context, workflowRunID, eventID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM loom_status_deliveries WHERE workflow_run_id = ? AND protocol_event_id = ?`,
		workflowRunID, eventID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		_, err = tx.ExecContext(ctx, `UPDATE loom_jobs SET delivery_state = 'delivered', updated_at = ? WHERE workflow_run_id = ?`,
			now.Unix(), workflowRunID)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkLoomStatusRetry records a delivery failure. A newer queued version is untouched.
func (s *SQLiteStore) MarkLoomStatusRetry(ctx context.Context, workflowRunID, eventID string, next time.Time, lastErr string, awaitingGitObject bool) error {
	if next.IsZero() {
		next = time.Now().UTC()
	}
	if len(lastErr) > 1000 {
		lastErr = lastErr[:1000]
	}
	if err := s.EnsureLoomTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE loom_status_deliveries SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
		WHERE workflow_run_id = ? AND protocol_event_id = ?
	`, next.Unix(), lastErr, workflowRunID, eventID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		state := "retrying"
		if awaitingGitObject {
			state = "awaiting_git_object"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE loom_jobs SET delivery_state = ?, updated_at = ? WHERE workflow_run_id = ?`,
			state, time.Now().UTC().Unix(), workflowRunID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SweepLoomJobs applies the configured resource bounds and returns deleted rows.
func (s *SQLiteStore) SweepLoomJobs(ctx context.Context, now time.Time, ttl time.Duration, maxRows int) (int64, error) {
	now, ttl, maxRows = normalizeLoomBounds(now, ttl, maxRows)
	if err := s.EnsureLoomTables(ctx); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	before, err := loomJobCountTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if err := sweepLoomJobsTx(ctx, tx, now, ttl, maxRows); err != nil {
		return 0, err
	}
	after, err := loomJobCountTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	return before - after, tx.Commit()
}

func sweepLoomJobsTx(ctx context.Context, tx *sql.Tx, now time.Time, ttl time.Duration, maxRows int) error {
	if maxRows < 0 {
		maxRows = 0
	}
	cutoff := now.Add(-ttl).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_status_deliveries WHERE workflow_run_id IN (SELECT workflow_run_id FROM loom_jobs WHERE updated_at < ?)`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_job_events WHERE workflow_run_id IN (SELECT workflow_run_id FROM loom_jobs WHERE updated_at < ?)`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_cashu_spends WHERE updated_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_jobs WHERE updated_at < ?`, cutoff); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM loom_jobs`).Scan(&count); err != nil {
		return err
	}
	excess := count - maxRows
	if excess <= 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_status_deliveries WHERE workflow_run_id IN (
		SELECT workflow_run_id FROM loom_jobs ORDER BY updated_at, workflow_run_id LIMIT ?
	)`, excess); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_job_events WHERE workflow_run_id IN (
		SELECT workflow_run_id FROM loom_jobs ORDER BY updated_at, workflow_run_id LIMIT ?
	)`, excess); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM loom_cashu_spends WHERE workflow_run_id IN (
		SELECT workflow_run_id FROM loom_jobs ORDER BY updated_at, workflow_run_id LIMIT ?
	)`, excess); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM loom_jobs WHERE workflow_run_id IN (
		SELECT workflow_run_id FROM loom_jobs ORDER BY updated_at, workflow_run_id LIMIT ?
	)`, excess)
	return err
}

func loomJobSelectSQL() string {
	return `SELECT dispatch_key, workflow_run_id, job_request_id, publisher_pub, worker_pub, owner, repo_name, repo_id,
		commit_sha, workflow_path, branch, workflow_run_event, job_request_event, status, terminal_source,
		last_protocol_event_id, status_event_created_at, status_event_id, delivery_state,
		dispatch_state, dispatch_attempts, dispatch_next_attempt_at, dispatch_last_error, published_at,
		cancel_event, cancel_event_id, cancel_state, cancel_attempts, cancel_next_attempt_at,
		cancel_last_error, cancelled_by, created_at, updated_at FROM loom_jobs`
}

type loomScanner interface{ Scan(...any) error }

func getLoomJobRow(row loomScanner) (LoomJob, error) {
	var job LoomJob
	var dispatchNext, published, cancelNext, created, updated int64
	err := row.Scan(&job.DispatchKey, &job.WorkflowRunID, &job.JobRequestID, &job.PublisherPub, &job.WorkerPub,
		&job.Owner, &job.RepoName, &job.RepoID, &job.CommitSHA, &job.WorkflowPath, &job.Branch,
		&job.WorkflowRunEvent, &job.JobRequestEvent, &job.Status, &job.TerminalSource,
		&job.LastProtocolEventID, &job.StatusEventCreatedAt, &job.StatusEventID,
		&job.DeliveryState, &job.DispatchState, &job.DispatchAttempts, &dispatchNext,
		&job.DispatchLastError, &published, &job.CancelEvent, &job.CancelEventID, &job.CancelState,
		&job.CancelAttempts, &cancelNext, &job.CancelLastError, &job.CancelledBy, &created, &updated)
	if err != nil {
		return LoomJob{}, err
	}
	if dispatchNext > 0 {
		job.DispatchNextAttempt = time.Unix(dispatchNext, 0).UTC()
	}
	if published > 0 {
		job.PublishedAt = time.Unix(published, 0).UTC()
	}
	if cancelNext > 0 {
		job.CancelNextAttempt = time.Unix(cancelNext, 0).UTC()
	}
	job.CreatedAt = time.Unix(created, 0).UTC()
	job.UpdatedAt = time.Unix(updated, 0).UTC()
	return job, nil
}

func getLoomJobTx(ctx context.Context, tx *sql.Tx, column, value string) (LoomJob, error) {
	if column != "workflow_run_id" && column != "job_request_id" && column != "dispatch_key" {
		return LoomJob{}, fmt.Errorf("invalid Loom lookup column")
	}
	return getLoomJobRow(tx.QueryRowContext(ctx, loomJobSelectSQL()+" WHERE "+column+" = ?", value))
}

func claimLoomTriggerRunTx(ctx context.Context, tx *sql.Tx, requested, stored LoomJob, now time.Time) error {
	if requested.TriggerEnvelopeID == "" {
		return nil
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO loom_trigger_runs(
		trigger_envelope_id, workflow_path, dispatch_key, workflow_run_id, created_at
	) VALUES(?, ?, ?, ?, ?)`, requested.TriggerEnvelopeID, requested.WorkflowPath,
		requested.DispatchKey, stored.WorkflowRunID, now.Unix())
	if err != nil {
		return fmt.Errorf("claim Loom trigger correlation: %w", err)
	}
	if inserted, _ := res.RowsAffected(); inserted > 0 {
		return nil
	}
	var dispatchKey, workflowRunID string
	err = tx.QueryRowContext(ctx, `SELECT dispatch_key, workflow_run_id FROM loom_trigger_runs
		WHERE trigger_envelope_id = ? AND workflow_path = ?`, requested.TriggerEnvelopeID,
		requested.WorkflowPath).Scan(&dispatchKey, &workflowRunID)
	if err != nil {
		return &TriggerConflictError{Source: "workflow", TriggerID: requested.TriggerEnvelopeID + "/" + requested.WorkflowPath}
	}
	if dispatchKey != requested.DispatchKey || workflowRunID != stored.WorkflowRunID {
		return &TriggerConflictError{Source: "workflow", TriggerID: requested.TriggerEnvelopeID + "/" + requested.WorkflowPath}
	}
	return nil
}

func loomJobCountTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var count int64
	err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM loom_jobs`).Scan(&count)
	return count, err
}

func loomCashuSelectSQL() string {
	return `SELECT dispatch_key, workflow_run_id, worker_pub, worker_ad_id, mint_url, quote_id, token, state,
		amount, price_per_second, duration_seconds, change_event_id, change_token, change_state,
		change_amount, created_at, updated_at FROM loom_cashu_spends`
}

func scanLoomCashuSpend(row loomScanner) (LoomCashuSpend, error) {
	var spend LoomCashuSpend
	var amount, price, changeAmount, created, updated int64
	err := row.Scan(&spend.DispatchKey, &spend.WorkflowRunID, &spend.WorkerPub, &spend.WorkerAdID, &spend.MintURL,
		&spend.QuoteID, &spend.Token, &spend.State, &amount, &price, &spend.DurationSeconds,
		&spend.ChangeEventID, &spend.ChangeToken, &spend.ChangeState, &changeAmount, &created, &updated)
	if err != nil {
		return LoomCashuSpend{}, err
	}
	if amount < 0 || price < 0 || changeAmount < 0 {
		return LoomCashuSpend{}, fmt.Errorf("invalid negative Loom Cashu amount")
	}
	spend.Amount, spend.PricePerSecond, spend.ChangeAmount = uint64(amount), uint64(price), uint64(changeAmount)
	spend.CreatedAt, spend.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return spend, nil
}

func getLoomCashuSpendTx(ctx context.Context, tx *sql.Tx, dispatchKey string) (LoomCashuSpend, error) {
	return scanLoomCashuSpend(tx.QueryRowContext(ctx, loomCashuSelectSQL()+" WHERE dispatch_key = ?", dispatchKey))
}

func normalizeLoomCashuSpend(spend *LoomCashuSpend) {
	spend.DispatchKey = strings.TrimSpace(spend.DispatchKey)
	spend.WorkflowRunID = strings.TrimSpace(spend.WorkflowRunID)
	spend.WorkerPub = strings.TrimSpace(spend.WorkerPub)
	spend.WorkerAdID = strings.TrimSpace(spend.WorkerAdID)
	spend.MintURL = strings.TrimSpace(spend.MintURL)
	spend.QuoteID = strings.TrimSpace(spend.QuoteID)
	spend.Token = strings.TrimSpace(spend.Token)
	spend.State = strings.TrimSpace(spend.State)
}

func sameLoomCashuSpend(a, b LoomCashuSpend) bool {
	return a.DispatchKey == b.DispatchKey && a.WorkerPub == b.WorkerPub && a.WorkerAdID == b.WorkerAdID && a.MintURL == b.MintURL &&
		a.Amount == b.Amount && a.PricePerSecond == b.PricePerSecond && a.DurationSeconds == b.DurationSeconds
}

func normalizeLoomJob(job *LoomJob) {
	job.DispatchKey = strings.TrimSpace(job.DispatchKey)
	job.TriggerEnvelopeID = strings.TrimSpace(job.TriggerEnvelopeID)
	job.WorkflowRunID = strings.TrimSpace(job.WorkflowRunID)
	job.JobRequestID = strings.TrimSpace(job.JobRequestID)
	job.PublisherPub = strings.TrimSpace(job.PublisherPub)
	job.WorkerPub = strings.TrimSpace(job.WorkerPub)
	job.Owner = strings.TrimSpace(job.Owner)
	job.RepoName = strings.TrimSpace(job.RepoName)
	job.RepoID = strings.TrimSpace(job.RepoID)
	job.CommitSHA = strings.TrimSpace(job.CommitSHA)
	job.WorkflowPath = strings.TrimSpace(job.WorkflowPath)
	job.Branch = strings.TrimSpace(job.Branch)
}

func validateLoomJob(job LoomJob) error {
	if job.WorkflowRunID == "" || job.Owner == "" || job.RepoName == "" || job.RepoID == "" ||
		job.CommitSHA == "" || job.WorkflowPath == "" {
		return fmt.Errorf("complete Loom dispatch identity is required")
	}
	return nil
}

func sameLoomIdentity(a, b LoomJob) bool {
	return a.DispatchKey == b.DispatchKey && a.WorkflowRunID == b.WorkflowRunID && a.JobRequestID == b.JobRequestID &&
		a.PublisherPub == b.PublisherPub && a.WorkerPub == b.WorkerPub &&
		a.Owner == b.Owner && a.RepoName == b.RepoName && a.RepoID == b.RepoID &&
		a.CommitSHA == b.CommitSHA && a.WorkflowPath == b.WorkflowPath && a.Branch == b.Branch &&
		a.WorkflowRunEvent == b.WorkflowRunEvent && a.JobRequestEvent == b.JobRequestEvent
}

func normalizeLoomStatus(update *LoomStatusUpdate) {
	update.State = strings.ToLower(strings.TrimSpace(update.State))
	update.Description = strings.TrimSpace(update.Description)
	update.Context = strings.TrimSpace(update.Context)
	update.TargetURL = strings.TrimSpace(update.TargetURL)
	update.Source = strings.TrimSpace(update.Source)
	update.ProtocolEventID = strings.TrimSpace(update.ProtocolEventID)
}

func normalizeLoomBounds(now time.Time, ttl time.Duration, maxRows int) (time.Time, time.Duration, int) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ttl <= 0 {
		ttl = DefaultLoomJobTTL
	}
	if maxRows <= 0 {
		maxRows = DefaultLoomJobCap
	}
	return now.UTC(), ttl, maxRows
}

func validLoomState(state string) bool {
	switch state {
	case LoomStatusPending, LoomStatusSuccess, LoomStatusFailure, LoomStatusError:
		return true
	default:
		return false
	}
}

func isLoomTerminal(state string) bool {
	return state == LoomStatusSuccess || state == LoomStatusFailure || state == LoomStatusError
}

// LoomJobTerminal reports whether retry must fail closed for a correlated run.
func LoomJobTerminal(job LoomJob) bool { return isLoomTerminal(job.Status) }

func loomTerminalRank(source string) int {
	switch source {
	case LoomSourceWorkflowResult:
		return 4
	case LoomSourceLocal:
		return 3
	case LoomSourceJobResult:
		return 2
	case LoomSourceJobStatus:
		return 1
	default:
		return 0
	}
}

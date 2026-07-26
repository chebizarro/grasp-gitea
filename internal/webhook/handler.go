// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/echofp"
	"github.com/sharegap/grasp-gitea/internal/grasp"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	KindComment       = 1111
	KindPatch         = 1617
	KindPROpen        = 1618
	KindPRUpdate      = 1619
	KindIssue         = 1621
	KindStatusOpen    = 1630
	KindStatusApplied = 1631
	KindStatusClosed  = 1632
	KindStatusDraft   = 1633
	KindNIP32Label    = 1985

	pendingActorEventsMaxPerUser = 500
	pendingActorEventsMaxAge     = 30 * 24 * time.Hour
)

// Publisher is the subset of *publisher.Service that the webhook handler needs
// to sign and publish NIP-34 events. It is defined as an interface so the
// handler can be exercised in tests with a capturing fake instead of a live
// relay connection.
type Publisher interface {
	PublishEvent(ctx context.Context, ev *nostr.Event) error
	RepublishForGiteaRepo(ctx context.Context, giteaRepoID int64) error
	HandleWebhookPushCI(ctx context.Context, giteaRepoID int64, ref, before, after, sourceRelay string) error
	FetchEvent(ctx context.Context, id string) (*nostr.Event, error)
}

type ActorSigner interface {
	Enabled() bool
}

type ActorOutbox interface {
	Enqueue(ctx context.Context, kind int, authorPubkey string, scope string, unsignedEvent *nostr.Event, dedupeKey string) error
}

type ActorIdentityLookup interface {
	GetIdentityLinkByGiteaUserID(ctx context.Context, userID int64) (store.NostrIdentityLink, error)
	GetSignerGrant(ctx context.Context, pubkey string) (store.SignerGrant, error)
}

// Handler handles inbound Gitea webhook events, maps them to NIP-34 Nostr
// events, and publishes via the publisher.
type Handler struct {
	pub             Publisher
	store           *store.SQLiteStore
	secret          string
	logger          *slog.Logger
	actorSigner     ActorSigner
	actorOutbox     ActorOutbox
	actorLookup     ActorIdentityLookup
	repositoriesDir string
	graspPublicURL  string
	now             func() time.Time
	echoGuardWindow time.Duration

	eucMu    sync.Mutex
	eucCache map[int64]string

	deliveryMu        sync.Mutex
	deliveryCreatedAt time.Time
	retriesEnabled    bool
	retryBase         time.Duration
}

// threadRef records the durable event id and author for an issue/PR root.
type threadRef struct {
	EventID string
	Pubkey  string
	Kind    int
}

// New creates a webhook Handler.
func New(pub *publisher.Service, st *store.SQLiteStore, secret string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		store: st, secret: secret, logger: logger, actorLookup: st,
		now: time.Now, echoGuardWindow: store.DefaultEchoGuardWindow,
		retriesEnabled: true, retryBase: 5 * time.Second,
	}
	// Guard against a typed-nil *publisher.Service being stored as a non-nil
	// interface, which would defeat the h.pub == nil checks below.
	if pub != nil {
		h.pub = pub
	}
	// Allow the caller to finish optional signer wiring before replaying rows
	// left pending by a previous process.
	time.AfterFunc(time.Second, h.retryPendingWebhookDeliveries)
	return h
}

func (h *Handler) SetActorSigning(signer ActorSigner, outbox ActorOutbox, lookup ActorIdentityLookup) {
	h.actorSigner = signer
	h.actorOutbox = outbox
	if lookup != nil {
		h.actorLookup = lookup
	}
}

func (h *Handler) SetRepositoriesDir(dir string) {
	h.repositoriesDir = dir
}

// ServeHTTP handles POST /webhook/gitea.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if h.secret != "" && !h.verifyHMAC(r.Header.Get("X-Gitea-Signature"), body) {
		h.logger.Warn("webhook: HMAC validation failed")
		http.Error(w, "signature mismatch", http.StatusUnauthorized)
		return
	}
	if h.store == nil {
		http.Error(w, "webhook persistence unavailable", http.StatusServiceUnavailable)
		return
	}

	eventType := r.Header.Get("X-Gitea-Event")
	deliveryID := strings.TrimSpace(r.Header.Get("X-Gitea-Delivery"))
	if deliveryID == "" {
		deliveryID = strings.TrimSpace(r.Header.Get("X-Gitea-Delivery-ID"))
	}
	if deliveryID == "" {
		sum := sha256.Sum256(append(append([]byte(eventType), 0), body...))
		deliveryID = hex.EncodeToString(sum[:])
	}
	now := time.Now().UTC()
	saved, _, err := h.store.SaveWebhookDelivery(r.Context(), store.WebhookDelivery{
		DeliveryID:    deliveryID,
		EventType:     eventType,
		Payload:       append([]byte(nil), body...),
		CreatedAt:     now,
		NextAttemptAt: now,
	})
	if err != nil {
		h.logger.Error("webhook: failed to persist delivery", "event", eventType, "delivery", deliveryID, "error", err)
		http.Error(w, "webhook persistence failed", http.StatusServiceUnavailable)
		return
	}

	h.logger.Info("webhook: received", "event", eventType, "delivery", deliveryID)
	metrics.IncWebhookEventsReceived()
	if saved.State != store.WebhookDeliveryDone {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		err = h.processPersistedDelivery(ctx, saved)
		cancel()
		if err != nil {
			h.logger.Warn("webhook: delivery remains pending for retry", "event", eventType, "delivery", deliveryID, "error", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleWebhookEvent(ctx context.Context, eventType string, body []byte) error {
	switch eventType {
	case "push":
		return h.handlePush(ctx, body)
	case "create":
		return h.handleCreate(ctx, body)
	case "delete":
		return h.handleDelete(ctx, body)
	case "pull_request":
		return h.handlePR(ctx, body)
	case "issues":
		return h.handleIssue(ctx, body)
	case "issue_comment":
		return h.handleIssueComment(ctx, body)
	case "label":
		return h.handleLabel(ctx, body)
	default:
		h.logger.Debug("webhook: unhandled event type", "event", eventType)
		return nil
	}
}

func (h *Handler) processPersistedDelivery(ctx context.Context, delivery store.WebhookDelivery) error {
	h.deliveryMu.Lock()
	defer h.deliveryMu.Unlock()

	current, err := h.store.GetWebhookDelivery(ctx, delivery.DeliveryID)
	if err != nil {
		return fmt.Errorf("load persisted webhook delivery: %w", err)
	}
	if current.State == store.WebhookDeliveryDone {
		return nil
	}
	h.deliveryCreatedAt = current.CreatedAt
	defer func() { h.deliveryCreatedAt = time.Time{} }()
	err = h.handleWebhookEvent(ctx, current.EventType, current.Payload)
	if err == nil {
		if markErr := h.store.MarkWebhookDeliveryDone(ctx, current.DeliveryID, time.Now().UTC()); markErr != nil {
			return fmt.Errorf("mark webhook delivery done: %w", markErr)
		}
		if current.EventType != "" {
			metrics.IncWebhookEventsPublished()
		}
		return nil
	}

	metrics.IncWebhookEventsFailed()
	delay := h.webhookRetryDelay(current.Attempts + 1)
	if _, markErr := h.store.MarkWebhookDeliveryRetry(context.Background(), current.DeliveryID, time.Now().UTC().Add(delay), err.Error()); markErr != nil {
		return errors.Join(err, fmt.Errorf("record webhook retry: %w", markErr))
	}
	return err
}

func (h *Handler) webhookRetryDelay(attempt int) time.Duration {
	base := h.retryBase
	if base <= 0 {
		base = 5 * time.Second
	}
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for i := 1; i < attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}

func (h *Handler) scheduleWebhookRetry(delay time.Duration) {
	if !h.retriesEnabled {
		return
	}
	if delay <= 0 {
		delay = time.Second
	}
	time.AfterFunc(delay, h.retryPendingWebhookDeliveries)
}

func (h *Handler) retryPendingWebhookDeliveries() {
	if h == nil || h.store == nil {
		return
	}
	defer h.scheduleWebhookRetry(h.webhookRetryDelay(1))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	deliveries, err := h.store.ListDueWebhookDeliveries(ctx, time.Now().UTC(), 25)
	if err != nil {
		h.logger.Warn("webhook: list pending deliveries failed", "error", err)
		return
	}
	for _, delivery := range deliveries {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 30*time.Second)
		err := h.processPersistedDelivery(attemptCtx, delivery)
		attemptCancel()
		if err != nil {
			h.logger.Warn("webhook: retry failed", "delivery", delivery.DeliveryID, "event", delivery.EventType, "error", err)
		}
	}
}

func (h *Handler) verifyHMAC(sig string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// handlePush publishes a kind:30618 repository state event, and for
// refs/nostr/<event-id> pushes also handles kind:1617 patch acknowledgement.
func (h *Handler) handlePush(ctx context.Context, body []byte) error {
	var p PushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse push payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil // not a GRASP-managed repo, ignore
	}

	// refs/nostr/<event-id> — this is a patch push from ngit or compatible tooling.
	// The author should have pre-published a kind:1617 to the relay. If not,
	// we synthesize a minimal patch event from the push metadata.
	if strings.HasPrefix(p.Ref, "refs/nostr/") {
		eventID := strings.TrimPrefix(p.Ref, "refs/nostr/")
		if err := h.handlePatchPush(ctx, eventID, p, mapping); err != nil {
			if errors.Is(err, refsnostr.ErrDifferingTip) {
				return err
			}
			h.logger.Warn("webhook: patch event handling failed (non-fatal)", "event_id", eventID, "error", err)
		}
	}

	if err := h.publishRepoState(ctx, mapping, p.Repository); err != nil {
		return err
	}

	if h.pub != nil {
		if err := h.pub.HandleWebhookPushCI(ctx, p.Repository.ID, p.Ref, p.Before, p.After, "webhook:gitea"); err != nil {
			return err
		}
	}

	return nil
}

// handleCreate publishes kind:30618 for branch/tag creation.
func (h *Handler) handleCreate(ctx context.Context, body []byte) error {
	var p CreatePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse create payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
}

// handleDelete publishes kind:30618 for branch/tag deletion.
func (h *Handler) handleDelete(ctx context.Context, body []byte) error {
	var p DeletePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse delete payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
}

// handlePR publishes NIP-34 PR roots (kind:1618), tip-change updates
// (kind:1619), and status events (kinds:1630-1633). Kind:1619 is reserved
// for synchronized/tip-advancing updates only; close/reopen/edit lifecycle
// actions are represented as status events.
func (h *Handler) handlePR(ctx context.Context, body []byte) error {
	var p PullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse PR payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	if p.Action == "opened" || p.Action == "synchronized" {
		index := p.Number
		if index == 0 {
			index = p.PullRequest.Number
		}
		kind := KindPROpen
		scope := "pr"
		fingerprint := echofp.PROpen(p.PullRequest.Title, p.PullRequest.Body)
		if p.Action == "synchronized" {
			kind = KindPRUpdate
			scope = "pr-update"
			fingerprint = echofp.PRUpdate(p.PullRequest.Head.SHA)
		}
		if h.wasReflected(ctx, mapping.GiteaRepoID, index, kind, fingerprint, scope) {
			return nil
		}
	}

	euc := h.eucForRepo(ctx, mapping, p.Repository, p.PullRequest.Base.Ref)

	switch p.Action {
	case "opened":
		ev := h.buildPROpenEvent(mapping, p, euc)
		scopeSuffix := fmt.Sprintf("pr:%d:opened", p.Number)
		emitted, err := h.publishActorEvent(ctx, p.Sender, mapping, ev, scopeSuffix)
		if err != nil {
			return err
		}
		if !emitted {
			return h.rememberPendingThread(ctx, p.Sender, mapping, ev, scopeSuffix, "pr", p.Number, KindPROpen)
		}
		if err := h.rememberThread(ctx, "pr", mapping.GiteaRepoID, p.Number, threadRef{EventID: ev.ID.Hex(), Pubkey: ev.PubKey.Hex(), Kind: KindPROpen}); err != nil {
			return err
		}
		if err := h.recordNostrObjectMapping(ctx, mapping, ev.ID.Hex(), p.Number, KindPROpen, "PR root"); err != nil {
			return err
		}
		if p.PullRequest.Draft {
			return h.publishPRStatus(ctx, p, mapping, threadRef{EventID: ev.ID.Hex(), Pubkey: ev.PubKey.Hex(), Kind: KindPROpen}, KindStatusDraft, euc)
		}
		return nil
	case "synchronized":
		root, ok := h.lookupThread(ctx, "pr", mapping.GiteaRepoID, p.Number)
		if !ok || root.EventID == "" || root.Pubkey == "" {
			h.warnMissingThread("PR update", mapping, p.Number)
			return nil
		}
		ev := h.buildPRUpdateEvent(mapping, p, root, euc)
		_, err := h.publishActorEvent(ctx, p.Sender, mapping, ev, fmt.Sprintf("pr:%d:synchronized:%s", p.Number, p.PullRequest.Head.SHA))
		return err
	case "closed", "reopened", "edited":
		root, ok := h.lookupThread(ctx, "pr", mapping.GiteaRepoID, p.Number)
		if !ok || root.EventID == "" {
			h.warnMissingThread("PR status", mapping, p.Number)
			return nil
		}
		return h.publishPRStatus(ctx, p, mapping, root, prStatusKind(p.PullRequest), euc)
	default:
		return nil
	}
}

// handleIssue publishes NIP-34 issue roots (kind:1621), labels, and lifecycle
// status events. Issue root events use subject tags and intentionally do not
// carry the old non-spec r/action tags.
func (h *Handler) handleIssue(ctx context.Context, body []byte) error {
	var p IssuePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse issue payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	// Handle label events inline
	if p.Action == "labeled" || p.Action == "unlabeled" {
		issueRef := fmt.Sprintf("%s/%s/issue/%d", mapping.Npub, mapping.RepoID, p.Number)
		remove := p.Action == "unlabeled"
		if h.wasReflected(ctx, mapping.GiteaRepoID, p.Number, KindNIP32Label, webhookLabelFingerprint(p.Label.Name, remove), "issue label") {
			return nil
		}
		return h.publishNIP32LabelForActor(ctx, p.Sender, mapping, int(KindIssue), issueRef, p.Label.Name, "gitea/label", remove)
	}

	if h.shouldSkipReflectedIssueWebhook(ctx, mapping, p) {
		return nil
	}

	euc := h.eucForRepo(ctx, mapping, p.Repository, p.Repository.DefaultBranch)

	switch p.Action {
	case "opened", "edited":
		ev := h.buildIssueEvent(mapping, p)
		scopeSuffix := fmt.Sprintf("issue:%d:%s", p.Number, p.Action)
		emitted, err := h.publishActorEvent(ctx, p.Sender, mapping, ev, scopeSuffix)
		if err != nil {
			return err
		}
		if !emitted {
			if p.Action == "opened" {
				return h.rememberPendingThread(ctx, p.Sender, mapping, ev, scopeSuffix, "issue", p.Number, KindIssue)
			}
			return nil
		}
		if p.Action == "opened" {
			if err := h.rememberThread(ctx, "issue", mapping.GiteaRepoID, p.Number, threadRef{EventID: ev.ID.Hex(), Pubkey: ev.PubKey.Hex(), Kind: KindIssue}); err != nil {
				return err
			}
			if err := h.recordNostrObjectMapping(ctx, mapping, ev.ID.Hex(), p.Number, KindIssue, "issue root"); err != nil {
				return err
			}
		}
		return nil
	case "closed", "reopened":
		root, ok := h.lookupThread(ctx, "issue", mapping.GiteaRepoID, p.Number)
		if !ok || root.EventID == "" {
			h.warnMissingThread("issue status", mapping, p.Number)
			return nil
		}
		statusKind := KindStatusClosed
		if p.Issue.State == "open" || p.Action == "reopened" {
			statusKind = KindStatusOpen
		}
		statusEv := h.buildStatusEvent(mapping, root, statusKind, "", euc)
		_, err := h.publishActorEvent(ctx, p.Sender, mapping, statusEv, fmt.Sprintf("issue:%d:%s:status", p.Number, p.Action))
		return err
	default:
		return nil
	}
}

func (h *Handler) handleIssueComment(ctx context.Context, body []byte) error {
	var p IssueCommentPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse issue_comment payload: %w", err)
	}
	if p.Action != "created" && p.Action != "edited" {
		return nil
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	commentIndex := p.Issue.Number
	if commentIndex == 0 {
		commentIndex = p.PullRequest.Number
	}
	if h.wasReflected(ctx, mapping.GiteaRepoID, commentIndex, KindComment, echofp.Comment(p.Comment.Body), "comment") {
		return nil
	}

	threadKind := "issue"
	rootKind := KindIssue
	number := p.Issue.Number
	if p.IsPull || p.PullRequest.Number != 0 {
		threadKind = "pr"
		rootKind = KindPROpen
		if p.PullRequest.Number != 0 {
			number = p.PullRequest.Number
		}
	}

	root, ok := h.lookupThread(ctx, threadKind, mapping.GiteaRepoID, number)
	if !ok || root.EventID == "" || root.Pubkey == "" {
		h.warnMissingThread("comment", mapping, number)
		return nil
	}
	root.Kind = rootKind

	ev := h.buildCommentEvent(mapping, root, p.Comment)
	_, err = h.publishActorEvent(ctx, p.Sender, mapping, ev, fmt.Sprintf("comment:%s:%d:%d:%s", threadKind, number, p.Comment.ID, p.Action))
	return err
}

func (h *Handler) buildPROpenEvent(mapping store.Mapping, p PullRequestPayload, euc string) *nostr.Event {
	tags := nostr.Tags{{"a", repoAddr(mapping)}}
	if euc != "" {
		tags = append(tags, nostr.Tag{"r", euc})
	}
	tags = append(tags, nostr.Tag{"p", mapping.Pubkey})
	if p.PullRequest.Title != "" {
		tags = append(tags, nostr.Tag{"subject", p.PullRequest.Title})
	}
	if p.PullRequest.Head.SHA != "" {
		tags = append(tags, nostr.Tag{"c", p.PullRequest.Head.SHA})
	}
	if clone := h.prCloneURL(mapping, p); clone != "" {
		tags = append(tags, nostr.Tag{"clone", clone})
	}
	if p.PullRequest.Head.Ref != "" {
		tags = append(tags, nostr.Tag{"branch-name", p.PullRequest.Head.Ref})
	}

	return &nostr.Event{
		Kind:      KindPROpen,
		CreatedAt: h.eventTimestamp(p.PullRequest.CreatedAt),
		Tags:      tags,
		Content:   p.PullRequest.Body,
	}
}

func (h *Handler) buildPRUpdateEvent(mapping store.Mapping, p PullRequestPayload, root threadRef, euc string) *nostr.Event {
	tags := nostr.Tags{{"a", repoAddr(mapping)}}
	if euc != "" {
		tags = append(tags, nostr.Tag{"r", euc})
	}
	tags = append(tags,
		nostr.Tag{"p", mapping.Pubkey},
		nostr.Tag{"E", root.EventID},
		nostr.Tag{"P", root.Pubkey},
	)
	if p.PullRequest.Head.SHA != "" {
		tags = append(tags, nostr.Tag{"c", p.PullRequest.Head.SHA})
	}
	if clone := h.prCloneURL(mapping, p); clone != "" {
		tags = append(tags, nostr.Tag{"clone", clone})
	}
	if p.PullRequest.MergeBase != "" {
		tags = append(tags, nostr.Tag{"merge-base", p.PullRequest.MergeBase})
	}

	return &nostr.Event{
		Kind:      KindPRUpdate,
		CreatedAt: h.eventTimestamp(p.PullRequest.UpdatedAt),
		Tags:      tags,
	}
}

func (h *Handler) buildIssueEvent(mapping store.Mapping, p IssuePayload) *nostr.Event {
	tags := nostr.Tags{
		{"a", repoAddr(mapping)},
		{"p", mapping.Pubkey},
	}
	if p.Issue.Title != "" {
		tags = append(tags, nostr.Tag{"subject", p.Issue.Title})
	}
	return &nostr.Event{
		Kind:      KindIssue,
		CreatedAt: h.eventTimestamp(p.Issue.CreatedAt),
		Tags:      tags,
		Content:   p.Issue.Body,
	}
}

func (h *Handler) publishPRStatus(ctx context.Context, p PullRequestPayload, mapping store.Mapping, root threadRef, statusKind int, euc string) error {
	statusEv := h.buildStatusEvent(mapping, root, statusKind, "", euc)
	if statusKind == KindStatusApplied {
		if p.PullRequest.MergedCommitID != "" {
			statusEv.Tags = append(statusEv.Tags,
				nostr.Tag{"merge-commit", p.PullRequest.MergedCommitID},
				nostr.Tag{"r", p.PullRequest.MergedCommitID},
			)
		}
	}
	_, err := h.publishActorEvent(ctx, p.Sender, mapping, statusEv, fmt.Sprintf("pr:%d:%s:status", p.Number, p.Action))
	return err
}

func (h *Handler) buildStatusEvent(mapping store.Mapping, root threadRef, kind int, content string, euc string) *nostr.Event {
	tags := nostr.Tags{
		{"e", root.EventID, "", "root"},
		{"a", repoAddr(mapping)},
		{"p", mapping.Pubkey},
	}
	if root.Pubkey != "" && root.Pubkey != mapping.Pubkey {
		tags = append(tags, nostr.Tag{"p", root.Pubkey})
	}
	if euc != "" {
		tags = append(tags, nostr.Tag{"r", euc})
	}
	return &nostr.Event{
		Kind:      nostr.Kind(kind),
		CreatedAt: h.eventTimestamp(time.Time{}),
		Tags:      tags,
		Content:   content,
	}
}

func (h *Handler) buildCommentEvent(mapping store.Mapping, root threadRef, comment Comment) *nostr.Event {
	return &nostr.Event{
		Kind:      KindComment,
		CreatedAt: h.eventTimestamp(comment.CreatedAt),
		Tags: nostr.Tags{
			{"a", repoAddr(mapping)},
			{"E", root.EventID, "", root.Pubkey},
			{"K", fmt.Sprint(root.Kind)},
			{"P", root.Pubkey},
			{"e", root.EventID, "", root.Pubkey},
			{"k", fmt.Sprint(root.Kind)},
			{"p", root.Pubkey},
		},
		Content: comment.Body,
	}
}

func prStatusKind(pr PullRequest) int {
	if pr.Draft {
		return KindStatusDraft
	}
	if pr.State == "open" {
		return KindStatusOpen
	}
	if pr.Merged {
		return KindStatusApplied
	}
	return KindStatusClosed
}

func (h *Handler) prCloneURL(mapping store.Mapping, p PullRequestPayload) string {
	// The canonical GRASP-01 npub clone URL takes precedence: conventional
	// Gitea /org/repo.git URLs are not canonical GRASP URLs.
	if canonical := grasp.CanonicalCloneURL(h.graspPublicURL, mapping.Npub, mapping.RepoID); canonical != "" {
		return canonical
	}
	if p.PullRequest.Head.Repo.CloneURL != "" {
		return p.PullRequest.Head.Repo.CloneURL
	}
	if p.Repository.CloneURL != "" {
		return p.Repository.CloneURL
	}
	if mapping.AnnouncedCloneURL != "" {
		return mapping.AnnouncedCloneURL
	}
	return mapping.CloneURL
}

// SetGraspPublicURL configures the canonical GRASP service origin used when
// advertising clone URLs on emitted NIP-34 events.
func (h *Handler) SetGraspPublicURL(publicURL string) {
	h.graspPublicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
}

func (h *Handler) eventTimestamp(t time.Time) nostr.Timestamp {
	if !t.IsZero() {
		return nostr.Timestamp(t.Unix())
	}
	if h != nil && !h.deliveryCreatedAt.IsZero() {
		return nostr.Timestamp(h.deliveryCreatedAt.Unix())
	}
	return nostr.Timestamp(time.Now().Unix())
}

func (h *Handler) rememberThread(ctx context.Context, kind string, repoID int64, number int64, ref threadRef) error {
	if ref.EventID == "" || h.store == nil {
		return nil
	}
	if err := h.store.UpsertThreadRoot(ctx, store.ThreadRoot{
		ObjectType:   kind,
		GiteaRepoID:  repoID,
		GiteaIndex:   number,
		NostrEventID: ref.EventID,
		Pubkey:       ref.Pubkey,
		Kind:         ref.Kind,
	}); err != nil {
		return fmt.Errorf("persist %s thread root: %w", kind, err)
	}
	return nil
}

func (h *Handler) rememberPendingThread(ctx context.Context, actor User, mapping store.Mapping, ev *nostr.Event, scopeSuffix, objectType string, number int64, kind int) error {
	if actor.ID == 0 || h.store == nil || !h.actorSigningEnabled() {
		return nil
	}
	_, dedupeKey := h.pendingActorEventKeys(mapping, ev, scopeSuffix)
	if err := h.store.SavePendingThreadRoot(ctx, dedupeKey, store.ThreadRoot{
		ObjectType: objectType, GiteaRepoID: mapping.GiteaRepoID, GiteaIndex: number, Kind: kind,
	}); err != nil {
		return fmt.Errorf("persist pending %s thread root: %w", objectType, err)
	}
	return nil
}

func (h *Handler) lookupThread(ctx context.Context, kind string, repoID int64, number int64) (threadRef, bool) {
	if h.store == nil {
		return threadRef{}, false
	}
	root, err := h.store.GetThreadRoot(ctx, kind, repoID, number)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) && h.logger != nil {
			h.logger.Warn("webhook: persisted thread root lookup failed", "kind", kind, "repo_id", repoID, "number", number, "error", err)
		}
		return threadRef{}, false
	}
	return threadRef{EventID: root.NostrEventID, Pubkey: root.Pubkey, Kind: root.Kind}, true
}

func (h *Handler) warnMissingThread(action string, mapping store.Mapping, number int64) {
	if h.logger != nil {
		h.logger.Warn("webhook: missing root Nostr event id; skipping threaded event", "action", action, "repo", mapping.Owner+"/"+mapping.RepoName, "number", number)
	}
}

func (h *Handler) shouldSkipReflectedIssueWebhook(ctx context.Context, mapping store.Mapping, p IssuePayload) bool {
	index := p.Number
	if index == 0 {
		index = p.Issue.Number
	}
	if index == 0 {
		return false
	}

	kind := 0
	scope := "issue"
	fingerprint := ""
	switch p.Action {
	case "opened", "edited":
		kind = KindIssue
		fingerprint = echofp.Issue(p.Issue.Title, p.Issue.Body)
	case "closed":
		kind = KindStatusClosed
		scope = "issue status"
		fingerprint = echofp.IssueStatus("closed")
	case "reopened":
		kind = KindStatusOpen
		scope = "issue status"
		fingerprint = echofp.IssueStatus("open")
	default:
		return false
	}
	return h.wasReflected(ctx, mapping.GiteaRepoID, index, kind, fingerprint, scope)
}

func (h *Handler) wasReflected(ctx context.Context, repoID int64, index int64, kind int, fingerprint string, scope string) bool {
	if h.store == nil || repoID == 0 || index == 0 || kind == 0 {
		return false
	}
	now := time.Now().UTC()
	if h.now != nil {
		now = h.now().UTC()
	}
	window := h.echoGuardWindow
	if window <= 0 {
		window = store.DefaultEchoGuardWindow
	}
	reflected, err := h.store.CheckReflectedGiteaEcho(ctx, repoID, index, kind, fingerprint, now, window)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("webhook: reflected-event guard lookup failed", "repo_id", repoID, "index", index, "kind", kind, "error", err)
		}
		return false
	}
	if reflected && h.logger != nil {
		h.logger.Info("webhook: skipping bridge-reflected object to prevent Nostr echo", "scope", scope, "repo_id", repoID, "index", index, "kind", kind)
	}
	return reflected
}

func (h *Handler) recordNostrObjectMapping(ctx context.Context, mapping store.Mapping, eventID string, index int64, kind int, scope string) error {
	if h.store == nil || eventID == "" || index == 0 {
		return nil
	}
	if _, err := h.store.RecordNostrObjectMapping(ctx, store.ReflectedEvent{
		NostrEventID: eventID,
		GiteaRepoID:  mapping.GiteaRepoID,
		GiteaIndex:   index,
		Kind:         kind,
	}); err != nil {
		return fmt.Errorf("record %s Nostr/Gitea mapping: %w", scope, err)
	}
	return nil
}

func (h *Handler) eucForRepo(ctx context.Context, mapping store.Mapping, repo Repository, defaultBranch string) string {
	if h.repositoriesDir == "" {
		return ""
	}

	h.eucMu.Lock()
	if h.eucCache != nil {
		if euc := h.eucCache[mapping.GiteaRepoID]; euc != "" {
			h.eucMu.Unlock()
			return euc
		}
	}
	h.eucMu.Unlock()

	branch := defaultBranch
	if branch == "" {
		branch = repo.DefaultBranch
	}
	if branch == "" {
		branch = "HEAD"
	}
	repoPath := filepath.Join(h.repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	euc, err := EarliestUniqueCommit(ctx, repoPath, branch)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("webhook: failed to compute earliest unique commit", "repo", mapping.Owner+"/"+mapping.RepoName, "branch", branch, "error", err)
		}
		return ""
	}

	h.eucMu.Lock()
	if h.eucCache == nil {
		h.eucCache = make(map[int64]string)
	}
	h.eucCache[mapping.GiteaRepoID] = euc
	h.eucMu.Unlock()
	return euc
}

// handleLabel publishes kind:1985 NIP-32 label events when Gitea labels are applied.
func (h *Handler) handleLabel(ctx context.Context, body []byte) error {
	// Gitea sends label events via issue/PR payloads with action=labeled/unlabeled.
	// Here we handle standalone label webhook events if configured.
	var p LabelPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse label payload: %w", err)
	}

	// Standalone label events are informational only
	h.logger.Debug("webhook: label event", "action", p.Action, "label", p.Label.Name)
	return nil
}

// handlePatchPush handles refs/nostr/<event-id> pushes (the ngit patch
// workflow). It confirms the referenced kind:1617 patch event on the relays
// when possible and publishes a kind:1631 (applied) status event that ties the
// patch to the repository and the commits it landed as. The git ref push is
// authoritative evidence that the patch was applied, so the applied status is
// emitted even when the patch event cannot be fetched (e.g. propagation lag).
func (h *Handler) handlePatchPush(ctx context.Context, eventID string, p PushPayload, mapping store.Mapping) error {
	h.logger.Info("webhook: patch push detected", "event_id", eventID, "repo", mapping.RepoID)

	// A refs/nostr/<id> ref must carry a 32-byte hex event id; anything else
	// would produce a malformed "e" tag, so skip status emission.
	if len(eventID) != 64 {
		h.logger.Warn("webhook: refs/nostr event id is not 64 hex chars, skipping", "event_id", eventID)
		return nil
	}
	if _, err := hex.DecodeString(eventID); err != nil {
		h.logger.Warn("webhook: refs/nostr event id is not hex, skipping", "event_id", eventID)
		return nil
	}

	if p.After == "" || strings.Trim(p.After, "0") == "" {
		if h.store != nil {
			if err := h.store.DeletePendingNostrRef(ctx, mapping.GiteaRepoID, eventID); err != nil {
				h.logger.Warn("webhook: failed to clear pending refs/nostr deletion", "event_id", eventID, "error", err)
			}
		}
		return nil
	}

	// Best-effort: fetch the referenced event so we can reject known differing
	// tips and attribute the applied status to a kind:1617 patch author. Fetch
	// failures are non-fatal, but a relay event that lists only other c-tag tips
	// is treated as a rejected refs/nostr push for lifecycle purposes.
	var patch *nostr.Event
	var fetched *nostr.Event
	if h.pub != nil {
		var err error
		fetched, err = refsnostr.FetchEventForTip(ctx, h.pub, eventID, p.After)
		if err != nil {
			if errors.Is(err, refsnostr.ErrDifferingTip) {
				return fmt.Errorf("reject refs/nostr push %s at %s: %w", eventID, p.After, err)
			}
			h.logger.Warn("webhook: fetch patch event failed (continuing)", "event_id", eventID, "error", err)
		}
	}
	if fetched == nil {
		h.logger.Info("webhook: patch event not found on relays; emitting applied status from push metadata", "event_id", eventID)
	} else if fetched.Kind != KindPatch {
		h.logger.Warn("webhook: refs/nostr referenced event is not a kind:1617 patch", "event_id", eventID, "kind", fetched.Kind)
	} else {
		patch = fetched
	}

	if h.store != nil {
		if err := h.store.RecordPendingNostrRef(ctx, store.PendingNostrRef{
			EventID:     eventID,
			TipSHA:      p.After,
			GiteaRepoID: mapping.GiteaRepoID,
			Owner:       mapping.Owner,
			RepoName:    mapping.RepoName,
			FirstSeenAt: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("record pending refs/nostr ref: %w", err)
		}
	}

	if h.pub == nil && !h.actorSigningEnabled() {
		return fmt.Errorf("publisher not configured")
	}

	euc := h.eucForRepo(ctx, mapping, p.Repository, p.Repository.DefaultBranch)
	tags := nostr.Tags{
		{"e", eventID, "", "root"},
		{"a", repoAddr(mapping)},
		{"p", mapping.Pubkey},
	}
	if euc != "" {
		tags = append(tags, nostr.Tag{"r", euc})
	}
	// Record the commit the patch landed as (NIP-34 applied-as-commits) and add
	// the companion r tag so clients can find status by applied commit id.
	if p.After != "" && strings.Trim(p.After, "0") != "" {
		tags = append(tags, nostr.Tag{"applied-as-commits", p.After}, nostr.Tag{"r", p.After})
	}
	// Attribute to the patch author when known and distinct from the maintainer.
	if patch != nil && patch.PubKey != (nostr.PubKey{}) {
		tags = append(tags, nostr.Tag{"q", eventID, "", patch.PubKey.Hex()})
		if patch.PubKey.Hex() != mapping.Pubkey {
			tags = append(tags, nostr.Tag{"p", patch.PubKey.Hex()})
		}
	}

	statusEv := &nostr.Event{
		Kind:      KindStatusApplied,
		CreatedAt: h.eventTimestamp(time.Time{}),
		Tags:      tags,
	}
	_, err := h.publishActorEvent(ctx, p.Sender, mapping, statusEv, fmt.Sprintf("patch:%s:applied:%s", eventID, p.After))
	return err
}

// PublishNIP32Label publishes a kind:1985 NIP-32 label event that labels the
// repository the target belongs to. The label references the repo announcement
// coordinate (30617:<hex-pubkey>:<repo-id>) and records the human-readable
// target (e.g. "npub/repo/issue/N") in an "r" tag for context.
func (h *Handler) PublishNIP32Label(ctx context.Context, mapping store.Mapping, targetKind int, targetRef string, label string, namespace string) error {
	ev := h.buildNIP32LabelEvent(mapping, targetKind, targetRef, label, namespace, false)
	return h.publish(ctx, ev)
}

func (h *Handler) publishNIP32LabelForActor(ctx context.Context, actor User, mapping store.Mapping, targetKind int, targetRef string, label string, namespace string, remove bool) error {
	ev := h.buildNIP32LabelEvent(mapping, targetKind, targetRef, label, namespace, remove)
	action := "apply"
	if remove {
		action = "remove"
	}
	_, err := h.publishActorEvent(ctx, actor, mapping, ev, fmt.Sprintf("label:%d:%s:%s:%s:%s", targetKind, targetRef, namespace, label, action))
	return err
}

func (h *Handler) buildNIP32LabelEvent(mapping store.Mapping, targetKind int, targetRef string, label string, namespace string, remove bool) *nostr.Event {
	action := "apply"
	if remove {
		action = "remove"
	}
	return &nostr.Event{
		Kind:      KindNIP32Label,
		CreatedAt: h.eventTimestamp(time.Time{}),
		Tags: nostr.Tags{
			{"L", namespace},
			{"l", label, namespace},
			{"action", action},
			{"a", repoAddr(mapping)},
			{"r", targetRef},
			{"p", mapping.Pubkey},
		},
	}
}

func webhookLabelFingerprint(label string, remove bool) string {
	action := "apply"
	if remove {
		action = "remove"
	}
	return action + "\x00" + strings.TrimSpace(label)
}

// NOTE: kind:30617 repository announcements are NOT minted by the bridge.
// The owner signs their own announcement; the bridge caches it at provisioning
// time (provisioner.CacheAnnouncementEvent) and rebroadcasts that owner-signed
// event verbatim (publisher.republishAnnouncement). A bridge-signed 30617 would
// misattribute the announcement to the bridge key, so no such method exists here.

func (h *Handler) publishRepoState(ctx context.Context, mapping store.Mapping, repo Repository) error {
	// Delegate to publisher service for kind:30618
	return h.pub.RepublishForGiteaRepo(ctx, repo.ID)
}

func (h *Handler) publishActorEvent(ctx context.Context, actor User, mapping store.Mapping, ev *nostr.Event, scopeSuffix string) (bool, error) {
	if !h.actorSigningEnabled() {
		return true, h.publish(ctx, ev)
	}
	if ev == nil {
		return false, fmt.Errorf("event is required")
	}
	if h.actorOutbox == nil {
		return false, fmt.Errorf("actor outbox not configured")
	}

	scope, pendingDedupeKey := h.pendingActorEventKeys(mapping, ev, scopeSuffix)

	authorPubkey, ok, err := h.resolveActorGrant(ctx, actor)
	if err != nil {
		return false, err
	}
	if !ok {
		if actor.ID != 0 && h.store != nil {
			if err := h.persistPendingActorEvent(ctx, actor, ev, scope, pendingDedupeKey); err != nil {
				return false, err
			}
		}
		return false, nil
	}

	authorPK, err := nostr.PubKeyFromHexCheap(authorPubkey)
	if err != nil {
		return false, fmt.Errorf("invalid actor pubkey %q: %w", authorPubkey, err)
	}
	ev.PubKey = authorPK
	ev.Sig = [64]byte{}
	ev.ID = ev.GetID()
	dedupeKey := fmt.Sprintf("webhook:%s:%d:%s", scope, ev.Kind, ev.ID.Hex())
	if err := h.actorOutbox.Enqueue(ctx, int(ev.Kind), authorPubkey, scope, ev, dedupeKey); err != nil {
		return false, err
	}
	return true, nil
}

func (h *Handler) pendingActorEventKeys(mapping store.Mapping, ev *nostr.Event, scopeSuffix string) (string, string) {
	scope := fmt.Sprintf("repo:%d:%s", mapping.GiteaRepoID, scopeSuffix)
	pendingID := ev.GetID()
	return scope, fmt.Sprintf("webhook:%s:%d:%s", scope, ev.Kind, pendingID.Hex())
}

func (h *Handler) actorSigningEnabled() bool {
	return h.actorSigner != nil && h.actorSigner.Enabled()
}

func (h *Handler) resolveActorGrant(ctx context.Context, actor User) (string, bool, error) {
	if h.actorLookup == nil {
		h.skipUnlinkedActor(actor, "identity lookup not configured")
		return "", false, nil
	}
	if actor.ID == 0 {
		h.skipUnlinkedActor(actor, "missing Gitea sender id")
		return "", false, nil
	}

	link, err := h.actorLookup.GetIdentityLinkByGiteaUserID(ctx, actor.ID)
	if errors.Is(err, sql.ErrNoRows) {
		h.skipUnlinkedActor(actor, "no identity link")
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lookup actor identity link for user %d: %w", actor.ID, err)
	}

	grant, err := h.actorLookup.GetSignerGrant(ctx, link.Pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		h.skipUnlinkedActor(actor, "no signer grant")
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lookup actor signer grant for user %d pubkey %s: %w", actor.ID, link.Pubkey, err)
	}
	if grant.Status != "active" || grant.RevokedAt != nil {
		h.skipUnlinkedActor(actor, "signer grant inactive")
		return "", false, nil
	}
	return link.Pubkey, true, nil
}

func (h *Handler) persistPendingActorEvent(ctx context.Context, actor User, ev *nostr.Event, scope string, dedupeKey string) error {
	pending := *ev
	pending.PubKey = nostr.PubKey{}
	pending.Sig = [64]byte{}
	pending.ID = nostr.ID{}
	b, err := json.Marshal(&pending)
	if err != nil {
		return fmt.Errorf("marshal pending actor event for user %d: %w", actor.ID, err)
	}
	_, trimmed, err := h.store.SavePendingActorEvent(ctx, store.PendingActorEvent{
		GiteaUserID:       actor.ID,
		Kind:              int(pending.Kind),
		UnsignedEventJSON: string(b),
		Scope:             scope,
		DedupeKey:         dedupeKey,
	}, time.Now().UTC(), pendingActorEventsMaxPerUser, pendingActorEventsMaxAge)
	if err != nil {
		return fmt.Errorf("persist pending actor event for user %d: %w", actor.ID, err)
	}
	if trimmed > 0 && h.logger != nil {
		h.logger.Warn("webhook: trimmed pending actor event backlog", "gitea_user_id", actor.ID, "trimmed", trimmed, "max_per_user", pendingActorEventsMaxPerUser, "max_age", pendingActorEventsMaxAge.String())
	}
	return nil
}

func (h *Handler) skipUnlinkedActor(actor User, reason string) {
	metrics.IncUnlinkedActorSkipped()
	h.logger.Warn("webhook: signer enabled but actor is not linked; queuing collaboration event for backfill when possible",
		"gitea_user_id", actor.ID, "gitea_user", actor.Login, "reason", reason)
}

func (h *Handler) publish(ctx context.Context, ev *nostr.Event) error {
	if h.pub == nil {
		return fmt.Errorf("publisher not configured")
	}

	// Sign and publish via publisher service
	// The publisher service handles signing with the bridge key
	return h.pub.PublishEvent(ctx, ev)
}

// repoAddr returns the NIP-34 addressable coordinate for a repository
// announcement: "30617:<hex-pubkey>:<repo-id>". This is the canonical
// reference used in "a" tags of PR, issue, status, and label events so that
// Nostr clients can resolve them back to the repo announcement.
func repoAddr(m store.Mapping) string {
	return fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, m.Pubkey, m.RepoID)
}

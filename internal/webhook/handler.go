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
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/refsnostr"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	KindPatch         = 1617
	KindPROpen        = 1618
	KindPRUpdate      = 1619
	KindIssue         = 1621
	KindStatusOpen    = 1630
	KindStatusApplied = 1631
	KindStatusClosed  = 1632
	KindStatusDraft   = 1633
	KindNIP32Label    = 1985
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
	pub         Publisher
	store       *store.SQLiteStore
	secret      string
	logger      *slog.Logger
	actorSigner ActorSigner
	actorOutbox ActorOutbox
	actorLookup ActorIdentityLookup
}

// New creates a webhook Handler.
func New(pub *publisher.Service, st *store.SQLiteStore, secret string, logger *slog.Logger) *Handler {
	h := &Handler{store: st, secret: secret, logger: logger, actorLookup: st}
	// Guard against a typed-nil *publisher.Service being stored as a non-nil
	// interface, which would defeat the h.pub == nil checks below.
	if pub != nil {
		h.pub = pub
	}
	return h
}

func (h *Handler) SetActorSigning(signer ActorSigner, outbox ActorOutbox, lookup ActorIdentityLookup) {
	h.actorSigner = signer
	h.actorOutbox = outbox
	if lookup != nil {
		h.actorLookup = lookup
	}
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

	if h.secret != "" {
		if !h.verifyHMAC(r.Header.Get("X-Gitea-Signature"), body) {
			h.logger.Warn("webhook: HMAC validation failed")
			http.Error(w, "signature mismatch", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-Gitea-Event")
	h.logger.Info("webhook: received", "event", eventType)
	metrics.IncWebhookEventsReceived()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var publishErr error
	switch eventType {
	case "push":
		publishErr = h.handlePush(ctx, body)
	case "create":
		publishErr = h.handleCreate(ctx, body)
	case "delete":
		publishErr = h.handleDelete(ctx, body)
	case "pull_request":
		publishErr = h.handlePR(ctx, body)
	case "issues":
		publishErr = h.handleIssue(ctx, body)
	case "label":
		publishErr = h.handleLabel(ctx, body)
	default:
		h.logger.Debug("webhook: unhandled event type", "event", eventType)
	}

	if publishErr != nil {
		h.logger.Warn("webhook: publish error", "event", eventType, "error", publishErr)
		metrics.IncWebhookEventsFailed()
		// Still return 200 — Gitea will retry on non-2xx which causes noise.
	} else if publishErr == nil && eventType != "" {
		metrics.IncWebhookEventsPublished()
	}

	w.WriteHeader(http.StatusOK)
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

// handlePR publishes kind:1618 (PR open), kind:1619 (PR update/close), and status events.
func (h *Handler) handlePR(ctx context.Context, body []byte) error {
	var p PullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse PR payload: %w", err)
	}

	mapping, err := h.store.GetMappingByGiteaRepoID(ctx, p.Repository.ID)
	if err != nil {
		return nil
	}

	repoAddr := repoAddr(mapping)
	prRef := fmt.Sprintf("%s/%s/pull/%d", mapping.Npub, mapping.RepoID, p.Number)

	var ev *nostr.Event
	switch p.Action {
	case "opened":
		ev = &nostr.Event{
			Kind:      KindPROpen,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags: nostr.Tags{
				{"a", repoAddr},
				{"p", mapping.Pubkey},
				{"r", prRef},
				{"title", p.PullRequest.Title},
				{"head", p.PullRequest.Head.Ref},
				{"base", p.PullRequest.Base.Ref},
			},
			Content: p.PullRequest.Body,
		}
	case "closed", "reopened", "edited", "synchronized":
		ev = &nostr.Event{
			Kind:      KindPRUpdate,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags: nostr.Tags{
				{"a", repoAddr},
				{"p", mapping.Pubkey},
				{"r", prRef},
				{"action", p.Action},
			},
			Content: p.PullRequest.Body,
		}
	default:
		return nil
	}

	emitted, err := h.publishActorEvent(ctx, p.Sender, mapping, ev, fmt.Sprintf("pr:%d:%s", p.Number, p.Action))
	if err != nil || !emitted {
		return err
	}

	// Emit status event
	var statusKind int
	if p.PullRequest.Draft {
		statusKind = KindStatusDraft
	} else if p.PullRequest.State == "open" {
		statusKind = KindStatusOpen
	} else if p.PullRequest.Merged {
		statusKind = KindStatusApplied
	} else {
		statusKind = KindStatusClosed
	}

	statusEv := &nostr.Event{
		Kind:      statusKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"e", ev.ID},
			{"a", repoAddr},
			{"p", mapping.Pubkey},
		},
	}

	_, err = h.publishActorEvent(ctx, p.Sender, mapping, statusEv, fmt.Sprintf("pr:%d:%s:status", p.Number, p.Action))
	return err
}

// handleIssue publishes kind:1621 for issue open/close/edit, and kind:1985 for label events.
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
		return h.publishNIP32LabelForActor(ctx, p.Sender, mapping, int(KindIssue), issueRef, p.Label.Name, "gitea/label")
	}

	switch p.Action {
	case "opened", "edited", "closed", "reopened":
		// handle below
	default:
		return nil
	}

	repoAddr := repoAddr(mapping)

	ev := &nostr.Event{
		Kind:      KindIssue,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"a", repoAddr},
			{"p", mapping.Pubkey},
			{"r", fmt.Sprintf("%s/%s/issue/%d", mapping.Npub, mapping.RepoID, p.Number)},
			{"title", p.Issue.Title},
			{"action", p.Action},
		},
		Content: p.Issue.Body,
	}

	emitted, err := h.publishActorEvent(ctx, p.Sender, mapping, ev, fmt.Sprintf("issue:%d:%s", p.Number, p.Action))
	if err != nil || !emitted {
		return err
	}

	// Emit status event
	var statusKind int
	if p.Issue.State == "open" {
		statusKind = KindStatusOpen
	} else {
		statusKind = KindStatusClosed
	}

	statusEv := &nostr.Event{
		Kind:      statusKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"e", ev.ID},
			{"a", repoAddr},
			{"p", mapping.Pubkey},
		},
	}

	_, err = h.publishActorEvent(ctx, p.Sender, mapping, statusEv, fmt.Sprintf("issue:%d:%s:status", p.Number, p.Action))
	return err
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

	tags := nostr.Tags{
		{"e", eventID},
		{"a", repoAddr(mapping)},
		{"p", mapping.Pubkey},
	}
	// Record the commit the patch landed as (NIP-34 applied-as-commits).
	if p.After != "" && strings.Trim(p.After, "0") != "" {
		tags = append(tags, nostr.Tag{"applied-as-commits", p.After})
	}
	// Attribute to the patch author when known and distinct from the maintainer.
	if patch != nil && patch.PubKey != "" && patch.PubKey != mapping.Pubkey {
		tags = append(tags, nostr.Tag{"p", patch.PubKey})
	}

	statusEv := &nostr.Event{
		Kind:      KindStatusApplied,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
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
	ev := h.buildNIP32LabelEvent(mapping, targetKind, targetRef, label, namespace)
	return h.publish(ctx, ev)
}

func (h *Handler) publishNIP32LabelForActor(ctx context.Context, actor User, mapping store.Mapping, targetKind int, targetRef string, label string, namespace string) error {
	ev := h.buildNIP32LabelEvent(mapping, targetKind, targetRef, label, namespace)
	_, err := h.publishActorEvent(ctx, actor, mapping, ev, fmt.Sprintf("label:%d:%s:%s:%s", targetKind, targetRef, namespace, label))
	return err
}

func (h *Handler) buildNIP32LabelEvent(mapping store.Mapping, targetKind int, targetRef string, label string, namespace string) *nostr.Event {
	return &nostr.Event{
		Kind:      KindNIP32Label,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"L", namespace},
			{"l", label, namespace},
			{"a", repoAddr(mapping)},
			{"r", targetRef},
			{"p", mapping.Pubkey},
		},
	}
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

	authorPubkey, ok, err := h.resolveActorGrant(ctx, actor)
	if err != nil || !ok {
		return false, err
	}

	ev.PubKey = authorPubkey
	ev.Sig = ""
	ev.ID = ev.GetID()
	scope := fmt.Sprintf("repo:%d:%s", mapping.GiteaRepoID, scopeSuffix)
	dedupeKey := fmt.Sprintf("webhook:%s:%d:%s", scope, ev.Kind, ev.ID)
	if err := h.actorOutbox.Enqueue(ctx, ev.Kind, authorPubkey, scope, ev, dedupeKey); err != nil {
		return false, err
	}
	return true, nil
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

func (h *Handler) skipUnlinkedActor(actor User, reason string) {
	// Phase D fallback: pre-link collaboration events are intentionally not
	// backfilled here; Phase G/follow-up migration can define any replay policy.
	metrics.IncUnlinkedActorSkipped()
	h.logger.Warn("webhook: signer enabled but actor is not linked; skipping collaboration event without bridge-signing",
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

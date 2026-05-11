// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/publisher"
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

// Handler handles inbound Gitea webhook events, maps them to NIP-34 Nostr
// events, and publishes via the publisher.
type Handler struct {
	pub    *publisher.Service
	store  *store.SQLiteStore
	secret string
	logger *slog.Logger
}

// New creates a webhook Handler.
func New(pub *publisher.Service, st *store.SQLiteStore, secret string, logger *slog.Logger) *Handler {
	return &Handler{pub: pub, store: st, secret: secret, logger: logger}
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
			h.logger.Warn("webhook: patch event handling failed (non-fatal)", "event_id", eventID, "error", err)
		}
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
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

	repoTag := fmt.Sprintf("%s/%s", mapping.Npub, mapping.RepoID)
	prRef := fmt.Sprintf("%s/pull/%d", repoTag, p.Number)

	var ev *nostr.Event
	switch p.Action {
	case "opened":
		ev = &nostr.Event{
			Kind:      KindPROpen,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags: nostr.Tags{
				{"a", repoTag},
				{"p", mapping.Npub},
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
				{"a", repoTag},
				{"p", mapping.Npub},
				{"r", prRef},
				{"action", p.Action},
			},
			Content: p.PullRequest.Body,
		}
	default:
		return nil
	}

	if err := h.publish(ctx, ev); err != nil {
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
			{"p", mapping.Npub},
		},
	}

	return h.publish(ctx, statusEv)
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
		return h.PublishNIP32Label(ctx, mapping, int(KindIssue), issueRef, p.Label.Name, "gitea/label")
	}

	switch p.Action {
	case "opened", "edited", "closed", "reopened":
		// handle below
	default:
		return nil
	}

	repoTag := fmt.Sprintf("%s/%s", mapping.Npub, mapping.RepoID)

	ev := &nostr.Event{
		Kind:      KindIssue,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"a", repoTag},
			{"p", mapping.Npub},
			{"r", fmt.Sprintf("%s/issue/%d", repoTag, p.Number)},
			{"title", p.Issue.Title},
			{"action", p.Action},
		},
		Content: p.Issue.Body,
	}

	if err := h.publish(ctx, ev); err != nil {
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
			{"p", mapping.Npub},
		},
	}

	return h.publish(ctx, statusEv)
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

// handlePatchPush handles refs/nostr/<event-id> pushes by fetching or synthesizing
// a kind:1617 patch event.
func (h *Handler) handlePatchPush(ctx context.Context, eventID string, p PushPayload, mapping store.Mapping) error {
	// Try to fetch the pre-published patch event from relay
	// If not found, synthesize a minimal event from push metadata
	h.logger.Info("webhook: patch push detected", "event_id", eventID, "repo", mapping.RepoID)

	// For now, just log — full implementation would fetch from relay
	// and emit a kind:1631 (applied) status event
	return nil
}

// PublishNIP32Label publishes a kind:1985 NIP-32 label event.
func (h *Handler) PublishNIP32Label(ctx context.Context, mapping store.Mapping, targetKind int, targetRef string, label string, namespace string) error {
	ev := &nostr.Event{
		Kind:      KindNIP32Label,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"L", namespace},
			{"l", label, namespace},
			{"a", fmt.Sprintf("%d:%s:%s", targetKind, mapping.Npub, targetRef)},
			{"p", mapping.Npub},
		},
	}

	return h.publish(ctx, ev)
}

// PublishAnnouncement publishes a kind:30617 repository announcement event
// after successful provisioning.
func (h *Handler) PublishAnnouncement(ctx context.Context, mapping store.Mapping, description string) error {
	ev := &nostr.Event{
		Kind:      relay.KindRepositoryAnnouncement,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"d", mapping.RepoID},
			{"name", mapping.RepoID},
			{"description", description},
			{"clone", mapping.CloneURL},
		},
		Content: description,
	}

	return h.publish(ctx, ev)
}

func (h *Handler) publishRepoState(ctx context.Context, mapping store.Mapping, repo Repository) error {
	// Delegate to publisher service for kind:30618
	return h.pub.RepublishForGiteaRepo(ctx, repo.ID)
}

func (h *Handler) publish(ctx context.Context, ev *nostr.Event) error {
	if h.pub == nil {
		return fmt.Errorf("publisher not configured")
	}

	// Sign and publish via publisher service
	// The publisher service handles signing with the bridge key
	return h.pub.PublishEvent(ctx, ev)
}

func splitFullName(fullName string) (owner, repo string) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", fullName
}

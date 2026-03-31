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

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	KindRepositoryAnnouncement = nostr.Kind(30617)
	KindRepositoryState        = nostr.Kind(30618)
	KindPatch                  = nostr.Kind(1617)
	KindPROpen                 = nostr.Kind(1618)
	KindPRUpdate               = nostr.Kind(1619)
	KindIssue                  = nostr.Kind(1621)
	KindStatusOpen             = nostr.Kind(1630)
	KindStatusApplied          = nostr.Kind(1631)
	KindStatusClosed           = nostr.Kind(1632)
	KindStatusDraft            = nostr.Kind(1633)
	KindNIP32Label             = nostr.Kind(1985)
)

// Handler handles inbound Gitea webhook events, maps them to NIP-34 Nostr
// events, and publishes via the publisher.
type Handler struct {
	pub    *publisher.Publisher
	store  *store.SQLiteStore
	secret string
	logger *slog.Logger
}

// New creates a webhook Handler. If pub is nil, events are not published
// (disabled mode — logs only).
func New(pub *publisher.Publisher, st *store.SQLiteStore, secret string, logger *slog.Logger) *Handler {
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
	default:
		h.logger.Debug("webhook: unhandled event type", "event", eventType)
	}

	if publishErr != nil {
		h.logger.Warn("webhook: publish error", "event", eventType, "error", publishErr)
		// Still return 200 — Gitea will retry on non-2xx which causes noise.
	}

	w.WriteHeader(http.StatusOK)
}

// verifyHMAC validates X-Gitea-Signature (HMAC-SHA256 hex).
func (h *Handler) verifyHMAC(sig string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// handlePush publishes a kind:30618 repository state event.
func (h *Handler) handlePush(ctx context.Context, body []byte) error {
	var p PushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse push payload: %w", err)
	}

	// zero SHA means branch deleted — handled by handleDelete
	if p.After == strings.Repeat("0", 40) {
		return nil
	}

	owner, repoName := splitFullName(p.Repository.FullName)
	mapping, err := h.store.GetMappingByOwnerRepo(ctx, owner, repoName)
	if err != nil {
		h.logger.Debug("webhook: push for untracked repo", "repo", p.Repository.FullName)
		return nil // not a GRASP-managed repo, ignore
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
}

// handleCreate publishes a kind:30618 state event when a branch/tag is created.
func (h *Handler) handleCreate(ctx context.Context, body []byte) error {
	var p CreatePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse create payload: %w", err)
	}

	owner, repoName := splitFullName(p.Repository.FullName)
	mapping, err := h.store.GetMappingByOwnerRepo(ctx, owner, repoName)
	if err != nil {
		return nil
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
}

// handleDelete publishes a kind:30618 state event when a branch/tag is removed.
func (h *Handler) handleDelete(ctx context.Context, body []byte) error {
	var p DeletePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse delete payload: %w", err)
	}

	owner, repoName := splitFullName(p.Repository.FullName)
	mapping, err := h.store.GetMappingByOwnerRepo(ctx, owner, repoName)
	if err != nil {
		return nil
	}

	return h.publishRepoState(ctx, mapping, p.Repository)
}

// handlePR publishes kind:1618 (open) or kind:1619 (update/close).
func (h *Handler) handlePR(ctx context.Context, body []byte) error {
	var p PullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse PR payload: %w", err)
	}

	owner, repoName := splitFullName(p.Repository.FullName)
	mapping, err := h.store.GetMappingByOwnerRepo(ctx, owner, repoName)
	if err != nil {
		return nil
	}

	repoTag := fmt.Sprintf("%s/%s", mapping.Npub, mapping.RepoID)
	prRef := fmt.Sprintf("%s/pr/%d", repoTag, p.Number)

	var kind nostr.Kind
	switch p.Action {
	case "opened":
		kind = KindPROpen
	case "closed", "merged", "edited", "synchronized", "reopened":
		kind = KindPRUpdate
	default:
		return nil
	}

	// Map state to status kind
	statusKind := KindStatusOpen
	if p.PullRequest.Merged {
		statusKind = KindStatusApplied
	} else if p.PullRequest.State == "closed" {
		statusKind = KindStatusClosed
	}

	ev := &nostr.Event{
		Kind:    kind,
		Content: p.PullRequest.Body,
		Tags: nostr.Tags{
			{"a", repoTag, "", "root"},
			{"p", mapping.Pubkey},
			{"t", "pr"},
			{"title", p.PullRequest.Title},
			{"r", p.PullRequest.HTMLURL},
			{"head", p.PullRequest.Head.SHA},
			{"base", p.PullRequest.Base.Ref},
		},
	}

	if err := h.publish(ctx, ev); err != nil {
		return err
	}

	// Also publish a status event
	statusEv := &nostr.Event{
		Kind:    statusKind,
		Content: "",
		Tags: nostr.Tags{
			{"e", prRef},
			{"a", repoTag},
		},
	}
	return h.publish(ctx, statusEv)
}

// handleIssue publishes kind:1621 for issue open/close/edit.
func (h *Handler) handleIssue(ctx context.Context, body []byte) error {
	var p IssuePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("parse issue payload: %w", err)
	}

	switch p.Action {
	case "opened", "edited", "closed", "reopened":
		// handle below
	default:
		return nil
	}

	owner, repoName := splitFullName(p.Repository.FullName)
	mapping, err := h.store.GetMappingByOwnerRepo(ctx, owner, repoName)
	if err != nil {
		return nil
	}

	repoTag := fmt.Sprintf("%s/%s", mapping.Npub, mapping.RepoID)

	ev := &nostr.Event{
		Kind:    KindIssue,
		Content: p.Issue.Body,
		Tags: nostr.Tags{
			{"a", repoTag, "", "root"},
			{"p", mapping.Pubkey},
			{"t", "issue"},
			{"title", p.Issue.Title},
			{"r", p.Issue.HTMLURL},
		},
	}

	if err := h.publish(ctx, ev); err != nil {
		return err
	}

	// Publish status event
	statusKind := KindStatusOpen
	if p.Issue.State == "closed" {
		statusKind = KindStatusClosed
	}
	issueRef := fmt.Sprintf("%s/issue/%d", repoTag, p.Index)
	statusEv := &nostr.Event{
		Kind:    statusKind,
		Content: "",
		Tags: nostr.Tags{
			{"e", issueRef},
			{"a", repoTag},
		},
	}
	return h.publish(ctx, statusEv)
}

// publishRepoState builds and publishes a kind:30618 repository state event
// by querying Gitea for the current refs. For now we encode the push SHA directly.
func (h *Handler) publishRepoState(ctx context.Context, mapping store.Mapping, repo Repository) error {
	tags := nostr.Tags{
		{"d", mapping.RepoID},
		{"name", repo.Name},
		{"description", ""},
		{"clone", mapping.CloneURL},
		{"web", repo.HTMLURL},
	}

	// HEAD ref from default branch
	if repo.DefaultBranch != "" {
		tags = append(tags, nostr.Tag{"HEAD", "ref: refs/heads/" + repo.DefaultBranch})
	}

	ev := &nostr.Event{
		Kind:    KindRepositoryState,
		Content: "",
		Tags:    tags,
	}

	return h.publish(ctx, ev)
}

// PublishAnnouncement publishes a kind:30617 repository announcement.
// Called by the provisioner after successful repo creation.
func (h *Handler) PublishAnnouncement(ctx context.Context, mapping store.Mapping, description string) error {
	ev := &nostr.Event{
		Kind:    KindRepositoryAnnouncement,
		Content: description,
		Tags: nostr.Tags{
			{"d", mapping.RepoID},
			{"name", mapping.RepoName},
			{"clone", mapping.CloneURL},
			{"r", "wss://relay.sharegap.net"},
		},
	}
	return h.publish(ctx, ev)
}

func (h *Handler) publish(ctx context.Context, ev *nostr.Event) error {
	if h.pub == nil {
		h.logger.Debug("webhook: publisher disabled, skipping event", "kind", ev.Kind)
		return nil
	}
	return h.pub.Publish(ctx, ev)
}

func splitFullName(fullName string) (owner, repo string) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return fullName, fullName
}

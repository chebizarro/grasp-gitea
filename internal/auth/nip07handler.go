// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
)

// NIP07Handler provides HTTP endpoints for the NIP-07 browser extension
// login flow: challenge issuance and NIP-98 proof verification.
type NIP07Handler struct {
	authService     *Service
	identityService *IdentityService
	relayURLs       []string
	logger          *slog.Logger
}

// NewNIP07Handler creates a new handler for NIP-07 auth endpoints.
func NewNIP07Handler(
	authSvc *Service,
	identitySvc *IdentityService,
	relayURLs []string,
	logger *slog.Logger,
) *NIP07Handler {
	return &NIP07Handler{
		authService:     authSvc,
		identityService: identitySvc,
		relayURLs:       relayURLs,
		logger:          logger.With("component", "auth.nip07"),
	}
}

// RegisterRoutes adds the NIP-07 auth routes to the given mux.
func (h *NIP07Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/nip07/challenge", h.methodGuard(http.MethodPost, h.handleChallenge))
	mux.HandleFunc("/auth/nip07/verify", h.methodGuard(http.MethodPost, h.handleVerify))
}

// handleChallenge issues a new login challenge.
// POST /auth/nip07/challenge
// Request: { "redirect_uri": "/dashboard" } (optional)
// Response: { "nonce": "...", "url": "...", "method": "POST", "expires_at": "..." }
func (h *NIP07Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
	}

	resp, err := h.authService.IssueChallenge(r.Context(), req)
	if err != nil {
		h.logger.Error("issue challenge failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue challenge"})
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleVerify validates a signed NIP-98 login proof.
// POST /auth/nip07/verify
// Request: { "signed_event": { ... nostr event ... } }
// Response: { "ok": true, "identity": { ... }, "redirect_uri": "..." }
func (h *NIP07Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.IncAuthVerifyFailure()
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	if req.SignedEvent == nil {
		metrics.IncAuthVerifyFailure()
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signed_event is required"})
		return
	}

	ev := req.SignedEvent

	// 1. Apply the fleet shared NIP-98 verification contract.
	if _, err := h.authService.VerifyNIP98(ev, http.MethodPost, h.authService.publicURL+"/auth/nip07/verify"); err != nil {
		metrics.IncAuthVerifyFailure()
		h.logger.Warn("NIP-98 verification failed", "error", err, "pubkey", ev.PubKey)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	// 3. Extract and validate the nonce.
	nonce := tagValue(ev.Tags, "nonce")
	if nonce == "" {
		metrics.IncAuthVerifyFailure()
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing nonce tag"})
		return
	}

	challenge, err := h.authService.ValidateChallenge(r.Context(), nonce)
	if err != nil {
		// ValidateChallenge already increments replay metric if needed.
		metrics.IncAuthVerifyFailure()
		h.logger.Warn("challenge validation failed", "nonce", nonce, "error", err)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	// 4. Consume the challenge (single-use).
	if err := h.authService.ConsumeChallenge(r.Context(), nonce); err != nil {
		metrics.IncAuthVerifyFailure()
		h.logger.Error("consume challenge failed", "nonce", nonce, "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to consume challenge"})
		return
	}

	// 5. Resolve or create the Gitea user.
	identity, err := h.identityService.ResolveOrCreate(r.Context(), ev.PubKey, h.relayURLs)
	if err != nil {
		metrics.IncAuthVerifyFailure()
		h.logger.Error("identity resolution failed", "pubkey", ev.PubKey, "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to resolve identity"})
		return
	}

	metrics.IncAuthVerifySuccess()
	h.logger.Info("NIP-07 login verified",
		"pubkey", ev.PubKey, "gitea_user", identity.GiteaUser,
		"created", identity.Created)

	resp := verifyResponse{
		OK:          true,
		Identity:    identity,
		RedirectURI: challenge.RedirectURI,
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// verifyRequest is the JSON body for POST /auth/nip07/verify.
type verifyRequest struct {
	SignedEvent *nostr.Event `json:"signed_event"`
}

// verifyResponse is the JSON response for a successful verification.
type verifyResponse struct {
	OK          bool             `json:"ok"`
	Identity    ResolvedIdentity `json:"identity"`
	RedirectURI string           `json:"redirect_uri,omitempty"`
}

// tagValue returns the first value for a tag key, or "" if not found.
func tagValue(tags nostr.Tags, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

func (h *NIP07Handler) methodGuard(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

func (h *NIP07Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

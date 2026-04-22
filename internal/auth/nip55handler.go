// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

// NIP55Handler provides HTTP endpoints for the NIP-55 Android signer
// login flow: challenge issuance and signed event callback.
type NIP55Handler struct {
	authService     *Service
	identityService *IdentityService
	relayURLs       []string
	logger          *slog.Logger
}

// NewNIP55Handler creates a new handler for NIP-55 auth endpoints.
func NewNIP55Handler(
	authSvc *Service,
	identitySvc *IdentityService,
	relayURLs []string,
	logger *slog.Logger,
) *NIP55Handler {
	return &NIP55Handler{
		authService:     authSvc,
		identityService: identitySvc,
		relayURLs:       relayURLs,
		logger:          logger.With("component", "auth.nip55"),
	}
}

// RegisterRoutes adds the NIP-55 auth routes to the given mux.
func (h *NIP55Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/nip55/challenge", h.methodGuard(http.MethodGet, h.handleChallenge))
	mux.HandleFunc("/auth/nip55/callback", h.methodGuard(http.MethodPost, h.handleCallback))
}

// nip55ChallengeResponse is the JSON response for GET /auth/nip55/challenge.
type nip55ChallengeResponse struct {
	Nonce          string `json:"nonce"`
	NostrSignerURI string `json:"nostrsigner_uri"`
	CallbackURL    string `json:"callback_url"`
	ExpiresAt      string `json:"expires_at"`
}

// nip55CallbackRequest is the JSON body for POST /auth/nip55/callback.
type nip55CallbackRequest struct {
	SignedEvent *nostr.Event `json:"signed_event"`
}

// nip55CallbackResponse is the JSON response for POST /auth/nip55/callback.
type nip55CallbackResponse struct {
	OK          bool             `json:"ok"`
	Identity    ResolvedIdentity `json:"identity"`
	RedirectURI string           `json:"redirect_uri,omitempty"`
}

// handleChallenge issues a NIP-55 login challenge.
// GET /auth/nip55/challenge?redirect_uri=/dashboard
// Response: { "nonce": "...", "nostrsigner_uri": "nostrsigner:...", "callback_url": "...", "expires_at": "..." }
func (h *NIP55Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")

	challenge, err := h.authService.IssueChallenge(r.Context(), ChallengeRequest{
		RedirectURI: redirectURI,
	})
	if err != nil {
		h.logger.Error("issue NIP-55 challenge failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue challenge"})
		return
	}

	metrics.IncNIP55ChallengesIssued()

	// Build the nostrsigner: URI for Android deep linking.
	// Format: nostrsigner:<challenge-payload>?type=sign_event&callbackUrl=<url>
	// The challenge payload includes the nonce and verify URL so the signer
	// can construct the NIP-98 event.
	challengePayload := url.QueryEscape(fmt.Sprintf(`{"nonce":"%s","url":"%s","method":"POST"}`, challenge.Nonce, challenge.URL))
	callbackURL := h.authService.publicURL + "/auth/nip55/callback"
	signerURI := fmt.Sprintf("nostrsigner:%s?type=sign_event&callbackUrl=%s",
		challengePayload, url.QueryEscape(callbackURL))

	h.writeJSON(w, http.StatusOK, nip55ChallengeResponse{
		Nonce:          challenge.Nonce,
		NostrSignerURI: signerURI,
		CallbackURL:    callbackURL,
		ExpiresAt:      challenge.ExpiresAt.Format(time.RFC3339),
	})
}

// handleCallback processes a signed NIP-98 event from an Android signer.
// POST /auth/nip55/callback
// Request: { "signed_event": { ... nostr event ... } }
// Response: { "ok": true, "identity": { ... }, "redirect_uri": "..." }
func (h *NIP55Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	var req nip55CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.IncNIP55VerifyFailure()
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	if req.SignedEvent == nil {
		metrics.IncNIP55VerifyFailure()
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signed_event is required"})
		return
	}

	ev := req.SignedEvent

	// 1. Validate event ID and signature.
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		metrics.IncNIP55VerifyFailure()
		h.logger.Warn("NIP-55 callback: event failed signature check", "error", err)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid event signature"})
		return
	}

	// 2. Validate NIP-98 semantics.
	if ev.Kind != 27235 {
		metrics.IncNIP55VerifyFailure()
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "expected kind 27235 for NIP-98"})
		return
	}

	// Check time window.
	eventTime := time.Unix(int64(ev.CreatedAt), 0)
	if time.Since(eventTime).Abs() > 60*time.Second {
		metrics.IncNIP55VerifyFailure()
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "event timestamp too far from current time"})
		return
	}

	// 3. Extract and validate the nonce.
	nonce := tagValue(ev.Tags, "nonce")
	if nonce == "" {
		metrics.IncNIP55VerifyFailure()
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing nonce tag"})
		return
	}

	challenge, err := h.authService.ValidateChallenge(r.Context(), nonce)
	if err != nil {
		metrics.IncNIP55VerifyFailure()
		h.logger.Warn("NIP-55 callback: challenge validation failed", "nonce", nonce, "error", err)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	// 4. Consume the challenge (single-use).
	if err := h.authService.ConsumeChallenge(r.Context(), nonce); err != nil {
		metrics.IncNIP55VerifyFailure()
		h.logger.Error("NIP-55 callback: consume challenge failed", "nonce", nonce, "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to consume challenge"})
		return
	}

	// 5. Resolve or create the Gitea user.
	identity, err := h.identityService.ResolveOrCreate(r.Context(), ev.PubKey, h.relayURLs)
	if err != nil {
		metrics.IncNIP55VerifyFailure()
		h.logger.Error("NIP-55 callback: identity resolution failed", "pubkey", ev.PubKey, "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to resolve identity"})
		return
	}

	metrics.IncNIP55VerifySuccess()
	h.logger.Info("NIP-55 login verified", "pubkey", ev.PubKey, "gitea_user", identity.GiteaUser)

	h.writeJSON(w, http.StatusOK, nip55CallbackResponse{
		OK:          true,
		Identity:    identity,
		RedirectURI: challenge.RedirectURI,
	})
}

func (h *NIP55Handler) methodGuard(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

func (h *NIP55Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

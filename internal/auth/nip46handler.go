// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// NIP46SessionTTL is the default lifetime of a NIP-46 login session.
const NIP46SessionTTL = 2 * time.Minute

// NIP46Handler provides HTTP endpoints for the NIP-46 remote signer
// (bunker) login flow: session init and status polling.
type NIP46Handler struct {
	store           *store.SQLiteStore
	identityService *IdentityService
	relayURLs       []string
	publicURL       string
	logger          *slog.Logger
	// BunkerConnector is called asynchronously to connect to a bunker and
	// sign a challenge event. Implementations should block until signing
	// completes or the context expires. The interface is kept abstract so
	// the actual NIP-46 SDK wiring can be swapped in without changing the
	// handler. For testing, a mock connector is used.
	BunkerConnector BunkerConnector
}

// BunkerConnector abstracts the NIP-46 bunker signing flow.
// Implementations connect to a bunker via relay, request a signature on a
// challenge event, and return the signer's pubkey on success.
type BunkerConnector interface {
	// Connect initiates the NIP-46 flow. It should:
	// 1. Parse the bunker URI to extract relay URL and bunker pubkey
	// 2. Connect to the bunker via the relay
	// 3. Request signing of a challenge event
	// 4. Return the signer's verified pubkey
	Connect(ctx context.Context, bunkerURI string) (signerPubkey string, err error)
}

// NewNIP46Handler creates a new handler for NIP-46 auth endpoints.
func NewNIP46Handler(
	st *store.SQLiteStore,
	identitySvc *IdentityService,
	relayURLs []string,
	publicURL string,
	connector BunkerConnector,
	logger *slog.Logger,
) *NIP46Handler {
	return &NIP46Handler{
		store:           st,
		identityService: identitySvc,
		relayURLs:       relayURLs,
		publicURL:       publicURL,
		BunkerConnector: connector,
		logger:          logger.With("component", "auth.nip46"),
	}
}

// RegisterRoutes adds the NIP-46 auth routes to the given mux.
func (h *NIP46Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/nip46/init", h.methodGuard(http.MethodPost, h.handleInit))
	mux.HandleFunc("/auth/nip46/status", h.methodGuard(http.MethodGet, h.handleStatus))
}

// nip46InitRequest is the JSON body for POST /auth/nip46/init.
type nip46InitRequest struct {
	BunkerURI   string `json:"bunker_uri"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// nip46InitResponse is the JSON response for a successful init.
type nip46InitResponse struct {
	SessionToken string `json:"session_token"`
	PollURL      string `json:"poll_url"`
	ExpiresAt    string `json:"expires_at"`
}

// nip46StatusResponse is the JSON response for GET /auth/nip46/status.
type nip46StatusResponse struct {
	Status      string            `json:"status"` // pending, complete, error
	Identity    *ResolvedIdentity `json:"identity,omitempty"`
	RedirectURI string            `json:"redirect_uri,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// handleInit starts a new NIP-46 login session.
// POST /auth/nip46/init
// Request: { "bunker_uri": "bunker://...", "redirect_uri": "/dashboard" }
// Response: { "session_token": "...", "poll_url": "...", "expires_at": "..." }
func (h *NIP46Handler) handleInit(w http.ResponseWriter, r *http.Request) {
	var req nip46InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	if req.BunkerURI == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bunker_uri is required"})
		return
	}

	// Validate bunker URI format.
	bunkerPubkey, err := parseBunkerURI(req.BunkerURI)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid bunker_uri: %v", err)})
		return
	}

	// Generate session token.
	token, err := generateSessionToken()
	if err != nil {
		h.logger.Error("generate session token failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	now := time.Now().UTC()
	sess := store.NIP46Session{
		SessionToken: token,
		BunkerPubkey: bunkerPubkey,
		ClientPubkey: "", // filled by connector
		State:        "pending",
		RedirectURI:  req.RedirectURI,
		CreatedAt:    now,
		ExpiresAt:    now.Add(NIP46SessionTTL),
	}

	if err := h.store.CreateNIP46Session(r.Context(), sess); err != nil {
		h.logger.Error("create NIP-46 session failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	metrics.IncNIP46SessionsInitiated()

	// Start async bunker connection.
	go h.runBunkerFlow(token, req.BunkerURI)

	pollURL := h.publicURL + "/auth/nip46/status?session=" + url.QueryEscape(token)
	h.writeJSON(w, http.StatusOK, nip46InitResponse{
		SessionToken: token,
		PollURL:      pollURL,
		ExpiresAt:    sess.ExpiresAt.Format(time.RFC3339),
	})
}

// handleStatus returns the current state of a NIP-46 login session.
// GET /auth/nip46/status?session=<token>
func (h *NIP46Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("session")
	if token == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	sess, err := h.store.GetNIP46Session(r.Context(), token)
	if err == sql.ErrNoRows {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if err != nil {
		h.logger.Error("get NIP-46 session failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Check if session has expired.
	if time.Now().UTC().After(sess.ExpiresAt) && sess.State == "pending" {
		h.writeJSON(w, http.StatusOK, nip46StatusResponse{
			Status: "error",
			Error:  "session expired",
		})
		return
	}

	resp := nip46StatusResponse{
		Status: sess.State,
	}

	switch sess.State {
	case "complete":
		// Resolve identity for the verified pubkey.
		identity, err := h.identityService.ResolveOrCreate(r.Context(), sess.ResultPubkey, h.relayURLs)
		if err != nil {
			h.logger.Error("identity resolution failed for NIP-46 session", "pubkey", sess.ResultPubkey, "error", err)
			resp.Status = "error"
			resp.Error = "identity resolution failed"
		} else {
			resp.Identity = &identity
			resp.RedirectURI = sess.RedirectURI
		}
	case "error":
		resp.Error = sess.Error
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// runBunkerFlow runs the NIP-46 bunker connection in a goroutine.
func (h *NIP46Handler) runBunkerFlow(sessionToken string, bunkerURI string) {
	ctx, cancel := context.WithTimeout(context.Background(), NIP46SessionTTL)
	defer cancel()

	if h.BunkerConnector == nil {
		h.logger.Error("no bunker connector configured")
		h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", "bunker connector not configured")
		metrics.IncNIP46SessionsFailed()
		return
	}

	signerPubkey, err := h.BunkerConnector.Connect(ctx, bunkerURI)
	if err != nil {
		h.logger.Warn("bunker connection failed", "session", sessionToken, "error", err)
		h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", err.Error())
		metrics.IncNIP46SessionsFailed()
		return
	}

	if err := h.store.UpdateNIP46SessionState(ctx, sessionToken, "complete", signerPubkey, ""); err != nil {
		h.logger.Error("update session state failed", "session", sessionToken, "error", err)
		metrics.IncNIP46SessionsFailed()
		return
	}

	metrics.IncNIP46SessionsCompleted()
	h.logger.Info("NIP-46 bunker login completed", "session", sessionToken, "signer_pubkey", signerPubkey)
}

// parseBunkerURI extracts the bunker pubkey from a bunker:// URI.
// Format: bunker://<hex-pubkey>?relay=wss://...
func parseBunkerURI(uri string) (string, error) {
	if !strings.HasPrefix(uri, "bunker://") {
		return "", fmt.Errorf("must start with bunker://")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid URI: %w", err)
	}

	pubkey := u.Host
	if pubkey == "" {
		// Some bunker URIs put the pubkey in the path.
		pubkey = strings.TrimPrefix(u.Path, "/")
	}

	if len(pubkey) != 64 {
		return "", fmt.Errorf("pubkey must be 64 hex characters, got %d", len(pubkey))
	}

	return pubkey, nil
}

// generateSessionToken returns a cryptographically random hex string for session IDs.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (h *NIP46Handler) methodGuard(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

func (h *NIP46Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

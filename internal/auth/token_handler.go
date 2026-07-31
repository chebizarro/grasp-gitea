// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// maxTokenBodyBytes bounds token-management request bodies.
const maxTokenBodyBytes = 16 << 10

const (
	tokenListDefaultLimit = 50
	tokenListMaxLimit     = 100
)

// TokenHandler exposes the NIP-98-authenticated bridge token API:
//
//	POST   /auth/token              mint
//	GET    /auth/tokens             list (limit/offset)
//	DELETE /auth/tokens/{id}        revoke
//	POST   /auth/tokens/{id}/rotate revoke-and-replace
//
// Every request must carry a fresh Authorization: Nostr proof whose u tag is
// the canonical public URL of the exact endpoint; bodies are bound via the
// payload tag. Proofs are single-use (durable replay claims).
type TokenHandler struct {
	auth   *Service
	tokens *TokenService
	logger *slog.Logger
}

// NewTokenHandler wires the token API. Both services must be enabled.
func NewTokenHandler(authSvc *Service, tokens *TokenService, logger *slog.Logger) *TokenHandler {
	return &TokenHandler{auth: authSvc, tokens: tokens, logger: logger.With("component", "auth.tokens.http")}
}

// RegisterRoutes attaches the token API to the mux.
func (h *TokenHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/token", h.handleMint)
	mux.HandleFunc("GET /auth/tokens", h.handleList)
	mux.HandleFunc("DELETE /auth/tokens/{id}", h.handleRevoke)
	mux.HandleFunc("POST /auth/tokens/{id}/rotate", h.handleRotate)
}

func (h *TokenHandler) handleMint(w http.ResponseWriter, r *http.Request) {
	principal, body, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req MintRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	result, err := h.tokens.Mint(r.Context(), principal.PubKey, principal.EventID, req)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

func (h *TokenHandler) handleList(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	limit := queryInt(r, "limit", tokenListDefaultLimit, 1, tokenListMaxLimit)
	offset := queryInt(r, "offset", 0, 0, 1<<30)
	tokens, err := h.tokens.List(r.Context(), principal.PubKey, limit, offset)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if tokens == nil {
		tokens = []TokenMetadata{}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"tokens": tokens,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *TokenHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "token id is required")
		return
	}
	if err := h.tokens.Revoke(r.Context(), principal.PubKey, id); err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.setNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *TokenHandler) handleRotate(w http.ResponseWriter, r *http.Request) {
	principal, body, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "token id is required")
		return
	}
	var req MintRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	result, err := h.tokens.Rotate(r.Context(), principal.PubKey, id, principal.EventID, req)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// authenticate reads the bounded body and validates the request's NIP-98
// proof against the canonical public URL. On failure it writes the response
// and returns ok=false.
func (h *TokenHandler) authenticate(w http.ResponseWriter, r *http.Request) (*sharednip98.Principal, []byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			h.writeError(w, http.StatusBadRequest, "unreadable request body")
		}
		return nil, nil, false
	}

	principal, err := h.auth.AuthenticateNIP98Request(r.Context(), r, body)
	if err != nil {
		switch {
		case errors.Is(err, ErrNIP98StoreUnavailable):
			h.writeError(w, http.StatusServiceUnavailable, "authorization ledger unavailable")
		default:
			w.Header().Set("WWW-Authenticate", "Nostr")
			h.writeError(w, http.StatusUnauthorized, "invalid NIP-98 authorization")
		}
		return nil, nil, false
	}
	return principal, body, true
}

func (h *TokenHandler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidTokenRequest):
		h.writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrBridgeTokenLimit):
		h.writeError(w, http.StatusTooManyRequests, "active token limit reached")
	case errors.Is(err, store.ErrBridgeTokenNotFound):
		h.writeError(w, http.StatusNotFound, "token not found")
	case errors.Is(err, ErrIdentityLinkRepair):
		h.logger.Error("identity link requires operator repair", "error", err)
		h.writeError(w, http.StatusConflict, "identity link requires operator repair")
	case errors.Is(err, ErrPATProvisioning):
		h.logger.Error("gitea PAT provisioning failed", "error", err)
		h.writeError(w, http.StatusBadGateway, "downstream credential provisioning failed")
	default:
		h.logger.Error("token service failure", "error", err)
		h.writeError(w, http.StatusServiceUnavailable, "token service unavailable")
	}
}

func (h *TokenHandler) setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *TokenHandler) writeJSON(w http.ResponseWriter, status int, payload any) {
	h.setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Warn("token response encode failed", "error", err)
	}
}

func (h *TokenHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, map[string]string{"error": message})
}

func queryInt(r *http.Request, key string, fallback, min, max int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return fallback
	}
	return n
}

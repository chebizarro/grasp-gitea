package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/signer"
)

type signerAuthorizeRequest struct {
	BunkerURI string `json:"bunker_uri"`
}

func (s *Server) signerAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.signerAuthorizer == nil || !s.signerAuthorizer.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "signer subsystem disabled"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req signerAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	req.BunkerURI = strings.TrimSpace(req.BunkerURI)
	if req.BunkerURI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bunker_uri is required"})
		return
	}

	grant, err := s.signerAuthorizer.CreateGrant(r.Context(), req.BunkerURI)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("signer authorization failed", "error", err)
		}
		status := http.StatusBadRequest
		if errors.Is(err, signer.ErrDisabled) {
			status = http.StatusServiceUnavailable
		} else if errors.Is(err, signer.ErrSignerOffline) {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"pubkey":        grant.Pubkey,
		"client_pubkey": grant.ClientPubkey,
		"relays":        grant.Relays,
		"granted_at":    grant.GrantedAt,
	})
}

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"fiatjaf.com/nostr"
	"github.com/sharegap/grasp-gitea/internal/publisher"
)

type proposedRepositoryStateRequest struct {
	GiteaRepoID           int64             `json:"gitea_repo_id"`
	ExpectedCurrentDigest string            `json:"expected_current_digest"`
	Head                  string            `json:"head"`
	Branches              map[string]string `json:"branches"`
	Tags                  map[string]string `json:"tags,omitempty"`
}

func (s *Server) proposeRepositoryState(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var request proposedRepositoryStateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if s.publisher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "publisher unavailable"})
		return
	}
	digest, err := s.publisher.EnqueueProposedState(r.Context(), request.GiteaRepoID, publisher.ProposedRepositoryState{
		ExpectedCurrentDigest: request.ExpectedCurrentDigest,
		Head:                  request.Head,
		Branches:              request.Branches,
		Tags:                  request.Tags,
	})
	if err != nil {
		s.logger.Warn("proposed repository state rejected", "repo_id", request.GiteaRepoID, "error", err)
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "digest": digest})
}

func (s *Server) proposedRepositoryState(w http.ResponseWriter, r *http.Request) {
	pubkey := strings.TrimSpace(r.URL.Query().Get("pubkey"))
	repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
	if !nostr.IsValid32ByteHex(pubkey) || repoID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid pubkey and repo_id are required"})
		return
	}
	held, err := s.store.LatestPurgatoryEvent(r.Context(), pubkey, int(nostr.KindRepositoryState), repoID)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no proposed repository state found"})
		return
	}
	if err != nil {
		s.logger.Error("read proposed repository state", "pubkey", pubkey, "repo_id", repoID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read proposed repository state"})
		return
	}
	var event nostr.Event
	if err := json.Unmarshal([]byte(held.EventJSON), &event); err != nil {
		s.logger.Error("decode proposed repository state", "event_id", held.EventID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to decode proposed repository state"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": event})
}

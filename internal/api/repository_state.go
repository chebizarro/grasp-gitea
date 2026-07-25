package api

import (
	"encoding/json"
	"net/http"

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

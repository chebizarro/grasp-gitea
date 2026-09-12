package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sharegap/grasp-gitea/internal/provisioner"
)

type writableUpstreamRequest struct {
	Npub                string `json:"npub"`
	RepoID              string `json:"repo_id"`
	ExpectedGiteaRepoID int64  `json:"expected_gitea_repo_id"`
	TargetRepoName      string `json:"target_repo_name,omitempty"`
}

func (s *Server) migrateWritableUpstream(w http.ResponseWriter, r *http.Request) {
	if s.provisioner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "repository migration service is not configured"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var request writableUpstreamRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	mapping, err := s.provisioner.MigrateWritableUpstream(r.Context(), request.Npub, request.RepoID, request.ExpectedGiteaRepoID, request.TargetRepoName)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, provisioner.ErrWritableUpstreamPreflight) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, mapping)
}

func (s *Server) rollbackWritableUpstream(w http.ResponseWriter, r *http.Request) {
	if s.provisioner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "repository migration service is not configured"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var request writableUpstreamRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	mapping, err := s.provisioner.RollbackWritableUpstream(r.Context(), request.Npub, request.RepoID, request.ExpectedGiteaRepoID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, provisioner.ErrWritableUpstreamPreflight) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, mapping)
}

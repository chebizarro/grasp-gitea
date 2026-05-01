// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

type mirrorSyncRequest struct {
	RepoID   int64  `json:"repo_id"`
	Owner    string `json:"owner,omitempty"`
	RepoName string `json:"repo_name,omitempty"`
	SyncedAt string `json:"synced_at,omitempty"`
}

// mirrorSync handles POST /internal/mirror-sync callbacks from Gitea
// after a pull mirror sync completes.
func (s *Server) mirrorSync(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req mirrorSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	if req.RepoID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "repo_id is required and must be positive"})
		return
	}

	if s.publisher == nil || !s.publisher.Enabled() {
		// Mirror publishing not configured; accept silently.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "publish_disabled"})
		return
	}

	if err := s.publisher.RepublishForGiteaRepo(r.Context(), req.RepoID); err != nil {
		s.logger.Error("mirror sync republish failed", "repo_id", req.RepoID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "republish failed"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "ok"})
}

// requireMirrorAuth wraps a handler with bearer token authentication
// using the MirrorCallbackToken (separate from the admin API token).
func (s *Server) requireMirrorAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.mirrorCallbackToken == "" {
			// No token configured; reject for safety.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "mirror callback not configured"})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			token = auth
		}
		if token != s.mirrorCallbackToken {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
			return
		}

		next(w, r)
	}
}

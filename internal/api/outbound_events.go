// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/http"
	"strconv"
)

// outboundEvents handles GET /outbound-events for admin queue inspection.
func (s *Server) outboundEvents(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}
	counts, err := s.store.OutboundQueueCounts(r.Context())
	if err != nil {
		if s.logger != nil {
			s.logger.Error("outbound queue counts failed", "error", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load outbound queue counts"})
		return
	}
	recent, err := s.store.RecentOutboundEvents(r.Context(), limit)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("recent outbound events failed", "error", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load outbound events"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "recent": recent})
}

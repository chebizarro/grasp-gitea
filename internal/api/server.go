package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// maxRequestBodySize limits POST request bodies to 1 MB.
const maxRequestBodySize = 1 << 20

type Server struct {
	provisioner          *provisioner.Service
	publisher            *publisher.Service
	store                *store.SQLiteStore
	logger               *slog.Logger
	apiToken             string
	mirrorCallbackToken  string
}

func New(cfg config.Config, provisionerSvc *provisioner.Service, publisherSvc *publisher.Service, st *store.SQLiteStore, logger *slog.Logger) *Server {
	return &Server{
		provisioner:         provisionerSvc,
		publisher:           publisherSvc,
		store:               st,
		logger:              logger,
		apiToken:            cfg.AdminAPIToken,
		mirrorCallbackToken: cfg.MirrorCallbackToken,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", method(http.MethodGet, s.health))
	mux.HandleFunc("/metrics", method(http.MethodGet, s.requireAuth(s.metrics)))
	mux.HandleFunc("/mappings", method(http.MethodGet, s.requireAuth(s.mappings)))
	mux.HandleFunc("/provision", method(http.MethodPost, s.requireAuth(s.manualProvision)))
	mux.HandleFunc("/internal/mirror-sync", method(http.MethodPost, s.requireMirrorAuth(s.mirrorSync)))
	return mux
}

// requireAuth wraps a handler with bearer token authentication.
// If no AdminAPIToken is configured, all requests are allowed (open mode).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken == "" {
			// No token configured; allow all requests (backwards-compatible).
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
			return
		}

		// Accept "Bearer <token>" format.
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			// No "Bearer " prefix; try plain token.
			token = auth
		}
		if token != s.apiToken {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
			return
		}

		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"metrics": metrics.Snapshot()})
}

func (s *Server) mappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := s.store.ListMappings(r.Context())
	if err != nil {
		s.logger.Error("list mappings failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list mappings"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"mappings": mappings})
}

func (s *Server) manualProvision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Npub   string `json:"npub"`
		Pubkey string `json:"pubkey"`
		RepoID string `json:"repo_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	req.Npub = strings.TrimSpace(req.Npub)
	req.Pubkey = strings.TrimSpace(req.Pubkey)
	req.RepoID = strings.TrimSpace(req.RepoID)
	if req.Npub == "" || req.RepoID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "npub and repo_id are required"})
		return
	}

	result, err := s.provisioner.ManualProvision(r.Context(), req.Npub, req.Pubkey, req.RepoID)
	if err != nil {
		s.logger.Error("manual provision failed", "npub", req.Npub, "repo_id", req.RepoID, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func method(expected string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

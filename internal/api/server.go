package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/oauth2"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/webhook"
)

type Server struct {
	provisioner    *provisioner.Service
	store          *store.SQLiteStore
	logger         *slog.Logger
	oauth2Provider *oauth2.Provider  // nil when NIP-07 auth is disabled
	webhookHandler *webhook.Handler  // nil when publishing is disabled
}

func New(provisionerSvc *provisioner.Service, st *store.SQLiteStore, logger *slog.Logger) *Server {
	return &Server{provisioner: provisionerSvc, store: st, logger: logger}
}

// SetOAuth2Provider enables NIP-07 web auth routes.
func (s *Server) SetOAuth2Provider(p *oauth2.Provider) {
	s.oauth2Provider = p
}

// SetWebhookHandler enables the Gitea webhook receiver endpoint.
func (s *Server) SetWebhookHandler(h *webhook.Handler) {
	s.webhookHandler = h
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", method(http.MethodGet, s.health))
	mux.HandleFunc("/metrics", method(http.MethodGet, s.metrics))
	mux.HandleFunc("/mappings", method(http.MethodGet, s.mappings))
	mux.HandleFunc("/provision", method(http.MethodPost, s.manualProvision))

	if s.webhookHandler != nil {
		mux.Handle("/webhook/gitea", s.webhookHandler)
	}

	if s.oauth2Provider != nil {
		mux.HandleFunc("/.well-known/openid-configuration", method(http.MethodGet, s.oauth2Provider.HandleDiscovery))
		mux.HandleFunc("/auth/oauth2/authorize", method(http.MethodGet, s.oauth2Provider.HandleAuthorize))
		mux.HandleFunc("/auth/nip07/verify", method(http.MethodPost, s.oauth2Provider.HandleVerify))
		mux.HandleFunc("/auth/oauth2/token", method(http.MethodPost, s.oauth2Provider.HandleToken))
		mux.HandleFunc("/auth/oauth2/userinfo", method(http.MethodGet, s.oauth2Provider.HandleUserInfo))
		// NIP-46 remote signing (bunker)
		mux.HandleFunc("/auth/nip46/init", method(http.MethodPost, s.oauth2Provider.HandleNIP46Init))
		mux.HandleFunc("/auth/nip46/status", method(http.MethodGet, s.oauth2Provider.HandleNIP46Status))
		// NIP-55 Android signer
		mux.HandleFunc("/auth/nip55/challenge", method(http.MethodGet, s.oauth2Provider.HandleNIP55Challenge))
		mux.HandleFunc("/auth/nip55/callback", s.oauth2Provider.HandleNIP55Callback) // GET+POST
	}

	return mux
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

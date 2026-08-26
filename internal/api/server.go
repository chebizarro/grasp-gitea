package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/giteaproxy"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/signer"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// maxRequestBodySize limits POST request bodies to 1 MB.
const maxRequestBodySize = 1 << 20

type Server struct {
	provisioner         *provisioner.Service
	publisher           *publisher.Service
	store               *store.SQLiteStore
	logger              *slog.Logger
	apiToken            string
	mirrorCallbackToken string
	webhookHandler      http.Handler // Gitea webhook handler for NIP-34 events
	routeRegistrars     []func(*http.ServeMux)
	readinessProbes     []ReadinessProbe
	giteaProxy          *giteaproxy.Proxy
	rootRelayHandler    http.Handler
	signerAuthorizer    SignerAuthorizer
	policyStore         *policy.Store
}

type SignerAuthorizer interface {
	Enabled() bool
	CreateGrant(ctx context.Context, bunkerURI string) (signer.GrantInfo, error)
}

func New(cfg config.Config, provisionerSvc *provisioner.Service, publisherSvc *publisher.Service, st *store.SQLiteStore, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		provisioner:         provisionerSvc,
		publisher:           publisherSvc,
		store:               st,
		logger:              logger,
		apiToken:            cfg.AdminAPIToken,
		mirrorCallbackToken: cfg.MirrorCallbackToken,
	}
	// A proxy without a token authenticator or repository inspector still
	// serves anonymous public traffic; main injects the fully wired one.
	// An unset GiteaURL simply means this Server does not proxy git.
	if cfg.GiteaURL != "" {
		proxy, err := giteaproxy.New(giteaproxy.Config{
			GiteaURL:           cfg.GiteaURL,
			PublicURL:          cfg.BridgePublicURL,
			EdgeSharedSecret:   cfg.EdgeSharedSecret,
			GitBackendUser:     cfg.GitBackendUser,
			GitBackendPassword: cfg.GitBackendPassword,
			FullProxy:          cfg.FullProxyEnabled,
		}, nil, nil, st, logger)
		if err != nil {
			logger.Error("gitea proxy unavailable; git smart-HTTP will fail", "gitea_url", cfg.GiteaURL, "error", err)
		} else {
			s.giteaProxy = proxy
		}
	}
	return s
}

// SetGiteaProxy installs the fully wired streaming proxy (token
// authentication and live repository visibility).
func (s *Server) SetGiteaProxy(p *giteaproxy.Proxy) {
	if p != nil {
		s.giteaProxy = p
	}
}

// SetRootRelayHandler serves a Nostr relay (WebSocket upgrade + NIP-11
// content negotiation) at the service root, per GRASP-01 single-endpoint
// requirements.
func (s *Server) SetRootRelayHandler(h http.Handler) {
	s.rootRelayHandler = h
}

// SetWebhookHandler wires the Gitea webhook handler for NIP-34 event publishing.
func (s *Server) SetWebhookHandler(h http.Handler) {
	s.webhookHandler = h
}

// SetSignerAuthorizer wires persistent NIP-46 grant authorization endpoints.
func (s *Server) SetSignerAuthorizer(authorizer SignerAuthorizer) {
	s.signerAuthorizer = authorizer
}

func (s *Server) SetPolicyStore(store *policy.Store) { s.policyStore = store }

// AddRouteRegistrar lets optional subsystems register extra routes on the main mux.
func (s *Server) AddRouteRegistrar(register func(*http.ServeMux)) {
	if register != nil {
		s.routeRegistrars = append(s.routeRegistrars, register)
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", method(http.MethodGet, s.health))
	mux.HandleFunc("/ready", method(http.MethodGet, s.ready))
	mux.HandleFunc("/metrics", method(http.MethodGet, s.requireAuth(s.metrics)))
	mux.HandleFunc("/mappings", method(http.MethodGet, s.requireAuth(s.mappings)))
	mux.HandleFunc("/outbound-events", method(http.MethodGet, s.requireAuth(s.outboundEvents)))
	mux.HandleFunc("/signer/authorize", method(http.MethodPost, s.requireAuth(s.signerAuthorize)))
	mux.HandleFunc("/repository-state/propose", method(http.MethodPost, s.requireAuth(s.proposeRepositoryState)))
	mux.HandleFunc("/repository-state/proposed", method(http.MethodGet, s.requireAuth(s.proposedRepositoryState)))
	mux.HandleFunc("/provision", method(http.MethodPost, s.requireAuth(s.manualProvision)))
	mux.HandleFunc("/admin/policy", s.requireAuth(s.policyDocument))
	mux.HandleFunc("/admin/policy/", s.requireAuth(s.policyGroup))
	mux.HandleFunc("/internal/mirror-sync", method(http.MethodPost, s.requireMirrorAuth(s.mirrorSync)))

	// Gitea webhook endpoint for NIP-34 events (PRs, issues, patches, labels)
	if s.webhookHandler != nil {
		mux.Handle("/webhook/gitea", s.webhookHandler)
	}

	for _, register := range s.routeRegistrars {
		register(mux)
	}

	mux.HandleFunc("/", s.rootHandler)

	return mux
}

func (s *Server) policyDocument(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.policyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store is not configured"})
		return
	}
	writeJSON(w, http.StatusOK, s.policyStore.Document())
}

func (s *Server) policyGroup(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store is not configured"})
		return
	}
	group := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/policy/"), "/")
	if group == "" || strings.Contains(group, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown policy group"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, ok := s.policyStore.Group(group)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown policy group"})
			return
		}
		writeJSON(w, http.StatusOK, value)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := s.policyStore.UpdateGroup(group, raw); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		value, _ := s.policyStore.Group(group)
		writeJSON(w, http.StatusOK, value)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// requireAuth wraps an administrative handler with fail-closed bearer-token
// authentication. A missing token is a configuration failure, never an open
// mode, even when a Server is constructed outside the production entrypoint.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "admin authentication is not configured"})
			return
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if auth == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer authorization required"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.apiToken)) != 1 {
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

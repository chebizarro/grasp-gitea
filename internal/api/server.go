package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/giteaproxy"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/publisher"
	"github.com/sharegap/grasp-gitea/internal/signer"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	// maxRequestBodySize limits POST request bodies to 1 MB.
	maxRequestBodySize             = 1 << 20
	defaultDomainAffiliationMaxAge = 24 * time.Hour
	domainCatalogLimit             = 100
)

type Server struct {
	provisioner             *provisioner.Service
	publisher               *publisher.Service
	store                   *store.SQLiteStore
	affiliationStore        store.AuthStore
	logger                  *slog.Logger
	apiToken                string
	mirrorCallbackToken     string
	webhookHandler          http.Handler // Gitea webhook handler for NIP-34 events
	routeRegistrars         []func(*http.ServeMux)
	readinessProbes         []ReadinessProbe
	giteaProxy              *giteaproxy.Proxy
	repositoryInspector     giteaproxy.RepositoryInspector
	domainAffiliationMaxAge time.Duration
	rootRelayHandler        http.Handler
	signerAuthorizer        SignerAuthorizer
	policyStore             *policy.Store
	tenantOperator          TenantOperator
	scimHandler             http.Handler
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
		provisioner:             provisionerSvc,
		publisher:               publisherSvc,
		store:                   st,
		logger:                  logger,
		apiToken:                cfg.AdminAPIToken,
		mirrorCallbackToken:     cfg.MirrorCallbackToken,
		domainAffiliationMaxAge: cfg.DomainAffiliationMaxAge,
	}
	if s.domainAffiliationMaxAge <= 0 {
		s.domainAffiliationMaxAge = defaultDomainAffiliationMaxAge
	}
	// A proxy without a token authenticator or repository inspector still
	// serves anonymous public traffic; main injects the fully wired one.
	// An unset GiteaURL simply means this Server does not proxy git.
	if st != nil {
		s.affiliationStore = st
	}
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

// SetRepositoryInspector installs the live Gitea repository metadata source
// used to fail closed when building public domain catalogs.
func (s *Server) SetRepositoryInspector(inspector giteaproxy.RepositoryInspector) {
	s.repositoryInspector = inspector
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

// SetAffiliationStore selects the shared affiliation backend. Main wires the
// Postgres-backed AuthStore here when POSTGRES_DSN is configured.
func (s *Server) SetAffiliationStore(st store.AuthStore) { s.affiliationStore = st }
func (s *Server) SetTenantOperator(op TenantOperator)    { s.tenantOperator = op }
func (s *Server) SetSCIMHandler(h http.Handler)          { s.scimHandler = h }

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
	mux.HandleFunc("/admin/tenants/", s.requireAuth(s.tenantAction))
	if s.scimHandler != nil {
		mux.Handle("/scim/v2/", s.scimHandler)
	}
	mux.HandleFunc("/internal/mirror-sync", method(http.MethodPost, s.requireMirrorAuth(s.mirrorSync)))
	mux.HandleFunc("/domains/", method(http.MethodGet, s.domainCatalog))
	mux.HandleFunc("/verified-badges/", method(http.MethodGet, s.verifiedBadge))

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

func (s *Server) domainCatalog(w http.ResponseWriter, r *http.Request) {
	const prefix = "/domains/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if !strings.HasSuffix(rest, "/repositories") {
		http.NotFound(w, r)
		return
	}
	rawHost := strings.TrimSuffix(rest, "/repositories")
	if rawHost == "" || strings.Contains(rawHost, "/") {
		http.NotFound(w, r)
		return
	}
	host, err := nip05resolve.CanonicalizeHost(rawHost)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain host"})
		return
	}
	if s.affiliationStore == nil || s.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "domain catalog unavailable"})
		return
	}
	affiliations, err := s.affiliationStore.ListVerifiedDomainAffiliations(
		r.Context(), host, time.Now().UTC().Add(-s.domainAffiliationMaxAge), domainCatalogLimit,
	)
	if err != nil {
		s.logger.Error("list verified domain affiliations failed", "host", host, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list domain affiliations"})
		return
	}
	if len(affiliations) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"host": host, "repositories": []any{}})
		return
	}
	pubkeys := make([]string, 0, len(affiliations))
	for _, affiliation := range affiliations {
		pubkeys = append(pubkeys, affiliation.Pubkey)
	}
	mappings, err := s.store.ListMappingsByPubkeys(r.Context(), pubkeys, domainCatalogLimit)
	if err != nil {
		s.logger.Error("list mappings for domain catalog failed", "host", host, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list repositories"})
		return
	}
	type catalogRepository struct {
		Npub   string `json:"npub"`
		Pubkey string `json:"pubkey"`
		RepoID string `json:"repo_id"`
		URL    string `json:"url"`
	}
	repositories := make([]catalogRepository, 0)
	for _, mapping := range mappings {
		if !mapping.HookInstalled || s.repositoryInspector == nil {
			continue
		}
		repo, err := s.repositoryInspector.GetRepo(r.Context(), mapping.Owner, mapping.RepoName)
		if err != nil || repo.ID != mapping.GiteaRepoID || !repo.PubliclyReadable() {
			continue
		}
		repositories = append(repositories, catalogRepository{
			Npub: mapping.Npub, Pubkey: mapping.Pubkey, RepoID: mapping.RepoID,
			URL: "/" + url.PathEscape(mapping.Npub) + "/" + url.PathEscape(mapping.RepoID) + ".git",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "repositories": repositories})
}

type publicDomainAffiliation struct {
	Identifier string    `json:"identifier,omitempty"`
	Host       string    `json:"host,omitempty"`
	Status     string    `json:"status"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

func (s *Server) verifiedBadge(w http.ResponseWriter, r *http.Request) {
	pubkey := strings.TrimPrefix(r.URL.Path, "/verified-badges/")
	if pubkey == "" || strings.Contains(pubkey, "/") {
		http.NotFound(w, r)
		return
	}
	if s.affiliationStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "verified badge unavailable"})
		return
	}
	affiliation, err := s.affiliationStore.GetDomainAffiliation(r.Context(), strings.ToLower(pubkey))
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{"pubkey": strings.ToLower(pubkey), "verified": false})
		return
	}
	if err != nil {
		s.logger.Error("verified badge lookup failed", "pubkey", pubkey, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to lookup verified badge"})
		return
	}
	status := affiliation.Status
	verified := status == store.DomainAffiliationVerified
	if verified && affiliation.CheckedAt.Before(time.Now().UTC().Add(-s.domainAffiliationMaxAge)) {
		status = store.DomainAffiliationStale
		verified = false
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pubkey":   affiliation.Pubkey,
		"verified": verified,
		"affiliation": publicDomainAffiliation{
			Identifier: affiliation.CanonicalIdentifier,
			Host:       affiliation.Host,
			Status:     status,
			VerifiedAt: affiliation.VerifiedAt,
			CheckedAt:  affiliation.CheckedAt,
		},
	})
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/signer"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	// NIP46SessionTTL is the default lifetime of a NIP-46 login session.
	NIP46SessionTTL = 2 * time.Minute

	nip46InitWindow       = time.Minute
	nip46InitPerIPLimit   = 10
	nip46InitGlobalLimit  = 100
	nip46MaxActiveFlows   = 16
	nip46MaxTrackedIPs    = 1024
	nip46CleanupInterval  = time.Minute
	nip46MaxInitBodyBytes = 64 << 10
)

// NIP46Handler provides HTTP endpoints for the NIP-46 remote signer
// (bunker) login flow: session init and status polling.
type NIP46Handler struct {
	store           *store.SQLiteStore
	identityService *IdentityService
	relayURLs       []string
	publicURL       string
	logger          *slog.Logger
	// GrantCreator is called asynchronously to connect to a bunker, verify the
	// signer, and persist a reusable NIP-46 signing grant. The signer.Service
	// satisfies this interface; tests provide fakes or a service with a fake
	// bunker connector.
	GrantCreator GrantCreator
	Backfiller   ActorEventBackfiller

	limitMu        sync.Mutex
	ipWindows      map[string]initRateWindow
	globalWindow   initRateWindow
	flowSlots      chan struct{}
	trustedProxies []*net.IPNet
}

type initRateWindow struct {
	started time.Time
	count   int
}

// GrantCreator abstracts durable NIP-46 signer authorization.
type GrantCreator interface {
	CreateGrant(ctx context.Context, bunkerURI string) (signer.GrantInfo, error)
}

// ActorEventBackfiller enqueues pre-link actor events after a signer pubkey is
// resolved to a Gitea user identity link.
type ActorEventBackfiller interface {
	EnqueuePending(ctx context.Context, giteaUserID int64, pubkey string) (int, error)
}

// NewNIP46Handler creates a new handler for NIP-46 auth endpoints.
func NewNIP46Handler(
	st *store.SQLiteStore,
	identitySvc *IdentityService,
	relayURLs []string,
	publicURL string,
	grantCreator GrantCreator,
	logger *slog.Logger,
) *NIP46Handler {
	return &NIP46Handler{
		store:           st,
		identityService: identitySvc,
		relayURLs:       relayURLs,
		publicURL:       publicURL,
		GrantCreator:    grantCreator,
		logger:          logger.With("component", "auth.nip46"),
		ipWindows:       make(map[string]initRateWindow),
		flowSlots:       make(chan struct{}, nip46MaxActiveFlows),
	}
}

// SetTrustedProxyCIDRs configures proxies whose forwarded client-address
// headers may be used for per-IP admission control. Untrusted peers can never
// influence the selected client IP.
func (h *NIP46Handler) SetTrustedProxyCIDRs(cidrs []string) {
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, network, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
			trusted = append(trusted, network)
		}
	}
	h.trustedProxies = trusted
}

// SetActorEventBackfiller wires the optional pre-link actor event backfill hook.
func (h *NIP46Handler) SetActorEventBackfiller(backfiller ActorEventBackfiller) {
	h.Backfiller = backfiller
}

// RegisterRoutes adds the NIP-46 auth routes to the given mux.
func (h *NIP46Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/nip46/init", h.methodGuard(http.MethodPost, h.handleInit))
	mux.HandleFunc("/auth/nip46/status", h.methodGuard(http.MethodGet, h.handleStatus))
}

// nip46InitRequest is the JSON body for POST /auth/nip46/init.
type nip46InitRequest struct {
	BunkerURI   string `json:"bunker_uri"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// nip46InitResponse is the JSON response for a successful init.
type nip46InitResponse struct {
	SessionToken string `json:"session_token"`
	PollURL      string `json:"poll_url"`
	ExpiresAt    string `json:"expires_at"`
}

// nip46StatusResponse is the JSON response for GET /auth/nip46/status.
type nip46StatusResponse struct {
	Status      string            `json:"status"` // pending, complete, error
	Identity    *ResolvedIdentity `json:"identity,omitempty"`
	RedirectURI string            `json:"redirect_uri,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// handleInit starts a new NIP-46 login session.
// POST /auth/nip46/init
// Request: { "bunker_uri": "bunker://...", "redirect_uri": "/dashboard" }
// Response: { "session_token": "...", "poll_url": "...", "expires_at": "..." }
func (h *NIP46Handler) handleInit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nip46MaxInitBodyBytes)
	var req nip46InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	if req.BunkerURI == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bunker_uri is required"})
		return
	}

	// Validate bunker URI format.
	bunkerPubkey, err := parseBunkerURI(req.BunkerURI)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid bunker_uri: %v", err)})
		return
	}

	if !h.admitInit(h.clientIP(r), time.Now().UTC()) {
		h.writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many NIP-46 initialization requests"})
		return
	}
	releaseFlow := true
	defer func() {
		if releaseFlow {
			h.releaseFlow()
		}
	}()

	// Generate session token.
	token, err := generateSessionToken()
	if err != nil {
		h.logger.Error("generate session token failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	now := time.Now().UTC()
	sess := store.NIP46Session{
		SessionToken: token,
		BunkerPubkey: bunkerPubkey,
		ClientPubkey: "", // filled by connector
		State:        "pending",
		RedirectURI:  req.RedirectURI,
		CreatedAt:    now,
		ExpiresAt:    now.Add(NIP46SessionTTL),
	}

	if err := h.store.CreateNIP46Session(r.Context(), sess); err != nil {
		h.logger.Error("create NIP-46 session failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	metrics.IncNIP46SessionsInitiated()

	// Start async bunker connection. The admission slot remains held until the
	// complete grant/identity flow exits, bounding expensive remote work.
	releaseFlow = false
	go func() {
		defer h.releaseFlow()
		h.runBunkerFlow(token, req.BunkerURI)
	}()

	pollURL := h.publicURL + "/auth/nip46/status?session=" + url.QueryEscape(token)
	h.writeJSON(w, http.StatusOK, nip46InitResponse{
		SessionToken: token,
		PollURL:      pollURL,
		ExpiresAt:    sess.ExpiresAt.Format(time.RFC3339),
	})
}

// RunCleanup deletes expired public auth records until ctx is cancelled.
// It bounds durable session/challenge growth even when clients never poll.
func (h *NIP46Handler) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(nip46CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := h.store.DeleteExpiredNIP46Sessions(ctx); err != nil {
				h.logger.Warn("delete expired NIP-46 sessions failed", "error", err)
			} else if n > 0 {
				h.logger.Debug("deleted expired NIP-46 sessions", "count", n)
			}
			if n, err := h.store.DeleteExpiredChallenges(ctx); err != nil {
				h.logger.Warn("delete expired auth challenges failed", "error", err)
			} else if n > 0 {
				h.logger.Debug("deleted expired auth challenges", "count", n)
			}
		}
	}
}

func (h *NIP46Handler) admitInit(ip string, now time.Time) bool {
	h.limitMu.Lock()
	defer h.limitMu.Unlock()

	if now.Sub(h.globalWindow.started) >= nip46InitWindow || h.globalWindow.started.IsZero() {
		h.globalWindow = initRateWindow{started: now}
	}
	if h.globalWindow.count >= nip46InitGlobalLimit {
		return false
	}

	window, ok := h.ipWindows[ip]
	if !ok || now.Sub(window.started) >= nip46InitWindow {
		if !ok && len(h.ipWindows) >= nip46MaxTrackedIPs {
			h.evictOldestIPWindow()
		}
		window = initRateWindow{started: now}
	}
	if window.count >= nip46InitPerIPLimit {
		return false
	}

	select {
	case h.flowSlots <- struct{}{}:
		window.count++
		h.ipWindows[ip] = window
		h.globalWindow.count++
		return true
	default:
		return false
	}
}

func (h *NIP46Handler) evictOldestIPWindow() {
	var oldestIP string
	var oldest time.Time
	for ip, window := range h.ipWindows {
		if oldestIP == "" || window.started.Before(oldest) {
			oldestIP = ip
			oldest = window.started
		}
	}
	if oldestIP != "" {
		delete(h.ipWindows, oldestIP)
	}
}

func (h *NIP46Handler) releaseFlow() {
	select {
	case <-h.flowSlots:
	default:
	}
}

func (h *NIP46Handler) clientIP(r *http.Request) string {
	peer := parseRemoteIP(r.RemoteAddr)
	if peer == nil || !h.trustedProxy(peer) {
		if peer == nil {
			return "unknown"
		}
		return peer.String()
	}

	// Walk the proxy chain from nearest to farthest and select the first
	// untrusted address. This prevents a client-supplied leftmost value from
	// overriding the address appended by a trusted reverse proxy.
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(forwarded[i]))
		if candidate != nil && !h.trustedProxy(candidate) {
			return candidate.String()
		}
	}
	return peer.String()
}

func (h *NIP46Handler) trustedProxy(ip net.IP) bool {
	for _, network := range h.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(remoteAddr))
}

// handleStatus returns the current state of a NIP-46 login session.
// GET /auth/nip46/status?session=<token>
func (h *NIP46Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("session")
	if token == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	sess, err := h.store.GetNIP46Session(r.Context(), token)
	if err == sql.ErrNoRows {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if err != nil {
		h.logger.Error("get NIP-46 session failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Check if session has expired.
	if time.Now().UTC().After(sess.ExpiresAt) && sess.State == "pending" {
		h.writeJSON(w, http.StatusOK, nip46StatusResponse{
			Status: "error",
			Error:  "session expired",
		})
		return
	}

	resp := nip46StatusResponse{
		Status: sess.State,
	}

	switch sess.State {
	case "complete":
		// Resolve identity for the verified pubkey.
		identity, err := h.identityService.ResolveOrCreate(r.Context(), sess.ResultPubkey, h.relayURLs)
		if err != nil {
			h.logger.Error("identity resolution failed for NIP-46 session", "pubkey", sess.ResultPubkey, "error", err)
			resp.Status = "error"
			resp.Error = "identity resolution failed"
		} else {
			resp.Identity = &identity
			resp.RedirectURI = sess.RedirectURI
		}
	case "error":
		resp.Error = sess.Error
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// runBunkerFlow runs the NIP-46 bunker connection in a goroutine.
func (h *NIP46Handler) runBunkerFlow(sessionToken string, bunkerURI string) {
	ctx, cancel := context.WithTimeout(context.Background(), NIP46SessionTTL)
	defer cancel()

	if h.GrantCreator == nil {
		h.logger.Error("no signer grant creator configured")
		h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", "signer grant creator not configured")
		metrics.IncNIP46SessionsFailed()
		return
	}

	grant, err := h.GrantCreator.CreateGrant(ctx, bunkerURI)
	if err != nil {
		h.logger.Warn("signer grant creation failed", "session", sessionToken, "error", err)
		h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", err.Error())
		metrics.IncNIP46SessionsFailed()
		return
	}

	if h.identityService != nil {
		identity, err := h.identityService.ResolveOrCreate(ctx, grant.Pubkey, h.relayURLs)
		if err != nil {
			h.logger.Error("identity resolution failed after signer grant creation", "session", sessionToken, "pubkey", grant.Pubkey, "error", err)
			h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", "identity resolution failed")
			metrics.IncNIP46SessionsFailed()
			return
		}
		if h.Backfiller != nil {
			count, err := h.Backfiller.EnqueuePending(ctx, identity.GiteaUserID, grant.Pubkey)
			if err != nil {
				h.logger.Error("pending actor event backfill failed after signer grant creation", "session", sessionToken, "pubkey", grant.Pubkey, "gitea_user_id", identity.GiteaUserID, "error", err)
				h.store.UpdateNIP46SessionState(ctx, sessionToken, "error", "", "pending actor event backfill failed")
				metrics.IncNIP46SessionsFailed()
				return
			}
			if count > 0 {
				h.logger.Info("pending actor events queued after NIP-46 link", "session", sessionToken, "pubkey", grant.Pubkey, "gitea_user_id", identity.GiteaUserID, "count", count)
			}
		}
	}

	if err := h.store.UpdateNIP46SessionState(ctx, sessionToken, "complete", grant.Pubkey, ""); err != nil {
		h.logger.Error("update session state failed", "session", sessionToken, "error", err)
		metrics.IncNIP46SessionsFailed()
		return
	}

	metrics.IncNIP46SessionsCompleted()
	h.logger.Info("NIP-46 bunker login completed", "session", sessionToken, "signer_pubkey", grant.Pubkey, "client_pubkey", grant.ClientPubkey)
}

// parseBunkerURI extracts the bunker pubkey from a bunker:// URI.
// Format: bunker://<hex-pubkey>?relay=wss://...
func parseBunkerURI(uri string) (string, error) {
	if !strings.HasPrefix(uri, "bunker://") {
		return "", fmt.Errorf("must start with bunker://")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid URI: %w", err)
	}

	pubkey := u.Host
	if pubkey == "" {
		// Some bunker URIs put the pubkey in the path.
		pubkey = strings.TrimPrefix(u.Path, "/")
	}

	if len(pubkey) != 64 {
		return "", fmt.Errorf("pubkey must be 64 hex characters, got %d", len(pubkey))
	}
	decoded, err := hex.DecodeString(pubkey)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("pubkey must be valid 32-byte hex")
	}

	return pubkey, nil
}

// generateSessionToken returns a cryptographically random hex string for session IDs.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (h *NIP46Handler) methodGuard(expected string, next http.HandlerFunc) http.HandlerFunc {
	return corsMethodGuard(expected, h.writeJSON, next)
}

func (h *NIP46Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

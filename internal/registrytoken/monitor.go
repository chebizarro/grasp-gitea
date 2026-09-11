// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package registrytoken monitors the lifetime of container-registry JWTs
// issued by Gitea. Their lifetime is the effective revocation bound after a
// bridge token has been revoked.
package registrytoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sharegap/grasp-gitea/internal/metrics"
)

const maxResponseBytes = 1 << 20

// Monitor periodically measures exp-iat on JWTs issued by Gitea's /v2/token
// endpoint and exposes the last result as a readiness probe.
type Monitor struct {
	endpoint    string
	username    string
	token       string
	maxLifetime time.Duration
	interval    time.Duration
	client      *http.Client
	logger      *slog.Logger

	mu      sync.RWMutex
	lastErr error
}

// New constructs a registry-token lifetime monitor.
func New(baseURL, username, token string, maxLifetime, interval time.Duration, client *http.Client, logger *slog.Logger) (*Monitor, error) {
	base, err := url.Parse(baseURL)
	if err != nil || !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("invalid Gitea URL %q", baseURL)
	}
	if username == "" || token == "" {
		return nil, errors.New("Gitea admin Basic credentials are required")
	}
	if maxLifetime <= 0 {
		return nil, errors.New("registry token maximum lifetime must be positive")
	}
	if interval <= 0 {
		return nil, errors.New("registry token probe interval must be positive")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}

	endpoint := base.JoinPath("/v2/token")
	query := endpoint.Query()
	query.Set("service", "container_registry")
	endpoint.RawQuery = query.Encode()
	return &Monitor{
		endpoint: endpoint.String(), username: username, token: token,
		maxLifetime: maxLifetime, interval: interval, client: client, logger: logger,
		lastErr: errors.New("registry token lifetime has not been measured"),
	}, nil
}

// Name identifies this monitor in the readiness response.
func (m *Monitor) Name() string { return "registry_token_lifetime" }

// Check returns the result of the most recent periodic probe.
func (m *Monitor) Check(context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

// SetToken atomically replaces the credential used by subsequent probes.
func (m *Monitor) SetToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, "\x00\r\n") {
		return errors.New("Gitea admin token is invalid")
	}
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()
	return nil
}

// Run probes immediately, then repeats until ctx is canceled.
func (m *Monitor) Run(ctx context.Context) {
	m.probeAndRecord(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeAndRecord(ctx)
		}
	}
}

func (m *Monitor) probeAndRecord(ctx context.Context) {
	lifetime, err := m.probe(ctx)
	if err == nil && lifetime > m.maxLifetime {
		err = fmt.Errorf("registry token lifetime %s exceeds accepted bound %s", lifetime, m.maxLifetime)
	}
	if lifetime > 0 {
		metrics.SetRegistryTokenLifetimeSeconds(int64(lifetime / time.Second))
		metrics.SetRegistryTokenRevocationBoundExceeded(lifetime > m.maxLifetime)
	}

	m.mu.Lock()
	m.lastErr = err
	m.mu.Unlock()

	if err != nil {
		m.logger.Warn("registry token revocation-bound probe failed", "error", err)
		return
	}
	m.logger.Info("registry token revocation bound measured", "lifetime", lifetime.String(), "accepted_bound", m.maxLifetime.String())
}

func (m *Monitor) probe(ctx context.Context) (time.Duration, error) {
	m.mu.RLock()
	token := m.token
	m.mu.RUnlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(m.username, token)
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request registry token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return 0, fmt.Errorf("registry token endpoint returned %s", resp.Status)
	}

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := decoder.Decode(&payload); err != nil {
		return 0, fmt.Errorf("decode registry token response: %w", err)
	}
	jwt := payload.Token
	if jwt == "" {
		jwt = payload.AccessToken
	}
	return jwtLifetime(jwt)
}

func jwtLifetime(token string) (time.Duration, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, errors.New("registry token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("decode registry JWT payload: %w", err)
	}
	var claims struct {
		IssuedAt  int64 `json:"iat"`
		NotBefore int64 `json:"nbf"`
		Expires   int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, fmt.Errorf("decode registry JWT claims: %w", err)
	}
	startsAt := claims.IssuedAt
	if startsAt == 0 {
		// Gitea 1.26 registry JWTs use nbf as the issuance boundary and do
		// not include iat. Prefer iat when present for compatibility with
		// older releases, and otherwise measure the bound from nbf.
		startsAt = claims.NotBefore
	}
	if startsAt <= 0 || claims.Expires <= startsAt {
		return 0, errors.New("registry JWT has invalid exp/iat/nbf claims")
	}
	seconds := claims.Expires - startsAt
	if seconds > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("registry JWT lifetime %d seconds overflows a duration", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

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

const (
	maxResponseBytes     = 1 << 20
	maxErrorResponseBody = 512
)

// Mode controls whether probe failures gate readiness.
type Mode string

const (
	ModeRequire  Mode = "require"
	ModeWarn     Mode = "warn"
	ModeDisabled Mode = "disabled"
)

// Monitor periodically measures exp-iat on JWTs issued by Gitea's /v2/token
// endpoint and exposes the last result as a readiness probe.
type Monitor struct {
	endpoint    string
	mode        Mode
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
func New(endpointURL, username, token string, mode Mode, maxLifetime, interval time.Duration, client *http.Client, logger *slog.Logger) (*Monitor, error) {
	endpoint, err := url.Parse(endpointURL)
	if err != nil || !endpoint.IsAbs() || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid registry token probe URL %q", endpointURL)
	}
	if mode != ModeRequire && mode != ModeWarn && mode != ModeDisabled {
		return nil, fmt.Errorf("invalid registry token monitor mode %q", mode)
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

	return &Monitor{
		endpoint: endpoint.String(), mode: mode, username: username, token: token,
		maxLifetime: maxLifetime, interval: interval, client: client, logger: logger,
		lastErr: errors.New("registry token lifetime has not been measured"),
	}, nil
}

// Name identifies this monitor in the readiness response.
func (m *Monitor) Name() string { return "registry_token_lifetime" }

// Check returns the result of the most recent periodic probe.
func (m *Monitor) Check(context.Context) error {
	if m.mode != ModeRequire {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

// RedactedURL returns a probe URL safe for logs and readiness errors.
func RedactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	return u.String()
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
	}
	metrics.SetRegistryTokenRevocationBoundExceeded(err != nil)

	m.mu.Lock()
	m.lastErr = err
	m.mu.Unlock()

	if err != nil {
		fields := []any{"error", err}
		var responseErr *endpointResponseError
		if errors.As(err, &responseErr) {
			fields = append(fields,
				"request_url", responseErr.requestURL,
				"http_status", responseErr.status,
				"www_authenticate", responseErr.wwwAuthenticate,
			)
			if responseErr.dockerDistributionAPIVersion != "" {
				fields = append(fields, "docker_distribution_api_version", responseErr.dockerDistributionAPIVersion)
			}
			fields = append(fields, "response_body", responseErr.body)
		}
		m.logger.Warn("registry token revocation-bound probe failed", fields...)
		return
	}
	m.logger.Info("registry token revocation bound measured", "lifetime", lifetime.String(), "accepted_bound", m.maxLifetime.String())
}

func (m *Monitor) probe(ctx context.Context) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(m.username, m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request registry token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBody))
		if readErr != nil {
			return 0, fmt.Errorf("read registry token error response from %s: %w", RedactedURL(m.endpoint), readErr)
		}
		return 0, &endpointResponseError{
			requestURL:                   RedactedURL(m.endpoint),
			status:                       resp.Status,
			wwwAuthenticate:              resp.Header.Get("WWW-Authenticate"),
			dockerDistributionAPIVersion: resp.Header.Get("Docker-Distribution-Api-Version"),
			body:                         string(body),
		}
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

type endpointResponseError struct {
	requestURL                   string
	status                       string
	wwwAuthenticate              string
	dockerDistributionAPIVersion string
	body                         string
}

func (e *endpointResponseError) Error() string {
	return fmt.Sprintf("registry token endpoint %s returned %s (WWW-Authenticate: %s)", e.requestURL, e.status, e.wwwAuthenticate)
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
		IssuedAt int64 `json:"iat"`
		Expires  int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, fmt.Errorf("decode registry JWT claims: %w", err)
	}
	if claims.IssuedAt <= 0 || claims.Expires <= claims.IssuedAt {
		return 0, errors.New("registry JWT has invalid exp/iat claims")
	}
	seconds := claims.Expires - claims.IssuedAt
	if seconds > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("registry JWT lifetime %d seconds overflows a duration", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

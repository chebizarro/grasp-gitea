// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// upstreamProbeTimeout bounds the readiness request to Gitea.
const upstreamProbeTimeout = 3 * time.Second

// UpstreamProbe reports whether Gitea is reachable through the proxy's own
// transport. In full-proxy mode the bridge is the only path to Gitea, so an
// unreachable upstream must make the bridge unready rather than serving
// errors to every caller.
type UpstreamProbe struct {
	proxy  *Proxy
	client *http.Client
}

// UpstreamProbe returns a readiness probe for the configured upstream.
func (p *Proxy) UpstreamProbe() *UpstreamProbe {
	return &UpstreamProbe{
		proxy:  p,
		client: &http.Client{Transport: p.proxy.Transport, Timeout: upstreamProbeTimeout},
	}
}

// Name identifies this probe in the readiness response.
func (u *UpstreamProbe) Name() string { return "gitea" }

// Check performs a bounded request against the configured Gitea health
// endpoint and requires a 2xx. Accepting 3xx/4xx would report "ready" for a
// misconfigured base path that answers 404 for every real request.
func (u *UpstreamProbe) Check(ctx context.Context) error {
	target := u.proxy.target.JoinPath("/api/healthz").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("gitea unreachable: %w", err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gitea health endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

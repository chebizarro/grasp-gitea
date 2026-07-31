// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package api

import (
	"context"
	"net/http"
	"time"
)

// readyCheckTimeout bounds the dependency probes so /ready cannot hang a
// load balancer's health poll.
const readyCheckTimeout = 5 * time.Second

// ReadinessProbe reports whether a dependency is usable.
type ReadinessProbe interface {
	// Name identifies the dependency in the response.
	Name() string
	// Check returns nil when the dependency is usable.
	Check(ctx context.Context) error
}

// AddReadinessProbe registers a dependency probe for /ready.
func (s *Server) AddReadinessProbe(p ReadinessProbe) {
	if p != nil {
		s.readinessProbes = append(s.readinessProbes, p)
	}
}

// ready reports whether the bridge can serve traffic. Unlike /health, which
// only says the process is alive, /ready verifies the store and — once the
// bridge fronts Gitea — that the upstream is reachable. In full-proxy mode an
// unready bridge means all of Gitea is unreachable, so this must be wired to
// the container healthcheck and load balancer.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
	defer cancel()

	// This endpoint is unauthenticated so load balancers can poll it, so the
	// response says only ok/error per dependency. Dial addresses and database
	// errors go to the log, not to anonymous callers.
	checks := make(map[string]string, len(s.readinessProbes)+1)
	status := http.StatusOK
	var failures []any

	if s.store != nil {
		if err := s.store.Ping(ctx); err != nil {
			checks["store"] = "error"
			failures = append(failures, "store", err)
			status = http.StatusServiceUnavailable
		} else {
			checks["store"] = "ok"
		}
	}

	for _, probe := range s.readinessProbes {
		if err := probe.Check(ctx); err != nil {
			checks[probe.Name()] = "error"
			failures = append(failures, probe.Name(), err)
			status = http.StatusServiceUnavailable
			continue
		}
		checks[probe.Name()] = "ok"
	}

	state := "ready"
	if status != http.StatusOK {
		state = "not ready"
		s.logger.Warn("readiness check failed", failures...)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{"status": state, "checks": checks})
}

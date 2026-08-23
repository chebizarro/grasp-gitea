//go:build !full

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/policy"
)

func startEmbeddedRelay(_ context.Context, cfg config.Config, _ *policy.Store, _ *slog.Logger) (string, http.Handler, func(context.Context) error, error) {
	if cfg.EmbeddedRelay {
		return "", nil, nil, fmt.Errorf("EMBEDDED_RELAY=true requires build tag 'full'")
	}
	return "", nil, func(context.Context) error { return nil }, nil
}

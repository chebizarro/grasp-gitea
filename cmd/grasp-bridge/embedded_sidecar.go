//go:build !full

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func startEmbeddedRelay(_ context.Context, cfg config.Config, _ *slog.Logger) (string, func(context.Context) error, error) {
	if cfg.EmbeddedRelay {
		return "", nil, fmt.Errorf("EMBEDDED_RELAY=true requires build tag 'full'")
	}
	return "", func(context.Context) error { return nil }, nil
}

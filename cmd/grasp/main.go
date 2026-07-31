// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Command grasp is the client CLI for a GRASP Gitea bridge: it mints and
// manages bridge tokens with a nostr identity (NIP-98 proofs signed by an
// nsec or NIP-46 bunker), serves them to git via the credential-helper
// protocol, and emits package-manager configuration.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sharegap/grasp-gitea/internal/graspcli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(graspcli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package refsnostr

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
)

type RelayChecker struct {
	RelayURLs []string
	Logger    *slog.Logger
	Timeout   time.Duration
}

func NewRelayChecker(relayURLs []string, logger *slog.Logger) *RelayChecker {
	return &RelayChecker{RelayURLs: relayURLs, Logger: logger, Timeout: 5 * time.Second}
}

func (c *RelayChecker) HasAcceptedPRWithTip(ctx context.Context, eventID, tipSHA string) (bool, error) {
	if c == nil || len(c.RelayURLs) == 0 {
		return false, fmt.Errorf("no relay URLs configured")
	}

	eid, err := nostr.IDFromHex(eventID)
	if err != nil {
		return false, fmt.Errorf("invalid event id %q: %w", eventID, err)
	}

	var queried int
	for _, relayURL := range c.RelayURLs {
		qCtx, cancel := context.WithTimeout(ctx, c.timeout())
		r, err := nostr.RelayConnect(qCtx, relayURL, nostr.RelayOptions{})
		if err != nil {
			cancel()
			c.warn("relay connect failed for refs/nostr check", "relay", relayURL, "event_id", eventID, "error", err)
			continue
		}
		queried++
		found := false
		for ev := range r.QueryEvents(nostr.Filter{
			IDs:   []nostr.ID{eid},
			Kinds: []nostr.Kind{relay.KindPROpen, relay.KindPRUpdate},
			Tags: nostr.TagMap{
				"c": []string{tipSHA},
			},
			Limit: 1,
		}) {
			e := ev
			if EventIsAcceptedPRWithTip(&e, eventID, tipSHA) {
				found = true
				break
			}
		}
		r.Close()
		cancel()
		if found {
			return true, nil
		}
	}

	if queried == 0 {
		return false, fmt.Errorf("refs/nostr event %s: all %d relays unreachable", eventID, len(c.RelayURLs))
	}
	return false, nil
}

func (c *RelayChecker) timeout() time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *RelayChecker) warn(msg string, args ...any) {
	if c != nil && c.Logger != nil {
		c.Logger.Warn(msg, args...)
	}
}

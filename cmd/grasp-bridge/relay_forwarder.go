package main

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

func forwardEventToRelay(ctx context.Context, relayURL string, ev *nostr.Event) error {
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return err
	}
	return relay.Publish(ctx, *ev)
}

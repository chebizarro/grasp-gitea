package main

import (
	"context"

	"fiatjaf.com/nostr"
)

func forwardEventToRelay(ctx context.Context, relayURL string, ev *nostr.Event) error {
	relay, err := nostr.RelayConnect(ctx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return err
	}
	return relay.Publish(ctx, *ev)
}

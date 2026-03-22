// Package nip46 provides a NIP-46 (Nostr Connect) client for the grasp-bridge
// OAuth2 login flow. It connects to a remote bunker, requests signing of a
// NIP-98 challenge event, and delivers the signed event back to the caller.
package nip46

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip46"
)

const SessionTimeout = 3 * time.Minute

// SignResult is the outcome of a bunker sign operation.
type SignResult struct {
	SignedEvent nostr.Event
	Err        error
}

// RunSession connects to the bunker described by bunkerURI, builds an unsigned
// NIP-98 challenge event (kind 27235) for the given URL and method, asks the
// bunker to sign it, and sends the result on the returned channel.
//
// The caller should use a context with a deadline matching sessionTimeout.
// The channel receives exactly one value and is then closed.
func RunSession(ctx context.Context, logger *slog.Logger, bunkerURI, challengeURL, method string) <-chan SignResult {
	ch := make(chan SignResult, 1)

	go func() {
		defer close(ch)

		clientSK := nostr.Generate()

		logger.Info("nip46: connecting to bunker", "uri_prefix", bunkerURI[:min(len(bunkerURI), 20)])

		client, err := nip46.ConnectBunker(ctx, clientSK, bunkerURI, nil, func(authURL string) {
			logger.Info("nip46: bunker requests auth URL", "url", authURL)
		})
		if err != nil {
			ch <- SignResult{Err: fmt.Errorf("nip46 connect: %w", err)}
			return
		}

		remotePubkey, err := client.GetPublicKey(ctx)
		if err != nil {
			ch <- SignResult{Err: fmt.Errorf("nip46 get_public_key: %w", err)}
			return
		}

		logger.Info("nip46: connected", "remote_pubkey", remotePubkey.Hex())

		// Build the NIP-98 challenge event (unsigned).
		evt := &nostr.Event{
			Kind:      27235,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags: nostr.Tags{
				{"u", challengeURL},
				{"method", method},
			},
			PubKey: remotePubkey,
		}

		// Ask the bunker to sign it.
		if err := client.SignEvent(ctx, evt); err != nil {
			ch <- SignResult{Err: fmt.Errorf("nip46 sign_event: %w", err)}
			return
		}

		logger.Info("nip46: event signed", "event_id", evt.ID.Hex())
		ch <- SignResult{SignedEvent: *evt}
	}()

	return ch
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

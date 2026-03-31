// Package publisher handles outbound Nostr event signing and relay publishing
// for grasp-bridge. It is activated only when GRASP_SERVER_NSEC is set.
package publisher

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
)

// Publisher signs and publishes Nostr events to one or more relay URLs.
type Publisher struct {
	sk        nostr.SecretKey
	pubKey    nostr.PubKey
	relayURLs []string
	logger    *slog.Logger
}

// New creates a Publisher from a raw nsec or hex secret key string.
// Returns nil, nil if nsec is empty (disabled).
func New(nsec string, relayURLs []string, logger *slog.Logger) (*Publisher, error) {
	if nsec == "" {
		return nil, nil
	}

	var sk nostr.SecretKey
	var err error

	// Try bech32 nsec first, then raw hex.
	prefix, val, decErr := nip19.Decode(nsec)
	if decErr == nil && prefix == "nsec" {
		switch v := val.(type) {
		case nostr.SecretKey:
			sk = v
		case []byte:
			if len(v) != 32 {
				return nil, fmt.Errorf("invalid nsec length: %d", len(v))
			}
			copy(sk[:], v)
		default:
			return nil, fmt.Errorf("unexpected nsec type %T", val)
		}
	} else {
		sk, err = nostr.SecretKeyFromHex(nsec)
		if err != nil {
			return nil, fmt.Errorf("parse GRASP_SERVER_NSEC: %w", err)
		}
	}

	pub := sk.Public()
	logger.Info("publisher: server signing key loaded", "pubkey", pub.Hex())

	return &Publisher{
		sk:        sk,
		pubKey:    pub,
		relayURLs: relayURLs,
		logger:    logger,
	}, nil
}

// PubKey returns the server's public key hex.
func (p *Publisher) PubKey() string {
	return p.pubKey.Hex()
}

// Publish signs the event with the server key and sends it to all configured relays.
// The event's PubKey, CreatedAt, and ID are set automatically.
func (p *Publisher) Publish(ctx context.Context, ev *nostr.Event) error {
	ev.PubKey = p.pubKey
	if ev.CreatedAt == 0 {
		ev.CreatedAt = nostr.Timestamp(time.Now().Unix())
	}
	if err := ev.Sign(p.sk); err != nil {
		return fmt.Errorf("sign event kind %d: %w", ev.Kind, err)
	}

	var lastErr error
	published := 0
	for _, url := range p.relayURLs {
		if err := p.publishToRelay(ctx, url, ev); err != nil {
			p.logger.Warn("publisher: relay publish failed", "relay", url, "kind", ev.Kind, "error", err)
			lastErr = err
		} else {
			published++
		}
	}

	if published == 0 && lastErr != nil {
		return fmt.Errorf("publish to all relays failed: %w", lastErr)
	}
	p.logger.Info("publisher: event published", "kind", ev.Kind, "id", ev.ID.Hex(), "relays", published)
	return nil
}

func (p *Publisher) publishToRelay(ctx context.Context, relayURL string, ev *nostr.Event) error {
	pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	relay, err := nostr.RelayConnect(pubCtx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return fmt.Errorf("connect %s: %w", relayURL, err)
	}
	defer relay.Close()

	return relay.Publish(pubCtx, *ev)
}

package auth

import (
	"context"
	"fmt"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

// LiveBunkerConnector performs a NIP-46 connect RPC with an ephemeral client key.
type LiveBunkerConnector struct{}

func (LiveBunkerConnector) Connect(ctx context.Context, uri string) (string, error) {
	client, err := nip46.ConnectBunker(ctx, nostr.GeneratePrivateKey(), uri, nil, nil)
	if err != nil {
		return "", fmt.Errorf("connect bunker: %w", err)
	}
	pubkey, err := client.GetPublicKey(ctx)
	if err != nil {
		return "", fmt.Errorf("get bunker public key: %w", err)
	}
	return pubkey, nil
}

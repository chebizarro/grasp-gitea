package publisher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

// EventSigner signs events without exposing the identity private key to the
// publisher. Implementations must set the event pubkey and signature.
type EventSigner interface {
	PublicKey() string
	SignEvent(context.Context, *nostr.Event) error
}

// NIP46Signer delegates signing to a NIP-46 bunker such as Signet. The local
// client key is ephemeral and identifies only this RPC session; it is not the
// bridge identity key and is never exported or persisted.
type NIP46Signer struct {
	mu     sync.Mutex
	client *nip46.BunkerClient
	pubkey string
}

func NewNIP46Signer(ctx context.Context, bunkerURI string) (*NIP46Signer, error) {
	if bunkerURI == "" {
		return nil, fmt.Errorf("bunker URI is required")
	}
	// Keep the relay pool on the application context while bounding only the
	// startup handshake. Cancelling the handshake context must not tear down the
	// long-lived NIP-46 subscription used for later signing calls.
	pool := nostr.NewSimplePool(ctx)
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client, err := nip46.ConnectBunker(connectCtx, nostr.GeneratePrivateKey(), bunkerURI, pool, nil)
	if err != nil {
		return nil, fmt.Errorf("connect signer bunker: %w", err)
	}
	pubkey, err := client.GetPublicKey(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("get signer public key: %w", err)
	}
	return &NIP46Signer{client: client, pubkey: pubkey}, nil
}

func (s *NIP46Signer) PublicKey() string { return s.pubkey }

func (s *NIP46Signer) SignEvent(ctx context.Context, ev *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev.PubKey = s.pubkey
	if err := s.client.SignEvent(ctx, ev); err != nil {
		return fmt.Errorf("remote sign event: %w", err)
	}
	if !ev.CheckID() {
		return fmt.Errorf("remote signer returned an invalid event id")
	}
	ok, err := ev.CheckSignature()
	if err != nil {
		return fmt.Errorf("verify remote signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("remote signer returned an invalid signature")
	}
	return nil
}

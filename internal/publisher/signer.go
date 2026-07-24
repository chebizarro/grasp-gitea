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
	// ConnectBunker retains the context passed to it for the long-lived response
	// subscription. Passing a short-lived handshake context would make startup
	// succeed and then silently cancel every later signing response. Keep the
	// application context in ConnectBunker and bound startup externally.
	pool := nostr.NewSimplePool(ctx)
	type connectResult struct {
		client *nip46.BunkerClient
		err    error
	}
	resultCh := make(chan connectResult, 1)
	go func() {
		client, err := nip46.ConnectBunker(ctx, nostr.GeneratePrivateKey(), bunkerURI, pool, nil)
		resultCh <- connectResult{client: client, err: err}
	}()

	var client *nip46.BunkerClient
	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, fmt.Errorf("connect signer bunker: %w", result.err)
		}
		client = result.client
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("connect signer bunker: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		return nil, fmt.Errorf("connect signer bunker: %w", ctx.Err())
	}
	publicKeyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pubkey, err := client.GetPublicKey(publicKeyCtx)
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

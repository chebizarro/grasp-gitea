package publisher

import (
	"context"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip46"
)

type localServerSigner struct {
	privKey string
	pubKey  string
}

func NewLocalServerSigner(nsec string) (ServerSigner, error) {
	typ, v, err := nip19.Decode(strings.TrimSpace(nsec))
	if err != nil {
		return nil, fmt.Errorf("decode BRIDGE_NSEC: %w", err)
	}
	if typ != "nsec" {
		return nil, fmt.Errorf("BRIDGE_NSEC must be an nsec, got %s", typ)
	}
	privKey, ok := v.(string)
	if !ok || privKey == "" {
		return nil, fmt.Errorf("invalid decoded nsec value")
	}
	pubKey, err := nostr.GetPublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key from BRIDGE_NSEC: %w", err)
	}
	return &localServerSigner{privKey: privKey, pubKey: pubKey}, nil
}

func (s *localServerSigner) PublicKey() string { return s.pubKey }

func (s *localServerSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	return ev.Sign(s.privKey)
}

type signetBunkerServerSigner struct {
	bunker *nip46.BunkerClient
	pubKey string
}

func NewSignetBunkerServerSigner(ctx context.Context, bunkerURL string) (ServerSigner, error) {
	bunkerURL = strings.TrimSpace(bunkerURL)
	if bunkerURL == "" {
		return nil, fmt.Errorf("SIGNET_BUNKER_URL is required")
	}
	clientSecretKey := nostr.GeneratePrivateKey()
	bunker, err := nip46.ConnectBunker(ctx, clientSecretKey, bunkerURL, nil, func(string) {})
	if err != nil {
		return nil, fmt.Errorf("connect Signet bunker: %w", err)
	}
	pubKey, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("get Signet bunker pubkey: %w", err)
	}
	if !nostr.IsValidPublicKey(pubKey) {
		return nil, fmt.Errorf("Signet bunker returned invalid pubkey %q", pubKey)
	}
	if err := bunker.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping Signet bunker: %w", err)
	}
	return &signetBunkerServerSigner{bunker: bunker, pubKey: pubKey}, nil
}

func (s *signetBunkerServerSigner) PublicKey() string { return s.pubKey }

func (s *signetBunkerServerSigner) SignEvent(ctx context.Context, ev *nostr.Event) error {
	return s.bunker.SignEvent(ctx, ev)
}

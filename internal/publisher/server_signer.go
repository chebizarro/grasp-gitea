package publisher

import (
	"context"
	"fmt"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip44"

	"git.sharegap.net/cascadia/cascadia-go/signet"
)

type localServerSigner struct {
	privKey nostr.SecretKey
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
	privKey, ok := v.(nostr.SecretKey)
	if !ok {
		return nil, fmt.Errorf("invalid decoded nsec value")
	}
	return &localServerSigner{privKey: privKey, pubKey: privKey.Public().Hex()}, nil
}

func (s *localServerSigner) PublicKey() string { return s.pubKey }

func (s *localServerSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	return ev.Sign(s.privKey)
}

func (s *localServerSigner) NIP44Encrypt(_ context.Context, target nostr.PubKey, plaintext string) (string, error) {
	key, err := nip44.GenerateConversationKey(target, s.privKey)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, key)
}

type signetBunkerServerSigner struct {
	signer signetSigner
	pubKey string
}

type signetSigner interface {
	GetPublicKey(ctx context.Context) (nostr.PubKey, error)
	SignEvent(ctx context.Context, event *nostr.Event) error
}

func NewSignetBunkerServerSigner(ctx context.Context, bunkerURL string, relays ...string) (ServerSigner, error) {
	bunkerURL = strings.TrimSpace(bunkerURL)
	if bunkerURL == "" {
		return nil, fmt.Errorf("SIGNET_BUNKER_URL is required")
	}
	bunker, err := signet.NewBunkerSigner(ctx, bunkerURL, relays...)
	if err != nil {
		return nil, fmt.Errorf("connect Signet bunker: %w", err)
	}
	pubKey, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("get Signet bunker pubkey: %w", err)
	}
	return &signetBunkerServerSigner{signer: bunker, pubKey: pubKey.Hex()}, nil
}

func (s *signetBunkerServerSigner) PublicKey() string { return s.pubKey }

func (s *signetBunkerServerSigner) SignEvent(ctx context.Context, ev *nostr.Event) error {
	if ev == nil {
		return fmt.Errorf("event is required")
	}
	return s.signer.SignEvent(ctx, ev)
}

func (s *signetBunkerServerSigner) NIP44Encrypt(ctx context.Context, target nostr.PubKey, plaintext string) (string, error) {
	encryptor, ok := s.signer.(interface {
		NIP44Encrypt(context.Context, nostr.PubKey, string) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("Signet signer does not support NIP-44 encryption")
	}
	return encryptor.NIP44Encrypt(ctx, target, plaintext)
}

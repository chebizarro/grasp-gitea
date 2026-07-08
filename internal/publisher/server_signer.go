package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	fiatjafnostr "fiatjaf.com/nostr"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"git.sharegap.net/cascadia/cascadia-go/signet"
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
	pubKey, err := gonostr.GetPublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key from BRIDGE_NSEC: %w", err)
	}
	return &localServerSigner{privKey: privKey, pubKey: pubKey}, nil
}

func (s *localServerSigner) PublicKey() string { return s.pubKey }

func (s *localServerSigner) SignEvent(_ context.Context, ev *gonostr.Event) error {
	return ev.Sign(s.privKey)
}

type signetBunkerServerSigner struct {
	signer signetSigner
	pubKey string
}

type signetSigner interface {
	GetPublicKey(ctx context.Context) (fiatjafnostr.PubKey, error)
	SignEvent(ctx context.Context, event *fiatjafnostr.Event) error
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
	pubKeyHex := pubKey.String()
	if !gonostr.IsValidPublicKey(pubKeyHex) {
		return nil, fmt.Errorf("Signet bunker returned invalid pubkey %q", pubKeyHex)
	}
	return &signetBunkerServerSigner{signer: bunker, pubKey: pubKeyHex}, nil
}

func (s *signetBunkerServerSigner) PublicKey() string { return s.pubKey }

func (s *signetBunkerServerSigner) SignEvent(ctx context.Context, ev *gonostr.Event) error {
	if ev == nil {
		return fmt.Errorf("event is required")
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event for Signet signer: %w", err)
	}
	var signetEvent fiatjafnostr.Event
	if err := json.Unmarshal(payload, &signetEvent); err != nil {
		return fmt.Errorf("convert event for Signet signer: %w", err)
	}
	if err := s.signer.SignEvent(ctx, &signetEvent); err != nil {
		return err
	}
	payload, err = json.Marshal(&signetEvent)
	if err != nil {
		return fmt.Errorf("marshal signed Signet event: %w", err)
	}
	if err := json.Unmarshal(payload, ev); err != nil {
		return fmt.Errorf("copy signed Signet event: %w", err)
	}
	return nil
}

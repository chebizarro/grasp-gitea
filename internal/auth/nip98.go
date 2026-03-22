package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
)

const (
	nip98Kind      = 27235
	nip98WindowSec = 60
)

// VerifyRequest holds the inputs for NIP-98 verification.
type VerifyRequest struct {
	SignedEventJSON string // JSON-encoded NIP-98 kind:27235 event from the browser
	ExpectedURL     string // Full URL of the endpoint being authorized
	ExpectedMethod  string // HTTP method (e.g. "POST")
}

// VerifyResult holds the verified identity.
type VerifyResult struct {
	Pubkey string // hex-encoded public key
	Npub   string // bech32 npub
}

// VerifyNIP98 validates a NIP-98 signed event and returns the verified identity.
func VerifyNIP98(req VerifyRequest) (VerifyResult, error) {
	var event nostr.Event
	if err := json.Unmarshal([]byte(req.SignedEventJSON), &event); err != nil {
		return VerifyResult{}, fmt.Errorf("parse event: %w", err)
	}

	if event.Kind != nip98Kind {
		return VerifyResult{}, fmt.Errorf("expected kind %d, got %d", nip98Kind, event.Kind)
	}

	if !event.CheckID() {
		return VerifyResult{}, fmt.Errorf("invalid event ID")
	}

	if !event.VerifySignature() {
		return VerifyResult{}, fmt.Errorf("invalid signature")
	}

	eventTime := time.Unix(int64(event.CreatedAt), 0)
	delta := time.Since(eventTime)
	if delta > nip98WindowSec*time.Second || delta < -nip98WindowSec*time.Second {
		return VerifyResult{}, fmt.Errorf("event timestamp out of window (delta=%v)", delta)
	}

	urlTag := event.Tags.Find("u")
	if len(urlTag) < 2 {
		return VerifyResult{}, fmt.Errorf("missing 'u' tag")
	}
	if !strings.EqualFold(urlTag[1], req.ExpectedURL) {
		return VerifyResult{}, fmt.Errorf("URL mismatch: got %q, expected %q", urlTag[1], req.ExpectedURL)
	}

	methodTag := event.Tags.Find("method")
	if len(methodTag) < 2 {
		return VerifyResult{}, fmt.Errorf("missing 'method' tag")
	}
	if !strings.EqualFold(methodTag[1], req.ExpectedMethod) {
		return VerifyResult{}, fmt.Errorf("method mismatch: got %q, expected %q", methodTag[1], req.ExpectedMethod)
	}

	return VerifyResult{
		Pubkey: event.PubKey.Hex(),
		Npub:   nip19.EncodeNpub(event.PubKey),
	}, nil
}

package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
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
	Pubkey string
	Npub   string
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

	// Validate event ID
	if !event.CheckID() {
		return VerifyResult{}, fmt.Errorf("invalid event ID")
	}

	// Validate signature
	ok, err := event.CheckSignature()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("signature check: %w", err)
	}
	if !ok {
		return VerifyResult{}, fmt.Errorf("invalid signature")
	}

	// Validate time window
	eventTime := time.Unix(int64(event.CreatedAt), 0)
	delta := time.Since(eventTime)
	if delta > nip98WindowSec*time.Second || delta < -nip98WindowSec*time.Second {
		return VerifyResult{}, fmt.Errorf("event timestamp out of window (delta=%v)", delta)
	}

	// Validate URL tag
	urlTag := event.Tags.GetFirst([]string{"u"})
	if urlTag == nil || len(*urlTag) < 2 {
		return VerifyResult{}, fmt.Errorf("missing 'u' tag")
	}
	if !strings.EqualFold((*urlTag)[1], req.ExpectedURL) {
		return VerifyResult{}, fmt.Errorf("URL mismatch: got %q, expected %q", (*urlTag)[1], req.ExpectedURL)
	}

	// Validate method tag
	methodTag := event.Tags.GetFirst([]string{"method"})
	if methodTag == nil || len(*methodTag) < 2 {
		return VerifyResult{}, fmt.Errorf("missing 'method' tag")
	}
	if !strings.EqualFold((*methodTag)[1], req.ExpectedMethod) {
		return VerifyResult{}, fmt.Errorf("method mismatch: got %q, expected %q", (*methodTag)[1], req.ExpectedMethod)
	}

	npub, err := nip19.EncodePublicKey(event.PubKey)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("encode npub: %w", err)
	}

	return VerifyResult{
		Pubkey: event.PubKey,
		Npub:   npub,
	}, nil
}

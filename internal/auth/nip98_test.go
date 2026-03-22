package auth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestVerifyNIP98_ValidEvent(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	event := nostr.Event{
		Kind:      nip98Kind,
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			{"u", "https://example.com/auth/nip07/verify"},
			{"method", "POST"},
		},
		Content: "",
	}
	_ = event.Sign(sk)

	eventJSON, _ := json.Marshal(event)

	result, err := VerifyNIP98(VerifyRequest{
		SignedEventJSON: string(eventJSON),
		ExpectedURL:     "https://example.com/auth/nip07/verify",
		ExpectedMethod:  "POST",
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Pubkey != pk {
		t.Errorf("pubkey mismatch: got %s, want %s", result.Pubkey, pk)
	}
	if result.Npub == "" {
		t.Error("npub should not be empty")
	}
}

func TestVerifyNIP98_WrongKind(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	event := nostr.Event{
		Kind:      1,
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"u", "https://example.com/auth"}, {"method", "POST"}},
		Content:   "",
	}
	_ = event.Sign(sk)
	eventJSON, _ := json.Marshal(event)

	_, err := VerifyNIP98(VerifyRequest{SignedEventJSON: string(eventJSON), ExpectedURL: "https://example.com/auth", ExpectedMethod: "POST"})
	if err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestVerifyNIP98_StaleTimestamp(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	event := nostr.Event{
		Kind:      nip98Kind,
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Add(-5 * time.Minute).Unix()),
		Tags:      nostr.Tags{{"u", "https://example.com/auth"}, {"method", "POST"}},
		Content:   "",
	}
	_ = event.Sign(sk)
	eventJSON, _ := json.Marshal(event)

	_, err := VerifyNIP98(VerifyRequest{SignedEventJSON: string(eventJSON), ExpectedURL: "https://example.com/auth", ExpectedMethod: "POST"})
	if err == nil {
		t.Fatal("expected error for stale timestamp")
	}
}

func TestVerifyNIP98_URLMismatch(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	event := nostr.Event{
		Kind:      nip98Kind,
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"u", "https://other.com/auth"}, {"method", "POST"}},
		Content:   "",
	}
	_ = event.Sign(sk)
	eventJSON, _ := json.Marshal(event)

	_, err := VerifyNIP98(VerifyRequest{SignedEventJSON: string(eventJSON), ExpectedURL: "https://example.com/auth", ExpectedMethod: "POST"})
	if err == nil {
		t.Fatal("expected error for URL mismatch")
	}
}

func TestVerifyNIP98_BadSignature(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	event := nostr.Event{
		Kind:      nip98Kind,
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"u", "https://example.com/auth"}, {"method", "POST"}},
		Content:   "",
	}
	_ = event.Sign(sk)
	// Tamper with signature
	event.Sig = "0000" + event.Sig[4:]
	eventJSON, _ := json.Marshal(event)

	_, err := VerifyNIP98(VerifyRequest{SignedEventJSON: string(eventJSON), ExpectedURL: "https://example.com/auth", ExpectedMethod: "POST"})
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

package auth

import (
	"net/http"
	"testing"
	"time"

	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"
)

func TestSharedNIP98VerifierBindsChallengeTransport(t *testing.T) {
	const target = "https://git.example.test/auth/nip55/callback"
	event := makeNIP98Event(t, "challenge-1", target, http.MethodPost)
	service := &Service{nip98: sharednip98.NewVerifier(time.Minute)}

	principal, err := service.VerifyNIP98(event, http.MethodPost, target)
	if err != nil {
		t.Fatal(err)
	}
	if principal.PubKey != event.PubKey || principal.EventID != event.ID {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestSharedNIP98VerifierRejectsWrongCallback(t *testing.T) {
	event := makeNIP98Event(t, "challenge-1", "https://git.example.test/auth/nip07/verify", http.MethodPost)
	service := &Service{nip98: sharednip98.NewVerifier(time.Minute)}
	if _, err := service.VerifyNIP98(event, http.MethodPost, "https://git.example.test/auth/nip55/callback"); err == nil {
		t.Fatal("expected callback URL mismatch")
	}
}

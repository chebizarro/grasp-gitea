// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// makePayloadNIP98Event signs a NIP-98 event with u/method tags and, for a
// non-empty body, the payload hash tag. A random nonce tag guarantees a
// unique event id even when two proofs are signed within the same second
// (real clients differ by created_at; tests do not).
func makePayloadNIP98Event(t *testing.T, target, method string, body []byte) *nostr.Event {
	t.Helper()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	tags := nostr.Tags{{"u", target}, {"method", method}, {"nonce", hex.EncodeToString(nonce)}}
	if len(body) > 0 {
		hash := sha256.Sum256(body)
		tags = append(tags, nostr.Tag{"payload", hex.EncodeToString(hash[:])})
	}
	ev := &nostr.Event{
		Kind:      27235,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
	}
	if err := ev.Sign(mustSK(testSecretKey)); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

func makeNIP98AuthHeader(t *testing.T, target, method string, body []byte) string {
	t.Helper()
	ev := makePayloadNIP98Event(t, target, method, body)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(raw)
}

func newNIP98TestService(t *testing.T, st *store.SQLiteStore) *Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &Service{
		store:     st,
		publicURL: "https://bridge.example.com",
		logger:    logger,
		nip98:     sharednip98.NewVerifier(time.Minute),
	}
}

func openNIP98TestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/nip98.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestParseNIP98AuthorizationRejectsGarbage(t *testing.T) {
	for _, header := range []string{
		"",
		"Bearer abc",
		"Nostr ",
		"Nostr not-base64!!!",
		"Nostr " + base64.StdEncoding.EncodeToString([]byte("not json")),
	} {
		if _, err := ParseNIP98Authorization(header); !errors.Is(err, ErrNIP98Unauthorized) {
			t.Errorf("ParseNIP98Authorization(%q) error = %v, want ErrNIP98Unauthorized", header, err)
		}
	}
}

func TestVerifyAndClaimNIP98PayloadBinding(t *testing.T) {
	st := openNIP98TestStore(t)
	svc := newNIP98TestService(t, st)
	ctx := context.Background()
	const target = "https://bridge.example.com/auth/token"
	body := []byte(`{"name":"laptop"}`)

	ev := makePayloadNIP98Event(t, target, "POST", body)
	principal, err := svc.VerifyAndClaimNIP98(ctx, ev, "POST", target, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if principal.PubKey != ev.PubKey.Hex() {
		t.Fatalf("principal = %+v", principal)
	}

	// The same signed event over a different body must fail.
	ev2 := makePayloadNIP98Event(t, target, "POST", body)
	if _, err := svc.VerifyAndClaimNIP98(ctx, ev2, "POST", target, []byte(`{"name":"evil"}`)); !errors.Is(err, ErrNIP98Unauthorized) {
		t.Fatalf("tampered body error = %v, want ErrNIP98Unauthorized", err)
	}

	// A non-empty body without a payload tag must fail.
	ev3 := makePayloadNIP98Event(t, target, "POST", nil)
	if _, err := svc.VerifyAndClaimNIP98(ctx, ev3, "POST", target, body); !errors.Is(err, ErrNIP98Unauthorized) {
		t.Fatalf("missing payload tag error = %v, want ErrNIP98Unauthorized", err)
	}
}

func TestVerifyAndClaimNIP98DurableReplay(t *testing.T) {
	st := openNIP98TestStore(t)
	ctx := context.Background()
	const target = "https://bridge.example.com/auth/tokens"
	ev := makePayloadNIP98Event(t, target, "GET", nil)

	first := newNIP98TestService(t, st)
	if _, err := first.VerifyAndClaimNIP98(ctx, ev, "GET", target, nil); err != nil {
		t.Fatalf("first use: %v", err)
	}

	// A fresh Service (fresh in-memory verifier, simulating a restart) must
	// still reject the event via the durable SQLite claim.
	second := newNIP98TestService(t, st)
	if _, err := second.VerifyAndClaimNIP98(ctx, ev, "GET", target, nil); !errors.Is(err, ErrNIP98Unauthorized) {
		t.Fatalf("replay across restart error = %v, want ErrNIP98Unauthorized", err)
	}
}

func TestCanonicalRequestTargetIgnoresHostHeader(t *testing.T) {
	svc := newNIP98TestService(t, openNIP98TestStore(t))
	r := httptest.NewRequest("GET", "/auth/tokens?limit=10", nil)
	r.Host = "evil.example.org"
	got := svc.CanonicalRequestTarget(r)
	want := "https://bridge.example.com/auth/tokens?limit=10"
	if got != want {
		t.Fatalf("CanonicalRequestTarget = %q, want %q (Host header must be ignored)", got, want)
	}
}

package signer

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeSessionBunker struct {
	pubkey    nostr.PubKey
	signed    int
	encrypted int
}

func (f *fakeSessionBunker) Ping(context.Context) error { return nil }
func (f *fakeSessionBunker) GetPublicKey(context.Context) (nostr.PubKey, error) {
	return f.pubkey, nil
}
func (f *fakeSessionBunker) SignEvent(context.Context, *nostr.Event) error {
	f.signed++
	return nil
}
func (f *fakeSessionBunker) NIP44Encrypt(_ context.Context, target nostr.PubKey, plaintext string) (string, error) {
	f.encrypted++
	return target.Hex() + ":" + plaintext, nil
}

func openSessionStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestDurableSignerForwardsNIP44ThroughManagedBunker(t *testing.T) {
	inner := &fakeSessionBunker{pubkey: nostr.Generate().Public()}
	managed := &managedBunkerSigner{BunkerSigner: inner, cancel: func() {}}
	durable := &DurableSignetSigner{bunker: managed, pubKey: inner.pubkey.Hex(), st: openSessionStore(t)}
	target := nostr.Generate().Public()
	got, err := durable.NIP44Encrypt(context.Background(), target, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if got != target.Hex()+":secret" || inner.encrypted != 1 {
		t.Fatalf("forwarded NIP-44 = %q, calls=%d", got, inner.encrypted)
	}
}

func TestSealUnsealSessionSecretRoundTrip(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	key := nostr.Generate()

	// Sealed with a master key.
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	sealed, err := sealSessionSecret(master, key, logger)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed[0] != sessionSealPrefix {
		t.Fatalf("expected sealed prefix, got %d", sealed[0])
	}
	got, err := unsealSessionSecret(master, sealed)
	if err != nil || got.Hex() != key.Hex() {
		t.Fatalf("unseal mismatch: %v", err)
	}
	if _, err := unsealSessionSecret(nil, sealed); err == nil {
		t.Fatal("expected error unsealing without master key")
	}

	// Plain mode without a master key.
	plain, err := sealSessionSecret(nil, key, logger)
	if err != nil {
		t.Fatalf("seal plain: %v", err)
	}
	if plain[0] != sessionPlainPrefix {
		t.Fatalf("expected plain prefix, got %d", plain[0])
	}
	got, err = unsealSessionSecret(nil, plain)
	if err != nil || got.Hex() != key.Hex() {
		t.Fatalf("unseal plain mismatch: %v", err)
	}
}

func TestDurableSignetSignerResumesPersistedClientKey(t *testing.T) {
	ctx := context.Background()
	st := openSessionStore(t)
	logger := slog.New(slog.DiscardHandler)
	signerKey := nostr.Generate()
	signerPub := signerKey.Public()
	bunkerURL := "bunker://" + signerPub.Hex() + "?relay=wss://relay.example&secret=one-time"

	type connectCall struct {
		clientKey string
		url       string
	}
	var calls []connectCall
	orig := bunkerConnectFn
	bunkerConnectFn = func(_ context.Context, clientKey nostr.SecretKey, url string) (BunkerSigner, error) {
		calls = append(calls, connectCall{clientKey: clientKey.Hex(), url: url})
		return &fakeSessionBunker{pubkey: signerPub}, nil
	}
	t.Cleanup(func() { bunkerConnectFn = orig })

	master := make([]byte, 32)

	// First connect: fresh key over the full URL (consumes the secret).
	s1, err := ConnectDurableSignetSigner(ctx, st, master, bunkerURL, nil, logger)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if s1.PublicKey() != signerPub.Hex() {
		t.Fatalf("pubkey = %s", s1.PublicKey())
	}
	if len(calls) != 1 || calls[0].url != bunkerURL {
		t.Fatalf("expected first connect over full URL, got %+v", calls)
	}
	firstClientKey := calls[0].clientKey

	// Restart: resume with the SAME client key over the secret-stripped URL.
	s2, err := ConnectDurableSignetSigner(ctx, st, master, bunkerURL, nil, logger)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if s2.PublicKey() != signerPub.Hex() {
		t.Fatalf("resume pubkey = %s", s2.PublicKey())
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 connects, got %d", len(calls))
	}
	if calls[1].clientKey != firstClientKey {
		t.Fatalf("restart must reuse the authorized client key: %s != %s", calls[1].clientKey, firstClientKey)
	}
	if calls[1].url == bunkerURL {
		t.Fatalf("resume must not replay the one-time connect secret")
	}

	// Resume failure falls back to fresh authorization over the full URL.
	failNext := true
	bunkerConnectFn = func(_ context.Context, clientKey nostr.SecretKey, url string) (BunkerSigner, error) {
		calls = append(calls, connectCall{clientKey: clientKey.Hex(), url: url})
		if failNext {
			failNext = false
			return nil, fmt.Errorf("bunker rejected stored key")
		}
		return &fakeSessionBunker{pubkey: signerPub}, nil
	}
	if _, err := ConnectDurableSignetSigner(ctx, st, master, bunkerURL, nil, logger); err != nil {
		t.Fatalf("fallback connect: %v", err)
	}
	last := calls[len(calls)-1]
	if last.url != bunkerURL {
		t.Fatalf("fallback must use full URL, got %q", last.url)
	}
	if last.clientKey == firstClientKey {
		t.Fatalf("fallback must generate a fresh client key")
	}
}

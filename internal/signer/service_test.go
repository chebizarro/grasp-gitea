package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeBunkerSigner struct {
	pubkey string
	secret string

	pingErr error
	getErr  error
	signErr error

	pingCount int
	signCount int
}

func (f *fakeBunkerSigner) Ping(ctx context.Context) error {
	f.pingCount++
	return f.pingErr
}

func (f *fakeBunkerSigner) GetPublicKey(ctx context.Context) (nostr.PubKey, error) {
	if f.getErr != nil {
		return nostr.PubKey{}, f.getErr
	}
	return nostr.PubKeyFromHex(f.pubkey)
}

func (f *fakeBunkerSigner) SignEvent(ctx context.Context, evt *nostr.Event) error {
	f.signCount++
	if f.signErr != nil {
		return f.signErr
	}
	sk, err := nostr.SecretKeyFromHex(f.secret)
	if err != nil {
		return err
	}
	return evt.Sign(sk)
}

func TestCreateGrantPersistsEncryptedGrant(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	signerSecret := nostr.Generate().Hex()
	signerPubkey := mustPubkey(t, signerSecret)
	bunkerURI := "bunker://" + signerPubkey + "?relay=wss://relay.example&secret=connect-secret"

	fake := &fakeBunkerSigner{pubkey: signerPubkey, secret: signerSecret}
	var capturedClientSecret string
	svc := newTestService(t, st, func(ctx context.Context, clientSecretKey string, gotURI string) (BunkerSigner, error) {
		capturedClientSecret = clientSecretKey
		if gotURI != bunkerURI {
			t.Fatalf("connector got URI %q, want %q", gotURI, bunkerURI)
		}
		return fake, nil
	})

	grantInfo, err := svc.CreateGrant(ctx, bunkerURI)
	if err != nil {
		t.Fatalf("CreateGrant() error: %v", err)
	}
	if grantInfo.Pubkey != signerPubkey {
		t.Fatalf("grant pubkey = %s, want %s", grantInfo.Pubkey, signerPubkey)
	}
	if capturedClientSecret == "" {
		t.Fatal("connector did not receive generated client secret")
	}
	if grantInfo.ClientPubkey != mustPubkey(t, capturedClientSecret) {
		t.Fatal("grant returned client pubkey does not match generated client secret")
	}

	stored, err := st.GetSignerGrant(ctx, signerPubkey)
	if err != nil {
		t.Fatalf("GetSignerGrant() error: %v", err)
	}
	if bytes.Contains(stored.ClientSeckeyEnc, []byte(capturedClientSecret)) {
		t.Fatal("stored client_seckey_enc contains plaintext client secret")
	}
	if bytes.Contains(stored.BunkerURIEnc, []byte(bunkerURI)) {
		t.Fatal("stored bunker_uri_enc contains plaintext bunker URI")
	}

	clientSecretPlain, err := svc.decryptSecret(stored.ClientSeckeyEnc)
	if err != nil {
		t.Fatalf("decrypt client secret: %v", err)
	}
	if clientSecretPlain != capturedClientSecret {
		t.Fatal("decrypted client secret did not round-trip")
	}
	bunkerURIPlain, err := svc.decryptSecret(stored.BunkerURIEnc)
	if err != nil {
		t.Fatalf("decrypt bunker URI: %v", err)
	}
	if bunkerURIPlain != "bunker://"+signerPubkey+"?relay=wss%3A%2F%2Frelay.example" {
		t.Fatalf("persisted bunker URI = %q; expected reusable URI without connect secret", bunkerURIPlain)
	}
	if stored.Relays != `["wss://relay.example"]` {
		t.Fatalf("stored relays = %s", stored.Relays)
	}
	if stored.Permissions != `["sign_event"]` {
		t.Fatalf("stored permissions = %s", stored.Permissions)
	}
	if stored.Status != "active" {
		t.Fatalf("stored status = %s", stored.Status)
	}
	if stored.LastOKAt == nil {
		t.Fatal("last_ok_at was not recorded")
	}
}

func TestCreateGrantRejectsSignerPubkeyMismatch(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	expectedSecret := nostr.Generate().Hex()
	expectedPubkey := mustPubkey(t, expectedSecret)
	actualSecret := nostr.Generate().Hex()
	actualPubkey := mustPubkey(t, actualSecret)
	bunkerURI := "bunker://" + expectedPubkey + "?relay=wss://relay.example"

	svc := newTestService(t, st, func(ctx context.Context, clientSecretKey string, gotURI string) (BunkerSigner, error) {
		return &fakeBunkerSigner{pubkey: actualPubkey, secret: actualSecret}, nil
	})

	_, err := svc.CreateGrant(ctx, bunkerURI)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "pubkey mismatch") {
		t.Fatalf("expected pubkey mismatch error, got %v", err)
	}
	if _, getErr := st.GetSignerGrant(ctx, expectedPubkey); !errors.Is(getErr, sql.ErrNoRows) {
		t.Fatalf("expected no stored grant for expected pubkey, got %v", getErr)
	}
	if _, getErr := st.GetSignerGrant(ctx, actualPubkey); !errors.Is(getErr, sql.ErrNoRows) {
		t.Fatalf("expected no stored grant for actual pubkey, got %v", getErr)
	}
}

func TestCreateGrantAcceptsIdentityFromTrustedMultiplexedBunker(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	servicePubkey := mustPubkey(t, nostr.Generate().Hex())
	identitySecret := nostr.Generate().Hex()
	identityPubkey := mustPubkey(t, identitySecret)
	bunkerURI := "bunker://" + servicePubkey + "?relay=wss://relay.example&secret=connect"

	svc, err := NewService(
		st,
		[]byte("12345678901234567890123456789012"),
		WithTrustedMultiplexedBunkerURI(bunkerURI),
		WithConnector(func(context.Context, string, string) (BunkerSigner, error) {
			return &fakeBunkerSigner{pubkey: identityPubkey, secret: identitySecret}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	grant, err := svc.CreateGrant(ctx, bunkerURI)
	if err != nil {
		t.Fatalf("CreateGrant() error: %v", err)
	}
	if grant.Pubkey != identityPubkey {
		t.Fatalf("grant pubkey = %s, want %s", grant.Pubkey, identityPubkey)
	}
	if _, err := st.GetSignerGrant(ctx, identityPubkey); err != nil {
		t.Fatalf("trusted multiplexed signer grant was not stored: %v", err)
	}
}

func TestSignWithGrantSignsViaPooledSigner(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	signerSecret := nostr.Generate().Hex()
	signerPubkey := mustPubkey(t, signerSecret)
	bunkerURI := "bunker://" + signerPubkey + "?relay=wss://relay.example"
	fake := &fakeBunkerSigner{pubkey: signerPubkey, secret: signerSecret}
	connectorCalls := 0
	svc := newTestService(t, st, func(ctx context.Context, clientSecretKey string, gotURI string) (BunkerSigner, error) {
		connectorCalls++
		return fake, nil
	})

	if _, err := svc.CreateGrant(ctx, bunkerURI); err != nil {
		t.Fatalf("CreateGrant() error: %v", err)
	}
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   "sign me through the pooled bunker",
	}
	if err := svc.SignWithGrant(ctx, signerPubkey, event); err != nil {
		t.Fatalf("SignWithGrant() error: %v", err)
	}
	if connectorCalls != 1 {
		t.Fatalf("connector calls = %d, want 1 pooled signer", connectorCalls)
	}
	if fake.signCount != 1 {
		t.Fatalf("fake signer sign count = %d, want 1", fake.signCount)
	}
	if event.PubKey.Hex() != signerPubkey {
		t.Fatalf("event pubkey = %s, want %s", event.PubKey, signerPubkey)
	}
	if !event.VerifySignature() {
		t.Fatal("signed event signature did not verify")
	}
}

func TestSignWithGrantNoGrantErrorsCleanly(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := newTestService(t, st, func(ctx context.Context, clientSecretKey string, gotURI string) (BunkerSigner, error) {
		t.Fatal("connector should not be called for missing grant")
		return nil, nil
	})

	missingPubkey := mustPubkey(t, nostr.Generate().Hex())
	err := svc.SignWithGrant(ctx, missingPubkey, &nostr.Event{Kind: nostr.KindTextNote, CreatedAt: nostr.Now()})
	if !errors.Is(err, ErrNoGrant) {
		t.Fatalf("SignWithGrant() error = %v, want ErrNoGrant", err)
	}
}

func TestDisabledSubsystemIsSafeNoop(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc, err := NewService(st, nil)
	if err != nil {
		t.Fatalf("NewService disabled error: %v", err)
	}
	if svc.Enabled() {
		t.Fatal("service should be disabled without master key")
	}
	if _, err := svc.CreateGrant(ctx, "bunker://ignored"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("CreateGrant disabled error = %v, want ErrDisabled", err)
	}
	if err := svc.SignWithGrant(ctx, mustPubkey(t, nostr.Generate().Hex()), &nostr.Event{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("SignWithGrant disabled error = %v, want ErrDisabled", err)
	}
}

func openTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/signer-test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newTestService(t *testing.T, st *store.SQLiteStore, connector BunkerConnector) *Service {
	t.Helper()
	svc, err := NewService(st, []byte("12345678901234567890123456789012"), WithConnector(connector))
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	return svc
}

func mustPubkey(t *testing.T, secret string) string {
	t.Helper()
	sk, err := nostr.SecretKeyFromHex(secret)
	if err != nil {
		t.Fatalf("SecretKeyFromHex() error: %v", err)
	}
	return sk.Public().Hex()
}

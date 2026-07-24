// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package signer

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip46"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// DurableSignetSigner is the bridge's restart-durable NIP-46 server signer.
// Signet authorization is one-time: the client key authorized at first
// connect is encrypted and persisted, and every restart reconnects with the
// stored identity instead of generating a fresh key.
type DurableSignetSigner struct {
	bunker    BunkerSigner
	pubKey    string
	bunkerURI string
	st        *store.SQLiteStore
	logger    *slog.Logger
}

// PublicKey returns the remote signer's pubkey (hex).
func (d *DurableSignetSigner) PublicKey() string { return d.pubKey }

// SignEvent signs with the persistent bunker session.
func (d *DurableSignetSigner) SignEvent(ctx context.Context, ev *nostr.Event) error {
	if ev == nil {
		return fmt.Errorf("event is required")
	}
	if err := d.bunker.SignEvent(ctx, ev); err != nil {
		return err
	}
	_ = d.st.TouchBridgeSignerSession(ctx, d.bunkerURI, time.Now())
	return nil
}

// ConnectDurableSignetSigner establishes (or resumes) the bridge's NIP-46
// session with a Signet bunker.
//
// Resume path: a persisted session for the secret-stripped bunker URI is
// decrypted and reconnected with the stored client key. First-connect path
// (or resume failure with a connect secret still present): a fresh client key
// connects using the full bunker URL — consuming the one-time secret — and
// the authorized identity is persisted for future restarts.
//
// The client secret key is sealed with the signer master key (NaCl
// secretbox) when one is configured; without a master key it is stored
// unsealed and a warning is logged.
func ConnectDurableSignetSigner(ctx context.Context, st *store.SQLiteStore, masterKey []byte, bunkerURL string, relays []string, logger *slog.Logger) (*DurableSignetSigner, error) {
	if st == nil {
		return nil, fmt.Errorf("store is required for durable signet signer")
	}
	logger = logger.With("component", "signet-session")

	preparedURL, err := appendFallbackRelays(bunkerURL, relays)
	if err != nil {
		return nil, err
	}
	durableURI, err := stripConnectSecret(preparedURL)
	if err != nil {
		return nil, err
	}

	// Resume a persisted session first.
	if sess, err := st.GetBridgeSignerSession(ctx, durableURI); err == nil {
		clientKey, decErr := unsealSessionSecret(masterKey, sess.ClientSeckeyEnc)
		if decErr != nil {
			logger.Warn("stored bridge signer session could not be decrypted; falling back to fresh authorization", "error", decErr)
		} else {
			signer, resumeErr := connectSignetSession(ctx, st, clientKey, durableURI, durableURI, masterKey, logger)
			if resumeErr == nil {
				logger.Info("resumed persisted NIP-46 bridge session", "signer_pubkey", signer.pubKey, "client_pubkey", sess.ClientPubkey)
				return signer, nil
			}
			logger.Warn("resume of persisted NIP-46 bridge session failed", "error", resumeErr)
		}
	}

	// First connect (or resume failure): fresh key over the full URL, which
	// consumes the one-time connect secret if present.
	freshKey := nostr.Generate()
	signer, err := connectSignetSession(ctx, st, freshKey, preparedURL, durableURI, masterKey, logger)
	if err != nil {
		return nil, fmt.Errorf("connect Signet bunker: %w", err)
	}
	logger.Info("established new NIP-46 bridge session", "signer_pubkey", signer.pubKey, "client_pubkey", freshKey.Public().Hex())
	return signer, nil
}

// bunkerConnectFn is swappable in tests.
var bunkerConnectFn = connectBunkerDetached

func connectSignetSession(ctx context.Context, st *store.SQLiteStore, clientKey nostr.SecretKey, connectURL string, durableURI string, masterKey []byte, logger *slog.Logger) (*DurableSignetSigner, error) {
	client, err := bunkerConnectFn(ctx, clientKey, connectURL)
	if err != nil {
		return nil, err
	}
	pkCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	pubKey, err := client.GetPublicKey(pkCtx)
	if err != nil {
		return nil, fmt.Errorf("get signer public key: %w", err)
	}

	sealed, err := sealSessionSecret(masterKey, clientKey, logger)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := st.UpsertBridgeSignerSession(ctx, store.BridgeSignerSession{
		BunkerURI:       durableURI,
		ClientSeckeyEnc: sealed,
		ClientPubkey:    clientKey.Public().Hex(),
		SignerPubkey:    pubKey.Hex(),
		CreatedAt:       now,
		LastOKAt:        &now,
	}); err != nil {
		return nil, err
	}

	return &DurableSignetSigner{
		bunker:    client,
		pubKey:    pubKey.Hex(),
		bunkerURI: durableURI,
		st:        st,
		logger:    logger,
	}, nil
}

// connectBunkerDetached mirrors Service.connectBunker for the bridge session:
// ConnectBunker retains its context for the long-lived response subscription,
// so the connection uses a cancellation-detached context while the handshake
// stays bounded.
func connectBunkerDetached(ctx context.Context, clientKey nostr.SecretKey, bunkerURL string) (BunkerSigner, error) {
	type result struct {
		client *nip46.BunkerClient
		err    error
	}
	resultCh := make(chan result, 1)
	connCtx := context.WithoutCancel(ctx)
	go func() {
		client, err := nip46.ConnectBunker(connCtx, clientKey, bunkerURL, nil, func(string) {})
		resultCh <- result{client: client, err: err}
	}()
	select {
	case r := <-resultCh:
		return r.client, r.err
	case <-time.After(connectTimeout):
		return nil, fmt.Errorf("connect bunker: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		return nil, fmt.Errorf("connect bunker: %w", ctx.Err())
	}
}

const sessionSealPrefix = byte(1)
const sessionPlainPrefix = byte(0)

func sealSessionSecret(masterKey []byte, clientKey nostr.SecretKey, logger *slog.Logger) ([]byte, error) {
	plaintext := clientKey.Hex()
	if len(masterKey) != 32 {
		logger.Warn("SIGNER_MASTER_KEY not configured; bridge NIP-46 client key stored unencrypted")
		return append([]byte{sessionPlainPrefix}, []byte(plaintext)...), nil
	}
	var key [32]byte
	copy(key[:], masterKey)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate session nonce: %w", err)
	}
	sealed := secretbox.Seal(nil, []byte(plaintext), &nonce, &key)
	out := make([]byte, 0, 1+len(nonce)+len(sealed))
	out = append(out, sessionSealPrefix)
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}

func unsealSessionSecret(masterKey []byte, blob []byte) (nostr.SecretKey, error) {
	if len(blob) < 2 {
		return nostr.SecretKey{}, fmt.Errorf("stored session secret too short")
	}
	switch blob[0] {
	case sessionPlainPrefix:
		return nostr.SecretKeyFromHex(string(blob[1:]))
	case sessionSealPrefix:
		if len(masterKey) != 32 {
			return nostr.SecretKey{}, fmt.Errorf("session sealed but SIGNER_MASTER_KEY is not configured")
		}
		if len(blob) < 1+24+secretbox.Overhead {
			return nostr.SecretKey{}, fmt.Errorf("sealed session secret too short")
		}
		var key [32]byte
		copy(key[:], masterKey)
		var nonce [24]byte
		copy(nonce[:], blob[1:25])
		opened, ok := secretbox.Open(nil, blob[25:], &nonce, &key)
		if !ok {
			return nostr.SecretKey{}, fmt.Errorf("decrypt session secret failed")
		}
		return nostr.SecretKeyFromHex(string(opened))
	default:
		return nostr.SecretKey{}, fmt.Errorf("unknown session secret format %d", blob[0])
	}
}

// appendFallbackRelays adds relay query parameters to a bunker:// URL that
// carries none, so the connection has somewhere to reach the signer.
func appendFallbackRelays(bunkerURL string, relays []string) (string, error) {
	u, err := url.Parse(bunkerURL)
	if err != nil {
		return "", fmt.Errorf("invalid bunker url: %w", err)
	}
	if u.Scheme != "bunker" || len(u.Query()["relay"]) > 0 || len(relays) == 0 {
		return bunkerURL, nil
	}
	q := u.Query()
	for _, r := range relays {
		if r != "" {
			q.Add("relay", r)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

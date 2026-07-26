package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip46"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/sharegap/grasp-gitea/internal/store"
)

var (
	// ErrDisabled is returned when SIGNER_MASTER_KEY is not configured.
	ErrDisabled = errors.New("signer subsystem disabled")
	// ErrNoGrant is returned when no active grant exists for a pubkey.
	ErrNoGrant = errors.New("signer grant not found")
	// ErrSignerOffline is returned when a grant exists but its remote signer cannot be reached.
	ErrSignerOffline = errors.New("signer offline")
)

const (
	grantStatusActive   = "active"
	permissionSignEvent = "sign_event"
)

// BunkerSigner is the small subset of the NIP-46 bunker client used by
// the persistent signer foundation. Tests provide fakes so they never need a
// live remote signer.
type BunkerSigner interface {
	Ping(ctx context.Context) error
	GetPublicKey(ctx context.Context) (nostr.PubKey, error)
	SignEvent(ctx context.Context, evt *nostr.Event) error
}

type managedBunkerSigner struct {
	BunkerSigner
	cancel context.CancelFunc
	once   sync.Once
}

// NIP44Encrypt forwards optional encryption without erasing it behind the
// narrower persistent BunkerSigner interface.
func (m *managedBunkerSigner) NIP44Encrypt(ctx context.Context, target nostr.PubKey, plaintext string) (string, error) {
	encryptor, ok := m.BunkerSigner.(interface {
		NIP44Encrypt(context.Context, nostr.PubKey, string) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("remote signer does not support NIP-44 encryption")
	}
	return encryptor.NIP44Encrypt(ctx, target, plaintext)
}

func (m *managedBunkerSigner) close() {
	if m != nil {
		m.once.Do(m.cancel)
	}
}

func closeBunkerSigner(signer BunkerSigner) {
	if managed, ok := signer.(*managedBunkerSigner); ok {
		managed.close()
	}
}

// BunkerConnector establishes a NIP-46 bunker signer for a persisted grant.
type BunkerConnector func(ctx context.Context, clientSecretKey string, bunkerURI string) (BunkerSigner, error)

// connectTimeout bounds the NIP-46 bunker handshake.
const connectTimeout = 30 * time.Second

// GrantInfo is returned after a grant is created without exposing plaintext
// secrets or encrypted blobs to callers.
type GrantInfo struct {
	Pubkey       string
	ClientPubkey string
	Relays       []string
	GrantedAt    time.Time
}

type Service struct {
	store                *store.SQLiteStore
	enabled              bool
	masterKey            [32]byte
	connector            BunkerConnector
	trustedBunkerPubkeys map[string]struct{}

	mu   sync.Mutex
	pool map[string]BunkerSigner
}

type Option func(*Service)

// WithConnector overrides the production NIP-46 connector. It is intended for tests.
func WithConnector(connector BunkerConnector) Option {
	return func(s *Service) {
		if connector != nil {
			s.connector = connector
		}
	}
}

// WithTrustedMultiplexedBunkerURI permits a configured NIP-46 service to
// return the selected identity pubkey instead of the service pubkey encoded in
// its URI. This supports multi-tenant signers such as Signet without relaxing
// pubkey matching for arbitrary user-supplied bunkers.
func WithTrustedMultiplexedBunkerURI(bunkerURI string) Option {
	return func(s *Service) {
		pubkey, _, err := parseBunkerURI(strings.TrimSpace(bunkerURI))
		if err == nil && pubkey != "" {
			s.trustedBunkerPubkeys[pubkey] = struct{}{}
		}
	}
}

// NewService creates the persistent signer service. A nil/empty master key is a
// safe disabled mode; callers can construct the service unconditionally and
// check Enabled before exposing signer-dependent features.
func NewService(st *store.SQLiteStore, masterKey []byte, opts ...Option) (*Service, error) {
	svc := &Service{
		store:                st,
		connector:            connectNIP46Bunker,
		pool:                 make(map[string]BunkerSigner),
		trustedBunkerPubkeys: make(map[string]struct{}),
	}
	if len(masterKey) == 0 {
		return svc, nil
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("signer master key must be 32 bytes")
	}
	if st == nil {
		return nil, fmt.Errorf("signer store is required when enabled")
	}
	copy(svc.masterKey[:], masterKey)
	svc.enabled = true
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

func (s *Service) Enabled() bool {
	return s != nil && s.enabled
}

// Close releases all cached long-lived bunker connections.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	pooled := make([]BunkerSigner, 0, len(s.pool))
	for pubkey, bunker := range s.pool {
		pooled = append(pooled, bunker)
		delete(s.pool, pubkey)
	}
	s.mu.Unlock()
	for _, bunker := range pooled {
		closeBunkerSigner(bunker)
	}
	return nil
}

// CreateGrant connects to a user bunker, verifies the signer pubkey, encrypts
// the reusable client secret and bunker URI, and stores the durable grant keyed
// by the signer's pubkey.
func (s *Service) CreateGrant(ctx context.Context, bunkerURI string) (GrantInfo, error) {
	if !s.Enabled() {
		return GrantInfo{}, ErrDisabled
	}
	bunkerURI = strings.TrimSpace(bunkerURI)
	if bunkerURI == "" {
		return GrantInfo{}, fmt.Errorf("bunker URI is required")
	}

	expectedPubkey, relays, err := parseBunkerURI(bunkerURI)
	if err != nil {
		return GrantInfo{}, err
	}

	clientSK := nostr.Generate()
	clientSecretKey := clientSK.Hex()
	clientPubkey := clientSK.Public().Hex()

	bunker, err := s.connectBunker(ctx, clientSecretKey, bunkerURI)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("%w: connect bunker: %v", ErrSignerOffline, err)
	}
	retained := false
	defer func() {
		if !retained {
			closeBunkerSigner(bunker)
		}
	}()
	signerPK, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("%w: get signer pubkey: %v", ErrSignerOffline, err)
	}
	signerPubkey := signerPK.Hex()
	if expectedPubkey != "" && signerPubkey != expectedPubkey {
		if _, trusted := s.trustedBunkerPubkeys[expectedPubkey]; !trusted {
			return GrantInfo{}, fmt.Errorf("signer pubkey mismatch: bunker URI targets %s but signer reported %s", expectedPubkey, signerPubkey)
		}
	}
	if err := bunker.Ping(ctx); err != nil {
		return GrantInfo{}, fmt.Errorf("%w: ping signer: %v", ErrSignerOffline, err)
	}

	clientSecretEnc, err := s.encryptSecret(clientSecretKey)
	if err != nil {
		return GrantInfo{}, err
	}
	durableBunkerURI, err := stripConnectSecret(bunkerURI)
	if err != nil {
		return GrantInfo{}, err
	}
	bunkerURIEnc, err := s.encryptSecret(durableBunkerURI)
	if err != nil {
		return GrantInfo{}, err
	}
	relaysJSON, err := marshalStrings(relays)
	if err != nil {
		return GrantInfo{}, err
	}
	permissionsJSON, err := marshalStrings([]string{permissionSignEvent})
	if err != nil {
		return GrantInfo{}, err
	}

	now := time.Now().UTC()
	grant := store.SignerGrant{
		Pubkey:          signerPubkey,
		ClientSeckeyEnc: clientSecretEnc,
		BunkerURIEnc:    bunkerURIEnc,
		Relays:          relaysJSON,
		Permissions:     permissionsJSON,
		GrantedAt:       now,
		LastOKAt:        &now,
		Status:          grantStatusActive,
	}
	if err := s.store.UpsertSignerGrant(ctx, grant); err != nil {
		return GrantInfo{}, fmt.Errorf("store signer grant: %w", err)
	}

	s.cacheSigner(signerPubkey, bunker)
	retained = true
	return GrantInfo{Pubkey: signerPubkey, ClientPubkey: clientPubkey, Relays: relays, GrantedAt: now}, nil
}

// stripConnectSecret removes the one-time NIP-46 connection secret before a
// grant is persisted. Reconnects authenticate with the durable client key that
// was authorized during CreateGrant; replaying the consumed secret can fail or
// unnecessarily retain sensitive bootstrap material.
func stripConnectSecret(bunkerURI string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(bunkerURI))
	if err != nil {
		return "", fmt.Errorf("parse bunker URI for persistence: %w", err)
	}
	q := u.Query()
	q.Del("secret")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SignWithGrant signs evt with the remote signer authorized by pubkey.
func (s *Service) SignWithGrant(ctx context.Context, pubkey string, evt *nostr.Event) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if evt == nil {
		return fmt.Errorf("event is required")
	}
	signer, err := s.signerForGrant(ctx, pubkey)
	if err != nil {
		return err
	}
	if err := signer.SignEvent(ctx, evt); err != nil {
		s.evictSigner(pubkey)
		return fmt.Errorf("%w: sign event for %s: %v", ErrSignerOffline, pubkey, err)
	}
	_ = s.store.RecordSignerGrantOK(ctx, pubkey, time.Now().UTC())
	return nil
}

// connectBunker gives ConnectBunker a dedicated long-lived context because
// the client retains it for later signing calls. Unlike context.WithoutCancel,
// this context is explicitly cancelled when the caller or handshake timeout
// wins, so failed connection attempts cannot outlive the request.
func (s *Service) connectBunker(ctx context.Context, clientSecretKey string, bunkerURI string) (BunkerSigner, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("connect bunker: %w", err)
	}
	type result struct {
		bunker BunkerSigner
		err    error
	}
	resultCh := make(chan result, 1)
	connCtx, connCancel := context.WithCancel(context.Background())
	go func() {
		bunker, err := s.connector(connCtx, clientSecretKey, bunkerURI)
		resultCh <- result{bunker: bunker, err: err}
	}()
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()
	select {
	case r := <-resultCh:
		if err := ctx.Err(); err != nil {
			connCancel()
			return nil, fmt.Errorf("connect bunker: %w", err)
		}
		if r.err != nil {
			connCancel()
			return nil, r.err
		}
		if r.bunker == nil {
			connCancel()
			return nil, fmt.Errorf("connector returned no bunker client")
		}
		return &managedBunkerSigner{BunkerSigner: r.bunker, cancel: connCancel}, nil
	case <-timer.C:
		connCancel()
		return nil, fmt.Errorf("connect bunker: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		connCancel()
		return nil, fmt.Errorf("connect bunker: %w", ctx.Err())
	}
}

func connectNIP46Bunker(ctx context.Context, clientSecretKey string, bunkerURI string) (BunkerSigner, error) {
	sk, err := nostr.SecretKeyFromHex(clientSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client secret key: %w", err)
	}
	return nip46.ConnectBunker(ctx, sk, bunkerURI, nil, func(string) {})
}

func (s *Service) signerForGrant(ctx context.Context, pubkey string) (BunkerSigner, error) {
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		return nil, fmt.Errorf("%w: empty pubkey", ErrNoGrant)
	}

	if cached := s.cachedSigner(pubkey); cached != nil {
		if err := cached.Ping(ctx); err == nil {
			_ = s.store.RecordSignerGrantOK(ctx, pubkey, time.Now().UTC())
			return cached, nil
		}
		s.evictSigner(pubkey)
	}

	grant, err := s.store.GetSignerGrant(ctx, pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w for pubkey %s", ErrNoGrant, pubkey)
	}
	if err != nil {
		return nil, fmt.Errorf("get signer grant: %w", err)
	}
	if grant.Status != grantStatusActive || grant.RevokedAt != nil {
		return nil, fmt.Errorf("%w for pubkey %s: status=%s", ErrNoGrant, pubkey, grant.Status)
	}

	clientSecretKey, err := s.decryptSecret(grant.ClientSeckeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt signer client key: %w", err)
	}
	bunkerURI, err := s.decryptSecret(grant.BunkerURIEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt signer bunker URI: %w", err)
	}

	bunker, err := s.connectBunker(ctx, clientSecretKey, bunkerURI)
	if err != nil {
		return nil, fmt.Errorf("%w: reconnect signer %s: %v", ErrSignerOffline, pubkey, err)
	}
	retained := false
	defer func() {
		if !retained {
			closeBunkerSigner(bunker)
		}
	}()
	signerPK, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: verify signer %s: %v", ErrSignerOffline, pubkey, err)
	}
	signerPubkey := signerPK.Hex()
	if signerPubkey != pubkey {
		return nil, fmt.Errorf("signer grant pubkey mismatch: requested %s but signer reported %s", pubkey, signerPubkey)
	}
	if err := bunker.Ping(ctx); err != nil {
		return nil, fmt.Errorf("%w: ping signer %s: %v", ErrSignerOffline, pubkey, err)
	}

	s.cacheSigner(pubkey, bunker)
	retained = true
	_ = s.store.RecordSignerGrantOK(ctx, pubkey, time.Now().UTC())
	return bunker, nil
}

func (s *Service) cachedSigner(pubkey string) BunkerSigner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pool[pubkey]
}

func (s *Service) cacheSigner(pubkey string, signer BunkerSigner) {
	s.mu.Lock()
	previous := s.pool[pubkey]
	s.pool[pubkey] = signer
	s.mu.Unlock()
	if previous != signer {
		closeBunkerSigner(previous)
	}
}

func (s *Service) evictSigner(pubkey string) {
	s.mu.Lock()
	previous := s.pool[pubkey]
	delete(s.pool, pubkey)
	s.mu.Unlock()
	closeBunkerSigner(previous)
}

func (s *Service) encryptSecret(plaintext string) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate signer secret nonce: %w", err)
	}
	sealed := secretbox.Seal(nil, []byte(plaintext), &nonce, &s.masterKey)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}

func (s *Service) decryptSecret(ciphertext []byte) (string, error) {
	if len(ciphertext) < 24+secretbox.Overhead {
		return "", fmt.Errorf("ciphertext too short")
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	opened, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &s.masterKey)
	if !ok {
		return "", fmt.Errorf("decrypt failed")
	}
	return string(opened), nil
}

func parseBunkerURI(raw string) (expectedPubkey string, relays []string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("invalid bunker URI: %w", err)
	}
	if u.Scheme == "" {
		// A scheme-less value is treated as NIP-05. There is no pubkey or
		// relay list to sanity-check until ConnectBunker resolves it.
		return "", nil, nil
	}
	if u.Scheme != "bunker" {
		return "", nil, fmt.Errorf("invalid bunker URI scheme %q", u.Scheme)
	}
	expectedPubkey = u.Host
	if expectedPubkey == "" {
		expectedPubkey = strings.TrimPrefix(u.Path, "/")
	}
	if _, err := nostr.PubKeyFromHex(expectedPubkey); err != nil {
		return "", nil, fmt.Errorf("invalid bunker pubkey %q", expectedPubkey)
	}
	return expectedPubkey, append([]string(nil), u.Query()["relay"]...), nil
}

func marshalStrings(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

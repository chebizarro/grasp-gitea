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

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
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

// BunkerSigner is the small subset of go-nostr's *nip46.BunkerClient used by
// the persistent signer foundation. Tests provide fakes so they never need a
// live remote signer.
type BunkerSigner interface {
	Ping(ctx context.Context) error
	GetPublicKey(ctx context.Context) (string, error)
	SignEvent(ctx context.Context, evt *nostr.Event) error
}

// BunkerConnector establishes a NIP-46 bunker signer for a persisted grant.
type BunkerConnector func(ctx context.Context, clientSecretKey string, bunkerURI string) (BunkerSigner, error)

// GrantInfo is returned after a grant is created without exposing plaintext
// secrets or encrypted blobs to callers.
type GrantInfo struct {
	Pubkey       string
	ClientPubkey string
	Relays       []string
	GrantedAt    time.Time
}

type Service struct {
	store     *store.SQLiteStore
	enabled   bool
	masterKey [32]byte
	connector BunkerConnector

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

// NewService creates the persistent signer service. A nil/empty master key is a
// safe disabled mode; callers can construct the service unconditionally and
// check Enabled before exposing signer-dependent features.
func NewService(st *store.SQLiteStore, masterKey []byte, opts ...Option) (*Service, error) {
	svc := &Service{
		store:     st,
		connector: connectNIP46Bunker,
		pool:      make(map[string]BunkerSigner),
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

	clientSecretKey := nostr.GeneratePrivateKey()
	clientPubkey, err := nostr.GetPublicKey(clientSecretKey)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("derive client pubkey: %w", err)
	}

	bunker, err := s.connector(ctx, clientSecretKey, bunkerURI)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("%w: connect bunker: %v", ErrSignerOffline, err)
	}
	signerPubkey, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("%w: get signer pubkey: %v", ErrSignerOffline, err)
	}
	if expectedPubkey != "" && signerPubkey != expectedPubkey {
		return GrantInfo{}, fmt.Errorf("signer pubkey mismatch: bunker URI targets %s but signer reported %s", expectedPubkey, signerPubkey)
	}
	if !nostr.IsValidPublicKey(signerPubkey) {
		return GrantInfo{}, fmt.Errorf("signer returned invalid pubkey %q", signerPubkey)
	}
	if err := bunker.Ping(ctx); err != nil {
		return GrantInfo{}, fmt.Errorf("%w: ping signer: %v", ErrSignerOffline, err)
	}

	clientSecretEnc, err := s.encryptSecret(clientSecretKey)
	if err != nil {
		return GrantInfo{}, err
	}
	bunkerURIEnc, err := s.encryptSecret(bunkerURI)
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
	return GrantInfo{Pubkey: signerPubkey, ClientPubkey: clientPubkey, Relays: relays, GrantedAt: now}, nil
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

func connectNIP46Bunker(ctx context.Context, clientSecretKey string, bunkerURI string) (BunkerSigner, error) {
	return nip46.ConnectBunker(ctx, clientSecretKey, bunkerURI, nil, func(string) {})
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

	bunker, err := s.connector(ctx, clientSecretKey, bunkerURI)
	if err != nil {
		return nil, fmt.Errorf("%w: reconnect signer %s: %v", ErrSignerOffline, pubkey, err)
	}
	signerPubkey, err := bunker.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: verify signer %s: %v", ErrSignerOffline, pubkey, err)
	}
	if signerPubkey != pubkey {
		return nil, fmt.Errorf("signer grant pubkey mismatch: requested %s but signer reported %s", pubkey, signerPubkey)
	}
	if err := bunker.Ping(ctx); err != nil {
		return nil, fmt.Errorf("%w: ping signer %s: %v", ErrSignerOffline, pubkey, err)
	}

	s.cacheSigner(pubkey, bunker)
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
	defer s.mu.Unlock()
	s.pool[pubkey] = signer
}

func (s *Service) evictSigner(pubkey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pool, pubkey)
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
		// go-nostr treats a scheme-less value as NIP-05. There is no pubkey or
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
	if !nostr.IsValidPublicKey(expectedPubkey) {
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

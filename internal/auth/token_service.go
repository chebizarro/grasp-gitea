// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// Bridge token scopes form a closed set. Scopes gate which proxied Gitea
// surfaces a token may reach; Gitea's own ACLs remain authoritative below
// that. There is no implicit write-includes-read rule.
const (
	ScopeGitRead      = "git:read"
	ScopeGitWrite     = "git:write"
	ScopePackagesRead  = "packages:read"
	ScopePackagesWrite = "packages:write"
	ScopeAPIRead      = "api:read"
	ScopeAPIWrite     = "api:write"
	ScopeLFSRead      = "lfs:read"
	ScopeLFSWrite     = "lfs:write"
)

const (
	// BridgeTokenPrefix marks every bridge-issued credential. The proxy edge
	// uses it to distinguish bridge tokens from ordinary Gitea credentials.
	BridgeTokenPrefix = "grasp_v1_"

	bridgeTokenSecretBytes = 32
	bridgeTokenEncodedLen  = 43 // unpadded base64url of 32 bytes

	// MaxActiveBridgeTokens bounds active tokens per pubkey.
	MaxActiveBridgeTokens = 50

	maxTokenNameLen = 80

	// tokenUsageTouchInterval throttles last_used_at writes.
	tokenUsageTouchInterval = 5 * time.Minute

	// patRetirementGrace delays retiring a user's hidden PAT after their last
	// bridge token stops being usable. Minting during the grace period cancels
	// retirement, because the user again has an active token.
	patRetirementGrace = 24 * time.Hour

	// patProvisionCleanupTimeout bounds detached persistence and rollback work
	// once Gitea may already have created a PAT.
	patProvisionCleanupTimeout = 30 * time.Second

	// patNamePrefix names hidden PATs "grasp-bridge-<userID>-<generation>" so
	// operators can identify and reconcile bridge-owned Gitea tokens.
	patNamePrefix = "grasp-bridge"

	tokenMaintenanceInterval = time.Hour
)

// giteaPATScopes is the minimum Gitea scope union for the currently enabled
// bridge features. Phase 1 enables Git smart HTTP only; write:repository
// covers read in Gitea's scope hierarchy. Never include admin scopes.
var giteaPATScopes = []string{"write:repository"}

// enabledTokenScopes lists the bridge scopes a deployment currently accepts.
var enabledTokenScopes = []string{ScopeGitRead, ScopeGitWrite}

var (
	// ErrInvalidTokenRequest reports malformed mint/rotate input (400).
	ErrInvalidTokenRequest = errors.New("invalid token request")
	// ErrTokenUnauthorized reports an unusable presented token (401).
	ErrTokenUnauthorized = errors.New("bridge token rejected")
	// ErrPATProvisioning reports downstream Gitea PAT lifecycle failure (502).
	ErrPATProvisioning = errors.New("gitea PAT provisioning failed")
	// ErrIdentityLinkRepair reports that a stored identity link no longer
	// matches Gitea (user deleted, or its login now belongs to a different
	// account). The bridge never adopts the replacement account (409).
	ErrIdentityLinkRepair = errors.New("identity link requires operator repair")
)

// TokenService owns the bridge-token lifecycle: NIP-98-authenticated minting,
// hidden per-user Gitea PAT provisioning, edge authentication, listing,
// revocation, and rotation.
type TokenService struct {
	store     *store.SQLiteStore
	identity  *IdentityService
	gitea     *gitea.Client
	cipher    *CredentialCipher
	logger    *slog.Logger
	relayURLs []string

	ttlDefault     time.Duration
	ttlMin         time.Duration
	ttlMax         time.Duration
	auditRetention time.Duration

	enabledScopes map[string]struct{}

	// userLocks serializes PAT ensure per Gitea user in this process.
	userLocks [64]sync.Mutex

	now func() time.Time
}

// NewTokenService builds the token service. It returns (nil, nil) when bridge
// tokens are disabled; a nil *TokenService is safe to query via Enabled.
func NewTokenService(cfg config.Config, st *store.SQLiteStore, identity *IdentityService, gc *gitea.Client, logger *slog.Logger) (*TokenService, error) {
	if !cfg.BridgeTokensEnabled {
		return nil, nil
	}
	if identity == nil || st == nil || gc == nil {
		return nil, fmt.Errorf("token service requires store, identity service, and gitea client")
	}
	if !gc.PATAdministrationEnabled() {
		return nil, fmt.Errorf("token service requires GITEA_ADMIN_USER for PAT administration")
	}
	cipher, err := NewCredentialCipher(cfg.CredentialKeys)
	if err != nil {
		return nil, fmt.Errorf("token service credential cipher: %w", err)
	}
	scopes := make(map[string]struct{}, len(enabledTokenScopes))
	for _, scope := range enabledTokenScopes {
		scopes[scope] = struct{}{}
	}
	return &TokenService{
		store:          st,
		identity:       identity,
		gitea:          gc,
		cipher:         cipher,
		logger:         logger.With("component", "auth.tokens"),
		relayURLs:      cfg.RelayURLs,
		ttlDefault:     cfg.TokenTTLDefault,
		ttlMin:         cfg.TokenTTLMin,
		ttlMax:         cfg.TokenTTLMax,
		auditRetention: cfg.AuthAuditRetention,
		enabledScopes:  scopes,
		now:            time.Now,
	}, nil
}

// Enabled reports whether the service is configured.
func (t *TokenService) Enabled() bool {
	return t != nil
}

// MintRequest is the mint/rotate input.
type MintRequest struct {
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// MintResult carries the one-time plaintext token.
type MintResult struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenMetadata is the plaintext-free listing shape.
type TokenMetadata struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Suffix     string    `json:"suffix"`
	Scopes     []string  `json:"scopes"`
	State      string    `json:"state"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

// TokenPrincipal identifies an authenticated bridge-token presenter. Npub and
// GiteaUser are the only usernames the proxy may accept alongside the token
// in HTTP Basic; a mismatch must be rejected rather than ignored.
type TokenPrincipal struct {
	TokenID     string
	Pubkey      string
	Npub        string
	GiteaUserID int64
	GiteaUser   string
	Scopes      []string
}

// PermitsUsername reports whether an incoming Basic username identifies this
// principal. Comparison is case-insensitive for the Gitea login (Gitea logins
// are case-insensitive) and exact for the canonical npub.
func (p TokenPrincipal) PermitsUsername(username string) bool {
	if username == "" {
		return false
	}
	if username == p.Npub {
		return true
	}
	return p.GiteaUser != "" && strings.EqualFold(username, p.GiteaUser)
}

// HasScope reports whether the principal holds an exact scope.
func (p TokenPrincipal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Mint provisions the caller's Gitea identity and hidden PAT if needed, then
// issues a new bridge token. eventID is the consumed NIP-98 proof id, kept
// for audit.
func (t *TokenService) Mint(ctx context.Context, pubkey, eventID string, req MintRequest) (MintResult, error) {
	name, scopes, ttl, err := t.validateRequest(req)
	if err != nil {
		return MintResult{}, err
	}

	identity, err := t.identity.ResolveOrCreate(ctx, pubkey, t.relayURLs)
	if err != nil {
		return MintResult{}, fmt.Errorf("resolve identity: %w", err)
	}

	if err := t.verifyIdentityLink(ctx, identity); err != nil {
		return MintResult{}, err
	}
	if err := t.ensureActivePAT(ctx, identity.GiteaUserID, identity.GiteaUser); err != nil {
		return MintResult{}, err
	}

	record, plaintext, err := t.newTokenRecord(identity.Pubkey, identity.GiteaUserID, name, scopes, ttl, eventID)
	if err != nil {
		return MintResult{}, err
	}
	if err := t.store.InsertBridgeToken(ctx, record, MaxActiveBridgeTokens); err != nil {
		return MintResult{}, err
	}

	metrics.IncBridgeTokensMinted()
	t.audit(ctx, store.AuthAuditEvent{
		EventType: "token_mint", Pubkey: pubkey, TokenID: record.ID,
		GiteaUserID: identity.GiteaUserID, Outcome: "success", RequestID: eventID,
	})
	t.logger.Info("bridge token minted", "token_id", record.ID, "pubkey", pubkey, "scopes", scopes, "expires_at", record.ExpiresAt)

	return MintResult{
		ID: record.ID, Token: plaintext, Name: name, Scopes: scopes,
		IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt,
	}, nil
}

// Authenticate resolves a presented plaintext bridge token to its principal.
// Every failure returns ErrTokenUnauthorized without distinguishing unknown,
// revoked, and expired tokens to callers.
func (t *TokenService) Authenticate(ctx context.Context, plaintext string) (TokenPrincipal, error) {
	if !ValidBridgeTokenFormat(plaintext) {
		metrics.IncBridgeTokenAuthFailures()
		return TokenPrincipal{}, ErrTokenUnauthorized
	}
	hash := sha256.Sum256([]byte(plaintext))
	record, err := t.store.GetBridgeTokenByHash(ctx, hash[:])
	if err != nil {
		metrics.IncBridgeTokenAuthFailures()
		if errors.Is(err, store.ErrBridgeTokenNotFound) {
			return TokenPrincipal{}, ErrTokenUnauthorized
		}
		return TokenPrincipal{}, fmt.Errorf("token lookup: %w", err)
	}
	now := t.now().UTC()
	if record.State(now) != store.BridgeTokenStateActive {
		metrics.IncBridgeTokenAuthFailures()
		return TokenPrincipal{}, ErrTokenUnauthorized
	}

	if record.LastUsedAt.IsZero() || now.Sub(record.LastUsedAt) >= tokenUsageTouchInterval {
		// The cutoff is re-evaluated in SQL so concurrent requests that all
		// read the same stale timestamp still yield one write.
		if err := t.store.TouchBridgeTokenUsage(ctx, record.ID, now, now.Add(-tokenUsageTouchInterval)); err != nil {
			t.logger.Warn("bridge token usage update failed", "token_id", record.ID, "error", err)
		}
	}

	principal := TokenPrincipal{
		TokenID:     record.ID,
		Pubkey:      record.Pubkey,
		GiteaUserID: record.GiteaUserID,
		Scopes:      record.Scopes,
	}
	if pk, err := nostr.PubKeyFromHex(record.Pubkey); err == nil {
		principal.Npub = nip19.EncodeNpub(pk)
	}
	if link, err := t.store.GetIdentityLinkByPubkey(ctx, record.Pubkey); err == nil {
		// A relinked Gitea account invalidates tokens bound to the old user.
		if link.GiteaUserID != record.GiteaUserID {
			metrics.IncBridgeTokenAuthFailures()
			return TokenPrincipal{}, ErrTokenUnauthorized
		}
		principal.GiteaUser = link.GiteaUser
	} else if !errors.Is(err, sql.ErrNoRows) {
		return TokenPrincipal{}, fmt.Errorf("identity link lookup: %w", err)
	} else {
		metrics.IncBridgeTokenAuthFailures()
		return TokenPrincipal{}, ErrTokenUnauthorized
	}
	return principal, nil
}

// DownstreamPAT decrypts the active hidden Gitea PAT for a user. The proxy
// injects it as Basic <login>:<pat> toward Gitea. The plaintext must never be
// logged or persisted.
func (t *TokenService) DownstreamPAT(ctx context.Context, giteaUserID int64) (login, pat string, err error) {
	cred, err := t.store.GetActivePATCredential(ctx, giteaUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("%w: no active credential for user %d", ErrPATProvisioning, giteaUserID)
		}
		return "", "", err
	}
	plaintext, err := t.cipher.Open(cred.Ciphertext, cred.KeyID,
		PATCredentialAAD(cred.GiteaUserID, cred.Generation, cred.PATName, cred.KeyID))
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrPATProvisioning, err)
	}
	if t.cipher.NeedsReencrypt(cred.KeyID) {
		t.reseal(ctx, cred, plaintext)
	}
	return cred.GiteaUser, string(plaintext), nil
}

// reseal lazily re-encrypts a PAT under the active key after a successful
// decryption, so retired keys can eventually be removed from the ring.
// Failure is non-fatal: the caller already holds a usable credential.
func (t *TokenService) reseal(ctx context.Context, cred store.GiteaPATCredential, plaintext []byte) {
	ciphertext, keyID, err := t.cipher.Seal(plaintext,
		PATCredentialAAD(cred.GiteaUserID, cred.Generation, cred.PATName, t.cipher.ActiveKeyID()))
	if err != nil {
		t.logger.Warn("PAT reseal failed", "gitea_user_id", cred.GiteaUserID, "error", err)
		return
	}
	if err := t.store.ResealPATCredential(ctx, cred.GiteaUserID, cred.Generation, cred.Ciphertext, ciphertext, keyID); err != nil {
		t.logger.Warn("PAT reseal persist failed", "gitea_user_id", cred.GiteaUserID, "error", err)
		return
	}
	t.logger.Info("PAT re-encrypted under active credential key",
		"gitea_user_id", cred.GiteaUserID, "generation", cred.Generation, "key_id", keyID)
}

// List returns plaintext-free token metadata for a pubkey.
func (t *TokenService) List(ctx context.Context, pubkey string, limit, offset int) ([]TokenMetadata, error) {
	records, err := t.store.ListBridgeTokens(ctx, pubkey, limit, offset)
	if err != nil {
		return nil, err
	}
	now := t.now().UTC()
	out := make([]TokenMetadata, 0, len(records))
	for _, record := range records {
		out = append(out, TokenMetadata{
			ID: record.ID, Name: record.Name, Suffix: record.TokenSuffix,
			Scopes: record.Scopes, State: record.State(now),
			IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt, LastUsedAt: record.LastUsedAt,
		})
	}
	return out, nil
}

// Revoke marks an owned token revoked.
func (t *TokenService) Revoke(ctx context.Context, pubkey, tokenID string) error {
	if err := t.store.RevokeBridgeToken(ctx, pubkey, tokenID, t.now().UTC()); err != nil {
		return err
	}
	metrics.IncBridgeTokensRevoked()
	t.audit(ctx, store.AuthAuditEvent{
		EventType: "token_revoke", Pubkey: pubkey, TokenID: tokenID, Outcome: "success",
	})
	return nil
}

// Rotate atomically revokes an owned active token and issues a replacement
// with freshly validated name/scopes/TTL. The subject is pinned by the store.
func (t *TokenService) Rotate(ctx context.Context, pubkey, tokenID, eventID string, req MintRequest) (MintResult, error) {
	name, scopes, ttl, err := t.validateRequest(req)
	if err != nil {
		return MintResult{}, err
	}
	record, plaintext, err := t.newTokenRecord(pubkey, 0, name, scopes, ttl, eventID)
	if err != nil {
		return MintResult{}, err
	}
	if err := t.store.RotateBridgeToken(ctx, pubkey, tokenID, record, t.now().UTC()); err != nil {
		return MintResult{}, err
	}
	metrics.IncBridgeTokensRotated()
	t.audit(ctx, store.AuthAuditEvent{
		EventType: "token_rotate", Pubkey: pubkey, TokenID: record.ID,
		Outcome: "success", RequestID: eventID, Detail: "replaced " + tokenID,
	})
	return MintResult{
		ID: record.ID, Token: plaintext, Name: name, Scopes: scopes,
		IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt,
	}, nil
}

// RunMaintenance periodically clears expired replay claims and enforces audit
// retention until the context is cancelled.
func (t *TokenService) RunMaintenance(ctx context.Context) {
	ticker := time.NewTicker(tokenMaintenanceInterval)
	defer ticker.Stop()
	for {
		t.maintain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *TokenService) maintain(ctx context.Context) {
	now := t.now().UTC()
	t.retireIdlePATs(ctx)
	if n, err := t.store.CleanupExpiredReplayClaims(ctx, now); err != nil {
		t.logger.Warn("replay claim cleanup failed", "error", err)
	} else if n > 0 {
		t.logger.Info("cleaned up expired NIP-98 replay claims", "count", n)
	}
	if n, err := t.store.CleanupAuthAuditEvents(ctx, now.Add(-t.auditRetention)); err != nil {
		t.logger.Warn("auth audit retention failed", "error", err)
	} else if n > 0 {
		t.logger.Info("pruned auth audit events", "count", n)
	}
}

// EnabledScopes returns the deployment's accepted bridge scopes, sorted.
func (t *TokenService) EnabledScopes() []string {
	out := make([]string, 0, len(t.enabledScopes))
	for scope := range t.enabledScopes {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

// ValidBridgeTokenFormat checks prefix, length, and charset before any
// database access.
func ValidBridgeTokenFormat(token string) bool {
	if len(token) != len(BridgeTokenPrefix)+bridgeTokenEncodedLen {
		return false
	}
	if !strings.HasPrefix(token, BridgeTokenPrefix) {
		return false
	}
	secret := token[len(BridgeTokenPrefix):]
	for _, r := range secret {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// HasBridgeTokenPrefix reports whether a credential claims to be a bridge
// token. Prefixed-but-invalid credentials must fail locally, never fall
// through to Gitea.
func HasBridgeTokenPrefix(credential string) bool {
	return strings.HasPrefix(credential, BridgeTokenPrefix)
}

func (t *TokenService) validateRequest(req MintRequest) (name string, scopes []string, ttl time.Duration, err error) {
	name = strings.TrimSpace(req.Name)
	if name == "" || len(name) > maxTokenNameLen {
		return "", nil, 0, fmt.Errorf("%w: name must be 1-%d characters", ErrInvalidTokenRequest, maxTokenNameLen)
	}

	requested := req.Scopes
	if len(requested) == 0 {
		requested = []string{ScopeGitRead}
	}
	seen := map[string]struct{}{}
	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if _, ok := t.enabledScopes[scope]; !ok {
			return "", nil, 0, fmt.Errorf("%w: scope %q is not enabled", ErrInvalidTokenRequest, scope)
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)

	ttl = t.ttlDefault
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < t.ttlMin || ttl > t.ttlMax {
			return "", nil, 0, fmt.Errorf("%w: ttl_seconds must be within [%d, %d]",
				ErrInvalidTokenRequest, int64(t.ttlMin.Seconds()), int64(t.ttlMax.Seconds()))
		}
	}
	return name, scopes, ttl, nil
}

func (t *TokenService) newTokenRecord(pubkey string, giteaUserID int64, name string, scopes []string, ttl time.Duration, eventID string) (store.BridgeToken, string, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return store.BridgeToken{}, "", fmt.Errorf("token id: %w", err)
	}
	secret := make([]byte, bridgeTokenSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return store.BridgeToken{}, "", fmt.Errorf("token secret: %w", err)
	}
	plaintext := BridgeTokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(plaintext))
	now := t.now().UTC()

	return store.BridgeToken{
		ID:             hex.EncodeToString(idBytes),
		TokenHash:      hash[:],
		TokenSuffix:    plaintext[len(plaintext)-6:],
		Pubkey:         pubkey,
		GiteaUserID:    giteaUserID,
		Name:           name,
		Scopes:         scopes,
		IssuedAt:       now,
		ExpiresAt:      now.Add(ttl),
		CreatedEventID: eventID,
	}, plaintext, nil
}

// verifyIdentityLink confirms the stored link still points at the same Gitea
// account. If the user was deleted, or its login now belongs to a different
// account, the bridge must never mint a PAT against the replacement: it
// orphans the credentials, revokes that user's tokens, and demands repair.
func (t *TokenService) verifyIdentityLink(ctx context.Context, identity ResolvedIdentity) error {
	if identity.Created {
		// Just created by this call; the ID is authoritative.
		return nil
	}
	user, err := t.gitea.GetUser(ctx, identity.GiteaUser)
	if err != nil {
		if gitea.IsNotFound(err) {
			t.quarantineIdentity(ctx, identity, "gitea user no longer exists")
			return fmt.Errorf("%w: gitea user %q no longer exists", ErrIdentityLinkRepair, identity.GiteaUser)
		}
		return fmt.Errorf("verify gitea user: %w", err)
	}
	if user.ID != identity.GiteaUserID {
		t.quarantineIdentity(ctx, identity, "gitea user id changed")
		return fmt.Errorf("%w: gitea login %q now maps to user %d, not %d",
			ErrIdentityLinkRepair, identity.GiteaUser, user.ID, identity.GiteaUserID)
	}
	return nil
}

func (t *TokenService) quarantineIdentity(ctx context.Context, identity ResolvedIdentity, reason string) {
	t.logger.Error("identity link no longer matches Gitea; quarantining bridge credentials",
		"pubkey", identity.Pubkey, "gitea_user", identity.GiteaUser, "gitea_user_id", identity.GiteaUserID, "reason", reason)

	if cred, err := t.store.GetActivePATCredential(ctx, identity.GiteaUserID); err == nil {
		if stateErr := t.store.SetPATCredentialState(ctx, cred.GiteaUserID, cred.Generation, store.PATStateOrphaned, reason); stateErr != nil {
			t.logger.Error("failed to orphan PAT credential", "gitea_user_id", identity.GiteaUserID, "error", stateErr)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.logger.Error("failed to load PAT credential for quarantine", "gitea_user_id", identity.GiteaUserID, "error", err)
	}

	if n, err := t.store.RevokeBridgeTokensForGiteaUser(ctx, identity.GiteaUserID, t.now().UTC()); err != nil {
		t.logger.Error("failed to revoke tokens for quarantined identity", "gitea_user_id", identity.GiteaUserID, "error", err)
	} else if n > 0 {
		t.logger.Warn("revoked bridge tokens for quarantined identity", "gitea_user_id", identity.GiteaUserID, "count", n)
	}

	t.audit(ctx, store.AuthAuditEvent{
		EventType: "identity_quarantine", Pubkey: identity.Pubkey,
		GiteaUserID: identity.GiteaUserID, Outcome: "quarantined", Detail: reason,
	})
}

// ensureActivePAT guarantees one active encrypted Gitea PAT for the user,
// following reserve -> create -> encrypt -> finalize -> activate. A PAT
// created in Gitea but not durably persisted is deleted immediately; if that
// deletion also fails the row is marked error for operator reconciliation.
// Once creation may have happened, persistence and rollback run on a detached
// context so a disconnecting client cannot strand a live Gitea PAT.
func (t *TokenService) ensureActivePAT(ctx context.Context, giteaUserID int64, giteaUser string) error {
	lock := &t.userLocks[uint64(giteaUserID)%uint64(len(t.userLocks))]
	lock.Lock()
	defer lock.Unlock()

	if _, err := t.store.GetActivePATCredential(ctx, giteaUserID); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	now := t.now().UTC()
	generation, patName, err := t.store.ReservePATCredential(ctx, giteaUserID, giteaUser, patNamePrefix, giteaPATScopes, now)
	if err != nil {
		return err
	}

	created, createErr := t.gitea.CreateUserAccessToken(ctx, giteaUser, patName, giteaPATScopes)

	// Past this point Gitea may hold a PAT even on error, so all persistence
	// and rollback use a detached context: cancelling the caller's request
	// must never strand a live credential.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), patProvisionCleanupTimeout)
	defer cancel()

	if createErr != nil {
		// The failure is ambiguous: Gitea may have committed the PAT before the
		// error (timeout, cancellation, truncated response). The reserved name
		// is unique, so deleting by name reconciles either outcome.
		t.reconcileAmbiguousPAT(cleanupCtx, giteaUser, patName)
		if stateErr := t.store.SetPATCredentialState(cleanupCtx, giteaUserID, generation, store.PATStateError, createErr.Error()); stateErr != nil {
			t.logger.Error("failed to record PAT provisioning error", "gitea_user_id", giteaUserID, "generation", generation, "error", stateErr)
		}
		metrics.IncPATProvisionFailures()
		t.audit(cleanupCtx, store.AuthAuditEvent{
			EventType: "pat_provision", GiteaUserID: giteaUserID, Outcome: "gitea_error",
		})
		return fmt.Errorf("%w: %v", ErrPATProvisioning, createErr)
	}

	// The client already enforces these, but the proxy must never activate a
	// credential it cannot later delete.
	err = nil
	if created.ID <= 0 {
		err = fmt.Errorf("gitea returned no usable token id")
	} else if created.Name != patName {
		err = fmt.Errorf("gitea returned token name %q, want %q", created.Name, patName)
	}

	if err == nil {
		var ciphertext []byte
		var keyID string
		ciphertext, keyID, err = t.cipher.Seal([]byte(created.Token),
			PATCredentialAAD(giteaUserID, generation, patName, t.cipher.ActiveKeyID()))
		if err == nil {
			err = t.store.FinalizePATCredential(cleanupCtx, giteaUserID, generation, created.ID, ciphertext, keyID)
		}
	}
	if err == nil {
		err = t.store.ActivatePATCredential(cleanupCtx, giteaUserID, generation, now)
	}
	if err != nil {
		// Never abandon an untracked Gitea PAT: delete it before reporting.
		ref := patName
		if created.ID > 0 {
			ref = fmt.Sprintf("%d", created.ID)
		}
		deleteErr := t.gitea.DeleteUserAccessToken(cleanupCtx, giteaUser, ref)
		if deleteErr != nil && !gitea.IsNotFound(deleteErr) {
			t.logger.Error("orphaned Gitea PAT requires operator cleanup",
				"gitea_user", giteaUser, "pat_name", patName, "gitea_token_id", created.ID, "error", deleteErr)
			if stateErr := t.store.SetPATCredentialState(cleanupCtx, giteaUserID, generation, store.PATStateError,
				"persist failed and Gitea deletion failed: "+deleteErr.Error()); stateErr != nil {
				t.logger.Error("failed to record orphaned PAT state", "error", stateErr)
			}
		} else {
			if stateErr := t.store.SetPATCredentialState(cleanupCtx, giteaUserID, generation, store.PATStateError,
				"persist failed; Gitea PAT deleted: "+err.Error()); stateErr != nil {
				t.logger.Error("failed to record PAT rollback state", "error", stateErr)
			}
		}
		metrics.IncPATProvisionFailures()
		return fmt.Errorf("%w: %v", ErrPATProvisioning, err)
	}

	metrics.IncPATCredentialsProvisioned()
	t.audit(ctx, store.AuthAuditEvent{
		EventType: "pat_provision", GiteaUserID: giteaUserID, Outcome: "success",
	})
	t.logger.Info("hidden Gitea PAT provisioned", "gitea_user", giteaUser, "generation", generation)
	return nil
}

// reconcileAmbiguousPAT deletes a possibly-created PAT by its reserved unique
// name. A 404 means Gitea never committed it, which is equally fine.
func (t *TokenService) reconcileAmbiguousPAT(ctx context.Context, giteaUser, patName string) {
	if err := t.gitea.DeleteUserAccessToken(ctx, giteaUser, patName); err != nil && !gitea.IsNotFound(err) {
		t.logger.Error("could not reconcile possibly-created Gitea PAT; operator cleanup may be required",
			"gitea_user", giteaUser, "pat_name", patName, "error", err)
	}
}

// retireIdlePATs sweeps users whose bridge tokens have all been revoked or
// expired for longer than the grace period, moving their hidden PAT into the
// pending-deletion queue, then deletes queued PATs from Gitea.
func (t *TokenService) retireIdlePATs(ctx context.Context) {
	now := t.now().UTC()
	idle, err := t.store.ListGiteaUsersWithoutActiveTokens(ctx, now, 200)
	if err != nil {
		t.logger.Warn("idle PAT scan failed", "error", err)
	} else {
		for giteaUserID, lastUsable := range idle {
			// A user who never held a token still gets the full grace period
			// measured from PAT creation, which lastUsable=zero cannot express;
			// skip rather than retire a just-provisioned credential.
			if lastUsable.IsZero() || now.Sub(lastUsable) < patRetirementGrace {
				continue
			}
			n, err := t.store.RetireActivePATCredential(ctx, giteaUserID)
			if err != nil {
				t.logger.Warn("PAT retirement failed", "gitea_user_id", giteaUserID, "error", err)
				continue
			}
			if n > 0 {
				t.logger.Info("queued idle hidden PAT for deletion", "gitea_user_id", giteaUserID)
			}
		}
	}

	pending, err := t.store.ListPATCredentialsPendingDeletion(ctx, 200)
	if err != nil {
		t.logger.Warn("pending PAT deletion scan failed", "error", err)
		return
	}
	for _, cred := range pending {
		ref := cred.PATName
		if cred.GiteaTokenID > 0 {
			ref = fmt.Sprintf("%d", cred.GiteaTokenID)
		}
		err := t.gitea.DeleteUserAccessToken(ctx, cred.GiteaUser, ref)
		if err != nil && !gitea.IsNotFound(err) {
			if recErr := t.store.RecordPATDeleteFailure(ctx, cred.GiteaUserID, cred.Generation, err.Error()); recErr != nil {
				t.logger.Warn("could not record PAT delete failure", "gitea_user_id", cred.GiteaUserID, "error", recErr)
			}
			continue
		}
		// A 404 means Gitea no longer holds it: cleanup is complete.
		if err := t.store.MarkPATCredentialRetired(ctx, cred.GiteaUserID, cred.Generation, t.now().UTC()); err != nil {
			t.logger.Warn("could not mark PAT retired", "gitea_user_id", cred.GiteaUserID, "error", err)
			continue
		}
		metrics.IncPATCredentialsRetired()
		t.logger.Info("hidden Gitea PAT retired", "gitea_user", cred.GiteaUser, "generation", cred.Generation)
	}
}

func (t *TokenService) audit(ctx context.Context, ev store.AuthAuditEvent) {
	ev.OccurredAt = t.now().UTC()
	if err := t.store.InsertAuthAuditEvent(ctx, ev); err != nil {
		t.logger.Warn("auth audit insert failed", "event_type", ev.EventType, "error", err)
	}
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// IdentityService resolves a verified Nostr pubkey to a Gitea user,
// creating the user and persisting the identity link if needed.
type IdentityService struct {
	store       *store.SQLiteStore
	giteaClient *gitea.Client
	orgResolver OrgNameResolver
	logger      *slog.Logger
}

// OrgNameResolver resolves a pubkey to a human-readable org/user name.
// The existing nip05resolve.Resolver satisfies this interface.
type OrgNameResolver interface {
	ResolveOrgName(ctx context.Context, pubkey string, relayURLs []string) string
}

// NewIdentityService creates a new identity resolution service.
func NewIdentityService(
	st *store.SQLiteStore,
	gc *gitea.Client,
	orgResolver OrgNameResolver,
	logger *slog.Logger,
) *IdentityService {
	return &IdentityService{
		store:       st,
		giteaClient: gc,
		orgResolver: orgResolver,
		logger:      logger.With("component", "auth.identity"),
	}
}

// ResolvedIdentity is the result of resolving a pubkey to a Gitea user.
type ResolvedIdentity struct {
	Pubkey      string `json:"pubkey"`
	Npub        string `json:"npub"`
	GiteaUserID int64  `json:"gitea_user_id"`
	GiteaUser   string `json:"gitea_user"`
	NIP05       string `json:"nip05,omitempty"`
	Created     bool   `json:"created"` // true if the Gitea user was just auto-created
}

// ResolveOrCreate looks up the identity link for a pubkey. If no link exists,
// it auto-creates a Gitea user using the NIP-05 naming policy and persists
// the link. On repeat login, it returns the existing link and updates
// last_login_at.
func (s *IdentityService) ResolveOrCreate(ctx context.Context, pubkey string, relayURLs []string) (ResolvedIdentity, error) {
	// Encode npub for storage.
	npub, err := nip19.EncodePublicKey(pubkey)
	if err != nil {
		return ResolvedIdentity{}, fmt.Errorf("encode npub: %w", err)
	}

	// Check for existing link.
	existing, err := s.store.GetIdentityLinkByPubkey(ctx, pubkey)
	if err == nil {
		// Existing user — update last login and return.
		if loginErr := s.store.UpdateLastLogin(ctx, pubkey); loginErr != nil {
			s.logger.Warn("failed to update last_login_at", "pubkey", pubkey, "error", loginErr)
		}
		s.logger.Info("returning login resolved to existing user", "pubkey", pubkey, "gitea_user", existing.GiteaUser)
		return ResolvedIdentity{
			Pubkey:      pubkey,
			Npub:        npub,
			GiteaUserID: existing.GiteaUserID,
			GiteaUser:   existing.GiteaUser,
			NIP05:       existing.NIP05,
			Created:     false,
		}, nil
	}
	if err != sql.ErrNoRows {
		return ResolvedIdentity{}, fmt.Errorf("lookup identity link: %w", err)
	}

	// No existing link — resolve name and auto-create.
	username := s.resolveUsername(ctx, pubkey, relayURLs)
	nip05Addr := ""

	// Check if this username came from NIP-05 resolution (not hex fallback).
	if s.orgResolver != nil {
		resolved := s.orgResolver.ResolveOrgName(ctx, pubkey, relayURLs)
		if resolved == username && !isHexPrefix(resolved) {
			nip05Addr = resolved
		}
	}

	// Generate a random password — the user will authenticate via Nostr,
	// never via password.
	password, err := generateRandomPassword()
	if err != nil {
		return ResolvedIdentity{}, fmt.Errorf("generate password: %w", err)
	}

	email := username + "@nostr.local"

	// Attempt to create the Gitea user.
	user, err := s.giteaClient.CreateUser(ctx, username, email, password)
	if err != nil {
		// If the username already exists (conflict), try to look it up.
		if !gitea.IsNotFound(err) {
			// It might be a 409/422 for existing user. Try GetUser.
			existingUser, getErr := s.giteaClient.GetUser(ctx, username)
			if getErr != nil {
				return ResolvedIdentity{}, fmt.Errorf("create user %q failed (%w) and lookup also failed: %v", username, err, getErr)
			}
			user = existingUser
		} else {
			return ResolvedIdentity{}, fmt.Errorf("create user %q: %w", username, err)
		}
	}

	// Persist the identity link.
	link := store.NostrIdentityLink{
		Pubkey:      pubkey,
		Npub:        npub,
		GiteaUserID: user.ID,
		GiteaUser:   user.Login,
		NIP05:       nip05Addr,
	}
	if err := s.store.UpsertIdentityLink(ctx, link); err != nil {
		return ResolvedIdentity{}, fmt.Errorf("persist identity link: %w", err)
	}

	metrics.IncAuthUserProvisioned()
	s.logger.Info("auto-created Gitea user for Nostr identity",
		"pubkey", pubkey, "gitea_user", user.Login, "gitea_user_id", user.ID)

	return ResolvedIdentity{
		Pubkey:      pubkey,
		Npub:        npub,
		GiteaUserID: user.ID,
		GiteaUser:   user.Login,
		NIP05:       nip05Addr,
		Created:     true,
	}, nil
}

// resolveUsername determines the Gitea username for a pubkey using the same
// naming policy as org provisioning: NIP-05 local-part if available, else
// 39-char hex prefix fallback.
func (s *IdentityService) resolveUsername(ctx context.Context, pubkey string, relayURLs []string) string {
	if s.orgResolver != nil {
		name := s.orgResolver.ResolveOrgName(ctx, pubkey, relayURLs)
		if name != "" {
			return name
		}
	}
	// Fallback: first 39 chars of hex pubkey (matches Gitea's 40-char limit).
	if len(pubkey) > 39 {
		return pubkey[:39]
	}
	return pubkey
}

// isHexPrefix returns true if the string looks like a raw hex pubkey prefix.
func isHexPrefix(s string) bool {
	if len(s) == 0 {
		return false
	}
	s = strings.ToLower(s)
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// generateRandomPassword returns a 32-byte hex-encoded random password.
func generateRandomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package auth implements Nostr-based authentication for the grasp-bridge.
// It provides challenge/verify flows for NIP-98 login proofs and manages
// the lifecycle of auth challenges (nonce issuance, validation, consumption).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// NonceLength is the byte length of generated challenge nonces (32 bytes = 64 hex chars).
const NonceLength = 32

// ChallengeRequest is the input for issuing a new login challenge.
type ChallengeRequest struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// ChallengeResponse is returned when a challenge is successfully issued.
type ChallengeResponse struct {
	Nonce     string    `json:"nonce"`
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Service manages auth challenge lifecycle and NIP-98 verification.
type Service struct {
	store        *store.SQLiteStore
	publicURL    string
	challengeTTL time.Duration
	logger       *slog.Logger
}

// NewService creates a new auth service. Returns nil if auth is disabled in config.
func NewService(cfg config.Config, st *store.SQLiteStore, logger *slog.Logger) *Service {
	if !cfg.AuthEnabled {
		return nil
	}
	return &Service{
		store:        st,
		publicURL:    cfg.BridgePublicURL,
		challengeTTL: cfg.ChallengeTTL,
		logger:       logger.With("component", "auth"),
	}
}

// IssueChallenge creates a new login challenge with a cryptographically random nonce.
func (s *Service) IssueChallenge(ctx context.Context, req ChallengeRequest) (ChallengeResponse, error) {
	nonce, err := generateNonce()
	if err != nil {
		return ChallengeResponse{}, fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now().UTC()
	verifyURL := s.publicURL + "/auth/nip07/verify"

	challenge := store.AuthChallenge{
		Nonce:       nonce,
		URL:         verifyURL,
		Method:      "POST",
		RedirectURI: req.RedirectURI,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.challengeTTL),
	}

	if err := s.store.CreateChallenge(ctx, challenge); err != nil {
		return ChallengeResponse{}, fmt.Errorf("persist challenge: %w", err)
	}

	metrics.IncAuthChallengesIssued()
	s.logger.Info("challenge issued", "nonce", nonce, "expires_at", challenge.ExpiresAt)

	return ChallengeResponse{
		Nonce:     nonce,
		URL:       verifyURL,
		Method:    "POST",
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

// ValidateChallenge loads a challenge by nonce and checks that it is valid:
// not expired, not already consumed. It does NOT consume it — call
// ConsumeChallenge after full NIP-98 event verification succeeds.
func (s *Service) ValidateChallenge(ctx context.Context, nonce string) (store.AuthChallenge, error) {
	challenge, err := s.store.GetChallenge(ctx, nonce)
	if err != nil {
		return store.AuthChallenge{}, fmt.Errorf("load challenge: %w", err)
	}

	if challenge.Consumed {
		metrics.IncAuthReplayRejected()
		return store.AuthChallenge{}, fmt.Errorf("challenge already consumed (replay)")
	}

	if time.Now().UTC().After(challenge.ExpiresAt) {
		return store.AuthChallenge{}, fmt.Errorf("challenge expired at %s", challenge.ExpiresAt)
	}

	return challenge, nil
}

// ConsumeChallenge marks a validated challenge as consumed (single-use).
func (s *Service) ConsumeChallenge(ctx context.Context, nonce string) error {
	return s.store.ConsumeChallenge(ctx, nonce)
}

// CleanupExpired removes expired challenges from the store and returns the count.
func (s *Service) CleanupExpired(ctx context.Context) (int64, error) {
	n, err := s.store.DeleteExpiredChallenges(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.logger.Info("cleaned up expired challenges", "count", n)
	}
	return n, nil
}

// Enabled returns true if the auth service is initialized (non-nil).
func (s *Service) Enabled() bool {
	return s != nil
}

// generateNonce returns a cryptographically random hex string.
func generateNonce() (string, error) {
	b := make([]byte, NonceLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

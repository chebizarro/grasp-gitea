package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// Service manages NIP-07 login challenges.
type Service struct {
	store      *store.SQLiteStore
	nonceTTL   time.Duration
}

// NewService creates an auth service.
func NewService(st *store.SQLiteStore, nonceTTL time.Duration) *Service {
	return &Service{store: st, nonceTTL: nonceTTL}
}

// ChallengeResponse is the data returned to the browser to construct a NIP-98 event.
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	URL         string `json:"url"`          // the verify URL to sign
	Method      string `json:"method"`       // always "POST"
	ExpiresAt   int64  `json:"expires_at"`   // unix timestamp
	RedirectURI string `json:"redirect_uri"` // carried for NIP-46/55 flows
	OAuth2State string `json:"oauth2_state"` // carried for NIP-46/55 flows
}

// IssueChallenge creates a nonce and returns the browser sign-in payload.
// oauth2State and redirectURI come from the upstream OAuth2 authorize request.
// verifyURL is the full public URL of the /auth/nip07/verify endpoint.
func (s *Service) IssueChallenge(ctx context.Context, oauth2State, redirectURI, verifyURL string) (ChallengeResponse, error) {
	id, err := randomHex(16)
	if err != nil {
		return ChallengeResponse{}, fmt.Errorf("generate nonce: %w", err)
	}

	expiresAt := time.Now().Add(s.nonceTTL)

	if err := s.store.CreateChallenge(ctx, id, oauth2State, redirectURI, expiresAt); err != nil {
		return ChallengeResponse{}, fmt.Errorf("store challenge: %w", err)
	}

	return ChallengeResponse{
		ChallengeID: id,
		URL:         verifyURL,
		Method:      "POST",
		ExpiresAt:   expiresAt.Unix(),
		RedirectURI: redirectURI,
		OAuth2State: oauth2State,
	}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

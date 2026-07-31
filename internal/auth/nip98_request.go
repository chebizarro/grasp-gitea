// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"

	"github.com/sharegap/grasp-gitea/internal/metrics"
)

const (
	// maxNIP98HeaderBytes bounds the base64 Authorization payload so a hostile
	// header cannot force large decodes.
	maxNIP98HeaderBytes = 16 << 10

	// nip98ReplayClaimTTL is how long a consumed event id stays in the durable
	// replay ledger. It exceeds the verifier freshness window (60s skew both
	// directions) with margin, so an event always fails freshness before its
	// claim expires.
	nip98ReplayClaimTTL = 5 * time.Minute

	nip98AuthScheme = "Nostr "
)

var (
	// ErrNIP98Unauthorized covers every client-side verification failure:
	// missing/invalid header, bad signature, URL/method/payload mismatch,
	// stale event, or replay. Handlers map it to 401.
	ErrNIP98Unauthorized = errors.New("NIP-98 authorization rejected")

	// ErrNIP98StoreUnavailable reports that the durable replay ledger could
	// not be consulted. Verification fails closed; handlers map it to 503.
	ErrNIP98StoreUnavailable = errors.New("NIP-98 replay ledger unavailable")
)

// ParseNIP98Authorization decodes an "Authorization: Nostr <base64-event>"
// header into a NIP-98 event without verifying it.
func ParseNIP98Authorization(header string) (*nostr.Event, error) {
	header = strings.TrimSpace(header)
	if len(header) < len(nip98AuthScheme) || !strings.EqualFold(header[:len(nip98AuthScheme)], nip98AuthScheme) {
		return nil, fmt.Errorf("%w: missing Nostr authorization", ErrNIP98Unauthorized)
	}
	encoded := strings.TrimSpace(header[len(nip98AuthScheme):])
	if len(encoded) == 0 || len(encoded) > maxNIP98HeaderBytes {
		return nil, fmt.Errorf("%w: authorization payload size", ErrNIP98Unauthorized)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64", ErrNIP98Unauthorized)
	}
	var event nostr.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("%w: invalid event JSON", ErrNIP98Unauthorized)
	}
	return &event, nil
}

// CanonicalRequestTarget rebuilds the externally visible request URL from the
// configured public origin plus the escaped path and raw query. The Host
// header and forwarded headers are deliberately ignored: only nginx-fronted
// canonical origins are valid NIP-98 targets.
func (s *Service) CanonicalRequestTarget(r *http.Request) string {
	return s.publicURL + r.URL.RequestURI()
}

// VerifyNIP98WithPayload verifies a NIP-98 event including its payload tag
// against the exact raw request body bytes. It shares the fleet verifier;
// no local signature/URL/freshness semantics are introduced.
func (s *Service) VerifyNIP98WithPayload(event *nostr.Event, method, target string, payload []byte) (*sharednip98.Principal, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: event is required", ErrNIP98Unauthorized)
	}
	principal, err := s.nip98.VerifyEvent(event, method, target, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNIP98Unauthorized, err)
	}
	return principal, nil
}

// VerifyAndClaimNIP98 verifies an event (payload-aware) and then atomically
// claims its id in the durable replay ledger. The in-process verifier already
// rejects same-process replays; the durable claim extends that guarantee
// across restarts. A verified event whose claim (or downstream operation)
// fails stays consumed — callers must sign a fresh event.
func (s *Service) VerifyAndClaimNIP98(ctx context.Context, event *nostr.Event, method, target string, payload []byte) (*sharednip98.Principal, error) {
	principal, err := s.VerifyNIP98WithPayload(event, method, target, payload)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	targetHash := sha256.Sum256([]byte(strings.ToUpper(method) + "|" + target))
	claimed, err := s.store.ClaimNIP98Event(ctx, principal.EventID, principal.PubKey, strings.ToUpper(method),
		targetHash[:], now, now.Add(nip98ReplayClaimTTL))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNIP98StoreUnavailable, err)
	}
	if !claimed {
		metrics.IncAuthReplayRejected()
		return nil, fmt.Errorf("%w: event replayed", ErrNIP98Unauthorized)
	}
	return principal, nil
}

// AuthenticateNIP98Request authenticates one HTTP request from its
// Authorization header, canonical public target, and already-read body bytes.
// Callers must read the body with an appropriate bound before invoking this.
func (s *Service) AuthenticateNIP98Request(ctx context.Context, r *http.Request, body []byte) (*sharednip98.Principal, error) {
	event, err := ParseNIP98Authorization(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	return s.VerifyAndClaimNIP98(ctx, event, r.Method, s.CanonicalRequestTarget(r), body)
}

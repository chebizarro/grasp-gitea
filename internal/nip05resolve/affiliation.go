// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip05"
	"golang.org/x/net/idna"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

const (
	FailureConfirmedAbsent = "confirmed_absent"
	FailureIndeterminate   = "indeterminate"
)

// AffiliationVerification is a fresh, uncached NIP-05 verification result.
// It never reads or writes Resolver's naming cache.
type AffiliationVerification struct {
	CanonicalIdentifier string
	LocalPart           string
	Host                string
	Pubkey              string
	VerifiedAt          time.Time
	FailureClass        string
	FailureCode         string
	FailureDetail       string
}

func (v AffiliationVerification) Verified() bool {
	return v.FailureClass == "" && !v.VerifiedAt.IsZero()
}

// CanonicalizeIdentifier normalizes only the DNS host (lowercase IDNA ASCII),
// preserving the NIP-05 local part and exact subdomain boundary.
func CanonicalizeIdentifier(identifier string) (canonical, localPart, host string, err error) {
	identifier = strings.TrimSpace(identifier)
	at := strings.LastIndexByte(identifier, '@')
	if at <= 0 || at == len(identifier)-1 || strings.Contains(identifier[:at], "@") {
		return "", "", "", fmt.Errorf("invalid NIP-05 identifier")
	}
	localPart = identifier[:at]
	host, err = CanonicalizeHost(identifier[at+1:])
	if err != nil {
		return "", "", "", err
	}
	// Validate the normalized identifier with the protocol library after IDNA
	// conversion; its parser intentionally accepts DNS ASCII only.
	parsedLocal, parsedHost, err := nip05.ParseIdentifier(localPart + "@" + host)
	if err != nil || parsedLocal != localPart || !strings.EqualFold(parsedHost, host) {
		return "", "", "", fmt.Errorf("invalid NIP-05 identifier")
	}
	return localPart + "@" + host, localPart, host, nil
}

// CanonicalizeHost converts an exact DNS host to lowercase IDNA ASCII without
// collapsing subdomains to a registrable parent.
func CanonicalizeHost(rawHost string) (string, error) {
	rawHost = strings.TrimSuffix(strings.TrimSpace(rawHost), ".")
	host, err := idna.Lookup.ToASCII(rawHost)
	if err != nil {
		return "", fmt.Errorf("canonicalize NIP-05 host: %w", err)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || strings.ContainsAny(host, "/:@") {
		return "", fmt.Errorf("invalid NIP-05 host")
	}
	return host, nil
}

// VerifyIdentifierFresh verifies one explicit identifier through the guarded
// HTTP client. A successful HTTP 200 that omits the name or maps another key
// is confirmed absence; transport failures, malformed responses, and non-200
// responses are indeterminate and therefore must only make old evidence stale.
func VerifyIdentifierFresh(ctx context.Context, identifier, pubkey string) AffiliationVerification {
	checkedAt := time.Now().UTC()
	canonical, localPart, host, err := CanonicalizeIdentifier(identifier)
	result := AffiliationVerification{CanonicalIdentifier: canonical, LocalPart: localPart, Host: host, Pubkey: strings.ToLower(pubkey)}
	if err != nil {
		return failedVerification(result, FailureConfirmedAbsent, "invalid_identifier", err)
	}
	expected, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return failedVerification(result, FailureConfirmedAbsent, "invalid_pubkey", err)
	}

	u := url.URL{Scheme: "https", Host: host, Path: "/.well-known/nostr.json"}
	q := u.Query()
	q.Set("name", localPart)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return failedVerification(result, FailureIndeterminate, "request", err)
	}
	resp, err := nip05HTTPClient.Do(req)
	if err != nil {
		return failedVerification(result, FailureIndeterminate, "transport", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return failedVerification(result, FailureIndeterminate, fmt.Sprintf("http_%d", resp.StatusCode), fmt.Errorf("NIP-05 endpoint returned HTTP %d", resp.StatusCode))
	}

	const maxResponseSize = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return failedVerification(result, FailureIndeterminate, "response_read", err)
	}
	if len(raw) > maxResponseSize {
		return failedVerification(result, FailureIndeterminate, "response_too_large", fmt.Errorf("NIP-05 response exceeds %d-byte limit", maxResponseSize))
	}
	var response nip05.WellKnownResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return failedVerification(result, FailureIndeterminate, "invalid_response", err)
	}
	resolved, ok := response.Names[localPart]
	if !ok {
		return failedVerification(result, FailureConfirmedAbsent, "name_absent", fmt.Errorf("NIP-05 response has no entry for %q", localPart))
	}
	if resolved != expected {
		return failedVerification(result, FailureConfirmedAbsent, "pubkey_mismatch", fmt.Errorf("NIP-05 identifier resolves to a different pubkey"))
	}
	result.VerifiedAt = checkedAt
	return result
}

// VerifyAffiliationFresh obtains the newest valid signed kind:0 observed from
// the configured relays, then performs an uncached well-known verification.
func VerifyAffiliationFresh(ctx context.Context, pubkey string, relayURLs []string) AffiliationVerification {
	base := AffiliationVerification{Pubkey: strings.ToLower(pubkey)}
	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		return failedVerification(base, FailureConfirmedAbsent, "invalid_pubkey", err)
	}
	var newest *nostr.Event
	var lastErr error
	for _, relayURL := range relayURLs {
		ev, err := fetchProfileEvent(ctx, pk, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		if ev != nil && (newest == nil || ev.CreatedAt > newest.CreatedAt || (ev.CreatedAt == newest.CreatedAt && ev.ID.Hex() < newest.ID.Hex())) {
			copy := *ev
			newest = &copy
		}
	}
	if newest == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("no valid kind:0 profile found")
		}
		return failedVerification(base, FailureIndeterminate, "profile_unavailable", lastErr)
	}
	var profile struct {
		NIP05 string `json:"nip05"`
	}
	if err := json.Unmarshal([]byte(newest.Content), &profile); err != nil {
		return failedVerification(base, FailureConfirmedAbsent, "invalid_profile", err)
	}
	if strings.TrimSpace(profile.NIP05) == "" {
		return failedVerification(base, FailureConfirmedAbsent, "identifier_absent", fmt.Errorf("signed profile has no NIP-05 identifier"))
	}
	return VerifyIdentifierFresh(ctx, profile.NIP05, pubkey)
}

func fetchProfileEvent(ctx context.Context, pubkey nostr.PubKey, relayURL string) (*nostr.Event, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	relay, err := nostr.RelayConnect(fetchCtx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return nil, fmt.Errorf("connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()
	sub, err := relay.Subscribe(fetchCtx, nostr.Filter{Authors: []nostr.PubKey{pubkey}, Kinds: []nostr.Kind{0}, Limit: 1}, nostr.SubscriptionOptions{})
	if err != nil {
		return nil, fmt.Errorf("subscribe for kind 0 on %s: %w", relayURL, err)
	}
	defer sub.Unsub()
	select {
	case ev := <-sub.Events:
		if ev.Kind != 0 || ev.PubKey != pubkey {
			return nil, fmt.Errorf("relay %s returned an unexpected kind:0 event", relayURL)
		}
		if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
			return nil, fmt.Errorf("invalid kind:0 event from %s: %w", relayURL, err)
		}
		return &ev, nil
	case <-sub.EndOfStoredEvents:
		return nil, nil
	case <-fetchCtx.Done():
		return nil, fmt.Errorf("kind:0 lookup on %s: %w", relayURL, fetchCtx.Err())
	}
}

func failedVerification(v AffiliationVerification, class, code string, err error) AffiliationVerification {
	v.FailureClass = class
	v.FailureCode = code
	if err != nil {
		v.FailureDetail = err.Error()
	}
	return v
}

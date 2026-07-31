// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
)

// ProxyNIP98Verifier authenticates a direct per-request NIP-98 proof on a
// proxied Gitea endpoint and resolves it to the signer's bridge principal.
//
// A signature is stronger evidence than any bearer token, so the resulting
// principal carries every enabled bridge scope. It is still subject to the
// proxy's surface gating: surfaces without an adapter (and /api/v1/admin)
// refuse it like any other bridge credential.
type ProxyNIP98Verifier struct {
	auth   *Service
	tokens *TokenService
}

// NewProxyNIP98Verifier wires the NIP-98 service (canonical-URL and payload
// verification plus the durable replay ledger) to the token service's
// identity resolution.
func NewProxyNIP98Verifier(authSvc *Service, tokens *TokenService) *ProxyNIP98Verifier {
	return &ProxyNIP98Verifier{auth: authSvc, tokens: tokens}
}

// VerifyProxyNIP98 verifies the request's Authorization: Nostr proof against
// the canonical public URL and the exact body, consumes its replay claim,
// and returns the principal for an already-linked identity. Unlinked pubkeys
// are rejected: proxied endpoints must never trigger account provisioning.
func (v *ProxyNIP98Verifier) VerifyProxyNIP98(ctx context.Context, r *http.Request, body []byte) (TokenPrincipal, error) {
	if v == nil || v.auth == nil || v.tokens == nil {
		return TokenPrincipal{}, ErrTokenUnauthorized
	}
	nipPrincipal, err := v.auth.AuthenticateNIP98Request(ctx, r, body)
	if err != nil {
		return TokenPrincipal{}, err
	}
	link, err := v.tokens.store.GetIdentityLinkByPubkey(ctx, nipPrincipal.PubKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenPrincipal{}, fmt.Errorf("%w: pubkey has no linked Gitea identity (mint a bridge token first)", ErrTokenUnauthorized)
		}
		return TokenPrincipal{}, fmt.Errorf("identity link lookup: %w", err)
	}

	// A signature-only caller may have no live bridge tokens keeping their
	// hidden PAT provisioned; ensure one exists before the proxy asks for
	// it. EnsureHiddenPAT re-verifies the link against Gitea and
	// quarantines on mismatch — a recreated login must never be adopted.
	identity := ResolvedIdentity{
		Pubkey:      link.Pubkey,
		GiteaUser:   link.GiteaUser,
		GiteaUserID: link.GiteaUserID,
	}
	if err := v.tokens.EnsureHiddenPAT(ctx, identity, v.tokens.EnabledScopes()); err != nil {
		return TokenPrincipal{}, err
	}

	principal := TokenPrincipal{
		Pubkey:      nipPrincipal.PubKey,
		GiteaUserID: link.GiteaUserID,
		GiteaUser:   link.GiteaUser,
		Scopes:      v.tokens.EnabledScopes(),
	}
	if pk, err := nostr.PubKeyFromHex(nipPrincipal.PubKey); err == nil {
		principal.Npub = nip19.EncodeNpub(pk)
	}
	return principal, nil
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	sharednip98 "git.sharegap.net/cascadia/cascadia-go/nip98"
	casnostr "git.sharegap.net/cascadia/cascadia-go/nostr"
)

// TokenMint mirrors the bridge's MintResult.
type TokenMint struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenInfo mirrors the bridge's TokenMetadata.
type TokenInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Suffix     string    `json:"suffix"`
	Scopes     []string  `json:"scopes"`
	State      string    `json:"state"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// Client talks to the bridge token API, signing every request with a fresh
// NIP-98 proof bound to the canonical URL and exact body.
type Client struct {
	base   string
	signer casnostr.Signer
	http   *http.Client
}

// NewClient validates the server origin. The URL must match the bridge's
// canonical public URL exactly (scheme and host): NIP-98 proofs are bound to
// it, so a mismatch fails authentication server-side, never silently.
func NewClient(server string, signer casnostr.Signer) (*Client, error) {
	trimmed := strings.TrimRight(server, "/")
	parsed, err := url.Parse(trimmed)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("server must be an absolute URL, got %q", server)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("server must be http or https, got %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("server URL must not carry credentials, query, or fragment")
	}
	return &Client{base: trimmed, signer: signer, http: &http.Client{
		Timeout: 60 * time.Second,
		// Never follow redirects: the NIP-98 proof is bound to the exact
		// URL, so resending it elsewhere can only fail — and could hand the
		// Authorization header to a different origin. The --server value
		// must equal the bridge's canonical public URL.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

// MintRequest is the token-mint payload.
type MintRequest struct {
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// Mint requests a new bridge token. The plaintext token is returned exactly
// once and never logged.
func (c *Client) Mint(ctx context.Context, req MintRequest) (TokenMint, error) {
	var out TokenMint
	err := c.do(ctx, http.MethodPost, "/auth/token", req, http.StatusCreated, &out)
	return out, err
}

// List returns the caller's token metadata.
func (c *Client) List(ctx context.Context) ([]TokenInfo, error) {
	var out struct {
		Tokens []TokenInfo `json:"tokens"`
	}
	err := c.do(ctx, http.MethodGet, "/auth/tokens", nil, http.StatusOK, &out)
	return out.Tokens, err
}

// Revoke revokes a token by id.
func (c *Client) Revoke(ctx context.Context, tokenID string) error {
	return c.do(ctx, http.MethodDelete, "/auth/tokens/"+url.PathEscape(tokenID), nil, http.StatusNoContent, nil)
}

// Rotate revokes a token and mints its replacement.
func (c *Client) Rotate(ctx context.Context, tokenID string, req MintRequest) (TokenMint, error) {
	var out TokenMint
	err := c.do(ctx, http.MethodPost, "/auth/tokens/"+url.PathEscape(tokenID)+"/rotate", req, http.StatusCreated, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, payload any, wantStatus int, out any) error {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	target := c.base + path

	authorization, err := sharednip98.Authorization(ctx, c.signer, method, target, body)
	if err != nil {
		return fmt.Errorf("sign NIP-98 proof: %w", err)
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("bridge redirected (%d) to %q: --server must be the bridge's exact canonical public URL",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.StatusCode != wantStatus {
		return decodeAPIError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// decodeAPIError surfaces the bridge's {"error": "..."} message without ever
// echoing credentials.
func decodeAPIError(resp *http.Response) error {
	var payload struct {
		Error string `json:"error"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if json.Unmarshal(data, &payload) == nil && payload.Error != "" {
		return fmt.Errorf("bridge returned %d: %s", resp.StatusCode, payload.Error)
	}
	return fmt.Errorf("bridge returned %d", resp.StatusCode)
}

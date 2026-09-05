// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05resolve

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCanonicalizeIdentifierUsesExactLowercaseIDNAHost(t *testing.T) {
	canonical, local, host, err := CanonicalizeIdentifier("alice@TÉST.Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "alice@xn--tst-bma.example.com" || local != "alice" || host != "xn--tst-bma.example.com" {
		t.Fatalf("unexpected canonicalization: %q %q %q", canonical, local, host)
	}
	parent, err := CanonicalizeHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	subdomain, err := CanonicalizeHost("Team.Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if parent == subdomain || subdomain != "team.example.com" {
		t.Fatalf("exact host boundary lost: parent=%q subdomain=%q", parent, subdomain)
	}
}

func TestVerifyIdentifierFreshClassifiesResponses(t *testing.T) {
	key := nostr.Generate()
	other := nostr.Generate()
	tests := []struct {
		name      string
		status    int
		body      string
		transport error
		class     string
		code      string
		verified  bool
	}{
		{name: "verified", status: 200, body: `{"names":{"alice":"` + key.Public().Hex() + `"}}`, verified: true},
		{name: "HTTP 200 omission is confirmed absence", status: 200, body: `{"names":{}}`, class: FailureConfirmedAbsent, code: "name_absent"},
		{name: "HTTP 200 mismatch is confirmed absence", status: 200, body: `{"names":{"alice":"` + other.Public().Hex() + `"}}`, class: FailureConfirmedAbsent, code: "pubkey_mismatch"},
		{name: "5xx is indeterminate", status: 503, body: `unavailable`, class: FailureIndeterminate, code: "http_503"},
		{name: "DNS TLS timeout transport class is indeterminate", transport: errors.New("network failure"), class: FailureIndeterminate, code: "transport"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := nip05HTTPClient
			t.Cleanup(func() { nip05HTTPClient = old })
			nip05HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if tt.transport != nil {
					return nil, tt.transport
				}
				return &http.Response{StatusCode: tt.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tt.body)), Request: req}, nil
			})}
			got := VerifyIdentifierFresh(context.Background(), "alice@example.com", key.Public().Hex())
			if got.Verified() != tt.verified || got.FailureClass != tt.class || got.FailureCode != tt.code {
				t.Fatalf("verification = %+v", got)
			}
			if got.Host != "example.com" || got.CanonicalIdentifier != "alice@example.com" || got.LocalPart != "alice" || got.Pubkey != key.Public().Hex() {
				t.Fatalf("structured evidence = %+v", got)
			}
		})
	}
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/publisher"
)

type bridgeTestSigner struct {
	key    string
	pubkey string
}

func (s bridgeTestSigner) PublicKey() string { return s.pubkey }
func (s bridgeTestSigner) SignEvent(_ context.Context, ev *nostr.Event) error {
	ev.PubKey = s.pubkey
	return ev.Sign(s.key)
}

func TestMergeRelayURLsEmpty(t *testing.T) {
	result := mergeRelayURLs(nil, "")
	if len(result) != 0 {
		t.Errorf("expected 0 URLs, got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsNoEmbedded(t *testing.T) {
	configured := []string{"wss://r1", "wss://r2"}
	result := mergeRelayURLs(configured, "")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[0] != "wss://r1" || result[1] != "wss://r2" {
		t.Errorf("unexpected URLs: %v", result)
	}
}

func TestMergeRelayURLsAppendsEmbedded(t *testing.T) {
	configured := []string{"wss://external"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(result), result)
	}
	if result[1] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL appended, got %v", result)
	}
}

func TestMergeRelayURLsDeduplicates(t *testing.T) {
	configured := []string{"ws://localhost:3334", "wss://other"}
	result := mergeRelayURLs(configured, "ws://localhost:3334")
	if len(result) != 2 {
		t.Errorf("expected 2 URLs (no duplicate), got %d: %v", len(result), result)
	}
}

func TestMergeRelayURLsEmbeddedOnly(t *testing.T) {
	result := mergeRelayURLs(nil, "ws://localhost:3334")
	if len(result) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(result), result)
	}
	if result[0] != "ws://localhost:3334" {
		t.Errorf("expected embedded URL, got %v", result)
	}
}

func TestMergeRelayURLsDoesNotMutateInput(t *testing.T) {
	configured := []string{"wss://r1"}
	original := make([]string, len(configured))
	copy(original, configured)

	_ = mergeRelayURLs(configured, "ws://localhost:3334")

	if len(configured) != len(original) {
		t.Error("mergeRelayURLs mutated the input slice")
	}
	if configured[0] != original[0] {
		t.Error("mergeRelayURLs mutated the input slice content")
	}
}

func TestCreatePublisherDisabledWithoutSignerInput(t *testing.T) {
	svc, err := createPublisher(context.Background(), config.Config{}, nil, nil, nil, nil)
	if err != nil || svc != nil {
		t.Fatalf("expected disabled publisher, got service=%v error=%v", svc, err)
	}
}

func TestCreatePublisherUsesRawKeyWithoutConnectingBunker(t *testing.T) {
	key := nostr.GeneratePrivateKey()
	connected := false
	svc, err := createPublisher(context.Background(), config.Config{BridgeNsec: key}, nil, nil, nil,
		func(context.Context, string) (publisher.EventSigner, error) {
			connected = true
			return nil, errors.New("must not connect")
		})
	if err != nil {
		t.Fatal(err)
	}
	if svc == nil || !svc.Enabled() || connected {
		t.Fatalf("raw-key mode selected incorrectly: service=%v connected=%v", svc, connected)
	}
}

func TestCreatePublisherUsesBunkerSigner(t *testing.T) {
	key := nostr.GeneratePrivateKey()
	pubkey, err := nostr.GetPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var gotURI string
	svc, err := createPublisher(context.Background(), config.Config{BridgeSignerBunkerURI: "bunker://signer"}, nil, nil, nil,
		func(_ context.Context, uri string) (publisher.EventSigner, error) {
			gotURI = uri
			return bridgeTestSigner{key: key, pubkey: pubkey}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if svc == nil || !svc.Enabled() || gotURI != "bunker://signer" {
		t.Fatalf("bunker mode selected incorrectly: service=%v uri=%q", svc, gotURI)
	}
}

func TestCreatePublisherPropagatesBunkerConnectorFailure(t *testing.T) {
	want := errors.New("signet unavailable")
	svc, err := createPublisher(context.Background(), config.Config{BridgeSignerBunkerURI: "bunker://signer"}, nil, nil, nil,
		func(context.Context, string) (publisher.EventSigner, error) { return nil, want })
	if svc != nil || !errors.Is(err, want) {
		t.Fatalf("expected connector failure, got service=%v error=%v", svc, err)
	}
}

func TestCreatePublisherRejectsBothSignerModesBeforeConnecting(t *testing.T) {
	connected := false
	svc, err := createPublisher(context.Background(), config.Config{BridgeNsec: nostr.GeneratePrivateKey(), BridgeSignerBunkerURI: "bunker://signer"}, nil, nil, nil,
		func(context.Context, string) (publisher.EventSigner, error) {
			connected = true
			return nil, nil
		})
	if svc != nil || err == nil || connected {
		t.Fatalf("expected fail-closed exclusivity, got service=%v error=%v connected=%v", svc, err, connected)
	}
}

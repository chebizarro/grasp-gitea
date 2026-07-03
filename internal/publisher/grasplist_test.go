// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"errors"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/relay"
)

func TestUserGraspListKindConstant(t *testing.T) {
	if relay.KindUserGraspList != 10317 {
		t.Fatalf("KindUserGraspList: expected 10317, got %d", relay.KindUserGraspList)
	}
}

func TestPublishUserGraspListRefusesBridgeSignedEvent(t *testing.T) {
	svc := &Service{
		bridgePrivKey: "configured",
		bridgePubKey:  "bridge-pubkey",
		relayURLs:     []string{"wss://relay.example.com"},
	}

	err := svc.PublishUserGraspList(context.Background(), []string{"wss://grasp.example.com"})
	if !errors.Is(err, ErrBridgeSignedUserGraspListUnsupported) {
		t.Fatalf("expected ErrBridgeSignedUserGraspListUnsupported, got %v", err)
	}
}

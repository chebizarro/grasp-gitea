// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// ErrBridgeSignedUserGraspListUnsupported is returned when code attempts to
// mint a kind:10317 user GRASP list with the bridge key. NIP-34 defines this
// as a user's replaceable preference list, so the only semantically valid
// bridge behavior is to relay an owner-signed event verbatim after observing
// and validating it.
var ErrBridgeSignedUserGraspListUnsupported = errors.New("bridge-signed kind:10317 user grasp lists are unsupported; use an owner-signed event")

// PublishUserGraspList deliberately refuses to create or sign kind:10317 events
// with the bridge key. A bridge-signed event would be the bridge's own GRASP
// server preference list, not the repository owner's list.
func (s *Service) PublishUserGraspList(context.Context, []string) error {
	return ErrBridgeSignedUserGraspListUnsupported
}

// HandleUserGraspListEvent validates, caches, and rebroadcasts an owner-signed
// kind:10317 user GRASP list. The bridge never signs or mutates the event; it
// only republishes the cached signed event bytes as a Nostr event object.
func (s *Service) HandleUserGraspListEvent(ctx context.Context, ev *nostr.Event, sourceRelay string) error {
	if ev == nil || ev.Kind != relay.KindUserGraspList {
		return nil
	}
	if s == nil || s.store == nil {
		return fmt.Errorf("user GRASP list cache unavailable")
	}
	if ev.ID == (nostr.ID{}) || ev.PubKey == (nostr.PubKey{}) {
		return fmt.Errorf("invalid user GRASP list: missing id/pubkey")
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return fmt.Errorf("user GRASP list cryptographic validation failed: %w", err)
	}

	knownOwner, err := s.store.HasProvisionedOwnerPubkey(ctx, ev.PubKey.Hex())
	if err != nil {
		return fmt.Errorf("lookup provisioned owner pubkey: %w", err)
	}
	if !knownOwner {
		s.logger.Debug("ignoring user GRASP list from unknown pubkey", "pubkey", ev.PubKey.Hex(), "event", ev.ID.Hex(), "relay", sourceRelay)
		return nil
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal user GRASP list event: %w", err)
	}
	cached, err := s.store.UpsertUserGraspListEvent(ctx, store.UserGraspList{
		Pubkey:    ev.PubKey.Hex(),
		EventJSON: string(raw),
		EventID:   ev.ID.Hex(),
		CreatedAt: int64(ev.CreatedAt),
	})
	if err != nil {
		return fmt.Errorf("cache user GRASP list event: %w", err)
	}

	shouldRepublish := cached
	if !shouldRepublish {
		current, err := s.store.GetUserGraspList(ctx, ev.PubKey.Hex())
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("read cached user GRASP list event: %w", err)
		}
		shouldRepublish = err == nil && current.EventID == ev.ID.Hex() && current.LastRepublishedID != ev.ID.Hex()
	}
	if !shouldRepublish {
		return nil
	}

	if err := s.RepublishUserGraspList(ctx, ev.PubKey.Hex()); err != nil {
		return fmt.Errorf("rebroadcast user GRASP list event: %w", err)
	}
	return nil
}

// RepublishUserGraspList rebroadcasts the cached owner-signed kind:10317 event
// unchanged and records last_republished_id after relay acceptance.
func (s *Service) RepublishUserGraspList(ctx context.Context, pubkey string) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("user GRASP list cache unavailable")
	}
	cached, err := s.store.GetUserGraspList(ctx, pubkey)
	if err != nil {
		return err
	}
	if cached.EventJSON == "" || cached.EventID == "" {
		return fmt.Errorf("cached user GRASP list for %s is incomplete", pubkey)
	}

	var ev nostr.Event
	if err := json.Unmarshal([]byte(cached.EventJSON), &ev); err != nil {
		return fmt.Errorf("unmarshal cached user GRASP list: %w", err)
	}
	if ev.ID.Hex() != cached.EventID || ev.PubKey.Hex() != cached.Pubkey || ev.Kind != relay.KindUserGraspList {
		return fmt.Errorf("cached user GRASP list metadata mismatch for %s", pubkey)
	}
	if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
		return fmt.Errorf("cached user GRASP list cryptographic validation failed: %w", err)
	}

	if err := s.publishToRelays(ctx, &ev); err != nil {
		return err
	}
	if err := s.store.RecordUserGraspListRepublished(ctx, cached.Pubkey, ev.ID.Hex()); err != nil {
		s.logger.Warn("failed to record user GRASP list republish", "pubkey", cached.Pubkey, "event", ev.ID.Hex(), "error", err)
	}

	s.logger.Info("republished owner-signed user GRASP list", "pubkey", ev.PubKey.Hex(), "event_id", ev.ID.Hex())
	return nil
}

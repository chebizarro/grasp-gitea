// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/relay"
	appstore "github.com/sharegap/grasp-gitea/internal/store"
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

func TestHandleUserGraspListEventCachesAndRebroadcastsOwnerSignedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := newTestRelay(t)
	st := newTestStore(t)

	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerPK, err := nostr.PubKeyFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerNpub := nip19.EncodeNpub(ownerPK)
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "repo1",
		Pubkey:        ownerPub,
		Owner:         "alice",
		RepoName:      "repo1",
		GiteaRepoID:   1,
		CloneURL:      "https://git.example/alice/repo1.git",
		SourceEvent:   "seed",
		HookInstalled: true,
	})

	svc, err := New("", st, []string{tr.url}, t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}

	first := signedUserGraspList(t, ownerPriv, 100, "wss://grasp1.example")
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first event: %v", err)
	}
	if err := svc.HandleUserGraspListEvent(ctx, first, tr.url); err != nil {
		t.Fatalf("handle first 10317: %v", err)
	}
	cached, err := st.GetUserGraspList(ctx, ownerPub)
	if err != nil {
		t.Fatalf("get cached first 10317: %v", err)
	}
	if cached.EventID != first.ID.Hex() || cached.EventJSON != string(firstJSON) || cached.CreatedAt != int64(first.CreatedAt) {
		t.Fatalf("cached first event mismatch: %+v", cached)
	}
	if cached.LastRepublishedID != first.ID.Hex() {
		t.Fatalf("LastRepublishedID = %q, want %q", cached.LastRepublishedID, first.ID)
	}
	published := tr.savedEventsByKind(relay.KindUserGraspList)
	if len(published) != 1 {
		t.Fatalf("published %d user GRASP lists, want 1", len(published))
	}
	assertSameEvent(t, first, published[0])

	newer := signedUserGraspList(t, ownerPriv, 200, "wss://grasp2.example")
	if err := svc.HandleUserGraspListEvent(ctx, newer, tr.url); err != nil {
		t.Fatalf("handle newer 10317: %v", err)
	}
	cached, err = st.GetUserGraspList(ctx, ownerPub)
	if err != nil {
		t.Fatalf("get cached newer 10317: %v", err)
	}
	if cached.EventID != newer.ID.Hex() || cached.CreatedAt != int64(newer.CreatedAt) || cached.LastRepublishedID != newer.ID.Hex() {
		t.Fatalf("cached newer event mismatch: %+v", cached)
	}
	published = tr.savedEventsByKind(relay.KindUserGraspList)
	if len(published) != 2 {
		t.Fatalf("published %d user GRASP lists after newer event, want 2", len(published))
	}
	assertSameEvent(t, newer, published[1])

	older := signedUserGraspList(t, ownerPriv, 150, "wss://older.example")
	if err := svc.HandleUserGraspListEvent(ctx, older, tr.url); err != nil {
		t.Fatalf("handle older 10317: %v", err)
	}
	cached, err = st.GetUserGraspList(ctx, ownerPub)
	if err != nil {
		t.Fatalf("get cached after older 10317: %v", err)
	}
	if cached.EventID != newer.ID.Hex() {
		t.Fatalf("older event replaced cache: got %q, want %q", cached.EventID, newer.ID.Hex())
	}
	if got := len(tr.savedEventsByKind(relay.KindUserGraspList)); got != 2 {
		t.Fatalf("older event republished; saved count = %d, want 2", got)
	}
}

func TestHandleUserGraspListEventIgnoresNonOwnerPubkey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := newTestRelay(t)
	st := newTestStore(t)
	svc, err := New("", st, []string{tr.url}, t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}

	unknownPriv := nostr.Generate().Hex()
	unknownPub, err := derivePubHex(unknownPriv)
	if err != nil {
		t.Fatalf("unknown pubkey: %v", err)
	}
	unknown := signedUserGraspList(t, unknownPriv, 100, "wss://unknown.example")
	if err := svc.HandleUserGraspListEvent(ctx, unknown, tr.url); err != nil {
		t.Fatalf("unknown pubkey should be ignored, got error: %v", err)
	}
	if _, err := st.GetUserGraspList(ctx, unknownPub); err != sql.ErrNoRows {
		t.Fatalf("unknown pubkey cache lookup err = %v, want sql.ErrNoRows", err)
	}
	if got := len(tr.savedEventsByKind(relay.KindUserGraspList)); got != 0 {
		t.Fatalf("unknown pubkey was republished; saved count = %d, want 0", got)
	}
}

func TestHandleUserGraspListEventRejectsInvalidSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := newTestRelay(t)
	st := newTestStore(t)
	ownerPriv := nostr.Generate().Hex()
	ownerPub, err := derivePubHex(ownerPriv)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerPK, err := nostr.PubKeyFromHex(ownerPub)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	ownerNpub := nip19.EncodeNpub(ownerPK)
	seedMapping(t, ctx, st, appstore.Mapping{
		Npub:          ownerNpub,
		RepoID:        "repo1",
		Pubkey:        ownerPub,
		Owner:         "alice",
		RepoName:      "repo1",
		GiteaRepoID:   1,
		CloneURL:      "https://git.example/alice/repo1.git",
		SourceEvent:   "seed",
		HookInstalled: true,
	})
	svc, err := New("", st, []string{tr.url}, t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}

	invalid := signedUserGraspList(t, ownerPriv, 100, "wss://valid.example")
	invalid.Content = "tampered after signing"
	if err := svc.HandleUserGraspListEvent(ctx, invalid, tr.url); err == nil {
		t.Fatal("expected invalid signature error")
	}
	if _, err := st.GetUserGraspList(ctx, ownerPub); err != sql.ErrNoRows {
		t.Fatalf("invalid event cache lookup err = %v, want sql.ErrNoRows", err)
	}
	if got := len(tr.savedEventsByKind(relay.KindUserGraspList)); got != 0 {
		t.Fatalf("invalid event was republished; saved count = %d, want 0", got)
	}
}

func signedUserGraspList(t *testing.T, priv string, createdAt int64, graspURL string) *nostr.Event {
	t.Helper()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	ev := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex(pub),
		CreatedAt: nostr.Timestamp(createdAt),
		Kind:      relay.KindUserGraspList,
		Tags:      nostr.Tags{{"g", graspURL}},
		Content:   "owner signed user GRASP list",
	}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatalf("sign 10317: %v", err)
	}
	return ev
}

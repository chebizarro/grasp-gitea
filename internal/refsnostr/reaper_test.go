// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package refsnostr

import (
	"context"
	"errors"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	testEventID = "1111111111111111111111111111111111111111111111111111111111111111"
	testTipSHA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type fakeStore struct {
	pending []store.PendingNostrRef
	deleted []string
}

func (s *fakeStore) ListPendingNostrRefsOlderThan(_ context.Context, cutoff time.Time) ([]store.PendingNostrRef, error) {
	var out []store.PendingNostrRef
	for _, ref := range s.pending {
		if !ref.FirstSeenAt.After(cutoff) {
			out = append(out, ref)
		}
	}
	return out, nil
}

func (s *fakeStore) DeletePendingNostrRef(_ context.Context, _ int64, eventID string) error {
	s.deleted = append(s.deleted, eventID)
	return nil
}

type fakeChecker struct {
	matched map[string]bool
	queries []string
}

func (c *fakeChecker) HasAcceptedPRWithTip(_ context.Context, eventID, tipSHA string) (bool, error) {
	c.queries = append(c.queries, eventID+"@"+tipSHA)
	return c.matched[eventID+"@"+tipSHA], nil
}

type fakeDeleter struct {
	deleted []store.PendingNostrRef
}

func (d *fakeDeleter) DeleteNostrRef(_ context.Context, ref store.PendingNostrRef) error {
	d.deleted = append(d.deleted, ref)
	return nil
}

type fakeFetcher struct {
	ev  *nostr.Event
	err error
}

func (f fakeFetcher) FetchEvent(_ context.Context, _ string) (*nostr.Event, error) {
	return f.ev, f.err
}

func pendingRef(firstSeen time.Time) store.PendingNostrRef {
	return store.PendingNostrRef{
		EventID:     testEventID,
		TipSHA:      testTipSHA,
		GiteaRepoID: 42,
		Owner:       "org1",
		RepoName:    "repo1",
		FirstSeenAt: firstSeen,
	}
}

func TestReaperDeletesExpiredRefWithoutMatchingPR(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	st := &fakeStore{pending: []store.PendingNostrRef{pendingRef(now.Add(-21 * time.Minute))}}
	checker := &fakeChecker{matched: map[string]bool{}}
	deleter := &fakeDeleter{}

	reaper := NewReaper(st, checker, deleter, nil, WithClock(func() time.Time { return now }), WithTTL(20*time.Minute))
	if err := reaper.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if len(deleter.deleted) != 1 || deleter.deleted[0].EventID != testEventID {
		t.Fatalf("expected stale ref to be deleted, got %#v", deleter.deleted)
	}
	if len(st.deleted) != 1 || st.deleted[0] != testEventID {
		t.Fatalf("expected pending row to be removed, got %v", st.deleted)
	}
}

func TestReaperKeepsExpiredRefWithMatchingPR(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	st := &fakeStore{pending: []store.PendingNostrRef{pendingRef(now.Add(-21 * time.Minute))}}
	checker := &fakeChecker{matched: map[string]bool{testEventID + "@" + testTipSHA: true}}
	deleter := &fakeDeleter{}

	reaper := NewReaper(st, checker, deleter, nil, WithClock(func() time.Time { return now }), WithTTL(20*time.Minute))
	if err := reaper.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if len(deleter.deleted) != 0 {
		t.Fatalf("matching PR should keep git ref, deleted %#v", deleter.deleted)
	}
	if len(st.deleted) != 1 || st.deleted[0] != testEventID {
		t.Fatalf("satisfied pending row should be cleared, got %v", st.deleted)
	}
}

func TestFetchEventForTipRejectsDifferingTipForPatchEvent(t *testing.T) {
	ev := &nostr.Event{
		ID:   nostr.MustIDFromHex(testEventID),
		Kind: relay.KindPatch,
		Tags: nostr.Tags{{"c", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	}
	_, err := FetchEventForTip(context.Background(), fakeFetcher{ev: ev}, testEventID, testTipSHA)
	if !errors.Is(err, ErrDifferingTip) {
		t.Fatalf("expected ErrDifferingTip, got %v", err)
	}
}

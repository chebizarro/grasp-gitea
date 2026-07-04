// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package relay

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewSubscriber(t *testing.T) {
	handler := func(ctx context.Context, ev *nostr.Event, relayURL string) error {
		return nil
	}
	s := New([]string{"wss://r1.test", "wss://r2.test"}, handler, testLogger())
	if len(s.relays) != 2 {
		t.Errorf("expected 2 relays, got %d", len(s.relays))
	}
}

func TestSleepOrDoneRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	sleepOrDone(ctx, 10*time.Second)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("sleepOrDone should return immediately on cancelled context, took %v", elapsed)
	}
}

func TestSleepOrDoneSleepsWhenNotCancelled(t *testing.T) {
	ctx := context.Background()

	start := time.Now()
	sleepOrDone(ctx, 50*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 40*time.Millisecond {
		t.Errorf("sleepOrDone should sleep for the duration, took only %v", elapsed)
	}
}

func TestRunAndWaitWithCancelledContext(t *testing.T) {
	handler := func(ctx context.Context, ev *nostr.Event, relayURL string) error {
		return nil
	}
	// Use a fake relay URL that won't connect.
	s := New([]string{"ws://127.0.0.1:1"}, handler, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	s.Run(ctx)

	done := make(chan struct{})
	go func() {
		s.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good: Wait returned.
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return within 5 seconds after cancelled context")
	}
}

func TestKindConstants(t *testing.T) {
	if KindRepositoryAnnouncement != 30617 {
		t.Errorf("KindRepositoryAnnouncement: expected 30617, got %d", KindRepositoryAnnouncement)
	}
	if KindRepositoryState != 30618 {
		t.Errorf("KindRepositoryState: expected 30618, got %d", KindRepositoryState)
	}
	if KindNIP22Comment != 1111 {
		t.Errorf("KindNIP22Comment: expected 1111, got %d", KindNIP22Comment)
	}
	if KindUserGraspList != 10317 {
		t.Errorf("KindUserGraspList: expected 10317, got %d", KindUserGraspList)
	}
}

func TestSubscriptionFiltersIncludeCollaborationKinds(t *testing.T) {
	filters := subscriptionFilters()
	if len(filters) != 1 {
		t.Fatalf("expected one filter, got %d", len(filters))
	}
	got := map[int]bool{}
	for _, kind := range filters[0].Kinds {
		got[kind] = true
	}
	for _, want := range []int{
		KindRepositoryAnnouncement,
		KindRepositoryState,
		KindUserGraspList,
		KindNIP22Comment,
		KindPatch,
		KindIssue,
		KindStatusOpen,
		KindStatusApplied,
		KindStatusClosed,
		KindStatusDraft,
	} {
		if !got[want] {
			t.Fatalf("subscription filter missing kind %d", want)
		}
	}
}

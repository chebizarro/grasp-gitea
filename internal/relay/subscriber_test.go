// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package relay

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"fiatjaf.com/nostr"
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

func TestDedicatedSubscriberUsesCanonicalLoomKinds(t *testing.T) {
	s := NewWithKinds(nil, []nostr.Kind{KindLoomJobStatus, KindLoomJobResult, KindHiveWorkflowResult},
		func(context.Context, *nostr.Event, string) error { return nil }, testLogger())
	got := s.filter().Kinds
	if len(got) != 3 || got[0] != KindLoomJobStatus || got[1] != KindLoomJobResult || got[2] != KindHiveWorkflowResult {
		t.Fatalf("dedicated kinds = %v", got)
	}
	if KindLoomJobRequest != 5100 || KindLoomJobResult != 5101 || KindLoomJobStatus != 30100 ||
		KindLoomJobCancel != 5102 || KindHiveWorkflowRun != 5401 || KindHiveWorkflowResult != 5402 {
		t.Fatal("canonical Loom/Hive-CI kind constants changed")
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
	if KindPRUpdate != 1619 {
		t.Errorf("KindPRUpdate: expected 1619, got %d", KindPRUpdate)
	}
}

func TestSubscriptionFiltersIncludeCollaborationKinds(t *testing.T) {
	filter := subscriptionFilter()
	got := map[nostr.Kind]bool{}
	for _, kind := range filter.Kinds {
		got[kind] = true
	}
	for _, want := range []nostr.Kind{
		KindRepositoryAnnouncement,
		KindRepositoryState,
		KindUserGraspList,
		KindNIP22Comment,
		KindCASAudit,
		KindPatch,
		KindPROpen,
		KindPRUpdate,
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package metrics

import "testing"

func TestSnapshotInitiallyZero(t *testing.T) {
	// Reset counters for test isolation.
	announcementEventsReceived.Store(0)
	announcementEventsRejected.Store(0)
	announcementEventsProvisioned.Store(0)
	manualProvisionRequests.Store(0)
	manualProvisionFailures.Store(0)
	authChallengesIssued.Store(0)
	authVerifySuccess.Store(0)
	authVerifyFailure.Store(0)
	authReplayRejected.Store(0)
	authUserProvisioned.Store(0)
	nip46SessionsInitiated.Store(0)
	nip46SessionsCompleted.Store(0)
	nip46SessionsFailed.Store(0)

	snap := Snapshot()
	for key, val := range snap {
		if val != 0 {
			t.Errorf("expected %s=0, got %d", key, val)
		}
	}
}

func TestIncFunctionsAndSnapshot(t *testing.T) {
	// Reset counters.
	announcementEventsReceived.Store(0)
	announcementEventsRejected.Store(0)
	announcementEventsProvisioned.Store(0)
	manualProvisionRequests.Store(0)
	manualProvisionFailures.Store(0)
	authChallengesIssued.Store(0)
	authVerifySuccess.Store(0)
	authVerifyFailure.Store(0)
	authReplayRejected.Store(0)
	authUserProvisioned.Store(0)
	nip46SessionsInitiated.Store(0)
	nip46SessionsCompleted.Store(0)
	nip46SessionsFailed.Store(0)

	IncAnnouncementReceived()
	IncAnnouncementReceived()
	IncAnnouncementRejected()
	IncAnnouncementProvisioned()
	IncAnnouncementProvisioned()
	IncAnnouncementProvisioned()
	IncManualProvisionRequests()
	IncManualProvisionFailures()
	IncManualProvisionFailures()
	IncAuthChallengesIssued()
	IncAuthChallengesIssued()
	IncAuthVerifySuccess()
	IncAuthVerifyFailure()
	IncAuthVerifyFailure()
	IncAuthVerifyFailure()
	IncAuthReplayRejected()
	IncAuthUserProvisioned()
	IncNIP46SessionsInitiated()
	IncNIP46SessionsInitiated()
	IncNIP46SessionsCompleted()
	IncNIP46SessionsFailed()

	snap := Snapshot()
	expected := map[string]int64{
		"announcement_events_received":    2,
		"announcement_events_rejected":    1,
		"announcement_events_provisioned": 3,
		"manual_provision_requests":       1,
		"manual_provision_failures":       2,
		"auth_challenges_issued":          2,
		"auth_verify_success":             1,
		"auth_verify_failure":             3,
		"auth_replay_rejected":            1,
		"auth_user_provisioned":           1,
		"nip46_sessions_initiated":         2,
		"nip46_sessions_completed":         1,
		"nip46_sessions_failed":            1,
	}
	for key, want := range expected {
		if got := snap[key]; got != want {
			t.Errorf("%s: expected %d, got %d", key, want, got)
		}
	}
}

func TestSnapshotReturnsAllKeys(t *testing.T) {
	snap := Snapshot()
	requiredKeys := []string{
		"announcement_events_received",
		"announcement_events_rejected",
		"announcement_events_provisioned",
		"manual_provision_requests",
		"manual_provision_failures",
		"auth_challenges_issued",
		"auth_verify_success",
		"auth_verify_failure",
		"auth_replay_rejected",
		"auth_user_provisioned",
		"nip46_sessions_initiated",
		"nip46_sessions_completed",
		"nip46_sessions_failed",
	}
	for _, key := range requiredKeys {
		if _, ok := snap[key]; !ok {
			t.Errorf("Snapshot() missing key %q", key)
		}
	}
}

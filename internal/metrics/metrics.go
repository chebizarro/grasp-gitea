package metrics

import "sync/atomic"

var announcementEventsReceived atomic.Int64
var announcementEventsRejected atomic.Int64
var announcementEventsProvisioned atomic.Int64
var manualProvisionRequests atomic.Int64
var manualProvisionFailures atomic.Int64
var authChallengesIssued atomic.Int64
var authVerifySuccess atomic.Int64
var authVerifyFailure atomic.Int64
var authReplayRejected atomic.Int64
var authUserProvisioned atomic.Int64
var nip46SessionsInitiated atomic.Int64
var nip46SessionsCompleted atomic.Int64
var nip46SessionsFailed atomic.Int64

func IncAnnouncementReceived() {
	announcementEventsReceived.Add(1)
}

func IncAnnouncementRejected() {
	announcementEventsRejected.Add(1)
}

func IncAnnouncementProvisioned() {
	announcementEventsProvisioned.Add(1)
}

func IncManualProvisionRequests() {
	manualProvisionRequests.Add(1)
}

func IncManualProvisionFailures() {
	manualProvisionFailures.Add(1)
}

func IncAuthChallengesIssued() {
	authChallengesIssued.Add(1)
}

func IncAuthVerifySuccess() {
	authVerifySuccess.Add(1)
}

func IncAuthVerifyFailure() {
	authVerifyFailure.Add(1)
}

func IncAuthReplayRejected() {
	authReplayRejected.Add(1)
}

func IncAuthUserProvisioned() {
	authUserProvisioned.Add(1)
}

func IncNIP46SessionsInitiated() {
	nip46SessionsInitiated.Add(1)
}

func IncNIP46SessionsCompleted() {
	nip46SessionsCompleted.Add(1)
}

func IncNIP46SessionsFailed() {
	nip46SessionsFailed.Add(1)
}

func Snapshot() map[string]int64 {
	return map[string]int64{
		"announcement_events_received":    announcementEventsReceived.Load(),
		"announcement_events_rejected":    announcementEventsRejected.Load(),
		"announcement_events_provisioned": announcementEventsProvisioned.Load(),
		"manual_provision_requests":       manualProvisionRequests.Load(),
		"manual_provision_failures":       manualProvisionFailures.Load(),
		"auth_challenges_issued":          authChallengesIssued.Load(),
		"auth_verify_success":             authVerifySuccess.Load(),
		"auth_verify_failure":             authVerifyFailure.Load(),
		"auth_replay_rejected":            authReplayRejected.Load(),
		"auth_user_provisioned":           authUserProvisioned.Load(),
		"nip46_sessions_initiated":         nip46SessionsInitiated.Load(),
		"nip46_sessions_completed":         nip46SessionsCompleted.Load(),
		"nip46_sessions_failed":            nip46SessionsFailed.Load(),
	}
}

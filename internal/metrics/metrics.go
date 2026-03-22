package metrics

import "sync/atomic"

var announcementEventsReceived atomic.Int64
var announcementEventsRejected atomic.Int64
var announcementEventsProvisioned atomic.Int64
var manualProvisionRequests atomic.Int64
var manualProvisionFailures atomic.Int64

// NIP-07 auth counters
var nip07ChallengesIssued atomic.Int64
var nip07VerifySuccess atomic.Int64
var nip07VerifyFailure atomic.Int64
var nip07ReplayRejected atomic.Int64
var oauth2TokenExchanges atomic.Int64
var nip07UsersAutoProvisioned atomic.Int64

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

func IncNIP07ChallengesIssued()     { nip07ChallengesIssued.Add(1) }
func IncNIP07VerifySuccess()        { nip07VerifySuccess.Add(1) }
func IncNIP07VerifyFailure()        { nip07VerifyFailure.Add(1) }
func IncNIP07ReplayRejected()       { nip07ReplayRejected.Add(1) }
func IncOAuth2TokenExchanges()      { oauth2TokenExchanges.Add(1) }
func IncNIP07UsersAutoProvisioned() { nip07UsersAutoProvisioned.Add(1) }

func Snapshot() map[string]int64 {
	return map[string]int64{
		"announcement_events_received":    announcementEventsReceived.Load(),
		"announcement_events_rejected":    announcementEventsRejected.Load(),
		"announcement_events_provisioned": announcementEventsProvisioned.Load(),
		"manual_provision_requests":       manualProvisionRequests.Load(),
		"manual_provision_failures":       manualProvisionFailures.Load(),
		"nip07_challenges_issued":         nip07ChallengesIssued.Load(),
		"nip07_verify_success":            nip07VerifySuccess.Load(),
		"nip07_verify_failure":            nip07VerifyFailure.Load(),
		"nip07_replay_rejected":           nip07ReplayRejected.Load(),
		"oauth2_token_exchanges":          oauth2TokenExchanges.Load(),
		"nip07_users_auto_provisioned":    nip07UsersAutoProvisioned.Load(),
	}
}

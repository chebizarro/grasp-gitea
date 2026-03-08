package metrics

import "sync/atomic"

var announcementEventsReceived atomic.Int64
var announcementEventsRejected atomic.Int64
var announcementEventsProvisioned atomic.Int64
var manualProvisionRequests atomic.Int64
var manualProvisionFailures atomic.Int64

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

func Snapshot() map[string]int64 {
	return map[string]int64{
		"announcement_events_received":    announcementEventsReceived.Load(),
		"announcement_events_rejected":    announcementEventsRejected.Load(),
		"announcement_events_provisioned": announcementEventsProvisioned.Load(),
		"manual_provision_requests":       manualProvisionRequests.Load(),
		"manual_provision_failures":       manualProvisionFailures.Load(),
	}
}

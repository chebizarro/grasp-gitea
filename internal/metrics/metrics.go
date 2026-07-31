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
var nip55ChallengesIssued atomic.Int64
var nip55VerifySuccess atomic.Int64
var nip55VerifyFailure atomic.Int64
var ciWorkflowRunsPublished atomic.Int64
var ciWorkflowRunsFailed atomic.Int64
var webhookEventsReceived atomic.Int64
var webhookEventsPublished atomic.Int64
var webhookEventsFailed atomic.Int64
var outboxQueueDepth atomic.Int64
var outboxPublished atomic.Int64
var outboxRetried atomic.Int64
var outboxDeadLettered atomic.Int64
var bridgeSignedFallback atomic.Int64
var unlinkedActorSkipped atomic.Int64
var actorEventsBackfilled atomic.Int64
var bridgeTokensMinted atomic.Int64
var bridgeTokensRevoked atomic.Int64
var bridgeTokensRotated atomic.Int64
var bridgeTokenAuthFailures atomic.Int64
var patCredentialsProvisioned atomic.Int64
var patProvisionFailures atomic.Int64
var patCredentialsRetired atomic.Int64
var patCredentialsReencrypted atomic.Int64
var patCredentialsReconciled atomic.Int64
var patReconcileFailures atomic.Int64
var patStuckProvisioning atomic.Int64
var profileSynced atomic.Int64
var profileSyncPATCleanupFailures atomic.Int64
var profileSyncRelayFailures atomic.Int64

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

func IncNIP55ChallengesIssued() {
	nip55ChallengesIssued.Add(1)
}

func IncNIP55VerifySuccess() {
	nip55VerifySuccess.Add(1)
}

func IncNIP55VerifyFailure() {
	nip55VerifyFailure.Add(1)
}

func IncCIWorkflowRunsPublished() {
	ciWorkflowRunsPublished.Add(1)
}

func IncCIWorkflowRunsFailed() {
	ciWorkflowRunsFailed.Add(1)
}

func IncWebhookEventsReceived() {
	webhookEventsReceived.Add(1)
}

func IncWebhookEventsPublished() {
	webhookEventsPublished.Add(1)
}

func IncWebhookEventsFailed() {
	webhookEventsFailed.Add(1)
}

func SetOutboxQueueDepth(depth int64) {
	if depth < 0 {
		depth = 0
	}
	outboxQueueDepth.Store(depth)
}

func IncOutboxPublished() {
	outboxPublished.Add(1)
}

func IncOutboxRetried() {
	outboxRetried.Add(1)
}

func IncOutboxDeadLettered() {
	outboxDeadLettered.Add(1)
}

func IncBridgeSignedFallback() {
	bridgeSignedFallback.Add(1)
}

func IncUnlinkedActorSkipped() {
	unlinkedActorSkipped.Add(1)
}

func IncActorEventsBackfilled() {
	actorEventsBackfilled.Add(1)
}

func IncBridgeTokensMinted() {
	bridgeTokensMinted.Add(1)
}

func IncBridgeTokensRevoked() {
	bridgeTokensRevoked.Add(1)
}

func IncBridgeTokensRotated() {
	bridgeTokensRotated.Add(1)
}

func IncBridgeTokenAuthFailures() {
	bridgeTokenAuthFailures.Add(1)
}

func IncPATCredentialsProvisioned() {
	patCredentialsProvisioned.Add(1)
}

func IncPATProvisionFailures() {
	patProvisionFailures.Add(1)
}

func IncPATCredentialsRetired() {
	patCredentialsRetired.Add(1)
}

// IncPATCredentialsReencrypted counts credentials re-sealed under the active
// key by the proactive re-encryption sweep.
func IncPATCredentialsReencrypted() { patCredentialsReencrypted.Add(1) }

// IncPATCredentialsReconciled counts error/orphaned credentials whose Gitea
// PAT was confirmed deleted and whose row was cleared.
func IncPATCredentialsReconciled() { patCredentialsReconciled.Add(1) }

// IncPATReconcileFailures counts reconciliation attempts that could not
// complete (Gitea unreachable, deletion failed).
func IncPATReconcileFailures() { patReconcileFailures.Add(1) }

// SetPATStuckProvisioning records the number of provisioning rows stranded
// past the recovery threshold at the last sweep — a gauge operators alert on.
func SetPATStuckProvisioning(n int64) { patStuckProvisioning.Store(n) }

// IncProfileSynced counts kind:0 profiles applied to a Gitea user.
func IncProfileSynced() { profileSynced.Add(1) }

// IncProfileSyncPATCleanupFailures counts ephemeral avatar PATs whose
// delete-after-use failed and was queued for reconciliation.
func IncProfileSyncPATCleanupFailures() { profileSyncPATCleanupFailures.Add(1) }

// IncProfileSyncRelayFailure counts profile fetches where every relay was
// unreachable, so a relay outage stays observable.
func IncProfileSyncRelayFailure() { profileSyncRelayFailures.Add(1) }

func Snapshot() map[string]int64 {
	return map[string]int64{
		"announcement_events_received":      announcementEventsReceived.Load(),
		"announcement_events_rejected":      announcementEventsRejected.Load(),
		"announcement_events_provisioned":   announcementEventsProvisioned.Load(),
		"manual_provision_requests":         manualProvisionRequests.Load(),
		"manual_provision_failures":         manualProvisionFailures.Load(),
		"auth_challenges_issued":            authChallengesIssued.Load(),
		"auth_verify_success":               authVerifySuccess.Load(),
		"auth_verify_failure":               authVerifyFailure.Load(),
		"auth_replay_rejected":              authReplayRejected.Load(),
		"auth_user_provisioned":             authUserProvisioned.Load(),
		"nip46_sessions_initiated":          nip46SessionsInitiated.Load(),
		"nip46_sessions_completed":          nip46SessionsCompleted.Load(),
		"nip46_sessions_failed":             nip46SessionsFailed.Load(),
		"nip55_challenges_issued":           nip55ChallengesIssued.Load(),
		"nip55_verify_success":              nip55VerifySuccess.Load(),
		"nip55_verify_failure":              nip55VerifyFailure.Load(),
		"ci_workflow_runs_published":        ciWorkflowRunsPublished.Load(),
		"ci_workflow_runs_failed":           ciWorkflowRunsFailed.Load(),
		"webhook_events_received":           webhookEventsReceived.Load(),
		"webhook_events_published":          webhookEventsPublished.Load(),
		"webhook_events_failed":             webhookEventsFailed.Load(),
		"outbox_queue_depth":                outboxQueueDepth.Load(),
		"outbox_published":                  outboxPublished.Load(),
		"outbox_retried":                    outboxRetried.Load(),
		"outbox_dead_lettered":              outboxDeadLettered.Load(),
		"bridge_signed_fallback":            bridgeSignedFallback.Load(),
		"unlinked_actor_skipped":            unlinkedActorSkipped.Load(),
		"actor_events_backfilled":           actorEventsBackfilled.Load(),
		"bridge_tokens_minted":              bridgeTokensMinted.Load(),
		"bridge_tokens_revoked":             bridgeTokensRevoked.Load(),
		"bridge_tokens_rotated":             bridgeTokensRotated.Load(),
		"bridge_token_auth_failures":        bridgeTokenAuthFailures.Load(),
		"pat_credentials_provisioned":       patCredentialsProvisioned.Load(),
		"pat_provision_failures":            patProvisionFailures.Load(),
		"pat_credentials_retired":           patCredentialsRetired.Load(),
		"pat_credentials_reencrypted":       patCredentialsReencrypted.Load(),
		"pat_credentials_reconciled":        patCredentialsReconciled.Load(),
		"pat_reconcile_failures":            patReconcileFailures.Load(),
		"pat_stuck_provisioning":            patStuckProvisioning.Load(),
		"profile_synced":                    profileSynced.Load(),
		"profile_sync_pat_cleanup_failures": profileSyncPATCleanupFailures.Load(),
		"profile_sync_relay_failures":       profileSyncRelayFailures.Load(),
	}
}

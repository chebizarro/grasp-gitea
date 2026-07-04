# NIP-34 Webhook Implementation

## Overview

The webhook bridge converts Gitea activity into NIP-34/NIP-22 Nostr events. The current model is user-signed by default when the signer subsystem is enabled: webhook handlers build unsigned event templates, enqueue them in the outbound signing queue, and publish only after the relevant user's NIP-46 bunker grant signs the event.

CI workflow-run events (`kind:5401`) are the exception: they remain operator-signed by `BRIDGE_NSEC` because they are executor attestations, not user-authored NIP-34 content.

## Signing model

| Event family | Author/signing path | Notes |
|---|---|---|
| `30617` repository announcement | Owner-signed upstream; bridge caches/rebroadcasts verbatim | Still owner-authored. The bridge does not add `maintainers` tags. |
| `30618` repository state | Owner grant → outbound queue → NIP-46 signer → relay | If the signer subsystem is disabled, legacy bridge-signed transition fallback remains intentional. |
| Contributor webhook events (`1617`, `1618`, `1619`, `1621`, `1630`-`1633`, `1985`) | Acting user's grant → outbound queue → NIP-46 signer → relay | Unlinked actors are skipped, not bridge-signed, and counted by `unlinked_actor_skipped`. |
| NIP-22 comments (`1111`) | Acting user's grant → outbound queue → NIP-46 signer → relay | Used for comment/review threading. |
| CI workflow run (`5401`) | Operator key (`BRIDGE_NSEC`) | GRASP extension / executor attestation. |

## Configuration

```bash
# Required for relay publishing / operator attestations / transition fallback
BRIDGE_NSEC=nsec1... or hex private key

# Required: HMAC secret shared with Gitea webhook
GITEA_WEBHOOK_SECRET=your-secret-here

# Optional: relay URLs to publish to
RELAY_URLS=wss://relay1.example.com,wss://relay2.example.com

# Optional: admin API bearer token for /signer/authorize and /outbound-events
ADMIN_API_TOKEN=admin-secret

# Optional but recommended: enables user-signed NIP-46 grants.
# Must decode to exactly 32 bytes from base64 or hex.
SIGNER_MASTER_KEY=base64-or-hex-32-byte-key

# Optional: proactive state sync cadence and archive behavior
PROACTIVE_SYNC_INTERVAL=1h
GRASP05_ARCHIVE_MODE=false
```

When `SIGNER_MASTER_KEY` is empty, the persistent signer service is disabled and the bridge runs in legacy bridge-signed transition mode where applicable. This fallback is intentional for migration compatibility and should not be removed from code during documentation-only work.

## Signer authorization

`POST /signer/authorize` creates a persistent NIP-46 signer grant from a bunker URI. The request must be authenticated with the admin bearer token.

Request:

```json
{"bunker_uri":"bunker://..."}
```

Success response includes:

```json
{
  "ok": true,
  "pubkey": "<authorized user pubkey>",
  "client_pubkey": "<bridge NIP-46 client pubkey>",
  "relays": ["wss://relay.example"],
  "granted_at": "..."
}
```

The grant stores the bridge's reusable NIP-46 client credentials and bunker URI encrypted at rest with `SIGNER_MASTER_KEY`. Owners use this flow for owner-authored repository state. Contributors link their own signer grants through the NIP-46 login/linking flow before their Gitea-authored collaboration events can be published.

## Outbound signing queue

`GET /outbound-events?limit=50` is the admin queue inspection endpoint. It shows queued unsigned templates and their state, attempts, next retry time, last error, and published event id when available.

Queue behavior:

- Events are deduplicated before publish.
- Offline bunkers cause retry/backoff instead of silent drops.
- Repeated failures surface as dead-lettered queue entries and metrics.
- Metrics include `outbox_queue_depth`, `outbox_published`, `outbox_retried`, `outbox_dead_lettered`, `bridge_signed_fallback`, and `unlinked_actor_skipped`.

## Gitea system webhook setup

1. Navigate to **Site Administration → System Webhooks**
2. Click **Add Webhook → Gitea**
3. Configure:
   - **Target URL**: `http://grasp-bridge:8090/webhook/gitea`
   - **HTTP Method**: `POST`
   - **POST Content Type**: `application/json`
   - **Secret**: Same value as `GITEA_WEBHOOK_SECRET`
   - **Trigger On**: Select all events (Push, Create, Delete, Pull Request, Issues, Label)
   - **Active**: ✓

## Event flow

```text
Gitea Event → /webhook/gitea → HMAC Verification → Event Builder
                                                        ↓
                                              Actor/owner grant lookup
                                                        ↓
                                unsigned event template → outbound queue
                                                        ↓
                                           NIP-46 user signing grant
                                                        ↓
                                                publish to relays
```

If `SIGNER_MASTER_KEY` is unset, signer/outbox user-signing is disabled and bridge-signed transition fallbacks remain in effect where implemented. If a contributor actor has not linked a signer while user-signing is enabled, their event is skipped and `unlinked_actor_skipped` is incremented; it is not later backfilled automatically.

## Supported webhook events

### Push events

- Regular push → `kind:30618` repository state, owner-signed through the owner grant when enabled.
- Patch push (`refs/nostr/<event-id>`) → `kind:1617` patch acknowledgement flow; Nostr 1617/1618 events are reflected as Gitea PRs (`phase1-2gq`).

### Branch/tag events

- Create/delete → `kind:30618` repository state.

### Pull request events

- Opened → `kind:1618` PR open + `kind:1630/1633` status.
- Edited/synchronized → `kind:1619` PR update.
- Closed/reopened → status events (`1631` applied or `1632` closed / `1630` reopened) with NIP-34 threading.

PR events use the NIP-34 tag schema (`subject`, `c`, `clone`, `branch-name`, euc `r`, and `E`/`P` references on updates) rather than the older bridge-local `title`/`head`/`base`/`action` shape.

### Issue and comment events

- Opened/edited → `kind:1621` issue.
- Closed/reopened → `kind:1632`/`kind:1630` status.
- Comments/review discussion → NIP-22 `kind:1111` comments.
- Labeled/unlabeled → `kind:1985` NIP-32 label.

## Nostr → Gitea reflection

The bridge also reflects supported Nostr-originated collaboration events into Gitea with echo-loop prevention:

- `1621` issues → Gitea issues.
- `1111` comments → Gitea comments.
- `1630`/`1632` status changes → Gitea state updates.
- Nostr patches/PRs (1617/1618) are reflected as Gitea pull requests via tip fetch or `git am` apply → head branch → Gitea PR (`phase1-2gq`); Nostr PR updates (1619) fetch the new tip and move the stored PR head branch, which Gitea reflects on its next branch-sync. Force-updates are expected for rebased PR revisions.

## Compatibility and known limitations

- Historical events already published under `BRIDGE_NSEC` are not re-signed.
- Events created before a contributor links a signer are not backfilled (`phase1-5ud`).
- Unlinked contributor actors are skipped and counted by `unlinked_actor_skipped`; the bridge does not forge their content with `BRIDGE_NSEC`.
- Legacy bridge-signed fallbacks remain intentional for transition compatibility when the signer subsystem is disabled.
- `maintainers` on `30617` is owner-driven; the bridge honors owner announcements and will not add maintainers itself.
- Nostr→Gitea reflection covers issues/comments/status (`phase1-ki5`), patches/PRs → Gitea pull requests (`phase1-2gq`), and PR-update (1619) tip updates (`phase1-ooy`).
- Kind `10317` owner-list cache/rebroadcast is separate work (`phase1-kyg`).

## Testing

For a documentation-level smoke test:

1. Set the environment variables above.
2. Start `grasp-bridge`.
3. Configure the Gitea system webhook.
4. Authorize an owner signer with `POST /signer/authorize` if user-signing is enabled.
5. Link contributor signers before expecting contributor-authored webhook events to publish.
6. Create a test PR, issue, comment, label, or push in a provisioned repository.
7. Inspect `/metrics`, `/outbound-events`, logs, and relay output.

## References

- [NIP-34: git stuff](https://github.com/nostr-protocol/nips/blob/master/34.md)
- [NIP-22: Comments](https://github.com/nostr-protocol/nips/blob/master/22.md)
- [NIP-32: Labeling](https://github.com/nostr-protocol/nips/blob/master/32.md)
- [NIP-46: Nostr Connect](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [Gitea Webhooks Documentation](https://docs.gitea.com/usage/webhooks)

# User-Signed NIP-34 Operations

## Mode selection

Set `SIGNER_MASTER_KEY` to enable persistent user signing. The value must decode to exactly 32 bytes from base64 or hex and is used to encrypt persisted NIP-46 signer grants.

If `SIGNER_MASTER_KEY` is empty, the signer subsystem is disabled and the bridge stays in legacy bridge-signed transition mode where implemented. This compatibility fallback is intentional.

## Authorizing signers

Use the admin endpoint to create a reusable NIP-46 bunker grant:

```http
POST /signer/authorize
Authorization: Bearer <ADMIN_API_TOKEN>
Content-Type: application/json
```

```json
{"bunker_uri":"bunker://..."}
```

Owners need a grant for owner-authored repository state (`30618`). Contributors need their own linked grants before Gitea-authored PR, issue, comment, status, patch, or label events can publish under their pubkey.

## Queue operations

Inspect pending, retrying, published, or dead-lettered user-signed items with:

```http
GET /outbound-events?limit=50
Authorization: Bearer <ADMIN_API_TOKEN>
```

Watch these metrics:

- `outbox_queue_depth`
- `outbox_published`
- `outbox_retried`
- `outbox_dead_lettered`
- `bridge_signed_fallback`
- `unlinked_actor_skipped`

## Compatibility notes

- `30617` announcements remain owner-signed and are rebroadcast verbatim.
- `30618` state is owner-signed through the queue when user-signing is enabled.
- CI `5401` events remain operator-signed by `BRIDGE_NSEC`.
- Contributor events from unlinked actors are skipped and counted as `unlinked_actor_skipped`; they are not bridge-signed and are not backfilled after the actor links a signer.
- Historical `BRIDGE_NSEC`-signed events are not re-signed.
- Nostr patches/PRs (1617/1618) are reflected as Gitea pull requests (tip fetch or `git am` apply → head branch → Gitea PR) (`phase1-2gq`); issue/comment/status reflection is also supported (`phase1-ki5`). PR-update (1619) tip updates remain a follow-up.
- `maintainers` on `30617` is owner-driven; the bridge will not add it.
- Kind `10317` owner-list cache/rebroadcast is tracked separately (`phase1-kyg`).

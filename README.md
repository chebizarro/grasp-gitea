# grasp-bridge

Phase 1 + Phase 2 + Phase 3 implementation currently provides:

> **Protocol note:** this bridge speaks NIP-34 for repo state and emits canonical ContextVM `ci/workflow-run` requests. Compute dispatch belongs downstream of that canonical command boundary.

- relay subscriber for NIP-34 repository announcements (kind `30617`)
- automatic Gitea org/repo provisioning for clone URLs matching `CLONE_PREFIX`
- automatic repo archival when a later announcement removes this server from `clone` tags
- proactive sync listener for repository state events (best-effort local ref update)
- user-signed NIP-34 publishing: owner/contributor events are built unsigned, queued, and signed through the user's NIP-46 bunker grant when `SIGNER_MASTER_KEY` is configured
- transition fallback to legacy bridge-signed publishing when the signer subsystem is disabled; unlinked contributor actors are skipped rather than bridge-signed
- SQLite mapping store for `{npub}/{repo-id} -> gitea repo`
- pre-receive companion hook installation into provisioned repositories via Gitea's `hooks/pre-receive.d/` chain
- `grasp-pre-receive` hook binary that validates pushed refs against latest kind `30618`
- cryptographic ID/signature validation for relay events used in provisioning and hook checks
- multi-maintainer state acceptance (maintainers from NIP-34 announcements)
- Phase 3 integration assets:
  - gitea config snippet (`deploy/gitea/app.ini.phase3.snippet`)
  - canonical nginx vhost (`deploy/nginx/gitea-vhost.conf.example`)
  - hardened compose overlay (`deploy/docker-compose.hardening.yml`)
- experimental Hive-CI trigger/execution path for owner-authored workflows; the standard image does **not** bundle `act` or a container runtime, so operators must explicitly provide `HIVE_CI_ACT_PATH` and its runtime before enabling it
- admin API:
  - `GET /health`
  - `GET /metrics`
  - `GET /mappings`
  - `GET /outbound-events` (admin view of pending/retry/dead-letter user-signed queue items)
  - `POST /signer/authorize` (admin-authorized NIP-46 bunker grant creation)
  - `POST /provision`

## Quick start

```bash
cp .env.example .env
make build
./bin/grasp-bridge
```

## Environment

```bash
GITEA_URL=http://gitea:3000
GITEA_ADMIN_TOKEN=<token>
CLONE_PREFIX=https://git.sharegap.net
RELAY_URLS=ws://gastown-relay:3334
HOOK_RELAY_URL=ws://grasp-bridge:3334
HOOK_BINARY_PATH=/opt/grasp/grasp-pre-receive
GRASP_HOOK_ADMIN_URL=http://grasp-bridge:8090
GRASP_HOOK_ADMIN_TOKEN_FILE=/run/secrets/grasp-admin-api-token
GITEA_REPOSITORIES_PATH=/gitea-data/git/repositories
EMBEDDED_RELAY=false
EMBEDDED_RELAY_PORT=3334
EMBEDDED_RELAY_DB=/data/relay-db
LISTEN=:8090
DB_PATH=./mappings.db
PUBKEY_ALLOWLIST=
PROVISION_RATE_LIMIT=10
ADMIN_API_TOKEN=<admin bearer token>
BRIDGE_PUBLIC_URL=https://bridge.example.com
CHALLENGE_TTL=5m
SIGNET_BUNKER_URL=<Signet/NIP-46 bunker URL>
# Development-only fallback; do not set in production without SIGNET_BUNKER_URL.
BRIDGE_NSEC=<operator nsec>
GITEA_WEBHOOK_SECRET=<webhook HMAC secret>
SIGNER_MASTER_KEY=<32-byte base64 or hex key, optional>
PROACTIVE_SYNC_INTERVAL=1h
GRASP05_ARCHIVE_MODE=false
GRASP_HOOK_TIMEOUT=15s
GRASP_HOOK_MAX_NOSTR_UPDATES=16
GRASP_HOOK_MAX_NOSTR_REFS=256
GRASP_HOOK_MAX_PACK_BYTES=268435456
GRASP_HOOK_MAX_OBJECTS=50000
GRASP_HOOK_MAX_OBJECT_BYTES=536870912
GRASP_HOOK_MAX_SINGLE_OBJECT_BYTES=67108864
```

`SIGNER_MASTER_KEY` enables the persistent NIP-46 signer subsystem. With it set, owner and contributor events are unsigned templates until the outbound queue obtains the user's bunker signature. Without it, the bridge intentionally remains in legacy bridge-signed transition mode for bridge-originated owner state; contributor events from unlinked actors are skipped and counted as `unlinked_actor_skipped`.

## User-signed NIP-34 model

- Repository announcements (`kind:30617`) remain owner-signed and are cached/rebroadcast verbatim.
- Repository state (`kind:30618`) is owner-signed through the owner's NIP-46 grant and the outbound queue; if the signer subsystem is disabled, the bridge-signed fallback remains available for compatibility.
- Contributor-authored webhook events (`1617`, `1618`, `1619`, `1621`, `1630`-`1633`, `1985`, and NIP-22 `1111` comments) are signed by the acting user's linked grant. If the actor has not linked a signer, the event is skipped, not bridge-signed, and `unlinked_actor_skipped` is incremented.
- CI workflow-run events (`kind:5401`) remain operator-signed as executor attestations, using `SIGNET_BUNKER_URL` in production; `BRIDGE_NSEC` is development fallback only.

### Signer and queue admin endpoints

`POST /signer/authorize` creates a persistent signer grant from a NIP-46 bunker URI. It requires the admin bearer token and accepts:

```json
{"bunker_uri":"bunker://..."}
```

The response includes the authorized user pubkey, bridge client pubkey, relays, and grant timestamp. Grants are encrypted at rest with `SIGNER_MASTER_KEY`.

`GET /outbound-events?limit=50` returns the admin queue view for unsigned templates waiting on user signatures, retrying after offline signers, or dead-lettered after repeated failure. See [`docs/user-signed-operations.md`](docs/user-signed-operations.md) for the short operations runbook.

## Compatibility and limitations

- Events emitted before this migration and signed by historical `BRIDGE_NSEC` are not re-signed.
- Unlinked actor events are retained in a bounded pending queue and backfilled when that Gitea user links a NIP-46 signer; rows trimmed by the queue's age/count bounds cannot be recovered.
- Nostr patches/PRs (kind 1617/1618) are reflected as Gitea pull requests, and kind 1619 PR updates move the existing reflected PR head when the root event is known.
- `maintainers` on `30617` is owner-driven; the bridge honors owner announcements and will not add maintainers itself.
- Kind `10317` owner-list cache/rebroadcast is tracked separately (`phase1-kyg`).

## Hook behavior

`grasp-pre-receive`:

- accepts `refs/nostr/<event-id>` only for commit tips within the configured per-push/ref/object/byte quotas
- rejects `refs/heads/pr/*` (must be sent over nostr refs)
- for `refs/heads/*` and `refs/tags/*`, requires exact SHA match with latest NIP-34 state event
- rejects push when no state event exists
- applies one 15-second end-to-end verification deadline and closes relay resources
- deletes stale temporary refs after 20 minutes and runs bounded, grace-period Git cleanup

## Self-contained test container

Run this to execute the bridge test suite in a single container (no live services required):

```bash
make selftest
```

## Build modes

- Sidecar/default build:

```bash
make build-sidecar
```

- Full build with embedded relay:

```bash
make build-full
```

- Compose examples:
  - Sidecar mode: `docker-compose.phase1.yml`
  - Embedded relay mode (Mode A): `docker-compose.mode-a.yml`
  - Security/hook/session overlay: `deploy/docker-compose.hardening.yml`

The hardened overlay installs `grasp-pre-receive` into an executable volume mounted read-only in the Gitea container and mounts the same admin-token secret used by the bridge. Hook relay/admin URLs use container-network addresses, not `localhost` or the public edge.

## Nostr web login

The canonical deployment supports real Gitea sessions after NIP-07 or NIP-46 verification. The bridge returns a 30-second, audience-bound, single-use handoff tied to an HttpOnly SameSite cookie; nginx consumes it internally and sends `X-Grasp-Auth-User` to Gitea for exactly one request. Gitea then writes its ordinary session cookie. Keep bridge auth and Gitea on the same HTTPS origin, keep Gitea private, and clear the reverse-auth header on every other proxy route as shown in the canonical nginx example. Redirect targets are normalized same-origin absolute paths only. The Android button fetches the NIP-55 challenge and launches the returned `nostrsigner:` URI.

## Phase 3 notes

- Ensure Gitea `ROOT_URL` equals the canonical single-host origin.
- Ensure proxy forwards `Host` and `X-Forwarded-Proto` headers.
- Follow `docs/phase3-e2e-checklist.md` to validate ngit init + push accept/reject behavior.
- Use the automation helper:

```bash
GITEA_PUBLIC_URL=https://git.sharegap.net \
BRIDGE_ADMIN_URL=http://localhost:8090 \
NPUB=npub1... \
REPO_ID=myrepo \
make phase3-e2e
```

- Save results to `docs/phase3-e2e-report.md`.

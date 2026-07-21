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
  - nginx vhost (`deploy/nginx/git.sharegap.net.conf`)
  - e2e checklist (`docs/phase3-e2e-checklist.md`)
- Hive CI trigger publishing (ContextVM `ci/workflow-run`) when repo changes reveal CI workflows
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
HOOK_RELAY_URL=ws://localhost:3334
HOOK_BINARY_PATH=/usr/local/bin/grasp-pre-receive
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
- Events created before a contributor links a signer are not backfilled; unlinked webhook actors are skipped (`phase1-5ud`).
- Nostr patches/PRs (kind 1617/1618) are reflected as Gitea pull requests: the referenced tip is fetched (or a format-patch is applied via a temporary worktree + `git am`) onto a head branch and a Gitea PR is opened against the base branch (`phase1-2gq`). PR-update (kind 1619) branch-tip updates remain a follow-up.
- `maintainers` on `30617` is owner-driven; the bridge honors owner announcements and will not add maintainers itself.
- Kind `10317` owner-list cache/rebroadcast is tracked separately (`phase1-kyg`).

## Hook behavior

`grasp-pre-receive`:

- accepts `refs/nostr/<event-id>` when event id is valid hex
- rejects `refs/heads/pr/*` (must be sent over nostr refs)
- for `refs/heads/*` and `refs/tags/*`, requires exact SHA match with latest NIP-34 state event
- rejects push when no state event exists

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

## Phase 3 notes

- Ensure gitea `ROOT_URL` is `https://git.sharegap.net`.
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

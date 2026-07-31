# grasp-bridge

A Nostr interoperability bridge for Gitea: repositories are announced and
authorized over NIP-34, and a Nostr identity can authenticate to Gitea over
HTTP without ever holding Gitea credentials.

> **Upgrading?** Read [`docs/UPGRADING.md`](docs/UPGRADING.md) first. In
> particular, `deploy/nginx/gitea-vhost.conf.example` now describes
> **full-proxy** mode; the previous topology moved to
> `deploy/nginx/gitea-vhost.legacy.conf.example`.

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
- Nostr authentication for Gitea HTTP surfaces (opt-in, see below):
  - NIP-98-authenticated bridge tokens (`grasp_v1_…`) minted, listed, revoked, and rotated over HTTP
  - a streaming reverse proxy that exchanges `npub + token` for a hidden, encrypted, per-user Gitea PAT
  - private repository clone/push over HTTP with a Nostr identity
- Phase 3 integration assets:
  - gitea config snippet (`deploy/gitea/app.ini.phase3.snippet`)
  - full-proxy nginx vhost (`deploy/nginx/gitea-vhost.conf.example`)
  - pre-cutover / rollback nginx vhost (`deploy/nginx/gitea-vhost.legacy.conf.example`)
  - hardened compose overlay (`deploy/docker-compose.hardening.yml`)
  - full-proxy compose overlay (`deploy/docker-compose.fullproxy.yml`)
- experimental Hive-CI trigger/execution path for owner-authored workflows; the standard image does **not** bundle `act` or a container runtime, so operators must explicitly provide `HIVE_CI_ACT_PATH` and its runtime before enabling it
- admin API:
  - `GET /health` (liveness only)
  - `GET /ready` (readiness: store, plus Gitea reachability in full-proxy mode; unauthenticated, for healthchecks)
  - `GET /metrics`
  - `GET /mappings`
  - `GET /outbound-events` (admin view of pending/retry/dead-letter user-signed queue items)
  - `POST /signer/authorize` (admin-authorized NIP-46 bunker grant creation)
  - `POST /provision`
- bridge token API (only when `BRIDGE_TOKENS_ENABLED=true`; each call needs a fresh single-use NIP-98 proof):
  - `POST /auth/token`
  - `GET /auth/tokens`
  - `DELETE /auth/tokens/{id}`
  - `POST /auth/tokens/{id}/rotate`

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

# Nostr web login (NIP-07/46/55). Required for the token API.
AUTH_ENABLED=false

# Scoped Gitea service identity used for the unauthenticated public GRASP
# path. Anonymous access is only served when the repository is public.
GIT_BACKEND_USER=
GIT_BACKEND_PASSWORD=

# --- Nostr authentication for all Gitea surfaces (opt-in) ------------------
# Enable in this order: full proxy + nginx cutover first, tokens afterwards.
# See docs/fullproxy-cutover-runbook.md.

# Route ALL Gitea traffic through the bridge. Requires the full-proxy nginx
# config and an unpublished Gitea port.
GITEA_FULL_PROXY_ENABLED=false
# Authenticates the nginx session-handoff continuation. Must be >= 43 chars of
# high-entropy random data: openssl rand -base64 32
GRASP_EDGE_SHARED_SECRET=
# NIP-98-authenticated bridge tokens exchanged for hidden per-user Gitea PATs.
BRIDGE_TOKENS_ENABLED=false
# Login owning GITEA_ADMIN_TOKEN; Gitea's user-token endpoints need Basic auth.
GITEA_ADMIN_USER=
# AES-256-GCM key ring protecting hidden PATs at rest, newest first:
#   current:<base64 32 bytes>[,previous:<base64 32 bytes>]
# BACK THIS UP: losing every key makes stored PATs undecryptable.
GRASP_CREDENTIAL_KEYS=
BRIDGE_TOKEN_TTL_DEFAULT=720h
BRIDGE_TOKEN_TTL_MIN=1h
BRIDGE_TOKEN_TTL_MAX=2160h
AUTH_AUDIT_RETENTION=2160h
# Graceful shutdown. Must outlast in-flight pushes; your orchestrator's stop
# timeout must exceed this (was hardcoded to 5s before this release).
SHUTDOWN_GRACE=5m
```

`SIGNER_MASTER_KEY` enables the persistent NIP-46 signer subsystem. With it set, owner and contributor events are unsigned templates until the outbound queue obtains the user's bunker signature. Without it, the bridge intentionally remains in legacy bridge-signed transition mode for bridge-originated owner state; contributor events from unlinked actors are skipped and counted as `unlinked_actor_skipped`.

## Nostr authentication for Gitea HTTP surfaces

Off by default. When enabled, a Nostr identity authenticates to Gitea without
ever holding a Gitea credential.

**How it works.** The user signs a NIP-98 event to `POST /auth/token` and gets
back an opaque `grasp_v1_…` token. They then use it as an ordinary HTTP
credential:

```bash
git clone https://<npub>:<grasp_v1_token>@git.example.com/owner/private-repo.git
```

The bridge authenticates the token at the edge, checks its scopes against the
requested surface, and forwards the request to Gitea using a hidden per-user
Personal Access Token that it provisions and encrypts at rest. The bridge
token itself never reaches Gitea, and the user never sees the PAT.

**Requirements.** This only works when the bridge fronts all of Gitea
(`GITEA_FULL_PROXY_ENABLED=true`) and Gitea is unreachable from outside the
private network. Otherwise a client could bypass the bridge and present
credentials directly, defeating scope enforcement — so the bridge refuses to
start with `BRIDGE_TOKENS_ENABLED=true` unless full-proxy mode is on.

**Scopes.** Tokens carry an explicit closed set of scopes. Currently enabled:
`git:read`, `git:write`, `packages:read`, and `packages:write`. The
`packages:*` scopes cover the `/api/packages/` registry family (npm, PyPI,
Cargo, Maven, Composer, NuGet, generic, …) regardless of how the client
presents the token — npm's `Bearer`, PyPI's Basic password, Cargo's raw
`Authorization` value, NuGet's `X-NuGet-ApiKey`, and token-in-username Basic
all work.

Docker/OCI works through the standard token flow: `docker login` with the
npub as username and a bridge token as password exchanges Basic credentials
at the `/v2` token endpoint for Gitea's short-lived registry JWT. The
bridge maps the docker-requested access to bridge scopes (`pull` →
`packages:read`; `push`/`delete` → `packages:write`; unknown actions fail
closed) and rewrites the challenge realm to the public origin. The JWT
itself passes through untouched — its short lifetime is the revocation
bound after a bridge token is revoked.

`api:*` and `lfs:*` are reserved for later phases and are rejected until
their adapters land. A token used on a surface without an adapter fails
with `403` rather than being forwarded.

Hidden PATs are provisioned with the matching Gitea scope union
(`write:repository`, `write:package`). A PAT provisioned by an older
deployment is automatically re-provisioned with the wider scopes the next
time it is needed (create-before-retire; the stale PAT is deleted from
Gitea by the retirement sweep).

**Lifecycle.** Tokens expire (default 30 days, bounded by
`BRIDGE_TOKEN_TTL_MIN`/`MAX`), can be revoked or rotated, and are stored only
as SHA-256 digests. Hidden PATs are retired 24 hours after a user's last token
stops being usable. NIP-98 proofs are single-use and bound to the exact
request URL and body.

See [`docs/fullproxy-cutover-runbook.md`](docs/fullproxy-cutover-runbook.md)
to enable this, and [`docs/UPGRADING.md`](docs/UPGRADING.md) for what changes.

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

- **Anonymous GRASP access now requires the repository to be publicly
  readable.** Private and Gitea-*internal* repositories return `401` on the
  public `/<npub>/<repo>.git` path instead of being served by the backend
  service identity. Authenticated access needs a bridge token.
- **Mapped repositories are verified before being served**: provisioning must
  have completed (hook installed) and the live Gitea repository ID must match
  the mapping, so a deleted-and-recreated repository is not served under the
  original coordinate.
- Bridge tokens are enforced only on surfaces the proxy has an adapter for.
  Phase 1 covers Git; package registries, the REST API, and LFS still pass
  ordinary Gitea credentials through unchanged and reject bridge tokens.
- Scale-out is not supported: session handoffs and NIP-46 bindings are
  in-process and SQLite is local. Run one bridge instance.
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
  - Full-proxy cutover overlay: `deploy/docker-compose.fullproxy.yml` (adds the
    credential key ring and edge secret; apply only during the cutover)

The hardened overlay installs `grasp-pre-receive` into an executable volume mounted read-only in the Gitea container and mounts the same admin-token secret used by the bridge. Hook relay/admin URLs use container-network addresses, not `localhost` or the public edge.

## Nostr web login

The canonical deployment supports real Gitea sessions after NIP-07 or NIP-46 verification. The bridge returns a 30-second, audience-bound, single-use handoff tied to an HttpOnly SameSite cookie; nginx consumes it internally and forwards the trusted `X-Grasp-Auth-User` for exactly one request. In full-proxy mode that continuation goes through the bridge and is authenticated with `GRASP_EDGE_SHARED_SECRET`, so only the edge can assert an identity. Gitea then writes its ordinary session cookie. Keep bridge auth and Gitea on the same HTTPS origin, keep Gitea private, and clear the reverse-auth header on every other proxy route as shown in the canonical nginx example. Redirect targets are normalized same-origin absolute paths only. The Android button fetches the NIP-55 challenge and launches the returned `nostrsigner:` URI.

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

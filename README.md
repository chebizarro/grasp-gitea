# grasp-bridge

A Go bridge that makes Gitea usable as a GRASP/NIP-34-backed git server.

## Current scope

The bridge handles **inbound** NIP-34 relay events and enforces push validation:

- relay subscriber for NIP-34 repository announcements (kind `30617`) and state (kind `30618`)
- automatic Gitea org/repo provisioning when an announcement includes a clone URL under `CLONE_PREFIX`
- automatic repo archival when a later announcement removes this server from `clone` tags
- proactive sync listener for repository state events (best-effort local ref update)
- SQLite mapping store for `{npub, repo-id}` → Gitea repo metadata
- pre-receive hook installation into provisioned repositories
- `grasp-pre-receive` hook binary that validates pushed refs against latest kind `30618`
- cryptographic ID/signature validation for all consumed relay events
- multi-maintainer state acceptance (maintainers from NIP-34 announcement graph)
- optional embedded Khatru relay behind the `full` build tag

### Owner-path resolution

Provisioned repos are **not** created under raw `npub` org names. The bridge resolves a short, Gitea-safe org name:

1. Fetch the user's kind `0` profile from a relay
2. Extract and verify the `nip05` field resolves back to the same pubkey
3. Sanitize the NIP-05 local-part for Gitea username rules, truncate to 39 chars
4. If NIP-05 resolution fails, fall back to the first 39 hex chars of the pubkey

This avoids Gitea's 40-character API username limit. The canonical identity remains the `npub` in the SQLite mapping.

### Admin API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/metrics` | GET | Bearer | In-memory metric counters (JSON) |
| `/mappings` | GET | Bearer | List all stored mappings |
| `/provision` | POST | Bearer | Trigger manual provisioning |

When `ADMIN_API_TOKEN` is set, `/metrics`, `/mappings`, and `/provision` require a `Bearer` token. When unset, all endpoints are open (backwards-compatible).

### Not implemented yet

The bridge does **not** currently:

- publish outbound NIP-34 events (announcements, state, patches, PRs, issues)
- provide Nostr-based authentication (NIP-07/NIP-46/NIP-55)
- handle webhook-driven event publishing
- sync Nostr profiles to Gitea

See the [backlog](.beads/issues.jsonl) for planned work.

## Quick start

```bash
cp .env.example .env
make build
./bin/grasp-bridge
```

## Environment

```bash
GITEA_URL=http://gitea:3000
GITEA_ADMIN_TOKEN=<token>              # required
CLONE_PREFIX=https://git.example.com   # required — your public git domain
RELAY_URLS=ws://gastown-relay:3334     # required (even for embedded mode, see caveat below)
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
ADMIN_API_TOKEN=                       # optional — enables bearer auth on admin endpoints
```

### Embedded relay caveat

`config.Load()` currently requires `RELAY_URLS` to be non-empty, even when `EMBEDDED_RELAY=true`. This means fully embedded-only operation requires providing at least one relay URL. Tracked as [phase3-006](.beads/issues.jsonl).

## Hook behavior

`grasp-pre-receive`:

- accepts `refs/nostr/<event-id>` when event id is valid hex (no state check required)
- rejects `refs/heads/pr/*` (must be sent over nostr refs)
- for `refs/heads/*` and `refs/tags/*`, requires exact SHA match with latest NIP-34 state event
- rejects push when no state event exists (for state-checked refs only)

## Self-contained test container

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

- Ensure Gitea `ROOT_URL` matches your `CLONE_PREFIX`.
- Ensure proxy forwards `Host` and `X-Forwarded-Proto` headers.
- Follow `docs/phase3-e2e-checklist.md` to validate ngit init + push accept/reject behavior.
- Use the automation helper:

```bash
GITEA_PUBLIC_URL=$CLONE_PREFIX \
BRIDGE_ADMIN_URL=http://localhost:8090 \
NPUB=npub1... \
REPO_ID=myrepo \
make phase3-e2e
```

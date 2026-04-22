# grasp-bridge

Phase 1 + Phase 2 + Phase 3 implementation currently provides:

- relay subscriber for NIP-34 repository announcements (kind `30617`)
- automatic Gitea org/repo provisioning for clone URLs matching `CLONE_PREFIX`
- automatic repo archival when a later announcement removes this server from `clone` tags
- proactive sync listener for repository state events (best-effort local ref update)
- SQLite mapping store for `{npub}/{repo-id} -> gitea repo`
- pre-receive hook installation into provisioned repositories
- `grasp-pre-receive` hook binary that validates pushed refs against latest kind `30618`
- cryptographic ID/signature validation for relay events used in provisioning and hook checks
- multi-maintainer state acceptance (maintainers from NIP-34 announcements)
- Phase 3 integration assets:
  - gitea config snippet (`deploy/gitea/app.ini.phase3.snippet`)
  - nginx vhost template (`deploy/nginx/gitea-vhost.conf.example`)
  - e2e checklist (`docs/phase3-e2e-checklist.md`)
- admin API:
  - `GET /health`
  - `GET /metrics`
  - `GET /mappings`
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
CLONE_PREFIX=https://git.example.com  # required — your public git domain
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
```

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

- Ensure gitea `ROOT_URL` matches your `CLONE_PREFIX`.
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

- Save results to `docs/phase3-e2e-report.md`.

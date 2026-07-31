# Upgrading

Breaking and behaviour-changing updates, newest first.

---

## Nostr authentication for all Gitea surfaces (full-proxy bridge)

This release adds NIP-98-authenticated bridge tokens and makes the bridge
capable of fronting all of Gitea. **Existing deployments keep working without
changes** — every new capability is off by default — but several defaults and
behaviours changed, and one file changed meaning.

### 1. `deploy/nginx/gitea-vhost.conf.example` now means FULL PROXY

**If you re-copy this file during an upgrade, you will cut over to full-proxy
mode unintentionally**, and it will not work until the bridge is configured
for it (the file removes the `gitea_backend` upstream entirely).

- Staying on the current topology: use
  **`deploy/nginx/gitea-vhost.legacy.conf.example`**, which is the previous
  config unchanged apart from added documentation and a `/ready` route.
- Cutting over: follow
  [`docs/fullproxy-cutover-runbook.md`](fullproxy-cutover-runbook.md). Do not
  copy the file without reading it.

### 2. Graceful shutdown now defaults to 5 minutes

Shutdown was previously hardcoded to 5 seconds, which killed in-flight pushes
on every deploy. It is now `SHUTDOWN_GRACE` (default `5m`).

**Action required if you orchestrate the bridge**: your stop timeout must
exceed it, or the supervisor will `SIGKILL` mid-drain. For Compose set
`stop_grace_period` higher than `SHUTDOWN_GRACE` (the full-proxy overlay uses
`6m`); for Kubernetes set `terminationGracePeriodSeconds`. To keep the old
behaviour, set `SHUTDOWN_GRACE=5s` — but expect interrupted pushes.

### 3. Anonymous GRASP access fails closed on non-public repositories

Anonymous requests to canonical `/<npub>/<repo>.git` paths are served with the
bridge's `GIT_BACKEND_USER` service identity. That identity's own Gitea
permissions previously decided the outcome, so a repository that became
private could still be served if the service account could read it.

Anonymous access now requires the repository to be **publicly readable**, and
returns `401` otherwise. This excludes Gitea's *internal* visibility
(`private=false` but owned by a private organization), which still requires an
authenticated user.

**Impact**: if you relied on the service account to expose non-public
repositories over the public GRASP path, those requests now fail. Make the
repository public, or have clients authenticate with a bridge token.

### 4. Mapped repositories are verified before being served

Requests to `/<npub>/<repo>.git` now require that:

- provisioning completed and `grasp-pre-receive` is installed
  (`hook_installed`), and
- the live Gitea repository ID still matches the stored mapping.

A repository that was deleted and recreated at the same path no longer serves
under the original NIP-34 coordinate, because it has no GRASP hook and a push
would bypass Nostr authority enforcement.

**Impact**: mappings left half-provisioned by an interrupted run now return
`404` instead of serving; a mismatched repository returns `502`. Re-run
provisioning (the bridge reconciles hooks at startup) or repair the mapping.

### 5. Stricter configuration validation (fails at startup)

Invalid combinations that were previously accepted now prevent start-up:

| Condition | Requirement |
|---|---|
| `BRIDGE_TOKENS_ENABLED=true` | requires `AUTH_ENABLED=true`, `GITEA_FULL_PROXY_ENABLED=true`, `GRASP_CREDENTIAL_KEYS`, `GITEA_ADMIN_USER`, `BRIDGE_PUBLIC_URL` |
| `GITEA_FULL_PROXY_ENABLED=true` + `AUTH_ENABLED=true` | requires `GRASP_EDGE_SHARED_SECRET` |
| `GRASP_EDGE_SHARED_SECRET` set | at least 43 characters (32 random bytes encoded) |
| `BRIDGE_TOKEN_TTL_*` | default must fall within min/max, min ≤ max |

Tokens cannot be minted without full-proxy mode because their scopes would not
be enforced on surfaces that bypass the bridge.

### 6. Database schema additions

Four tables are added (`bridge_tokens`, `gitea_pat_credentials`,
`nip98_replay_claims`, `auth_audit_events`) plus a `gitea_token_id` column on
`gitea_pat_credentials`. Migrations are additive and idempotent; older binaries
ignore the new tables, so rollback is safe.

### 7. New endpoints

- `GET /ready` — unauthenticated readiness (store, and in full-proxy mode
  Gitea reachability). Point container healthchecks here rather than
  `/health`, which only proves the process is alive.
- `POST /auth/token`, `GET /auth/tokens`, `DELETE /auth/tokens/{id}`,
  `POST /auth/tokens/{id}/rotate` — bridge token management, each requiring a
  fresh single-use NIP-98 proof. Present only when `BRIDGE_TOKENS_ENABLED=true`.

### 8. Forwarded headers in full-proxy mode

The bridge gives Gitea the canonical public `Host` and `X-Forwarded-Host` /
`X-Forwarded-Proto` derived from `BRIDGE_PUBLIC_URL`, rather than the
client-supplied `Host`. `X-Forwarded-For` preserves the chain nginx built and
appends the bridge, but only when the immediate peer is a private address.

**Action**: `BRIDGE_PUBLIC_URL` must be correct before enabling full proxy, or
Gitea will generate wrong URLs.

### 9. Embedders only: Go API changes

- `api.New` no longer takes Gitea backend credentials from config directly;
  it builds a `giteaproxy.Proxy` internally. Inject a fully wired one with
  `Server.SetGiteaProxy`.
- `gitea.NewClient(...).WithAdminUser(login)` is required before the PAT
  lifecycle methods work, because Gitea gates those endpoints behind Basic
  auth.

### Rolling back

Restore `deploy/nginx/gitea-vhost.legacy.conf.example` **and** set both
`GITEA_FULL_PROXY_ENABLED=false` and `BRIDGE_TOKENS_ENABLED=false`. Disabling
only one leaves token scopes unenforced on the surfaces that bypass the
bridge. See the runbook's rollback section for what happens to already-issued
tokens and hidden PATs.

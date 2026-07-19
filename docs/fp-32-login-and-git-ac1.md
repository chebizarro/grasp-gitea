# fp-32: Gitea Nostr login and GIT-AC1 evidence

## Deployment handoff

The bridge is an OIDC provider for Gitea. Keep the client secret in the deployment
secret store; do not put it in Git or command history.

Required bridge inputs:

```text
AUTH_ENABLED=true
BRIDGE_PUBLIC_URL=https://grasp.sharegap.net
OAUTH2_CLIENT_ID=gitea-nostr
OAUTH2_CLIENT_SECRET=<secret-store reference>
OAUTH2_REDIRECT_URI=https://git.sharegap.net/user/oauth2/nostr/callback
```

Register the matching authentication source from inside the Gitea 1.26.1
container, with `OAUTH2_CLIENT_SECRET` injected by the secret store:

```sh
gitea admin auth add-oauth \
  --name 'Nostr' \
  --provider openidConnect \
  --key gitea-nostr \
  --secret "$OAUTH2_CLIENT_SECRET" \
  --auto-discover-url https://grasp.sharegap.net/.well-known/openid-configuration
```

The command and flags were checked against Gitea tag `v1.26.1` source. Do not
enable the source until bridge discovery passes; do not capture the expanded
secret in shell tracing, process listings, logs, or evidence.

Prechecks:

```sh
curl -fsS https://grasp.sharegap.net/health
curl -fsS https://grasp.sharegap.net/.well-known/openid-configuration
curl -fsS https://git.sharegap.net/api/v1/version
```

Verify that Gitea's sign-in page shows the new source, complete one login with an
approved disposable NIP-07 identity, log out, then repeat with its NIP-46 bunker.
Both flows must return through `/user/oauth2/nostr/callback` and establish a Gitea
session. The NIP-46 bridge client uses an ephemeral key; no server nsec is read or
stored by either login flow.

Rollback is configuration-only: remove/disable the Gitea auth source, set
`AUTH_ENABLED=false`, and redeploy the prior bridge image. The SQLite additions are
additive and may remain; existing Gitea repositories, users, sessions, and data are
not rewritten.

## Verification record — 2026-07-18

Read-only live checks before change:

- Gitea reported version `1.26.1` at `/api/v1/version`.
- `https://grasp.sharegap.net/health` returned `200 {"status":"ok"}`.
- OIDC discovery returned 404, confirming the session handoff was not deployed.
- `POST /auth/nip46/init` with an empty JSON object returned 400, confirming the
  existing NIP-46 route was mounted; source inspection showed its production
  connector was `nil`.

Source verification:

```sh
go test ./...
go vet ./...
git diff --check
```

The local host lacked a C compiler, so SQLite/CGO tests fail closed with the known
`go-sqlite3 requires cgo` stub error. Non-SQLite packages, including bridge config
and command wiring, compile and pass. The repository CI/build environment remains
the full gate.

GIT-AC1 push evidence:

- Gitea accepted `netward/fp-32` at commit
  `0a59abb8219d90b605a03ff97c3621c9e209239e` and reported `Processing 1
  references` / `Processed 1 references in total`.
- Relay event `d465280fa75a9d9a2c89581b82a17dee2068bdf51f9bb5be272a448067490aec`
  is kind 30618, `d=grasp-gitea`, and contains
  `refs/heads/netward/fp-32=0a59abb8219d90b605a03ff97c3621c9e209239e`.
- Independent go-nostr verification returned `computed ID == event ID`,
  `CheckID=true`, and `CheckSignature=true`.
- A relay query for kinds 30617/30618 with `d=grasp-gitea` returned the new
  30618 and older 30618 states, but no 30617. This is a real remaining gap: the
  mapping has no relay-visible owner announcement to republish. Do not synthesize
  one with a server key. GIT-AC1 is therefore not fully met until the owner signs
  and publishes the canonical 30617 and a subsequent push proves both records.

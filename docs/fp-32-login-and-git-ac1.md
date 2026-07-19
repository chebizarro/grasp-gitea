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

GIT-AC1 is recorded after pushing this branch: retain the pushed commit SHA,
webhook delivery response/log entry, and the relay-returned kind 30617 and 30618
event IDs. Validate each event's computed ID and Schnorr signature before accepting
the result. A 30617 may be a republished cached owner-signed announcement; 30618 is
the bridge-signed pushed-ref state.

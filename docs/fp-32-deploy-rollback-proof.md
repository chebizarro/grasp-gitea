# fp-32 offline deploy, rollback, and live-proof runbook

This runbook prepares the fp-32 change window. It does not authorize changing
live Gitea, production trust, the repository owner identity, or Signet custody.
Run the live sections only after explicit owner approval.

## Offline build and signer-mode proof

```sh
git switch netward/fp-32-next
git status --short --branch
git rev-parse HEAD
git diff --check
docker build -f Dockerfile.selftest -t grasp-gitea:fp-32-selftest .
docker run --rm grasp-gitea:fp-32-selftest

# Both inputs must fail closed before any network connection is attempted.
docker run --rm \
  -e GITEA_ADMIN_TOKEN=test \
  -e CLONE_PREFIX=https://git.invalid \
  -e RELAY_URLS=wss://relay.invalid \
  -e BRIDGE_NSEC=nsec1invalid \
  -e BRIDGE_SIGNER_BUNKER_URI=bunker://invalid \
  grasp-gitea:fp-32-selftest \
  go test ./internal/config -run '^TestPublisherSignerInputsAreMutuallyExclusive$' -count=1

docker run --rm grasp-gitea:fp-32-selftest \
  go test ./internal/config -run '^TestPublisher(RawKey|Bunker)ModeEnabled$' -count=1
```

## Approved change-window backup

Resolve deployment paths and container names before copying anything. These
commands are templates with deliberately required variables.

```sh
set -eu
: "${DEPLOY_DIR:?set the grasp-gitea deployment directory}"
: "${GITEA_CONTAINER:?set the Gitea container name}"
: "${BRIDGE_CONTAINER:?set the bridge container name}"
BACKUP_DIR="${DEPLOY_DIR}/backups/fp-32-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$BACKUP_DIR"

docker inspect "$GITEA_CONTAINER" >"$BACKUP_DIR/gitea.inspect.json"
docker inspect "$BRIDGE_CONTAINER" >"$BACKUP_DIR/bridge.inspect.json"
docker compose -f "$DEPLOY_DIR/docker-compose.yml" config \
  >"$BACKUP_DIR/compose.rendered.yml"
cp -a "$DEPLOY_DIR/.env" "$BACKUP_DIR/env.backup"
chmod 0600 "$BACKUP_DIR/env.backup"

# Gitea's built-in dump is the application-consistent data backup.
docker exec --user git "$GITEA_CONTAINER" gitea dump \
  --file /tmp/fp-32-gitea-dump.zip
docker cp "$GITEA_CONTAINER:/tmp/fp-32-gitea-dump.zip" \
  "$BACKUP_DIR/gitea-dump.zip"
docker exec "$GITEA_CONTAINER" rm -f /tmp/fp-32-gitea-dump.zip
sha256sum "$BACKUP_DIR"/* >"$BACKUP_DIR/SHA256SUMS"
printf '%s\n' "$BACKUP_DIR"
```

Do not print `.env`, the OIDC secret, `BRIDGE_NSEC`, or a bunker URI. In the
approved deployment choose exactly one publisher signer mode:

```text
# Preferred Signet mode
BRIDGE_NSEC=
BRIDGE_SIGNER_BUNKER_URI=<injected secret reference>

# Temporary raw-key compatibility mode (owner approval required)
BRIDGE_NSEC=<injected secret reference>
BRIDGE_SIGNER_BUNKER_URI=
```

Render and validate the candidate without starting it:

```sh
docker compose -f "$DEPLOY_DIR/docker-compose.yml" config --quiet
docker compose -f "$DEPLOY_DIR/docker-compose.yml" build grasp-bridge
docker compose -f "$DEPLOY_DIR/docker-compose.yml" run --rm --no-deps \
  grasp-bridge /bin/sh -c 'test -n "${BRIDGE_NSEC:-}${BRIDGE_SIGNER_BUNKER_URI:-}"; test -z "${BRIDGE_NSEC:-}" || test -z "${BRIDGE_SIGNER_BUNKER_URI:-}"'
```

## Rollback

Rollback the bridge and auth-source exposure first; do not rewrite repositories,
users, owner events, or Signet identities.

```sh
set -eu
: "${DEPLOY_DIR:?set deployment directory}"
: "${BACKUP_DIR:?set the verified fp-32 backup directory}"
cp -a "$BACKUP_DIR/env.backup" "$DEPLOY_DIR/.env"
docker compose -f "$DEPLOY_DIR/docker-compose.yml" up -d --no-deps grasp-bridge
docker compose -f "$DEPLOY_DIR/docker-compose.yml" ps grasp-bridge
curl -fsS https://grasp.sharegap.net/health
```

If the approved change created or enabled the Gitea OAuth source, disable or
delete that source using the exact recorded source ID before restoring service.
Restoring the Gitea dump is a last resort and must be separately approved because
it overwrites application state created after the backup.

## Approved live proof

Set non-secret evidence inputs without shell tracing:

```sh
set +x
export RELAY_URL=wss://relay.sharegap.net
export BRIDGE_URL=https://grasp.sharegap.net
export GITEA_URL=https://git.sharegap.net
export REPO_D=grasp-gitea
export OWNER_PUBKEY=cdee943cbb19c51ab847a66d5d774373aa9f63d287246bb59b0827fa5e637400
export EXPECTED_REF=refs/heads/netward/fp-32-next
export EXPECTED_SHA="$(git rev-parse netward/fp-32-next)"
```

1. Prove OIDC surfaces before exposing the login source:

```sh
curl -fsS "$BRIDGE_URL/health"
curl -fsS "$BRIDGE_URL/.well-known/openid-configuration" | jq -e \
  --arg issuer "$BRIDGE_URL" '.issuer == $issuer and .authorization_endpoint and .token_endpoint and .userinfo_endpoint'
curl -fsS "$GITEA_URL/api/v1/version" | jq -e '.version'
```

2. With an owner-approved disposable identity, complete one NIP-07 login and one
NIP-46 login. Record only timestamps, HTTP status, callback path, resulting Gitea
username, and logout success. Never record tokens, cookies, nsecs, or bunker URIs.

3. The owner must publish canonical kind `30617`, `d=grasp-gitea`, signed by
`$OWNER_PUBKEY`. Do not synthesize or re-sign it with the bridge key. Then push
the expected branch through the normal Gitea path so the bridge emits `30618`.

4. Query the relay with an approved Nostr CLI and save JSON to a protected
evidence directory. Verify both events independently:

```sh
: "${NOSTR_QUERY_CMD:?set command that writes matching relay events as JSONL}"
EVIDENCE_DIR="$(mktemp -d)"
chmod 0700 "$EVIDENCE_DIR"
sh -c "$NOSTR_QUERY_CMD" >"$EVIDENCE_DIR/nip34.jsonl"
jq -e --arg owner "$OWNER_PUBKEY" --arg d "$REPO_D" \
  'select(.kind == 30617 and .pubkey == $owner and any(.tags[]; .[0] == "d" and .[1] == $d))' \
  "$EVIDENCE_DIR/nip34.jsonl" >/dev/null
jq -e --arg ref "$EXPECTED_REF" --arg sha "$EXPECTED_SHA" --arg d "$REPO_D" \
  'select(.kind == 30618 and any(.tags[]; .[0] == "d" and .[1] == $d) and any(.tags[]; .[0] == $ref and .[1] == $sha))' \
  "$EVIDENCE_DIR/nip34.jsonl" >/dev/null
: "${NOSTR_VERIFY_CMD:?set independent event ID/signature verifier command}"
sh -c "$NOSTR_VERIFY_CMD '$EVIDENCE_DIR/nip34.jsonl'"
sha256sum "$EVIDENCE_DIR/nip34.jsonl"
```

The placeholders `NOSTR_QUERY_CMD` and `NOSTR_VERIFY_CMD` must be replaced by
Gus's fp-ops.1 interface when delivered. fp-ops.2 is complete only when that
interface proves relay receipt, computed IDs, Schnorr signatures, owner pubkey,
`d` tag, expected ref, and expected SHA.

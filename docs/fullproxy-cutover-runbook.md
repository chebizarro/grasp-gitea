# Full-proxy cutover runbook

How to switch grasp-gitea from "nginx fronts Gitea" to "the bridge fronts
Gitea", which is what makes Nostr authentication work on Gitea surfaces beyond
the public GRASP npub paths.

**This is the highest-risk change in the project.** After it, the bridge is on
the critical path for every Gitea request. Read the whole document before
starting, and do it during a maintenance window.

## What changes

Before:

```
client -> nginx -+-> grasp-bridge   (GRASP npub paths, /auth/*, admin APIs)
                 `-> gitea          (UI, REST, packages, LFS, conventional git)
```

After:

```
client -> nginx -> grasp-bridge -> gitea      (everything)
                `-> grasp-bridge:3334         (relay WebSocket at "/")
```

The bridge can then authenticate `npub + grasp_v1_ token` on any surface it
has an adapter for, exchanging it for a hidden per-user Gitea PAT. Git and
the `/api/packages/` registry family (npm Bearer, PyPI/Maven/Composer/generic
Basic, Cargo raw token, NuGet `X-NuGet-ApiKey`) have adapters; Docker/OCI
`/v2`, REST, and LFS adapters follow. Hidden PATs carry
`write:package, write:repository`; credentials provisioned before package
support are rotated automatically on next use.

## Prerequisites

1. **Gitea must be unreachable from outside the private network.** Remove any
   published port. If a client can reach Gitea directly, it can present a
   hidden PAT's full authority and bypass every bridge scope check. This is
   the single most important precondition.

   Compose merges `ports` additively, so an overlay cannot remove a
   publication declared in the base file — delete it there. Verify:

   ```bash
   docker compose config | grep -A5 'gitea:' | grep -i published   # expect no output
   ```

   Then confirm from a host **outside** the deployment network that the port
   is closed. Checking from inside proves nothing.

2. **Validate the deployed Gitea image** (issue `phase1-z88`). Confirm against
   the exact image you run:
   - `POST /api/v1/users/{username}/tokens` works with **Basic** auth using
     the admin login + admin PAT. The `Authorization: token` header does not
     work: Gitea gates this route behind `reqBasicOrRevProxyAuth`.
   - The PAT scope string `write:repository` is accepted by
     `AccessTokenScope.Normalize`.
   - Git smart HTTP accepts a PAT as the Basic password.
   - `ENABLE_REVERSE_PROXY_AUTHENTICATION = true` and
     `REVERSE_PROXY_AUTHENTICATION_USER = X-Grasp-Auth-User` are set
     (`deploy/gitea/app.ini.phase3.snippet`).
   - `ROOT_URL` equals the canonical public origin.

3. **Generate the edge shared secret.** It authorizes arbitrary
   `X-Grasp-Auth-User` impersonation, so it must be high-entropy:

   ```bash
   openssl rand -base64 32
   ```

   Set it as `GRASP_EDGE_SHARED_SECRET` on the bridge and in the nginx
   `/auth/session/handoff` location. The bridge rejects anything shorter than
   43 characters.

4. **Generate the credential key ring** protecting hidden PATs at rest:

   ```bash
   echo "current:$(openssl rand -base64 32)"
   ```

   Set as `GRASP_CREDENTIAL_KEYS`. Back it up: losing every key makes existing
   hidden PATs undecryptable, and they must then be deleted from Gitea and
   re-provisioned.

## Cutover

Do these in order. Steps 1–3 are reversible with no user impact.

### 1. Deploy the bridge with full proxy on, tokens off

Apply the full-proxy overlay, which carries the new secrets and settings:

```bash
mkdir -p ./secrets
echo "current:$(openssl rand -base64 32)" > ./secrets/grasp-credential-keys
openssl rand -base64 32 > ./secrets/grasp-edge-shared-secret
chmod 600 ./secrets/grasp-credential-keys ./secrets/grasp-edge-shared-secret

GITEA_ADMIN_USER=<admin login> \
docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.hardening.yml \
  -f deploy/docker-compose.fullproxy.yml \
  up -d grasp-bridge
```

The overlay defaults to `GITEA_FULL_PROXY_ENABLED=true` and
`BRIDGE_TOKENS_ENABLED=false`, which is exactly this step. It is a separate
file because Compose fails when a declared secret file is missing, so the base
hardening overlay keeps working for deployments that have not cut over.

nginx is still on the legacy config, so the new fallback carries no traffic
yet. Confirm the bridge starts and reports ready — `/ready` now includes an
upstream reachability probe:

```bash
docker compose exec grasp-bridge wget -qO- http://127.0.0.1:8090/ready
```

Query it on the bridge directly rather than through the public origin: until
the cutover, the public `/ready` may not be routed to the bridge.

### 2. Switch nginx

```bash
cp deploy/nginx/gitea-vhost.conf.example /etc/nginx/conf.d/gitea.conf
# Edit every YOUR_DOMAIN occurrence, the certificate paths, and
# REPLACE_WITH_GRASP_EDGE_SHARED_SECRET (must match ./secrets/grasp-edge-shared-secret).
# YOUR_DOMAIN appears in the redirect and handoff audience on purpose: those
# must not be derived from the client-supplied Host header.
nginx -t && nginx -s reload
```

The config was written without a running nginx available, so `nginx -t` is the
first real syntax validation it gets. Do not skip it.

`nginx -t` must pass before reloading. A failed reload leaves the old config
running, which is safe.

### 3. Verify

```bash
PUBLIC_URL=https://git.example.com \
NPUB=npub1... REPO_ID=myrepo \
./scripts/fullproxy-cutover-verify.sh
```

Then work through the manual checks the script prints — especially a **large**
clone and push, which is what proves nothing buffers the pack. Watch bridge
and nginx memory during it.

### 4. Enable bridge tokens

Only after step 3 is clean:

```
BRIDGE_TOKENS_ENABLED=true
AUTH_ENABLED=true
GITEA_ADMIN_USER=<admin login owning GITEA_ADMIN_TOKEN>
GRASP_CREDENTIAL_KEYS=current:<base64 32 bytes>
```

The bridge refuses to start with tokens enabled unless full proxy, auth, the
key ring, the admin user, and the public URL are all configured — minting
tokens without downstream isolation would let their scopes be bypassed.

Mint one token and re-run the verification script with `BRIDGE_TOKEN` and
`TOKEN_NPUB` set.

## Rollback

If anything is wrong, roll back immediately; do not debug in production.

```bash
cp deploy/nginx/gitea-vhost.legacy.conf.example /etc/nginx/conf.d/gitea.conf
# edit YOUR_DOMAIN and certificate paths
nginx -t && nginx -s reload
```

Then on the bridge set:

```
GITEA_FULL_PROXY_ENABLED=false
BRIDGE_TOKENS_ENABLED=false
```

**Both are required.** In the legacy topology, conventional git, package, and
API requests bypass the bridge, so bridge-token scopes are not enforced on
those surfaces.

After rolling back:

- Bridge tokens stop working as soon as the bridge restarts with the token
  service disabled: the proxy still recognizes the `grasp_v1_` prefix and
  rejects it locally rather than forwarding it. Clients using them will get
  401s until they switch back to ordinary Gitea credentials.
- Token rows and hidden PATs are not deleted. Hidden PATs remain valid inside
  Gitea until the retirement sweep removes them (24h after a user's last token
  stops being usable) or an operator deletes the Gitea tokens named
  `grasp-bridge-<userID>-<generation>`. If the rollback was security-motivated,
  delete them immediately rather than waiting for the sweep.

## Operating notes

**Availability.** The bridge is now a single point of failure for all of
Gitea. Supervise it with automatic restart, wire the container healthcheck to
`/ready` (not `/health`, which only proves the process is alive), and keep
`SHUTDOWN_GRACE` long enough for in-flight pushes — 5 minutes is a reasonable
default. A shorter grace kills active uploads on every deploy.

**Timeouts.** The streaming locations use one-hour read/send timeouts because
large clones legitimately take that long. The bridge deliberately has no
whole-request timeout for the same reason.

**Scaling out** is not supported yet: session handoffs and NIP-46 bindings are
in-process and SQLite is local. Running two bridge replicas requires sticky
sessions at minimum, and properly requires shared storage (issue `phase1-boe`).

**Logs.** Token-bearing routes (`/auth/token`, `/auth/tokens*`,
`/auth/session/nip46/status`) have `access_log off` because their credentials
appear in headers or query strings. Verify no token, PAT, or `Authorization`
value appears in nginx or bridge logs after cutover.

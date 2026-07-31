# Oracle Plan

## 3.2 Credential extraction and translation

### Incoming credential precedence

The proxy must classify credentials before classifying the downstream surface:

1. **Trusted session handoff**
   - Accepted only when nginx supplies both the handoff marker and a valid edge shared secret.
   - Forward using `X-Grasp-Auth-User`; remove all other caller authentication headers.
2. **Bridge token in Basic**
   - Decode Basic credentials with a strict size limit.
   - Treat the password as a bridge token only when it begins with `grasp_v1_`.
   - Require the username to equal either the token subject’s canonical `npub` or linked `GiteaUser`.
   - A mismatch is `401`; never ignore the username and authenticate solely by password.
3. **Bridge token in Bearer**
   - Treat `Authorization: Bearer grasp_v1_…` as a bridge token.
4. **Registry-specific token header**
   - Recognize the prefix in headers such as Cargo’s raw `Authorization` value or `X-NuGet-ApiKey`.
5. **Direct NIP-98**
   - Recognize `Authorization: Nostr <base64-event>` only on routes explicitly eligible for direct NIP-98.
6. **Existing Gitea credentials**
   - On ordinary Gitea paths, non-bridge Basic, Bearer, token, cookies, and protocol tokens pass through unchanged for backward compatibility.
   - On canonical npub paths, they remain stripped as today.
7. **No credential**
   - Ordinary paths pass through anonymously.
   - Canonical npub smart HTTP uses the existing service identity only after confirming the mapped repository is currently public.

If a credential has the bridge prefix but is invalid, expired, revoked, or insufficiently scoped, fail locally. Never fall back to anonymous or pass the credential to Gitea.

### Uniform public credential shape

Users receive one opaque bridge token and use it as:

- Basic: username = canonical npub, password = bridge token.
- Bearer: `Authorization: Bearer <bridge-token>`.
- Raw registry token/API-key fields: the bridge token alone.

The proxy converts that credential into the protocol-specific downstream presentation of the same hidden per-user Gitea PAT.

### Surface/action classifier

Add a closed internal classification:

```text
Surface:
  git | packages | container | api | lfs | web | unknown

Action:
  read | write | token_exchange | session
```

Classification must use path, method, and only bounded protocol metadata. It must run before authentication so scope checks are deterministic.

#### Git smart HTTP

| Request | Required bridge scope | Downstream credential |
|---|---|---|
| `GET .../info/refs?service=git-upload-pack` | `git:read` | Basic `GiteaUser:PAT` |
| `POST .../git-upload-pack` | `git:read` | Basic `GiteaUser:PAT` |
| `GET .../info/refs?service=git-receive-pack` | `git:write` | Basic `GiteaUser:PAT` |
| `POST .../git-receive-pack` | `git:write` | Basic `GiteaUser:PAT` |

Reject missing or unsupported `service` values rather than guessing. Both conventional `/<owner>/<repo>.git/...` and mapped `/<npub>/<repo-id>.git/...` use this classifier.

For mapped npub paths:

- Valid bridge token: rewrite the repository path and inject the subject PAT.
- No bridge token:
  1. Fetch current repository metadata through the admin client.
  2. Require `Repository.Private == false`.
  3. Inject the existing `GitBackendUser`/`GitBackendPassword`.
  4. Preserve the pre-receive hook as the push authorization boundary.
- Invalid bridge-prefixed credential: return `401`.
- Non-bridge credentials: preserve existing behavior by stripping them and using the anonymous path, provided the repository is public.

Do not cache public visibility in Phase 1; a stale cache could expose a repository immediately after it becomes private.

#### npm

Paths under Gitea’s npm package route, expected to be `/api/packages/{owner}/npm/...`:

- Accept `Bearer grasp_v1_…`.
- Require `packages:read` for metadata/tarball downloads and `packages:write` for publish, unpublish, and mutation requests.
- Forward as `Authorization: Bearer <PAT>`, subject to validation against the deployed Gitea version.
- Preserve non-bridge npm tokens unchanged.

#### Cargo

Cargo uses a token-shaped authorization value rather than consistently using Basic:

- Accept a raw `Authorization: grasp_v1_…` value and, where supported by the client, `Bearer grasp_v1_…`.
- Rewrite to the exact raw/Bearer PAT form documented by the deployed Gitea version.
- Sparse-index and crate downloads require `packages:read`.
- Publish/yank/unyank require `packages:write`.
- Do not classify all Cargo POST requests as writes without route-specific tests; sparse protocol queries can be read operations.

#### PyPI

- `pip`/index downloads may be anonymous or Basic-authenticated.
- `twine` upload uses Basic username/password.
- Accept npub plus bridge token in Basic and forward `GiteaUser:PAT`.
- GET/HEAD require `packages:read`; upload and delete operations require `packages:write`.

#### Docker/OCI `/v2`

Docker requires a two-stage flow:

1. Docker requests `/v2/`; Gitea returns a Bearer challenge.
2. Docker follows the challenge realm/token endpoint, usually `/v2/token`, and submits login Basic credentials.
3. The bridge validates npub plus bridge token, forwards `GiteaUser:PAT` to Gitea, and Gitea issues its short-lived registry token.
4. Subsequent Docker requests carry that Gitea-issued Bearer token. Because it does not have the `grasp_v1_` prefix, the bridge passes it through unchanged.

Rules:

- Rewrite `WWW-Authenticate` realm URLs only when their origin equals the configured Gitea origin; replace that origin with `BridgePublicURL`.
- Classify the token endpoint from the actual challenge emitted by the deployed Gitea version rather than assuming its path.
- Parse requested Docker token scopes such as `repository:owner/image:pull,push`:
  - `pull` requires `packages:read`.
  - `push` and `delete` require `packages:write`.
  - Unknown actions fail closed.
- Revoking a bridge token prevents new registry tokens but cannot invalidate an already-issued Gitea registry token. Configure Gitea’s registry-token lifetime to the shortest operationally reasonable value, targeted at five minutes, and document that as the revocation bound.
- Helm OCI uses this same adapter.

#### Other Gitea package registries

Implement adapters by credential family rather than one handler per package format:

| Credential family | Gitea registries | Translation |
|---|---|---|
| HTTP Basic | Maven/Gradle, Composer, Generic, Go via `.netrc`, Helm chart HTTP, Conan where Basic is configured, Debian/RPM/Alpine authenticated uploads, PyPI | npub/token → Gitea user/PAT |
| Bearer | npm and any version-confirmed Bearer registries | bridge Bearer → PAT Bearer |
| Raw token | Cargo and registry-specific token fields | bridge token → PAT in the same header form |
| API-key header | NuGet and any version-confirmed API-key clients | `X-NuGet-ApiKey: bridge-token` → PAT |
| Docker token exchange | Container and Helm OCI | Basic only at exchange; pass Gitea registry token afterward |

The implementation must inventory every package format exposed by the exact Gitea version and add a fixture/integration test for its documented authentication form. An unknown package path carrying a bridge-prefixed token must return `403 unsupported bridge credential surface`, not forward the token.

#### REST API

Added after package/tooling phases:

- `GET` and `HEAD` require `api:read`.
- Mutating methods require `api:write`.
- Bridge Bearer becomes the documented Gitea API form, preferably `Authorization: token <PAT>` unless the deployed version confirms equivalent Bearer behavior.
- Hidden PATs never receive Gitea `admin` scopes. Gitea remains responsible for repository, organization, and object-level ACL checks.

#### Git LFS

Added after REST:

- LFS batch requests are bounded JSON:
  - `operation: download` requires `lfs:read`.
  - `operation: upload` requires `lfs:write`.
- Actual object GET requires `lfs:read`; PUT/POST upload requires `lfs:write`.
- Object bodies remain streaming.
- Forward Basic `GiteaUser:PAT` or the Gitea-issued LFS authorization form confirmed by integration tests.
- Rewrite backend-origin transfer URLs to `BridgePublicURL`.

## 3.3 Bridge token service

### `auth.TokenService`

Add a long-lived service in `internal/auth/token_service.go`, owned by `main`:

```text
Mint(ctx, verifiedPrincipal, request) -> MintResult, error
Authenticate(ctx, plaintextToken) -> TokenPrincipal, error
List(ctx, pubkey, page) -> []TokenMetadata, error
Revoke(ctx, pubkey, tokenID) -> error
Rotate(ctx, pubkey, tokenID, request) -> MintResult, error
```

It composes:

- `auth.Service` for NIP-98 verification.
- `IdentityService` for Nostr-to-Gitea resolution.
- `SQLiteStore` for tokens, replay claims, PAT records, and audit.
- `gitea.Client` for PAT creation/deletion and user existence checks.
- A credential cipher/key ring.
- Per-user striped locks to prevent duplicate PAT creation in the current single-process deployment.

### Token format

Use:

```text
grasp_v1_<43-character-base64url-secret>
```

- Secret: 32 random bytes from `crypto/rand`.
- Encoding: unpadded base64url.
- Prefix and exact encoded length are validated before database access.
- Store `SHA-256(full plaintext token)` as a 32-byte BLOB with a unique index.
- SHA-256 is sufficient because tokens have 256 bits of entropy; no low-entropy password hashing is needed.
- Return the plaintext only in the successful mint/rotate response.
- Token listings expose a separate random token ID and the last six display characters, never the digest.

### Closed scope set

Initial scope enum:

```text
git:read
git:write
packages:read
packages:write
api:read
api:write
lfs:read
lfs:write
```

Rules:

- Scopes are stored sorted and deduplicated.
- No implicit “write includes read” rule; clients request both when both are needed.
- Phase 1 enables only `git:read` and `git:write`.
- API requests for scopes not enabled by the running deployment return `400`.
- Do not use `nostrauthz` for general repository attenuation. Gitea ACLs govern private repositories and packages; `nostrauthz` and the pre-receive hook continue to govern canonical GRASP push authority.
- Do not introduce repository-specific token resources in these phases. They would require reliable path-to-resource classification across every registry and would duplicate Gitea ACLs.

### TTL and refresh

Configuration:

- Default token TTL: 30 days.
- Minimum: 1 hour.
- Maximum: 90 days.
- Requested TTL is rejected if outside bounds rather than silently clamped.
- Expiration is checked against UTC at every authentication.

No separate refresh token is introduced. Refresh is rotation authenticated by a fresh NIP-98 proof:

```text
POST /auth/tokens/{id}/rotate
```

Rotation atomically revokes the old bridge token and stores a replacement with the requested TTL/scopes. If persistence fails, the old token remains usable and no new plaintext is returned.

### HTTP API

Add `auth.TokenHandler` with:

| Endpoint | Authentication | Behavior |
|---|---|---|
| `POST /auth/token` | Fresh replay-protected NIP-98 | Mint token; default scope `git:read` if omitted |
| `GET /auth/tokens` | Fresh replay-protected NIP-98 | Paginated metadata for the signing pubkey |
| `DELETE /auth/tokens/{id}` | Fresh replay-protected NIP-98 | Revoke owned token |
| `POST /auth/tokens/{id}/rotate` | Fresh replay-protected NIP-98 | Revoke and replace |

Mint body shape:

```text
name: string, 1–80 characters
scopes: array of known scope strings
ttl_seconds: integer
```

Limits:

- Maximum body: 16 KiB.
- Maximum 50 active tokens per pubkey.
- List page size: default 50, maximum 100.
- Names are metadata only and need not be unique.
- Responses set `Cache-Control: no-store` and `Pragma: no-cache`.
- Mint/rotate responses include the plaintext token once, token ID, scopes, and expiration.
- List responses include state: `active`, `expired`, or `revoked`.
- Revoke is ownership-filtered; unknown or other-user IDs return `404`.
- Store failures return `503`; Gitea PAT provisioning failures return `502` without exposing Gitea bodies.

### SQLite schema

Add tables through `store.Open` and place CRUD methods in `internal/store/auth_tokens.go`.

#### `bridge_tokens`

```text
id                 TEXT PRIMARY KEY
token_hash         BLOB NOT NULL UNIQUE
token_suffix       TEXT NOT NULL
pubkey             TEXT NOT NULL
gitea_user_id      INTEGER NOT NULL
name               TEXT NOT NULL
scopes             TEXT NOT NULL       -- sorted JSON array
issued_at          TEXT NOT NULL
expires_at         TEXT NOT NULL
revoked_at         TEXT NOT NULL DEFAULT ''
last_used_at       TEXT NOT NULL DEFAULT ''
created_event_id   TEXT NOT NULL
```

Indexes:

- `(pubkey, issued_at DESC)`
- `(pubkey, revoked_at, expires_at)`
- `(gitea_user_id, revoked_at, expires_at)`

Update `last_used_at` at most once per five-minute window to avoid a SQLite write for every package/blob request. Dropped usage updates do not affect authorization.

#### `gitea_pat_credentials`

```text
gitea_user_id      INTEGER NOT NULL
generation         INTEGER NOT NULL
gitea_user         TEXT NOT NULL
pat_name           TEXT NOT NULL UNIQUE
pat_ciphertext     BLOB NOT NULL
key_id             TEXT NOT NULL
gitea_scopes       TEXT NOT NULL
state              TEXT NOT NULL        -- provisioning|active|retiring|orphaned|error
created_at         TEXT NOT NULL
activated_at       TEXT NOT NULL DEFAULT ''
retired_at         TEXT NOT NULL DEFAULT ''
delete_attempts    INTEGER NOT NULL DEFAULT 0
last_error         TEXT NOT NULL DEFAULT ''
PRIMARY KEY (gitea_user_id, generation)
```

Add a partial unique index allowing one `active` credential per user.

#### `nip98_replay_claims`

```text
event_id           TEXT PRIMARY KEY
pubkey             TEXT NOT NULL
method             TEXT NOT NULL
target_hash        BLOB NOT NULL
claimed_at         TEXT NOT NULL
expires_at         TEXT NOT NULL
```

#### `auth_audit_events`

```text
id                 INTEGER PRIMARY KEY AUTOINCREMENT
occurred_at        TEXT NOT NULL
event_type         TEXT NOT NULL
pubkey             TEXT NOT NULL DEFAULT ''
token_id           TEXT NOT NULL DEFAULT ''
gitea_user_id      INTEGER NOT NULL DEFAULT 0
surface            TEXT NOT NULL DEFAULT ''
action              TEXT NOT NULL DEFAULT ''
outcome             TEXT NOT NULL
request_id          TEXT NOT NULL DEFAULT ''
source_fingerprint  TEXT NOT NULL DEFAULT ''
detail              TEXT NOT NULL DEFAULT ''
```

Store no token, PAT, Authorization header, raw NIP-98 event, query secret, or sensitive request body. Apply a configurable 90-day audit retention job.

### Concurrency and atomicity

- Authentication is read-only except throttled `last_used_at`.
- Minting obtains a per-Gitea-user striped lock before ensuring a PAT.
- Bridge token insert and active-token limit enforcement occur in one SQLite transaction.
- Replay claiming uses `INSERT OR IGNORE`; zero affected rows means replay.
- External Gitea PAT creation cannot participate in the SQLite transaction:
  - Record the encrypted PAT as `provisioning`.
  - Promote it to `active` only after the row is durable.
  - If persistence fails after Gitea creation, immediately attempt deletion and record an operator-visible error if deletion also fails.
- Request cancellation stops PAT API work where possible. A PAT already created before cancellation must still be encrypted/persisted or deleted; do not abandon an untracked Gitea PAT.

## 3.4 Hidden Gitea PAT lifecycle

### Gitea client additions

Extend `internal/gitea/client.go` with version-validated methods:

```text
CreateUserAccessToken(ctx, username, name, scopes) -> AccessToken
DeleteUserAccessToken(ctx, username, tokenName) -> error
```

`AccessToken` contains the returned plaintext only in memory plus its server identifier/name if available.

Also add `Repository.Private` to `gitea.Repository` and decode the `private` response field.

Before Phase 1, validate against the deployed Gitea version:

- Administrator-created user-token endpoint path.
- Delete-by-name versus delete-by-ID semantics.
- Exact PAT scope strings.
- Whether Git Basic accepts the PAT as password.
- Whether creating a PAT returns plaintext only once.

Do not fall back to saving, resetting, or using `IdentityService`’s random user password.

### PAT granularity and scopes

Use one active hidden PAT per linked Gitea user, not one PAT per bridge token.

Rationale: per-token PATs would multiply durable high-value secrets and Gitea token objects, while bridge scopes and revocation are already enforced before the shared PAT is exposed downstream.

PAT scopes are the minimum union required by enabled bridge features:

- Phase 1: Gitea repository read/write scopes.
- Package phase: add package read/write scopes through PAT rotation.
- REST phase: add only non-admin API scope families needed by the supported API.
- LFS: repository scopes if Gitea does not expose separate LFS scopes.

The bridge’s own administrator token is never used to proxy a user request.

### Encryption at rest

Add a dedicated credential-key ring; do not reuse `SignerMasterKey`.

Configuration shape:

```text
GRASP_CREDENTIAL_KEYS=current-id:<base64-32-bytes>,older-id:<base64-32-bytes>
```

- First key is active for encryption.
- Remaining keys are decryption-only.
- Production startup fails if token authentication is enabled without a valid key.
- Encrypt PATs with AES-256-GCM and a fresh 12-byte nonce.
- Authenticate AAD containing the Gitea user ID, generation, PAT name, and key ID.
- Store nonce plus ciphertext in `pat_ciphertext`.
- Re-encrypt records using the active key lazily on successful use and through a maintenance command/job.
- Never log plaintext, include it in errors, or serialize it outside the Gitea request header.

### Rotation and cleanup

PAT rotation is create-before-retire:

1. Create a new uniquely named PAT, using a stable bridge instance prefix and increasing generation.
2. Encrypt and persist it as `provisioning`.
3. Atomically switch the prior `active` row to `retiring` and the new row to `active`.
4. Delete the old PAT through Gitea.
5. Mark it retired; failed deletion remains retryable.

When the last active bridge token for a user is revoked or expires, schedule PAT retirement after a 24-hour grace period. A new token minted during the grace period cancels retirement.

When a Gitea user is missing or its ID no longer matches the identity link:

- Mark PAT rows `orphaned`.
- Revoke every bridge token for that Gitea user.
- Treat Gitea PAT deletion returning `404` as successful cleanup.
- Do not automatically adopt or recreate a same-named account; return `409 identity link requires operator repair`.

A downstream `401` after the proxy injected a hidden PAT indicates bridge credential failure, not caller failure. Do not retry a streamed request. Sanitize the challenge, return `502`, audit the credential fault, and require controlled PAT reconciliation/rotation.

## 3.5 Direct NIP-98 on proxied requests

### Verification interface

Extend `auth.Service` additively:

```text
VerifyNIP98(event, method, target)                    // retained
VerifyNIP98WithPayload(event, method, target, payload) // new
VerifyAndClaimNIP98(ctx, event, method, target, payload) // new orchestration
```

Both verification paths must use `cascadia-go/nip98`. The bridge must not implement separate signature, URL, timestamp, or payload-tag semantics.

Canonical target construction uses `BridgePublicURL` plus the incoming escaped path and raw query. Never derive the verification origin from public `Host` or `X-Forwarded-*` headers.

### Replay protection

For every token-management or direct proxy NIP-98 request:

1. Parse and validate the event.
2. Validate method, canonical target, freshness, signature, and payload hash where required.
3. Atomically insert its event ID into `nip98_replay_claims`.
4. Continue only if the insert succeeds.

Claims expire after the verifier freshness window plus clock-skew allowance. A cleanup job may delete older rows because replayed events will then fail freshness. If replay-claim persistence is unavailable, fail closed with `503`.

A verified event whose downstream operation later fails remains consumed; the caller must sign a new event.

### Safe eligibility rules

Direct NIP-98 is allowed only when verification does not undermine streaming:

- GET and HEAD with no request body.
- Bounded REST JSON requests with known `Content-Length` no larger than 1 MiB.
- Bounded protocol-control JSON such as a future LFS batch request.
- Token-service JSON, limited to 16 KiB.

For bounded bodies:

1. Wrap in `MaxBytesReader`.
2. Read exact raw bytes once.
3. Verify the NIP-98 payload tag against those bytes.
4. Restore an equivalent reader for downstream forwarding.

Reject direct NIP-98 with `400` or `413` on:

- Git upload-pack or receive-pack POSTs.
- Docker blob upload PATCH/PUT.
- Package artifact publication/upload bodies.
- LFS object transfer.
- Chunked or unknown-length bodies.
- Bodies over the route limit.
- `Expect: 100-continue` streaming requests.

A direct NIP-98 proof authorizes only that exact request and has no reusable scope object. After identity/PAT resolution, Gitea ACLs decide object authorization. Direct NIP-98 should be enabled for REST and safe metadata routes only after their route classifiers are complete; Phase 1 uses NIP-98 only for token management.

## 3.6 nginx cutover

### Routing model

After Phase 1, nginx has one public application upstream: `grasp_bridge_backend`. Gitea remains reachable only by the bridge on the private network.

Retain special nginx locations only for:

- Session handoff/auth subrequest.
- Log suppression for token-bearing auth/status routes.
- Public npub push rate limits.
- Large streaming limits/timeouts.
- Optional relay-specific connection limits.

All ordinary Gitea UI, Git, API, package, LFS, and `/v2` requests proxy to the bridge.

### Session handoff

Keep `auth_request`, but change the successful main request from direct Gitea proxying to bridge proxying:

```text
browser /auth/session/handoff
  → nginx auth_request /_grasp_session_handoff_consume
  → bridge consumes one-time handoff
  → nginx obtains user + redirect
  → nginx proxies redirected request to bridge with trusted session marker
  → bridge strips marker and forwards X-Grasp-Auth-User to Gitea
```

The handoff request must include:

- `X-Grasp-Session-Proxy: 1`
- `X-Grasp-Auth-User: <auth_request result>`
- `X-Grasp-Edge-Secret: <deployment secret>`

Every other public location overwrites these headers with empty values. The bridge accepts them only after constant-time verification of `GRASP_EDGE_SHARED_SECRET`. Restrict bridge network exposure as defense in depth.

The selected `main.go` does not visibly register `SessionHandoffHandler`; Phase 1 must explicitly register it and add an integration test proving `/auth/session/handoff/consume` is reachable when auth is enabled.

### Root relay

Send `/` to bridge in all cases. In `api.Server`:

- WebSocket upgrade at `/` → `rootRelayHandler`.
- `Accept: application/nostr+json` at `/` → `rootRelayHandler`.
- Ordinary browser `/` → `giteaproxy.Proxy`.

Forward `Upgrade` and `Connection` through nginx. This removes nginx/Gitea split-brain routing while retaining GRASP-01 relay negotiation.

### Buffering and timeouts

For all requests to bridge:

- `proxy_request_buffering off`.
- HTTP/1.1 upstream.
- Preserve `Authorization` and cookies.
- Strip all internal/reverse-auth headers.
- Forward canonical client/protocol headers.

For Git, `/v2`, package uploads, and LFS:

- `proxy_buffering off`.
- Long `proxy_read_timeout` and `proxy_send_timeout`, targeted at one hour.
- No nginx retry after body transmission.
- Docker/LFS blob routes use `client_max_body_size 0` or a deployment-defined storage limit large enough for supported artifacts.
- Preserve the existing 256 MiB public npub receive-pack limit unless the operator deliberately changes it.
- Rely on Gitea repository/package quotas and nginx connection/rate limits for resource control.

Ordinary UI/static responses may retain nginx response buffering.

### Header policy

Public locations must clear at least:

```text
X-Grasp-Auth-User
X-Grasp-Session-Proxy
X-Grasp-Internal-Handoff
X-Grasp-Handoff-Token
X-Grasp-Handoff-Audience
X-Grasp-Edge-Secret
X-WEBAUTH-USER
X-Forwarded-User
Proxy-Authorization
```

The bridge repeats this stripping before forwarding. nginx should set `X-Forwarded-Proto`, `X-Forwarded-Host`, and the client IP chain; the bridge must trust these only from configured nginx CIDRs.

## 3.7 Security and operational hardening

### Upstream isolation and SSRF prevention

- Parse `GiteaURL` once at startup and require HTTP/HTTPS with a fixed host.
- Disable environment proxy use in the streaming transport.
- Reject `CONNECT`, absolute-form proxy requests, unsupported schemes, and mismatched public hosts.
- Never use a request header, Docker challenge parameter, redirect, or query value to select the upstream.
- Rewrite backend-origin `Location`, Docker challenge realm, and LFS transfer URLs only after confirming they match the configured Gitea origin.
- Gitea must not publish a host port outside the private container/network boundary.

### Credential/header containment

- The Gitea administrator token is used only by `gitea.Client`.
- User PATs are injected only after successful bridge authentication and scope checks.
- Strip reverse-auth identity headers on every normal request.
- Strip `Nostr` authorization before forwarding.
- Remove the bridge credential before setting its replacement; never retain multiple Authorization values.
- Never include Authorization, cookies, NIP-98 events, package API keys, token endpoint query credentials, or PAT-bearing URLs in logs.
- Sanitize downstream `401` challenges when the injected hidden PAT failed.

### Public GRASP pushes

The anonymous npub behavior remains intentionally separate:

- Confirm repository is public on every anonymous smart-HTTP request.
- Inject only the existing narrow service identity.
- Preserve receive-pack rate and connection limits.
- Preserve `grasp-pre-receive` as the authority enforcement point.
- Authenticated pushes also continue through the same hook; Gitea ACL success does not bypass Nostr repository-state authorization.

### Audit and abuse controls

- Audit token mint, rotation, revocation, replay rejection, scope denial, PAT lifecycle faults, and successful write-class operations.
- Rate-limit token mint/rotate and repeated invalid bridge-token attempts by source and pubkey.
- Add metrics for active streams, bytes proxied, authentication outcomes, token state, PAT state, upstream latency, and upstream errors.
- Audit retention and expired token cleanup run under the main cancellation context.

### Availability/performance

The bridge becomes a single point of failure for all Gitea HTTP traffic. Phase 1 mitigations:

- Streaming rather than buffering.
- Shared connection-pooled transport.
- No whole-request timeout.
- nginx connection limits and backpressure.
- Increased file-descriptor/container limits.
- A `/ready` endpoint that checks SQLite and a bounded Gitea health request.
- Supervised restart and a documented nginx rollback configuration.
- Graceful shutdown longer than five seconds, configurable and targeted at five minutes for active uploads.

Do not introduce a PAT plaintext cache in Phase 1. Measure SQLite lookup and AES-GCM overhead first. If later required, use a small, time-bounded cache whose entries are invalidated on revocation/PAT rotation.

Active-active deployment remains deferred because session handoffs and NIP-46 bindings are in memory and SQLite is local. Before multiple bridge replicas, persist those records in shared storage or provide strict affinity, and use a shared transactional token/replay store.

## 3.8 Backward compatibility

The cutover must preserve:

- Existing NIP-07/46/55 login routes and response shapes.
- One-time, cookie-bound session handoff and Gitea browser session creation.
- Existing bridge administrative and webhook routes.
- Root relay WebSocket and NIP-11 behavior.
- Anonymous mapped npub clone/push for public repositories.
- Existing pre-receive authorization.
- Existing Gitea browser cookies.
- Existing direct Gitea Basic/PAT authentication on ordinary Gitea paths.
- Existing package clients using ordinary Gitea tokens.
- Existing REST clients using ordinary Gitea credentials.

Explicit bridge routes continue to win over the Gitea fallback. Bridge-token-looking credentials on unsupported surfaces fail locally; non-bridge credentials continue to Gitea.

Gate the new fallback with `GITEA_FULL_PROXY_ENABLED` during rollout:

- Land proxy code while nginx still routes ordinary Gitea traffic directly.
- Enable and test the bridge fallback.
- Cut nginx over last.
- Do not enable bridge token minting unless full proxying and downstream Gitea isolation are in place; otherwise the scope boundary could be bypassed using the hidden PAT if exposed through another route.

## 3.9 Phased delivery

### Phase 1 — Token service and private Git end to end

Deliver as four incremental PRs that form one deployment phase.

#### PR 1A: persistence, crypto, and PAT administration

- Add configuration for credential keys, token TTL bounds, edge secret, full-proxy flag, audit retention, and shutdown grace.
- Add the four SQLite tables and CRUD/transaction methods.
- Add PAT encryption/key rotation primitives.
- Extend `gitea.Client` with PAT lifecycle methods and `Repository.Private`.
- Add tests for migration idempotency, token hashing, encryption AAD, old-key decryption, active-PAT uniqueness, and Gitea API request shapes.
- Validate the exact Gitea PAT endpoints/scopes before merging.

This PR is independently compilable and does not alter routing.

#### PR 1B: token API and replay-safe NIP-98

- Add payload-aware shared NIP-98 verification.
- Add atomic replay claims.
- Add `TokenService` and `TokenHandler`.
- Implement mint/list/revoke/rotate for Git scopes.
- Reuse `IdentityService.ResolveOrCreate`.
- Explicitly register `SessionHandoffHandler`.
- Add cleanup/audit jobs.
- Test concurrent replay, concurrent mint, token active limits, expiration, ownership-filtered revocation, PAT creation failure, and plaintext-returned-once behavior.

This PR may expose token endpoints only behind a disabled feature flag until PR 1C/1D are deployed.

#### PR 1C: streaming proxy and Git translation

- Add `internal/giteaproxy`.
- Replace per-request construction of the npub reverse proxy with the shared streaming proxy.
- Add Basic bridge-token extraction and Git scope classification.
- Support private conventional and mapped Git URLs.
- Preserve anonymous mapped public access after live visibility checks.
- Preserve ordinary Gitea credentials on ordinary paths.
- Route ordinary `/` to Gitea unless relay negotiation is present.
- Add trusted handoff continuation through the proxy.
- Add integration tests using an `httptest` Gitea backend to prove bodies stream without pre-read.

#### PR 1D: nginx cutover and deployment validation

- Route all Gitea HTTP traffic through bridge.
- Preserve auth_request handoff.
- Add edge shared-secret injection/stripping.
- Apply streaming locations, limits, and timeouts.
- Remove direct public nginx-to-Gitea routes.
- Add rollback instructions and readiness checks.

Phase 1 acceptance tests:

1. Mint a Git read/write token using a valid payload-bound NIP-98 event.
2. List it without exposing plaintext.
3. Reject replay of the mint/list proof.
4. Clone a private repository using `npub` plus bridge token over conventional Gitea Git URL.
5. Clone the same private repository through a mapped npub URL.
6. Push when Gitea ACLs and pre-receive Nostr authority both allow it.
7. Deny insufficient scope, revoked token, expired token, wrong Basic username, missing Gitea ACL, and failed pre-receive authority.
8. Confirm anonymous public mapped clone/push remains unchanged.
9. Confirm anonymous access to a mapped repository fails immediately after it becomes private.
10. Confirm ordinary Gitea login, PAT Git access, web session handoff, relay WebSocket, and NIP-11 still work.
11. Confirm large receive-pack bodies are not buffered in nginx or the bridge.
12. Confirm Gitea/admin/user PAT values never appear in logs or responses.

### Phase 2 — Package registries

Split by protocol risk:

1. **2A: common adapters**
   - npm Bearer.
   - PyPI Basic.
   - Cargo raw token.
   - Generic/Maven/Composer Basic.
   - Enable `packages:read` and `packages:write`.
2. **2B: Docker/OCI**
   - Challenge rewriting.
   - Token endpoint Basic translation.
   - Requested pull/push scope enforcement.
   - Gitea registry-token passthrough and expiry validation.
3. **2C: remaining Gitea registry catalog**
   - NuGet API key.
   - Go, Conan, Debian, RPM, Alpine, RubyGems, Swift, Pub, Vagrant, CRAN/Conda, and every format supported by the deployed Gitea release.
   - Each format requires publish, authenticated download, insufficient-scope, revocation, and large-upload tests.

### Phase 3 — Client tooling

Add a `grasp` client command with:

- NIP-46/NIP-55-compatible token acquisition.
- `grasp auth list`, `revoke`, and `rotate`.
- `grasp git-credential` implementing Git’s credential-helper protocol.
- Host/path matching so credentials are sent only to the configured bridge origin.
- npm/Cargo/PyPI/Docker login/configuration helpers.
- OS credential-store integration where available; fallback file mode `0600`.
- No token in command-line arguments, process listings, shell history, or logs.

Default CLI token scope should be explicit by workflow: Git login requests `git:read` and optionally `git:write`; package login requests only the selected package scopes.

### Phase 4 — REST API and safe direct NIP-98

- Enable `api:read`/`api:write`.
- Add REST route/action classification and PAT scope rotation.
- Accept direct NIP-98 for GET/HEAD and bounded REST JSON only.
- Add replay, body-hash, URL/query canonicalization, and admin-scope denial tests.
- Keep ordinary Gitea API tokens compatible.

### Phase 5 — Git LFS

- Add LFS batch parsing and scope classification.
- Add streaming object transfer.
- Rewrite transfer URLs.
- Reject direct NIP-98 on object streams.
- Test multi-gigabyte-equivalent streaming with generated readers rather than retained buffers.

### Phase 6 — Scale and resilience

- Persist session handoffs/NIP-46 bindings in shared storage.
- Replace local SQLite token/replay coordination where active-active deployment is required.
- Add multiple bridge upstreams, load tests, graceful connection draining, and chaos/failure tests.
- Add automated PAT reconciliation, re-encryption, orphan cleanup, and registry-token revocation-bound monitoring.

# 4. File-by-file impact

## Existing files

### `internal/auth/auth.go`

- Add payload-aware verification and replay-claim orchestration.
- Retain `VerifyNIP98` unchanged for existing callers.
- Depend on new store replay methods.

### `internal/auth/identity.go`

- Keep `ResolveOrCreate` as the subject provisioning path.
- Add or expose validation needed to confirm an existing linked Gitea username still maps to the recorded user ID.
- Do not recreate or adopt deleted/replaced accounts automatically.

### `internal/auth/session_handoff.go`

- Preserve current handoff semantics.
- No public contract change.
- Add tests for trusted bridge continuation after nginx no longer fronts Gitea.

### `internal/api/server.go`

- Replace raw Gitea URL/backend credential ownership with a `giteaproxy.Proxy` dependency.
- Make `"/"` dispatch mapped npub, relay negotiation, or generic Gitea fallback.
- Retain explicit bridge route precedence.

### `internal/api/githttp_npub.go`

- Retain path parsing, mapping lookup, CORS, and landing pages.
- Delegate downstream proxying and credential policy to `giteaproxy.Proxy`.
- Remove duplicated per-request `httputil.ReverseProxy` construction.
- Preserve public response sanitization through the shared proxy.

### `internal/gitea/client.go`

- Add PAT creation/deletion types and methods.
- Add repository visibility decoding.
- Keep the bounded JSON client separate from streaming proxy transport.

### `internal/store/sqlite.go`

- Add schema creation/index statements.
- Keep migrations additive and idempotent.
- Start cleanup/reconciliation support without changing existing tables.

### `internal/config/config.go`

- Add and validate credential key ring, edge secret, full-proxy toggle, TTL bounds, audit retention, and shutdown grace.
- Require credential keys and edge secret in production when token/full-proxy functionality is enabled.

### `cmd/grasp-bridge/main.go`

- Construct token, PAT, and proxy services.
- Register token and session-handoff routes.
- Start token/replay/audit/PAT cleanup workers.
- Inject the proxy into `api.Server`.
- Use configurable graceful shutdown.
- Fail startup when required proxy/auth secrets are invalid.

### `deploy/nginx/gitea-vhost.conf.example`

- Change all Gitea traffic to the bridge upstream.
- Preserve auth_request with trusted handoff continuation.
- Add universal internal-header stripping.
- Add streaming/package/Docker/LFS locations and timeouts.
- Remove direct public Gitea proxying.

### `deploy/gitea/app.ini.phase3.snippet`

- Document required reverse-proxy auth header.
- Set canonical `ROOT_URL`.
- Document short Docker registry-token expiry and package/LFS limits after verifying exact Gitea keys.

### `.env.example` and compose files

- Add credential-key and edge-secret settings through secret files/runtime secrets rather than committed environment literals.
- Remove public Gitea port publication.
- Add bridge resource/file-descriptor settings and health/readiness checks.

### `internal/metrics/metrics.go`

- Add token, PAT, replay, scope-denial, active-stream, bytes, and upstream-error counters/gauges.

## New files

### `internal/auth/token_service.go`

Token lifecycle, scope validation, PAT coordination, and token authentication.

### `internal/auth/token_handler.go`

NIP-98-protected HTTP API and response/body limits.

### `internal/auth/nip98_request.go`

Standard header parsing, canonical target construction, payload verification, and replay claiming.

### `internal/auth/credential_crypto.go`

Versioned key ring and AEAD handling.

### `internal/store/auth_tokens.go`

Typed token, PAT, replay, and audit persistence methods.

### `internal/giteaproxy/proxy.go`

Shared streaming reverse proxy and fixed upstream transport.

### `internal/giteaproxy/authenticate.go`

Credential extraction, prefix handling, subject matching, and downstream injection.

### `internal/giteaproxy/surface.go`

Closed surface/action types and generic classifier.

### `internal/giteaproxy/git.go`

Git smart-HTTP classification and mapped/public policy.

### `internal/giteaproxy/packages.go`

Common package credential-family adapters.

### `internal/giteaproxy/container.go`

Docker challenge/token flow.

### `internal/giteaproxy/lfs.go`

Added in Phase 5.

### Tests

Add matching unit and integration test files for every new component, plus nginx/e2e coverage in `scripts/phase3-e2e.sh` or a new interoperability script.

# 5. Risks and migration

- SQLite migration is additive; old binaries ignore the new tables.
- Rolling back nginx restores ordinary Gitea access but disables bridge tokens. Keep a tested direct-Gitea rollback template.
- PATs created before rollback remain in Gitea. Provide an admin cleanup command that lists/revokes only the bridge instance’s PAT-name prefix.
- Loss of all credential encryption keys makes hidden PATs unusable. Fail closed, preserve encrypted rows for recovery, and never attempt to reinterpret ciphertext.
- A partially rotated PAT is reconciled from lifecycle state at startup.
- Registry tokens already issued by Gitea outlive bridge-token revocation until their short expiry.
- The full proxy increases blast radius. Cut over only after readiness, streaming, relay, session, and rollback tests pass.
- Phase 1 changes the anonymous npub path to fail closed for private repositories; this is an intentional security correction rather than a compatibility regression.

# 6. Implementation order

1. Validate deployed Gitea PAT endpoints, scope names, Git Basic behavior, registry challenge path, and registry token lifetime configuration.
2. Add configuration/key-ring parsing and additive SQLite schema.
3. Add store models, token transactions, replay claims, PAT lifecycle records, and audit persistence.
4. Add credential encryption and Gitea PAT administration.
5. Add payload-aware NIP-98 verification and atomic replay protection.
6. Add `TokenService`, token handlers, and explicit session-handoff route registration.
7. Add the shared fixed-target streaming proxy and generic credential-stripping policy.
8. Refactor mapped npub Git handling to delegate to the shared proxy.
9. Add conventional and mapped Git bridge-token translation plus public visibility checks.
10. Add trusted session continuation and root relay negotiation in the bridge fallback.
11. Land nginx/full-proxy configuration, compose isolation, readiness, and rollback documentation atomically.
12. Run all Phase 1 acceptance tests before enabling token minting in production.
13. Add common package adapters, then Docker/OCI, then the remaining registry catalog.
14. Add client tooling.
15. Add REST/direct NIP-98.
16. Add LFS.
17. Address shared-state/active-active deployment only after single-instance behavior and protocol coverage are stable.
# Design: Migrate to Fully User-Signed, NIP-34-Compliant Repositories

Status: **Proposed** (rev. 2 — corrected: NIP-34 *does* define kinds 1618/1619 PR/PR-update; they are kept, and the real gap is their tag schema) · Owner: bridge team · Supersedes the current gateway-signing model

## 0. Execution progress & decisions (living checklist — orchestrator-owned)

Phases (see §9). Each is implemented by a dedicated agent, verified, and committed before the next.

- [x] **Phase A** (phase1-w24) — Persistent NIP-46 signer foundation ✅ `internal/signer` (encrypted grants + BunkerClient pool + SignWithGrant)
- [x] **Phase B** (phase1-s0f) — Outbound signing queue ✅ `internal/outbox` (persistent, dedup, retry/backoff/dead-letter, admin endpoint)
- [x] **Phase C** (phase1-tu6) — Owner-authored events (30618) user-signed ✅ enqueued owner-signed via outbox; `/signer/authorize`; bridge-signed fallback
- [x] **Phase D** (phase1-5ud) — Contributor signer grants ✅ NIP-46 login persists reusable grant; webhook events enqueued under acting user; unlinked → skip (no bridge-sign)
- [ ] **Phase E** (phase1-xwx) — Full NIP-34 tag-schema compliance
- [ ] **Phase F** (phase1-ki5) — Bidirectional sync (Nostr→Gitea)
- [ ] **Phase G** (phase1-cmj) — Migration, compat & docs
- [ ] **10317** (phase1-kyg) — owner-signed grasp-list cache + rebroadcast

**Decisions baked for execution (defaults; flag for later review):**

1. **Contributor fallback (Phase D).** If an acting Gitea user has no linked NIP-46 signer
   grant, their collaboration event is **queued as pending and NOT published** until they link
   a signer (`queue-until-linked`). The bridge does **not** fall back to signing user content
   with `BRIDGE_NSEC` (that would reintroduce the impersonation problem). Behavior is
   configurable, but the safe default is queue-until-linked; operator-attributed signing stays
   OFF.
2. **Offline signer.** Publishing is **eventually-consistent** via the Phase-B queue
   (retry/backoff, TTL/dead-letter). When an owner/contributor signer is offline, the event is
   deferred and retried; it is never dropped silently (dead-letter is surfaced via metrics).
3. **CI (5401)** stays operator-signed (executor attestation), not user-signed.
4. **Crypto.** Grants encrypted at rest with `golang.org/x/crypto/nacl/secretbox` using a
   32-byte master key from env (`SIGNER_MASTER_KEY`, base64/hex); plaintext keys never persisted.

## 1. Objective

Every Nostr event that represents **user-owned or contributor-authored content** must be
signed by that user's own key via a **NIP-46 remote signer (bunker)**, with signing
authorization established when a repository is first set up and **bound to the owner's
pubkey**. The bridge stops minting owner/contributor content under `BRIDGE_NSEC`.

Secondary objective: expand the feature set to be **fully NIP-34 compliant** (patch-based
pull requests, NIP-22 comment threading, status threading, earliest-unique-commit repo
identity, maintainers, and bidirectional Nostr↔Gitea sync).

## 2. Current baseline (verified)

Signing model today (`internal/publisher`, `internal/webhook`):

| Kind | Meaning | Signed by (today) | Correct author |
|---|---|---|---|
| 30617 | repo announcement | **owner** (cached + rebroadcast verbatim) | owner ✅ |
| 30618 | repo state | **bridge** (`BRIDGE_NSEC`) | owner ✗ |
| 1617 | patch | contributor (reacted to, not signed) | contributor ✅ |
| 1618/1619 | PR open / PR update | **bridge** | contributor ✗ (NIP-34 kinds, but tag schema non-compliant) |
| 1621 | issue | **bridge** | contributor ✗ |
| 1630–1633 | status | **bridge** | actor ✗ |
| 1985 | NIP-32 label | **bridge** | labeler ✗ |
| 5401 | CI workflow run *(GRASP ext.)* | **bridge** | executor ✅ (attestation) |
| 10317 | user grasp list | (guardrailed, unimplemented) | owner |

NIP-46 status: **authentication-only**. `auth.BunkerConnector` is an abstract interface,
`cmd/grasp-bridge/main.go:102` passes it as **`nil`**, sessions have a 2-minute TTL, and only
a single login challenge is signed before the connection is dropped. `nip46_sessions` stores
`BunkerPubkey/ClientPubkey/ResultPubkey` — **no client secret, no bunker connect string, no
granted permissions** — so nothing is reusable for later signing.

Collaboration flow is **one-directional** (Gitea → Nostr via webhook). The relay subscriber
(`internal/relay/subscriber.go`) ingests only 30617/30618; it never ingests 1617/1621/status,
so Nostr-originated collaboration cannot reflect into Gitea.

## 3. The core challenge: asynchronous remote signing

NIP-46 is a request/response protocol to a remote signer that **must be online** to answer.
But the events we need signed are produced **asynchronously** by Gitea webhooks (a PR opened,
a push, an issue edited) — often when the user's signer is offline. This forces three
architectural facts:

1. **Durable signing authorization.** We must persist a reusable NIP-46 *client* keypair plus
   the bunker connect string (relay + secret) and the granted `sign_event` permission scope,
   keyed by the authorizing pubkey. `go-nostr/nip46.ConnectBunker` + `BunkerClient.SignEvent`
   can then be re-established and reused on demand.
2. **An outbound signing queue.** Events are enqueued unsigned, and a worker requests
   signatures with retry/backoff; if the signer is offline the item waits (bounded) and
   retries, with a dead-letter path and metrics/admin visibility. Publishing becomes
   eventually-consistent, not synchronous.
3. **Two identity scopes.** "Tied to the repo owner at setup" only covers **owner-authored**
   events (30617 announcement, 30618 state). **Contributor-authored** events (1617 patch,
   1621 issue, status, labels) must be signed by the **acting user's** key, so each
   contributor who acts through Gitea needs their *own* signer grant. Operator
   **attestations** (5401 CI) are legitimately signed by the executor and stay that way.

## 4. Target architecture

```
                       ┌────────────────────────────────────────────┐
  Gitea webhook  ──▶   │  Event Builder (unsigned NIP-34 templates)  │
  Relay ingest   ──▶   └───────────────┬────────────────────────────┘
                                       ▼
                         ┌──────────────────────────┐   enqueue
                         │   Outbound Event Queue    │◀───────────
                         │  (persistent, ret/backoff)│
                         └───────────┬───────────────┘
                                     ▼ drain
                         ┌──────────────────────────┐
                         │      Signer Service       │
                         │  grant lookup by pubkey   │
                         └───────────┬───────────────┘
                                     ▼
                         ┌──────────────────────────┐   NIP-46 sign_event
                         │  BunkerClient pool        │──────────────────▶  user's remote signer
                         │  (reconnect + Ping health)│◀──────────────────  (bunker over relay)
                         └───────────┬───────────────┘   signature
                                     ▼ signed
                         ┌──────────────────────────┐
                         │   publishToRelays         │──▶ relays
                         └──────────────────────────┘
```

**New components**

- **Signer Authorization Service** — at provisioning, the owner authorizes the bridge as a
  NIP-46 client with a scoped `sign_event` permission. Persists an encrypted grant.
- **Signer Service + BunkerClient pool** — in-memory cache of live `*nip46.BunkerClient` keyed
  by pubkey; lazy reconnect from the stored grant; `Ping`-based health; `GetPublicKey` sanity
  check that the bunker controls the claimed pubkey.
- **Outbound Event Queue + worker** — persistent, at-least-once, idempotent (dedupe by a
  content key so retries don't double-publish); backoff, TTL/dead-letter, metrics, admin view.
- **Contributor linking** — extend NIP-46 login to persist a *reusable* grant (not a one-time
  challenge), mapping Gitea user → pubkey → grant.

The bridge keeps its own key only as (a) the NIP-46 *client* identity used to talk to bunkers
and (b) the signer of operator attestations (5401). It can no longer forge user content — a
material security improvement (§8).

## 5. Event-by-event migration

| Kind | New author | Signing path | Notes |
|---|---|---|---|
| 30617 announcement | owner | unchanged (cache + rebroadcast owner-signed) | already correct |
| 30618 state | owner | queue → owner grant → sign → publish | if owner offline, state publish is deferred+retried |
| 1617 patch | contributor | ingest contributor-signed; for Gitea-web patches, sign with actor grant | never bridge-signed |
| 1618/1619 PR | actor | queue → actor grant; **keep** (NIP-34 kinds); fix tag schema | see §6 |
| 1621 issue | actor | queue → actor grant | fallback policy for unlinked actors (§9-D) |
| 1630–1633 status | actor/maintainer | queue → actor grant; proper e/a/p/r markers | |
| 1985 label | labeler/maintainer | queue → labeler grant | |
| 5401 CI run | executor (bridge/CI key) | stays operator-signed | documented as attestation, not NIP-34 core |
| 10317 grasp list | owner | owner-signed cache + rebroadcast | tracked by phase1-kyg |

## 6. Full NIP-34 compliance expansion

1. **Bring PRs, patches, issues, and status to the NIP-34 tag schema.** NIP-34 defines BOTH
   patches (1617) and pull requests (1618 open / 1619 update) as first-class kinds — keep
   both. Gaps in what we currently emit: PR/issue use `title` where the spec wants `subject`;
   PR `r` carries a human path instead of the earliest-unique-commit (`euc`); PRs omit `c`
   (tip commit-id), `clone`, and `branch-name`, and emit non-spec `head`/`base` tags; 1619
   updates omit the required `E`/`P` reference to the PR being updated (and close/reopen should
   be **status** events, not 1619); patches (1617) need `t root`/`root-revision`, `commit`,
   `parent-commit`, `commit-pgp-sig`, `committer`; status (1630-1633) needs `e` root/reply
   markers plus `q`/`merge-commit`/`applied-as-commits`; replies use NIP-22 (kind 1111). Use
   the `go-nostr/nip34` helpers (`Repository`/`Patch`/`RepositoryState`).
2. **Earliest-unique-commit (euc)** `r` tag as the stable cross-fork repo identity; compute at
   provisioning and thread through announcements/patches.
3. **Maintainers** — populate the `maintainers` tag on announcements and honor multi-maintainer
   acceptance (the pre-receive hook already has partial multi-maintainer logic).
4. **NIP-22 comments (kind 1111)** for issue/patch review threads, replacing ad-hoc bodies.
5. **Status threading** — correct `e` root/reply markers, `a` repo coordinate, `p` recipients,
   and `r` (`applied-as-commits`/`merge-commit`) semantics.
6. **Bidirectional sync (Nostr → Gitea).** Subscribe to 1617/1621/1111/1630-1633 scoped to
   provisioned repos (by repo `a` coordinate), and reflect them into Gitea (create issue/PR,
   apply patch, post comment, update status). Requires echo-loop prevention (§10).
7. **Divergence doc** — explicitly document GRASP extensions (5401 CI) as non-NIP-34.

## 7. Data model changes (`internal/store`)

New tables:

- `signer_grants(pubkey PK, client_seckey_enc, bunker_uri_enc, relays, permissions,
  granted_at, revoked_at, last_ok_at, status)` — one durable signing authorization per pubkey.
- `outbound_events(id PK, dedupe_key UNIQUE, kind, author_pubkey, scope, unsigned_json, state,
  attempts, next_attempt_at, last_error, created_at, published_event_id)` — the signing queue.
- Extend `nostr_identity_links` to reference a `signer_grants` row (Gitea user → pubkey →
  grant), enabling contributor signing.

Secrets (`client_seckey_enc`, `bunker_uri_enc`) are **encrypted at rest** with a bridge master
key (env-provided; e.g. NaCl secretbox / age). Plaintext keys are never persisted.

## 8. Security

- **Reduced impersonation surface.** The bridge no longer holds a key that can author user
  content; a bridge compromise can no longer forge announcements/issues/PRs as users.
- **Residual risk.** The bridge holds *live signing authorizations*; a compromise can request
  signatures **within granted scope** until the user revokes. Mitigate with (a) minimal
  `sign_event:<kind>` scoping, (b) encrypted-at-rest grants, (c) revocation, (d) short-lived
  reconnection secrets where the signer supports it, (e) audit logging of every sign request.
- **Authorization integrity.** On grant creation, verify `BunkerClient.GetPublicKey()` matches
  the claimed owner pubkey before trusting the grant.
- **Availability/DoS.** Queue caps, per-pubkey rate limits, backoff, dead-letter, metrics.

## 9. Phased rollout (maps to Beads epic)

- **Phase A — Persistent NIP-46 signer foundation.** Real `BunkerConnector` via
  `go-nostr/nip46`; `signer_grants` storage + at-rest encryption; BunkerClient pool with
  reconnect + `Ping`/`GetPublicKey`; `SignWithGrant` API + tests against a mock bunker.
- **Phase B — Outbound signing queue.** `outbound_events` table + idempotent worker +
  backoff/dead-letter + metrics + admin endpoint.
- **Phase C — Owner-authored events user-signed.** Provisioning establishes the owner grant;
  route 30618 state through the queue signed by the owner; keep 5401 operator-signed; stop
  bridge-signing owner content.
- **Phase D — Contributor grants.** Reusable NIP-46 login → persistent grant; Gitea user →
  pubkey → grant; sign 1617/1621/status/label with the acting user's grant; explicit fallback
  policy for unlinked actors (queue-until-linked vs reject vs operator-attributed).
- **Phase E — NIP-34 compliance.** Fix tag schemas for PRs (1618/1619 — **kept**, they are
  NIP-34 kinds), patches (1617), issues (1621), and status (1630-1633) to match the spec
  (`subject`, euc `r`, `c`/`clone`/`branch-name`, `E`/`P` on PR updates, patch commit tags,
  status `e` markers); add euc, maintainers, and NIP-22 (1111) comments.
- **Phase F — Bidirectional sync (Nostr → Gitea).** Ingest collaboration kinds scoped by repo
  `a`; reflect into Gitea; echo-loop prevention.
- **Phase G — Migration, compat & docs.** Deprecation window for 1618/1619; backfill/migration
  notes; update all docs; remove dead gateway-signing paths.

## 10. Risks & open questions

- **Signer availability.** Offline bunkers defer publishing; set user expectations, surface
  queue depth/age. Consider optional NIP-46 "always-online" signer guidance.
- **Contributor onboarding friction.** Every acting contributor needs a signer; the fallback
  policy (Phase D) is a product decision, not just engineering.
- **Tag-schema change for already-emitted 1618/1619/1621.** Existing events used
  `title`/`head`/`base`/`action`; moving to spec tags (`subject`/`c`/`clone`/`branch-name`/
  `E`/`P`) is a consumer-visible change that needs a compat note (the kinds themselves are
  unchanged and remain valid NIP-34).
- **Echo loops.** Gitea webhook → Nostr and Nostr → Gitea can loop; require idempotency and
  source-tagging (extend `processed_events`, tag bridge-origin writes) so reflected events are
  not re-ingested.
- **Key custody.** Master encryption key management (rotation, storage) is operational surface.
- **Backward compatibility.** Events already published under `BRIDGE_NSEC` remain; document
  that they are historical and will not be re-signed.

## 11. Out of scope / explicitly deferred

- Migrating historical bridge-signed events (they stay as-is).
- A hosted/custodial signer for users without a bunker (would reintroduce the custody problem).
- CI (5401) redesign — remains a GRASP extension, operator-signed.

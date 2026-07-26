# Design: Loom Integration for grasp-gitea (Decentralized CI over Nostr)

Status: **Proposed (design-only)** · Bead: `phase1-yk8` · Owner: bridge team · Item **F** of the security & completeness remediation plan (`docs/reviews/security-remediation-plan.md`)

> This is a **design pass only** — no code is implemented in this bead. It defines
> which Loom-protocol events grasp-gitea consumes/publishes, their Nostr kinds,
> how they map onto Gitea CI/status/checks, the subscription + publication path,
> the authorization model (reusing `internal/nostrauthz`), the configuration
> surface, and a phased implementation plan. Open questions for the maintainer
> are collected in §12 and **must be resolved before Phase 2 code lands**.

---

## 1. Objective & scope

Loom integration is **entirely absent** from grasp-gitea today. The goal is to let
a grasp-gitea bridge participate in decentralized CI/CD by acting as a **Hive-CI
orchestrator / Loom client**:

- **Outbound (publish):** when an authorized push/PR arrives over Nostr, submit
  the repository's CI workflows to Loom compute workers (Hive-CI-over-Loom) and
  record the dispatch.
- **Inbound (consume):** subscribe to Loom job status/result and Hive-CI workflow
  result events, correlate them to the dispatch, and **reflect the outcome into
  Gitea as commit statuses** (checks that render on commits and pull requests and
  can gate merges via branch protection).

grasp-gitea is a git host + Nostr bridge, **not** a compute provider. It therefore
does **not** advertise itself as a Loom worker (kind `10100`). The one nuance: the
existing `internal/hiveci` runner already executes `act` locally (an in-fleet
"Tier A" executor); Loom remote dispatch is "Tier B". Both tiers should feed the
same inbound → Gitea-status mapping (§6).

Non-goals for this design: building a Loom worker; a general Cashu wallet
(payment is phased — §8); replacing the NIP-34 reflector.

---

## 2. Current baseline (verified against the tree)

There are **two pre-existing, divergent CI code paths**, and neither speaks the
canonical Loom protocol, and neither writes results back into Gitea:

| Path | File | Kinds | Signed by | What it does |
|---|---|---|---|---|
| **Tier A local runner** | `internal/hiveci/runner.go` | consumes `30618`/`1617`/`1618`/`1619`; publishes `30315` (check result) + `4903` (CAS audit) | operator/server signer | Detects workflows at a commit, runs `act` locally in a worktree, publishes signed check + audit attestations **to Nostr only**. Just hardened to owner/maintainer-authored workflows only (`workflowAuthorAuthorized`). |
| **ContextVM request publisher** | `internal/publisher/ci.go` | publishes `25910` (`CAS_INTENT`) `ci/workflow-run`, schema `hive.ci.workflow.v1` | bridge/server signer | On `30618` state (or webhook push), detects workflows and publishes a **cascadia CAS_INTENT** job request for a remote executor. Never consumes a result. |

Key facts established during discovery:

- **No Gitea commit-status/check-run writer exists.** `internal/gitea/client.go`
  exposes `CreateIssue`, `CreatePullRequest`, `CreateIssueComment`, `SetIssueState`,
  `AddIssueLabel`, `RemoveIssueLabel` — and **no** `POST /repos/{owner}/{repo}/statuses/{sha}`.
  The reflector (`internal/reflector/reflector.go`) maps NIP-34 status kinds
  `1630`–`1633` only to `SetIssueState` (open/closed issues). So today, **CI
  results are never surfaced in the Gitea UI.**
- **Authorization helper is ready.** `internal/nostrauthz.Resolver`
  (`NewResolver([]nostr.Event)`, `Resolve(coord)`, `IsAuthorized(pubkey, coord)`)
  resolves owner + recursive maintainer authority from cryptographically valid
  kind `30617` announcements. Hive-CI hardening (Item D) already restricts runs to
  owner/maintainer-authored workflows; Loom must use the same gate.
- **Composition root** (`cmd/grasp-bridge/main.go`) wires a single relay
  `Subscriber` with a `handler` closure that fans events out to
  provisioner → reflector → CI trigger → proactive sync → `hiveRunner`.
  The subscription kind set lives in `internal/relay/subscriber.go`
  (`subscriptionFilter()`), and kind constants in `internal/relay/kinds.go`.
- **Signer** is the Signet/NIP-46 `ServerSigner` (or `BRIDGE_NSEC` dev fallback),
  reused by both publisher and hiveci runner.

### 2a. The central protocol-dialect problem (⚠️ decide first — see §12 Q1)

The two spec roots and the binding grasp-gitea already imports describe **two
different protocols** for the same concepts:

| Concept | Canonical Loom / Hive-CI spec (`loom-protocol/`, `hive-ci-protocol/`) | cascadia-go binding grasp-gitea imports (`git.sharegap.net/cascadia/cascadia-go`) |
|---|---|---|
| Worker advertisement | kind **10100** (`= CAS_WORKER_AD`, matches) | kind **10100** ✅ |
| Job request | kind **5100** (subprocess model: `cmd`/`args`/`payment`/`secret`) | **kind 25910 `CAS_INTENT`**, method `loom/submit`/`compute/run`, schema `cascadia.loom.v1` — **no legacy mapping for 5100** |
| Job status | kind **30100** (param-replaceable, `d`=job id) | legacy map `30100 → 30900` loom-job projection |
| Job result | kind **5101** | **no mapping for 5101** |
| Job cancel | kind **5102** | legacy map `5102 → loom/cancel` |
| Workflow run | kind **5401** | legacy map `5401 → ci/workflow-run` (25910) |
| Workflow result | kind **5402** | legacy map `5402 → ci` (25910) |

So cascadia is a "next-gen" reframing where every command is a single
`CAS_INTENT` (25910) JSON-RPC envelope, with a **partial** legacy translation
table that notably **does not cover the canonical Loom job request/result
(5100/5101)** — the very core of the Loom subprocess model. grasp-gitea's
`publisher/ci.go` already emits the *cascadia* dialect (25910), **not** what
`loom-protocol/SPECIFICATION.md` describes.

**This design targets the canonical Loom + Hive-CI spec kinds** (`5100/5101/30100/5102`
+ `5401/5402`) because (a) that is what the two authoritative spec roots and
real-world Loom workers implement, and (b) the subprocess execution model
(`cmd`/`args`/stdin/`secret`/`payment`) is fully specified there whereas the
cascadia `cascadia.loom.v1` payload (`{job_id, worker_id, status}`) is a thin
projection with no execution semantics. The existing cascadia `ci/workflow-run`
path is treated as a **separate legacy dialect** to be bridged or deprecated
(§11 Phase 4). **Maintainer must confirm** (Q1).

Because cascadia cannot losslessly represent canonical `5100`/`5101` (payment,
secret, artifact semantics), the two dialects are made **mutually exclusive** via
a `CI_PROTOCOL=canonical|cascadia` switch (default `canonical` once this lands).
Silently replacing `publisher/ci.go` would break existing cascadia consumers, and
**dual-publishing the same trigger would execute every workflow twice** — so if a
transition period needs both, they must be modeled as *distinct attempts* and only
one may own the primary Gitea status context.

---

## 3. Event kinds: consumed & published

Canonical kinds this integration touches (all per `loom-protocol/SPECIFICATION.md`
and `hive-ci-protocol/SPECIFICATION.md`):

| Kind | Name | Direction | Role in grasp-gitea |
|---|---|---|---|
| `10100` | Loom Worker Advertisement (replaceable) | **consume** | Worker discovery + capability/price/software filtering for dispatch. |
| `5401` | Hive-CI Workflow Run (regular) | **publish** | Record a CI run; declares the ephemeral `publisher` pubkey. |
| `5100` | Loom Job Request (regular) | **publish** | Submit the workflow execution to a chosen worker; carries `cmd`, `payment`, and NIP-44-encrypted `HIVE_CI_NSEC` secret. |
| `30100` | Loom Job Status (param-replaceable, `d`=job req id) | **consume** | queued/running/completed/failed/cancelled/timeout → drive `pending` Gitea status + progress. |
| `5101` | Loom Job Result (regular) | **consume** | Worker's exit_code/duration/stdout/stderr (Blossom) → terminal Gitea status if no 5402. |
| `5402` | Hive-CI Workflow Result (regular) | **consume** | Signed by the ephemeral publisher key we minted; `status`/`log_url` → terminal Gitea commit status. |
| `5102` | Loom Job Cancellation (regular) | **publish** (Phase 3) | Cancel a superseded/aborted run. |

New kind constants to add to `internal/relay/kinds.go`:

```go
KindLoomWorkerAd    = 10100
KindLoomJobRequest  = 5100
KindLoomJobStatus   = 30100
KindLoomJobResult   = 5101
KindLoomJobCancel   = 5102
KindHiveWorkflowRun    = 5401
KindHiveWorkflowResult = 5402
```

> Note `KindCheckRunResult` (`30315`) already exists for the Tier-A local-runner
> attestation; it is orthogonal to the Loom kinds and is retained.

---

## 4. Outbound path — submitting Hive-CI-over-Loom

Trigger reuses the **existing** authorized detection in `main.go` (`30618` state
events, striped per-repo lock, `nostrauthz` + `CI_TRIGGER_REPOS` gate) and the
webhook push path. For each `(repo, branch, commit, workflow)` that passes the
gate:

1. **Authorize workflow author** (§7). Only owner/maintainer-authored workflows
   are dispatched — identical policy to the hardened Tier-A runner.
2. **Discover a worker.** From cached kind `10100` ads (a bounded in-memory pool,
   refreshed from the subscription), pick a worker that:
   - is in the `LOOM_WORKER_PUBKEYS` allowlist (Phase 1/2 trust model), and
   - advertises the required software (`act` / container runtime) via `S` tags,
   - satisfies `min_duration`/`max_duration` vs our configured job bound.
   If no worker qualifies and a local Tier-A runner is enabled, fall back to
   local execution (`LOOM_DISPATCH_MODE`, §9).
3. **Mint an ephemeral keypair** `(pub_e, nsec_e)` for this run (the Hive-CI
   "publisher"). `pub_e` is declared in the `5401` `["publisher", …]` tag; `nsec_e`
   is handed to the worker so the workflow can sign its own `5402` result.
4. **Publish kind 5401 Workflow Run** (bridge/operator-signed), tags:
   `["a", <30617:owner:repoID>]`, `["commit", sha]`, `["branch", name]`,
   `["trigger", "push"|"pull_request"]`, `["triggered-by", <author>]`,
   `["workflow", path]`, `["publisher", pub_e]`, `["t", "hive-ci"]`.
5. **Build the payment token** (§8). Phase 1: none / trusted-worker / static
   pre-funded token from config. Phase 3: real Cashu.
6. **Publish kind 5100 Loom Job Request** to the worker (bridge-signed), tags:
   `["p", <worker_pub>]`, `["cmd", <runner>]`, `["args", …]` (clone repo at
   commit, run the workflow with `act`), `["e", <5401 id>]`,
   `["secret", "HIVE_CI_NSEC", <nip44(nsec_e → worker_pub)>]`,
   `["payment", <cashu token>]`. `content` = stdin (empty for Hive-CI).
7. **Persist a dispatch record** in a new `loom_jobs` correlation table (§6a) and
   set the initial Gitea commit status to `pending` (context
   `hive-ci/<workflow>`).

**Worker-selection hardening.** A valid `10100` advertisement proves only *who
authored the ad*, not that the worker is trustworthy — and the worker receives
the ephemeral `HIVE_CI_NSEC`, so it can itself fabricate a valid `5402`. Trusted/
free mode therefore **requires** the `LOOM_WORKER_PUBKEYS` allowlist; ads are
replaceable, so select the **canonical latest ad per author** (created_at desc,
lower id tie-break) with an ad TTL + future-skew bound; validate advertised
software/payment capability; and **refuse** (do not silently dispatch unpaid work)
if a worker requires Cashu and no payment is configured.

> The **command**
> the coordinate/commit and invoke `act` (or the hive-ci runner image). The exact
> `cmd`/`args`/worker image contract is an open question (Q3) — it depends on
> what published Loom worker images expect. The bridge builds it from config-
> supplied templates so it can adapt without code changes.

---

## 5. Inbound path — consuming results

Three inbound kinds, all correlated back to a dispatch record before any effect:

- **`30100` Job Status** — `d`/`e` = our `5100` job-request id. Map non-terminal
  states to Gitea `pending`; record `queue_position`/log tail. Terminal states
  (`completed`/`failed`/`timeout`/`cancelled`) are advisory here — the
  authoritative terminal signal is `5402` (preferred) or `5101`.
- **`5101` Job Result** — `e` = our `5100` id, signed by the worker. Carries
  `success`/`exit_code`/`duration`/`stdout`/`stderr` (Blossom URLs). Used as the
  terminal signal **when no `5402` arrives** (e.g. worker crash, non-Hive job).
- **`5402` Workflow Result** — `e` = our `5401` id, **signed by the ephemeral
  `publisher` pubkey we minted**. Carries `status` (`success`/`failure`),
  `log_url`, `exit_code`, `duration`. This is the preferred terminal signal for
  Hive-CI runs because the Hive-CI spec ties `HIVE_CI_NSEC` ↔ `publisher`, giving
  us a cryptographic guarantee it came from the job we dispatched.

Terminal mapping to Gitea commit-status `state`:

| Source | Condition | Gitea state |
|---|---|---|
| `5402` | `status=success` | `success` |
| `5402` | `status=failure` | `failure` |
| `5101` (no 5402) | `success=true` | `success` |
| `5101` (no 5402) | `success=false`, exit≠0 | `failure` |
| `30100` | `status=timeout` / Loom job died | `error` |
| `30100` | `status=cancelled` | `error` (or delete/neutral) |
| `30100` | `queued`/`running` | `pending` |

`target_url` should point at a **bridge-owned job-details URL** (validated),
not an unvalidated worker/Blossom URL pasted straight into the Gitea UI.
Optionally (Phase 3) fetch the Blossom log via `internal/safefetch` (size + SHA-256
validated) and attach a tail.

### 5a. Ordering, dedup & the job state machine

Loom status is noisy: `30100` is param-replaceable, events arrive from multiple
relays out of order, and a worker can stamp future `created_at` to pin the
replaceable slot. The consumer must therefore:

- **Scope replaceable identity to the worker.** A `30100` is only meaningful as
  `(kind=30100, author=selected_worker_pub, d=job_req_id)` — never select globally
  by `d`, or an attacker publishes the same `d` under another key.
- **Order canonically** within that identity: newer `created_at` wins, lower
  event id breaks ties (the same rule Item E centralized for replaceables), with a
  bounded future-skew rejection.
- **Enforce a monotonic state machine:** `queued`/`running` → `pending`; a late
  `running` must never overwrite an already-terminal status. `success`/`failure`/
  `error`/`cancelled` are terminal and sticky.
- **Dedup terminal results by event id** and define precedence when `5101` and
  `5402` disagree or arrive in either order: **`5402` (Hive workflow result) wins**
  as the assertion of the CI outcome; `5101` is the fallback only when no `5402`
  arrives within a grace window.

---

## 6. Mapping onto Gitea CI / status / checks

### 6a. Gitea commit status (the primary surface)

Gitea (like GitHub) exposes commit statuses via
`POST /api/v1/repos/{owner}/{repo}/statuses/{sha}` with body:

```json
{ "state": "pending|success|error|failure|warning",
  "target_url": "https://blossom…/log",
  "description": "hive-ci: build passed in 234s",
  "context": "hive-ci/.github/workflows/test.yml" }
```

Commit statuses render as **checks** on the commit and any PR whose head is that
commit, and can gate merges when branch protection requires the status context.
This is the natural, native mapping for CI results — no Gitea Actions runner is
involved.

**New Gitea client method** (`internal/gitea/status.go`, extends the existing
`*Client`):

```go
type CommitStatus struct {
    State       string // pending|success|error|failure|warning
    TargetURL   string
    Description string
    Context     string
}
func (c *Client) CreateCommitStatus(ctx context.Context, owner, repo, sha string, s CommitStatus) error
```

Auth reuses the existing admin-token client (`"token "+c.token`). One `context`
per `(workflow)` so multiple workflows appear as distinct checks and a later
terminal status overwrites the earlier `pending` for the same context+sha.

**The `sha` always comes from the dispatch record, never from a result event** —
a result cannot retarget the status onto an arbitrary commit. Gitea needs **no**
separate PR association: it automatically shows a commit's statuses on any PR
whose current head SHA matches, and a status on an old revision correctly stays
on the old commit. `context`/`description` lengths are bounded. State bucketing:
queued/running → `pending`; workflow assertion failure → `failure`; success →
`success`; infra/timeout/cancellation/malformed-result/artifact failure → `error`.

### 6b. Correlation store (new)

Loom results reference our dispatch **only by event id** (`e`), not by repo
coordinate + commit. We must remember the mapping. Add a table (isolated file to
avoid churn on `sqlite.go`, mirroring Item B's `internal/store/threads.go`
pattern), e.g. `internal/store/loomjobs.go`:

```
loom_jobs(
  workflow_run_id TEXT PRIMARY KEY,   -- kind 5401 event id
  job_request_id  TEXT,               -- kind 5100 event id (indexed)
  publisher_pub   TEXT,               -- ephemeral pub_e (verifies 5402)
  worker_pub      TEXT,               -- verifies 5101/30100
  owner           TEXT,               -- Gitea owner
  repo_name       TEXT,               -- Gitea repo
  repo_id         TEXT,               -- NIP-34 d/identifier
  commit_sha      TEXT,
  workflow_path   TEXT,
  status          TEXT,               -- last applied state
  created_at      INTEGER,
  updated_at      INTEGER
)
```

Bounded by TTL/row cap (reuse the sweep pattern from `hiveci` `markStarted` /
`publisher` `ciDedup`).

### 6c. Optional: Nostr check-run attestation

To stay consistent with the Tier-A runner, the inbound consumer MAY also
republish a signed `30315` check-run result + `4903` audit (reusing
`hiveci`'s builders) so Nostr clients see the outcome too. This is optional and
gated behind the same enable flag.

### 6d. Also reflect the existing Tier-A local runner into Gitea

Quick win, independent of remote Loom: route the local
`hiveci/runner.go` result through the **same** `CreateCommitStatus` writer so
that even without any Loom worker, CI results finally show up in the Gitea UI.
This is the smallest shippable slice and de-risks §6a.

---

## 7. Authorization (reuse `internal/nostrauthz`)

**Outbound (who may cause a dispatch):** identical to the hardened Hive-CI model.
The workflow author (the signer of the `30618`/PR event, or the workflow file's
committer) must be in the repo's owner + recursive maintainer set. Resolve with:

```go
resolver := nostrauthz.NewResolver(validAnnouncementPool)  // from cached 30617s
ok, err := resolver.IsAuthorized(authorPubkey, "30617:"+owner+":"+repoID)
```

This replaces the ad-hoc `workflowAuthorAuthorized` in `hiveci/runner.go`
(which hand-parses the `maintainers` tag) with the shared resolver, so Loom and
Tier-A share one authority source. `p`/`a` tags remain **hints, never authority**
(per Item A's cross-item note).

**Inbound (whose result may set a Gitea status):** authority is anchored in our
**own immutable dispatch record**, not in announcement authority. Signer checks
alone are insufficient — every echoed field must match the attempt we stored
*before* dispatch (job-request id, `5401` id, repo coordinate, commit, workflow,
selected worker pubkey, ephemeral publisher pubkey), so an authorized key cannot
replay or cross-associate a valid result onto a different job:

- `5402` accepted only if `ev.pubkey == loom_jobs.publisher_pub` **and** its `e`
  resolves to that exact `5401` record (cryptographic tie via `HIVE_CI_NSEC` ↔
  `publisher`).
- `5101`/`30100` accepted only if `ev.pubkey == loom_jobs.worker_pub` **and** the
  `e`/`d` resolves to that exact `5100` record.
- Every inbound event is first validated with
  `nostrverify.ValidateEventIDAndSignature` (as the runner already does).
- No dispatch record ⇒ ignore silently (prevents a stranger from posting a fake
  "success" status for someone else's commit).

**Trust caveat (state explicitly):** because the worker holds the delegated
`HIVE_CI_NSEC`, the `5402` publisher signature authenticates *possession of the
delegated secret*, not an independent attesting party. The **selected worker is
ultimately trusted for both execution and the delegated Hive result**, which is
precisely why worker selection is allowlist-gated (§4). A separate executor-
attestation mechanism would be needed to break that trust dependency.

The repo coordinate on the dispatch record was itself established from an
`nostrauthz`-authorized owner coordinate, so the Gitea target is always a repo
we legitimately map.

---

## 7a. Durable dispatch & retryable delivery

Correlation must be **persisted before publication**, and CI execution must be
decoupled from Gitea delivery:

- **Persist the attempt + the exact signed `5401`/`5100` event bytes *before*
  relay publish.** A fast worker can answer before the record exists, and a crash
  after one relay accepts the request would otherwise orphan the result. On
  restart, republish the *same* event ids (idempotent) rather than minting new
  ones (which would double-execute + double-pay).
- **Separate the Gitea status-delivery queue.** A failed `CreateCommitStatus`
  POST must be retried on its own — **never** by re-running the workflow. Record
  the last applied protocol event id so a stale non-terminal update is never
  posted after a terminal one. Duplicate identical status rows under the same
  context are semantically harmless.
- **Commit availability.** Inbound `30618` state can arrive *before* its git
  objects (especially from external relays). Both current workflow detectors
  (`hiveci` + `publisher/ci.go`) swallow every `git ls-tree` error, silently
  turning "commit missing" into "no workflows." The Loom path must **distinguish
  an absent workflow directory from an unavailable/invalid commit**, persist an
  `awaiting_git_object` attempt, and retry after proactive sync / purgatory
  release rather than dropping the run.

## 8. Payment (Cashu) — phased, and the main blocker

The Loom spec **requires** a pubkey-locked Cashu `payment` token in every `5100`
request, and workers compute `timeout = payment_amount / price_per_second`. A
general Cashu wallet (mint interaction, NUT proofs, change redemption from
`5101`) is a substantial subsystem and is **out of scope for the first shippable
slices**. Phasing:

- **Phase 1 (inbound only):** no outbound submission, so no payment. Reflect
  Tier-A local runs + any externally-submitted results into Gitea.
- **Phase 2 (outbound, trusted/free workers):** dispatch to `LOOM_WORKER_PUBKEYS`
  workers operated by the same operator/fleet that either accept a `0`/absent
  payment or a static pre-funded token from `LOOM_STATIC_PAYMENT_TOKEN`. No
  wallet logic. Explicitly documented as "trusted-fleet mode".
- **Phase 3 (real Cashu):** integrate a Cashu wallet (mint from `LOOM_MINT_URL`),
  compute payment from the worker's `price`/`max_duration`, pubkey-lock to the
  worker, and redeem `change` tokens from `5101`. New `internal/cashu` package.
  This is where most of the remaining effort lives; flag for a dedicated bead.

`LOOM_MINT_URL` / wallet config surface is reserved now (§9) but unused until
Phase 3.

---

## 9. Configuration / env surface (minimal-config goal)

All new keys default OFF so existing deployments are unaffected. Reuse existing
`CI_TRIGGER_REPOS` for the repo allowlist rather than adding a parallel one.

| Env | Type | Default | Meaning |
|---|---|---|---|
| `LOOM_ENABLED` | bool | `false` | Master switch for Loom inbound consumer + outbound dispatch. |
| `LOOM_DISPATCH_MODE` | enum | `local` | `local` (Tier-A only), `remote` (Loom workers only), `both` (prefer remote, fall back local). |
| `LOOM_WORKER_PUBKEYS` | csv | – | Allowlisted worker pubkeys (trust anchor for Phase 1/2; also validates inbound `5101`/`30100`). |
| `LOOM_RELAY_URLS` | csv | merged relay set | Relays for Loom job publish/subscribe (default = the same merged set `main.go` already builds). |
| `LOOM_JOB_MAX_DURATION` | duration | `15m` | Upper bound on a job (bounds payment/timeout; mirrors `HIVE_CI_RUN_TIMEOUT`). |
| `LOOM_JOB_CMD_TEMPLATE` | string | (built-in) | Template for the worker `cmd`/`args` contract (Q3). |
| `LOOM_STATUS_CONTEXT_PREFIX` | string | `hive-ci` | Prefix for the Gitea commit-status `context`. |
| `LOOM_MINT_URL` | url | – | (Phase 3) Cashu mint. |
| `LOOM_STATIC_PAYMENT_TOKEN` | string | – | (Phase 2) pre-funded trusted-fleet token. |
| `CI_PROTOCOL` | enum | `canonical` | `canonical` (Loom/Hive 5x00 kinds) or `cascadia` (legacy 25910 `ci/workflow-run`). Mutually exclusive — never both for one trigger (§2a). |

`internal/config/config.go` gains a `Loom*` block loaded with the same helpers
(`boolEnv`, `csvEnv`, `boundedDurationEnv`) and a `Config.LoomEnabled()` guard,
following the `HiveCI*` precedent. Production guardrails: if `LOOM_DISPATCH_MODE`
is `remote`/`both` and no worker allowlist and no payment config, fail closed or
log a loud warning (mirrors the fail-closed philosophy from Item D).

---

## 10. Subscription & publication path (where it plugs in)

**Subscription** — the canonical Loom kinds should ride a **dedicated
`LOOM_RELAY_URLS` client/subscriber**, not the main repository subscriber, for two
reasons: (a) the **embedded relay currently rejects unknown kinds**, so `5100`/
`5101`/`5401`/`5402`/`10100`/`30100` traffic will not flow over the merged relay
set without an admission-policy change; and (b) folding global worker-ad traffic
into the main repo handler couples unrelated concerns. The Loom subscriber
applies response filters (only kinds we consume) and **ignores events we
ourselves published** (compare against dispatch records) to avoid self-echo. If
the embedded relay must carry Loom, extend its admission policy so it accepts
outbound requests only from the configured orchestrator and inbound events only
when correlated to a stored dispatch. The existing `forwardEventToRelay` path
must stay narrow (announcement/state only) to avoid reflection loops.

If instead the shared subscriber is used, extend `subscriptionFilter()` to add
`KindLoomJobStatus (30100)`, `KindLoomJobResult (5101)`,
`KindHiveWorkflowResult (5402)`, and `KindLoomWorkerAd (10100)`.

**Do not block the relay loop.** `relay.Subscriber` invokes its handler
synchronously; the current Tier-A runner can already stall one subscription for a
full run timeout. The Loom handler must validate + enqueue quickly and run
dispatch, artifact retrieval, Gitea writes, and any local execution in **bounded
background workers**.

**Dispatch in the handler** — in `cmd/grasp-bridge/main.go`'s `handler` closure,
after the existing `hiveRunner.HandleEvent`, add:

```go
if loomSvc != nil {
    if err := loomSvc.HandleEvent(ctx, ev, sourceRelay); err != nil {
        logger.Warn("Loom handler failed", "event", ev.ID, "kind", ev.Kind, "error", err)
    }
}
```

`loomSvc.HandleEvent` switches on kind: `10100` → cache worker ad; `30100/5101/5402`
→ inbound status mapping; and (if `LOOM_DISPATCH_MODE` includes remote) it also
receives the `30618`/PR trigger to submit jobs — OR, to keep the outbound trigger
next to the existing CI trigger, `main.go` calls `loomSvc.MaybeDispatch(...)`
inside the existing per-repo-locked `KindRepositoryState` block right where
`publisherSvc.HandleStateEventCI` is called today.

**Publication** — reuse the runner's proven `publishToRelays` pattern (connect,
`Publish`, count successes, error if all fail) or factor it into a small shared
`internal/relay` publish helper so `hiveci`, `publisher`, and `loom` don't each
re-implement it (optional cleanup).

**Composition root wiring** (new, in `main.go`):

```go
loomSvc := loom.New(loom.Config{
    Enabled:      cfg.LoomEnabled,
    DispatchMode: cfg.LoomDispatchMode,
    WorkerPubkeys: cfg.LoomWorkerPubkeys,
    MaxDuration:  cfg.LoomJobMaxDuration,
    // …
}, st, giteaClient, serverSigner, loomRelayURLs, cfg.GiteaRepositoriesDir, resolverSource, logger)
```

---

## 11. Phased implementation plan (files / packages)

Each phase is independently shippable and testable. Suggested beads are noted;
file them as children of `phase1-yk8`.

### Phase 1 — Gitea commit-status writer + reflect Tier-A results *(smallest slice, no Loom submission, no payment)*
- **Add** `internal/gitea/status.go`: `CreateCommitStatus` (§6a).
- **Add** `internal/store/loomjobs.go`: correlation table + bounded CRUD (§6b).
- **Add** `internal/loom/` package skeleton with the inbound consumer + status
  mapper (§5, §6).
- **Change** `internal/hiveci/runner.go`: emit `pending` before waiting/running
  and exactly one terminal state after, through a **neutral status-sink
  interface** (e.g. `type StatusSink interface { Set(ctx, ref, state, ...) }`)
  rather than importing `gitea.Client` directly — so the runner stays decoupled
  and status delivery is independently retryable (§6d). *(Coordinate: this is
  Item D-owned; land via the hook interface or with owner sign-off.)*
- **Change** `internal/relay/kinds.go` (+ constants), `subscriber.go` (filter),
  `main.go` (wire `loomSvc`), `config.go` (`Loom*`).
- **Tests:** commit-status POST (httptest), correlation TTL, terminal-state mapping.

### Phase 2 — Outbound Hive-CI-over-Loom (trusted/free workers)
- **Add** worker-ad pool + selection in `internal/loom/` (kind `10100`).
- **Add** ephemeral keypair mint + NIP-44 `HIVE_CI_NSEC` encryption to worker.
- **Add** `5401` + `5100` builders/publishers; dispatch record write; initial
  `pending` status.
- **Authz:** route author authorization through `nostrauthz.Resolver` (§7);
  refactor `hiveci` to share it.
- **Config:** `LOOM_DISPATCH_MODE`, `LOOM_WORKER_PUBKEYS`, `LOOM_STATIC_PAYMENT_TOKEN`.
- **Tests:** authorized/unauthorized dispatch, secret encryption round-trip,
  inbound `5402` publisher-key verification.

### Phase 3 — Cashu payment, Blossom log ingestion, cancellation
- **Add** `internal/cashu/` wallet (mint, pubkey-lock, change redemption from `5101`).
- Compute payment/timeout from worker `price`/`max_duration`.
- **Add** guarded Blossom log fetch (`internal/safefetch`) → attach tail to status
  description / Nostr `30315`.
- **Add** `5102` cancellation on superseded runs.
- **Tests:** payment math, change redemption, egress guard.

### Phase 4 — Dialect reconciliation (pending Q1)
- Decide the fate of `publisher/ci.go`'s cascadia `ci/workflow-run` (25910) path:
  deprecate, or bridge canonical `5401` ⇄ cascadia via its legacy map. Only after
  maintainer resolves Q1.

Dependency order: **Phase 1 → 2 → 3**; Phase 4 is independent and gated on Q1.

---

## 12. Open questions for the maintainer

1. **Protocol dialect (blocking Phase 2/4).** Should grasp-gitea speak the
   **canonical Loom/Hive-CI kinds** (`5100/5101/30100/5102/5401/5402`, this
   design's assumption) or the **cascadia `CAS_INTENT` (25910) dialect** its
   `publisher/ci.go` already emits — or bridge both? cascadia has **no legacy
   mapping for the canonical Loom `5100`/`5101`**, so the two cannot fully
   interoperate today. Which do real target workers consume?
2. **grasp-gitea's role.** Confirm grasp-gitea is a **client/orchestrator only**
   and will not advertise as a Loom worker (`10100`). (Assumed yes.)
3. **Worker command contract.** What `cmd`/`args`/container image do published
   Hive-CI Loom workers expect for "clone ngit repo at commit + run act"? This
   determines `LOOM_JOB_CMD_TEMPLATE`. Is there a reference worker image?
4. **Payment posture.** Is a **trusted-fleet, free/static-token** mode (Phase 2)
   acceptable for the first release, deferring a real Cashu wallet (Phase 3)? Any
   existing mint/wallet the bridge should reuse?
5. **Local vs remote default.** Should the default `LOOM_DISPATCH_MODE` be `local`
   (keep Tier-A `act`), `remote`, or `both`? Does the operator want to keep the
   local runner at all once remote Loom exists?
6. **Merge gating.** Should Loom commit statuses **gate merges** (branch
   protection required-status contexts), or be advisory-only initially?
7. **Blossom logs.** Should the bridge fetch/re-host Blossom logs (guarded egress)
   or just link `target_url` to the worker-provided Blossom URL (cheaper, Phase 1)?
8. **Webhook-triggered CI authorization.** Relay triggers have a Nostr author to
   authorize via `nostrauthz`. A **Gitea webhook push has no Nostr event author** —
   treating the webhook sender as a maintainer conflates two trust domains. Should
   webhook-triggered dispatch be scoped to an already-provisioned owner mapping /
   an owner-authorized state transition, and not use `nostrauthz` author resolution
   at all? (Recommended: yes.)

---

## 13. Security considerations

- **Inbound forgery.** Anchoring inbound authority in our own dispatch record +
  ephemeral-publisher/worker-pubkey verification (§7) prevents a stranger from
  posting a fake CI status for an arbitrary commit. Never trust a `5101`/`5402`
  that lacks a correlated dispatch.
- **Outbound author authz.** Reuse `nostrauthz` so only owner/maintainer-authored
  workflows are ever dispatched (no untrusted-contributor code execution on paid
  workers) — consistent with the confirmed product decision in the remediation
  plan.
- **Secret handling.** `HIVE_CI_NSEC` is a per-run ephemeral key, NIP-44 encrypted
  to the worker; it can sign only that run's `5402` and controls nothing else.
- **Resource bounds.** Correlation table, worker-ad pool, and dedup caches are all
  TTL/size-bounded (reuse existing patterns) — no attacker-controlled key
  retention (Item D's bounded-map requirement).
- **Egress.** Any Blossom/log fetch (Phase 3) goes through `internal/safefetch`
  (HTTPS-only, private-range denial), per Item C.
- **Payment safety.** Cashu tokens pubkey-locked; change redeemed only from a
  worker-signed `5101` correlated to our dispatch. Persist token/quote spend state
  **before** dispatch and make retries reuse the exact request, so a retry never
  mints a second payment (Phase 3).
- **Ephemeral secret hygiene.** Persist only `publisher_pub`; avoid persisting
  `nsec_e` unless crash recovery requires it, and if so encrypt at rest (reuse the
  signer's `secretbox` master-key pattern) and delete on terminal completion.
  **Never reuse the same `HIVE_CI_NSEC` when re-dispatching to a different worker.**
- **Async isolation.** The relay handler enqueues; execution/delivery run in
  bounded background workers so a slow worker cannot stall the subscription
  (§10).

---

## 15. Test & interop matrix

Beyond happy-path event flow, the implementation beads must cover adversarial and
interop cases with **canonical wire-event fixtures**:

- Multi-relay duplicate `30100`/`5101`/`5402` (dedup by id).
- Equal-`created_at` `30100` conflict (lower-id tie-break) and **future-`created_at`**
  skew rejection.
- `30100` replaying a foreign `d` under a non-worker key (rejected).
- Terminal result arriving **before** any `30100` status; late `running` after
  terminal (ignored).
- `5101` vs `5402` disagreement / both orders (`5402` precedence).
- Restart **between attempt-persist and relay-publish** (idempotent republish).
- Gitea status POST 404 / 5xx (status retried, workflow **not** re-run).
- Stale / rotated worker ad; unpaid dispatch to a Cashu-requiring worker (refused).
- Cancellation race (`5102`) vs incoming terminal result.
- Missing commit (`awaiting_git_object`) then release after sync.
- Blossom SSRF / oversize download (guarded, Phase 3).
- Embedded-relay admission of Loom kinds; confirm **no self-echo loop**.
- Confirm no cascadia `25910` translation is required in `canonical` mode.

---

## 14. Summary of new/changed files

**New:**
- `internal/loom/` — worker-ad pool, dispatch, inbound consumer, status mapper.
- `internal/gitea/status.go` — `CreateCommitStatus`.
- `internal/store/loomjobs.go` — dispatch correlation table.
- `internal/cashu/` — (Phase 3) wallet.

**Changed:**
- `internal/relay/kinds.go` — Loom/Hive kind constants.
- `internal/relay/subscriber.go` — subscription filter kinds.
- `internal/config/config.go` — `Loom*` config block.
- `cmd/grasp-bridge/main.go` — construct + wire `loomSvc`; dispatch hook.
- `internal/hiveci/runner.go` — route local results to the Gitea status writer;
  share `nostrauthz` for author authorization.

**Cross-item note (append to remediation plan):** Phase 1 touches Item D-owned
`internal/hiveci/runner.go` and `cmd/grasp-bridge/main.go` and Item C-owned
`internal/gitea/client.go` (new sibling file `status.go`). Coordinate via small
hooks / owner sign-off as the plan requires.

# Phase 6b — Active-active shared transactional store (design)

Status: **design** (beads `phase1-09c`). This scopes the work; it is not yet
implemented. The single-node reconciliation subsystem (`phase1-u11`) shipped
independently and does not depend on this.

## Problem

The bridge stores all durable state in a single embedded SQLite file:

- `bridge_tokens` — hashed bridge tokens, per-user active limit
- `gitea_pat_credentials` — encrypted hidden PATs, one-active partial unique index
- `nip98_replay_claims` — single-use NIP-98 proof ledger
- `auth_audit_events`
- session handoffs / NIP-46 bindings (relay-auth continuity)

A single writer is a single point of failure and caps throughput at one node.
Active-active (two+ bridge replicas fronting one Gitea, or sharded Giteas)
requires a **shared transactional backend** with cross-node guarantees that
SQLite-on-a-file cannot provide.

## The invariants that must survive multi-writer

These are the correctness properties the current code relies on, each of
which becomes a distributed concern:

1. **NIP-98 single-use.** A proof consumed on node A must be rejected on node
   B. Today this is a conditional INSERT into `nip98_replay_claims` on one
   writer. Multi-node needs a unique constraint enforced by the shared store
   with `INSERT ... ON CONFLICT DO NOTHING` semantics and a real serializable
   or at least read-committed-with-unique-violation guarantee.
2. **One active hidden PAT per user.** Enforced today by a partial unique
   index (`WHERE state='active'`). Postgres supports the same partial unique
   index, but the create-before-retire transaction (activate new + demote old
   in one tx) must remain atomic under concurrent minters on different nodes.
   The per-user striped in-process mutex (`userLock`) is **node-local** and
   does not serialize across nodes — it must be replaced or supplemented by a
   DB-level advisory lock keyed on the Gitea user id.
3. **Active bridge-token limit per subject.** The race-free conditional
   insert (`INSERT ... SELECT WHERE (count) < limit`) must execute in a
   single round trip against the shared store.
4. **PAT retirement / reconciliation sweeps** must not double-run destructive
   Gitea deletes from two nodes. Needs either a leader-elected maintenance
   role or idempotent-by-construction sweeps (the current sweeps are already
   404-idempotent, but the stuck-provisioning recovery takes `userLock`,
   which must become a DB advisory lock).

## Approach

### Store interface abstraction (prerequisite, ships first)

Extract a `Store` interface from `*store.SQLiteStore` covering every method
the auth/proxy layers call (already ~40 methods, all concrete today). Both
`SQLiteStore` and a new `PostgresStore` implement it. This is mechanical,
fully testable in the dev environment, and unblocks everything else. **Do
this first as its own PR**; it has value even single-node (test doubles).

### Postgres backend

- Schema parity with the SQLite DDL; partial unique indexes port directly.
- Replace node-local `userLock` with `pg_advisory_xact_lock(giteaUserID)`
  around the PAT lifecycle transaction.
- `nip98_replay_claims`: `INSERT ... ON CONFLICT (event_id) DO NOTHING`,
  treat 0 rows affected as replay.
- Connection pooling with a bounded pool; the streaming proxy hot path only
  touches the store for token auth + DownstreamPAT, so pool pressure is
  auth-rate, not transfer-rate.

### Maintenance leadership (step 4 — designed here)

**Problem.** `TokenService.maintain()` runs once per tick and performs five
global sweeps: idle-PAT retirement, proactive re-encryption, terminal/
stuck-provisioning reconciliation, expired-replay-claim cleanup, and audit
retention. Two of them (retire, stuck-provisioning) already serialize per
user through `WithUserLock` (step 3), so they are *correct* multi-node — but
all five are wasteful when every replica runs them every tick: duplicate
Gitea `DELETE` calls, duplicate CAS reseals, N× the DB churn. Terminal
reconciliation in particular fires a Gitea API call per error/orphaned row;
running it on 3 nodes triples that load for zero benefit.

Leadership is therefore an **efficiency** guarantee, not a **correctness**
one. Every sweep must remain idempotent regardless (they are: Gitea deletes
treat 404 as success, reseal is CAS, cleanup deletes are set-based). This is
deliberate — it means a leadership handoff mid-sweep can never corrupt state,
only waste a little work.

**Chosen design: per-tick advisory-lease leader.**

Add to the store contract:

```go
// TryMaintenanceLease attempts to become the maintenance leader for one
// sweep. acquired=false means another node holds it right now (skip this
// tick). release() frees it; always call it when acquired.
TryMaintenanceLease(ctx context.Context) (acquired bool, release func(), err error)
```

- **Postgres:** `pg_try_advisory_lock(MAINT_KEY)` on a dedicated pooled
  connection. Non-blocking: a follower gets `acquired=false` instantly and
  skips the sweep. `release()` runs `pg_advisory_unlock` and closes the
  connection. If the leader **crashes**, its session ends and Postgres frees
  the lock automatically — the next tick, some node acquires it. At most one
  holder per key across the whole cluster, by construction.
- **SQLite:** single-node, so it is always the leader — `(true, noop, nil)`.

`RunMaintenance` wraps the whole `maintain()` pass:

```go
for {
    if acquired, release, err := t.store.TryMaintenanceLease(ctx); err != nil {
        t.logger.Warn("maintenance lease error; skipping tick", "error", err)
    } else if acquired {
        t.maintain(ctx)
        release()
    } else {
        t.logger.Debug("not maintenance leader this tick; skipping")
    }
    select { case <-ctx.Done(): return; case <-ticker.C: }
}
```

**Why per-tick, not a held lease with heartbeat.** The lock is acquired at
the start of a tick and released at its end — held only for the duration of
one `maintain()` pass, not continuously. Rationale:

- A continuously-held lease means a *wedged* (not crashed) leader — alive
  but stuck — blocks all maintenance indefinitely and needs liveness
  detection (heartbeat + takeover timeout) to recover. Per-tick acquisition
  makes the worst case a single skipped tick.
- Leadership may flap between nodes tick-to-tick. That is fine: maintenance
  is stateless, and the interval (default 1h) dwarfs a sweep's duration, so
  in practice one node holds it for the whole sweep and releases well
  before the next tick.
- No new tables, no heartbeat rows, no clock assumptions. The Postgres
  session *is* the liveness signal.

**Failure modes.**

| Event | Behavior |
|---|---|
| Follower tick | `acquired=false`, sweep skipped, no-op |
| Leader crash mid-sweep | Session ends → Postgres frees lock → next tick re-elects; partial sweep is idempotent, resumes next tick |
| DB unreachable at lease time | `err != nil` → skip tick, log, stay follower, retry next tick (never crash) |
| Two nodes race the lease | `pg_try_advisory_lock` grants exactly one; the loser skips |
| Long sweep overruns the interval | Leader still holds the lock; followers keep skipping; no overlap |

**What this does NOT need:** a heartbeat table, a lease-expiry timestamp, or
clock synchronization — all of which a token-bucket or timestamp-lease design
would require. The advisory lock's session lifetime is the entire mechanism.

**Rejected alternatives.**

- *Idempotent-everywhere, no leader (original option B):* correct, but leaves
  the N× Gitea API load unaddressed — the whole point of leadership here.
  Kept as the safety net *under* leadership, not instead of it.
- *Held lease + heartbeat:* needed only if a sweep must not restart on
  handoff. Ours are idempotent, so the added liveness machinery buys nothing.
- *External coordinator (etcd/Consul/k8s lease):* real infra dependency for a
  problem one `pg_try_advisory_lock` solves, given we already require the
  shared Postgres.

**Testable now (implemented alongside this sketch):** `TryMaintenanceLease`
on both backends + a conformance check (`MaintenanceLeaseIsSingleHolder`:
of N racing acquirers exactly one succeeds; after release another can take
it). The `RunMaintenance` wrapper is wired but inert single-node (SQLite is
always leader). Multi-node exercise waits for the two-replica deploy
(step 5).

### Session handoff / NIP-46 bindings

These already persist in the store today; once the interface + Postgres
backend exist they move with everything else. The edge-secret handoff is
stateless per request (HMAC-style shared secret), so no new distributed
state — only the NIP-46 durable session rows need shared storage, which the
backend swap covers.

## Sequencing (proposed sub-PRs under phase1-09c)

1. ✅ **SHIPPED** — `store.AuthStore` interface (internal/store/interface.go)
   covering the 40+ methods the auth layer calls, with the distributed
   contract documented on the interface (cross-node single-use replay
   claims, atomic token limit, create-before-retire activation, CAS
   reseal, sql.ErrNoRows). internal/auth (Service, IdentityService,
   TokenService, NIP46Handler) now holds the interface, never
   *SQLiteStore. Reusable conformance suite in internal/store/storetest
   — a Postgres backend runs storetest.Run unchanged.
2. ✅ **SHIPPED** — `store.PostgresStore` (internal/store/postgres.go)
   implements AuthStore with byte-identical representation (RFC3339 TEXT
   timestamps, JSON scope arrays, BYTEA secrets) so comparisons behave the
   same on both backends. Conformance runs against a real Postgres when
   `GRASP_TEST_POSTGRES_DSN` is set (docker: postgres:16-alpine on :5433,
   per-test schemas via connection-scoped search_path). The suite now
   includes concurrency checks — and they immediately caught the READ
   COMMITTED token-limit race SQLite's single-writer hides (7 tokens
   under a limit of 3): fixed with a pg_advisory_xact_lock keyed on the
   pubkey inside InsertBridgeToken. Concurrent replay claims (one winner)
   and concurrent PAT reservations (distinct generations, PK-enforced,
   error=retry) verified on both backends.
3. ✅ **SHIPPED** — `AuthStore.WithUserLock(ctx, giteaUserID, fn)` is now
   part of the store contract: SQLite implements it as the in-process
   striped mutex (single-node, unchanged semantics), Postgres as a
   session-scoped `pg_advisory_lock` on a dedicated pooled connection
   (never wrapping a transaction — fn performs Gitea HTTP calls). The
   TokenService's node-local `userLock` is GONE: mint, scope upgrade,
   EnsureHiddenPAT, retirement, and stuck-provisioning recovery all
   serialize through the store, so exclusion follows the backend.
   Replay ON CONFLICT landed with step 2. Conformance:
   UserLockIsMutuallyExclusive (16 racing critical sections, overlap
   detector, lost-update check; distinct users don't block).
   NOT yet wired: main.go still opens SQLite only — identity links are
   read by publisher/signer/webhook/profilesync/proxy, so switching
   auth alone to Postgres would split-brain identity data. DSN wiring
   belongs with the consumer convergence in step 5.
4. Advisory-lock maintenance leadership.
5. Deploy two replicas behind the existing nginx; run the `phase1-fww`
   load/chaos suite (needs real infra — that issue owns it).

## Explicitly out of scope here

- Multiple **Gitea** upstreams / sharding (that is `phase1-fww`; this issue
  is about multiple **bridge** replicas over one Gitea).
- Load/chaos harness (`phase1-fww`).
- Anything that can only be validated on the deployed stack is gated behind
  live verification, exactly as the earlier phases were.

## Why this is a design, not code, right now

Steps 2–5 require a running Postgres and a two-node deployment to verify the
distributed invariants — none of which exists in the dev environment, and
each of which is a correctness-critical property that must be *tested*, not
assumed. Step 1 (the interface extraction) is mechanical and safe to do now
whenever we choose to start; it is filed as the first sub-PR.

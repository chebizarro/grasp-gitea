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

### Maintenance leadership

The maintenance loop (`RunMaintenance`) runs destructive sweeps. Options:

- **A. Advisory-lock leader:** each node tries `pg_try_advisory_lock(MAINT)`
  once per tick; only the holder sweeps. Simple, no extra infra.
- **B. Idempotent everywhere:** make every sweep safe to run concurrently
  (they mostly are — Gitea deletes are 404-idempotent; the stuck-provisioning
  path already re-reads under a lock). Preferred long-term, but the
  advisory-lock leader is the safer first cut.

### Session handoff / NIP-46 bindings

These already persist in the store today; once the interface + Postgres
backend exist they move with everything else. The edge-secret handoff is
stateless per request (HMAC-style shared secret), so no new distributed
state — only the NIP-46 durable session rows need shared storage, which the
backend swap covers.

## Sequencing (proposed sub-PRs under phase1-09c)

1. `Store` interface extraction + SQLite conformance test suite (single-node,
   no behavior change).
2. Postgres backend implementing the interface + the same conformance suite
   run against a Postgres testcontainer.
3. DB advisory locks replacing `userLock`; replay-claim ON CONFLICT.
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

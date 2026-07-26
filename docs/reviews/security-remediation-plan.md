# grasp-gitea Security & Completeness Remediation Plan

Source: holistic audit (2026-07-25). This is the shared coordination doc for the
remediation effort. Each work item below is owned by exactly one agent to avoid
concurrent edits to the same file. **Do not edit files outside your item's
"Owns" list** — if you need a change in another item's file, add a small hook
and note it here under "Cross-item notes".

Confirmed product decisions (from maintainer):
- Open mode (empty `ADMIN_API_TOKEN`) is NOT deliberate → fail closed.
- Hive-CI is expected to run ONLY owner-authored workflows (full untrusted-
  contributor sandboxing is out of scope for now).

## Shared helpers (create once, reuse everywhere)
- `internal/nostrauthz` (NEW, created by Item A): resolves a repo's owner +
  recursive maintainer set from the announcement/state, and answers
  `IsAuthorized(pubkey, repoCoord)`. Used by A (state), B (issue status).
- `internal/safefetch` (NEW, created by Item C): guarded HTTP client (HTTPS-only,
  per-redirect resolved-IP validation, deny private/loopback/link-local/metadata)
  and a git-clone-URL validator. Used by C (avatars), A (clone in proactivesync),
  B (clone in reflector).

## Wave 1 (parallel — file-disjoint): Items A, C, D
## Wave 2 (parallel — file-disjoint, depend on A+C helpers): Items B, E
## Wave 3: Item F (Loom design)

---

### Item A — Inbound authorization & state authority  [Wave 1]
Beads: phase1-cqu (P0 state authz), phase1-nlx (P1 maintainer/bridge purgatory),
phase1-3x7 (P1 outbox state tracking).
Owns: `internal/proactivesync/service.go`, `cmd/grasp-bridge/embedded_full.go`,
`internal/publisher/service.go`, `internal/outbox/worker.go`,
`internal/nostrstate/state.go`, NEW `internal/nostrauthz/*`.
Done when:
- [ ] Unauthorized kind:30618 (author not owner/maintainer) rejected before any
      ref mutation; `p` treated as hint only; ref-deletion attack test added.
- [ ] Maintainer/bridge-signed state resolves to correct repo via validated owner
      coordinate and is held in purgatory when git objects are absent.
- [ ] `mappings.last_state_digest` advances after owner-signed outbox publication.
- [ ] `internal/nostrauthz` exports the resolver used by Item B.
- [ ] Wire `internal/safefetch` (from Item C) into the proactivesync clone fetch.

### Item C — SSRF guard + identity/NIP-05 hardening  [Wave 1]
Beads: phase1-l91 (P0 SSRF), phase1-6k7 (P0 NIP-05 collisions), phase1-9w4 (P1 kind-0 validation).
Owns: NEW `internal/safefetch/*`, `internal/gitea/profile.go`,
`internal/gitea/client.go`, `internal/nip05resolve/resolve.go`,
`internal/nostrprofile/profile.go`, `internal/provisioner/provisioner.go`,
`internal/auth/identity.go`, identity uniqueness constraint in `internal/store/sqlite.go`.
Done when:
- [ ] `internal/safefetch` blocks non-HTTPS + private/loopback/link-local/metadata
      addrs including across redirects; avatar download uses it.
- [ ] NIP-05 org/user/repo names are domain-qualified/collision-resistant;
      existing Gitea org/user never silently adopted; explicit ownership-link
      required; DB uniqueness constraint on gitea identity.
- [ ] kind-0 events rejected unless event id/sig/author validate.

### Item D — API / signer / CI / config hardening  [Wave 1]
Beads: phase1-7fr (P0 fail-closed admin), phase1-5tt (P0 Hive owner-only),
phase1-h8g (P1 NIP-46 init limits), phase1-bi9 (P1 signer master key + merged relays),
phase1-u5m (P2 bounded maps — repoStateLocks + hiveci `started` only).
Owns: `internal/api/server.go`, `internal/config/config.go`,
`internal/auth/nip46handler.go`, `internal/signer/service.go`,
`internal/signer/server_session.go`, `internal/hiveci/runner.go`,
`cmd/grasp-bridge/main.go`.
Done when:
- [x] Startup fails in production without `ADMIN_API_TOKEN`; all mutation/signer/
      queue/mapping/metrics routes fail closed (no open-mode fallthrough).
- [x] Hive-CI executes only owner/maintainer-authored workflows; per-run timeout
      + concurrency cap enforced.
- [x] NIP-46 init rate-limited/bounded; connection attempts cancel on timeout;
      expired sessions/challenges pruned.
- [x] Production durable signing requires `SIGNER_MASTER_KEY`; signer gets merged
      embedded+configured relay set.
- [x] repoStateLocks + hiveci `started` maps are bounded/TTL.
Note: NIP-46 handler is shared conceptually with Item E's session work but E does
NOT edit nip46handler.go — E only adds a session-handoff endpoint elsewhere.

### Item B — NIP-34 reflection completeness  [Wave 2 — needs A + C helpers]
Beads: phase1-306 (P0 issue status authz), phase1-8w0 (P1 durable threads + NIP-22),
phase1-i96 (P1 inbound labels + removal), phase1-0fk (P1 webhook durability),
phase1-u5m (threads-map portion, subsumed by persistence).
Owns: `internal/reflector/reflector.go`, `internal/webhook/handler.go`,
`internal/webhook/*.go`, `internal/relay/subscriber.go`.
Done when:
- [ ] Issue status events enforce NIP-34 authority (use `internal/nostrauthz`).
- [ ] Thread roots persisted (SQLite) + survive restart; standard NIP-22 comment
      referencing only its root reflects correctly.
- [ ] Inbound NIP-32 (kind 1985) labels map to Gitea; unlabeled has distinct
      removal representation.
- [ ] Webhook deliveries durably recorded before HTTP 200; bridge-signed paths retried.
- [ ] Wire `internal/safefetch` into reflector clone fetch.

### Item E — Login/session + deploy + pre-receive + ordering  [Wave 2]
Beads: phase1-p1j (P1 Gitea session + NIP-55), phase1-9mq (P1 open redirect),
phase1-qn6 (P1 canonical nginx), phase1-k9u (P1 compose hook install),
phase1-h6b (P1 refs/nostr push quotas), phase1-vga (P1 pre-receive timeout),
phase1-11i (P1 replaceable ordering), phase1-x94 (P2 README/Dockerfile drift).
Owns: `internal/auth/auth.go`, `internal/auth/nip07handler.go`,
`internal/auth/nip55handler.go`, `deploy/**`,
`deploy/gitea/custom/public/assets/js/grasp-nostr-login.js`,
`cmd/grasp-pre-receive/main.go`, `internal/refsnostr/*`,
replaceable-ordering helpers in `internal/store/sqlite.go` +
`internal/store/purgatory.go` (ordering columns only — coordinate with C which
adds an identity uniqueness constraint to the same file; edits are in different
regions), `README.md`, `Dockerfile`.
Done when:
- [ ] Verified NIP-07/46 user obtains a real Gitea session; NIP-55 launches deep link.
- [ ] `redirect_uri` restricted to same-origin relative paths / allowlist.
- [ ] Canonical single-host nginx serves relay WS + NIP-11 at `/`, bridge API/auth,
      bare npub repo URLs; compose installs hook binary + admin-token secret in the
      Gitea container with correct relay addressing.
- [ ] refs/nostr pushes quota-limited; pre-receive relay lookups bounded + closed.
- [ ] Replaceable ordering (created_at desc, id asc tie-break) centralized for
      announcements/grasp-lists/proposed state.
- [ ] README/Dockerfile claims reconciled (install `act` or label Hive-CI experimental).

### Item F — Loom integration (design first)  [Wave 3]
Bead: phase1-yk8 (P1). Greenfield; produce a design doc under `docs/designs/`
mapping loom-protocol events → Gitea CI/status, subscription kinds, publication
path, config, then implement. Do design pass before code.

---

## Cross-item notes (append as you go)
- 2026-07-25 Item C: `internal/safefetch` now compiles. Items A/B can use `safefetch.ValidateGitCloneURL(ctx, rawURL)` immediately before Git clone/fetch; guarded HTTP callers should use `safefetch.NewClient()`.

## Progress log
- 2026-07-25: Plan created; beads filed; Wave 1 dispatch pending.

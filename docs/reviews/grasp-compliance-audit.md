# GRASP Compliance Audit (grasp-gitea stack)

Audited against `grasp/01.md`, `grasp/02.md`, `grasp/05.md` (workspace copies).
Scope = the whole stack: **grasp-bridge** + the **Gitea fork** (`/Users/bizarro/Documents/Dev/gitea`) + deploy (nginx).

## Verdict

**Not 100% GRASP compatible.** GRASP-01 (the only *required* GRASP) and GRASP-02 both have
open `MUST` gaps. The stack implements the *authorization* half of GRASP well (signed repo
state, pre-receive maintainer validation, mirror publishing) but is missing much of the
*service* half (relay accept policy, NIP-11 advertisement, npub git-HTTP path, CORS, refs/nostr
lifecycle, and periodic proactive git-data sync).

## GRASP-01 — Core Service Requirements (REQUIRED)

| # | MUST requirement | Status | Evidence |
|---|---|---|---|
| 1 | NIP-01 relay at `/` accepting 30617/30618 | ⚠️ Partial | Embedded khatru relay at `/` — but **optional** (`cfg.EmbeddedRelay`); default deploy relies on external relays. `cmd/grasp-bridge/embedded_full.go` |
| 2 | Reject announcements not listing service in **both** `clone` **and** `relays` tags | ❌ No | Provisioner checks only the `clone` prefix (`findCloneForPrefix`); never checks the `relays` tag. Embedded relay accepts any 30617/30618 unconditionally. `internal/provisioner/provisioner.go:111,355` |
| 3 | Accept other events that **tag / are tagged by** accepted announcements/issues/patches | ❌ No | Embedded relay `RejectEvent` **rejects everything except 30617/30618** — issues (1621), patches (1617), PRs (1618/1619), status (1630-1633), NIP-22 (1111) are all refused. `cmd/grasp-bridge/embedded_full.go` |
| 4 | NIP-11 doc with `supported_grasps`, `repo_acceptance_criteria`, `curation` | ❌ No | No GRASP NIP-11 fields anywhere (bridge or fork). khatru's default NIP-11 lacks them. |
| 5 | Git smart-HTTP at `/<npub>/<percent-encoded-identifier>.git` | ❌ No | Stock Gitea serves `/{username}/{reponame}` only; bridge provisions under a **NIP-05-resolved org name**, not an npub. `gitea routers/web/githttp.go:11`, `routers/web/web.go:1753`; `internal/provisioner/provisioner.go` (`giteaCloneURL` uses `orgName`) |
| 6 | Accept pushes matching latest repo-state, recursive maintainer set | ✅ Yes | `grasp-pre-receive` hook validates refs vs state, multi-maintainer. `cmd/grasp-pre-receive`, `internal/nostrstate` |
| 7 | Set repo HEAD per repo-state announcement | ⚠️ Partial | State→ref reconciliation exists (`proactivesync.updateRefIfObjectExists`) but HEAD-per-state is not explicitly enforced. |
| 8 | Accept `refs/nostr/<id>` pushes; reject on differing tip; delete/GC if no matching PR (`c` tag) within 20 min | ❌ No | Pushes are accepted (generic Gitea) and the bridge reacts with a 1631, but there is **no tip-conflict rejection and no 20-minute GC**. `internal/webhook/handler.go:355`; fork has zero `refs/nostr` handling |
| 9 | Advertise `allow-tip-sha1-in-want`, `allow-reachable-sha1-in-want`, `uploadpack.allowFilter` | ⚠️ Partial | Gitea sets `uploadpack.allowfilter` + `uploadpack.allowAnySHA1InWant` **only when partial clone enabled**; the two literal `*-sha1-in-want` flags are not set. `gitea modules/git/config.go:94-104` |
| 10 | CORS on ALL git-HTTP responses (`*`, `GET, POST`, `Content-Type`) + OPTIONS 204 | ❌ No | Gitea git-HTTP CORS is configurable and **off by default** (`AccessControlAllowOrigin` empty), and uses different values; only WebFinger hardcodes `*`. `gitea routers/web/repo/githttp.go:46-53`, `modules/setting/repository.go:172` |

## GRASP-02 — Proactive Sync (REQUIRED for GRASP-05; expected of a full server)

| MUST requirement | Status | Evidence |
|---|---|---|
| Proactively sync Nostr events (historic + live) from each announcement's `relays` tag | ⚠️ Partial | Live subscription to **configured** relays only (`internal/relay/subscriber.go`); no per-announcement `relays`-tag sync, no historic backfill. |
| Sync missing git data from `clone` servers **≥ every 1h** | ❌ No | `proactivesync` only updates refs for objects **already present locally** (`updateRefIfObjectExists`); no periodic timer and no `git fetch` from clone URLs. `internal/proactivesync/service.go` |
| Fetch git data for PR / PR-update events **≥ every 1h** and serve from `/refs/nostr/<id>` | ❌ No | Not implemented. |

## GRASP-05 — Archive (OPTIONAL)

| Requirement | Status | Evidence |
|---|---|---|
| MAY accept announcements not listing service in clone+relays | ✅ Partial | Archive-on-clone-tag-removal exists. `provisioner` `ArchiveRepo` path |
| MUST implement GRASP-02 | ❌ No | Blocked by the GRASP-02 gaps above. |

## Interpretation

Two gaps are **architectural, not bugs**:

- **#5 npub git-HTTP path.** The bridge deliberately resolves human-readable org names (NIP-05
  or hex prefix) instead of npubs — a product choice that directly conflicts with the GRASP-01
  path requirement. Reconciling means either serving an `/<npub>/...` route/redirect in the
  fork or accepting documented divergence.
- **#3 relay accept policy.** The embedded relay is intentionally announcement-only. A GRASP
  server relay must also carry the collaboration events. This is the same surface the
  user-signed migration (Phase F, bidirectional sync) needs, so the two efforts converge.

The rest (#2, #4, #8, #9, #10, all of GRASP-02) are **completable gaps** with clear specs.
Tracked under the `GRASP compliance` epic.

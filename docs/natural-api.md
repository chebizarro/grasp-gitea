# Natural git API conformance

grasp-gitea's canonical npub git smart-HTTP surface
(`/<npub>/<percent-encoded-repo-id>.git/...`) is served so that it can be
consumed directly by [`@fiatjaf/git-natural-api`](https://viewsource.win/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6/git-natural-api)
(reference checkout: `/Users/bizarro/Documents/Dev/git-natural-api`) — a
lightweight, cloneless git HTTP client used by Nostr repository-discovery
clients (e.g. gitworkshop.dev) to browse refs, trees, commits, and individual
blobs without running `git clone`.

This document describes the wire-level contract the bridge guarantees, how
it maps onto the natural-api client's exported functions, and what a deploy
must configure for the contract to hold. It complements
`docs/reviews/grasp-compliance-audit.md` (GRASP-01 requirements 5, 9, 10),
which tracks this surface as spec compliance; this document is the
operational/API reference.

## Endpoints

Both endpoints live under the canonical npub path handled by
`rootHandler` → `gitHTTPNpubProxy` in `internal/api/githttp_npub.go`, which
resolves `(npub, repo-id)` through the mapping store and proxies to Gitea's
own git smart-HTTP backend via `internal/giteaproxy`:

- `GET /<npub>/<percent-encoded-repo-id>.git/info/refs?service=git-upload-pack`
  — ref advertisement + capability list (`getInfoRefs`).
- `POST /<npub>/<percent-encoded-repo-id>.git/git-upload-pack`
  — pkt-line `want`/`deepen`/`filter` negotiation, packfile response
  (`fetchPackfile` and everything built on it: `getObject`,
  `getDirectoryTreeAt`, `fetchCommitsOnly`, `getSingleCommit`,
  `getObjectByPath`, `shallowCloneRepositoryAt`).

`git-receive-pack` (push) is also proxied at this path but is out of scope
for natural-api, which is read-only.

Both `npub` and the repo identifier are percent-decoded independently by
`parseNpubGitHTTPPath`; the identifier is whatever string the NIP-34
announcement's `d` tag / `clone` URL uses, not necessarily a Gitea-safe
slug. Requests for a `.git` path with no mapping return 404 (or a
human-readable landing page for `GET .../<id>.git` with no subpath); requests
where provisioning hasn't finished installing the pre-receive hook are also
treated as not-found rather than served, so the guarantees below never apply
to a partially-provisioned repository.

## Protocol v0 capabilities

`GET info/refs?service=git-upload-pack` returns the advertisement that
`git http-backend` (invoked inside Gitea, reached through the proxy)
produces for the underlying bare repository. The advertised capability set
is exercised end-to-end by
`internal/api/githttp_natural_api_test.go::TestNaturalAPIInfoRefsAdvertisement`,
which checks it against the exact sets `packs.ts` defines:

| natural-api set (`packs.ts`) | capabilities | why |
|---|---|---|
| `necessaryCapabilities` | `multi_ack_detailed`, `side-band-64k` | `getObject`/`fetchCommitsOnly`/`getDirectoryTreeAt` throw `MissingCapability` without these; the client always echoes them on its `want` line. |
| `requiredCapabilities` | `shallow`, `object-format=sha1` | server-side declarations checked before any fetch. |
| `defaultCapabilities` | `ofs-delta`, `no-progress` | echoed when advertised; the natural-api conformance suite pins their presence since their absence would change the request shape it validates. |
| filter support | `filter` | required by `getDirectoryTreeAt` (`blob:none`) and `fetchCommitsOnly` (`tree:0`); comes from `uploadpack.allowFilter`. |
| arbitrary-want support | `allow-tip-sha1-in-want`, `allow-reachable-sha1-in-want` | `getObject`'s want of a non-ref-tip SHA would otherwise be refused with `not our ref`. |

**Protocol v0 has no `allow-any-sha1-in-want` capability token.** Git only
advertises `allow-tip-sha1-in-want` and `allow-reachable-sha1-in-want`, even
when `uploadpack.allowAnySHA1InWant` is set server-side (see
`hooks.uploadPackCapabilities`). `allowAnySHA1InWant` therefore has no
distinct wire signal — it surfaces behaviorally, not as an advertised token:
it's what lets `git-upload-pack` accept a `want` for a **dangling** blob (in
the object database but unreachable from any ref), not just a reachable
non-tip object. `TestNaturalAPIWantArbitraryBlob` proves the reachable case
and `TestNaturalAPIWantDanglingBlob` proves the dangling case, both against
the literal `deepen 1`, no-filter want shape `getObject` sends.

## Partial clone (`filter`) and shallow (`deepen`)

`createWantRequest` in `packs.ts` builds requests of the shape:

```
want <sha> <capabilities...> agent=nsa/1.0.0
deepen <n>        # optional
filter <spec>     # optional
<flush>
done
```

Two filter specs are exercised end-to-end:

- **`filter blob:none`** — `getDirectoryTreeAt`'s request (`deepen 1`,
  `filter blob:none`). `TestNaturalAPIUploadPackDeepenFilterBlobNone` proves
  the resulting packfile contains the wanted commit and its trees (root +
  nested) but omits blobs and the parent commit — i.e. both `filter` and
  `deepen 1` are honored simultaneously.
- **`filter tree:0`** — `fetchCommitsOnly`'s request (`deepen <n>`,
  `filter tree:0`). `TestNaturalAPIUploadPackFilterTreeZero` proves the
  packfile contains only the wanted commit object, no trees, no blobs.

Both depend on `uploadpack.allowFilter = true` on the repository (set by
`hooks.Installer`); without it the server would reject the `filter` line
in the want request rather than silently ignoring it.

`deepen <n>` alone (no filter) is used by `getObject` and
`shallowCloneRepositoryAt`/`getSingleCommit`/`fetchCommitsOnly` with
`deepen 1` to bound history depth; `getDirectoryTreeAt`'s `nestLimit`
parameter maps to the same `deepen` pkt-line, not to a distinct capability.

## Arbitrary blob wants

`getObject(url, blobHash)` sends a plain `want <blobHash> ... agent=nsa/1.0.0`
with `deepen 1` and no filter — i.e. it wants an object by SHA directly,
which may not be a ref tip and may not even be reachable from any ref (a
Nostr event can reference a blob hash before any ref advertises it). This
requires all three `uploadpack.allow*SHA1InWant` settings from
`hooks.uploadPackCapabilities`:

- `uploadpack.allowTipSHA1InWant`
- `uploadpack.allowReachableSHA1InWant`
- `uploadpack.allowAnySHA1InWant`

`TestNaturalAPIWantArbitraryBlob` (reachable non-tip blob) and
`TestNaturalAPIWantDanglingBlob` (blob unreachable from any ref) both assert
`200 OK` and that the wanted blob is present, byte-for-byte, in the returned
pack.

## CORS

Browser-based discovery clients (natural-api runs in gitworkshop.dev and
similar) call `fetch()` cross-origin against both endpoints, so both must
carry CORS headers and answer preflight. `setGitHTTPCORS` in
`internal/api/githttp_npub.go` (mirrored by `giteaproxy`'s own
`setGitHTTPCORS` for requests it rejects before reaching the npub handler)
sets, on every response including errors:

```
Access-Control-Allow-Origin:  *
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
```

`OPTIONS` requests to either endpoint short-circuit to `204 No Content`
with those headers attached (`gitHTTPNpubProxy`'s method switch, ahead of
the mapping lookup — a preflight never depends on whether the repository
exists). `TestNaturalAPICORSAndPreflight` asserts `204` plus the header set
for `OPTIONS` on both `info/refs` and `git-upload-pack`; every other natural
API conformance test also asserts the header set is present on its `200`
response via `assertGitHTTPCORS`.

Nginx does not set or override these headers — `deploy/nginx/gitea-vhost.conf.example`
routes the `^(/npub1.+\.git(?:/.*)?|...)$` location straight to the bridge
backend (`grasp_bridge_backend`) with `proxy_pass`/`proxy_set_header`
plumbing only, so the CORS response the client sees is exactly what the
bridge's Go handler produced.

## Client function → server behavior map

| `git-natural-api` export | HTTP calls | server behavior it relies on |
|---|---|---|
| `getInfoRefs(url)` | `GET info/refs?service=git-upload-pack` | ref/HEAD/symref advertisement + full capability list above |
| `getObject(url, blobHash)` | `GET info/refs`, `POST git-upload-pack` (`deepen 1`, no filter) | `allow-tip`/`allow-reachable`/`allow-any` SHA1-in-want |
| `getDirectoryTreeAt(url, ref, nestLimit?)` | `GET info/refs` (if `ref` starts with `refs/`), `POST git-upload-pack` (`deepen nestLimit`, `filter blob:none`) | `filter` capability + `uploadpack.allowFilter` |
| `shallowCloneRepositoryAt(url, ref)` | `GET info/refs`, `POST git-upload-pack` (`deepen 1`, no filter) | necessary/required/default capabilities |
| `fetchCommitsOnly(url, ref, maxCommits?)` | `GET info/refs`, `POST git-upload-pack` (`deepen maxCommits`, `filter tree:0`) | `filter` capability |
| `getSingleCommit(url, ref)` | same as `fetchCommitsOnly`, `maxCommits=1` | same |
| `getObjectByPath(url, ref, path)` | `getDirectoryTreeAt` at `path.length` depth, then walks the returned tree | same as `getDirectoryTreeAt` |

## Conformance test suite

`internal/api/githttp_natural_api_test.go` (introduced in commit `bb5ac90`,
"Add natural git API conformance test suite (phase1-0vv)") is the source of
truth for all of the above. It does not mock the git protocol: it drives a
real bare repository through `hooks.Installer` (the same config a
provisioned repo gets), serves it with `git http-backend` under CGI, fronts
it with the real `giteaproxy` behind the `/<npub>/<id>.git` path, and then
replays the exact byte-level request shapes `packs.ts`/`refs.ts` send —
parsing responses the same way the client parses them (pkt-line advertisement
parsing mirroring `refs.ts`, side-band-64k demuxing mirroring `packs.ts`).
Each assertion failure message names the natural-api client function that
would break, e.g. *"missing capability … getObject wants of non-tip SHAs
would be refused (not our ref)"*.

Test coverage:

- `TestNaturalAPIInfoRefsAdvertisement` — Behavior 1: full capability list.
- `TestNaturalAPIUploadPackDeepenFilterBlobNone` — Behavior 2:
  `getDirectoryTreeAt`'s `deepen 1` + `filter blob:none`.
- `TestNaturalAPIUploadPackFilterTreeZero` — Behavior 2b:
  `fetchCommitsOnly`'s `filter tree:0`.
- `TestNaturalAPIWantArbitraryBlob` — Behavior 3: reachable non-tip blob
  want (`getObject`).
- `TestNaturalAPIWantDanglingBlob` — Behavior 3b: dangling (unreachable)
  blob want.
- `TestNaturalAPICORSAndPreflight` — Behavior 4: CORS headers + `OPTIONS`
  204 on both endpoints.

## Deploy prerequisites

The conformance guarantees above depend on repository-level git config that
nothing enforces except the bridge's own provisioning and startup paths —
a repository created outside that path (or restored from a backup with
different config) will silently fail natural-api calls with `not our ref`
or `MissingCapability` errors rather than an obvious deploy error.

- **`internal/hooks/installer.go` — `uploadPackCapabilities`**: the four
  `uploadpack.*` git-config keys (`allowFilter`, `allowTipSHA1InWant`,
  `allowReachableSHA1InWant`, `allowAnySHA1InWant`, all `true`) applied
  per-repository via `git config --file <repo>/config`. Applied in two
  places:
  - **At provision time**: `Installer.Install` calls
    `configureUploadPack` right after writing the pre-receive hook, so
    every newly provisioned repository gets it atomically with hook
    installation.
  - **At startup migration**: `provisioner.Service.EnsureUploadPackCapabilities`
    (called from `cmd/grasp-bridge/main.go` on boot) walks every mapped
    repository and reapplies `Installer.ConfigureUploadPack`, so
    repositories provisioned before this capability set existed — or
    repos whose git config was reset — get migrated forward on every
    bridge restart.
- **`deploy/gitea/app.ini.phase3.snippet` — `[git.config]`**: sets
  `uploadpack.allowFilter` and `uploadpack.allowAnySHA1InWant` as Gitea-wide
  defaults (`receive.maxInputSize` is unrelated push-size hardening). The
  snippet notes that operators wanting strict literal GRASP-01 compliance
  can also set `allowTipSHA1InWant`/`allowReachableSHA1InWant` per served
  repo — in practice `hooks.Installer` already does this for every bridge-
  provisioned repository, so the per-repo config (not the Gitea-wide
  default) is what the conformance suite and production traffic rely on.
- **`deploy/nginx/gitea-vhost.conf.example`**: routes
  `/npub1.../<id>.git(/...)?` (along with conventional `.git/{info/refs,
  git-upload-pack, git-receive-pack, info/lfs/...}` paths, package registry,
  and container registry paths) to the bridge backend rather than straight
  to Gitea, so that CORS headers, hook-installed gating, and npub→owner/repo
  mapping resolution all happen before the request reaches `git
  http-backend`. There is no nginx-level CORS configuration — CORS is
  entirely the bridge's responsibility (see above).

## Related

- `docs/reviews/grasp-compliance-audit.md` — GRASP-01 requirements 5
  (npub git smart-HTTP path), 9 (advertise `allow-tip`/`allow-reachable`/
  `allowFilter`), and 10 (CORS on all git-HTTP responses + `OPTIONS` 204).
- `internal/api/githttp_npub.go` — npub path parsing, CORS, mapping
  resolution, and dispatch to the git proxy.
- `internal/giteaproxy` — the shared streaming proxy that fronts Gitea's
  git smart-HTTP backend for both conventional and npub paths.

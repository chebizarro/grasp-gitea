# Scope: NIP-05 domains as an organizational unit

Status: **proposal, not scheduled**. Written 2026-07-30.

## The question

Can a NIP-05 domain (`example.com`) act as an optional organizational unit —
grouping the identities that share it, and optionally their repositories, into
a Gitea organization?

## Recommendation up front

**Build verified domain affiliation. Do not build automatic shared Gitea
organizations yet.**

The reason is constraint (5) below: the canonical GRASP URL is
`/<npub>/<repo-id>.git` and resolves through the mapping store, so the Gitea
organization name is an *internal placement detail* with no protocol
significance. Grouping repositories into a shared org therefore buys nothing
for GRASP interoperability. It buys native Gitea features — org pages, teams,
shared private-repo ACLs, a shared package namespace — and those come with
repository transfers, a flat namespace, and a continuous revocation
obligation.

Build the shared org only when there is a committed requirement for one of:
domain-wide private read access, a shared package/container namespace, or
native Gitea org administration.

## Current behaviour (verified in code)

`internal/nip05resolve.ResolveOrgName(pubkey, relays)`:

1. Fetch `kind:0` from each relay in order; validate event ID and signature.
2. Read `nip05`; verify bidirectionally against
   `https://<domain>/.well-known/nostr.json?name=<local>` through the
   SSRF-guarded `safefetch` client (the domain is attacker-controlled content).
3. Return `<local≤8>-<domain≤9>-<80-bit sha256(local@domain + pubkey)>`, or a
   39-char hex pubkey prefix when no verified identifier exists.

Used in exactly two places: the Gitea **org** at first provisioning
(`provisioner.go:297`, only when `linkedOwner()` finds no durable link) and the
Gitea **username** at first login (`auth/identity.go`).

Net result: **one Gitea org per pubkey, no domain grouping.** The hash suffix
and the `linkedOwner()` pin are deliberate — NIP-05 reassignment can neither
rename an existing namespace nor take one over.

## Constraints that shape the design

1. `gitea.Client` has **no org-membership, team, collaborator, or transfer
   API**. Membership is an entirely new client surface.
2. `mapping.Owner` is an **on-disk path**:
   `repositoriesDir/<Owner>/<RepoName>.git`, used by hook installation,
   `webhook/handler.go`, and `hiveci/runner.go`. Changing an org is a real
   repository move plus hook reinstallation.
3. `hiveci.isRepoCIAllowed(mapping.Owner, mapping.RepoID)` keys CI on `Owner`,
   so org changes silently alter `CI_TRIGGER_REPOS` semantics.
4. Gitea has **no nested namespaces**. A shared org is one flat repository
   namespace; `example-com/alice/dotfiles` is impossible.
5. The canonical public URL is npub-based and independent of the org name.
6. Push authority comes from signed NIP-34 repository-state events enforced by
   `grasp-pre-receive`. Gitea ACLs govern private *reads*, the web UI, and
   packages — not Nostr push authority.

Two further facts checked against the pinned Gitea source (still worth a live
confirmation, but the source is unambiguous):

- **Repo-level collaborators exist independently of org membership**
  (`AddOrUpdateCollaborator`). So a repository owner can retain access to their
  own repo after losing domain membership, without a transfer.
- **`transferOwnership` preserves `repo.ID`** — it reassigns `OwnerID` and
  renames directories. This matters: PR 1C's mapped-repo `ExpectedID` guard
  keys on the repository ID, so a legitimate transfer does *not* trip it, while
  a delete-and-recreate still does. A migration must update `mapping.Owner`
  atomically, or `GetRepo(oldOwner, name)` 404s and the path fails closed.

## Two features, not one

### Feature A — verified domain affiliation (recommended)

A pubkey has a current, verified relationship with an exact NIP-05 host.

Delivers: verified domain badge, domain catalog of repositories (linked by
canonical npub URLs), search/filter by domain, a foundation for later policy.

Changes nothing about: repository placement, Gitea usernames and orgs,
filesystem paths, private access, package coordinates, NIP-34 ownership.

### Feature B — managed domain tenant (defer)

An operator-approved domain gets a bridge-managed Gitea org that can hold
repositories.

Delivers: native org pages, teams, shared private-repo ACLs, domain-owned
package namespaces.

Costs: membership/team/transfer client surface, continuous re-verification and
ACL reconciliation, flat-namespace allocation, repository transfers, tenant
governance.

| | Affiliation (A) | Shared org (B) |
|---|---|---|
| npub clone URLs | unchanged | unchanged |
| Domain catalog / badge | yes | yes |
| Native org page, teams | no | yes |
| Shared private-repo ACL | no | yes |
| Shared package namespace | no | yes |
| Repo name collisions | none | must be managed |
| Existing-repo transfers | none | required to consolidate |
| Revocation worker | freshness only | **security-critical** |
| Risk | low | high |

## The hard problems in Feature B

### Flat namespace

Two users at `example.com` both announce repo-id `dotfiles`. Options:

- *Domain-unique names*: first user blocks everyone else. Only acceptable if a
  domain admin explicitly allocates names.
- *First unsuffixed, later suffixed*: order-dependent, rewards squatting.
  Rejected.
- *Local-part prefix* (`alice-dotfiles`): readable, but local parts are
  reassignable and can duplicate across subdomains.
- **Recommended — always suffix with a pubkey-derived component**, applied to
  *every* shared-org repo, not just collisions. Deterministic, squat-resistant,
  unaffected by NIP-05 reassignment. The clean repo-id remains visible through
  the mapping and canonical URL.

**Packages do not inherit this fix.** Package coordinates expose owner and
package name to clients, so an internal suffix would leak into the coordinate.
A shared package namespace needs its own allocation policy; do not promise one.

### Who may claim a domain

NIP-05 verification proves only: *this domain currently maps this name to this
pubkey.* It does **not** prove the user administers the domain. So
"first verified user claims the domain" is unacceptable — it would let anyone
with a `nostr.json` entry claim a branded tenant.

- Tenants require **operator approval / an allowlist**.
- The bridge creates the org and records the **immutable Gitea org ID**. A random
  provisioning marker is persisted before the create call and copied into the
  org/team descriptions, so crash recovery may re-pin only the exact in-flight
  resources created for that intent.
- Never adopt an existing same-named org — this preserves the existing rule in
  `provisioner.go` that a same-named org is not an ownership proof.
- Name tenants in a reserved, full-domain-hashed form (not raw `github-com`,
  and not the current 9-char truncated component, which collides).
- Do **not** grant Gitea org-owner rights automatically; that role can delete
  or transfer repositories outside the bridge's reconciliation.

Group by the **exact host**: `team.example.com` ≠ `example.com`. Canonicalize
to lowercase IDNA/punycode. Do not group by eTLD+1.

### Revocation

The 5-minute *naming* cache must never become the *authorization* cache, and
it currently cannot distinguish "removed" from "DNS broken".

- Re-verify active affiliations (~15 min, jittered).
- HTTP 200 that omits the name or maps a different pubkey = **confirmed
  revocation**. DNS/TLS/timeout/5xx = **indeterminate → stale**, not
  revocation.
- Warn after 1h without success; suspend domain-derived ACLs after 24h.
- Operator kill switch for immediate tenant suspension.

When alice is removed from `example.com`:

1. Revoke domain-derived teams and access to *other* private domain repos.
2. **Preserve** her identity link, bridge tokens, and repo-level access to
   repositories she owns under NIP-34 (via repo collaborator, per the verified
   fact above).
3. Leave her repositories in place, flagged tenant-orphaned for review.
4. Never auto-delete, auto-archive, or auto-transfer.

The principle: **removing someone from `nostr.json` must not let a domain
operator seize repositories that are cryptographically owned by that pubkey.**

Default tenant policy is `directory-only` (affiliation grants no ACL).
`shared-read` is opt-in, and must not ship before the revocation worker.

### Migration

Existing per-pubkey orgs stay pinned forever. Affiliation must be established
by **fresh verification**, never inferred from `mapping.Owner`, the qualified
name, or `NostrIdentityLink.NIP05` (which today stores the derived namespace,
not the identifier — see `phase1-6dx`).

Placement is prospective and opt-in: new repos may go to an approved tenant;
existing repos never move automatically. Any later per-repo migration must
key CI on an immutable identity first (owner pubkey + repo-id, not `Owner`),
then: quiesce the mapping, transfer, verify the repo ID is unchanged, update
`mapping.Owner`/`RepoName`, reinstall and verify the hook at the new path,
re-enable.

## Phasing and effort

Estimates assume one engineer familiar with the bridge; frontend excluded.

| Phase | Scope | Effort |
|---|---|---|
| **0** | Decide the actual requirement; validate org/team/collaborator/transfer semantics against the pinned Gitea image | 3–5 days |
| **1** | Verified domain affiliation: structured verification evidence, persistence, catalogs, badges | 2–3 weeks |
| **2** | Tenant foundation: operator-approved tenants by immutable org ID, membership/team client surface, re-verification, states, reconciliation, kill switch | 3–4 weeks |
| **3** | Opt-in placement for *new* repos, deterministic suffixed names, owner collaborator access | 2–3 weeks |
| **4** | Existing-repo migration: preflight, one-at-a-time transfer, hook/path/ID verification, rollback | 3–5 weeks |
| **5** | Domain package namespace policy (per-registry) | 2–4+ weeks |

**Phase 0 is a decision gate.** Stop there unless native Gitea tenant
behaviour has a concrete user requirement.

Phase 2 must not ship membership without revocation in the same deployment.

### Future OwnAuth SCIM seam

OwnAuth SCIM (phase `phase1-8qz`) will later become the membership source of
truth. Source evaluation is therefore kept separate from the tenant
membership-mutation/reconciliation boundary: SCIM will supply intended members
to the same immutable-org/team-pinned, per-tenant-locked applicator. It must use
the same deny reconciliation and tenant-orphan handling. This phase adds no
SCIM endpoint, token, schema, or precedence behavior.

## Risks

- **Domain compromise blast radius**: under `shared-read`, compromising a
  `nostr.json` endpoint could expose every private repo the team covers. Hence
  `directory-only` default plus a kill switch.
- **NIP-05 is mutable by design** — good for current affiliation, wrong for
  durable repository ownership.
- **Fail-closed vs. outage**: strict revocation is secure but fragile; the
  stale/hard-expiry split must be visible and audited.
- **Transfers are not metadata-only**: disk paths, hooks, CI keys, and
  possibly package ownership all move.
- **Mixed placement is permanent**: per-pubkey orgs must stay supported.
- **Verifier load**: re-checking every identity independently can overload the
  bridge and the domain endpoint; coalesce by domain.

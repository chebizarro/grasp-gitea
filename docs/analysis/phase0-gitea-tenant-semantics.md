# Phase 0: Gitea tenant semantics validation

**Bead:** `phase1-1ka`  
**Validation date:** 2026-09-04  
**Result type:** Empirical, against a throwaway Docker container

## Scope and pinned version

The deployment compose file pins `${GITEA_IMAGE:-gitea/gitea:1.24.6}` in `deploy/docker-compose.hardening.yml`. The probe ran that default image and confirmed `GET /api/v1/version` returned `1.24.6`.

Container image details:

- tag: `gitea/gitea:1.24.6`
- image ID/digest: `sha256:2edc102cbb636ae1ddac5fa0c715aa5b03079dee13ac6800b2cef6d4e912e718`
- database: throwaway SQLite

The probe created local users `alice` (organization owner), `bob` (membership probe), and `outsider` (non-member collaborator probe), plus a private organization named `tenant-acme`.

## Findings

### 1. Organization membership and team APIs

Organization membership is team-driven in the tested API:

1. `POST /api/v1/orgs` as `alice` created the private organization (`201`). `alice` was its initial member and belonged to the automatically created `Owners` team.
2. `PUT /api/v1/orgs/tenant-acme/members/bob` returned `405`. Gitea 1.24.6 exposes organization-member read/delete operations, but not a direct add-member operation at that path.
3. `POST /api/v1/orgs/tenant-acme/teams` created team `readers` (`201`) with `repo.code: read`.
4. `PUT /api/v1/teams/2/members/bob` returned `204`. Afterward, both the organization-member list and team-member list contained `bob`.
5. `DELETE /api/v1/teams/2/members/bob` returned `204`. Because this was `bob`'s last team, `GET /api/v1/orgs/tenant-acme/members/bob` then returned `404`: removing the user from the last team also removed organization membership.
6. After re-adding `bob` to the team, `DELETE /api/v1/orgs/tenant-acme/members/bob` returned `204`; both the organization-membership check and the team-membership check then returned `404`.

**Technical conclusion:** adding a user to a team establishes organization membership; removing the last team membership removes organization membership; deleting organization membership removes team membership. Team permissions are expressed per unit (the probe returned `permission: "none"` with `units_map.repo.code: "read"` for the code-only team).

### 2. Repository collaborator access for a non-member

A private repository, `tenant-acme/collab-probe`, was created under the organization.

Before the grant:

- `GET /api/v1/orgs/tenant-acme/members/outsider` returned `404`.
- Authenticated `GET /api/v1/repos/tenant-acme/collab-probe` as `outsider` returned `404`.

The equivalent of `AddOrUpdateCollaborator` was then exercised:

```text
PUT /api/v1/repos/tenant-acme/collab-probe/collaborators/outsider
{"permission":"read"}
```

It returned `204`. Afterward:

- the repository collaborator list contained `outsider`;
- authenticated repository lookup as `outsider` returned `200` with `permissions.pull: true`, `permissions.push: false`, and `permissions.admin: false`;
- the collaborator-permission endpoint returned `permission: "read"`;
- the organization-membership check for `outsider` still returned `404`.

**Technical conclusion:** `AddOrUpdateCollaborator` grants direct access to an organization-owned private repository to a user who is not an organization member, without implicitly making that user an organization member.

### 3. `transferOwnership` repository ID behavior

A private user-owned repository was created and then transferred into the organization:

```text
Before: id=2, full_name=alice/transfer-probe
POST /api/v1/repos/alice/transfer-probe/transfer
{"new_owner":"tenant-acme","team_ids":[2]}
After:  id=2, full_name=tenant-acme/transfer-probe
```

The transfer returned `202`. A subsequent lookup at the new owner/name returned the same repository ID.

**Technical conclusion:** ownership transfer from a user to an organization preserved `repo.ID` in Gitea 1.24.6. PR 1C's `ExpectedID` guard can therefore continue to identify this repository across that transfer.

## Open product decision (not decided here)

These results establish what the pinned Gitea version can do; they do not select the tenant model. A human still needs to decide which capability is required for NIP-05 domain affiliation:

- discovery/badging only;
- shared private-repository read access;
- a shared package namespace;
- native Gitea organization administration;
- and, if native administration is required, whether domain administrators need self-service control proof or operator approval is sufficient.

No implementation should be selected from this validation alone. Per the bead's decision-gate scope, stop unless and until the desired capability and control model are explicitly chosen.

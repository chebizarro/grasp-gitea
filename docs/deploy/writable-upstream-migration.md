# Writable upstream migration

Grasp repository mappings normally point at a writable Gitea repository whose
pre-receive hook enforces owner-signed NIP-34 repository state. Older mappings
may instead point directly at a Gitea pull mirror. Those mappings can publish a
signed state event but cannot accept the Git objects referenced by it.

The authenticated `POST /admin/mappings/writable-upstream` operation converts
one such mapping to the dual-repository topology without changing or disabling
the pull mirror.

```json
{
  "npub": "npub1...",
  "repo_id": "example",
  "expected_gitea_repo_id": 21,
  "target_repo_name": "example-grasp-upstream"
}
```

The operation fails closed unless the current mapping names the exact expected
public pull mirror. Before creating anything it records the source mapping and
deterministic target name. Gitea imports the sibling as a private normal
repository; Grasp archives it, compares every API-visible ref with the source,
verifies a cryptographically random creation marker recorded before import,
installs and verifies the owner-state hook, and atomically switches the mapping
using the original mapping timestamp as a compare-and-swap precondition. Only
after activation is the sibling unarchived and made public. Repeating the exact
request completes an interrupted post-activation visibility change.

An unrelated repository with the requested target name is never adopted. A
pre-activation crash leaves the target private and archived and can be resumed
only from the durable preparation record.

Rollback uses `POST /admin/mappings/writable-upstream/rollback`:

```json
{
  "npub": "npub1...",
  "repo_id": "example",
  "expected_gitea_repo_id": 57
}
```

Rollback verifies the preserved repository is still the exact pull mirror,
atomically restores the old mapping, then makes the writable sibling private
and archived. A retry completes that quarantine if the visibility update was
interrupted. Neither repository is deleted. The operation does not create,
rotate, revoke, re-pair, or otherwise modify repository-owner signer grants or
agent identities.

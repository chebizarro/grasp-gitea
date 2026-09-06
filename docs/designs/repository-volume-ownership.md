# Gitea repository volume ownership

## Decision

Run `grasp-bridge` as the same numeric uid/gid as Gitea's `git` user for every operation after a minimal root entrypoint. The pinned `gitea/gitea:1.24.6` image was verified with `id git` as uid 1000 and gid 1000. `USER_UID` and `USER_GID` are mandatory, must be decimal values in `1..2147483647`, and are supplied to both containers so an empty volume cannot hide a deployment override mismatch.

This is preferred over post-write `chown`: Git object and ref transactions remain owned correctly from inode creation onward, so Gitea never observes a root-owned object or ref between a bridge write and a repair step. It also covers every direct shared-volume writer: proactive NIP-34 fetch/ref/HEAD reconciliation, repository hook installation and configuration, packed refs, linked-worktree metadata, migration markers, and ref reaping. Repository creation itself stays behind the Gitea API and therefore runs as Gitea's git user.

## Privilege boundary

The image entrypoint starts as root only to:

1. make the bridge-private `/data` directory writable by the configured uid/gid;
2. optionally run the explicitly enabled ownership and mode repair described below; and
3. drop to `USER_UID:USER_GID` with `su-exec` before starting the bridge or any Git operation.

UID or GID zero, oversized values, missing variables, and nonnumeric values fail before filesystem mutation. If Compose starts the image as a non-root user whose numeric identity differs from the configured Gitea identity, startup also fails closed. Production Compose overlays invoke the image entrypoint rather than bypassing it.

## Managed write boundary and symlinks

The complete managed bare-repository tree is the write boundary, including `HEAD`, `config`, `packed-refs`, `refs/`, `objects/`, `hooks/`, `info/`, linked-worktree metadata, and migration markers. The preflight requires the configured uid/gid and owner write permission on files plus owner write/execute permission on directories.

Symlinks anywhere in this boundary are rejected without being followed. This prevents a symlinked `refs`, `objects`, or hook path from hiding drift or redirecting repair outside the repository. `objects/info/alternates` is the exception only as a reference mechanism: the alternates file remains part of the checked repository, while each referenced object directory must exist and be readable/searchable by the configured identity. Alternate directories are never traversed, chowned, or chmodded.

## Startup preflight and observability

After opening the mapping store and before hook reconciliation or proactive synchronization, the bridge scans every managed bare repository and exits on any drift or scan error. It scans again after startup migration/hook/config recovery, after each new repository is provisioned, and every five minutes with jitter. Each mismatch log includes:

- canonical `30617:<pubkey>:<repo-id>` repository address;
- physical repository path and offending path;
- actual and expected uid/gid, the ownership/mode reason; and
- an exact guarded operator repair command.

The scan sets `repository_ownership_drift` in `/metrics`. The latest result is registered as the `repository_ownership` readiness probe, so `/ready` tracks repairs or newly introduced drift rather than retaining the startup result. Git permission failures from proactive state/proposal handling include the repository identity/path and a fresh ownership diagnosis.

## Repair policy

Automatic repair is **off by default**. Operators should normally inspect the diagnostic and run its per-repository command during a controlled maintenance window.

For an explicitly approved recovery, set:

```sh
GITEA_REPO_OWNERSHIP_AUTO_REPAIR=true
USER_UID=1000
USER_GID=1000
```

Before changing anything, the root entrypoint rejects repository symlinks and validates Git alternates. It then repairs ownership and owner write modes across the complete bare repository without traversing alternates, and aborts on any failure. Remove the repair flag after recovery. The application process never retains root privileges and never silently repairs ownership.

## Verification

Unit coverage checks invalid uid/gid values; every bridge-written bare-repository path; file and directory write modes; symlinked refs; readable and missing alternates; structured diagnostics; and drift-then-repair readiness refresh. Proactive-sync coverage proves HEAD and deleted-ref failures are joined and returned after a partial branch update.

The deployment E2E uses the pinned Gitea image and verifies both processes use the same uid/gid. It processes a synthetic NIP-34 proposal, creates and updates its Gitea pull request, then stops the bridge and seeds root-owned/read-only `HEAD`, `config`, `packed-refs`, hooks, and a migration marker. Restart with explicit repair must succeed; subsequent hook replacement, symbolic HEAD update, packed-ref rewrite, and migration-marker write run as the non-root Gitea identity. The final scan asserts the entire repository tree has the required identity and write modes.

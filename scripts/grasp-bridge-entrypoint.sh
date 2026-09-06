#!/bin/sh
set -eu

if [ -z "${USER_UID+x}" ] || [ -z "$USER_UID" ]; then
  echo "USER_UID is required and must match Gitea's git uid" >&2
  exit 1
fi
if [ -z "${USER_GID+x}" ] || [ -z "$USER_GID" ]; then
  echo "USER_GID is required and must match Gitea's git gid" >&2
  exit 1
fi
uid=$USER_UID
gid=$USER_GID
case "$uid" in *[!0-9]*) echo "invalid USER_UID: $uid" >&2; exit 1 ;; esac
case "$gid" in *[!0-9]*) echo "invalid USER_GID: $gid" >&2; exit 1 ;; esac
if [ "$uid" -eq 0 ] || [ "$uid" -gt 2147483647 ]; then
  echo "invalid USER_UID: $uid (must be 1..2147483647)" >&2
  exit 1
fi
if [ "$gid" -eq 0 ] || [ "$gid" -gt 2147483647 ]; then
  echo "invalid USER_GID: $gid (must be 1..2147483647)" >&2
  exit 1
fi

current_uid=$(id -u)
current_gid=$(id -g)
if [ "$current_uid" != 0 ]; then
  if [ "$current_uid" != "$uid" ] || [ "$current_gid" != "$gid" ]; then
    echo "grasp-bridge must run as Gitea git uid/gid $uid:$gid; running as $current_uid:$current_gid" >&2
    exit 1
  fi
  exec "$@"
fi

# The bridge owns its private state directory, but must never write the shared
# repository volume as root.
mkdir -p /data
chown -R "$uid:$gid" /data

repositories=${GITEA_REPOSITORIES_PATH:-/gitea-data/git/repositories}
if [ "${GITEA_REPO_OWNERSHIP_AUTO_REPAIR:-false}" = "true" ] && [ -d "$repositories" ]; then
  echo "GITEA_REPO_OWNERSHIP_AUTO_REPAIR enabled; repairing managed bare repositories under $repositories to $uid:$gid" >&2
  hidden_repo_symlink=$(find "$repositories" -mindepth 2 -maxdepth 2 -name '*.git' -type l -print -quit)
  if [ -n "$hidden_repo_symlink" ]; then
    echo "refusing repository ownership repair: managed repository is a symlink: $hidden_repo_symlink" >&2
    exit 1
  fi
  find "$repositories" -mindepth 2 -maxdepth 2 -type d -name '*.git' -exec sh -ec '
    uid=$1; gid=$2; shift 2
    for repo do
      symlink=$(find "$repo" -type l -print -quit)
      if [ -n "$symlink" ]; then
        echo "refusing repository ownership repair: symlink in managed write path: $symlink" >&2
        exit 1
      fi
      alternates="$repo/objects/info/alternates"
      if [ -f "$alternates" ]; then
        while IFS= read -r alternate || [ -n "$alternate" ]; do
          [ -n "$alternate" ] || continue
          case "$alternate" in
            /*) target=$alternate ;;
            *) target="$repo/objects/$alternate" ;;
          esac
          if [ ! -d "$target" ] || ! su-exec "$uid:$gid" sh -ec '\''test -r "$1" && test -x "$1"'\'' sh "$target"; then
            echo "refusing repository ownership repair: git alternate is missing or unreadable: $alternate (repo $repo)" >&2
            exit 1
          fi
        done < "$alternates"
      fi
      # No symlink is present, so this changes only the bare repository tree;
      # alternate object directories are referenced but never traversed.
      chown -R "$uid:$gid" "$repo"
      chmod -R u+rwX "$repo"
    done
  ' sh "$uid" "$gid" {} +
fi

export HOME=/tmp
exec su-exec "$uid:$gid" "$@"

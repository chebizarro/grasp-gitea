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
      chown -R "$uid:$gid" "$repo"
      chmod -R u+rwX "$repo"
    done
  ' sh "$uid" "$gid" {} +
fi

secret_dir=/run/grasp-secrets
if [ -L "$secret_dir" ]; then
  echo "refusing mounted secret copy: destination is a symlink: $secret_dir" >&2
  exit 1
fi
if ! rm -rf "$secret_dir"; then
  echo "refusing mounted secret copy: cannot clear destination: $secret_dir" >&2
  exit 1
fi
if ! mkdir -p "$secret_dir"; then
  echo "refusing mounted secret copy: cannot create destination: $secret_dir" >&2
  exit 1
fi
if ! chown "0:$gid" "$secret_dir"; then
  echo "refusing mounted secret copy: destination chown failed: $secret_dir" >&2
  exit 1
fi
if ! chmod 0750 "$secret_dir"; then
  echo "refusing mounted secret copy: destination chmod failed: $secret_dir" >&2
  exit 1
fi

copy_secret() {
  path=$1
  allow_alternative_root=$2
  case "$path" in
    /*) ;;
    *) echo "refusing mounted secret copy: path is not absolute: $path" >&2; return 1 ;;
  esac
  if [ "$allow_alternative_root" != "true" ]; then
    case "$path" in
      /run/secrets/*) ;;
      *) echo "refusing mounted secret copy: path escapes /run/secrets: $path" >&2; return 1 ;;
    esac
  fi
  if [ -L "$path" ]; then
    echo "refusing mounted secret copy: secret is a symlink: $path" >&2
    return 1
  fi
  if [ ! -f "$path" ]; then
    echo "refusing mounted secret copy: secret is not a regular file: $path" >&2
    return 1
  fi
  target="$secret_dir/${path##*/}"
  if ! cp "$path" "$target"; then
    echo "refusing mounted secret copy: copy failed: $path" >&2
    return 1
  fi
  if ! chown "$uid:$gid" "$target"; then
    echo "refusing mounted secret copy: chown failed: $target" >&2
    return 1
  fi
  if ! chmod 0400 "$target"; then
    echo "refusing mounted secret copy: chmod failed: $target" >&2
    return 1
  fi
  echo "mounted secret copy: $path -> $target" >&2
}

if [ -n "${GRASP_SECRET_FILES+x}" ]; then
  printf '%s' "$GRASP_SECRET_FILES" | tr ':' '\n' | while IFS= read -r path || [ -n "$path" ]; do
    [ -n "$path" ] || continue
    copy_secret "$path" true
  done
else
  for path in /run/secrets/grasp-*; do
    if [ "$path" = '/run/secrets/grasp-*' ] && [ ! -e "$path" ] && [ ! -L "$path" ]; then
      continue
    fi
    copy_secret "$path" false
  done
fi

export HOME=/tmp
exec su-exec "$uid:$gid" "$@"

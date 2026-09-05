#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/grasp-phase6-e2e.XXXXXX")"
project="grasp-phase6-e2e-${$}"

export COMPOSE_PROJECT_NAME="$project"
export E2E_NGINX_CONFIG="$tmp/nginx.conf"
export E2E_UPSTREAM_CONFIG="$tmp/upstream.conf"
export E2E_POSTGRES_PORT="${E2E_POSTGRES_PORT:-55439}"
export E2E_NGINX_PORT="${E2E_NGINX_PORT:-58096}"
export E2E_GOPROXY="${E2E_GOPROXY:-$(go env GOPROXY)}"
export GRASP_BRIDGE_IMAGE="${GRASP_BRIDGE_IMAGE:-grasp-bridge:phase6-active-active-e2e}"
export COMPOSE_FILE="$repo_root/deploy/docker-compose.phase6-active-active-e2e.yml"

cleanup() {
  status=$?
  if (( status != 0 )); then
    docker compose ps >&2 || true
    docker compose logs --no-color --tail=200 >&2 || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT INT TERM

for command in docker go curl awk sort grep; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
docker info >/dev/null

cat >"$E2E_UPSTREAM_CONFIG" <<'NGINX'
server {
    listen 80;
    location = /api/healthz { return 200 "healthy\n"; }
    location / {
        if ($http_authorization != "Basic cGhhc2U2OnN0YWJsZQ==") { return 401; }
        return 200 "phase6 upstream\n";
    }
}
NGINX

cat >"$E2E_NGINX_CONFIG" <<'NGINX'
upstream grasp_bridges {
    least_conn;
    server bridge-a:8090 max_fails=1 fail_timeout=2s;
    server bridge-b:8090 max_fails=1 fail_timeout=2s;
    keepalive 16;
}
server {
    listen 8080;
    location = /__bridge_a_ready {
        proxy_pass http://bridge-a:8090/ready;
        add_header X-Grasp-Upstream $upstream_addr always;
    }
    location = /__bridge_b_ready {
        proxy_pass http://bridge-b:8090/ready;
        add_header X-Grasp-Upstream $upstream_addr always;
    }
    location / {
        proxy_pass http://grasp_bridges;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_connect_timeout 1s;
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_next_upstream_tries 2;
        add_header X-Grasp-Upstream $upstream_addr always;
    }
}
NGINX

echo "[setup] building and starting Postgres + two bridge replicas + nginx"
if [[ "${E2E_USE_EXISTING_BRIDGE_IMAGE:-false}" == "true" ]]; then
  docker compose up -d
else
  # Both replicas share one image; build it once to avoid concurrent BuildKit
  # writers racing on the same image tag.
  docker compose build bridge-a
  docker compose up -d --no-build
fi

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:${E2E_NGINX_PORT}/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${E2E_NGINX_PORT}/ready" >/dev/null

echo "[verify] both bridge processes selected the shared Postgres backend"
for service in bridge-a bridge-b; do
  docker compose logs --no-color "$service" | grep 'shared Postgres auth store enabled' >/dev/null
done

echo "[verify] nginx reaches both bridge replicas"
upstreams="$({
  for replica in a b; do
    curl -fsS -D - -o /dev/null "http://127.0.0.1:${E2E_NGINX_PORT}/__bridge_${replica}_ready" | awk -F': ' 'tolower($1)=="x-grasp-upstream" {gsub("\\r", "", $2); print $2}'
  done
} | sort -u)"
if [[ "$(printf '%s\n' "$upstreams" | grep -c .)" -ne 2 ]]; then
  echo "nginx did not route to both replicas; observed: $upstreams" >&2
  exit 1
fi
printf 'nginx upstreams:\n%s\n' "$upstreams"

echo "[verify] cross-node transactional invariants"
cd "$repo_root"
POSTGRES_DSN="postgres://grasp:grasp-e2e@127.0.0.1:${E2E_POSTGRES_PORT}/grasp?sslmode=disable" \
  go run ./scripts/phase6-active-active-e2e.go

echo "phase6 active-active two-replica deployment: PASS"

#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/grasp-phase6-chaos-e2e.XXXXXX")"
project="grasp-phase6-chaos-e2e-${$}"
load_pid=""

export COMPOSE_PROJECT_NAME="$project"
export E2E_NGINX_CONFIG="$tmp/nginx.conf"
export E2E_UPSTREAM_CONFIG="$tmp/upstream.conf"
export E2E_POSTGRES_PORT="${E2E_POSTGRES_PORT:-55439}"
export E2E_NGINX_PORT="${E2E_NGINX_PORT:-58096}"
export E2E_GOPROXY="${E2E_GOPROXY:-$(go env GOPROXY)}"
export GRASP_BRIDGE_IMAGE="${GRASP_BRIDGE_IMAGE:-grasp-bridge:phase6-active-active-e2e}"
export COMPOSE_FILE="$repo_root/deploy/docker-compose.phase6-active-active-e2e.yml"
base_url="http://127.0.0.1:${E2E_NGINX_PORT}"

cleanup() {
  status=$?
  if [[ -n "$load_pid" ]]; then
    kill "$load_pid" >/dev/null 2>&1 || true
    wait "$load_pid" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    docker compose ps >&2 || true
    docker compose logs --no-color --tail=200 >&2 || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT INT TERM

for command in docker go curl grep; do
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
    }
    location = /__bridge_b_ready {
        proxy_pass http://bridge-b:8090/ready;
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

wait_for_status() {
  local url=$1 want=$2 attempts=${3:-120} got=""
  for _ in $(seq 1 "$attempts"); do
    got="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
    if [[ "$got" == "$want" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "$url returned $got, want $want" >&2
  return 1
}

run_load() {
  go run ./scripts/phase6-load-e2e.go -base-url "$base_url" "$@"
}

cd "$repo_root"
echo "[setup] starting Postgres + two bridge replicas + nginx"
if [[ "${E2E_USE_EXISTING_BRIDGE_IMAGE:-false}" == "true" ]]; then
  docker compose up -d
else
  # Both replicas share one image; build it once to avoid concurrent BuildKit
  # writers racing on the same image tag.
  docker compose build bridge-a
  docker compose up -d --no-build
fi
wait_for_status "$base_url/__bridge_a_ready" 200
wait_for_status "$base_url/__bridge_b_ready" 200

for service in bridge-a bridge-b; do
  docker compose logs --no-color "$service" | grep 'shared Postgres auth store enabled' >/dev/null
done

echo "[load] concurrent git, package, API, and DB-backed auth traffic across both replicas"
run_load -duration 5s -concurrency 24 -mode all -min-upstreams 2

echo "[chaos] killing bridge-a during traffic; nginx must fail over without errors"
chaos_log="$tmp/bridge-kill-load.log"
run_load -duration 8s -concurrency 24 -mode all -min-upstreams 1 >"$chaos_log" 2>&1 &
load_pid=$!
sleep 2
docker compose kill bridge-a >/dev/null
set +e
wait "$load_pid"
load_status=$?
set -e
load_pid=""
cat "$chaos_log"
if (( load_status != 0 )); then
  exit "$load_status"
fi
# bridge-a is stopped, so a successful direct probe proves bridge-b is the
# survivor serving the zero-error load interval.
wait_for_status "$base_url/__bridge_b_ready" 200 20
wait_for_status "$base_url/ready" 200 20

echo "[chaos] restarting bridge-a and verifying it rejoins load balancing"
docker compose up -d bridge-a >/dev/null
wait_for_status "$base_url/__bridge_a_ready" 200
# Allow nginx's passive fail_timeout window to expire before requiring rejoin.
sleep 3
run_load -duration 5s -concurrency 24 -mode all -min-upstreams 2

echo "[chaos] stopping Postgres: proxy traffic stays available and auth fails closed"
docker compose stop postgres >/dev/null
wait_for_status "$base_url/auth/nip46/status?session=phase6-chaos-missing" 500 30
run_load -duration 4s -concurrency 16 -mode forwarded -min-upstreams 2

echo "[chaos] restarting Postgres and verifying both replicas recover DB-backed auth"
docker compose start postgres >/dev/null
for _ in $(seq 1 60); do
  if docker compose exec -T postgres pg_isready -U grasp -d grasp >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
wait_for_status "$base_url/auth/nip46/status?session=phase6-chaos-missing" 404 60
run_load -duration 5s -concurrency 24 -mode all -min-upstreams 2

echo "phase6 multiple-upstream load and chaos deployment: PASS"

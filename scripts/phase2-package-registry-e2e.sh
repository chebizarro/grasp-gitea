#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/grasp-phase2-packages.XXXXXX")"
project="grasp-phase2-packages-${$}"
volume="${project}-gitea-data"
admin_token="phase2-e2e-admin-token-0123456789abcdef"
edge_secret="phase2-e2e-edge-secret-0123456789abcdef0123456789abcdef"

export COMPOSE_PROJECT_NAME="$project"
export E2E_GITEA_DATA_VOLUME="$volume"
export E2E_NGINX_CONFIG="$tmp/nginx.conf"
export E2E_TLS_CERT="$tmp/tls.crt"
export E2E_TLS_KEY="$tmp/tls.key"
export GRASP_ADMIN_TOKEN_FILE="$tmp/grasp-admin-api-token"
export GRASP_CREDENTIAL_KEYS_FILE="$tmp/grasp-credential-keys"
export GRASP_EDGE_SECRET_FILE="$tmp/grasp-edge-shared-secret"
export E2E_ADMIN_TOKEN="$admin_token"
export E2E_EDGE_SECRET="$edge_secret"
export E2E_REPO_ROOT="$repo_root"
export GITEA_ADMIN_USER=e2e-admin
export GITEA_IMAGE="${GITEA_IMAGE:-gitea/gitea:1.24.6}"
export GRASP_BRIDGE_IMAGE="${GRASP_BRIDGE_IMAGE:-grasp-bridge:phase2-packages}"
export E2E_GOPROXY="${E2E_GOPROXY:-$(go env GOPROXY)}"
cat >"$tmp/phase2.override.yml" <<'YAML'
services:
  grasp-bridge:
    environment:
      BRIDGE_TOKENS_ENABLED: "true"
      REGISTRY_TOKEN_MAX_LIFETIME: "24h"
      REGISTRY_TOKEN_PROBE_INTERVAL: "1h"
    # This suite excludes Docker because its deployed JWT is not promptly
    # revocable. Keep the package bridge alive even when that independent
    # readiness probe reports the known registry-token finding.
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8090/health"]
YAML
export COMPOSE_FILE="$repo_root/deploy/docker-compose.phase1-e2e.yml:$repo_root/deploy/docker-compose.hardening.yml:$repo_root/deploy/docker-compose.fullproxy.yml:$tmp/phase2.override.yml"

cleanup() {
  status=$?
  if (( status != 0 )); then
    docker compose ps >&2 || true
    docker compose logs --no-color --tail=200 >&2 || true
  fi
  if [[ "${KEEP_PHASE2_PACKAGE_STACK:-false}" != "true" ]]; then
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    rm -rf "$tmp"
  else
    echo "keeping stack ${project} and fixtures ${tmp}" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

for command in docker openssl go sed curl bzip2; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
docker info >/dev/null

printf %s "$admin_token" >"$GRASP_ADMIN_TOKEN_FILE"
printf %s 'current:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=' >"$GRASP_CREDENTIAL_KEYS_FILE"
printf %s "$edge_secret" >"$GRASP_EDGE_SECRET_FILE"
chmod 600 "$GRASP_ADMIN_TOKEN_FILE" "$GRASP_CREDENTIAL_KEYS_FILE" "$GRASP_EDGE_SECRET_FILE"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=grasp.test' \
  -addext 'subjectAltName=DNS:grasp.test' -keyout "$E2E_TLS_KEY" -out "$E2E_TLS_CERT" >/dev/null 2>&1
sed -e 's/YOUR_DOMAIN/grasp.test/g' \
  -e "s/REPLACE_WITH_GRASP_EDGE_SHARED_SECRET/${edge_secret}/g" \
  -e 's/server grasp-bridge-a:8090/server grasp-bridge:8090/' \
  -e '/server grasp-bridge-b:8090/d' \
  -e 's#/etc/letsencrypt/live/grasp.test/fullchain.pem#/etc/nginx/tls/tls.crt#g' \
  -e 's#/etc/letsencrypt/live/grasp.test/privkey.pem#/etc/nginx/tls/tls.key#g' \
  "$repo_root/deploy/nginx/gitea-vhost.conf.example" >"$E2E_NGINX_CONFIG"

docker volume create "$volume" >/dev/null
echo "[setup] starting exact deployed Gitea image: $GITEA_IMAGE"
docker compose up -d --no-deps gitea
for _ in $(seq 1 90); do
  docker compose exec -T gitea wget -qO- http://127.0.0.1:3000/api/healthz >/dev/null 2>&1 && break
  sleep 1
done
docker compose exec -T gitea wget -qO- http://127.0.0.1:3000/api/healthz >/dev/null

docker compose exec -T --user git gitea gitea admin user create \
  --config /data/gitea/conf/app.ini --username e2e-admin --password 'phase2-e2e-password' \
  --email e2e-admin@example.invalid --admin --must-change-password=false >/dev/null
E2E_GITEA_ADMIN_TOKEN="$(docker compose exec -T --user git gitea gitea admin user generate-access-token \
  --config /data/gitea/conf/app.ini --username e2e-admin --token-name phase2-e2e --scopes all --raw | tr -d '\r\n')"
test -n "$E2E_GITEA_ADMIN_TOKEN"
export E2E_GITEA_ADMIN_TOKEN

echo "[setup] building and starting hardened full-proxy stack with bridge tokens"
if [[ "${E2E_USE_EXISTING_BRIDGE_IMAGE:-false}" == "true" ]]; then
  docker compose up -d
else
  docker compose up -d --build
fi
for _ in $(seq 1 120); do
  curl -ksS --resolve grasp.test:443:127.0.0.1 https://grasp.test/health >/dev/null 2>&1 && break
  sleep 1
done
curl -kfsS --resolve grasp.test:443:127.0.0.1 https://grasp.test/health >/dev/null

test "sha256:$(docker compose images -q gitea)" = "$(docker image inspect "$GITEA_IMAGE" --format '{{.Id}}')"
cd "$repo_root"
go run ./scripts/phase2-package-registry-e2e.go

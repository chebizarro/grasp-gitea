#!/usr/bin/env bash
set -euo pipefail

# Phase 3 deployed verification script
# Required env:
#   GITEA_PUBLIC_URL=https://git.sharegap.net
#   BRIDGE_ADMIN_URL=http://localhost:8090
#   NPUB=npub1...
#   REPO_ID=myrepo
# Optional:
#   GITEA_REPO_HOOK_PATH=/gitea-data/git/repositories/$NPUB/$REPO_ID.git/hooks/pre-receive

require() {
  if [[ -z "${!1:-}" ]]; then
    echo "missing required env: $1" >&2
    exit 1
  fi
}

require GITEA_PUBLIC_URL
require BRIDGE_ADMIN_URL
require NPUB
require REPO_ID

echo "[1/5] check gitea public URL"
curl -fsS -I "${GITEA_PUBLIC_URL}" >/dev/null

echo "[2/5] check bridge health"
curl -fsS "${BRIDGE_ADMIN_URL}/health" | tee /tmp/grasp-phase3-health.json

echo "[3/5] check bridge mappings include repo"
if command -v jq >/dev/null 2>&1; then
  curl -fsS "${BRIDGE_ADMIN_URL}/mappings" \
    | jq -e --arg npub "${NPUB}" --arg repo "${REPO_ID}" '.mappings[] | select(.npub==$npub and .repo_id==$repo)' >/dev/null
  echo "mapping found for ${NPUB}/${REPO_ID}"
else
  echo "jq not installed; skipping strict mapping assertion"
  curl -fsS "${BRIDGE_ADMIN_URL}/mappings" >/dev/null
fi

echo "[4/5] check hook file (optional local check)"
if [[ -n "${GITEA_REPO_HOOK_PATH:-}" ]]; then
  test -x "${GITEA_REPO_HOOK_PATH}"
  echo "hook exists and is executable: ${GITEA_REPO_HOOK_PATH}"
else
  echo "GITEA_REPO_HOOK_PATH not set; skipping local hook file check"
fi

echo "[5/5] manual ngit validation steps"
cat <<'EOF'
Run these manually from a client machine:

  1) ngit init for a new repo published to this server
  2) publish state event (kind 30618) for refs to be pushed
  3) git push matching commit => should succeed
  4) git push mismatching commit without updated state => should fail with SHA mismatch

Record outputs in docs/phase3-e2e-report.md.
EOF

echo "phase3-e2e script completed"

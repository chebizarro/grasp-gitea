#!/usr/bin/env bash
set -uo pipefail

# Full-proxy cutover verification (PR 1D acceptance criteria).
#
# Run this against a DEPLOYED stack immediately after switching nginx to the
# full-proxy configuration, and before enabling BRIDGE_TOKENS_ENABLED for
# real users.
#
# Required env:
#   PUBLIC_URL=https://git.example.com   canonical public origin
# Optional env:
#   GITEA_DIRECT_URL=http://gitea:3000   to assert Gitea is NOT publicly reachable
#   NPUB=npub1...                        public mapped repo, for anonymous clone
#   REPO_ID=myrepo
#   BRIDGE_TOKEN=grasp_v1_...            a minted token, for authenticated checks
#   TOKEN_NPUB=npub1...                  the token's subject
#   PRIVATE_REPO_PATH=/owner/repo.git    a private repo the token may read
#
# Checks that need a token are skipped when BRIDGE_TOKEN is unset, so this is
# useful both immediately after cutover and after the first mint.

pass=0; fail=0; skip=0

ok()   { echo "  PASS: $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail+1)); }
note() { echo "  SKIP: $*"; skip=$((skip+1)); }

require() {
  if [[ -z "${!1:-}" ]]; then
    echo "missing required env: $1" >&2
    exit 2
  fi
}
require PUBLIC_URL

# All curl calls are bounded so a hung dependency cannot hang the check.
CURL=(curl -s --connect-timeout 5 --max-time 20)
status_of()  { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }
headers_of() { "${CURL[@]}" -o /dev/null -D - "$@"; }

echo "== 1. Bridge liveness and readiness =="
if [[ "$(status_of "${PUBLIC_URL}/health")" == "200" ]]; then
  ok "/health responds"
else
  bad "/health did not return 200"
fi
ready_code="$(status_of "${PUBLIC_URL}/ready")"
if [[ "${ready_code}" == "200" ]]; then
  ok "/ready reports the store and Gitea upstream are usable"
else
  bad "/ready returned ${ready_code}; the bridge cannot reach a dependency (all Gitea traffic is down)"
fi

echo "== 2. Gitea is not directly reachable =="
# Prefer the authoritative check: does Compose publish any Gitea port?
if command -v docker >/dev/null 2>&1 && docker compose config >/dev/null 2>&1; then
  if docker compose config --format json 2>/dev/null \
       | grep -o '"gitea"[^}]*"ports":\[[^]]*\]' | grep -q 'published'; then
    bad "docker compose publishes a Gitea port; remove it or scope enforcement is bypassable"
  else
    ok "docker compose publishes no Gitea port"
  fi
else
  note "docker compose unavailable here; run 'docker compose config | grep -i published' on the host"
fi

if [[ -n "${GITEA_DIRECT_URL:-}" ]]; then
  # Distinguish "refused/filtered" from "could not even resolve": an
  # unresolvable name proves nothing about reachability from the internet.
  probe_out="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${GITEA_DIRECT_URL}" 2>&1)"
  probe_rc=$?
  if [[ ${probe_rc} -eq 0 ]]; then
    bad "${GITEA_DIRECT_URL} answered (HTTP ${probe_out}); if this vantage point is outside the private network, Gitea is exposed"
  elif [[ ${probe_rc} -eq 6 ]]; then
    note "${GITEA_DIRECT_URL} did not resolve from here; this does NOT prove isolation. Re-run from an external host"
  else
    ok "Gitea did not answer from this vantage point (curl exit ${probe_rc})"
  fi
  echo "       NOTE: run this check from OUTSIDE the deployment network to be meaningful."
else
  note "GITEA_DIRECT_URL unset; verify manually that Gitea's port is unpublished"
fi

echo "== 3. Gitea UI is served through the bridge =="
ui_code="$(status_of "${PUBLIC_URL}/")"
if [[ "${ui_code}" =~ ^(200|303|302)$ ]]; then
  ok "GET / returns ${ui_code} (Gitea UI through the bridge)"
else
  bad "GET / returned ${ui_code}"
fi

echo "== 4. NIP-11 and relay negotiation still work at the root =="
nip11="$(curl -s -H 'Accept: application/nostr+json' "${PUBLIC_URL}/")"
if grep -qi 'supported_nips\|name\|GRASP' <<<"${nip11}"; then
  ok "NIP-11 document served at /"
else
  bad "NIP-11 negotiation at / did not return a relay document"
fi

echo "== 5. Internal headers cannot be forged =="
forged="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'X-Grasp-Auth-User: admin' \
  -H 'X-Grasp-Session-Proxy: 1' \
  -H 'X-Grasp-Edge-Secret: guess' \
  "${PUBLIC_URL}/api/v1/user")"
if [[ "${forged}" == "401" || "${forged}" == "403" ]]; then
  ok "forged reverse-proxy identity rejected (${forged})"
else
  bad "forged identity returned ${forged}; expected 401/403. Check that nginx clears X-Grasp-* on every location"
fi

echo "== 6. Anonymous public GRASP clone still works =="
if [[ -n "${NPUB:-}" && -n "${REPO_ID:-}" ]]; then
  refs_code="$(status_of "${PUBLIC_URL}/${NPUB}/${REPO_ID}.git/info/refs?service=git-upload-pack")"
  if [[ "${refs_code}" == "200" ]]; then
    ok "anonymous upload-pack advertisement for ${NPUB}/${REPO_ID}"
  else
    bad "anonymous upload-pack returned ${refs_code}"
  fi
  hdrs="$(headers_of "${PUBLIC_URL}/${NPUB}/${REPO_ID}.git/info/refs?service=git-upload-pack")"
  if grep -qi '^www-authenticate:' <<<"${hdrs}"; then
    bad "public GRASP path emitted a WWW-Authenticate challenge"
  else
    ok "public GRASP path emits no auth challenge"
  fi
else
  note "NPUB/REPO_ID unset; anonymous clone not checked"
fi

echo "== 7. Bridge token authentication =="
if [[ -n "${BRIDGE_TOKEN:-}" && -n "${TOKEN_NPUB:-}" ]]; then
  if [[ -n "${PRIVATE_REPO_PATH:-}" ]]; then
    code="$(status_of -u "${TOKEN_NPUB}:${BRIDGE_TOKEN}" \
      "${PUBLIC_URL}${PRIVATE_REPO_PATH}/info/refs?service=git-upload-pack")"
    if [[ "${code}" == "200" ]]; then
      ok "private repo readable with npub + bridge token"
    else
      bad "private repo read returned ${code}"
    fi

    # The username must identify the token subject.
    code="$(status_of -u "someone-else:${BRIDGE_TOKEN}" \
      "${PUBLIC_URL}${PRIVATE_REPO_PATH}/info/refs?service=git-upload-pack")"
    if [[ "${code}" == "401" ]]; then
      ok "mismatched Basic username rejected"
    else
      bad "mismatched username returned ${code}, expected 401"
    fi
  else
    note "PRIVATE_REPO_PATH unset; private clone not checked"
  fi

  # A bridge token works on the package registry family (packages scopes).
  code="$(status_of -H "Authorization: Bearer ${BRIDGE_TOKEN}" "${PUBLIC_URL}/api/packages/${TOKEN_NPUB}/npm/does-not-exist")"
  if [[ "${code}" == "404" || "${code}" == "200" ]]; then
    ok "bridge token accepted on the package registry surface (got ${code})"
  elif [[ "${code}" == "403" ]]; then
    bad "bridge token refused on /api/packages — token likely lacks packages:read scope"
  else
    bad "bridge token on /api/packages returned ${code}, expected 404/200"
  fi

  # A bridge token on a surface without an adapter must fail closed.
  code="$(status_of -H "Authorization: Bearer ${BRIDGE_TOKEN}" "${PUBLIC_URL}/api/v1/user")"
  if [[ "${code}" == "403" ]]; then
    ok "bridge token refused on the REST API (phase 4 surface)"
  else
    bad "bridge token on /api/v1/user returned ${code}, expected 403"
  fi

  # A malformed bridge credential must never reach Gitea.
  code="$(status_of -u "${TOKEN_NPUB}:grasp_v1_malformed" \
    "${PUBLIC_URL}/api/v1/user")"
  if [[ "${code}" == "401" ]]; then
    ok "malformed bridge credential rejected locally"
  else
    bad "malformed bridge credential returned ${code}, expected 401"
  fi
else
  note "BRIDGE_TOKEN/TOKEN_NPUB unset; token checks not run"
fi

echo "== 8. Ordinary Gitea credentials still work (backwards compatibility) =="
if [[ -n "${GITEA_USER:-}" && -n "${GITEA_PAT:-}" ]]; then
  code="$(status_of -H "Authorization: token ${GITEA_PAT}" "${PUBLIC_URL}/api/v1/user")"
  if [[ "${code}" == "200" ]]; then
    ok "existing Gitea PAT authenticates on the REST API through the bridge"
  else
    bad "Gitea PAT on /api/v1/user returned ${code}"
  fi

  # Conventional git with an ordinary PAT must keep working: this is the
  # single most common existing workflow.
  if [[ -n "${GITEA_REPO_PATH:-}" ]]; then
    code="$(status_of -u "${GITEA_USER}:${GITEA_PAT}" \
      "${PUBLIC_URL}${GITEA_REPO_PATH}/info/refs?service=git-upload-pack")"
    if [[ "${code}" == "200" ]]; then
      ok "conventional git clone with an ordinary Gitea PAT still works"
    else
      bad "conventional git with a Gitea PAT returned ${code}"
    fi
  else
    note "GITEA_REPO_PATH unset; conventional git compatibility not checked"
  fi

  # LFS batch reachable with an ordinary credential.
  if [[ -n "${GITEA_REPO_PATH:-}" ]]; then
    code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' \
      -u "${GITEA_USER}:${GITEA_PAT}" \
      -X POST \
      -H 'Content-Type: application/vnd.git-lfs+json' \
      -H 'Accept: application/vnd.git-lfs+json' \
      -d '{"operation":"download","transfers":["basic"],"objects":[]}' \
      "${PUBLIC_URL}${GITEA_REPO_PATH}/info/lfs/objects/batch")"
    if [[ "${code}" =~ ^(200|422)$ ]]; then
      ok "LFS batch endpoint reachable with an ordinary credential (${code})"
    else
      bad "LFS batch returned ${code}"
    fi

    # With a bridge token, the batch operation resolves the required scope
    # from the body: an lfs:read token may download; upload needs lfs:write.
    if [[ -n "${BRIDGE_TOKEN:-}" ]]; then
      code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${BRIDGE_TOKEN}" \
        -X POST \
        -H 'Content-Type: application/vnd.git-lfs+json' \
        -d '{"operation":"download","transfers":["basic"],"objects":[]}' \
        "${PUBLIC_URL}${GITEA_REPO_PATH}/info/lfs/objects/batch")"
      if [[ "${code}" =~ ^(200|422)$ ]]; then
        ok "LFS batch download accepted with a bridge token (${code})"
      else
        bad "LFS batch download with bridge token returned ${code}"
      fi
    fi
  fi
else
  note "GITEA_USER/GITEA_PAT unset; backwards-compat checks not run"
fi

echo "== 9. Relay WebSocket still upgrades at the root =="
ws_headers="$("${CURL[@]}" --http1.1 -o /dev/null -D - \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  "${PUBLIC_URL}/" 2>/dev/null)"
if grep -qi '^HTTP/1.1 101' <<<"${ws_headers}"; then
  ok "relay WebSocket upgrade succeeded at /"
else
  bad "WebSocket upgrade at / did not return 101; the relay may be unreachable after cutover"
fi

echo
echo "passed=${pass} failed=${fail} skipped=${skip}"
echo
echo "STILL REQUIRES MANUAL VERIFICATION:"
cat <<'EOF'
  - git clone/push of a LARGE repo through the bridge (proves nothing buffers
    the pack: watch memory on the bridge and nginx during the push)
  - push authorized by a signed repository-state event succeeds, and an
    unauthorized push is rejected by grasp-pre-receive
  - anonymous access to a mapped repo stops immediately after making it private
  - browser login via NIP-07/46/55 completes the session handoff and lands in
    the Gitea UI with a working session cookie (check the cookie is set on the
    handoff response and that a follow-up page load stays logged in)
  - at least one existing package client keeps working end to end
    (e.g. npm install / docker pull with its current credentials)
  - Gitea is unreachable from an EXTERNAL host, not just from this one
  - no token, PAT, or Authorization value appears in nginx or bridge logs:
      docker compose logs grasp-bridge | grep -iE 'grasp_v1_|authorization|sha1'
EOF

if [[ "${fail}" -gt 0 ]]; then
  echo
  echo "CUTOVER NOT VERIFIED: roll back to deploy/nginx/gitea-vhost.legacy.conf.example"
  exit 1
fi

#!/usr/bin/env bash
# z88-gitea-validate.sh — validate the deployed Gitea image's PAT/auth
# behavior BEFORE the full-proxy cutover (beads issue phase1-z88).
#
# Run from a host that can reach Gitea DIRECTLY (inside the private network,
# or before the port is closed). These checks deliberately bypass the bridge:
# they prove the assumptions the bridge's credential translation depends on.
#
# Required environment:
#   GITEA_URL         direct Gitea origin, e.g. http://127.0.0.1:3000
#   GITEA_ADMIN_USER  admin login
#   GITEA_ADMIN_PAT   admin personal access token (used as Basic password)
#   TEST_USER         an existing NON-admin login to mint a scoped PAT for
#
# Optional:
#   TEST_PRIVATE_REPO owner/name of a private repo TEST_USER can read
#   PKG_OWNER         owner for package upload tests (default: TEST_USER)
#   PUBLIC_URL        the bridge's canonical public origin, to compare the
#                     docker realm against ROOT_URL
#
# The script mints PATs for TEST_USER and uploads a scratch generic package;
# both are deleted before exit.

set -u -o pipefail

: "${GITEA_URL:?set GITEA_URL}"
: "${GITEA_ADMIN_USER:?set GITEA_ADMIN_USER}"
: "${GITEA_ADMIN_PAT:?set GITEA_ADMIN_PAT}"
: "${TEST_USER:?set TEST_USER}"
PKG_OWNER="${PKG_OWNER:-${TEST_USER}}"
GITEA_URL="${GITEA_URL%/}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

pass=0; fail=0
ok()   { echo "  ok   $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL $*"; fail=$((fail+1)); }
note() { echo "  note $*"; }
hdr()  { echo; echo "== $*"; }

admin_curl() { curl -sS -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PAT}" "$@"; }
status_of()  { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

PAT_NAME="z88-validate-$$"
PAT_NAME2="z88-validate-byname-$$"
USER_PAT=""

cleanup() {
  # Best-effort: remove anything this run created.
  if [[ -n "${USER_PAT}" ]]; then
    admin_curl -X DELETE "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens/${PAT_NAME}" >/dev/null 2>&1
  fi
  admin_curl -X DELETE "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens/${PAT_NAME2}" >/dev/null 2>&1
  curl -sS -u "${TEST_USER}:${USER_PAT}" -X DELETE \
    "${GITEA_URL}/api/packages/${PKG_OWNER}/generic/z88-scratch/1.0.0" >/dev/null 2>&1
}
trap cleanup EXIT

hdr "0. Deployed image"
version="$(curl -sS "${GITEA_URL}/api/v1/version" | jq -r .version 2>/dev/null)"
if [[ -n "${version}" && "${version}" != "null" ]]; then
  ok "gitea version ${version}"
else
  bad "could not read /api/v1/version — is GITEA_URL direct and reachable?"
  echo; echo "aborting: nothing else can be validated"; exit 1
fi

hdr "1. Admin PAT mint requires Basic (reqBasicOrRevProxyAuth)"
# The 'token' auth header must NOT work on this route.
code="$(status_of -X POST -H "Authorization: token ${GITEA_ADMIN_PAT}" \
  -H 'Content-Type: application/json' \
  -d '{"name":"z88-should-fail","scopes":["write:repository"]}' \
  "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens")"
if [[ "${code}" == "401" || "${code}" == "403" ]]; then
  ok "Authorization: token header refused (${code}) — Basic is required, as the bridge assumes"
else
  bad "Authorization: token header returned ${code}; expected 401/403 (assumption violated — investigate before cutover)"
fi

hdr "2. Mint scoped PAT with Basic admin auth (the bridge's exact scope set)"
resp="$(admin_curl -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"${PAT_NAME}\",\"scopes\":[\"write:package\",\"write:repository\"]}" \
  -w '\n%{http_code}' "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens")"
code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
if [[ "${code}" == "201" ]]; then
  ok "mint returned 201"
else
  bad "mint returned ${code}: ${body}"
fi
USER_PAT="$(jq -r '.sha1 // empty' <<<"${body}")"
token_id="$(jq -r '.id // empty' <<<"${body}")"
if [[ -n "${USER_PAT}" ]]; then
  ok "plaintext PAT present in response (returned once)"
else
  bad "no sha1 in mint response"
fi
scopes="$(jq -r '(.scopes // []) | sort | join(",")' <<<"${body}")"
if [[ "${scopes}" == *"write:package"* && "${scopes}" == *"write:repository"* ]]; then
  ok "scope strings normalized and preserved: ${scopes}"
else
  bad "scopes came back as '${scopes}', want write:package+write:repository"
fi

hdr "3. Bogus scope is rejected (Normalize is strict)"
code="$(admin_curl -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"name":"z88-bogus","scopes":["write:bogus"]}' \
  "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens")"
if [[ "${code}" == "400" || "${code}" == "422" ]]; then
  ok "bogus scope refused (${code})"
else
  bad "bogus scope returned ${code}, expected 400/422"
fi

hdr "4. PAT delete by numeric id and by name"
if [[ -n "${token_id}" ]]; then
  code="$(admin_curl -o /dev/null -w '%{http_code}' -X DELETE \
    "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens/${token_id}")"
  if [[ "${code}" == "204" ]]; then
    ok "delete by id ${token_id} → 204"
  else
    bad "delete by id returned ${code}"
  fi
fi
# Re-mint for the remaining live checks, and prove delete-by-name works
# (the bridge's ambiguous-creation reconciliation depends on it).
resp="$(admin_curl -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"${PAT_NAME2}\",\"scopes\":[\"write:package\",\"write:repository\"]}" \
  "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens")"
byname_pat="$(jq -r '.sha1 // empty' <<<"${resp}")"
code="$(admin_curl -o /dev/null -w '%{http_code}' -X DELETE \
  "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens/${PAT_NAME2}")"
if [[ "${code}" == "204" ]]; then
  ok "delete by name → 204"
else
  bad "delete by name returned ${code}"
fi
resp="$(admin_curl -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"${PAT_NAME}\",\"scopes\":[\"write:package\",\"write:repository\"]}" \
  "${GITEA_URL}/api/v1/users/${TEST_USER}/tokens")"
USER_PAT="$(jq -r '.sha1 // empty' <<<"${resp}")"
[[ -n "${USER_PAT}" ]] || { bad "re-mint for live checks failed"; }

hdr "5. Git smart HTTP accepts the PAT as Basic password"
if [[ -n "${TEST_PRIVATE_REPO:-}" && -n "${USER_PAT}" ]]; then
  code="$(status_of -u "${TEST_USER}:${USER_PAT}" \
    "${GITEA_URL}/${TEST_PRIVATE_REPO}.git/info/refs?service=git-upload-pack")"
  if [[ "${code}" == "200" ]]; then
    ok "authenticated info/refs on private ${TEST_PRIVATE_REPO} → 200"
  else
    bad "authenticated info/refs returned ${code}"
  fi
  code="$(status_of "${GITEA_URL}/${TEST_PRIVATE_REPO}.git/info/refs?service=git-upload-pack")"
  if [[ "${code}" == "401" || "${code}" == "404" ]]; then
    ok "anonymous info/refs on private repo refused (${code})"
  else
    bad "anonymous info/refs on private repo returned ${code}"
  fi
else
  note "TEST_PRIVATE_REPO unset; git smart HTTP not checked"
fi

hdr "6. Package routes accept Basic user:PAT (the bridge's injected shape)"
if [[ -n "${USER_PAT}" ]]; then
  code="$(status_of -u "${TEST_USER}:${USER_PAT}" -X PUT --data-binary 'z88' \
    "${GITEA_URL}/api/packages/${PKG_OWNER}/generic/z88-scratch/1.0.0/z88.txt")"
  if [[ "${code}" == "201" ]]; then
    ok "generic upload with Basic PAT → 201"
  else
    bad "generic upload returned ${code} (write:package scope or Basic acceptance broken)"
  fi
  code="$(status_of -u "${TEST_USER}:${USER_PAT}" \
    "${GITEA_URL}/api/packages/${PKG_OWNER}/generic/z88-scratch/1.0.0/z88.txt")"
  if [[ "${code}" == "200" ]]; then
    ok "generic download with Basic PAT → 200"
  else
    bad "generic download returned ${code}"
  fi
  # NuGet is the family whose CLIENT uses a bespoke header; downstream the
  # bridge always injects Basic, so Basic must work on the nuget route.
  code="$(status_of -u "${TEST_USER}:${USER_PAT}" \
    "${GITEA_URL}/api/packages/${PKG_OWNER}/nuget/index.json")"
  if [[ "${code}" == "200" ]]; then
    ok "nuget service index with Basic PAT → 200"
  else
    bad "nuget service index returned ${code} (bridge injects Basic on nuget routes)"
  fi
else
  note "no user PAT; package checks skipped"
fi

hdr "7. Docker /v2 challenge and registry token"
challenge="$(curl -sS -o /dev/null -D - "${GITEA_URL}/v2/" | tr -d '\r' | grep -i '^www-authenticate:' || true)"
code="$(status_of "${GITEA_URL}/v2/")"
if [[ "${code}" == "401" && -n "${challenge}" ]]; then
  ok "anonymous /v2/ → 401 with challenge"
  echo "       ${challenge}"
else
  bad "anonymous /v2/ returned ${code} challenge='${challenge}'"
fi
realm="$(sed -n 's/.*realm="\([^"]*\)".*/\1/p' <<<"${challenge}")"
service="$(sed -n 's/.*service="\([^"]*\)".*/\1/p' <<<"${challenge}")"
if [[ -n "${realm}" ]]; then
  ok "realm: ${realm} (service: ${service:-<none>})"
  if [[ -n "${PUBLIC_URL:-}" ]]; then
    if [[ "${realm}" == "${PUBLIC_URL%/}"* ]]; then
      ok "realm already uses the public origin (ROOT_URL is the public URL)"
    else
      note "realm origin differs from PUBLIC_URL — the bridge rewrites exact-Gitea-origin realms, so verify ROOT_URL intent"
    fi
  fi
else
  bad "no realm in challenge"
fi
if [[ -n "${realm}" && -n "${USER_PAT}" ]]; then
  sep='?'; [[ "${realm}" == *\?* ]] && sep='&'
  tok_resp="$(curl -sS -u "${TEST_USER}:${USER_PAT}" \
    "${realm}${sep}service=${service}&scope=repository:${PKG_OWNER}/z88-scratch:pull")"
  reg_token="$(jq -r '.token // .access_token // empty' <<<"${tok_resp}")"
  if [[ -n "${reg_token}" ]]; then
    ok "token endpoint accepted Basic user:PAT and returned a registry token"
    payload="$(cut -d. -f2 <<<"${reg_token}" | tr '_-' '/+' )"
    pad=$(( (4 - ${#payload} % 4) % 4 )); payload="${payload}$(printf '=%.0s' $(seq 1 ${pad}) 2>/dev/null)"
    decoded="$(base64 -d <<<"${payload}" 2>/dev/null || base64 -D <<<"${payload}" 2>/dev/null)"
    iat="$(jq -r '.iat // empty' <<<"${decoded}")"
    exp="$(jq -r '.exp // empty' <<<"${decoded}")"
    if [[ -n "${iat}" && -n "${exp}" ]]; then
      lifetime=$(( exp - iat ))
      if (( lifetime <= 600 )); then
        ok "registry JWT lifetime = ${lifetime}s (revocation bound; <= 600s)"
      else
        bad "registry JWT lifetime = ${lifetime}s — exceeds the intended ~5min revocation bound; document or reduce before enabling tokens for docker"
      fi
    else
      note "could not decode JWT exp/iat; inspect manually: ${tok_resp:0:120}..."
    fi
  else
    bad "token endpoint did not return a token: ${tok_resp:0:200}"
  fi
fi

hdr "8. Manual items (cannot be probed over HTTP)"
cat <<'EOF'
  [ ] app.ini: ENABLE_REVERSE_PROXY_AUTHENTICATION = true
  [ ] app.ini: REVERSE_PROXY_AUTHENTICATION_USER = X-Grasp-Auth-User
      (deploy/gitea/app.ini.phase3.snippet; header must ONLY be settable by
      the bridge — nginx and the proxy both strip it from client requests)
  [ ] app.ini: ROOT_URL equals the bridge's canonical public origin
  [ ] Gitea is unreachable from outside the private network (verify from an
      EXTERNAL host; docker compose config | grep -i published shows nothing)
  [ ] Registry token lifetime: if step 7 exceeded 600s, check whether the
      deployed Gitea version exposes a setting for it, or record the actual
      lifetime as the accepted revocation bound in the runbook
EOF

echo
echo "== result: ${pass} ok, ${fail} failed"
if (( fail > 0 )); then
  echo "   phase1-z88 is NOT satisfied — resolve failures before the cutover (phase1-3fs)."
  exit 1
fi
echo "   automated checks satisfied; complete the manual items above, then update phase1-z88."

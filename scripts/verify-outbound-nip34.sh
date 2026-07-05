#!/usr/bin/env bash
set -euo pipefail

: "${BRIDGE_ADMIN_URL:=http://localhost:8090}"
: "${RELAY_URL:=wss://relay.sharegap.net}"
: "${REPO_PUBKEY:?set REPO_PUBKEY to the 64-char NIP-34 repo owner pubkey}"
: "${REPO_ID:?set REPO_ID to the NIP-34 repo d tag}"

if ! command -v nak >/dev/null 2>&1; then
  echo "missing dependency: nak (used to subscribe to relay events)" >&2
  exit 2
fi

echo "Bridge health:"
curl -fsS "${BRIDGE_ADMIN_URL}/health"
echo

echo "Subscribing for outbound repo/CI events on ${RELAY_URL}."
echo "In another terminal, push an accepted branch update to the provisioned repo."
echo "Expect signed 30617/30618 as applicable and 5401 when CI workflows changed."

nak req \
  -k 30617 -k 30618 -k 5401 \
  -a "${REPO_PUBKEY}" \
  -t "d=${REPO_ID}" \
  "${RELAY_URL}"

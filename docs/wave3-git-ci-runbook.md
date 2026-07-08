# Wave 3 Git + CI runbook

## WS0 — Nostr login UI/session handoff

Deploy the custom Gitea assets under `deploy/gitea/custom/` into Gitea's custom path and restart Gitea:

- `templates/custom/body_outer_pre.tmpl` injects the sign-in script without replacing upstream templates.
- `public/assets/js/grasp-nostr-login.js` renders **Sign in with Nostr** on `/user/login` and calls:
  - `POST https://grasp.sharegap.net/auth/nip07/challenge`
  - `POST https://grasp.sharegap.net/auth/nip07/verify`
  - `POST https://grasp.sharegap.net/auth/nip46/init`
  - `GET https://grasp.sharegap.net/auth/nip46/status`
  - `GET https://grasp.sharegap.net/auth/nip55/challenge`

Bridge auth routes now allow browser CORS preflight from the Gitea sign-in page. Successful verification resolves or auto-creates the Gitea user and persists `nostr_identity_links` using the existing verified NIP-05 / hex-prefix naming policy.

Operator-gated verification:

1. Open `https://git.sharegap.net/user/login` in a browser with a NIP-07 extension.
2. Click **Sign in with Nostr** and sign the NIP-98 event.
3. Confirm `nostr_identity_links` has the pubkey → Gitea user link and that a first login created the expected user.
4. Repeat with a Signet `bunker://...` URI through the NIP-46 panel.
5. Repeat the Android NIP-55 deep-link/QR flow on an Android signer.

Known handoff boundary: this repository does not vendor Gitea core. The bridge verifies identity and creates/links the Gitea user; the live Gitea session creation must be completed by the deployed Gitea auth source/callback hook that consumes the verified identity. If that hook is absent in the live image, install the corresponding Gitea-side callback before enabling the button for general users.

## WS1 — outbound NIP-34 + Hive-CI trigger verification

Local/non-live checks:

```bash
go test ./internal/publisher ./internal/webhook ./internal/auth ./internal/store
go test ./...
go build ./...
```

Live relay exercise is operator-gated because it publishes real events to `relay.sharegap.net`:

1. Ensure bridge env on edge-01 includes:
   - `RELAY_URLS=wss://relay.sharegap.net`
   - `HOOK_RELAY_URL=wss://relay.sharegap.net`
   - `SIGNET_BUNKER_URL` for server/operator signing (production); `BRIDGE_NSEC` only for development fallback
   - `GITEA_WEBHOOK_SECRET`
   - `CI_ENABLED=true`
   - `CI_TRIGGER_REPOS=*` or the target `owner/repo`
2. Pick a provisioned test repository with a workflow file in `.github/workflows/*.yml` or `.hive/workflows/*.yaml`.
3. Start a relay subscription filtered to the repo coordinate and CI kind:
   - kinds `30617`, `30618`, `5401`
   - `#d` = repo id for repo events
4. Push a branch update that is accepted by the pre-receive NIP-34 state policy.
5. Confirm `/webhook/gitea` receives the push and the bridge publishes:
   - owner/repo announcement/state as applicable (`30617`/`30618`)
   - a `5401` WorkflowRun event for each changed branch/workflow pair
6. Confirm event IDs/signatures validate and events arrive on `relay.sharegap.net`.
7. Save relay event IDs, bridge logs, and Gitea delivery IDs in the session handoff.

## WS2 hygiene checks

- Confirm no orphaned `nip34-review-mcp` Node/tsx process is running on `ai-02` before live relay tests.
- Confirm whether public `git.sharegap.net:2222` SSH is intentionally unexposed or missing routing.
- Keep websocket-capable nginx proxying on the git vhost so websocket failures are visible.

## WS3 fast-follow TODO — Signet signing

Server/operator signing now uses `SIGNET_BUNKER_URL` over NIP-46 in production so the bridge no longer holds a long-lived nsec; live verification requires a provisioned Signet daemon/bunker.

## WS4 — fleet-internal Hive-CI check-runner

`dvm-cicd-runner` is external and operator-gated; do not vendor it here.

Deployment shape on Lemmy:

1. Mint a dedicated runner key in Signet.
2. Configure the runner with allowlisted fleet pubkeys only.
3. Disable Cashu/payment gating for the MVP fleet-internal runner.
4. Run with Deno + `act` and Docker access scoped to CI jobs.
5. Apply/fork the upstream `Deno.chdir` global-state concurrency fix before enabling concurrent jobs; until then, run one job at a time.
6. Upload build logs to Blossom and include Blossom URLs in `5402`/result events.
7. Subscribe to `5401` WorkflowRun events emitted by grasp-gitea and execute matching workflows.

Post-MVP exclusions: do not implement the canonical deployment pipeline (`5401` → `5100` → `5402` → OCI → Bahia intent) in this wave.

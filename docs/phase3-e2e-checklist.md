# Phase 3 end-to-end checklist

> **Updated 2026-04-22:** Provisioned repos now use resolved owner names (NIP-05 local-part
> or 39-char hex prefix), not raw `npub`. Adjust path expectations accordingly.
> Use `GET /mappings` to discover the actual owner path for a provisioned repo.

## 1) Gitea config

- Confirm in `app.ini`:
  - `[server] ROOT_URL = <your CLONE_PREFIX value>`
- Restart gitea and verify health.

## 2) Reverse proxy

- Copy `deploy/nginx/gitea-vhost.conf.example`, replace `YOUR_DOMAIN` with your domain.
- Reload nginx.
- Verify:
  - `curl -I https://<your-domain>` returns `200` or `302` from gitea.

## 3) Bridge + relay connectivity

- Start bridge with:
  - `RELAY_URLS=ws://gastown-relay:3334`
  - `HOOK_RELAY_URL=ws://gastown-relay:3334`
  - `ADMIN_API_TOKEN=<your-token>` (optional but recommended)
- Verify bridge health:
  - `curl http://localhost:8090/health`

## 4) ngit flow

- Run `ngit init` for a new repo.
- Verify bridge logs show provisioning for `{npub}/{repo-id}`.
- Fetch the resolved owner from the bridge:
  - `curl -H "Authorization: Bearer <token>" http://localhost:8090/mappings`
- Verify in gitea web UI that the resolved org/repo exists (may be NIP-05 name or hex prefix, NOT raw npub).
- Verify hook exists at the resolved path:
  - `/gitea-data/git/repositories/{resolved-owner}/{repo-id}.git/hooks/pre-receive`

## 5) push validation

- Publish valid kind `30618` and push matching commit => expect success.
- Push non-matching commit without new state => expect rejection with SHA mismatch.
- Push to `refs/nostr/<valid-hex>` without any state event => expect success.

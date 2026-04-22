# Phase 3 end-to-end checklist

## 1) Gitea config

- Confirm in `app.ini`:
  - `[service] MAX_USERNAME_LENGTH = 70`
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
- Verify bridge health:
  - `curl http://localhost:8090/health`

## 4) ngit flow

- Run `ngit init` for a new repo.
- Verify bridge logs show provisioning for `{npub}/{repo-id}`.
- Verify in gitea web UI that org/repo exists.
- Verify hook exists:
  - `/gitea-data/git/repositories/{npub}/{repo-id}.git/hooks/pre-receive`

## 5) push validation

- Publish valid kind `30618` and push matching commit => expect success.
- Push non-matching commit without new state => expect rejection with SHA mismatch.

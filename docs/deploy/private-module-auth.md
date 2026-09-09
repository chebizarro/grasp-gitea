# Building grasp-gitea with private-module authentication

`go.mod` pulls two private modules from the sharegap forge:

- `git.sharegap.net/cascadia/cascadia-go`
- `git.sharegap.net/cascadia/cascadia-nips/generated/go`

A clean-host `docker build` cannot fetch these anonymously — `go mod download`
returns `403 Forbidden`. This document is the reproducible auth recipe for
Track B / operator rebuilds (the incident that filed
`grasp-gitea-clean-edge-build-private-module-auth-20260906`).

The Dockerfile expects a **BuildKit secret** named `git-credentials`
containing one line in the git credential-store format. The secret is
mounted only for the `go mod download` step and never persisted to a layer.
Git is configured for that step through an in-memory, read-only credential
helper: it reads the mounted credential for `get` requests and ignores
write/erase requests, so Git never tries to modify the secret mount.

The generated Go module is a subdirectory of the `cascadia-nips` repository.
Its Go import metadata maps
`git.sharegap.net/cascadia/cascadia-nips/generated/go` to the repository root
`git.sharegap.net/cascadia/cascadia-nips`, so the same host credential covers
both the root repository lookup and the generated subdirectory module.
That import metadata is currently served without authentication; the
credential helper authenticates only the subsequent Git fetch. If the forge
ever protects `?go-get=1` metadata, this path must move to a protected module
proxy because Git credentials cannot authenticate Go's metadata request.

## One-time setup on the build host

1. Create a **read-only bot user** on `git.sharegap.net` with access to
   `cascadia/cascadia-go` and `cascadia/cascadia-nips`. Do not reuse an
   admin account; do not embed a human developer's PAT in shared build
   infrastructure.
2. Mint a Gitea Personal Access Token for that bot with `read:repository`
   scope.
3. Write the credential to a file readable only by the build user, e.g.:

    ```sh
    umask 077
    printf 'https://grasp-build-bot:%s@git.sharegap.net\n' "$TOKEN" \
      > "$HOME/.git-credentials"
    ```

   Do not write this into the repo, into build args, or into environment
   dumps. Rotate on any operator handoff.

## Building the release image

Use the Makefile target — it validates the credential file exists and passes
the correct BuildKit flags:

```sh
GRASP_IMAGE_TAG=nip34-live-$(git rev-parse --short HEAD)-full \
  make docker-build-full
```

The target fails closed with an actionable message if `.git-credentials`
is missing, empty, or inside the repository's Docker build context. Keep the
protected file outside the checkout. To point at a non-default credential
path:

```sh
GRASP_GIT_CREDENTIALS=/var/run/secrets/grasp/git-credentials \
  GRASP_IMAGE_TAG=nip34-live-$(git rev-parse --short HEAD)-full \
  make docker-build-full
```

The direct `docker build` invocation is equivalent:

```sh
DOCKER_BUILDKIT=1 docker build \
  --secret id=git-credentials,src="$HOME/.git-credentials" \
  --build-arg BUILD_TAGS=full \
  -t grasp-bridge:nip34-live-$(git rev-parse --short HEAD)-full .
```

## CI and repository self-test

This repository has no checked-in hosted-runner workflow. Its containerized
CI entry point is `make selftest`, backed by `Dockerfile.selftest`. Configure
the CI secret manager to supply the credential as a protected **file-type**
secret, then pass only that file's path to Make:

```sh
GRASP_GIT_CREDENTIALS=/run/ci-secrets/grasp-git-credentials make selftest
```

`make selftest` validates that the file exists and passes it to the self-test
image build as the same `git-credentials` BuildKit secret. The Dockerfile
mounts it only while asserting `go mod tidy -diff` and running
`go mod download all`; it then runs tests with module network access disabled.
The subsequent test image does not contain the secret. CI must not convert
the credential to a build argument, environment value, command-line value,
or repository file. Both Make targets reject a credential file inside the
Docker build context, and `.dockerignore` excludes conventional credential
filenames as defense in depth.

CI jobs that build the release image use the same file-type protected input
with `GRASP_GIT_CREDENTIALS` and `make docker-build-full`.

## Docker Compose builds

Every checked-in Compose file that builds the bridge declares the same
`git-credentials` build secret. Set `GRASP_GIT_CREDENTIALS` to a protected
file outside the checkout before `docker compose build` or an E2E target that
builds the image. Compose mounts it only for the Dockerfile download step.

## Optional: public/anonymous builds

For CI paths that build only the OSS surface (no private-module code
required), pass `--build-arg PRIVATE_MODULE_AUTH=optional`. The Dockerfile
will still attempt `go mod download`; if the private modules are actually
required by `go.mod`, the build fails with the underlying Go module error
rather than the friendly credential message.

## Verifying the built image does not leak the credential

The BuildKit secret mount type never writes the file into any layer. To
audit:

```sh
docker history grasp-bridge:<tag> --no-trunc | grep -i credential || true
docker save grasp-bridge:<tag> | tar -x -O | grep -a credentials || true
```

Both should be empty.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `exit code 78` from build with `private module auth is required` | `.git-credentials` file empty or missing | Provide the secret per steps above |
| `exit code 78` from `make selftest` | CI did not supply a non-empty protected credential file | Configure a file-type CI secret and set `GRASP_GIT_CREDENTIALS` to its path |
| `go: 403 Forbidden` from `git.sharegap.net/...` | Bot user lacks read access | Grant the bot user repo access on both cascadia-go and cascadia-nips |
| `fatal: could not read Username` mid-build | Read-only credential helper not configured for the download RUN | Confirm the Dockerfile exports `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`, and `GIT_CONFIG_VALUE_0` when the secret is non-empty |
| Track B rollback with `grasp-gitea-clean-edge-build-private-module-auth-20260906` | Old build path assumed a host-level `.netrc` copied from a rollout folder | Use `make docker-build-full` from a clean checkout |

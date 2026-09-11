# syntax=docker/dockerfile:1.6
#
# Private module fetch: go.mod pulls git.sharegap.net/cascadia/cascadia-go and
# .../cascadia-nips (both private). Auth is supplied via a BuildKit secret
# named `git-credentials` containing one line in the git credential-store
# format (https://user:token@host). Track B / operator recipe:
#
#   DOCKER_BUILDKIT=1 docker build \
#     --secret id=git-credentials,src=$HOME/.git-credentials \
#     --build-arg BUILD_TAGS=full \
#     -t grasp-bridge:<label>-full .
#
# For unauthenticated public builds (no private modules needed) pass
# --build-arg PRIVATE_MODULE_AUTH=optional; go mod download will fail
# closed with a clear message if the private modules are actually required.
FROM golang:1.25-alpine AS build
ARG BUILD_TAGS=""
ARG GOPROXY=""
# PRIVATE_MODULE_AUTH: required (default) fails closed when the git-credentials
# secret is absent; optional allows the build to proceed anonymously.
ARG PRIVATE_MODULE_AUTH="required"
ENV GOPRIVATE=git.sharegap.net/*
RUN apk add --no-cache build-base git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
# BuildKit secret is mounted only for this RUN and never persisted to a
# layer. `required=true` on the mount is deliberately NOT used because we
# want to give an operator-friendly error and still support optional builds.
RUN --mount=type=secret,id=git-credentials,target=/root/.git-credentials \
	set -eu; \
	if [ -s /root/.git-credentials ]; then \
	  export GIT_CONFIG_COUNT=1; \
	  export GIT_CONFIG_KEY_0=credential.helper; \
	  export GIT_CONFIG_VALUE_0='!f() { [ "$1" != get ] || git credential-store --file=/root/.git-credentials get; }; f'; \
	elif [ "$PRIVATE_MODULE_AUTH" = "required" ]; then \
	  echo "grasp-gitea build: private module auth is required but the 'git-credentials' BuildKit secret was empty or missing." >&2; \
	  echo "Pass '--secret id=git-credentials,src=<path-to-git-credentials>' to 'docker build'." >&2; \
	  echo "See docs/deploy/private-module-auth.md for the exact recipe." >&2; \
	  exit 78; \
	fi; \
	go mod download all
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "${BUILD_TAGS}" -o /out/grasp-bridge ./cmd/grasp-bridge
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/grasp-pre-receive ./cmd/grasp-pre-receive

FROM alpine:3.20
# Hive-CI remains experimental: this runtime intentionally does not bundle
# act or a privileged container runtime. See README.md before enabling it.
RUN apk add --no-cache ca-certificates git sqlite-libs su-exec
WORKDIR /app
COPY --from=build /out/grasp-bridge /usr/local/bin/grasp-bridge
COPY --from=build /out/grasp-pre-receive /usr/local/bin/grasp-pre-receive
COPY scripts/grasp-bridge-entrypoint.sh /usr/local/bin/grasp-bridge-entrypoint
RUN chmod 0755 /usr/local/bin/grasp-bridge-entrypoint
ENTRYPOINT ["/usr/local/bin/grasp-bridge-entrypoint"]
CMD ["grasp-bridge"]

BRIDGE=grasp-bridge
HOOK=grasp-pre-receive

.PHONY: help build build-sidecar build-full run fmt lint-go test selftest deploy-compose-lint docker-build-full phase1-deployment-e2e phase1-repo-ownership-e2e phase3-e2e

help:
	@echo "Targets: build build-sidecar build-full run fmt lint-go test selftest deploy-compose-lint docker-build-full phase1-deployment-e2e phase1-repo-ownership-e2e phase3-e2e"

# docker-build-full: build the release grasp-bridge OCI image with the -full
# build tag and private-module auth wired via a BuildKit secret. Track B
# and clean-host operators MUST use this recipe. See
# docs/deploy/private-module-auth.md for how to construct .git-credentials.
#
# Inputs (env):
#   GRASP_IMAGE_TAG          required, e.g. nip34-live-5273df5-full
#   GRASP_GIT_CREDENTIALS    optional path to git-credentials file
#                            (default: $HOME/.git-credentials)
#
# Fails closed with an actionable message if the credential file is missing.
docker-build-full:
	@set -eu; \
	tag="$${GRASP_IMAGE_TAG:?set GRASP_IMAGE_TAG (e.g. nip34-live-$$(git rev-parse --short HEAD)-full)}"; \
	creds="$${GRASP_GIT_CREDENTIALS:-$$HOME/.git-credentials}"; \
	if [ ! -s "$$creds" ]; then \
	  echo "grasp-gitea: .git-credentials file not found at $$creds" >&2; \
	  echo "See docs/deploy/private-module-auth.md for the exact recipe." >&2; \
	  exit 78; \
	fi; \
	DOCKER_BUILDKIT=1 docker build \
	  --secret id=git-credentials,src="$$creds" \
	  --build-arg BUILD_TAGS=full \
	  -t grasp-bridge:$$tag .

build: build-sidecar

build-sidecar:
	go build -o bin/$(BRIDGE) ./cmd/grasp-bridge
	go build -o bin/$(HOOK) ./cmd/grasp-pre-receive

build-full:
	go build -tags full -o bin/$(BRIDGE) ./cmd/grasp-bridge
	go build -o bin/$(HOOK) ./cmd/grasp-pre-receive

run:
	go run ./cmd/grasp-bridge

fmt:
	gofmt -w ./cmd ./internal

lint-go:
	go vet ./...

test:
	go test ./...

selftest:
	docker build -f Dockerfile.selftest -t grasp-gitea-selftest .
	docker run --rm grasp-gitea-selftest

deploy-compose-lint:
	@set -eu; \
	config=$$(mktemp); \
	trap 'rm -f "$$config"' EXIT; \
	uid=$${USER_UID:-1000}; \
	gid=$${USER_GID:-1000}; \
	admin=$${GITEA_ADMIN_USER:-compose-lint-admin}; \
	token_file=$${GRASP_ADMIN_TOKEN_FILE:-/dev/null}; \
	USER_UID="$$uid" USER_GID="$$gid" GITEA_ADMIN_USER="$$admin" GRASP_ADMIN_TOKEN_FILE="$$token_file" \
		docker compose -f deploy/docker-compose.fullproxy.yml -f deploy/docker-compose.hardening.yml config >/dev/null; \
	USER_UID="$$uid" USER_GID="$$gid" GITEA_ADMIN_USER="$$admin" GRASP_ADMIN_TOKEN_FILE="$$token_file" \
		docker compose -f deploy/docker-compose.hardening.yml -f deploy/docker-compose.fullproxy.yml config >"$$config"; \
	for secret in grasp-admin-api-token grasp-credential-keys grasp-edge-shared-secret; do \
		grep -q "/run/grasp-secrets/$$secret" "$$config" || { \
			echo "rendered grasp-bridge command does not use private copy for $$secret" >&2; \
			exit 1; \
		}; \
	done

phase1-deployment-e2e:
	bash ./scripts/phase1-deployment-e2e.sh

phase1-repo-ownership-e2e:
	E2E_OWNERSHIP_ONLY=true bash ./scripts/phase1-deployment-e2e.sh

phase3-e2e:
	bash ./scripts/phase3-e2e.sh

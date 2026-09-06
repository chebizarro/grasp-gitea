BRIDGE=grasp-bridge
HOOK=grasp-pre-receive

.PHONY: help build build-sidecar build-full run fmt lint-go test selftest deploy-compose-lint phase1-deployment-e2e phase1-repo-ownership-e2e phase3-e2e

help:
	@echo "Targets: build build-sidecar build-full run fmt lint-go test selftest deploy-compose-lint phase1-deployment-e2e phase1-repo-ownership-e2e phase3-e2e"

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

BRIDGE=grasp-bridge
HOOK=grasp-pre-receive

.PHONY: help build build-sidecar build-full run fmt lint-go test selftest phase3-e2e

help:
	@echo "Targets: build build-sidecar build-full run fmt lint-go test selftest phase3-e2e"

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

phase3-e2e:
	bash ./scripts/phase3-e2e.sh

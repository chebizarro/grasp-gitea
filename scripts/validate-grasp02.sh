#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

go test ./internal/proactivesync -run TestGRASP02LocalValidation -count=1 -v
go test ./internal/proactivesync ./internal/relay ./internal/config -count=1

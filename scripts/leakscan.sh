#!/usr/bin/env bash
# Thin wrapper. The scanner itself is Go so that one tested implementation runs
# identically on every machine and in CI; see cmd/leakscan.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go run ./cmd/leakscan "$@"

#!/usr/bin/env bash
# Builds the published evidence page's compiled assets.
#
# The page ships the real gatekeeper compiled to WebAssembly so a reader can put
# their own proposals in front of the same rules the worker runs. That is only
# evidence if the module is built from this checkout rather than committed once
# and forgotten, so this script is the single place that produces it and CI runs
# it to confirm the committed artefact still matches the source.
set -euo pipefail
cd "$(dirname "$0")/.."

out=space/gatekeeper.wasm
exec_js=space/wasm_exec.js

echo "building $out from ./cmd/meshwasm"
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/meshwasm

# The loader shim has to come from the toolchain that produced the module. A
# mismatched pair fails at instantiation with an error that names neither.
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$exec_js"

size=$(wc -c < "$out")
gz=$(gzip -9 -c "$out" | wc -c)
printf 'gatekeeper.wasm  %s bytes (%s gzipped, which is what a browser downloads)\n' "$size" "$gz"
printf 'wasm_exec.js     %s bytes, from %s\n' "$(wc -c < "$exec_js")" "$(go env GOROOT)"

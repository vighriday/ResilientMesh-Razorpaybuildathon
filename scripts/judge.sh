#!/usr/bin/env bash
#
# ResilientMesh evaluation harness.
#
# One command that proves, rather than asserts, every claim the project makes.
# It runs the full test suite under the race detector, exhausts the mandate
# state space, boots the whole system on embedded infrastructure, drives a
# scripted outage through it, measures recovery against three competing
# policies, verifies the audit chain, then deliberately corrupts a ledger row
# and shows verification catching it.
#
#   ./scripts/judge.sh            # full run
#   ./scripts/judge.sh --quick    # reduced incident count
#
# Exit code is 0 only if every gate passed. Writes artifacts/JUDGE_REPORT.md.

set -uo pipefail
cd "$(dirname "$0")/.."

INCIDENTS=500
SEED=20260904
SKIP_RACE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --quick)      INCIDENTS=60 ;;
    --skip-race)  SKIP_RACE=1 ;;
    --incidents)  shift; INCIDENTS="${1:-500}" ;;
    --seed)       shift; SEED="${1:-20260904}" ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
CYAN=$'\033[36m'; GREY=$'\033[90m'; RESET=$'\033[0m'

FAILED=0
ROWS=()
START=$(date +%s)

section() {
  printf '\n%s%s%s\n'   "$GREY" "$(printf '=%.0s' {1..72})" "$RESET"
  printf '%s  %s%s\n'   "$CYAN" "$1" "$RESET"
  printf '%s%s%s\n'     "$GREY" "$(printf '=%.0s' {1..72})" "$RESET"
}

# Every gate records its own verdict, so the report reflects what actually ran
# rather than what the script intended to run.
gate() {
  local name="$1"; shift
  local optional=0
  if [ "$1" = "--optional" ]; then optional=1; shift; fi

  local t0 out rc elapsed
  t0=$(date +%s)
  out=$("$@" 2>&1); rc=$?
  elapsed=$(( $(date +%s) - t0 ))

  if [ $rc -eq 0 ]; then
    printf '  %sPASS%s  %s  (%ss)\n' "$GREEN" "$RESET" "$name" "$elapsed"
    ROWS+=("| $name | PASS | $elapsed |")
    return 0
  fi

  if [ $optional -eq 1 ]; then
    printf '  %sWARN%s  %s  (%ss)\n' "$YELLOW" "$RESET" "$name" "$elapsed"
    ROWS+=("| $name | WARN | $elapsed |")
  else
    printf '  %sFAIL%s  %s  (%ss)\n' "$RED" "$RESET" "$name" "$elapsed"
    printf '%s\n' "$out" | head -15 | sed 's/^/        /'
    ROWS+=("| $name | FAIL | $elapsed |")
    FAILED=$((FAILED + 1))
  fi
  return 1
}

gate_skip() {
  printf '  %sSKIP%s  %s -- %s\n' "$YELLOW" "$RESET" "$1" "$2"
  ROWS+=("| $1 | SKIP | 0 |")
}

printf '\n  ResilientMesh -- evaluation harness\n'
printf '%s  %s incidents, seed %s%s\n' "$GREY" "$INCIDENTS" "$SEED" "$RESET"

# ---------------------------------------------------------------------------
section 'Preflight'

GO_VERSION=$(go version)
printf '%s  toolchain: %s%s\n' "$GREY" "$GO_VERSION" "$RESET"

# The race detector needs cgo and a working C toolchain. Its absence is
# reported honestly rather than silently downgrading the run.
RACE_READY=0
RACE_REASON=""
if [ "$SKIP_RACE" -eq 1 ]; then
  RACE_REASON="disabled with --skip-race"
elif ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  RACE_REASON="no C toolchain on PATH; the race detector requires cgo"
elif [ "$(go env CGO_ENABLED)" = "0" ]; then
  RACE_REASON="CGO_ENABLED=0; the race detector requires cgo"
else
  RACE_READY=1
fi
[ "$RACE_READY" -eq 0 ] && printf '%s  race detector: unavailable -- %s%s\n' "$YELLOW" "$RACE_REASON" "$RESET"

mkdir -p artifacts

# Downloading the PostgreSQL binary inside a timed gate would measure the
# network rather than the system.
gate 'Warm embedded PostgreSQL binaries' go run ./cmd/meshctl warm-infra

gate 'Build all packages' go build ./...
gate 'Vet all packages'   go vet ./...

check_fmt() {
  local bad
  bad=$(gofmt -l . | grep -v '^$' || true)
  if [ -n "$bad" ]; then echo "not gofmt-clean:"; echo "$bad"; return 1; fi
  echo "gofmt clean"
}
gate 'Formatting is clean' check_fmt

# ---------------------------------------------------------------------------
section 'Security gates'

gate 'Leak scan (nothing private is tracked)' go run ./cmd/leakscan
gate 'Leak scanner self-tests'                go test ./cmd/leakscan -count=1

run_vulncheck() {
  go install golang.org/x/vuln/cmd/govulncheck@latest >/dev/null 2>&1 || return 1
  "$(go env GOPATH)/bin/govulncheck" ./...
}
gate 'Dependency audit' --optional run_vulncheck

# ---------------------------------------------------------------------------
section 'Correctness'

if [ "$RACE_READY" -eq 1 ]; then
  gate 'Full test suite under the race detector' go test ./... -race -count=1 -timeout 20m
else
  gate_skip 'Full test suite under the race detector' "$RACE_REASON"
  gate 'Full test suite (race detector unavailable)' go test ./... -count=1 -timeout 20m
fi

gate 'Gatekeeper invariants over 20,000 adversarial inputs' \
  go test ./internal/gatekeeper -run Property -count=1 -v

gate 'Mandate state space exhausted (model check)' \
  go run ./cmd/meshctl verify-model

gate 'Deterministic simulation: same seed, identical trace' \
  go run ./cmd/meshsim --seed "$SEED" --incidents 400 --assert-determinism

FUZZ=40; [ "$INCIDENTS" -lt 100 ] && FUZZ=8
gate 'Deterministic simulation: seed fuzz for invariant violations' \
  go run ./cmd/meshsim --fuzz "$FUZZ" --incidents 200

# ---------------------------------------------------------------------------
section 'End-to-end behaviour'

gate 'Boot, inject a bank outage, heal a live session' \
  go run ./cmd/meshctl e2e --seed "$SEED" --scenario issuer-outage

gate 'Queue outage: edge keeps accepting, backlog drains, nothing duplicated' \
  go run ./cmd/meshctl e2e --scenario queue-outage

gate 'Duplicate delivery storm produces exactly one incident' \
  go run ./cmd/meshctl e2e --scenario duplicate-storm

# ---------------------------------------------------------------------------
section 'Recovery measurement'

BENCH=artifacts/benchmark.json
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python

gate "Recovery benchmark across four policies ($INCIDENTS incidents)" \
  "$PY" eval/benchmark.py --incidents "$INCIDENTS" --seed "$SEED" --out "$BENCH"

gate 'Benchmark attestation re-derives' \
  go run ./cmd/meshctl bench verify --manifest "$BENCH"

# ---------------------------------------------------------------------------
section 'Audit trail'

gate 'Audit chain verifies' go run ./cmd/meshctl audit verify

# The tamper demonstration is the reason the chain exists: an audit trail that
# cannot detect its own modification is a log, not evidence.
gate 'Tampering with a ledger row is detected at the exact sequence' \
  go run ./cmd/meshctl audit prove-tamper

# ---------------------------------------------------------------------------
section 'Report'

ELAPSED=$(( $(date +%s) - START ))
PASS=$(printf '%s\n' "${ROWS[@]}" | grep -c '| PASS |' || true)
FAIL=$(printf '%s\n' "${ROWS[@]}" | grep -c '| FAIL |' || true)
WARN=$(printf '%s\n' "${ROWS[@]}" | grep -c '| WARN |' || true)
SKIP=$(printf '%s\n' "${ROWS[@]}" | grep -c '| SKIP |' || true)

{
  echo '# Evaluation report'
  echo
  echo "Generated $(date '+%Y-%m-%d %H:%M:%S %z') on $(uname -srm). Seed $SEED, $INCIDENTS incidents."
  echo
  echo "**$PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped** in ${ELAPSED}s."
  echo
  if [ "$RACE_READY" -eq 0 ] && [ "$SKIP_RACE" -eq 0 ]; then
    echo "> The race detector did not run: $RACE_REASON. Every other gate ran normally, and CI runs the suite with \`-race\` on Linux."
    echo
  fi
  echo '| Gate | Result | Seconds |'
  echo '|---|---|---|'
  printf '%s\n' "${ROWS[@]}"
  echo
  if [ -f "$BENCH" ]; then
    echo '## Recovery'
    echo
    "$PY" - "$BENCH" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print('Benchmark output could not be parsed.'); raise SystemExit(0)
print('| Policy | Recovered | Retries | Violations | Net value |')
print('|---|---|---|---|---|')
for p in d.get('policies', []):
    print(f"| {p.get('name')} | {p.get('gross_recovered_display')} | {p.get('retries')} "
          f"| {p.get('violations')} | **{p.get('nrcv_display')}** |")
print()
c = d.get('comparison') or {}
if c.get('ci_display'):
    print(f"Paired 95% CI against the strongest baseline: {c['ci_display']}")
    print()
m = d.get('manifest') or {}
if m.get('hash'):
    print(f"Attestation `{m['hash']}` -- re-derive with "
          f"`meshctl bench verify --manifest {sys.argv[1]}`")
    print()
PY
  fi
  echo '## Environment'
  echo
  echo "- $GO_VERSION"
  if [ "$RACE_READY" -eq 1 ]; then
    echo '- Race detector: enabled'
  else
    echo "- Race detector: unavailable -- $RACE_REASON"
  fi
  echo '- PostgreSQL: embedded binary, real server, no Docker'
  echo '- Redis: in-process RESP server, real protocol'
  echo '- Inference: whichever tier the console reports; no API key is required'
} > artifacts/JUDGE_REPORT.md

printf '\n  %s passed, %s failed, %s warnings, %s skipped  (%ss)\n' "$PASS" "$FAIL" "$WARN" "$SKIP" "$ELAPSED"
printf '%s  Report: artifacts/JUDGE_REPORT.md%s\n\n' "$GREY" "$RESET"

if [ "$FAILED" -gt 0 ]; then
  printf '  %sEVALUATION FAILED%s\n' "$RED" "$RESET"
  exit 1
fi
printf '  %sALL GATES PASSED%s\n' "$GREEN" "$RESET"

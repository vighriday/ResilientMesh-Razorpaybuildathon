# ResilientMesh evaluation harness.
#
# One command that proves, rather than asserts, every claim the project makes.
# It runs the full test suite under the race detector, exhausts the mandate
# state space, boots the whole system on embedded infrastructure, drives a
# scripted outage through it, measures recovery against three competing
# policies, verifies the audit chain, then deliberately corrupts a ledger row
# and shows verification catching it.
#
#   powershell -ExecutionPolicy Bypass -File scripts/judge.ps1
#
# Exit code is 0 only if every gate passed. Writes artifacts/JUDGE_REPORT.md.

[CmdletBinding()]
param(
  [int]$Incidents = 500,
  [int]$Seed = 20260904,
  [switch]$SkipRace,
  [switch]$Quick
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Quick) { $Incidents = 60 }

$script:Results = [System.Collections.ArrayList]::new()
$script:Failed = 0
$started = Get-Date

function Section($name) {
  Write-Host ''
  Write-Host ('=' * 72) -ForegroundColor DarkGray
  Write-Host "  $name" -ForegroundColor Cyan
  Write-Host ('=' * 72) -ForegroundColor DarkGray
}

# Every gate records its own verdict so the report reflects what actually ran,
# not what the script intended to run.
function Gate {
  param(
    [string]$Name,
    [scriptblock]$Body,
    [switch]$Optional,
    [string]$SkipReason
  )

  if ($SkipReason) {
    Write-Host "  SKIP  $Name -- $SkipReason" -ForegroundColor Yellow
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Status = 'SKIP'; Detail = $SkipReason; Seconds = 0 })
    return
  }

  $t0 = Get-Date
  try {
    $output = & $Body 2>&1 | Out-String
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
      throw "exit code $LASTEXITCODE`n$output"
    }
    Write-Host "  PASS  $Name  (${elapsed}s)" -ForegroundColor Green
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Status = 'PASS'; Detail = ($output.Trim() -split "`n" | Select-Object -Last 3) -join ' '; Seconds = $elapsed })
    return $output
  }
  catch {
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $status = if ($Optional) { 'WARN' } else { 'FAIL' }
    $colour = if ($Optional) { 'Yellow' } else { 'Red' }
    Write-Host "  $status  $Name  (${elapsed}s)" -ForegroundColor $colour
    Write-Host ($_.Exception.Message -split "`n" | Select-Object -First 15 | ForEach-Object { "        $_" }) -ForegroundColor DarkGray
    if (-not $Optional) { $script:Failed++ }
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Status = $status; Detail = ($_.Exception.Message -split "`n" | Select-Object -First 3) -join ' '; Seconds = $elapsed })
    return $null
  }
}

Write-Host ''
Write-Host '  ResilientMesh -- evaluation harness' -ForegroundColor White
Write-Host "  $Incidents incidents, seed $Seed" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
Section 'Preflight'

$goVersion = (& go version) 2>&1
Write-Host "  toolchain: $goVersion" -ForegroundColor DarkGray

# The race detector needs cgo and a 64-bit C toolchain. A 32-bit gcc on PATH
# fails with an error that looks like a code problem but is not, so the
# toolchain is resolved explicitly and its absence is reported honestly rather
# than silently downgrading the run.
$raceReady = $false
$raceReason = ''
if ($SkipRace) {
  $raceReason = 'disabled with -SkipRace'
} else {
  $candidates = @()
  if ($env:CC) { $candidates += $env:CC }
  $candidates += @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin\gcc.exe'),
    'C:\msys64\mingw64\bin\gcc.exe',
    'C:\mingw64\bin\gcc.exe'
  )
  $onPath = (Get-Command gcc -ErrorAction SilentlyContinue)
  if ($onPath) { $candidates += $onPath.Source }

  foreach ($c in $candidates) {
    if (-not $c -or -not (Test-Path -LiteralPath $c)) { continue }
    try { $target = (& $c -dumpmachine) 2>&1 } catch { continue }
    if ($target -match 'x86_64') {
      $env:CC = $c
      $raceReady = $true
      Write-Host "  race detector: using $target toolchain" -ForegroundColor DarkGray
      break
    }
  }
  if (-not $raceReady) {
    $raceReason = 'no 64-bit C toolchain found; install MSYS2 or WinLibs mingw64 to enable -race'
    Write-Host "  race detector: unavailable -- $raceReason" -ForegroundColor Yellow
  }
}

New-Item -ItemType Directory -Force artifacts | Out-Null

# Downloading the PostgreSQL binary inside a timed gate would measure the
# network, not the system.
Gate 'Warm embedded PostgreSQL binaries' { & go run ./cmd/meshctl warm-infra }

Gate 'Build all packages' { & go build ./... }
Gate 'Vet all packages'   { & go vet ./... }

Gate 'Formatting is clean' {
  $bad = & gofmt -l . | Where-Object { $_ -and $_ -notmatch '^\s*$' }
  if ($bad) { throw "not gofmt-clean:`n$($bad -join "`n")" }
  'gofmt clean'
}

# ---------------------------------------------------------------------------
Section 'Security gates'

Gate 'Leak scan (nothing private is tracked)' { & go run ./cmd/leakscan }
Gate 'Leak scanner self-tests'                { & go test ./cmd/leakscan -count=1 }

Gate 'Dependency audit' {
  & go install golang.org/x/vuln/cmd/govulncheck@latest
  & govulncheck ./...
} -Optional

# ---------------------------------------------------------------------------
Section 'Correctness'

if ($raceReady) {
  Gate 'Full test suite under the race detector' { & go test ./... -race -count=1 -timeout 20m }
} else {
  Gate 'Full test suite under the race detector' -SkipReason $raceReason
  Gate 'Full test suite (race detector unavailable)' { & go test ./... -count=1 -timeout 20m }
}

Gate 'Gatekeeper invariants over 20,000 adversarial inputs' {
  & go test ./internal/gatekeeper -run Property -count=1 -v
}

Gate 'Mandate state space exhausted (model check)' {
  & go run ./cmd/meshctl verify-model
}

Gate 'Deterministic simulation: same seed, identical trace' {
  & go run ./cmd/meshsim --seed $Seed --incidents 400 --assert-determinism
}

Gate 'Deterministic simulation: seed fuzz for invariant violations' {
  $n = if ($Quick) { 8 } else { 40 }
  & go run ./cmd/meshsim --fuzz $n --incidents 200
}

# ---------------------------------------------------------------------------
Section 'End-to-end behaviour'

Gate 'Boot, inject a bank outage, heal a live session' {
  & go run ./cmd/meshctl e2e --seed $Seed --scenario issuer-outage
}

Gate 'Queue outage: edge keeps accepting, backlog drains, nothing duplicated' {
  & go run ./cmd/meshctl e2e --scenario queue-outage
}

Gate 'Duplicate delivery storm produces exactly one incident' {
  & go run ./cmd/meshctl e2e --scenario duplicate-storm
}

# ---------------------------------------------------------------------------
Section 'Recovery measurement'

$benchOut = 'artifacts/benchmark.json'
Gate "Recovery benchmark across four policies ($Incidents incidents)" {
  & python eval/benchmark.py --incidents $Incidents --seed $Seed --out $benchOut
}

Gate 'Benchmark attestation re-derives' {
  & go run ./cmd/meshctl bench verify --manifest $benchOut
}

# ---------------------------------------------------------------------------
Section 'Audit trail'

Gate 'Audit chain verifies' { & go run ./cmd/meshctl audit verify }

# The tamper demonstration is the reason the chain exists: an audit trail that
# cannot detect its own modification is a log, not evidence.
Gate 'Tampering with a ledger row is detected at the exact sequence' {
  & go run ./cmd/meshctl audit prove-tamper
}

# ---------------------------------------------------------------------------
Section 'Report'

$elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
$pass = ($script:Results | Where-Object Status -eq 'PASS').Count
$fail = ($script:Results | Where-Object Status -eq 'FAIL').Count
$warn = ($script:Results | Where-Object Status -eq 'WARN').Count
$skip = ($script:Results | Where-Object Status -eq 'SKIP').Count

$lines = [System.Collections.ArrayList]::new()
[void]$lines.Add('# Evaluation report')
[void]$lines.Add('')
[void]$lines.Add("Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')) on $($env:COMPUTERNAME). Seed $Seed, $Incidents incidents.")
[void]$lines.Add('')
[void]$lines.Add("**$pass passed, $fail failed, $warn warnings, $skip skipped** in ${elapsed}s.")
[void]$lines.Add('')
if (-not $raceReady -and -not $SkipRace) {
  [void]$lines.Add("> The race detector did not run: $raceReason. Every other gate ran normally, and CI runs the suite with ``-race`` on Linux.")
  [void]$lines.Add('')
}
[void]$lines.Add('| Gate | Result | Seconds |')
[void]$lines.Add('|---|---|---|')
foreach ($r in $script:Results) {
  [void]$lines.Add("| $($r.Name) | $($r.Status) | $($r.Seconds) |")
}
[void]$lines.Add('')

if (Test-Path $benchOut) {
  [void]$lines.Add('## Recovery')
  [void]$lines.Add('')
  try {
    $b = Get-Content $benchOut -Raw | ConvertFrom-Json
    [void]$lines.Add('| Policy | Recovered | Retries | Violations | Net value |')
    [void]$lines.Add('|---|---|---|---|---|')
    foreach ($p in $b.policies) {
      [void]$lines.Add("| $($p.name) | $($p.gross_recovered_display) | $($p.retries) | $($p.violations) | **$($p.nrcv_display)** |")
    }
    [void]$lines.Add('')
    if ($b.comparison) {
      [void]$lines.Add("Paired 95% CI against the strongest baseline: $($b.comparison.ci_display)")
      [void]$lines.Add('')
    }
    if ($b.manifest) {
      [void]$lines.Add("Attestation ``$($b.manifest.hash)`` -- re-derive with ``meshctl bench verify --manifest $benchOut``")
      [void]$lines.Add('')
    }
  } catch {
    [void]$lines.Add('Benchmark output could not be parsed.')
    [void]$lines.Add('')
  }
}

[void]$lines.Add('## Environment')
[void]$lines.Add('')
[void]$lines.Add("- $goVersion")
[void]$lines.Add("- Race detector: $(if ($raceReady) { "enabled ($($env:CC))" } else { "unavailable -- $raceReason" })")
[void]$lines.Add('- PostgreSQL: embedded binary, real server, no Docker')
[void]$lines.Add('- Redis: in-process RESP server, real protocol')
[void]$lines.Add('- Inference: whichever tier the console reports; no API key is required')

$lines -join "`n" | Set-Content -Encoding UTF8 'artifacts/JUDGE_REPORT.md'

Write-Host ''
Write-Host "  $pass passed, $fail failed, $warn warnings, $skip skipped  (${elapsed}s)" -ForegroundColor White
Write-Host '  Report: artifacts/JUDGE_REPORT.md' -ForegroundColor DarkGray
Write-Host ''

if ($script:Failed -gt 0) {
  Write-Host '  EVALUATION FAILED' -ForegroundColor Red
  exit 1
}
Write-Host '  ALL GATES PASSED' -ForegroundColor Green
exit 0

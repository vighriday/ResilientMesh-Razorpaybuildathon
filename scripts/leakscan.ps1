# Thin wrapper. The scanner itself is Go so that one tested implementation runs
# identically on every machine and in CI; see cmd/leakscan.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
& go run ./cmd/leakscan @args
exit $LASTEXITCODE

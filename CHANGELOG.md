# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are milestones of the build, not releases to users.

## [Unreleased]

### Added
- **Frozen domain contracts** (`internal/domain`) — Razorpay wire types, the failure taxonomy, the rail model, the probabilistic/deterministic trust boundary (`DiagnosticContext` → `DiagnosticProposal` → `SanitizedCommand`), persistence records, the hash-chained audit entry, the shared cost model, and every cross-package port. No I/O, no internal imports, acyclic by construction.
- **Length-prefixed audit hashing** — `AuditEntry.ComputeHash` absorbs each field with an explicit length prefix rather than concatenating, closing the boundary-shifting forgery that naive concatenation allows.
- **Bucketed model input** — `AmountBand` keeps exact monetary values out of prompts while preserving the band-shaped signal that issuer limits actually carry.
- **Issuer key space** — `PaymentEntity.Issuer()` and `DowntimeEntity.TelemetryKey()` project payments and downtime notices into one key space, so a downtime notice joins against live failure counters without a lookup table. UPI keys off the VPA handle because UPI outages are PSP-scoped, not bank-scoped.
- Architecture decision log (`decisions.md`), 17 entries covering every non-obvious choice and its rejected alternatives.

### Security
- Private strategy material quarantined under a git-ignored `_internal/`; `.gitignore` blocks `*.docx`, all `.env` variants, key material, and runtime state.
- `DiagnosticContext` designed as a struct allowlist so cardholder data, VPAs, and raw webhook bodies are structurally incapable of reaching a model prompt.
- `SessionRecord` stores only a token hash, never the token.

### Verified
- `go build ./...`, `go vet ./internal/domain/`, `gofmt -l` all clean.
- Runtime dependencies proven on the target machine before being committed to: embedded PostgreSQL 18.3 boots in 23 s cold and accepts `pgx` connections with `jsonb` DDL; `miniredis` serves real RESP over TCP with `XADD`/`XGROUP`/`XREADGROUP`/`XACK`/`XPENDING`/`XAUTOCLAIM`/`EVAL` all working against `go-redis` v9.

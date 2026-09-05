# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are milestones of the build, not releases to users.

## [Unreleased]

### Added, the README checks itself
- **`cmd/receipts`**, a runner over `docs/receipts.json`: every claim the README makes, with the command that produces it, the value recorded when it was written, and the observation that would falsify it. Exits non-zero if a figure has drifted. Wired into `scripts/judge.sh` and `scripts/judge.ps1` as a gate.
- **The README restructured around one real payment.** `pay_XD0nBPG9aT3YHf` and its eleven ledger entries are the table of contents, and each mechanism is described at the entry where it actually bit, rather than in a feature tour.
- Three receipts are marked `browser` and deliberately not automated, because they are claims about what a reader's own machine does with the published artefacts. Each carries the reason in the manifest.

### Fixed, found by the harness on a slower configuration
- **A test budgeted in frames for something measured in seconds.** The SSE helper skipped heartbeat comments until a fixed count rather than a deadline, so sixty-four concurrent streams under the race detector queued more than thirty-two comments ahead of the event and healthy connections were reported as broken.
- **`t.Fatal` called from spawned goroutines** in the same test, which exits only the calling goroutine and printed one cause as six failures.
- **`judge.sh` truncated a failing gate to its first fifteen lines**, which for `go test ./...` is fifteen lines of `ok` with the cause cut off below. Failing gates now print the lines matching a failure signature, and the tail.

### Fixed, found by re-running the README against the code
- **The tamper demonstration named entry 269**; the published run tampers with entry 556.
- **The inference-tier split quoted a superseded run.** Every decision in the published run was made by the deterministic tier, and the README now says so.
- **The veto table came from a different scenario** than the one that ships with the page.
- **The evidence bundle was described as nine entries proved in 15 kB**; it is eleven entries in 21.5 kB, against a 1,112-entry ledger.

### Added, the learning layer
- **Off-policy evaluation** (`internal/ope`), IPS, self-normalised IPS and doubly-robust estimators over logged propensities, with a bias-corrected and accelerated bootstrap interval, overlap diagnostics and effective sample size. Refuses to emit a number when the target policy is unsupported by the log rather than dividing by a small probability.
- **A contextual bandit** (`internal/bandit`), Thompson sampling over Beta posteriors with an exact logged propensity: the action distribution is materialised before the draw, so the probability is recorded rather than reconstructed. Deterministic given a seed, with a hand-rolled gamma variate whose moments are asserted against the closed form.
- **Production wiring** (`internal/tuner`), the delay vocabulary and the rule mapping a gate floor onto a permitted arm set. The worker chooses its retry delay through it and writes a `POLICY_DECISION` ledger entry, carrying the propensity, before the attempt runs.
- **A cross-fitted recovery model** (`internal/reward`), logistic regression over hashed features trained with AdaGrad, reporting held-out log loss, skill against the base rate, AUC and Brier score. Cross-fitting is enforced rather than optional, with a test that requires zero held-out skill on pure noise.
- **Calibration** (`internal/calib`), expected calibration error, the Murphy decomposition, isotonic repair by pool-adjacent-violators, and a parametric-bootstrap noise floor so a small-sample artefact is not reported as a defect. Includes a threshold sweep that turns a chosen confidence constant into a measured trade against coverage.
- **A world with a known answer** (`internal/lab`), a generated recovery corpus whose latent structure is computable in closed form, gated by the real `internal/gatekeeper`, so an off-policy estimate can be scored against the truth it was trying to recover.
- **A proposer** (`internal/mill`), a language model reading aggregate statistics and suggesting typed segments, every one scored by the estimator at a confidence widened for the number of tests. Specificity is tested against a world with the planted effect flattened, where the same hypothesis must be refused.
- **`meshctl learn validate | discover | calibrate`**, three commands that need no database, queue, credential or network.
- **A learning chapter on the published page**, rendered entirely from `space/learn.json`, which is the verbatim JSON output of those three commands.
- `MESH_EXPLORE_FLOOR`, the share of decisions spent keeping the log evaluable. Zero disables the learner and restores the deterministic schedule.

### Fixed, found by measuring rather than by reading
- **The lift estimator self-normalised one side of a difference**, so the bias of the self-normalised term no longer cancelled and interval coverage sat near three quarters instead of nineteen twentieths.
- **The percentile bootstrap misplaced its interval on skewed data**, replaced with a bias-corrected and accelerated interval.
- **Isotonic regression did not pool tied confidences**, so a run of equal values survived as several blocks and a lookup read back the wrong one. It presented as a calibrator confidently wrong by exactly one bin.
- **Candidate policies were scored against the fixed schedule** rather than against the policy that produced the log, which drowned every segment-level effect in a whole-corpus difference.
- **A doubly-robust finding was published from a single small-corpus run** and reversed by measuring across sizes.

### Added
- **Frozen domain contracts** (`internal/domain`), Razorpay wire types, the failure taxonomy, the rail model, the probabilistic/deterministic trust boundary (`DiagnosticContext` → `DiagnosticProposal` → `SanitizedCommand`), persistence records, the hash-chained audit entry, the shared cost model, and every cross-package port. No I/O, no internal imports, acyclic by construction.
- **Length-prefixed audit hashing**, `AuditEntry.ComputeHash` absorbs each field with an explicit length prefix rather than concatenating, closing the boundary-shifting forgery that naive concatenation allows.
- **Bucketed model input**, `AmountBand` keeps exact monetary values out of prompts while preserving the band-shaped signal that issuer limits actually carry.
- **Issuer key space**, `PaymentEntity.Issuer()` and `DowntimeEntity.TelemetryKey()` project payments and downtime notices into one key space, so a downtime notice joins against live failure counters without a lookup table. UPI keys off the VPA handle because UPI outages are PSP-scoped, not bank-scoped.
- Architecture decision log (`decisions.md`), 17 entries covering every non-obvious choice and its rejected alternatives.

### Security
- Private strategy material quarantined under a git-ignored `_internal/`; `.gitignore` blocks `*.docx`, all `.env` variants, key material, and runtime state.
- `DiagnosticContext` designed as a struct allowlist so cardholder data, VPAs, and raw webhook bodies are structurally incapable of reaching a model prompt.
- `SessionRecord` stores only a token hash, never the token.

### Verified
- `go build ./...`, `go vet ./internal/domain/`, `gofmt -l` all clean.
- Runtime dependencies proven on the target machine before being committed to: embedded PostgreSQL 18.3 boots in 23 s cold and accepts `pgx` connections with `jsonb` DDL; `miniredis` serves real RESP over TCP with `XADD`/`XGROUP`/`XREADGROUP`/`XACK`/`XPENDING`/`XAUTOCLAIM`/`EVAL` all working against `go-redis` v9.

### Added, core engine
- `internal/config`, 29 documented environment variables, redacting `String()`/`LogValue()`, managed-mode credential generation from `crypto/rand`, and a cost model shared with the Python harness through one `eval/costs.json` so the live policy engine and the offline benchmark cannot price an incident differently.
- `internal/obs`, a redacting `slog` handler that covers `WithAttrs` and `WithGroup`, not just top-level attributes, plus an in-process metrics registry with bucketed latency histograms.
- `internal/policy`, Laplace-smoothed rail selection, so a rail at 1/1 does not outrank one at 400/500; integer-paisa expected value; seeded jitter for reproducible backoff.
- `internal/gatekeeper`, twelve ordered invariants, verified by a property test over 20,000 randomised adversarial inputs including hostile model responses and NaN confidences.
- `internal/agent`, three inference tiers behind one interface, a bucketed context digest that excludes attacker-influenced free text, and prompt construction that fences untrusted strings as data.
- `internal/infra`, real PostgreSQL and a real RESP server in-process, so the zero-dependency path and the Docker path share exactly one code path.
- `internal/store`, `SELECT ... FOR UPDATE SKIP LOCKED` for the outbox and an advisory-locked audit append, both verified concurrently against a real PostgreSQL.

### Fixed
- Five fail-open paths in the domain contracts, each found by an independent review of the contract by its consumers rather than by its author. See the commit for the full account.

### Changed
- `card_expired` and `card_not_supported` are no longer terminal declines. A changed card number does not mean the funding account is gone, and the network token still resolves, treating them as terminal silently discards recoverable revenue that incumbent processors recover routinely.

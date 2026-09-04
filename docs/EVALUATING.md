# Evaluating ResilientMesh

> **A published record of one real run** is at
> <https://huggingface.co/spaces/hriday29/resilientmesh>. It carries the full narration, one
> incident followed end to end, and all 538 entries of that run's audit ledger. The page
> re-derives every SHA-256 digest in your browser and lets you plant a forgery in the chain,
> so the tamper-evidence claim can be checked without running anything at all.


For a reviewer with no prior context. Everything below runs on a laptop with no
Docker, no cloud account, no API key, no payment account, and no network access
after `go mod download`.

Nothing binds beyond `127.0.0.1`. You should get no firewall prompt; if your OS
asks, you can safely deny it.

---

## 0. Prerequisites

| Need | Why | Check |
|---|---|---|
| **Go 1.25+** | The system is Go. | `go version` |
| ~200 MB disk | A PostgreSQL 18.3 binary is downloaded once and cached. | — |
| Python 3.10+ *(optional)* | Only for the recovery benchmark in `eval/`. | `python --version` |

Nothing else. No `psql`, no `redis-server`, no migration tool: PostgreSQL and a
Redis-protocol server run **inside the process**.

```bash
git clone https://github.com/vighriday/ResilientMesh-Razorpaybuildathon.git
cd ResilientMesh-Razorpay-buildathon
go mod download
```

---

## 1. The 60-second version

One command. It narrates itself, so there is nothing to read alongside it:

```bash
go run ./cmd/meshdemo
```

It boots the whole system, drives a bank outage and a batch of recurring
mandates through it, shows one incident's complete decision trail, lists the
invariants that refused things and why, reports what was recovered and what it
cost, then edits a row of its own audit ledger and proves the tamper is caught
at exactly that row. A transcript lands in `artifacts/DEMO_REPORT.md`.

```
go run ./cmd/meshdemo -full     # adds the model check and the benchmark
go run ./cmd/meshdemo -keep     # stays up afterwards so you can open the console
go run ./cmd/meshdemo -h        # every flag
```

Every number it prints is read out of the running system's database. If a claim
in this repository is false, this command prints the false version.

### The same thing as a pass/fail gate

```bash
go run ./cmd/meshctl selftest
```

It boots embedded PostgreSQL and Redis, starts a Razorpay API simulator, drives
a signed webhook stream of failed payments through the **real** pipeline, waits
for payments to actually recover, verifies the audit chain, then **edits a
ledger row directly in the database** and requires the tamper to be caught at
exactly that row.

Expected output (numbers vary slightly by timing):

```
  · booting embedded PostgreSQL and Redis
  · driving a scripted issuer outage through the live pipeline
  · verifying the audit chain, then attacking it

scenario                  issuer-outage (seed 42)
incidents ingested        8
recovered                 5
still scheduled           3
abstained                 0
gateway attempts          5
  diagnosed by HEURISTIC  13
audit entries             57
chain before tamper       intact
row edited in database    seq 28
tamper detected           yes
detected at               seq 28
elapsed                   42.4s
```

Exit code `0` only if a payment actually recovered **and** the tamper was caught
at the right sequence. `--json` gives a machine-readable version.

Why this gate and not a simpler one: decisions alone would pass even with the
retry scheduler deleted. The gate is a **completed recovery**, because that is
the failure this system exists to prevent, and it is the bug that was actually
found this way (see [`../README.md`](../README.md), "what broke").

**First run takes ~60s extra** while the PostgreSQL binary downloads. It is
cached in your user cache directory afterwards.

---

## 2. See it happen — the interactive demo

```bash
go run ./cmd/mesh
```

Wait for the banner, then open the two URLs it prints.

```
────────────────────────────────────────────────────────────────────
  ResilientMesh is running. Everything below is local.
────────────────────────────────────────────────────────────────────
  Checkout        http://127.0.0.1:8080/checkout.html
  Ops console     http://127.0.0.1:8080/console.html
  Razorpay API    http://127.0.0.1:8081
  Health          http://127.0.0.1:8080/readyz
────────────────────────────────────────────────────────────────────
  Ops token       d3cf8cf1e0611959e921eced46be19dd…
                  (generated for this run; paste it into the console)
────────────────────────────────────────────────────────────────────
```

### 2a. The ops console — what to look at

Open `/console.html` and paste the **ops token** from the banner.

| What you see | What it means |
|---|---|
| **Incidents** table filling | Failed payments arriving over signed webhooks and being recorded |
| **Inference tier** badge per row | Which tier decided: `LIVE`, `REPLAY` or `HEURISTIC`. With no API key you will see `HEURISTIC` — the system is fully functional without a model |
| **Issuer health** table | Rolling success rate per issuer, and each circuit breaker's state |
| **Audit chain** table | Every consequential decision, hash-chained |
| **Verify** button | Recomputes every link in the chain and reports the verdict |

Press **Verify**. It should say the chain is intact and give you the entry count
and head hash.

### 2b. The checkout — in-session healing

Open `/checkout.html` in a second tab. It opens a live session and connects to
the event stream. When the scripted outage hits its rail, the page **moves the
customer from Netbanking to UPI mid-session**, over Server-Sent Events, with the
amount unchanged. That is the "before the customer gives up" claim, visible.

The stream is keyed by an opaque session id plus a single-purpose bearer token,
not by order id — see ADR-011 in [`../decisions.md`](../decisions.md) for why
the obvious design is an authorisation bug.

### 2c. Useful flags

```bash
go run ./cmd/mesh -scenario mandate-batch     # recurring-mandate failures instead
go run ./cmd/mesh -scenario psp-degradation   # a UPI PSP failing rather than a bank
go run ./cmd/mesh -scenario mixed-traffic     # everything at once
go run ./cmd/mesh -rate 12                    # more failures per second
go run ./cmd/mesh -speed 1                    # real production delays, no compression
go run ./cmd/mesh -traffic=false              # serve the API without driving it
go run ./cmd/mesh -h                          # every flag
```

**About `-speed`:** correct production backoff is minutes to hours, so an
un-compressed demo shows decisions and never an outcome. `-speed` shortens
**only the wall-clock wait** before a scheduled retry. It never changes a
decision — the gatekeeper's delays include regulatory floors such as RBI's
24-hour cooling window, and a system that could configure its way under one
would have no invariant at all. Both the real delay and the compression factor
are written to the audit ledger, so a compressed run can never be mistaken for a
production one. Use `-speed 1` to watch it behave exactly as it would in
production.

---

## 3. Inspect what it did — the operator CLI

While `cmd/mesh` is running, open a second terminal. `meshctl` attaches to a
running mesh, so give it that mesh's endpoints — `cmd/mesh` logs the managed
PostgreSQL and Redis ports at startup:

```bash
# cmd/mesh logs its managed ports on the "managed infrastructure ready" line.
# The managed credentials are generated per run and printed there too.
export MESH_INFRA_MODE=external
export PGUSER=mesh PGPASSWORD=mesh PGPORT=<pg_port>
export MESH_PG_DSN="postgres://${PGUSER}:${PGPASSWORD}@127.0.0.1:${PGPORT}/mesh?sslmode=disable"
export MESH_REDIS_ADDR=127.0.0.1:<redis_port>
export MESH_WEBHOOK_SECRET=placeholder   # required in external mode; unused by reads
export MESH_OPS_TOKEN=placeholder

go run ./cmd/meshctl status
go run ./cmd/meshctl incident list
go run ./cmd/meshctl incident show <incident_id>
go run ./cmd/meshctl audit verify
```

`incident show` is the explainability surface — the whole story of one incident
in the order it happened:

```
incident      3f1c…              amount   ₹2,089.00 INR
issuer        upi:okaxis via upi decline  bank_technical_error
state         RECOVERED after 2 attempt(s)

decision trail
  SEQ  KIND                 DETAIL
  25   WEBHOOK_ACCEPTED     …
  26   DIAGNOSIS_PROPOSED   HEURISTIC proposed ASYNC_EXPONENTIAL_RETRY at 0.60 — upstream …
  27   GATE_DECISION        ASYNC_EXPONENTIAL_RETRY rail=upi_intent delay=60s [AMOUNT_PINNED DELAY_BOUNDS]
  28   INCIDENT_SCHEDULED   …
  29   ATTEMPT_STARTED      …
  30   ATTEMPT_RESULT       …
  31   INCIDENT_CLOSED      …

attempts
  N  RAIL        OUTCOME    CODE  COST     COMPLETED
  2  upi_intent  succeeded  —     ₹2.50    2026-09-04T16:23:10Z
```

Note `applied_invariants` on the gate decision. Every rule that fired is named.

Mutating commands exist too, and all of them require `--yes` and write their
intent to the ledger **before** acting:

```bash
go run ./cmd/meshctl mandate halt sub_xyz --reason "customer disputed" --yes
go run ./cmd/meshctl mandate resume sub_xyz --yes
go run ./cmd/meshctl dlq list
go run ./cmd/meshctl dlq replay <message_id> --yes
```

---

## 4. Verify the claims

Each of these is independent. Run any subset.

### The full harness (one command, ~5–15 min)

```bash
./scripts/judge.sh                                   # macOS / Linux / Git Bash
powershell -ExecutionPolicy Bypass -File scripts/judge.ps1    # Windows
# add -Quick / --quick for a ~3 minute pass
```

Runs every gate below, writes `artifacts/JUDGE_REPORT.md`, and exits non-zero if
anything fails. It reports honestly when a gate is skipped and why — including
when the race detector is unavailable on your machine.

### Exhaustive proof over the decision state space

```bash
go run ./cmd/modelcheck
```

Walks **every reachable mandate state** and evaluates every invariant at each
one. Property testing samples; this enumerates.

```
reachable states    510720
transitions         8390192
digest              66360d23c797833f2daf5db3b582dff9014dc5f2976f5b77d89841df7b6d22e7
  [HOLDS ] AMOUNT_PINNED                    510720 checked  0 violations
  [HOLDS ] RECURRING_COOLING_AND_NOTICE     510720 checked  0 violations
  [HOLDS ] ATTEMPT_CAP                      510720 checked  0 violations
  [HOLDS ] AFA_CEILING                      510720 checked  0 violations
  [HOLDS ] CLOSED_ACTION_SET                510720 checked  0 violations
  [HOLDS ] REFRESH_PRESERVES_TERMS          510720 checked  0 violations
  [HOLDS ] EXECUTABLE_NAMES_A_RAIL          510720 checked  0 violations
  [HOLDS ] SCHEDULE_BOUNDED                 510720 checked  0 violations
  [HOLDS ] GATE_DECIDES_WITHOUT_ERROR       510720 checked  0 violations
total violations 0
```

This is what found two defects that 20,000 property-test cases missed.

### Deterministic simulation with fault injection

```bash
go run ./cmd/meshsim --seed 20260904 --incidents 400 --assert-determinism
go run ./cmd/meshsim --fuzz 40 --incidents 200
go run ./cmd/meshsim --seed 20260904 --incidents 300 --chaos storm
```

Virtual clock, seeded scheduler, byte-identical traces. Injects duplicate
delivery, message loss, clock skew and partial writes at the boundaries that
actually fail in production. `--assert-determinism` runs the same seed twice and
requires the traces to match byte for byte.

### The test suite

```bash
go test ./... -count=1
go test ./... -race -count=1          # needs a 64-bit C toolchain
go test ./internal/gatekeeper -run Property -count=1 -v
```

The property run drives 20,000 randomised, adversarial inputs — including
prompt-injection strings, NaN confidences, SQL in action names and 500-character
identifiers — through the real gatekeeper and asserts every invariant holds. It
also asserts its **own** coverage: if any rule stops firing, the test fails
rather than passing vacuously.

### Recovery measured against competitors

```bash
python eval/benchmark.py --incidents 500 --seed 20260904 --out artifacts/benchmark.json
```

Runs four policies over the same generated incident stream — do nothing, blind
retry, static rules, an incumbent-style smart retry, and this system — and
compares them with a **paired bootstrap over merchants** (not over incidents;
incidents from one merchant are not independent draws, and treating them as such
narrows the interval to a number that is not true).

Real output from a 60-incident run:

| Policy | Recovery rate | Retries | Violations | Net recovered value |
|---|---:|---:|---:|---:|
| blind_retry | 23.3% | 165 | 94 | ₹82,232.50 |
| static_rules | 35.0% | 87 | 19 | ₹1,12,632.50 |
| incumbent_smart_retry | 50.0% | 113 | 24 | ₹2,15,620.50 |
| **resilientmesh** | **73.3%** | **86** | **0** | **₹3,52,748.40** |

`p = 0.0001`, paired 95% CI `+₹35,730` to `+₹2,71,455`. Note the **violations**
column: the incumbent policy recovers well and breaks regulatory rules 24 times
doing it. Every run writes an attestation manifest so a number can be
reproduced rather than believed.

### Security scan

```bash
go run ./cmd/leakscan
go test ./cmd/leakscan -count=1
```

Seven checks over every tracked file: private paths, credential shapes, private
references, `.env.example` hygiene, DOM-sink usage, dependency allowlist, and
control characters. It runs in CI and blocks the commit.

---

## 5. Optional: run with a live model

**The system is fully functional without one.** With no key it runs on cassette
replay plus the deterministic classifier, and the audit trail always says which
tier decided. The three tiers exist so a judge with no key sees the same
decisions as one with a model.

To enable the `LIVE` tier, Groq issues free API keys:

1. Sign up at <https://console.groq.com/keys> and create a key (free, no card).
2. Run with it set:

```bash
# macOS / Linux
MESH_LLM_PROVIDER=groq MESH_LLM_API_KEY=gsk_your_key_here go run ./cmd/mesh

# Windows PowerShell
$env:MESH_LLM_PROVIDER='groq'; $env:MESH_LLM_API_KEY='gsk_your_key_here'
go run ./cmd/mesh
```

The banner will read `Inference  LIVE openai/gpt-oss-120b, falling back to
REPLAY then HEURISTIC`, and console rows will show `LIVE` badges.

Google AI Studio, OpenAI and a local Ollama work the same way — set
`MESH_LLM_PROVIDER` to `gemini`, `openai` or `ollama`. All four speak the
OpenAI-compatible format, so the provider only selects endpoint and model
defaults. See [`../.env.example`](../.env.example).

**What changes with a key:** only the ambiguous failure set is decided
differently. Terminal declines, soft declines, every regulatory rule and every
money value are deterministic in all three tiers — see the "AI judgment" section
of the README for where a model is deliberately not used, and why.

**What does not change:** the gatekeeper. The model's output is advisory. You
can verify this the fun way — set `MESH_LOG_LEVEL=debug`, watch the proposals,
and confirm that a proposal the gate rejects is recorded as a veto with reasons
and executes nothing.

---

## 6. Running the pieces separately

The one-command demo is a convenience, not a special build. The same composition
root serves a split deployment:

```bash
# Terminal 1 — the Razorpay simulator
go run ./cmd/simulator

# Terminal 2 — the API edge only
MESH_INFRA_MODE=external MESH_PG_DSN=... MESH_REDIS_ADDR=... \
MESH_WEBHOOK_SECRET=... MESH_OPS_TOKEN=... go run ./cmd/api

# Terminal 3 — the recovery pipeline only
MESH_INFRA_MODE=external MESH_PG_DSN=... MESH_REDIS_ADDR=... \
MESH_WEBHOOK_SECRET=... MESH_OPS_TOKEN=... go run ./cmd/worker
```

Splitting them is what lets the edge scale on request volume and the worker on
incident volume — unrelated numbers, since one very large outage produces few
requests and many incidents.

There is also a `Dockerfile` and a `docker-compose.yml` if you would rather run
against a containerised PostgreSQL and Redis. Same code path either way: managed
mode speaks real PostgreSQL over pgx and a real RESP server over go-redis, so
there is no "local mode" whose bugs differ from production's.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `bind: address already in use` | A previous run is still holding a port. The system refuses to silently pick another, because printing a URL that is not the one you configured is worse than failing. Stop the old process, or use `-simulator-addr 127.0.0.1:0`. |
| First run hangs ~60s at startup | Downloading the PostgreSQL binary. Once only; it is cached. |
| `unable to clean up data directory` | An earlier run was killed hard and left a `postgres` process holding `.mesh/pg`. Stop it, then delete `.mesh/`. Normal `Ctrl-C` shutdown does not leave one. |
| Console shows "That token was rejected" | Paste the ops token exactly as printed in the banner. It is regenerated on every managed-mode run. |
| Everything shows `HEURISTIC` | Expected with no API key. Section 5 enables the live tier. |
| Incidents sit in `SCHEDULED` | Working as intended at `-speed 1`: recovery is deferred by minutes to hours. Use the default `-speed 60` to watch the loop close. |
| `go test -race` fails to link | Needs a 64-bit C toolchain. `scripts/judge.ps1` detects this and reports it honestly rather than skipping silently. |

---

## 8. Where to look in the code

If you read nothing else, read these three:

| File | Why |
|---|---|
| [`../internal/gatekeeper/gatekeeper.go`](../internal/gatekeeper/gatekeeper.go) | The 14 invariants. The authoritative decision. Every rule carries the reasoning for its existence. |
| [`../internal/domain/decision.go`](../internal/domain/decision.go) | The trust boundary. Note that `DiagnosticProposal` has **no amount field** — a model cannot propose a different amount because the wire format gives it nowhere to write one. |
| [`../internal/worker/worker.go`](../internal/worker/worker.go) | The pipeline, including the deferred-recovery sweep that a whole-system run proved was missing. |

Then: [`../docs/ARCHITECTURE.md`](ARCHITECTURE.md),
[`../docs/THREAT_MODEL.md`](THREAT_MODEL.md),
[`../decisions.md`](../decisions.md).

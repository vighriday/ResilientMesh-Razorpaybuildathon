# ResilientMesh

In-session payment protocol healing and mandate lifecycle sentry.

When a bank degrades mid-checkout, ResilientMesh moves the live session onto a working rail over Server-Sent Events before the customer gives up. When a recurring mandate fails, it schedules recovery inside RBI's constraints instead of retrying blindly. Every decision is written to a hash-chained audit ledger you can verify in one command.

Built for **Track 03 — AI Revenue Recovery**.

---

## Run it

One command. No Docker, no database install, no API key, no account, no spend.

```bash
go run ./cmd/mesh --demo
```

That boots a real PostgreSQL 18.3, a real Redis-protocol server, the HTTP edge, the worker pool, and a Razorpay simulator — all in one process — then runs a scripted bank outage against it.

Open the two URLs it prints:

| URL | What you see |
|---|---|
| `/checkout` | A live checkout. Watch it move from Netbanking to UPI mid-session when the bank fails. |
| `/console` | Incidents, issuer health, circuit breakers, and the audit chain with a **Verify** button. |

First run downloads a PostgreSQL binary once (~60 MB) and caches it. Everything after is a few seconds.

### Prove it, the way a reviewer would

```bash
./scripts/judge.sh      # or: powershell -File scripts/judge.ps1
```

This runs the full test suite including the race detector, boots the stack, drives a 500-incident batch through three competing recovery policies, verifies the audit chain, then **deliberately corrupts a ledger row and shows verification catching it**. It writes `artifacts/JUDGE_REPORT.md` and exits non-zero if anything fails.

---

## What the problem actually is

A payment fails with `gateway_technical_error`. That code is genuinely ambiguous — it covers a transient switch degradation, a planned overnight maintenance window, and a dead PSP, and the correct response to each is different. Meanwhile the customer is still on the page for a few more seconds.

The common answer is to send a payment link over WhatsApp. That fails on three counts: issuing banks do not send clickable payment links under RBI anti-phishing norms, the customer has already left, and out-of-band recovery drops most of the intent it is trying to capture.

ResilientMesh works inside the session that is still open, and treats everything else as a compliance-bounded scheduling problem.

---

## How the pieces fit

```
webhook ──► HMAC verify ──► one transaction { incident, outbox, audit }
                                     │
                              outbox relay (SKIP LOCKED)
                                     │
                              Redis Streams ──► dead letter
                                     │
                                  worker
                     breaker ─► diagnose ─► GATEKEEPER ─► execute
                                (advisory)   (authoritative)
                                     │
                              SSE ──► live checkout
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### The part that matters: the model has no authority

```
DiagnosticContext ──► model ──► DiagnosticProposal ──► Gatekeeper ──► SanitizedCommand
 allowlisted,                    advisory,                             executed
 bucketed, no PII                no authority
```

The model answers one genuinely probabilistic question: *what kind of failure is this, given the ambient evidence?* It never computes an amount, never decides a compliance outcome, and can only choose from a closed action set.

`DiagnosticProposal` has no amount field at all — an absent field cannot be wrong, whereas a validated field can still be wrong within its range. The amount on every command is copied from bytes that passed HMAC verification. Twelve deterministic invariants — the 24-hour mandate cooling window, the pre-debit notification, the attempt cap, the rail allowlist — are enforced in code and verified by property tests over 20,000 adversarial inputs, including deliberately hostile model responses.

---

## What it recovers, and how sure we are

Three policies over the same 500 incidents (paired design, so the difference has far lower variance than independent runs):

| | Blind retry | Static rules | ResilientMesh |
|---|---|---|---|
| Gross recovered | — | — | — |
| Gateway retries | — | — | — |
| Compliance violations | — | — | — |
| **Net recovered value** | — | — | — |

Numbers are filled in by `eval/benchmark.py` and reported with a paired bootstrap 95% confidence interval, because a single number from one simulated batch is one sample, not a result. `artifacts/benchmark.json` holds the raw output.

---

## Running against real infrastructure

Everything above uses a local simulator that speaks Razorpay's exact schemas. Switching to the real thing is configuration, not code:

```bash
MESH_INFRA_MODE=external
MESH_RAZORPAY_BASE_URL=https://api.razorpay.com
MESH_RAZORPAY_KEY_ID=...            # test-mode keys are free
MESH_WEBHOOK_SECRET=...
MESH_LLM_BASE_URL=https://api.groq.com/openai/v1   # free tier
MESH_LLM_API_KEY=...
```

See [.env.example](.env.example). With no key, diagnosis falls back to deterministic recorded inference and then to an audit-flagged heuristic — and the console shows you which tier answered, every time.

Docker Compose is also supported: `docker compose up`.

---

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, trust boundary, degradation behaviour |
| [decisions.md](decisions.md) | Every non-obvious choice and the alternatives rejected |
| [docs/POSTMORTEM.md](docs/POSTMORTEM.md) | What broke at 2 AM, and how we got out |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE across each trust boundary, with the test proving each control |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operating procedures for each failure mode |
| [docs/SLO.md](docs/SLO.md) | Objectives, error budgets, and what is an invariant instead |
| [docs/CAPACITY.md](docs/CAPACITY.md) | Measured throughput and connection numbers |
| [docs/DATA.md](docs/DATA.md) | What is stored, why, and what is deliberately not |

---

## Layout

```
cmd/        mesh (one-command runtime) · api · worker · simulator · meshctl
internal/   domain (frozen contracts) · ingest · outbox · store · audit
            agent · gatekeeper · policy · telemetry · breaker · sse · httpx
web/        checkout and operations console — no build step, no external assets
eval/       chaos injection and the NRCV benchmark
scripts/    judge harness, load, chaos, leak scan
```

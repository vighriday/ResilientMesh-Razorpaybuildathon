# Service Objectives

Two kinds of promise live here, and conflating them is how payment systems get into trouble.

**Objectives** have error budgets. Spending the budget is expected; running out means stop shipping features and fix reliability.

**Invariants** have no budget. A single breach is an incident, and there is no acceptable rate.

---

## Invariants

| Invariant | Enforcement | Evidence |
|---|---|---|
| The amount on a recovery attempt equals the amount on the HMAC-verified payload | `DiagnosticProposal` has no amount field; the gatekeeper copies from `PaymentEntity` | Property test, 20,000 adversarial inputs |
| No recurring debit inside the 24-hour cooling window | `RBI_MANDATE_COOLING`, computed from a durable timestamp | Property test, plus mandate state survives a Redis flush |
| No recurring debit without a pre-debit notification in the cycle | `RBI_PRE_DEBIT_NOTICE` | Property test |
| No incident exceeds its attempt cap | `STOP_RULE_MAX_ATTEMPTS`, counter in PostgreSQL not Redis | Property test; cache-eviction test |
| No accepted webhook is lost | Incident and outbox written in one transaction | Redis-outage test: API keeps accepting, everything drains |
| No event is processed twice into two incidents | `event_id` unique | Duplicate storm test |
| No audit entry can be silently altered | Hash chain, advisory-locked append | Tamper test names the exact broken sequence |
| No unverified webhook produces an effect | HMAC before parse, before any write | Signature test matrix |

Why these are invariants rather than objectives: each corresponds to money moving wrongly or a regulatory breach. "99.9% of debits respect the cooling window" is not a weaker version of compliance — it is non-compliance with extra steps.

---

## Objectives

Measured at the edge over a rolling 28-day window.

| Objective | Target | Budget | Why this number |
|---|---|---|---|
| Webhook ingest availability | 99.9% non-5xx | 43 min/month | Razorpay retries, so brief unavailability defers rather than loses. Chasing more here buys little |
| Webhook ingest latency, p99 | < 25 ms | 1% over | The sender has a timeout. Slow acceptance causes redelivery, which multiplies load exactly when it is already high |
| Signature verification, p99 | < 2 ms | 1% over | On the hot path for every request; a regression here is usually an accidental allocation |
| Outbox drain lag, p95 | < 5 s | 5% over | The gap between durable and actionable. Above this, in-session healing misses the window entirely |
| End-to-end heal, p95 | < 3 s from webhook to SSE frame | 5% over | The customer is still on the page for a handful of seconds. Beyond that the session is gone and healing is pointless |
| Recovery decision correctness | ≥ 95% of ambiguous incidents diagnosed by `LIVE` or `REPLAY` | 5% | Falling to `HEURISTIC` is a real quality drop, not a neutral fallback |
| Dead-letter rate | < 0.1% of incidents | — | Above this the DLQ has stopped being an exception path |

### Deliberately not an objective

**Recovery rate.** It depends on issuer behaviour we do not control, and targeting it creates pressure to retry more aggressively — which trades a metric against the compliance invariants. Net recovered value is *reported* and *optimised*, never committed to as an SLO.

---

## What the error budget governs

| Budget remaining | Posture |
|---|---|
| > 50% | Ship normally |
| 10–50% | Reliability work takes priority over features |
| < 10% | Changes limited to reliability fixes and security patches |
| Any invariant breached | Full stop, incident review, root cause before any deploy |

---

## Measurement

All figures come from in-process metrics on `/api/v1/ops/metrics`, not from logs. Latency uses fixed exponential buckets, so percentiles are bucket-bounded estimates — accurate enough to detect regressions, and honest about it rather than implying precision the histogram cannot give.

Capacity figures backing these targets are measured, not assumed. See [CAPACITY.md](CAPACITY.md).

# Architecture

ResilientMesh is a failure-domain service. It sits downstream of routing and fraud decisioning and activates only when a payment has already failed: it heals the live checkout session where one is still open, and orchestrates compliant recovery where one is not.

---

## 1. Where this sits

```
        customer
           |
     checkout session
           |
   [ routing / optimiser ]      <- picks the best rail before dispatch
           |
   [ acquiring bank / issuer ]  <- the thing that degrades
           |
      payment.failed
           |
   >>> ResilientMesh <<<        <- the failure domain
```

Upstream systems optimise the *first* attempt. ResilientMesh owns what happens after partner infrastructure degrades despite optimal routing. That separation is the whole design: it never re-decides routing, it reacts to failure.

---

## 2. Two recovery vectors

**In-session protocol healing.** A soft failure arrives while the customer is still on the checkout page. Correlating the error against rolling issuer telemetry and live downtime notices, the system morphs the active session onto a healthy rail over Server-Sent Events. No session teardown, no out-of-band message, no drop-off.

**Mandate lifecycle sentry.** A recurring debit fails and there is no session to heal. Recovery becomes a scheduling problem under hard regulatory constraints: a 24-hour cooling window, a pre-debit notification obligation, and a per-cycle attempt cap. These are enforced deterministically, never inferred.

---

## 3. Component map

```
                        HTTP edge (Go)
  ┌──────────────────────────────────────────────────────────┐
  │  POST /api/v1/webhooks/razorpay                          │
  │    1MiB cap → HMAC-SHA256 (constant time) → parse        │
  │    → replay guard (event_id UNIQUE) → terminal filter    │
  │    → ONE transaction: incidents + outbox_events + audit   │
  ├──────────────────────────────────────────────────────────┤
  │  GET  /api/v1/session/stream/{session_id}   (SSE, token) │
  │  GET  /api/v1/ops/*                         (token)      │
  └───────────────┬──────────────────────────────────────────┘
                  │
          PostgreSQL (durable truth)
       incidents · outbox_events · mandates
       attempts · sessions · audit_ledger
                  │
          outbox relay  (FOR UPDATE SKIP LOCKED)
                  │
          Redis Streams  ──►  dead-letter stream
                  │
        ┌─────────┴──────────┐
        │   worker pool      │
        │                    │
        │  breaker check ────┼─► open? skip inference, straight to backoff
        │  build context     │
        │  DIAGNOSE  ────────┼─► live → replay → heuristic   (advisory)
        │  GATEKEEPER ───────┼─► 12 deterministic invariants (authoritative)
        │  execute           │
        │  record + audit    │
        └────────────────────┘
                  │
        ┌─────────┴──────────┐
        │  SSE hub → browser │   rail morph, live
        └────────────────────┘
```

---

## 4. The trust boundary

This is the part that matters most.

```
  DiagnosticContext  ─►  model  ─►  DiagnosticProposal  ─►  Gatekeeper  ─►  SanitizedCommand
   (allowlist,                        (advisory,                             (authoritative,
    bucketed,                          no authority)                          executed)
    no PII)
```

| Question | Nature | Owner |
|---|---|---|
| Does `gateway_technical_error` mean transient degradation or planned maintenance? | genuinely underdetermined | model |
| Which rail is healthiest right now? | arithmetic over telemetry | policy engine |
| What is the amount? | a fact | HMAC-verified payload |
| Has 24 hours elapsed since the last mandate debit? | a fact | database timestamp |
| Is this the fourth attempt? | a fact | durable counter |

The model classifies. It never computes money, never decides compliance, never chooses an action outside a closed set. `DiagnosticProposal` has no amount field at all, an absent field cannot be wrong, whereas a validated one can still be wrong within its range.

### The twelve invariants

Applied in order, each recording its name on the command when it fires:

1. `AMOUNT_PINNED`, amount and currency copied from the verified payload. Always.
2. `TERMINAL_DECLINE`, unrecoverable issuer response → abstain.
3. `STOP_RULE_MAX_ATTEMPTS`, attempt cap exceeded → abstain.
4. `LOW_CONFIDENCE_ABSTAIN`, below the confidence floor → abstain.
5. `UNRECOVERABLE_CLASS`, class not worth a retry → abstain.
6. `SESSION_REQUIRED_FOR_MORPH`, no live session → downgrade to async retry.
7. `RAIL_ALLOWLIST`, target rail must be enabled, healthy, and different from the failing one.
8. `RBI_MANDATE_COOLING`, recurring: delay forced to ≥ 24 h, action becomes a mandate cascade.
9. `RBI_PRE_DEBIT_NOTICE`, recurring: notification required before any debit in this cycle.
10. `MANDATE_HALTED`, halted mandate → abstain.
11. `MANDATE_CYCLE_CAP`, per-cycle attempts exhausted → abstain and halt.
12. `DELAY_BOUNDS`, final delay clamped into range.

The gatekeeper is pure: same input, same command, always. It is verified by property tests over 20,000 randomised adversarial inputs, including deliberately malformed model responses.

---

## 5. Why the outbox exists

Writing to the database and then publishing to a queue is two operations with no shared atomicity:

```
  BEGIN; INSERT incident; COMMIT;
  ─── crash / timeout / partition here ───
  redis.XADD(...)                          ← never happens
```

The incident exists and will never be processed. No error handling closes this, because the failure can occur after the commit and before the process regains control. So the queue write moves *inside* the transaction:

```
  BEGIN;
    INSERT INTO incidents      ...
    INSERT INTO outbox_events  ...
    INSERT INTO audit_ledger   ...
  COMMIT;                                  ← all or nothing
```

A relay drains `outbox_events` into Redis using `SELECT ... FOR UPDATE SKIP LOCKED`, so multiple relays run concurrently without double dispatch. Delivery is at-least-once, which is why consumers are idempotent (`event_id` is `UNIQUE`).

**The operational consequence:** if Redis is down, the API keeps returning 200 and rows accumulate in the outbox. When Redis returns, everything drains. Nothing is lost.

---

## 6. Audit as evidence, not decoration

Every consequential decision appends an entry that commits to its predecessor's hash. Any edit, deletion, or reordering breaks the chain from that point forward, and `meshctl audit verify` names the first broken sequence number.

Two details carry the weight:

- **Length-prefixed absorption.** Fields are hashed with explicit length prefixes, not concatenated. Concatenation would let anyone controlling two adjacent fields shift the boundary between them and forge a colliding entry.
- **Serialised allocation.** Sequence and previous-hash assignment happen under a PostgreSQL advisory lock inside the transaction. Concurrent appends without it produce a silently corrupt chain.

---

## 7. Degradation behaviour

| Failure | Behaviour |
|---|---|
| Redis unavailable | API keeps accepting; outbox buffers; drains on recovery |
| PostgreSQL unavailable | Edge returns 503, accepting a payment event it cannot durably record would lose it |
| Inference provider unavailable | Falls to replay, then to the audit-flagged heuristic; tier is recorded on every incident |
| Issuer in a confirmed outage | Breaker opens; incidents skip inference entirely and route straight to backoff |
| Outbox depth above high-water mark | Edge sheds load with 503 + `Retry-After` rather than accepting undrainable work |
| Worker dies mid-message | `XAUTOCLAIM` reclaims it; idempotency makes reprocessing safe |
| Message poisons a worker | Panic recovered, audited, routed to the dead-letter stream |
| Slow SSE client | That subscriber's frame is dropped; the publisher never blocks |

---

## 8. Runtime modes

| Mode | Postgres | Redis | Purpose |
|---|---|---|---|
| `managed` (default) | embedded binary, real PG 18.3 | in-process RESP server | one command, no Docker, no installs |
| `external` | your DSN | your address | Compose, or real infrastructure |

Both modes hand the same DSNs to the same `pgx` and `go-redis` clients. There is exactly one code path, no behaviour exists only in demo mode.


---

## 9. The learning layer

Everything above is deliberately fixed. The gatekeeper applies the same invariants forever,
the policy engine computes the same backoff from the same inputs, and that rigidity is what
makes the audit trail worth reading. This section is the one place where behaviour changes in
response to what happened, and it is contained accordingly.

```
tuner    the delay vocabulary, and which of those delays the gate has already permitted
bandit   a Beta posterior per (context cell, delay); the propensity is exact, not estimated
reward   a cross-fitted logistic model of whether an attempt recovers
ope      IPS, SNIPS and doubly-robust estimators with a bias-corrected bootstrap
calib    expected calibration error, isotonic repair, and the noise floor beneath both
mill     a proposer that suggests segments; the estimator decides whether they are real
lab      a world whose answer is known, so the estimator itself can be scored
```

### Where it sits in the request path

The learner sits between the advisory proposal and the gate, and it can only make the system
more patient:

```
DiagnosticProposal  ->  tuner.Choose  ->  Gatekeeper.Decide  ->  SanitizedCommand
                          |                                          |
                          |  arms at or above policy.BackoffCeiling  |
                          |                                          v
                          +--------->  POLICY_DECISION  ------>  the ledger
                                       (propensity, before the attempt runs)
```

`policy.BackoffCeiling` is deterministic and exported, and the gate draws its own delay from
below it, so every arm the learner is offered is one the gate will honour exactly. An arm the
gate then raised anyway, which happens when a later invariant such as the RBI cooling window
applies, is recorded with `honoured: false` and excluded from evaluation. A propensity
recorded for an action that was not taken corrupts every estimate made from that log
afterwards, so the flag is load-bearing rather than diagnostic.

### Why the propensity is in the ledger

Off-policy evaluation needs the probability the deployed policy assigned to the action it
chose. If that number can be produced after the outcomes are known, it can be adjusted until
the answer flatters whoever is presenting it, and nothing in the resulting figures reveals
that it was. Writing it as a `POLICY_DECISION` entry before the attempt runs, in a chain that
fixes the ordering, is what makes a counterfactual claim checkable rather than merely stated.

### Why the learner reads the ledger back

An arm is chosen on the pass that schedules a retry; the outcome arrives on a later
redelivery, possibly hours afterwards and certainly in a different process invocation.
Rather than carry the choice in memory, where a restart loses it, the worker reads it back
out of the entry that already had to be written. The record is the source of truth for what
was decided, so the learner and an auditor are looking at the same row.

### Turning the learner off

`MESH_EXPLORE_FLOOR=0` disables it entirely and restores the purely deterministic schedule.
That is the state to fall back to if the learning layer is ever in doubt, and it is why the
floor is a configuration value rather than a constant.

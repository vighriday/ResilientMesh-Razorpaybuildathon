# Architecture Decision Log

Every entry records a decision that was not obvious, the alternatives that were rejected, and the consequence we accepted. Entries are append-only; a reversal is a new entry, not an edit.

---

## ADR-001, Go for the edge, Python only for evaluation

**Decision.** Webhook ingestion, HMAC verification, the SSE multiplexer, the outbox relay, and the worker pool are Go. Chaos injection, the NRCV benchmark, and the analytical dashboard are Python.

**Why.** The edge is CPU-bound cryptography plus tens of thousands of idle-but-open connections. A goroutine costs ~2 KB of initial stack and the runtime multiplexes them onto epoll/IOCP; a Python thread costs ~8 MB and contends on the GIL for the HMAC work. This is the same reasoning that moved Razorpay's UPI switch and EDGE gateway to Go.

**Rejected.** All-Python (fails at connection scale), all-Go (loses NumPy/pandas/plotly for the statistical work, where Python is genuinely better).

**Consequence.** Two toolchains. Mitigated by making the two share one cost model file (`eval/costs.json`) so the economics can never drift between the running system and the benchmark that measures it.

---

## ADR-002, pgx over GORM

**Decision.** `jackc/pgx/v5` directly, with hand-written SQL.

**Why.** The outbox relay depends on `SELECT ... FOR UPDATE SKIP LOCKED`, and the audit ledger depends on `pg_advisory_xact_lock`. Both are the load-bearing correctness primitives of this system, and both are exactly what an ORM abstracts away or emits unpredictably. When the critical path is a specific locking behaviour, hiding the SQL is a liability. pgx is also materially faster and has no reflection in the hot path.

**Rejected.** GORM (obscures locking, reflection overhead), `database/sql` + lib/pq (unmaintained, no native protocol features).

**Consequence.** More SQL to write and test. Paid back by a store conformance suite that runs against a real PostgreSQL.

---

## ADR-003, `log/slog` over zap, behind a redacting handler

**Decision.** Standard library structured logging, wrapped in a handler that redacts secret-shaped keys and truncates oversized values.

**Why.** The requirement is not "fast logging", it is "a payment system must not be able to log a webhook signature, an API key, a VPA, or a card reference, even by accident, even in a future call site nobody reviews". That is a property of the handler, not of the call sites, so it belongs in the logging layer. slog supports this cleanly and removes a dependency from a security-sensitive path.

**Rejected.** zap (an extra dependency in the security path for throughput we do not need at this volume), plain `log` (unstructured, unfilterable).

**Consequence.** Redaction must handle `WithAttrs` and `WithGroup` correctly, which is the part implementations usually get wrong. Explicitly tested.

---

## ADR-004, Transactional outbox, not a try/catch dual write

**Decision.** The webhook handler writes the incident row and the outbox row inside one PostgreSQL transaction. A separate relay drains the outbox into the Redis stream with at-least-once delivery.

**Why.** Writing to the database and then publishing to a queue is two operations with no shared atomicity. A crash, a timeout, or a network partition between them silently produces an event that exists but will never be processed. No amount of error handling in the application closes that window, because the failure can occur after the commit and before the process regains control. Moving the queue write into the transaction removes the window entirely.

**Rejected.** Try/catch around both calls (does not survive process death); 2PC (operationally unjustifiable here); change-data-capture (correct, but requires infrastructure a reviewer cannot run in one command).

**Consequence.** At-least-once delivery, so every consumer must be idempotent. Accepted deliberately, see ADR-005.

---

## ADR-005, `X-Razorpay-Event-Id` as the idempotency key, enforced by a UNIQUE index

**Decision.** The event id is stored `UNIQUE` on `incidents`. A duplicate delivery returns `200 {"status":"duplicate_ignored"}` and creates no new outbox row.

**Why.** Razorpay retries webhooks, and our own outbox is at-least-once. Deduplicating in application code is a check-then-act race under concurrency: two workers both read "not present" and both insert. A unique constraint makes the database the serialisation point, which is the only component that can arbitrate correctly. Returning 200 rather than 409 is deliberate, a duplicate is a successfully-handled delivery from the sender's point of view, and a non-2xx would cause the sender to retry a message we have already processed.

**Consequence.** The insert path must distinguish a unique-violation from a real error. Tested.

---

## ADR-006, The model proposes; the gatekeeper disposes

**Decision.** Inference emits a `DiagnosticProposal` with no authority. A deterministic gatekeeper converts it into a `SanitizedCommand`, recomputing every money-bearing and compliance-bearing field from the HMAC-verified payload and durable state.

**Why.** The correct division is not "AI vs rules", it is *which questions are genuinely probabilistic*. "Does `gateway_technical_error` mean a transient switch degradation or a planned maintenance window?" is genuinely underdetermined from the code alone and benefits from correlating ambient telemetry, that is a judgement call. "Is this amount ₹4,999?" and "has 24 hours elapsed since the last mandate debit?" are not judgement calls; they are facts with exactly one correct answer, and routing them through a probabilistic system can only introduce error. So the amount is pinned from the signed payload and the cooling window is computed from a timestamp, while the causal classification is inferred.

**Consequence.** The gatekeeper may override the model entirely; `OverrodeProposal` records when it did, which makes disagreement measurable rather than invisible.

---

## ADR-007, Amount is never sourced from a model response

**Decision.** `SanitizedCommand.ImmutableAmountPaisa` is copied from `PaymentEntity.Amount`, which came from bytes that passed HMAC verification. The proposal has no amount field at all.

**Why.** Removing the field is stronger than validating it. A validated field can still be wrong within its valid range; an absent field cannot be wrong. This makes "the model inflated a charge" structurally impossible rather than defended against.

**Consequence.** Enforced by a property test over 20,000 adversarial inputs, including hostile model outputs.

---

## ADR-008, Money is integer paisa; floats are banned from the money path

**Decision.** All monetary values are `int64` paisa. Probabilities entering money math are converted to integer basis points first.

**Why.** IEEE-754 binary floating point cannot represent 0.1 exactly. Accumulating float rupees across a 500-incident batch produces a total that fails to reconcile, and a reconciliation mismatch in a payment system is not a rounding nit, it is the whole problem the system exists to avoid. Integer paisa with explicit truncation is exactly representable and reproducible.

**Consequence.** Rounding direction must be chosen explicitly (we truncate, which under-claims recovery rather than over-claims it, the conservative direction for a metric we are asking a reviewer to trust).

---

## ADR-009, Four-tier inference stack: Live → Replay → Heuristic, with provenance recorded

**Decision.** Diagnosis attempts a live model, falls back to a deterministic cassette replay keyed by a bucketed context digest, then to an audit-flagged heuristic classifier. Every proposal records which tier produced it.

**Why.** Three requirements collide: the demo should show real inference; the benchmark must be reproducible to the rupee; and a reviewer must be able to run everything offline with no account and no spend. One tier cannot satisfy all three. Recording the tier on every incident is what keeps this honest, a benchmark cannot silently substitute the heuristic for the model and claim the model's result.

**Rejected.** Live-only (unreproducible, requires a key, fails offline); heuristic-only (the static-rules baseline we are trying to beat, so shipping it as the product would be self-defeating).

**Consequence.** Cassette coverage is finite. A miss is a visible fallthrough with `Degraded: true`, never a silent substitution.

---

## ADR-010, Cassette digest is computed over a bucketed projection, not raw context

**Decision.** `ContextDigest` hashes error code, method, issuer key, amount *band*, recurring flag, session-active flag, attempt number, telemetry bucketed to the nearest 10%, and downtime presence/severity/match. Free text is excluded.

**Why.** Hashing the raw context gives a distinct key per incident, so the corpus never hits and replay is useless. Bucketing collapses the state space to the dimensions that actually change the decision, which makes a few hundred cassettes cover the space. Excluding free text also keeps attacker-influenced strings out of the cache key, so a hostile `error_reason` cannot be used to force cache misses and drive traffic to the live tier.

**Consequence.** Two incidents differing only in narrative detail share a diagnosis. That is correct: they *are* the same situation.

---

## ADR-011, Session streams are authenticated by an opaque token, not addressed by order id

**Decision.** The SSE endpoint is `/api/v1/session/stream/{session_id}` and requires a bearer session token. Only the token's SHA-256 hash is stored. Comparison is constant-time.

**Why.** An endpoint keyed on `order_id` is an insecure direct object reference: order identifiers are semi-predictable, appear in URLs, emails, and client-side code, and are shared with the customer. Anyone who learns one could attach to another merchant's live checkout stream and observe payment state and rail changes in real time. Storing only the hash means a database read cannot be replayed against the endpoint. Constant-time comparison prevents recovering a valid token byte-by-byte from timing.

**Consequence.** The checkout client must carry a token issued at session creation. The token also appears as a `?token=` query parameter because the browser `EventSource` API cannot set headers, accepted as a bounded risk given the token is single-purpose, short-lived, and hashed at rest.

---

## ADR-012, Prompt inputs are allowlisted by struct, and untrusted text is fenced as data

**Decision.** Only fields declared on `DiagnosticContext` can reach the model. Attacker-influenced strings are control-character stripped, capped at 200 characters, and embedded inside an explicitly delimited data block that the system prompt declares is never instruction.

**Why.** `error_reason` originates upstream and passes through systems we do not control, so it is untrusted input. Defence is layered: the allowlist means cardholder data and raw payloads are structurally incapable of reaching a prompt; the fencing reduces injection success; and the gatekeeper means a *successful* injection still cannot move money, because the compromised field has no authority over amount, compliance, or the action set. The third layer is the one that actually matters, the first two reduce probability, only the third bounds impact.

**Consequence.** An explicit adversarial test asserts a command stays safe when the model is fully compromised.

---

## ADR-013, Circuit breaker per issuer, opening *before* inference

**Decision.** When an issuer's rolling success rate falls below threshold with sufficient samples, the breaker opens and subsequent incidents for that issuer bypass inference entirely, routing straight to backoff.

**Why.** An outage is exactly when incident volume spikes and inference is least useful, the cause is already known. Diagnosing 4,000 identical failures individually spends latency and money to rediscover one fact. Bypassing inference during a confirmed outage is both cheaper and *more* correct.

**Consequence.** Breaker state lives in Redis so every worker agrees; half-open probe budget is decremented atomically via a Lua script, because a non-atomic read-modify-write lets a thundering herd through at exactly the wrong moment.

---

## ADR-014, Hash-chained, tamper-evident audit ledger

**Decision.** Every consequential decision appends an entry committing to its predecessor's hash. `meshctl audit verify` walks the chain and reports the first break by sequence number.

**Why.** The track asks for an audit trail. A table of rows is a log; a log that cannot detect its own modification is not evidence. Chaining makes any edit, deletion, or reordering detectable, and exposing verification as a command turns the claim into something a reviewer can check in ten seconds rather than take on faith.

**Implementation detail that matters.** Fields are absorbed into the hash length-prefixed rather than concatenated. Naive concatenation lets anyone controlling two adjacent fields shift the boundary between them and forge a colliding entry.

**Consequence.** Sequence and previous-hash allocation must be serialised; concurrent appends are guarded by a PostgreSQL advisory lock inside the transaction. Without it, concurrent writers silently produce a corrupt chain.

---

## ADR-015, Managed runtime: real PostgreSQL and real RESP, no Docker

**Decision.** `go run ./cmd/mesh` boots an embedded PostgreSQL binary and an in-process RESP server, handing the same DSNs the external mode uses. Docker Compose ships but is optional.

**Why.** The reviewer's first command is the highest-risk moment in the whole submission. Every prerequisite is a chance for it to fail on someone else's machine. Requiring only the Go toolchain removes Docker, Postgres, and Redis installs from that path. Critically this is *not* an in-memory fake: it is PostgreSQL 18.3 speaking the real wire protocol and a real RESP server, so there is exactly one code path, `pgx` and `go-redis`, and no behaviour that only exists in demo mode.

**Rejected.** SQLite + in-memory queue (two SQL dialects, two code paths, and the divergence would land precisely on the locking semantics the design depends on).

**Consequence.** First run downloads a PostgreSQL binary once and caches it. Documented, and pre-warmed by the judge harness before anything is timed.

---

## ADR-016, Benchmark reports confidence intervals, not a point estimate

**Decision.** The 500-incident comparison reports NRCV per policy with a paired bootstrap 95% confidence interval and a paired significance test against the baselines.

**Why.** "We recovered ₹1.48M versus ₹740K" from one simulated batch is a single sample from a stochastic process. Without a dispersion estimate there is no way to distinguish a real effect from a favourable seed, and the honest response to an unqualified number is scepticism. Pairing matters because all three policies are evaluated on the *same* incidents, so the paired difference has far lower variance than comparing independent runs.

**Consequence.** The benchmark is slower and the headline number gains an interval. Both are the point.

---

## ADR-017, Private material is quarantined outside the tracked tree

**Decision.** Strategy notes, planning documents, and the source brief live under `_internal/`, which is git-ignored. A `leakscan` script fails the build if a tracked file matches secret patterns or references internal paths, and it runs in CI.

**Why.** A public repository is the deliverable. Anything published is published permanently, and secret material or internal planning in a payments repository is both an embarrassment and, for real credentials, an incident. A `.gitignore` alone is a convention; a scanner that fails the build is a control.

**Consequence.** Internal documents are not available to readers of the repository. Intentional.

---

## ADR-018, the learner may only make the system more patient

**Decision.** The Thompson sampler chooses a retry delay from the arms at or above
`policy.BackoffCeiling`, and never below it. The gatekeeper is not modified to accommodate it.

**Why.** The gate already honours a proposed delay longer than its own and discards a shorter
one, because only the aggressive direction spends money and trips issuer abuse heuristics.
That asymmetry was written for a language model and it happens to be exactly the boundary a
learner needs, so exploration is bounded by a property already checked over 510,720 reachable
states rather than by a new mechanism nobody has verified.

**Rejected.** Giving the learner the full action space and clamping afterwards. The clamp
would be invisible in the log: the system would record having chosen an arm it did not take,
and every off-policy estimate made from that log afterwards would rest on a propensity for an
action that never happened.

**Consequence.** A recurring debit inside the RBI cooling window has one arm and a terminal
decline has none, so there are incidents on which the learner contributes nothing. That is the
correct outcome and it is measured: `learn validate` reports how many incidents each arm was
available on.

---

## ADR-019, the exploration floor is a cost we pay on purpose

**Decision.** The action distribution keeps a floor of probability, two percent by default, on
every permitted arm, configurable through `MESH_EXPLORE_FLOOR` and disabled at zero.

**Why.** A policy that collapses onto its current best action produces a log with no
information about anything else. Tomorrow's candidate policy is then unmeasurable and has to
be tested on live customers to be evaluated at all. The floor buys the ability to answer
questions that have not been asked yet, and it is the only line item in this system whose
benefit is entirely in the future.

**Rejected.** Decaying the floor to zero as confidence grows. It is the standard move and it
optimises for a world that stops changing. An issuer that moves its settlement window makes a
converged policy wrong, and a converged log cannot detect that it has become wrong.

**Consequence.** A few percent of recoveries are spent on actions the model does not currently
favour. `learn validate` prints the exploration rate so the cost is visible rather than
implied.

---

## ADR-020, the propensity goes in the ledger, not in a metrics store

**Decision.** Each scheduling decision is written as a `POLICY_DECISION` audit entry carrying
the probability the chosen arm was drawn with, before the attempt runs.

**Why.** Off-policy evaluation is only trustworthy if the propensities were fixed before the
outcomes were known. A propensity in a metrics store can be recomputed, backfilled or
corrected, and none of those leave a trace. In a hash chain the ordering is fixed and an edit
invalidates every entry after it, so the claim that these probabilities were not chosen to
suit the answer becomes checkable by someone who does not trust us.

**Rejected.** A separate propensity table. Cheaper to query and worth nothing to a sceptic.

**Consequence.** The ledger grows by one entry per scheduled retry, and the worker reads the
chain back to learn from an outcome that arrives hours later. That read is the same row an
auditor would look at, which is a property worth having rather than an inconvenience.

---

## ADR-021, the model proposes segments; it never decides whether they are real

**Decision.** `internal/mill` sends aggregate statistics to a language model and accepts a
typed hypothesis from a closed grammar. Whether the hypothesis is true is decided by an
off-policy estimator against data the model did not influence, at a confidence widened for the
number of hypotheses in the round.

**Why.** Reading a large boring log and noticing that one slice behaves differently is the
thing language models are genuinely good at and that no other component here can do. Deciding
whether a difference is real is the thing they are worst at, because a confident assertion and
a correct one are indistinguishable in their output.

**Rejected.** Letting the model rank or score its own proposals. That is the failure mode that
makes language models unusable for analysis, and it would have made the whole loop a
sophisticated way of agreeing with a model.

**Consequence.** Most proposals are refuted, and the refutations are published. A round that
found nothing is a legitimate outcome rather than a failure to report.

---

## ADR-022, family-wise error control, not per-test confidence

**Decision.** A discovery round testing k hypotheses computes every interval at 1 - alpha/k
rather than at 1 - alpha.

**Why.** Eight tests at 95 percent produce a false discovery roughly every other round. A
system running nightly would accumulate a recovery policy made of noise inside a month, and
every individual step would have looked statistically respectable. Bonferroni is conservative
and assumption-free, and correlation between the tests can only make it more conservative
rather than less.

**Rejected.** Benjamini-Hochberg, which is less conservative and controls the false discovery
rate rather than the family-wise error rate. Controlling the expected proportion of false
survivors is the right choice when hundreds of hypotheses are screened and a few false
positives are acceptable. Here a false survivor becomes a change to how real payments are
retried, so the stricter guarantee is worth the sensitivity.

**Consequence.** Testing more hypotheses makes each one harder to confirm, so a proposer that
sprays guesses is actively worse than one that does not. The proposal budget defaults to eight.

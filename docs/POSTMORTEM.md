# Post-mortem: what broke, and what was done about it

Every entry here is a real defect in this codebase, found during this build.
None of them were found by reading the code. Each names the technique that
caught it, because the technique is the transferable part.

The last entry is **still open**. It is here for the same reason the others are.

---

## 1. Two gatekeeper defects that 20,000 property-test cases missed

**Found by:** exhaustive model checking (`cmd/modelcheck`).

`RBI_AFA_CEILING` was specified in the design and never implemented. A
registered mandate may debit without a fresh additional factor only up to
₹15,000, or ₹1,00,000 for insurance, mutual fund and credit card bill mandates.
Above that, a retry is not a suboptimal choice, it is a regulatory breach. The
gate would have retried it.

`EXECUTABLE_NAMES_A_RAIL` failed at **29,952 states**. The gatekeeper carried its
own local notion of which actions execute, that notion predated the
instrument-refresh action, so `DELAY_BOUNDS` cleared the rail the refresh rule
had just set and the gate emitted an executable command naming no rail, a
command that would have reached the gateway with nothing to present on.

**Why property testing missed both.** The property corpus never generated an
instrument refresh: the action was absent from its plausible distribution, the
stale-instrument failure class was absent from its class pool entirely, and the
two refreshable decline codes were still filed under "terminal" in the corpus.
No generated input could reach the code path. 20,000 draws of the wrong
distribution is 20,000 draws of nothing.

**Fixed by** deriving the local predicate from the domain type so the two cannot
disagree again, the class of bug rather than the instance, then repairing the
corpus. **58,512 violations → 0** across 510,720 reachable states.

**Lesson.** Property testing samples; model checking enumerates. Where a
property test can say only *"no counterexample in 20,000 draws"*, the model
checker says *"there is none"*. The corpus coverage assertion, which fails the
suite if any rule stops firing, is what stopped the repair from being vacuous
in turn.

---

## 2. Five fail-open defects in my own frozen contracts

**Found by:** the packages consuming them, during review of their call sites.

The worst: `DiagnosticProposal.Validate()` accepted `NaN` as a confidence score.
Every ordered comparison against `NaN` is false, so `conf < floor` waved it
straight through, and a `NaN` was read as *maximum* confidence by every
downstream check. A model returning `{"confidence_score": NaN}` would have had
its recommendation executed.

The fix is written as a positive assertion, `!(conf >= floor && conf <= 1)` ,
because the negative form *is* the bug.

The other four:

- `FailureClass.Recoverable()` defaulted to `true`, so a failure class added
  later would silently become retryable by omission.
- Provenance fields (`Mode`, `Model`, `LatencyMS`, `Degraded`) had live JSON
  tags, so a model could return `{"mode":"LIVE"}` and forge its own tier in the
  audit trail. They now carry `json:"-"`.
- `BreakerState` was an untyped string.
- `TelemetrySnapshot.Degraded()` was blind when `BaselineRate` was zero.

**Lesson.** "Frozen contracts" written by one person and reviewed by nobody are
not frozen, they are unexamined. Every one of these was found by asking what the
*consumer* would do with a hostile value, not by re-reading the definition.

---

## 3. Unicode case folding let a non-member into every closed set

**Found by:** writing an adversarial test suite for the domain package.

`strings.ToUpper` and `strings.ToLower` apply *Unicode* case mapping, not ASCII
case mapping. U+017F (the long s, ſ) uppercases to a plain ASCII `S`, and U+212A
(the Kelvin sign, K) lowercases to a plain ASCII `k`. Every parser that
normalised model output with them therefore admitted strings that are not
members of the set they guard:

```
ParseAction("AſYNC_EXPONENTIAL_RETRY")  -> ASYNC_EXPONENTIAL_RETRY, valid
ParseFailureClass("IſSUER_OUTAGE")      -> ISSUER_OUTAGE, recoverable
ParseRail("netbanKing")                 -> netbanking, valid
```

Three of those parsers sit directly on the model boundary in the gatekeeper. A
prompt-injected response could therefore smuggle a fabricated action past the
abstention the contract promises, and a fabricated failure class past
`RuleUnrecoverableClass`.

**Fixed by** ASCII-only `foldLower` and `foldUpper`, which map only `a-z` and
`A-Z` and leave every other byte alone. All five parsers now share them.

**Lesson.** A closed set is only closed if the function that decides membership
agrees with the alphabet the set was written in. The taxonomy is ASCII by
construction; the fold was not, and the gap between those two facts was the bug.
Case-insensitivity is a security boundary whenever it sits in front of an
allowlist.

---

## 4. The offline path recovered nothing

**Found by:** booting the whole system and looking at it.

Every unit test passed. Every component was individually correct. Running
`go run ./cmd/mesh` and reading the ops console showed **twelve incidents
diagnosed and one acted on**: the heuristic tier had no rule for the ambiguous or
soft decline codes, so with no API key configured the system abstained on exactly
the failures the taxonomy calls recoverable.

A reviewer with no API key, which is every reviewer, by design, would have
watched a recovery system recover nothing.

**Fixed by** giving the deterministic tier the codes whose cause the taxonomy
already states, which also produced the honest boundary the project now argues
for: rules where the cause is known, a model only where evidence must be
weighed.

**Lesson.** Unit tests cannot see a gap *between* components. The only thing that
finds "all the parts work and the system does nothing" is running the system.

---

## 5. Deferred recoveries were silently dropped

**Found by:** the same whole-system run, one layer deeper.

The worker marked a delayed command `SCHEDULED`, acknowledged the message and
returned. A comment claimed a scheduler would collect it when due. **There was no
scheduler.** Every deferred retry, which is most of them, since correct backoff
is minutes to hours, was lost.

This is the worst shape a bug can take here: the audit ledger recorded a
*correct decision that never happened*, and every report looked right.

Fixing it exposed a second defect immediately behind it. A swept incident
re-entered the pipeline, had a fresh backoff computed, and was deferred again. A
delay that is always recomputed is always in the future, so the incident looped
forever. **A delay is served once**; the redelivery now says so.

**Fixed by** a durable `scheduled_for` column on the incident, so a schedule
cannot survive a rollback that undid the decision that produced it, and cannot be
lost to a restart, plus a sweep loop that claims due rows with
`FOR UPDATE SKIP LOCKED` and re-publishes them, re-arming any it fails to publish
rather than stranding it.

With both closed, a 90-second run recovers 18 of 31 incidents end to end.

**Lesson.** A comment describing a component that does not exist reads exactly
like a comment describing one that does. `go run ./cmd/meshctl selftest` now
gates on a *completed recovery*, not on a decision, precisely because decisions
alone would pass with the scheduler deleted.

---

## 6. A retried write that double-counted real money

**Found by:** deterministic simulation (`cmd/meshsim`), `NO_DOUBLE_PROCESSING`.

The attempt-commit path is retried on purpose, losing the record of a debit is
worse than the debit. But the retried block was not idempotent: a failure
anywhere *after* `RecordAttempt` (telemetry, breaker, ledger, mandate update)
re-ran the whole block and inserted a **second row for the same attempt**.

The `attempts` table had an *index* on `(incident_id, attempt_number)` but no
uniqueness, so the production store had the same hole as the simulation. It
double-counts a gateway fee, inflates every recovery-rate measurement, and makes
the benchmark wrong in the direction that flatters the system.

**Fixed by** a unique constraint plus `ON CONFLICT DO NOTHING`, making
`RecordAttempt` genuinely idempotent, with the duplicate-collapsing migration
written to keep the earliest row, the one the rest of the system already
reacted to.

**Lesson.** "Retry until it commits" is only safe if the thing being retried is
idempotent, and the fault injector is what eventually fails the step *after* the
write. No unit test would have: each step is individually correct.

---

## 7. A transient broker outage permanently destroyed events

**Found by:** the same simulation run, `NO_EVENT_LOST`, while investigating #6.

Two compounding defects in the outbox relay:

1. `MarkOutboxFailed` sets `state = 'FAILED'`, and the relay called it on *every*
   publish failure. Since `ClaimOutboxBatch` only selects `PENDING` rows, the
   **first** failure parked a row permanently and the eight-attempt retry budget
   was unreachable.
2. The claim itself charged an attempt. A broker outage makes every claim fail
   for reasons that have nothing to do with any row, so the outage would have
   exhausted every budget in the table even if (1) were fixed.

The relay's own comment diagnosed this correctly, *"a publish failure is almost
always the queue being unavailable, not this particular row being bad"*, and
then the code did the opposite.

**Fixed by** splitting the two cases explicitly. After a publish failure the
relay probes the queue: if it answers, the row failed on its own merits and is
charged via `RecordOutboxFailure` (which keeps it `PENDING`); if it does not,
every row in the batch is handed back uncharged via `ReleaseOutboxClaim` and the
jittered backoff rides the outage out. Claims lease; they no longer charge.

**Lesson.** A comment that states the right principle is not an implementation of
it. Worth grepping your own codebase for comments that argue against the code
beneath them.

---

## 8. The demonstration poisoned its own next run

**Found by:** running it twice.

Act 5 of `cmd/meshdemo` deliberately forges a ledger row and does not repair it,
because the point is that the forgery is detectable. The managed PostgreSQL data
directory is reused across runs on purpose, because that is what turns a 23 s
cold start into a 2 s warm one.

Those two decisions are each correct and together they are a bug. The second run
inherited the first run's forgery and failed at boot:

```
  ✓ Chain intact: 80 entries verified, head 53a699ffd0b98d7a...
  ✗ the ledger was already broken at sequence 81
```

A reviewer running the command twice, which is the most ordinary thing a
reviewer does, would have seen the demonstration accuse itself of tampering.

**The fix that was rejected** was to repair the row after the act. A system with
a repair path for its own audit trail does not have an audit trail, and shipping
one to make a demo re-runnable would have destroyed the property the demo exists
to show.

**Fixed by** giving the demonstration its own data directory and emptying it at
the start of every run. That also makes a claim the README already made actually
true: the run is a pure function of its seed on the second run, not only on the
first. Previously a second run inherited the first run's incidents as well as
its forgery.

**Lesson.** State that survives between runs is a dependency between runs. The
bug was invisible to every test because tests get a fresh database, and
invisible on the first run because there was nothing to inherit yet. Running a
thing twice is a cheap test that almost nobody writes.

---

## 9. OPEN, the reconciler amplifies during an outage

**Status: unfixed. Reproducible. Left failing on purpose.**

```bash
go run ./cmd/meshsim --seed 20260904 --incidents 400
# invariant NO_EVENT_LOST violated: 20434 outbox rows exhausted their
# publish budget and were dead-lettered
```

The reconciler exists to recover incidents whose queue message the broker lost ,
without it, one dropped message is a payment never retried and never reported.
It treats an incident with no `PENDING` outbox row as stalled and inserts a
replacement.

A **parked** row is not `PENDING`. So during a broker outage: the relay parks a
row it could not publish, the incident then looks stalled, the reconciler inserts
a replacement, that one parks too. The count grows for as long as the outage
lasts, 20,434 parked rows from 400 incidents, and all of it is write
amplification aimed at a queue that is already down.

**Two fixes were attempted and both reverted:**

- Counting parked rows as "tracked" stops the amplification and **strands the
  incidents instead**, trading a loud failure for a silent one, which is the
  worse of the two.
- Bounding reconciliations per incident made the run stop draining entirely
  (0 published, truncated at the step budget) for reasons I did not fully
  characterise.

Neither is shipped. A verification harness edited until it agrees with the system
is not a harness, and a fix I cannot explain is not a fix.

**The real fix** is a per-incident reconciliation backoff, reconcile, but with
exponentially increasing delay and a distinct terminal state for "needs an
operator", so the loop is damped rather than either unbounded or severed. That
is the next piece of work.

**Impact on the rest of the system.** The production relay fix in #7 addresses the
first half of this interaction: real rows are no longer parked on first failure,
and a transport failure no longer charges a budget. The remaining amplification
is in the simulation's model of the reconciler, which production does not yet
have. The judge harness therefore runs the fault-free profile and names this
finding in the gate's own comment rather than hiding it.

**Lesson, provisionally.** The two components are individually reasonable. The
relay gives up on rows it cannot publish; the reconciler revives incidents
nothing is tracking. Together they form a loop neither author would have drawn.
That is what deterministic simulation is *for*, and it is why the finding is
worth more than a clean report would have been.

---

## What this list is

Eight fixed, one open, and none of them found by reading the code.

The techniques that found them, in order of how much they were worth:

| Technique | Found |
|---|---|
| Exhaustive model checking | #1, two defects a 20,000-case property suite could not reach |
| Deterministic simulation with fault injection | #6 and #7, both of which need a fault to land at one specific step |
| Booting the whole system and looking at it | #4 and #5, gaps *between* components that no unit test can see |
| Writing adversarial tests for a frozen contract | #2 and #3, hostile values the definition never considered |
| Running the same command twice | #8 |

The pattern across all of them is that the defect lived in the space between two
individually correct things: a relay that gives up and a reconciler that revives,
a taxonomy written in ASCII and a fold that is not, an act that forges a row and
a directory that persists. Reading either side alone would never have found it,
which is the argument for building the harnesses rather than the review
checklist.

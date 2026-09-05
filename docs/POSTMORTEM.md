# Post-mortem: what broke, and what was done about it

Every entry here is a real defect in this codebase, found during this build.
None of them were found by reading the code. Each names the technique that
caught it, because the technique is the transferable part.

Six of them are statistical, and they are the ones worth reading first. Every
one produced output that looked entirely reasonable: intervals of a plausible
width, estimates of a plausible size, a finding with a good mechanism behind it.
None would have been caught by a test that asserted the code does what the code
does. They were caught by building a world where the right answer is already
known and counting how often the machinery got it.

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

## 9. A conformance vector that made the gate look like it permitted a stolen card

**Found by:** running the vectors and reading the answers.

The browser gatekeeper ships with recorded inputs and the answers the server
binary gave them, so a reader can watch two builds of one package agree. One of
those vectors was written to show a terminal decline being refused, using
`error_code: "card_stolen"`. The gate permitted a retry.

That looked, for about a minute, like a serious defect: a system that would
spend a gateway fee retrying a card the issuer had reported stolen.

It was the fixture. The taxonomy's code is `card_lost_or_stolen`. An unknown
code is deliberately not treated as terminal, because inventing terminality for
strings nobody recognises is how a recovery system silently stops recovering.
The gate did the right thing with the input it was given, and the input was
wrong.

**Fixed by** using the real code, at which point the vector refuses as intended.

**Lesson.** The vectors earn their place twice over. They exist to prove the
WebAssembly build matches the server build, and the first thing they actually
caught was an error in my own understanding of the taxonomy. Worth noting that
the mistake was legible only because the expected answer is *recorded from a
real run* rather than asserted by hand: had I written "expect
PERMANENT_ABSTAIN", the suite would have gone red with no indication of which
side was wrong.

---

## 10. A flaky verification gate, which is worse than a failing one

**Found by:** running scripts/judge.sh twice.

The race-detector gate failed once and passed on a re-run. That is the worst
result a gate can give: a reviewer who hits it concludes the project is broken,
and a reviewer who does not never learns there is anything wrong. "Flaky, just
run it again" is not an answer when the whole submission argues that verification
should be trustworthy.

The cause was a genuine unsynchronised read in the simulator's test helper. The
webhook capture appends each delivery under a mutex, and the assertions then read
`cap.bodies[0]` and `cap.headers[1]` straight off the struct with no lock. The
deliveries are logically complete by then, which is why it passed in isolation
eight times running, but the handler goroutine that appended the last one has not
necessarily returned, so the read really is concurrent with a write and the race
detector was right.

**Fixed by** locked `body(i)` and `header(i)` accessors, with every direct index
in the package routed through them.

**Lesson.** A test helper is production code for the purposes of concurrency. The
failure mode here was entirely characteristic: passes alone, fails under load,
tempting to re-run. Chasing it was worth more than the defect itself, because an
intermittent gate quietly destroys the credibility of every gate beside it.

---

## 11. A lift estimator that self-normalised one side of a difference

**Found by** counting how often an interval contained a truth I could compute exactly.

Off-policy evaluation has a standard recommendation: prefer the self-normalised estimator to
the plain one, because it has far lower variance and cannot report a value outside the range
of rewards that actually occurred. That advice is correct for estimating a *level*, and I
applied it to a *difference* without thinking about whether it carried over.

It does not. The lift was computed as

```
SNIPS(target) - mean(observed rewards)
```

The first term divides the importance-weighted sum by the realised weight mass; the second
divides by n. The two halves are scaled differently, so the O(1/n) bias of the self-normalised
term no longer cancels against anything. On a candidate policy that changes one segment, that
residual is the same size as the effect being measured.

The symptom was an interval that looked entirely respectable and contained the truth about
three quarters of the time instead of nineteen times in twenty. Nothing about the output
suggested a problem. It was only visible by running the estimator against a world whose exact
answer is computable, several dozen times, and counting.

**The fix** is the mean of `(w - 1) * r`, which is unbiased under overlap and, for a candidate
that changes one segment and matches the deployed policy everywhere else, has a term of
exactly zero on every decision outside that segment.

**What I take from it.** Statistical advice comes attached to an estimand, and the estimand
changes when you subtract two things. The general lesson is narrower than "check your
statistics": it is that a variance-reduction technique which is a *ratio* stops composing the
moment you put it inside a *difference*.

---

## 12. A percentile bootstrap that put the interval in the wrong place

**Found by** the same coverage count, after fixing the estimator above.

Coverage improved and was still wrong. The interval was the 2.5th and 97.5th percentiles of
the bootstrap distribution, which is the textbook percentile interval and is correct
asymptotically.

Indian ticket sizes in this corpus span four orders of magnitude, from a fifty rupee top-up to
a fifty thousand rupee premium. A handful of large recoveries carry most of the signal in any
one segment, so the bootstrap distribution leans hard. A percentile interval is symmetric in
that distribution and takes no view on whether it is centred on the estimate, so the interval
is placed in the wrong *position* rather than merely being the wrong width. Coverage was near
one half at small segment sizes.

**The fix** is the bias-corrected and accelerated interval. It shifts the two percentiles by
two quantities read off the data: how much of the bootstrap distribution sits below the point
estimate, which measures median bias, and how quickly the variance changes as observations are
dropped, which measures skew. That second term needs a leave-one-out jackknife, which needed
an inverse normal CDF, neither of which the standard library has.

Both were affordable because every estimator in the package is a ratio of sums, so a
leave-one-out value costs a subtraction rather than a re-run.

**What I take from it.** "Correct asymptotically" is a statement about a limit, and a segment
of a few hundred decisions is not near it. The measurement that caught this is now a test.

---

## 13. Publishing a finding before measuring it across the range

**Found by** measuring properly after I had already written the conclusion down.

Doubly-robust estimation is the standard recommendation for reducing the variance of an
off-policy estimate. I ran it once, on a small corpus, and it was worse: wider intervals and
poorer coverage than the plain difference. I had an explanation ready and it was a good one.
A recovery reward is a rare large payout against a small fixed fee, so most attempts are worth
exactly minus one gateway charge, while the model residual is roughly the ticket size times a
prediction error on *every* decision including the cheap failures. Subtracting a baseline
converts a mostly-tiny quantity into a mostly-large one.

I wrote that up as a finding, in the package documentation, with a test pinning it.

Then I measured it across corpus sizes:

```
corpus   IPS coverage  IPS width   DR coverage  DR width   model skill
 6,000        70%         2021         85%        2094        0.028
20,000        80%         2067         90%        1659        0.058
40,000        95%         1441         95%        1132        0.066
```

Doubly-robust covers better at every size and is narrower once the model has enough data to
have any skill at all. The single run I generalised from was one where the reward model had a
skill of 0.028, so the residual it subtracted was almost pure noise. The estimator was fine;
the reasoning was fine as far as it went; the mistake was concluding from one point.

**The fix** is that doubly-robust is now the default whenever an outcome model is supplied,
the table above is in the package documentation, and a test regenerates it so the claim cannot
quietly stop being true.

**What I take from it.** A plausible mechanism is not evidence, and it is more dangerous than
no explanation at all, because a good story makes a single measurement feel like a
confirmation.

---

## 14. Reporting my own model as badly overconfident, on a label I invented

**Found by** reading my own output and not believing it.

The calibration command measured the inference tier as wildly overconfident: right 33 percent
of the time while claiming 74, an expected calibration error of 0.41 against a noise floor of
0.05. It was a striking number and it went straight into a draft.

The label was mine. I had picked the decline codes whose causal class looked fixed by the code
itself, and two of them are not. A `payment_timed_out` raised in the middle of a confirmed
issuer outage really is an issuer outage rather than a network timeout, and the recorded
proposals classify it that way about eighty percent of the time. `issuer_down` has the same
problem in the other direction, because the corpus deliberately varies the telemetry behind it.

I was scoring the model against a ground truth I had made up, and it was losing.

**The fix** is that the command measures nothing there and explains why. The recorded corpus
was assembled to exercise *ambiguous* failures, so it cannot supply the ground truth a
calibration study needs. The two remaining options were to invent a label or to score the
model against this system's own heuristic, and a measurement built on either is worth less
than the admission.

The command does calibrate the learned recovery model, where the outcome is observed and the
ground truth is not a matter of opinion, and it finds a real defect there.

**What I take from it.** The most dangerous number is the one that confirms something
unflattering, because scepticism runs out exactly when a result is interesting.

---

## 15. Scoring a proposal against the wrong baseline

**Found by** a hypothesis that was correct and came back confidently negative.

The discovery loop tests proposed segments by constructing the policy each one implies and
estimating its value. I built that policy as "the proposed action inside the segment, the fixed
backoff schedule everywhere else", and scored it against the log.

A hypothesis is a proposed *change to what is deployed*. Building it on the backoff schedule
made every candidate a wholesale policy replacement that also happened to contain the segment,
so the estimate measured the difference between two entirely different policies across the
whole corpus, and the segment was a rounding error inside it. The correct hypothesis about a
real 52-point effect came back at `[-20594, -5254]`.

**The fix** is that a nil base means the policy that produced the log, replayed. Outside the
segment the candidate and the log agree exactly, the importance weight is one, and the
estimator reads only the decisions the change actually touches.

**What I take from it.** An estimator answers the question it was asked. This one was answering
a question I had not meant to ask, and it was answering it correctly.

---

## 16. A null hypothesis test whose null was not null

**Found by** the test failing, and the failure being right.

The discovery loop widens every interval by the number of hypotheses under test, so I wanted
a test proving the correction does something: build a null where there is nothing to find, run
a round, and require it to find nothing.

The null I reached for was a permutation. Take a real log, shuffle the outcomes across its
entries, and the association between an action and its result is destroyed while the corpus,
the action distribution and every propensity stay exactly as they were. It is the standard
construction and it reads as obviously correct.

It admitted three false discoveries in four rounds.

The correction was fine. The null was not. The lift is the mean of `(w - 1) * r`, whose
expectation decomposes into the covariance of the weight with the reward plus
`(mean(w) - 1) * mean(r)`. Permuting removes the covariance, which is the intent, and leaves
the second term untouched. That term is a small finite-sample deviation of the mean weight
multiplied by a mean reward that is large, because a recovery is a rare payout of a whole
ticket. Worse, removing the covariance is exactly what the bootstrap was resampling, so the
interval narrows around a point estimate that did not move.

A permutation is only a null if the estimator is invariant to it, and this one is not.

**The fix** is a null that is actually null: a world generated with the planted effect
flattened, so the segment recovers at the same rate on every delay and nothing else changes.
A hypothesis naming it is then a claim about something that is not there, and it is refused.
Beside it sits the same claim against the same world with the effect present, so the test is
known to be capable of the other answer, and a third test asserting that the corrected
interval is strictly wider than the naive one.

**What I take from it.** A test that fails is evidence about something, and the something is
not always the code under test. I nearly weakened the correction to make this pass.

---

## 17. OPEN, the reconciler amplifies during an outage

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

Sixteen fixed, one open, and none of them found by reading the code.

The techniques that found them, in order of how much they were worth:

| Technique | Found |
|---|---|
| Exhaustive model checking | #1, two defects a 20,000-case property suite could not reach |
| Building a world with a known answer and counting | #11, #12 and #15, three defects in statistics that produced entirely reasonable-looking output |
| Deterministic simulation with fault injection | #6 and #7, both of which need a fault to land at one specific step |
| Booting the whole system and looking at it | #4 and #5, gaps *between* components that no unit test can see |
| Writing adversarial tests for a frozen contract | #2 and #3, hostile values the definition never considered |
| Measuring across a range instead of at a point | #13, a conclusion I had already written up |
| Disbelieving my own output | #14, an unflattering number produced by a label I invented |
| Running the same command twice | #8 |
| Recording expected answers instead of asserting them | #9 |
| Running the verification harness twice | #10 |
| Believing a failing test over the thing it was testing | #16, a null hypothesis that was not null |

The pattern across all of them is that the defect lived in the space between two
individually correct things: a relay that gives up and a reconciler that revives,
a taxonomy written in ASCII and a fold that is not, an act that forges a row and
a directory that persists. Reading either side alone would never have found it,
which is the argument for building the harnesses rather than the review
checklist.

<div align="center">

<img src="docs/img/space-hero.png" alt="ResilientMesh" width="820">

# ResilientMesh

**A failed payment is a decision, not a retry.**

The deterministic control plane that sits between a language model and a merchant's money.
The model may describe what it thinks went wrong. It may never decide what happens next,
never name an amount, and never move a rupee. Every action it takes, and every action it
refuses, comes out as a proof you can check without trusting the system that produced it.

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Model checked](https://img.shields.io/badge/model%20checked-510%2C720%20states%20·%200%20violations-0f7a52)](#proof-not-assertion)
[![Invariants](https://img.shields.io/badge/invariants-14%20deterministic-2b5cff)](#the-fourteen-invariants)
[![Direct dependencies](https://img.shields.io/badge/direct%20dependencies-6-7a8399)](#dependencies)

[![Open in Spaces](https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-lg.svg)](https://huggingface.co/spaces/hriday29/resilientmesh)

### Two ways to evaluate this

| | | |
|---|---|---|
| **Attack it** | **[huggingface.co/spaces/hriday29/resilientmesh](https://huggingface.co/spaces/hriday29/resilientmesh)** | The real gatekeeper, compiled to WebAssembly. Send it proposals no model would produce and watch fourteen invariants refuse them, **in your browser**, with no server involved. |
| **Verify it** | same page | Re-derives all 594 audit digests, then proves one payment on its own with 8 sibling hashes instead of the whole ledger. Both run on your machine. |
| **Run it** | `go run ./cmd/meshdemo` | The whole system, two minutes. No Docker, no account, no key. |

[Evaluation guide](docs/EVALUATING.md)
·
[Post-mortem](docs/POSTMORTEM.md)
·
[Live evidence page](https://huggingface.co/spaces/hriday29/resilientmesh)

</div>

---

## Run it in one command

Go 1.25 or newer is the only prerequisite. No Docker, no cloud account, no payment
credentials, no API key.

```bash
git clone https://github.com/vighriday/ResilientMesh-Razorpaybuildathon
cd ResilientMesh-Razorpaybuildathon
go run ./cmd/meshdemo
```

That starts embedded PostgreSQL 18.3 and a Redis-protocol server **inside the process**,
boots the real API and worker, drives a scripted bank outage through them, and narrates what
is happening while every number is read back out of the database. It finishes in about two
minutes and writes a transcript to `artifacts/DEMO_REPORT.md`.

<details>
<summary><b>What that run actually prints</b> (real output, trimmed)</summary>

```
  0. Booting the real system
  · Starting embedded PostgreSQL 18.3 and an in-process Redis server
  · Initialising an empty database, so this run depends on nothing before it
  ✓ Up in 28.8s. API on 127.0.0.1:8080, Razorpay API on 127.0.0.1:8081

  1. A bank goes down and failed payments start arriving
     PAYMENT             ISSUER           DECLINE                  AMOUNT        STATE
     pay_XD0nBPG9aT3YHf  netbanking:SBIN  authentication_failed    ₹6,829.00     ABSTAINED
     pay_nLuP6TRLhYUFTx  netbanking:HDFC  bank_technical_error     ₹3,494.00     RECOVERED
     pay_bDEHVc295COswR  card:ICIC        gateway_technical_error  ₹1,52,574.00  EXECUTING

  2. What the model proposes, and what the gatekeeper allows
       WEBHOOK_ACCEPTED     invalid_otp, ₹939.00, signature verified
       DIAGNOSIS_PROPOSED   LIVE proposed ASYNC_EXPONENTIAL_RETRY at 0.78
       GATE_DECISION        MANDATE_COMPLIANT_CASCADE on card after 86400s
                            [AMOUNT_PINNED RBI_MANDATE_COOLING RBI_PRE_DEBIT_NOTICE DELAY_BOUNDS]
  Decided by LIVE 13   HEURISTIC 118

  3. The decisions it refuses to make
     INVARIANT               TIMES FIRED  WHAT IT PREVENTS
     TERMINAL_DECLINE        12           a decline no retry can fix, so no fee is spent
     AMOUNT_PINNED           10           the amount can only come from the signed payload
     DELAY_BOUNDS            10           the schedule stays inside a sane horizon
     RBI_AFA_CEILING          3           above the ceiling a debit needs authentication
     RBI_MANDATE_COOLING      3           RBI's 24-hour gap between recurring debits
     RBI_PRE_DEBIT_NOTICE     3           the payer must be warned before a debit
     LOW_CONFIDENCE_ABSTAIN   1           the model was not sure enough to spend money

  5. The audit ledger, and an attack on it
  ✓ Chain intact: 538 entries verified, head e61cea979b8ca13d...
  · Editing entry 269 directly in PostgreSQL, as an attacker with database access would
  ✓ Detected at entry 269, the exact row that was edited
```

</details>

<div align="center">
<img src="docs/img/space-pipeline.png" alt="Payments flowing through the recovery pipeline and branching at the gatekeeper" width="900">
<br><em>The <a href="https://huggingface.co/spaces/hriday29/resilientmesh">evidence page</a> replays this run's own incidents through the real architecture. Each one branches at the gate the way it actually branched.</em>
</div>

---

## What is real, and what is simulated

Stated first, because a recovery system that overstates its own numbers has failed at the
thing it exists to do.

| Real | Simulated |
|---|---|
| **The system.** Embedded PostgreSQL, Redis Streams, the outbox relay, the worker, the gatekeeper and the executor are the production code paths, not a demo build. | **The payments.** Traffic comes from a Razorpay simulator that serves Razorpay's schemas, signs real HMAC webhooks and emits real decline codes against real Indian issuer codes. No customer, and no rupee, is real. |
| **Every decision**, and the rule that permitted or refused it. | **Therefore every money figure is simulated money.** It is summed honestly from the `attempts` table, and it measures the policy rather than a merchant's actual revenue. |
| **The audit ledger** and its SHA-256 hash chain. | **The clock.** Waits before a scheduled retry are compressed so the loop closes while you watch. Regulatory delays are never compressed, and the factor is recorded in the ledger. |
| **The LIVE inference calls**, over the network, at temperature 0. | |
| **Every count, amount and timestamp**, read from the running system's own database. | |

---

## Why this, and not a sixth recovery agent

Razorpay's Agent Studio already ships Subscription Recovery, Revenue Drop Detector,
Auto-Capture, RTO Shielder and Dispute Auto Responder. Building a seventh variation of those
would be building the part that is already solved.

The unsolved part is the one that stops any of them from being shipped to a regulated Indian
merchant:

> "Your agent retried my customer's mandate. Prove it was allowed to, prove it did not change
> the amount, and show me the record. The one that would still be trustworthy if someone had
> database access."

A log line and a model's rationale do not answer that. Both are written by the same system
that took the action, and an LLM's explanation is a post-hoc narration, not a cause.

**ResilientMesh is the layer that makes shipping the first five defensible**, demonstrated on
the hardest case: RBI-regulated recurring mandate recovery, where a wrong retry is not a bad
outcome but a regulatory breach.

---

## Architecture

```mermaid
flowchart TB
    subgraph edge["Outside world"]
        WH["Razorpay webhook<br/><i>payment.failed</i>"]
    end

    subgraph ingest["Ingest edge"]
        HMAC["HMAC verify<br/><i>before anything parses</i>"]
        TX["One PostgreSQL transaction:<br/>incident + outbox row + audit entry"]
    end

    subgraph transport["Asynchronous transport"]
        RELAY["Outbox relay<br/><i>probes the queue, backs off</i>"]
        STREAM["Redis Streams<br/><i>consumer group and DLQ</i>"]
        SWEEP["Due sweeper<br/><i>FOR UPDATE SKIP LOCKED</i>"]
    end

    subgraph decide["Decision"]
        CTX["DiagnosticContext<br/><i>allowlisted, bucketed, no PII</i>"]
        TIERS["LIVE, then REPLAY, then HEURISTIC"]
        PROP["DiagnosticProposal<br/><i>advisory, no amount field</i>"]
        GATE{{"Gatekeeper<br/>14 deterministic invariants"}}
        CMD["SanitizedCommand<br/><i>authoritative</i>"]
    end

    subgraph act["Effect"]
        EXEC["Executor<br/><i>the only thing that spends money</i>"]
        LEDGER[("Hash-chained ledger<br/><i>actions and refusals alike</i>")]
    end

    WH --> HMAC --> TX
    TX --> RELAY --> STREAM --> CTX
    TX -. deferred .-> SWEEP -. due .-> STREAM
    CTX --> TIERS --> PROP --> GATE
    GATE -->|permitted| CMD --> EXEC
    GATE -->|refused, with the rule named| LEDGER
    EXEC --> LEDGER
    EXEC -. retry with budget .-> SWEEP

    style GATE fill:#e3f5ed,stroke:#0f7a52,stroke-width:2px
    style PROP stroke-dasharray: 5 5
    style LEDGER fill:#eaefff,stroke:#2b5cff,stroke-width:2px
```

### The trust boundary

It is structural, not procedural. It is enforced by **which fields exist on which type**, so
it cannot be forgotten at a call site.

```mermaid
flowchart LR
    A["<b>DiagnosticContext</b><br/>sent to the model<br/><br/>success rate as '0 to 20 percent'<br/>never a number<br/>no PII, no customer id<br/>no exact amount"]
    B["<b>DiagnosticProposal</b><br/>returned by the model<br/><br/>failure_class<br/>recommended_action<br/>confidence_score<br/><b>no amount field at all</b>"]
    C{{"<b>Gatekeeper</b><br/>14 pure functions of state<br/><br/>may downgrade or refuse<br/><b>may never upgrade</b>"}}
    D["<b>SanitizedCommand</b><br/>authoritative<br/><br/>amount copied from<br/>the signed payload"]

    A -->|bucketed| B -->|advisory only| C -->|"or an abstention,<br/>with the rule named"| D

    style B stroke-dasharray: 5 5
    style C fill:#e3f5ed,stroke:#0f7a52,stroke-width:2px
```

Three consequences worth stating plainly:

- A model returning `{"mode":"LIVE"}` **cannot forge its own tier**, because provenance fields
  carry `json:"-"` and are set in-process after the call returns.
- A model **cannot change a sum**, because the proposal type has no amount field to carry one.
  Not a validated field. No field.
- A prompt-injected action string **cannot become a valid action**, because the parsers fold
  ASCII only. That last one was a real bug: see [what broke](#what-broke-and-what-i-did-about-it).

### Where the model is, and where it deliberately is not

```mermaid
flowchart TD
    START["A payment fails"] --> Q1{"Does the taxonomy<br/>already state the cause?"}
    Q1 -->|"card_expired,<br/>terminal declines"| H["<b>HEURISTIC</b><br/>deterministic classifier<br/><i>no model, no cost, no latency</i>"]
    Q1 -->|"ambiguous code,<br/>issuer degrading,<br/>downtime notice"| Q2{"Is a model reachable?"}
    Q2 -->|yes| L["<b>LIVE</b><br/>temperature 0, JSON only, hard timeout"]
    Q2 -->|no| R["<b>REPLAY</b><br/>1,080 digest-keyed cassettes<br/><i>same evidence, same answer</i>"]
    R -->|"no cassette matches"| H
    H --> G{{"Gatekeeper"}}
    L --> G
    R --> G
    G --> OUT["The decision, and the rule that allowed it"]

    style G fill:#e3f5ed,stroke:#0f7a52,stroke-width:2px
    style H fill:#f0f2f7
```

A model is **never** used for:

| Decision | Why not |
|---|---|
| Anything at all | The gatekeeper is 14 pure functions. Model output is an input to it, never a substitute for it. |
| Money | Amounts are copied from the signed payload. |
| Regulatory timing | RBI's cooling window and pre-debit notice are arithmetic on timestamps. A model that is 99 percent right about a legal minimum is 100 percent unusable. |
| Retry budgets and backoff | Bounded arithmetic, not judgment. |
| The ledger | Written by the code that acted, hashed by a function with no configuration. |

---

## The fourteen invariants

Every one is a pure function of state, and every refusal is written to the ledger naming the
invariant that caused it.

| Invariant | What it prevents |
|---|---|
| `AMOUNT_PINNED` | The amount can only come from the signed payload |
| `TERMINAL_DECLINE` | A decline no retry can fix, so no fee is spent on it |
| `STOP_RULE_MAX_ATTEMPTS` | The per-incident retry ceiling |
| `LOW_CONFIDENCE_ABSTAIN` | The model was not sure enough to spend money |
| `UNRECOVERABLE_CLASS` | Retrying this class cannot help |
| `SESSION_REQUIRED_FOR_MORPH` | No live checkout to move, so no rail morph |
| `RAIL_ALLOWLIST` | The merchant never enabled that rail |
| `RBI_MANDATE_COOLING` | RBI's 24-hour gap between recurring debits |
| `RBI_PRE_DEBIT_NOTICE` | The payer must be warned before a debit |
| `RBI_AFA_CEILING` | Above ₹15,000 (₹1,00,000 for some categories) a debit needs a fresh authentication factor |
| `MANDATE_HALTED` | This mandate must not be debited again |
| `MANDATE_CYCLE_CAP` | Attempts allowed within one billing cycle |
| `INSTRUMENT_REFRESH_ALLOWED` | Re-present the token rather than the dead card |
| `DELAY_BOUNDS` | The schedule stays inside a sane horizon |

### Proof, not assertion

```
$ go run ./cmd/modelcheck

  abstract states     1612800
  reachable states    510720
  transitions         8390192
  elapsed             3862 ms

  [HOLDS ] AMOUNT_PINNED                 510720 checked   0 violations
  [HOLDS ] RECURRING_COOLING_AND_NOTICE  510720 checked   0 violations
  [HOLDS ] ATTEMPT_CAP                   510720 checked   0 violations
  [HOLDS ] AFA_CEILING                   510720 checked   0 violations
  [HOLDS ] CLOSED_ACTION_SET             510720 checked   0 violations
  [HOLDS ] REFRESH_PRESERVES_TERMS       510720 checked   0 violations
  [HOLDS ] EXECUTABLE_NAMES_A_RAIL       510720 checked   0 violations
  [HOLDS ] SCHEDULE_BOUNDED              510720 checked   0 violations
  [HOLDS ] GATE_DECIDES_WITHOUT_ERROR    510720 checked   0 violations

total violations 0
```

Property testing samples. **Model checking enumerates.** Where a property test can only say
"no counterexample in 20,000 draws", this says there is none. That distinction found two real
bugs: see [the post-mortem](docs/POSTMORTEM.md).

---

## Proof-carrying recovery

The blocker on letting an agent act on a regulated merchant's money is not capability. It is
**liability**: when the agent retries a customer's mandate, somebody has to be able to show
afterwards that it was allowed to. Today that means mining logs written by the same system
that took the action.

Three things here answer that, and all three are checkable by someone who does not trust this
codebase.

### 1. Attack the gatekeeper yourself

`cmd/meshwasm` compiles the production gatekeeper to WebAssembly. It imports
`internal/gatekeeper` through `internal/gatewire` and adds nothing but JSON decoding, so there
is no second implementation to drift. Its clock comes from the request rather than the host,
so the same input gives the same decision on every machine.

The published page loads it on demand and hands it to you. Smuggle an amount into the JSON,
spell an action with U+017F so Unicode case folding would once have made it valid, claim a
confidence of 1e9, debit a mandate two hours into RBI's twenty-four hour cooling window.

<div align="center">
<img src="docs/img/space-attack.png" alt="A model proposal asking for a larger amount, and the gatekeeper pinning it" width="900">
<br><em>The model asked for ₹49,999.00. The command came out ₹4,999.00, pinned from the signed payload, with the rule that did it named.</em>
</div>

**And the module is proved to match the server build.** The exporter records eleven inputs
with the answers this binary gave them; the page re-derives all eleven in your browser and
compares every field, including which invariants fired and in what order. Two builds of one
package agreeing, shown rather than claimed.

### 2. One payment, provable on its own

A hash chain makes the ledger tamper-evident, but checking a single entry against it means
walking every entry before it. So proving one payment meant handing over the whole ledger,
which a merchant cannot do: it contains every other customer's traffic.

`internal/attest` adds a Merkle tree over the same entry digests the chain links. An inclusion
proof is about log2(n) sibling hashes, and the siblings are digests, so a bundle proves its
payment and discloses nothing about any other.

<div align="center">
<img src="docs/img/space-evidence.png" alt="Nine ledger entries proved against a Merkle root with eight sibling hashes each" width="900">
<br><em>Nine entries proved in 2 ms with 8 sibling hashes each, without reading the other 585 entries.</em>
</div>

```bash
go run ./cmd/meshctl evidence pay_XSeuU4A6Kdc90b --out dispute.json
```

That is the shape a merchant hands a bank during a **chargeback dispute**, and the shape a
compliance team hands an auditor asking whether a mandate debit was permitted. It is plain
JSON with the verification recipe written into it, because evidence that can only be checked
by the tool that produced it is not evidence. Two implementation details matter and are
tested: leaves and interior nodes carry different tags, following RFC 6962, so no leaf can
impersonate an interior node; and odd levels promote rather than duplicate, which is the shape
CVE-2012-2459 exploited.

If the chain is already broken, `meshctl evidence` refuses to emit anything rather than
producing a bundle with a caveat. A valid-looking proof of membership in a compromised set is
worse than no proof.

### 3. The ledger itself

## The audit ledger

Every consequential decision is hash-chained. Fields are absorbed **length-prefixed**, an
8-byte big-endian length then the bytes, rather than concatenated, so an attacker who controls
two adjacent fields cannot forge a collision by shifting the boundary between them.

```go
h := sha256.New()
absorbUint(h, uint64(e.Seq))
absorbStr(h, e.IncidentID)
absorbStr(h, string(e.Kind))
absorbStr(h, e.Actor)
absorb(h, e.Detail)
absorbUint(h, uint64(e.At.UTC().UnixNano()))
absorbStr(h, e.PrevHash)
```

The demonstration attacks it. It edits a row **in the middle of the chain** directly in
PostgreSQL, as an attacker with database access would, and requires verification to localise
the break to that exact sequence number. A ledger that only catches a modified head catches
nothing, because the head is what an attacker rewrites last.

**You can check this without running anything.** The
[evidence page](https://huggingface.co/spaces/hriday29/resilientmesh) ships all 538 entries of
a real run as the exact bytes the ledger hashed, re-derives every digest with `crypto.subtle`
in your browser, and gives you a button that plants a forgery.

Both proofs run on the [evidence page](https://huggingface.co/spaces/hriday29/resilientmesh),
in your browser, with buttons that plant forgeries so you can watch them fail.

---

## The system while it runs

`go run ./cmd/meshdemo -keep` leaves everything up. The operations console is read-only.
Every mutating action lives in `meshctl` behind an explicit `--yes`.

<div align="center">
<img src="docs/img/ops-console.png" alt="ResilientMesh operations console" width="900">
<br><em>Live issuer health with circuit-breaker state, the inference-tier split, and the audit chain with its hashes.</em>
</div>

The checkout page exists for one reason: in-session rail morphing needs a live session to
move, and a session that only exists in a test is not evidence that the path works.

<div align="center">
<img src="docs/img/checkout.png" alt="Checkout with a live SSE session" width="560">
</div>

---

## Build quality

| Claim | How to check it | Result |
|---|---|---|
| It runs on a clean machine | `go run ./cmd/meshdemo` | boots in ~29 s from an empty database |
| It runs as a pass/fail gate | `go run ./cmd/meshctl selftest` | requires a *completed* recovery, then plants a tamper and requires detection at the exact row |
| The invariants hold everywhere | `go run ./cmd/modelcheck` | 510,720 states, 8,390,192 transitions, 0 violations |
| It survives faults | `go run ./cmd/meshsim --seed 42 --chaos standard` | deterministic, byte-identical traces, 9 invariants checked |
| The suite is green | `go test ./... -count=1` | domain 98.3%, simulation 87.7%, attest 96.4% |
| It is race-free | `go test ./... -race` | clean |
| The browser gatekeeper matches the server | open the page, press "Re-derive every decision" | 11 of 11 identical, ~70 ms |
| One payment is provable alone | press "Verify this payment on its own" | 9 entries, 8 hashes each, 15 kB |
| Nothing private is tracked | `go run ./cmd/leakscan` | 1,249 tracked files, PASS |
| Every gate at once | `./scripts/judge.sh` | writes a report to `artifacts/` |

### Dependencies

Six direct, all of them load-bearing:

| Module | Why |
|---|---|
| `jackc/pgx/v5` | PostgreSQL driver and pool |
| `redis/go-redis/v9` | Redis Streams consumer groups |
| `alicebob/miniredis/v2` | a real RESP server in-process, so managed mode needs no Redis |
| `fergusstrange/embedded-postgres` | real PostgreSQL 18.3 in-process, so managed mode needs no Docker |
| `google/uuid` | identifiers |
| `golang.org/x/time` | rate limiting |

There is one code path. Managed mode starts real PostgreSQL and a real RESP server and hands
back connection strings shaped exactly like the ones external mode takes from an operator, so
nothing downstream branches on how the infrastructure was started. **A demo path that diverges
from the production path proves nothing about the production path.**

---

## What broke, and what I did about it

Ten real defects, none of them found by reading the code. Full write-ups in
[docs/POSTMORTEM.md](docs/POSTMORTEM.md). The last one is **still open and left failing on
purpose**.

| # | Found by | What it was |
|---|---|---|
| 1 | Exhaustive model checking | `RBI_AFA_CEILING` was specified and never implemented. A mandate above ₹15,000 would have been retried without a fresh authentication factor. `EXECUTABLE_NAMES_A_RAIL` failed at 29,952 states. **58,512 violations to 0.** |
| 2 | Reviewing consumers, not definitions | `Validate()` accepted `NaN` as a confidence score. Every ordered comparison against NaN is false, so `conf < floor` waved it through and downstream read it as *maximum* confidence. Four more fail-open contracts beside it. |
| 3 | Unicode case folding | `strings.ToUpper` applies *Unicode* case mapping, so U+017F (ſ) uppercases to ASCII S and `ParseAction("AſYNC_EXPONENTIAL_RETRY")` returned a valid action. These parsers sit directly on the model boundary. |
| 4 | Booting the whole thing | The offline path recovered nothing. Every unit test passed; the deterministic tier had no rule for soft declines, so a reviewer with no API key watched a recovery system recover nothing. |
| 5 | Booting the whole thing | Deferred recoveries were silently dropped. A comment claimed a scheduler would collect them. **There was no scheduler.** The ledger recorded correct decisions that never happened. |
| 6 | Deterministic simulation | A retried write double-counted money. The `attempts` table had an index on `(incident, attempt)` but no uniqueness, so a fault after `RecordAttempt` inserted a second row and inflated every measurement, in the direction that flatters the system. |
| 7 | Deterministic simulation | A transient broker outage permanently destroyed events. The relay parked a row on its *first* publish failure, and the claim itself charged an attempt. The relay's own comment stated the correct principle and the code did the opposite. |
| 8 | Running the demo twice | The demonstration poisoned its own next run: act 5 forges a ledger row and does not repair it, and the next run inherited that forgery through a reused data directory. Fixed by giving the demo its own database and emptying it every run. Adding a repair path for one's own audit trail would have been the wrong fix. |
| 9 | Recorded vectors | A conformance vector used `card_stolen`, which is not in the taxonomy, so it fell through to a generic retry and looked like the gate permitting a stolen card. The code is `card_lost_or_stolen`. The fixture was wrong, not the gate, and it was legible only because the expected answer is recorded from a real run rather than asserted by hand. |
| 10 | **OPEN** | The reconciler amplifies during an outage: a parked outbox row is not `PENDING`, so the reconciler treats its incident as stalled and inserts a replacement, which parks too. 20,434 rows from 400 incidents. **Two fixes were attempted and both reverted.** One traded a loud failure for a silent one; the other stopped the run draining for reasons I did not fully characterise. A verification harness edited until it agrees with the system is not a harness, and a fix I cannot explain is not a fix. |

Reproduce the open one:

```bash
go run ./cmd/meshsim --seed 20260904 --incidents 400
# invariant NO_EVENT_LOST violated: 20434 outbox rows exhausted their
# publish budget and were dead-lettered
```

---

## Security

The bar was: nothing internal reaches GitHub, and nothing internal reaches a user.

- **Webhooks** are HMAC-verified with a constant-time compare **before anything parses the
  body**, with a bounded timestamp skew in both directions so a captured delivery cannot be
  replayed indefinitely.
- **The model boundary** is described above. It is enforced by types, not by prompt wording.
- **Money** is integer paisa end to end. Floats are banned from money paths.
- **The operations console** is read-only and behind a per-run token. Every mutation lives in
  `meshctl` behind `--yes`, and writes its intent to the ledger *before* acting.
- **The web UI** is CSP-strict and writes through `textContent` only, never `innerHTML`.
- **`cmd/leakscan`** is a committed scanner, run in CI over every tracked file: credential
  shapes, private-document paths, `.env` values, and control characters in tracked text. Test
  fixtures compose credential-shaped strings at runtime (`internal/testsecret`) so no tracked
  file contains a literal matching a scanner pattern, and no scanner exemptions are needed.
- **The exported run** is scrubbed of every secret before it is written, and the writer
  **refuses to write the file at all** if a secret survives redaction.
- **`.env` loading** accepts `MESH_`-prefixed names only, so a dotfile that lands in a checkout
  cannot set `PATH` or `LD_PRELOAD`.

---

## Repository layout

```
cmd/
  meshdemo     the guided demonstration; start here
  mesh         the whole system in one process
  meshctl      operator CLI: selftest, audit verify, dlq replay, mandate halt
  modelcheck   exhaustive state-space walk over the gatekeeper
  meshsim      deterministic simulation with fault injection
  meshwasm     the gatekeeper, compiled to WebAssembly for the page
  leakscan     the secret and private-document scanner CI runs
  api, worker, simulator
internal/
  domain       frozen contracts: taxonomy, decisions, records, hashing
  gatekeeper   the 14 invariants
  agent        the three inference tiers
  ingest       the webhook trust boundary
  outbox       transactional outbox relay
  queue        Redis Streams consumer group and DLQ
  worker       the decision loop, sweeper and executor wiring
  store        PostgreSQL, migrations, hash-chain allocation
  audit        the ledger
  attest       Merkle tree, inclusion proofs, portable evidence
  gatewire     the JSON boundary both the browser and the server call
  infra        embedded PostgreSQL and RESP, for managed mode
  simulation   the deterministic simulator and its invariants
space/         the published evidence page
docs/          EVALUATING.md, POSTMORTEM.md
eval/          the four-policy benchmark
```

---

## Submission

| | |
|---|---|
| **Name** | Hriday Vig |
| **College** | Maharaja Surajmal Institute of Technology |
| **Graduating** | 2028 |
| **Track** | Track 03, AI Revenue Recovery |
| **Project** | ResilientMesh |
| **What it solves** | Failed payments in India are recovered today by blind retries that burn gateway fees, annoy customers, and on recurring mandates can breach RBI's e-mandate rules. ResilientMesh decides each failure on evidence, refuses the ones no retry can fix, obeys the regulatory constraints as hard invariants rather than as prompt instructions, and leaves a tamper-evident record of every decision including the refusals. |
| **Repository** | https://github.com/vighriday/ResilientMesh-Razorpaybuildathon |
| **Evidence page** | https://huggingface.co/spaces/hriday29/resilientmesh |
| **Pitch video** | *(to be added)* |

---

<div align="center">

### [Open the evidence page](https://huggingface.co/spaces/hriday29/resilientmesh)

Verify a real run's audit ledger in your own browser. Nothing to install, nothing to trust.

<br>

### Anyone can make an agent act.

### The hard part is proving, afterwards, that it was allowed to.

<br>

**`go run ./cmd/meshdemo`**

Two minutes. No account, no key, no Docker.

Or open the [evidence page](https://huggingface.co/spaces/hriday29/resilientmesh) and try to
talk the gatekeeper into moving money. It is the real one.

</div>

# Runbook

Procedures for the failure modes this system is designed to survive. Each entry states what you will see, what is actually happening, what to do, and what *not* to do.

Every procedure assumes `meshctl` on your path and the ops token in `MESH_OPS_TOKEN`.

---

## Triage order

Two numbers tell you almost everything, and they are both on the console header:

- **Outbox pending** — events durably recorded but not yet queued. Rising means the relay or Redis is unhealthy. Money is not lost; work is delayed.
- **Queue lag** — events queued but not yet processed. Rising means workers are unhealthy or overwhelmed.

If outbox pending is flat and queue lag is flat, the pipeline is healthy regardless of what else looks alarming.

```bash
meshctl health          # dependency status and both depths
meshctl audit tail -n50 # the last decisions, in order
```

---

## Redis is unavailable

**You see.** Outbox pending climbing steadily. Queue lag flat or zero. Ingest still returning 200. Worker logs quiet.

**What is happening.** This is the designed behaviour, not an incident yet. The edge writes incidents and outbox rows in one PostgreSQL transaction, so nothing depends on Redis being up at ingest time. The relay is failing to publish and backing off with jitter. Nothing has been lost.

**Do.**
1. Confirm the shape: `meshctl health` should show Redis unreachable, PostgreSQL healthy.
2. Restore Redis. The relay drains automatically; no manual replay is needed.
3. Watch outbox pending return to zero. Drain rate is roughly batch size ÷ poll interval.

**Do not.** Do not restart the API to "clear" the backlog — the backlog *is* the durable buffer. Do not truncate `outbox_events`; those are unprocessed payment failures.

**Escalate if.** Outbox pending is still climbing after Redis is confirmed healthy. That points at the relay, not the queue: check for rows stuck in `FAILED` (`meshctl outbox failed`).

---

## PostgreSQL is unavailable

**You see.** Ingest returning 503. Console unable to load.

**What is happening.** The edge deliberately refuses webhooks it cannot durably record. Returning 200 for an event we cannot persist would silently lose a payment failure, which is exactly the class of bug this system exists to prevent. Razorpay will retry the webhook, so refusing is recoverable and accepting is not.

**Do.**
1. Restore PostgreSQL.
2. Confirm migrations are current: `meshctl health` reports schema version.
3. Expect a burst of redelivered webhooks. The `event_id` unique constraint deduplicates them; a spike of `duplicate_ignored` in the logs is correct behaviour, not an error.

**Do not.** Do not disable HMAC verification or the durability write to "get traffic flowing".

---

## The inference provider is down or slow

**You see.** Console "Inference source" panel shifting from `LIVE` to `REPLAY` or `HEURISTIC`. Recovery continues.

**What is happening.** Working as designed. The tiered stack falls through and records which tier answered on every incident.

**Do.**
1. Decide whether the drift matters. `HEURISTIC` is a genuine quality reduction — it is the static-rules baseline — so a sustained shift is a real regression even though nothing is erroring.
2. Check the provider, the key, and `MESH_LLM_TIMEOUT`. A timeout that is too tight looks identical to an outage.
3. If the provider is down for a long window, `REPLAY` coverage is what protects quality. Check the cassette hit rate in metrics.

**Do not.** Do not raise the timeout past a few seconds. The worker holds a stream message while diagnosing; long timeouts convert a slow provider into queue lag.

---

## Outbox backlog growing with Redis healthy

**Do.**
1. `meshctl outbox failed` — rows that exhausted publish attempts. Their `last_error` names the cause.
2. If the cause is transient and resolved, requeue: `meshctl outbox requeue --state FAILED`.
3. If a specific payload fails repeatedly, it is poison. It is already in the dead-letter stream with its failure history; treat it as a bug report, not an ops task.

**Root causes seen.** Redis memory limit reached (stream trimming misconfigured); a payload exceeding the stream entry limit; consumer group missing after a Redis flush — recreate with `meshctl queue ensure-group`.

---

## A circuit breaker is stuck open

**You see.** An issuer showing `OPEN` on the console long after it recovered. Incidents for it skipping inference and going straight to backoff.

**What is happening.** The breaker opens on a rolling window and half-opens after the cooldown, admitting a limited probe budget. Stuck open means probes are still failing, or no traffic is arriving to probe with.

**Do.**
1. `meshctl breaker status <issuer>` — state, sample count, time since opening.
2. If the issuer is genuinely healthy but idle, the breaker cannot know: it needs traffic. It will close on the next successful probe.
3. Only if you are certain: `meshctl breaker reset <issuer>`.

**Do not.** Do not reset breakers in bulk during a live outage. That is precisely the thundering herd the breaker exists to prevent.

---

## Audit chain verification fails

**Treat this as a security incident until proven otherwise.**

**You see.** `meshctl audit verify` exits non-zero and names a sequence number and cause.

**What it means.**
- `hash mismatch` — that entry's content changed after it was written.
- `prev_hash mismatch` — an entry was inserted or reordered.
- `sequence gap` — an entry was deleted.

**Do.**
1. Do not write to the ledger further than necessary; preserve the current state.
2. Capture evidence: `meshctl audit export --from <seq-10> --to <seq+10>`.
3. Everything at and after the reported sequence is untrustworthy. Everything before it is still cryptographically intact — that is the point of the chain.
4. Check database access logs for direct writes. The application only appends; any `UPDATE` or `DELETE` on `audit_ledger` came from outside it.
5. Revoke and rotate database credentials before resuming.

**Known benign cause.** The judge harness deliberately corrupts a row to demonstrate detection. If verification fails immediately after `judge.sh`, that is the demonstration, and the harness restores the row afterwards.

---

## Dead-letter stream growing

**You see.** Dead letters non-zero and rising.

**What is happening.** Messages that failed processing repeatedly, or panicked a worker, are moved out of the main stream with their full failure history so one bad payload cannot stall the pool.

**Do.**
1. `meshctl dlq list` — grouped by failure signature.
2. A single signature dominating is a code bug. Fix it, then `meshctl dlq requeue --signature <sig>`.
3. Scattered signatures suggest an environmental problem — usually the database or the provider — and the DLQ is a symptom, not the cause.

**Do not.** Do not requeue in bulk without identifying the signature; you will simply re-poison the pool.

---

## Edge returning 503 with `Retry-After`

**What is happening.** Admission control. Outbox depth passed the high-water mark, so the edge is shedding load rather than accepting work it cannot drain. Razorpay retries webhooks, so shed load is deferred, not lost.

**Do.** Treat it as a drain problem, not an ingest problem — go to the outbox and worker procedures. Raise the high-water mark only if you have confirmed the drain path is healthy and the mark is simply too low for current volume.

---

## Rotating the webhook secret

Razorpay signs with one secret at a time, so rotation has a window where both must be accepted.

1. Set `MESH_WEBHOOK_SECRET_NEXT` to the new secret and restart. The edge now accepts either.
2. Change the secret in the Razorpay dashboard.
3. Watch verification failures. They should stay at zero.
4. Promote: move the new value to `MESH_WEBHOOK_SECRET`, clear `MESH_WEBHOOK_SECRET_NEXT`, restart.

Never accept unsigned webhooks during rotation, and never log either secret — only fingerprints are logged.

---

## Safe replay

Replay is safe by construction because `event_id` is unique and consumers are idempotent. Reprocessing a delivered event creates no second incident and no second attempt.

```bash
meshctl replay --incident <id>            # one incident
meshctl replay --since 2026-09-04T02:00Z  # a window
```

Replay does **not** reset attempt counters or mandate cooling state. That is deliberate: those are compliance counters, and a replay that reset them would permit a debit the regulator does not.

---

## Graceful restart

`SIGTERM` drains in-flight HTTP, finishes the current outbox batch, acks in-flight stream messages, sends a `closed` frame to every SSE client, then exits — bounded by a deadline, after which it force-exits with a logged reason.

Messages held by a worker that dies without acking are reclaimed by `XAUTOCLAIM` after the idle timeout. No manual intervention.

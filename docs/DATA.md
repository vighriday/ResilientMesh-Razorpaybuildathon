# Data Handling

What this system stores, why each item is necessary, how long it stays, and what it deliberately never touches.

---

## What is stored

| Table | Contents | Why it is necessary |
|---|---|---|
| `incidents` | Payment id, order id, subscription id, event id, amount in paisa, currency, method, issuer key, error code, state, attempt count, and the raw verified webhook body | The raw body is the evidence that the amount was never mutated. Without it, "we pinned the amount from the signed payload" is a claim rather than a checkable fact |
| `outbox_events` | Event reference and payload, dispatch state | The durability guarantee. Deleting a pending row loses a payment failure |
| `mandates` | Subscription id, last attempt, next eligible time, attempts in cycle, pre-debit notification time | The RBI cooling window and cycle cap are computed from these. They live in PostgreSQL rather than Redis specifically so a cache eviction cannot reset a compliance counter |
| `attempts` | Action, rail, amount, outcome, fees, timestamps | What the recovery-value benchmark aggregates over |
| `sessions` | Session id, order id, token **hash**, rail, amount, expiry | Enables in-session healing. The token itself is never stored |
| `audit_ledger` | Sequence, kind, actor, redacted detail, timestamp, previous hash, hash | The tamper-evident decision record |

---

## What is never stored, and never transmitted

- **Card numbers, expiry, CVV, cardholder name.** Razorpay does not send them in these webhooks, and there is no column for them. The system is not in PCI scope and is designed to stay that way.
- **Customer contact details**, phone, email, address. No field exists.
- **VPA in full.** Only the handle is extracted for issuer keying: `name@okhdfcbank` becomes `upi:okhdfcbank`. The local part is discarded at the boundary, because outages are handle-scoped and the local part carries only identity.
- **Authentication material.** Session tokens are stored as SHA-256 hashes. The webhook secret and API keys exist only in process memory from the environment.

---

## What reaches the inference provider

This is the narrowest surface in the system, and it is defined by a struct rather than by a filter, `DiagnosticContext` is an allowlist, so a field that does not exist cannot leak.

| Sent | Not sent |
|---|---|
| Error code, source, step | Payment id, order id, subscription id |
| Payment method, issuer key | VPA, contact details, any instrument data |
| Amount **band** (`mid_2k_10k`) | The exact amount |
| Recurring flag, session-active flag, attempt number | The raw webhook body |
| Rolling telemetry and downtime signals | Merchant identity |
| `error_reason`, sanitised and capped at 200 characters, fenced as data | Anything else |

`error_reason` is the only free text that crosses the boundary. It originates upstream, so it is treated as untrusted: control characters stripped, length capped, and placed inside an explicitly delimited data block. The bucketed amount is deliberate, the model has no legitimate use for the exact figure, and removing it eliminates both a correlation vector and an injection vector.

---

## Redaction in logs and audit detail

Log attributes and audit details pass through a redaction handler that masks any key matching `secret`, `token`, `key`, `password`, `signature`, `authorization`, `vpa`, `card`, `contact`, `email`, `phone`, or `dsn`, and truncates values over 512 bytes on a rune boundary. The handler walks nested groups and attributes added via `WithAttrs`, because a redactor that only covers the top level fails exactly where structured logging is most useful.

Audit details are redacted **before** hashing, so a secret cannot be recovered from the ledger even by someone reconstructing it.

---

## Retention

| Data | Retention | Reason |
|---|---|---|
| `incidents` including raw payload | 90 days | Long enough for dispute and reconciliation windows; short enough to bound exposure |
| `attempts` | 90 days | Paired with incidents for analysis |
| `outbox_events`, dispatched | 7 days | Operational debugging only; the durability role ends at dispatch |
| `sessions` | 24 hours after expiry | Sessions are minutes long; the row is only kept briefly for post-hoc debugging |
| `mandates` | Life of the mandate plus 90 days | Cooling and cycle state must outlive individual incidents |
| `audit_ledger` | 7 years | Financial audit record. Never pruned from the head, the chain is only meaningful whole, so archival exports a verified prefix rather than deleting rows |
| Telemetry and breaker state in Redis | Rolling window × 3, by TTL | Operational signal with no retention value |

Retention is enforced by a scheduled prune that deletes only from tables where deletion is safe. `audit_ledger` is deliberately excluded from any automated deletion path.

---

## Access

- Application credentials hold `SELECT`, `INSERT`, and `UPDATE` on operational tables, and `SELECT` plus `INSERT` on `audit_ledger`, no `UPDATE`, no `DELETE`. The application only appends, so anything else in the audit table came from outside it.
- The operations API is closed by default. If no token is configured it denies everything rather than allowing everything.
- No data leaves the deployment except the allowlisted diagnostic context, and only when the live inference tier is configured.

---

## Regulatory posture

- **RBI e-mandate rules** are enforced as invariants: the 24-hour cooling window, the pre-debit notification, and the per-cycle attempt cap are deterministic checks against durable timestamps, never inferred and never model-decided.
- **PCI DSS** is out of scope by design, and staying out of scope is an architectural constraint rather than an accident.
- **Data minimisation.** Every stored field traces to a specific decision or obligation. The raw webhook body is the one deliberately generous retention, and it exists because it is the evidence underpinning the amount-immutability guarantee.

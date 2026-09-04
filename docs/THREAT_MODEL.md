# Threat Model

Scope: the ResilientMesh service — its HTTP edge, worker pool, datastores, inference dependency, and operator surfaces. Out of scope: the acquiring bank, the issuer, and Razorpay's own platform.

Each threat lists the control and the test that proves the control works. A control without a test is an intention, not a control.

---

## Trust boundaries

```
  [1] internet ──► webhook edge          unauthenticated until HMAC verifies
  [2] browser  ──► SSE stream            customer-held token
  [3] operator ──► ops API               operator token
  [4] service  ──► inference provider    outbound, carries untrusted text
  [5] service  ──► PostgreSQL / Redis    trusted network, still least-privilege
```

---

## [1] Webhook edge

| # | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| 1.1 | Forged `payment.failed` triggers recovery on a payment that never failed | Spoofing | HMAC-SHA256 over the raw body, constant-time compare on decoded bytes. Header absent, wrong length, or malformed hex is rejected before comparison | `ingest`: valid / tampered body / wrong secret / missing header / malformed hex |
| 1.2 | Replayed capture of a genuine webhook drives repeat retries | Repudiation, Elevation | `X-Razorpay-Event-Id` is `UNIQUE` on `incidents`; duplicates return 200 and create no outbox row. The database is the serialisation point, so two concurrent deliveries cannot both win | Duplicate-delivery test, plus a concurrent duplicate storm |
| 1.3 | Very old captured event replayed after the issuer recovers | Spoofing | `created_at` outside a ±300 s skew window is rejected | Skew test, both directions |
| 1.4 | Multi-gigabyte body exhausts memory | DoS | `http.MaxBytesReader` at 1 MiB before any read; body is never buffered unbounded | Oversized body returns 413 |
| 1.5 | Request flood from one source | DoS | Per-IP token bucket in a capacity-bounded LRU, plus a global limiter. `X-Forwarded-For` honoured only behind an explicit trust flag — blindly trusting it lets any client forge its identity and bypass the limit | Rate limit test; XFF spoof test |
| 1.6 | Slowloris holds connections open | DoS | `ReadHeaderTimeout` and `ReadTimeout` set on the server | Server config assertion |
| 1.7 | Error responses leak internals | Information disclosure | Fixed response bodies. Parse errors, SQL errors, and panics never reach the client; panics are recovered and logged with an opaque 500 | Panic middleware test asserts no leak |
| 1.8 | Timing side channel recovers the signature | Information disclosure | `hmac.Equal` over equal-length byte slices | Constant-time comparison is asserted by code review and enforced by the decode-then-compare ordering |
| 1.9 | Accepting work the system cannot drain turns an incident into an outage | DoS | Admission control: 503 + `Retry-After` once outbox depth passes the high-water mark | Backpressure test |

---

## [2] Session stream

| # | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| 2.1 | Attacker attaches to another customer's live checkout stream | Information disclosure | **This is the defect the original design had.** Streams are keyed by an opaque `session_id` and require a bearer token issued once at creation. Order ids are never addressable | Wrong token → 401; unknown session → 404 |
| 2.2 | Database read yields a replayable credential | Elevation | Only the SHA-256 hash of the token is stored | Store assertion: the raw token never persists |
| 2.3 | Token recovered byte-by-byte from response timing | Information disclosure | `subtle.ConstantTimeCompare` | Token comparison test |
| 2.4 | Token leaks via browser history or referrer | Information disclosure | `EventSource` cannot set headers, so a query token is supported, but it is single-purpose, short-lived, hashed at rest, and the console strips it from the address bar via `replaceState`. `Referrer-Policy: no-referrer` | Header path preferred and tested; console strips the query |
| 2.5 | Connection exhaustion via unbounded subscribers | DoS | Hard cap on concurrent sessions, 503 past it; per-subscriber buffered channel with non-blocking send so one slow client cannot wedge the publisher | 1000-subscriber race test; slow-consumer drop test |
| 2.6 | Sensitive data on the wire | Information disclosure | Frames carry only order, amount, rails, and a reason drawn from a fixed vocabulary. Never model free text, never PII | Event payload assertion |

---

## [3] Operations API

| # | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| 3.1 | Unauthenticated access to incident and audit data | Information disclosure | Bearer token, constant-time compare. **If no token is configured the API denies everything** rather than allowing everything — fail closed | Empty-token test asserts 401 |
| 3.2 | Console XSS via attacker-controlled incident text | Tampering | Every cell is written with `textContent`; `innerHTML` appears nowhere. CSP is `default-src 'self'` with no `unsafe-inline`, achievable because styles and scripts are separate same-origin files | CSP header test; code review gate on `innerHTML` |
| 3.3 | Cross-origin read of the ops API | Information disclosure | CORS denies by default and never reflects an arbitrary `Origin`; credentials are never paired with a wildcard | Foreign-origin test |
| 3.4 | Clickjacking the console | Tampering | `X-Frame-Options: DENY`, `frame-ancestors 'none'` | Header test |
| 3.5 | Token persisted where other scripts can read it later | Information disclosure | `sessionStorage` only, cleared when the tab closes | Console code review |

---

## [4] Inference provider

| # | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| 4.1 | Prompt injection via `error_reason` from upstream | Tampering, Elevation | Three layers: `DiagnosticContext` is a struct allowlist so PII and raw payloads *cannot* reach a prompt; untrusted text is control-character stripped, capped at 200 chars, and fenced as data; and the gatekeeper means even a fully successful injection cannot move money. Layers one and two reduce probability, layer three bounds impact | Adversarial injection suite; a test that treats the model as fully compromised and asserts the command is still safe |
| 4.2 | Model returns an action outside the closed set | Tampering | `ParseAction` fails closed to `PERMANENT_ABSTAIN`; `Validate()` rejects out-of-range confidence and delay | Property test over hostile responses |
| 4.3 | Model inflates or alters the amount | Tampering | The proposal has no amount field. The command's amount is copied from HMAC-verified bytes | Property test: 20,000 cases, amount always equals the payment |
| 4.4 | PII sent to a third-party endpoint | Information disclosure | Allowlisted struct; amount bucketed to a band; no VPA, contact, card, or raw payload is a field at all | Prompt-content assertion |
| 4.5 | API key leaks into logs or audit | Information disclosure | Redacting slog handler covering `WithAttrs` and `WithGroup`; prompts and responses log at debug only | Log assertion: key never appears |
| 4.6 | Provider outage stalls recovery | DoS | Tiered fallback to replay then heuristic, with the tier recorded per incident so degradation is visible rather than silent | Live-tier failure tests: 429, 5xx, timeout, malformed JSON |
| 4.7 | Hostile response body exhausts memory | DoS | Response read capped at 64 KiB | Oversized response test |

---

## [5] Datastores

| # | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| 5.1 | SQL injection | Tampering, Elevation | Every query parameterised; no string building into SQL anywhere in `internal/store` | Code review gate; grep for `Sprintf` in SQL paths |
| 5.2 | Silent modification of the audit trail | Repudiation | Hash chain with length-prefixed field absorption. Any edit, deletion, or reorder breaks verification from that point, and `meshctl audit verify` names the first broken sequence | Tamper test mutates entry 137 and asserts the break is reported at 137 |
| 5.3 | Concurrent appends corrupt the chain | Tampering | Sequence and previous-hash allocation serialised by `pg_advisory_xact_lock` inside the transaction | 8-goroutine concurrent append test asserts a perfectly linear chain |
| 5.4 | Two relays dispatch the same event | Tampering | `SELECT ... FOR UPDATE SKIP LOCKED` | Two relays × 500 rows, zero overlap |
| 5.5 | Cache eviction resets a compliance counter and permits unbounded retries | Elevation | Attempt counts and mandate state live in PostgreSQL, not Redis. Redis holds only telemetry and breaker state, both of which fail safe when empty | Mandate state survives a Redis flush |
| 5.6 | Credentials in the connection string reach a log | Information disclosure | Config redaction masks the DSN password; `String()`/`LogValue()` never emit raw secrets | Redaction test asserts the raw secret substring is absent |
| 5.7 | Unbounded Redis growth | DoS | Every telemetry key has a TTL and is trimmed on write | TTL assertion |

---

## Supply chain and repository

| # | Threat | Control | Test |
|---|---|---|---|
| 6.1 | Malicious or abandoned dependency | Six direct dependencies, all widely used and maintained. `go-redis` pinned to v9 because v8 is unmaintained. No ORM, no web framework. `go.sum` pins every hash; `govulncheck` runs in CI | CI job |
| 6.2 | Secret committed to a public repository | `.gitignore` blocks `.env*`, key material, and `*.docx`; `scripts/leakscan` fails the build on secret patterns or internal-path references, and runs in CI | CI job; deliberately planted pattern must fail the scan |
| 6.3 | Internal planning material published | All strategy and planning documents live under a git-ignored `_internal/`, and the leak scanner rejects any tracked reference to it | CI job |
| 6.4 | Container runs as root | Distroless final stage, non-root user, static binary, no shell | Image inspection in CI |

---

## Accepted risks

| Risk | Why accepted |
|---|---|
| Session token appears as a query parameter | `EventSource` cannot set headers. Bounded by short TTL, single purpose, hash-at-rest, `Referrer-Policy: no-referrer`, and removal from browser history by the client |
| At-least-once delivery means duplicate processing | Deliberate — the alternative is lost events. Bounded by `UNIQUE` idempotency on `event_id` |
| In-memory SSE hub loses subscriptions on restart | Sessions are seconds-to-minutes long and the client reconnects. Persisting them would add a datastore dependency to the latency-critical path for little gain; the limitation is stated honestly to the client rather than papered over |
| Replay cassettes are recorded, not live | Recorded inference is what makes the benchmark reproducible. The tier is recorded on every incident so it can never be passed off as live |

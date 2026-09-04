-- ResilientMesh schema, migration 0001_init.
--
-- Money is BIGINT paisa everywhere: the whole system does integer arithmetic on
-- amounts, so there is no float anywhere on the path from webhook to ledger and
-- no rounding artefact can change a recovered amount. Every timestamp is
-- TIMESTAMPTZ because an RBI cooling window that means a different instant in
-- two datacentres is a compliance incident, not a formatting bug. Payloads are
-- JSONB so the ops console can query inside them without a second encoding.
--
-- Every statement is idempotent (IF NOT EXISTS). migrations.go already guards
-- this file with a version row inside a single transaction; the guard and the
-- idempotency are belt and braces, because a half-applied schema on a payment
-- system is unrecoverable in a way a redundant CREATE never is.

-- ---------------------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------------------
-- raw_payload holds the HMAC-verified webhook body. JSONB normalises key order
-- and whitespace, so this column preserves the content of the evidence, not its
-- bytes; byte-level tamper evidence is the job of the audit_ledger hash chain,
-- and the amount the system acts on is read from amount_paisa, never re-parsed
-- from here.
CREATE TABLE IF NOT EXISTS incidents (
    id              TEXT        NOT NULL PRIMARY KEY,
    payment_id      TEXT        NOT NULL,
    order_id        TEXT        NOT NULL DEFAULT '',
    subscription_id TEXT        NOT NULL DEFAULT '',
    event_id        TEXT        NOT NULL,
    amount_paisa    BIGINT      NOT NULL,
    currency        TEXT        NOT NULL,
    method          TEXT        NOT NULL,
    issuer_key      TEXT        NOT NULL,
    error_code      TEXT        NOT NULL DEFAULT '',
    state           TEXT        NOT NULL,
    attempt_count   INTEGER     NOT NULL DEFAULT 0,
    is_recurring    BOOLEAN     NOT NULL DEFAULT FALSE,
    raw_payload     JSONB       NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT incidents_id_len          CHECK (char_length(id) BETWEEN 1 AND 128),
    CONSTRAINT incidents_event_id_len    CHECK (char_length(event_id) BETWEEN 1 AND 128),
    CONSTRAINT incidents_payment_id_len  CHECK (char_length(payment_id) BETWEEN 1 AND 128),
    CONSTRAINT incidents_order_id_len    CHECK (char_length(order_id) <= 128),
    CONSTRAINT incidents_sub_id_len      CHECK (char_length(subscription_id) <= 128),
    CONSTRAINT incidents_currency_len    CHECK (char_length(currency) BETWEEN 1 AND 8),
    CONSTRAINT incidents_method_len      CHECK (char_length(method) <= 32),
    CONSTRAINT incidents_issuer_len      CHECK (char_length(issuer_key) <= 128),
    CONSTRAINT incidents_error_code_len  CHECK (char_length(error_code) <= 64),
    CONSTRAINT incidents_amount_nonneg   CHECK (amount_paisa >= 0),
    CONSTRAINT incidents_attempts_nonneg CHECK (attempt_count >= 0),
    CONSTRAINT incidents_state_known     CHECK (state IN (
        'RECEIVED', 'DIAGNOSED', 'GATED', 'SCHEDULED', 'EXECUTING', 'RECOVERED', 'ABANDONED', 'ABSTAINED'))
);

-- The replay guard. A duplicate X-Razorpay-Event-Id must be impossible to
-- store, not merely unlikely to be inserted: uniqueness lives here so that two
-- edge processes racing on the same redelivery still produce exactly one
-- incident and exactly one outbox row.
CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_event_id ON incidents (event_id);
CREATE INDEX IF NOT EXISTS ix_incidents_payment_id ON incidents (payment_id);
CREATE INDEX IF NOT EXISTS ix_incidents_recent ON incidents (received_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- outbox_events
-- ---------------------------------------------------------------------------
-- Written in the same transaction as the incident it describes, which is what
-- removes the dual-write failure mode: either both land or neither does.
--
-- claimed_until is a lease, not a state. FOR UPDATE SKIP LOCKED stops two
-- relays overlapping inside a claim transaction; the lease is what stops them
-- overlapping in the window after that transaction commits and before the batch
-- is marked dispatched. It expires, so a relay that dies mid-batch strands its
-- events for one lease period rather than forever.
CREATE TABLE IF NOT EXISTS outbox_events (
    id            BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id   TEXT        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    topic         TEXT        NOT NULL,
    payload       JSONB       NOT NULL,
    state         TEXT        NOT NULL DEFAULT 'PENDING',
    attempts      INTEGER     NOT NULL DEFAULT 0,
    last_error    TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at TIMESTAMPTZ,
    claimed_until TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT outbox_topic_len       CHECK (char_length(topic) BETWEEN 1 AND 128),
    CONSTRAINT outbox_last_error_len  CHECK (char_length(last_error) <= 512),
    CONSTRAINT outbox_attempts_nonneg CHECK (attempts >= 0),
    CONSTRAINT outbox_state_known     CHECK (state IN ('PENDING', 'DISPATCHED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS ix_outbox_state_id ON outbox_events (state, id);
CREATE INDEX IF NOT EXISTS ix_outbox_incident ON outbox_events (incident_id);

-- ---------------------------------------------------------------------------
-- mandates
-- ---------------------------------------------------------------------------
-- RBI e-mandate compliance state. It lives in the database rather than in a
-- worker process so a restart cannot reset a cooling window or a per-cycle
-- attempt count, which are exactly the two counters a regulator would ask about.
CREATE TABLE IF NOT EXISTS mandates (
    subscription_id       TEXT        NOT NULL PRIMARY KEY,
    customer_id           TEXT        NOT NULL DEFAULT '',
    amount_paisa          BIGINT      NOT NULL DEFAULT 0,
    last_attempt_at       TIMESTAMPTZ,
    next_eligible_at      TIMESTAMPTZ,
    attempts_in_cycle     INTEGER     NOT NULL DEFAULT 0,
    pre_debit_notified_at TIMESTAMPTZ,
    cycle_key             TEXT        NOT NULL DEFAULT '',
    category              TEXT        NOT NULL DEFAULT 'general',
    halted                BOOLEAN     NOT NULL DEFAULT FALSE,
    halt_reason           TEXT        NOT NULL DEFAULT '',
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mandates_sub_id_len      CHECK (char_length(subscription_id) BETWEEN 1 AND 128),
    CONSTRAINT mandates_customer_len    CHECK (char_length(customer_id) <= 128),
    CONSTRAINT mandates_cycle_key_len   CHECK (char_length(cycle_key) <= 128),
    CONSTRAINT mandates_halt_reason_len CHECK (char_length(halt_reason) <= 512),
    CONSTRAINT mandates_amount_nonneg   CHECK (amount_paisa >= 0),
    CONSTRAINT mandates_attempts_nonneg CHECK (attempts_in_cycle >= 0),
    -- The category decides which RBI additional-factor ceiling applies, so an
    -- unrecognised value must not reach the column: the default and the check
    -- together mean a mandate is always judged against a real ceiling, and the
    -- strictest one when nothing else is known.
    CONSTRAINT mandates_category_known  CHECK (category IN (
        'general', 'insurance', 'mutual_fund', 'credit_card_bill'))
);

-- Partial index: the scheduler only ever asks for mandates that are not halted.
CREATE INDEX IF NOT EXISTS ix_mandates_next_eligible
    ON mandates (next_eligible_at) WHERE halted = FALSE;

-- ---------------------------------------------------------------------------
-- attempts
-- ---------------------------------------------------------------------------
-- One executed recovery attempt and its economics. This is the table the NRCV
-- benchmark aggregates, so fees and friction are stored per attempt in paisa
-- rather than recomputed later from a cost model that may since have changed.
CREATE TABLE IF NOT EXISTS attempts (
    id                BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id       TEXT        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    attempt_number    INTEGER     NOT NULL,
    action            TEXT        NOT NULL,
    rail              TEXT        NOT NULL,
    presentation      TEXT        NOT NULL DEFAULT 'unchanged',
    amount_paisa      BIGINT      NOT NULL,
    succeeded         BOOLEAN     NOT NULL,
    gateway_fee_paisa BIGINT      NOT NULL DEFAULT 0,
    friction_paisa    BIGINT      NOT NULL DEFAULT 0,
    error_code        TEXT        NOT NULL DEFAULT '',
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT attempts_number_positive CHECK (attempt_number >= 1),
    CONSTRAINT attempts_amount_nonneg   CHECK (amount_paisa >= 0),
    CONSTRAINT attempts_fee_nonneg      CHECK (gateway_fee_paisa >= 0),
    CONSTRAINT attempts_friction_nonneg CHECK (friction_paisa >= 0),
    CONSTRAINT attempts_error_code_len  CHECK (char_length(error_code) <= 64),
    -- These three lists mirror the domain enums. Go validates against the domain
    -- values themselves before any write, so the checks are here to stop a write
    -- that did not come through this package, and a drift between them shows up
    -- as a loud constraint violation rather than an unreadable row.
    CONSTRAINT attempts_action_known    CHECK (action IN (
        'IN_SESSION_RAIL_MORPH', 'ASYNC_EXPONENTIAL_RETRY', 'MANDATE_COMPLIANT_CASCADE',
        'INSTRUMENT_REFRESH', 'PERMANENT_ABSTAIN')),
    CONSTRAINT attempts_rail_known      CHECK (rail IN (
        'upi_intent', 'upi_collect', 'card', 'netbanking', 'wallet', 'none')),
    CONSTRAINT attempts_presentation_known CHECK (presentation IN (
        'unchanged', 'network_token', 'stored_credential', 'fresh_authorisation'))
);

CREATE INDEX IF NOT EXISTS ix_attempts_incident ON attempts (incident_id, attempt_number);

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------
-- token_hash stores a digest, never the bearer token: a database dump must not
-- be replayable against the SSE stream endpoint. The length floor exists so a
-- truncated or empty digest cannot be written and quietly become an
-- "everything matches" comparison upstream.
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT        NOT NULL PRIMARY KEY,
    order_id     TEXT        NOT NULL,
    token_hash   TEXT        NOT NULL,
    current_rail TEXT        NOT NULL DEFAULT 'none',
    amount_paisa BIGINT      NOT NULL DEFAULT 0,
    currency     TEXT        NOT NULL DEFAULT 'INR',
    active       BOOLEAN     NOT NULL DEFAULT TRUE,
    morph_count  INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    closed_at    TIMESTAMPTZ,
    CONSTRAINT sessions_id_len        CHECK (char_length(id) BETWEEN 1 AND 128),
    CONSTRAINT sessions_order_id_len  CHECK (char_length(order_id) BETWEEN 1 AND 128),
    CONSTRAINT sessions_token_len     CHECK (char_length(token_hash) BETWEEN 32 AND 128),
    CONSTRAINT sessions_currency_len  CHECK (char_length(currency) BETWEEN 1 AND 8),
    CONSTRAINT sessions_amount_nonneg CHECK (amount_paisa >= 0),
    CONSTRAINT sessions_morph_nonneg  CHECK (morph_count >= 0),
    CONSTRAINT sessions_rail_known    CHECK (current_rail IN (
        'upi_intent', 'upi_collect', 'card', 'netbanking', 'wallet', 'none'))
);

CREATE INDEX IF NOT EXISTS ix_sessions_order_id ON sessions (order_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- audit_ledger
-- ---------------------------------------------------------------------------
-- The hash chain. seq is the chain position and is allocated under a
-- transaction-scoped advisory lock in Go (see appendAudit); PRIMARY KEY here is
-- both the UNIQUE(seq) index the chain relies on and the last line of defence
-- if that lock is ever lost, because a second writer racing to the same
-- position then fails loudly instead of forking the chain.
--
-- hash is UNIQUE too, which turns "replace this row with a copy of another row"
-- into a constraint violation rather than a subtle chain break.
--
-- There is deliberately no foreign key on incident_id: rejected webhooks and
-- breaker transitions are audited without an incident, and the trail has to
-- outlive anything it describes.
CREATE TABLE IF NOT EXISTS audit_ledger (
    seq         BIGINT      NOT NULL PRIMARY KEY,
    incident_id TEXT        NOT NULL DEFAULT '',
    kind        TEXT        NOT NULL,
    actor       TEXT        NOT NULL,
    detail      JSONB       NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    prev_hash   TEXT        NOT NULL,
    hash        TEXT        NOT NULL,
    CONSTRAINT audit_seq_positive  CHECK (seq > 0),
    CONSTRAINT audit_incident_len  CHECK (char_length(incident_id) <= 128),
    CONSTRAINT audit_kind_len      CHECK (char_length(kind) BETWEEN 1 AND 64),
    CONSTRAINT audit_actor_len     CHECK (char_length(actor) BETWEEN 1 AND 64),
    CONSTRAINT audit_hash_len      CHECK (char_length(hash) = 64),
    CONSTRAINT audit_prev_hash_len CHECK (char_length(prev_hash) = 64),
    CONSTRAINT audit_hash_unique   UNIQUE (hash)
);

CREATE INDEX IF NOT EXISTS ix_audit_incident_seq ON audit_ledger (incident_id, seq);

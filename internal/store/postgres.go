// Package store is the durable state boundary of ResilientMesh: PostgreSQL
// behind the domain.Store port.
//
// Three properties are load-bearing here and everything else follows from them.
// The transactional outbox means an incident and its queue event are written
// together or not at all. FOR UPDATE SKIP LOCKED plus a claim lease means many
// relays can drain that outbox without dispatching the same event twice. A
// transaction-scoped advisory lock around audit_ledger means the hash chain has
// exactly one writer at a time, because a chain built by concurrent writers is
// corrupt in a way that still verifies locally and cannot be repaired later.
//
// Every statement in this package is a constant with bind parameters. No SQL is
// ever assembled from a value, and pgx.ErrNoRows never escapes: callers see
// ErrNotFound.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Pool tuning. Twenty connections is comfortably above the edge server plus
// worker concurrency the mesh runs with, and far below what a small PostgreSQL
// instance starts thrashing at. Connections are recycled on a lifetime so a
// failover or a DNS change is picked up without a restart, and jittered so the
// whole pool does not reconnect in the same second.
const (
	poolMaxConns              = 20
	poolMinConns              = 2
	poolMaxConnLifetime       = 30 * time.Minute
	poolMaxConnLifetimeJitter = 5 * time.Minute
	poolMaxConnIdleTime       = 5 * time.Minute
	poolHealthCheckPeriod     = 30 * time.Second
	poolConnectTimeout        = 10 * time.Second
	poolPingTimeout           = 10 * time.Second

	// rollbackTimeout bounds the unwind of a transaction whose context is
	// already cancelled. Without its own deadline the rollback inherits the
	// dead context, fails instantly, and the connection is destroyed instead of
	// being returned to the pool.
	rollbackTimeout = 5 * time.Second
)

// Input bounds. The store is the last place an over-long or malformed value can
// be stopped before it becomes a row that every later read has to cope with, so
// it rejects rather than truncates anything identity-bearing.
const (
	maxIdentifierLen      = 128
	maxCurrencyLen        = 8
	maxMethodLen          = 32
	maxErrorCodeLen       = 64
	maxTopicLen           = 128
	maxFreeTextLen        = 512
	maxActorLen           = 64
	maxKindLen            = 64
	maxRawPayloadBytes    = 1 << 21 // 2 MiB, twice the webhook body cap
	maxOutboxPayloadBytes = 1 << 20
	maxAuditDetailBytes   = 1 << 16
	maxClaimBatch         = 1000
	maxListLimit          = 500
	maxDispatchIDs        = 10000
	maxAuditListEntries   = 1000

	// outboxClaimLeaseSeconds is how long a claimed batch stays invisible to
	// other relays. Long enough that a slow publish cannot lose its claim,
	// short enough that a relay killed mid-batch does not strand events.
	outboxClaimLeaseSeconds = 60
)

// auditChainLockKey is the ASCII of "RESMAUDI". Every audit append in the fleet
// serialises on this one key; see appendAudit for why that is not negotiable.
const auditChainLockKey int64 = 0x5245534d41554449

// Postgres implements domain.Store. It is safe for concurrent use: all state is
// the pgxpool, which is itself concurrent, and no method keeps a connection
// beyond the call.
type Postgres struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

var _ domain.Store = (*Postgres)(nil)

// New opens the pool and brings the schema up to date before returning, so a
// caller that gets a *Postgres has a database it can immediately write to.
// Failure closes the pool rather than leaking connections into a process that
// is about to exit.
//
// The DSN is never logged and never placed in an error message by this package;
// pgx redacts the password in its own parse errors.
func New(ctx context.Context, dsn string, logger *slog.Logger) (*Postgres, error) {
	if logger == nil {
		logger = slog.Default()
	}
	log := logger.With("component", "store")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse postgres dsn: %w", err)
	}
	cfg.MaxConns = poolMaxConns
	cfg.MinConns = poolMinConns
	cfg.MaxConnLifetime = poolMaxConnLifetime
	cfg.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	cfg.MaxConnIdleTime = poolMaxConnIdleTime
	cfg.HealthCheckPeriod = poolHealthCheckPeriod
	cfg.ConnConfig.ConnectTimeout = poolConnectTimeout

	// Server-side safety nets, set as startup parameters so every pooled
	// connection gets them. lock_timeout bounds the wait for the audit chain
	// lock: under pathological contention an append fails loudly instead of
	// piling up connections. idle_in_transaction_session_timeout kills a
	// client that opened a transaction and then hung, which matters most for
	// the audit lock, since holding it stalls every appender in the fleet.
	cfg.ConnConfig.RuntimeParams["application_name"] = "resilient-mesh"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "15000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, poolPingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connect to postgres: %w", err)
	}

	p := &Postgres{pool: pool, log: log}
	if err := applyMigrations(ctx, pool, log); err != nil {
		pool.Close()
		return nil, err
	}

	log.Info("postgres store ready",
		"host", cfg.ConnConfig.Host,
		"port", cfg.ConnConfig.Port,
		"database", cfg.ConnConfig.Database,
		"max_conns", cfg.MaxConns)
	return p, nil
}

// Ping reports whether the database is reachable; it backs /readyz.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}

// Close releases every pooled connection. It is safe to call more than once,
// which matters because both the managed-infra stop func and a deferred close
// in main may reach it during shutdown.
func (p *Postgres) Close() error {
	p.pool.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

// queryer is the subset of pgx shared by the pool and a transaction, so a
// statement can run in either without being written twice.
type queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// scanner unifies pgx.Row and pgx.Rows so one scan function serves point reads
// and list reads, and the two can never drift out of column order.
type scanner interface {
	Scan(dest ...any) error
}

// pgTx implements domain.Tx. It is unexported and holds the pgx transaction in
// an unexported field, so no caller can type-assert its way to the raw handle
// and commit half a batch — the outbox guarantee depends on that being
// impossible rather than merely discouraged.
type pgTx struct {
	tx pgx.Tx
}

var _ domain.Tx = (*pgTx)(nil)

// WithTx runs fn inside one transaction, committing only if fn returns nil.
func (p *Postgres) WithTx(ctx context.Context, fn func(ctx context.Context, tx domain.Tx) error) error {
	return p.runInTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return fn(ctx, &pgTx{tx: tx})
	})
}

// runInTx is the single place this package begins, commits, and unwinds a
// transaction, so the panic and rollback handling cannot be got wrong in one
// method and right in another.
func (p *Postgres) runInTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) (err error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if r := recover(); r != nil {
			// A panic must not leave an open transaction on a pooled
			// connection: it would hold locks — including the audit chain
			// lock — until the idle timeout fired. Unwind, then re-panic so
			// the caller's recovery still sees the original failure.
			if rbErr := rollback(ctx, tx); rbErr != nil {
				p.log.Error("rollback after panic failed", "error", rbErr)
			}
			panic(r)
		}
		if committed {
			return
		}
		if rbErr := rollback(ctx, tx); rbErr != nil {
			err = errors.Join(err, rbErr)
		}
	}()

	if fnErr := fn(ctx, tx); fnErr != nil {
		return fmt.Errorf("store: transaction rolled back: %w", fnErr)
	}
	if cErr := tx.Commit(ctx); cErr != nil {
		return fmt.Errorf("store: commit transaction: %w", cErr)
	}
	committed = true
	return nil
}

// rollback unwinds a transaction on a context that may already be dead, and
// treats an already-closed transaction as success so the deferred path can run
// unconditionally.
func rollback(ctx context.Context, tx pgx.Tx) error {
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := tx.Rollback(rbCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("store: rollback: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

const (
	insertIncidentSQL = `
INSERT INTO incidents (
    id, payment_id, order_id, subscription_id, event_id, amount_paisa, currency, method,
    issuer_key, error_code, state, attempt_count, is_recurring, raw_payload, received_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, COALESCE($15, now()), COALESCE($16, now()))`

	selectIncidentByIDSQL = `
SELECT id, payment_id, order_id, subscription_id, event_id, amount_paisa, currency, method,
       issuer_key, error_code, state, attempt_count, is_recurring, raw_payload, received_at, updated_at
  FROM incidents WHERE id = $1`

	selectIncidentByEventIDSQL = `
SELECT id, payment_id, order_id, subscription_id, event_id, amount_paisa, currency, method,
       issuer_key, error_code, state, attempt_count, is_recurring, raw_payload, received_at, updated_at
  FROM incidents WHERE event_id = $1`

	listIncidentsSQL = `
SELECT id, payment_id, order_id, subscription_id, event_id, amount_paisa, currency, method,
       issuer_key, error_code, state, attempt_count, is_recurring, raw_payload, received_at, updated_at
  FROM incidents ORDER BY received_at DESC, id DESC LIMIT $1`

	updateIncidentStateSQL = `UPDATE incidents SET state = $2, updated_at = now() WHERE id = $1`

	// The increment doubles as the claim. The WHERE clause is what makes it one:
	// only an incident that is waiting for work can be advanced, so a second
	// consumer holding a redelivery of the same message updates zero rows and
	// learns that someone else owns it. Splitting the check from the increment —
	// read the state, decide, then increment — is the version that lets two
	// consumers both see RECEIVED and both spend a gateway fee.
	incrementIncidentAttemptsSQL = `
UPDATE incidents
   SET attempt_count = attempt_count + 1, state = 'EXECUTING', updated_at = now()
 WHERE id = $1 AND state IN ('RECEIVED', 'SCHEDULED')
RETURNING attempt_count`
)

// InsertIncident writes the incident. A second insert of the same event_id is
// rejected by the unique index and surfaces as ErrConflict, which is how the
// ingest replay guard stays correct even when two edge processes race on the
// same Razorpay redelivery.
func (t *pgTx) InsertIncident(ctx context.Context, in domain.Incident) error {
	if err := validateIncident(in); err != nil {
		return err
	}
	_, err := t.tx.Exec(ctx, insertIncidentSQL,
		in.ID, in.PaymentID, in.OrderID, in.SubscriptionID, in.EventID, in.AmountPaisa,
		in.Currency, in.Method, in.IssuerKey, in.ErrorCode, string(in.State), in.AttemptCount,
		in.IsRecurring, []byte(in.RawPayload), timeParam(in.ReceivedAt), timeParam(in.UpdatedAt))
	return classify("store: insert incident", err)
}

// GetIncident reads one incident by its internal id.
func (p *Postgres) GetIncident(ctx context.Context, id string) (domain.Incident, error) {
	if err := checkText("id", id, 1, maxIdentifierLen); err != nil {
		return domain.Incident{}, err
	}
	in, err := scanIncident(p.pool.QueryRow(ctx, selectIncidentByIDSQL, id))
	if err != nil {
		return domain.Incident{}, classify("store: get incident", err)
	}
	return in, nil
}

// GetIncidentByEventID resolves the Razorpay idempotency key. ErrNotFound here
// is the ingest path's "this is a new event" signal, so it must never be
// confused with a transport failure.
func (p *Postgres) GetIncidentByEventID(ctx context.Context, eventID string) (domain.Incident, error) {
	if err := checkText("event_id", eventID, 1, maxIdentifierLen); err != nil {
		return domain.Incident{}, err
	}
	in, err := scanIncident(p.pool.QueryRow(ctx, selectIncidentByEventIDSQL, eventID))
	if err != nil {
		return domain.Incident{}, classify("store: get incident by event id", err)
	}
	return in, nil
}

// UpdateIncidentState advances the lifecycle. Unknown states are refused in Go
// as well as by the table constraint, so a typo in a caller cannot park an
// incident in a state no consumer handles.
func (p *Postgres) UpdateIncidentState(ctx context.Context, id string, state domain.IncidentState) error {
	if err := checkText("id", id, 1, maxIdentifierLen); err != nil {
		return err
	}
	if !validIncidentState(state) {
		return invalid("state", "is not a known incident state")
	}
	tag, err := p.pool.Exec(ctx, updateIncidentStateSQL, id, string(state))
	if err != nil {
		return classify("store: update incident state", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: update incident state: %w", ErrNotFound)
	}
	return nil
}

// IncrementIncidentAttempts claims an incident and returns its new attempt
// number, or ErrConflict when another consumer already holds it.
//
// The read-modify-write happens in the database because the stop rule that caps
// retries is only as good as this counter: two workers doing it in Go would
// both see the same value and both be allowed another attempt. For the same
// reason it also moves the incident to EXECUTING, so the claim and the count
// advance together and at-least-once delivery cannot buy a second debit.
//
// ErrConflict here is ordinary, not exceptional. It is what a duplicate
// delivery looks like, and duplicate delivery is a guarantee of the transport
// rather than a fault.
func (p *Postgres) IncrementIncidentAttempts(ctx context.Context, id string) (int, error) {
	if err := checkText("id", id, 1, maxIdentifierLen); err != nil {
		return 0, err
	}
	var attempts int
	err := p.pool.QueryRow(ctx, incrementIncidentAttemptsSQL, id).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either another consumer holds it or it has already concluded. Both are
		// "not mine to run", and the caller treats them the same way.
		return 0, fmt.Errorf("store: increment incident attempts: %w", ErrConflict)
	}
	if err != nil {
		return 0, classify("store: increment incident attempts", err)
	}
	return attempts, nil
}

// ListIncidents feeds the ops console, newest first.
func (p *Postgres) ListIncidents(ctx context.Context, limit int) ([]domain.Incident, error) {
	rows, err := p.pool.Query(ctx, listIncidentsSQL, boundLimit(limit, maxListLimit))
	if err != nil {
		return nil, classify("store: list incidents", err)
	}
	defer rows.Close()

	out := make([]domain.Incident, 0, 16)
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, classify("store: scan incident", err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("store: list incidents", err)
	}
	return out, nil
}

func scanIncident(s scanner) (domain.Incident, error) {
	var (
		in      domain.Incident
		state   string
		payload []byte
	)
	if err := s.Scan(&in.ID, &in.PaymentID, &in.OrderID, &in.SubscriptionID, &in.EventID,
		&in.AmountPaisa, &in.Currency, &in.Method, &in.IssuerKey, &in.ErrorCode, &state,
		&in.AttemptCount, &in.IsRecurring, &payload, &in.ReceivedAt, &in.UpdatedAt); err != nil {
		return domain.Incident{}, err
	}
	in.State = domain.IncidentState(state)
	in.RawPayload = domain.RawJSON(payload)
	in.ReceivedAt = in.ReceivedAt.UTC()
	in.UpdatedAt = in.UpdatedAt.UTC()
	return in, nil
}

func validateIncident(in domain.Incident) error {
	if err := checkText("id", in.ID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("payment_id", in.PaymentID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("event_id", in.EventID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("order_id", in.OrderID, 0, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("subscription_id", in.SubscriptionID, 0, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("currency", in.Currency, 1, maxCurrencyLen); err != nil {
		return err
	}
	if err := checkText("method", in.Method, 0, maxMethodLen); err != nil {
		return err
	}
	if err := checkText("issuer_key", in.IssuerKey, 0, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("error_code", in.ErrorCode, 0, maxErrorCodeLen); err != nil {
		return err
	}
	if in.AmountPaisa < 0 {
		return invalid("amount_paisa", "is negative")
	}
	if in.AttemptCount < 0 {
		return invalid("attempt_count", "is negative")
	}
	if !validIncidentState(in.State) {
		return invalid("state", "is not a known incident state")
	}
	return checkJSON("raw_payload", in.RawPayload, maxRawPayloadBytes, true)
}

func validIncidentState(s domain.IncidentState) bool {
	switch s {
	case domain.IncidentReceived, domain.IncidentDiagnosed, domain.IncidentGated,
		domain.IncidentScheduled, domain.IncidentExecuting, domain.IncidentRecovered,
		domain.IncidentAbandoned, domain.IncidentAbstained:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Outbox
// ---------------------------------------------------------------------------

const (
	insertOutboxSQL = `
INSERT INTO outbox_events (incident_id, topic, payload, state, attempts, last_error, created_at)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, now()))`

	// claimOutboxBatchSQL takes a batch for this relay and leases it in one
	// statement. The inner SELECT does the work:
	//
	//	FOR UPDATE      row locks so a concurrent claim cannot read these rows
	//	SKIP LOCKED     and does not block on them either, it moves on
	//	ORDER BY id     oldest first, and a stable lock order between relays
	//	LIMIT $1        bounded work per poll
	//
	// The outer UPDATE extends the claim past the transaction with a lease, so
	// the rows stay invisible to other relays through the publish that follows.
	//
	// The lease is all it sets. Charging an attempt here would spend a row's
	// retry budget on merely being looked at, so a broker outage — which makes
	// every claim fail for reasons that have nothing to do with any row — would
	// exhaust every budget in the table and park work that was never poison.
	// Attempts are charged in RecordOutboxFailure, where the failure is known
	// to be attributable to the row.
	claimOutboxBatchSQL = `
WITH claimed AS (
    SELECT id FROM outbox_events WHERE state='PENDING' AND claimed_until <= now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1
)
UPDATE outbox_events o
   SET claimed_until = now() + ($2::int * INTERVAL '1 second')
  FROM claimed c
 WHERE o.id = c.id
RETURNING o.id, o.incident_id, o.topic, o.payload, o.state, o.attempts, o.last_error, o.created_at, o.dispatched_at`

	markOutboxDispatchedSQL = `
UPDATE outbox_events SET state = 'DISPATCHED', dispatched_at = now(), last_error = ''
 WHERE id = ANY($1) AND state <> 'DISPATCHED'`

	markOutboxFailedSQL = `
UPDATE outbox_events SET state = 'FAILED', last_error = $2, claimed_until = now() WHERE id = $1`

	// recordOutboxFailureSQL charges one attempt to a row and releases its
	// lease, leaving it PENDING so the next poll re-claims it. This is the
	// non-terminal failure path; MarkOutboxFailed is the terminal one.
	recordOutboxFailureSQL = `
UPDATE outbox_events
   SET attempts = attempts + 1, last_error = $2, claimed_until = now()
 WHERE id = $1 AND state = 'PENDING'`

	// releaseOutboxClaimSQL hands rows back untouched. The queue was
	// unreachable, which says nothing about these rows, so their attempt budget
	// is not charged.
	releaseOutboxClaimSQL = `
UPDATE outbox_events SET claimed_until = now() WHERE id = ANY($1) AND state = 'PENDING'`

	outboxDepthSQL = `
SELECT count(*) FILTER (WHERE state = 'PENDING'), count(*) FILTER (WHERE state = 'FAILED')
  FROM outbox_events`
)

// InsertOutboxEvent queues the work item. It exists only on the transaction
// interface because writing it outside the incident's transaction would
// reintroduce the dual-write failure the outbox pattern is here to remove.
func (t *pgTx) InsertOutboxEvent(ctx context.Context, ev domain.OutboxEvent) error {
	if err := checkText("incident_id", ev.IncidentID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("topic", ev.Topic, 1, maxTopicLen); err != nil {
		return err
	}
	if err := checkJSON("payload", ev.Payload, maxOutboxPayloadBytes, true); err != nil {
		return err
	}
	state := ev.State
	if state == "" {
		state = domain.OutboxPending
	}
	if !validOutboxState(state) {
		return invalid("state", "is not a known outbox state")
	}
	if ev.Attempts < 0 {
		return invalid("attempts", "is negative")
	}
	_, err := t.tx.Exec(ctx, insertOutboxSQL,
		ev.IncidentID, ev.Topic, []byte(ev.Payload), string(state), ev.Attempts,
		truncate(ev.LastError, maxFreeTextLen), timeParam(ev.CreatedAt))
	return classify("store: insert outbox event", err)
}

// ClaimOutboxBatch takes up to limit pending events for this relay.
//
// The race this prevents: two relays polling the same table both read the same
// pending rows, both publish them, and every consumer sees each incident twice
// — on a payment system that is a duplicate retry against a real gateway.
// FOR UPDATE SKIP LOCKED makes the read itself exclusive, so the second relay
// steps over the locked rows instead of reading or waiting for them, and the
// claim lease keeps them exclusive after this transaction commits, through the
// publish, until the batch is marked dispatched or the lease expires.
func (p *Postgres) ClaimOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	var out []domain.OutboxEvent
	err := p.runInTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, claimOutboxBatchSQL, boundLimit(limit, maxClaimBatch), outboxClaimLeaseSeconds)
		if err != nil {
			return classify("store: claim outbox batch", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				ev    domain.OutboxEvent
				state string
				load  []byte
			)
			if err := rows.Scan(&ev.ID, &ev.IncidentID, &ev.Topic, &load, &state,
				&ev.Attempts, &ev.LastError, &ev.CreatedAt, &ev.DispatchedAt); err != nil {
				return classify("store: scan outbox event", err)
			}
			ev.State = domain.OutboxState(state)
			ev.Payload = domain.RawJSON(load)
			ev.CreatedAt = ev.CreatedAt.UTC()
			out = append(out, ev)
		}
		return classify("store: claim outbox batch", rows.Err())
	})
	if err != nil {
		return nil, err
	}
	// UPDATE ... RETURNING has no defined row order; the relay publishes in id
	// order so events reach the queue in the order they were produced.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// MarkOutboxDispatched closes out a published batch. It is idempotent: rows
// already dispatched are left alone, because a relay that crashed between
// publishing and marking will retry the whole batch after its lease expires.
func (p *Postgres) MarkOutboxDispatched(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) > maxDispatchIDs {
		return invalid("ids", "exceeds the maximum batch size")
	}
	tag, err := p.pool.Exec(ctx, markOutboxDispatchedSQL, ids)
	if err != nil {
		return classify("store: mark outbox dispatched", err)
	}
	if n := tag.RowsAffected(); n != int64(len(ids)) {
		// Not an error — a redelivered batch legitimately hits this — but it is
		// worth seeing, because a persistent gap means events are vanishing.
		p.log.Warn("outbox rows already dispatched or missing",
			"requested", len(ids), "updated", n)
	}
	return nil
}

// MarkOutboxFailed parks a poison event. The cause is truncated rather than
// rejected: it is gateway or driver text, and losing the whole failure record
// because the message was long would hide the very thing being recorded.
// RecordOutboxFailure charges one attempt against a row and hands it back.
//
// The row stays PENDING: a single failed publish is not a verdict on the row,
// it is one data point, and the caller decides when the accumulated count means
// the row is poison. Before this existed the relay reached for MarkOutboxFailed
// on every failure, which sets state to FAILED — so the very first failure
// parked the row permanently, the eight-attempt budget was unreachable, and a
// transient broker outage silently destroyed every event it touched.
//
// Deterministic simulation found that: the NO_EVENT_LOST invariant reported
// twenty thousand dead-lettered rows under an injected queue outage, from four
// hundred incidents.
func (p *Postgres) RecordOutboxFailure(ctx context.Context, id int64, cause string) error {
	if _, err := p.pool.Exec(ctx, recordOutboxFailureSQL, id, truncate(cause, maxFreeTextLen)); err != nil {
		return classify("store: record outbox failure", err)
	}
	// A zero row count means the row was concurrently dispatched or parked.
	// Neither is an error worth propagating: the caller's next poll will see
	// the current state, and failing here would turn a benign race into an
	// error log during exactly the incident that produced the race.
	return nil
}

// ReleaseOutboxClaim returns leased rows without charging them.
//
// It is the transport-failure path: the queue could not be reached, which is a
// statement about the queue and not about these rows, so their budgets are
// untouched and they become claimable again immediately. The relay's own
// jittered backoff is what stops that becoming a hot loop against a dead
// broker.
func (p *Postgres) ReleaseOutboxClaim(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := p.pool.Exec(ctx, releaseOutboxClaimSQL, ids); err != nil {
		return classify("store: release outbox claim", err)
	}
	return nil
}

func (p *Postgres) MarkOutboxFailed(ctx context.Context, id int64, cause string) error {
	tag, err := p.pool.Exec(ctx, markOutboxFailedSQL, id, truncate(cause, maxFreeTextLen))
	if err != nil {
		return classify("store: mark outbox failed", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: mark outbox failed: %w", ErrNotFound)
	}
	return nil
}

// OutboxDepth backs the queue-depth gauge on the ops console: pending is the
// backlog, failed is the poison pile that needs a human.
func (p *Postgres) OutboxDepth(ctx context.Context) (int, int, error) {
	var pending, failed int64
	if err := p.pool.QueryRow(ctx, outboxDepthSQL).Scan(&pending, &failed); err != nil {
		return 0, 0, classify("store: outbox depth", err)
	}
	return int(pending), int(failed), nil
}

func validOutboxState(s domain.OutboxState) bool {
	switch s {
	case domain.OutboxPending, domain.OutboxDispatched, domain.OutboxFailed:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Mandates
// ---------------------------------------------------------------------------

const (
	upsertMandateSQL = `
INSERT INTO mandates (
    subscription_id, customer_id, amount_paisa, last_attempt_at, next_eligible_at,
    attempts_in_cycle, pre_debit_notified_at, cycle_key, category, halted, halt_reason, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12, now()))
ON CONFLICT (subscription_id) DO UPDATE SET
    customer_id           = EXCLUDED.customer_id,
    amount_paisa          = EXCLUDED.amount_paisa,
    last_attempt_at       = EXCLUDED.last_attempt_at,
    next_eligible_at      = EXCLUDED.next_eligible_at,
    attempts_in_cycle     = EXCLUDED.attempts_in_cycle,
    pre_debit_notified_at = EXCLUDED.pre_debit_notified_at,
    cycle_key             = EXCLUDED.cycle_key,
    category              = EXCLUDED.category,
    halted                = EXCLUDED.halted,
    halt_reason           = EXCLUDED.halt_reason,
    updated_at            = EXCLUDED.updated_at`

	selectMandateSQL = `
SELECT subscription_id, customer_id, amount_paisa, last_attempt_at, next_eligible_at,
       attempts_in_cycle, pre_debit_notified_at, cycle_key, category, halted, halt_reason, updated_at
  FROM mandates WHERE subscription_id = $1`
)

// UpsertMandate keeps mandate compliance state in step with the incident that
// changed it, in the same transaction, so a crash cannot leave an attempt
// recorded without its cooling window.
func (t *pgTx) UpsertMandate(ctx context.Context, m domain.MandateRecord) error {
	args, err := mandateArgs(m)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx, upsertMandateSQL, args...)
	return classify("store: upsert mandate", err)
}

// SaveMandate is the same upsert outside a transaction, for the worker paths
// that only touch the mandate.
func (p *Postgres) SaveMandate(ctx context.Context, m domain.MandateRecord) error {
	args, err := mandateArgs(m)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, upsertMandateSQL, args...)
	return classify("store: save mandate", err)
}

// GetMandate reads mandate state; ErrNotFound means this subscription has no
// recorded cycle yet, which the gatekeeper treats as "first attempt".
func (p *Postgres) GetMandate(ctx context.Context, subscriptionID string) (domain.MandateRecord, error) {
	if err := checkText("subscription_id", subscriptionID, 1, maxIdentifierLen); err != nil {
		return domain.MandateRecord{}, err
	}
	var (
		m        domain.MandateRecord
		category string
	)
	err := p.pool.QueryRow(ctx, selectMandateSQL, subscriptionID).Scan(
		&m.SubscriptionID, &m.CustomerID, &m.AmountPaisa, &m.LastAttemptAt, &m.NextEligibleAt,
		&m.AttemptsInCycle, &m.PreDebitNotifiedAt, &m.CycleKey, &category, &m.Halted,
		&m.HaltReason, &m.UpdatedAt)
	if err != nil {
		return domain.MandateRecord{}, classify("store: get mandate", err)
	}
	m.Category = domain.ParseMandateCategory(category)
	m.LastAttemptAt = utcPtr(m.LastAttemptAt)
	m.NextEligibleAt = utcPtr(m.NextEligibleAt)
	m.PreDebitNotifiedAt = utcPtr(m.PreDebitNotifiedAt)
	m.UpdatedAt = m.UpdatedAt.UTC()
	return m, nil
}

func mandateArgs(m domain.MandateRecord) ([]any, error) {
	if err := checkText("subscription_id", m.SubscriptionID, 1, maxIdentifierLen); err != nil {
		return nil, err
	}
	if err := checkText("customer_id", m.CustomerID, 0, maxIdentifierLen); err != nil {
		return nil, err
	}
	if err := checkText("cycle_key", m.CycleKey, 0, maxIdentifierLen); err != nil {
		return nil, err
	}
	if m.AmountPaisa < 0 {
		return nil, invalid("amount_paisa", "is negative")
	}
	if m.AttemptsInCycle < 0 {
		return nil, invalid("attempts_in_cycle", "is negative")
	}
	// ParseMandateCategory rather than a validity check: an unrecognised category
	// resolves to the general, stricter AFA ceiling. Widening a regulatory limit
	// because a field was misspelled is the one outcome that is never acceptable.
	category := domain.ParseMandateCategory(string(m.Category))
	return []any{
		m.SubscriptionID, m.CustomerID, m.AmountPaisa, timePtrParam(m.LastAttemptAt),
		timePtrParam(m.NextEligibleAt), m.AttemptsInCycle, timePtrParam(m.PreDebitNotifiedAt),
		m.CycleKey, string(category), m.Halted, truncate(m.HaltReason, maxFreeTextLen),
		timeParam(m.UpdatedAt),
	}, nil
}

// ---------------------------------------------------------------------------
// Attempts
// ---------------------------------------------------------------------------

const (
	insertAttemptSQL = `
INSERT INTO attempts (
    incident_id, attempt_number, action, rail, presentation, amount_paisa, succeeded,
    gateway_fee_paisa, friction_paisa, error_code, started_at, completed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, now()), COALESCE($12, now()))
ON CONFLICT (incident_id, attempt_number) DO NOTHING`

	listAttemptsSQL = `
SELECT id, incident_id, attempt_number, action, rail, presentation, amount_paisa, succeeded,
       gateway_fee_paisa, friction_paisa, error_code, started_at, completed_at
  FROM attempts WHERE incident_id = $1 ORDER BY attempt_number, id`
)

// RecordAttempt stores an executed attempt and its economics, idempotently.
//
// The caller retries this until it commits, because losing the record of a
// debit is worse than the debit. That retry is only safe if a second insert of
// the same attempt is a no-op, so the uniqueness of (incident_id,
// attempt_number) is enforced by the database and the conflict is swallowed
// here. Swallowing it is correct rather than lazy: the row already present
// describes the same attempt, and the alternative — an error the caller must
// distinguish from a real failure — is how a retry loop turns into a stall.
//
// Fees and friction
// are persisted per attempt rather than derived later, so the NRCV benchmark
// reports what the run actually cost and not what today's cost model says it
// would have cost.
func (p *Postgres) RecordAttempt(ctx context.Context, a domain.AttemptRecord) error {
	if err := checkText("incident_id", a.IncidentID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("error_code", a.ErrorCode, 0, maxErrorCodeLen); err != nil {
		return err
	}
	if a.AttemptNumber < 1 {
		return invalid("attempt_number", "is below one")
	}
	if a.AmountPaisa < 0 || a.GatewayFeePaisa < 0 || a.FrictionPaisa < 0 {
		return invalid("amount_paisa", "is negative")
	}
	if !a.Action.Valid() {
		return invalid("action", "is not a known action")
	}
	rail := a.Rail
	if rail == "" {
		rail = domain.RailNone
	}
	if !rail.Valid() {
		return invalid("rail", "is not a known rail")
	}
	// Presentation is how the instrument was offered to the issuer. It is
	// recorded per attempt because a retry that presents the same credential the
	// same way is a strictly weaker retry, and the benchmark cannot tell the two
	// apart afterwards unless it was stored at the time.
	presentation := a.Presentation
	if presentation == "" {
		presentation = domain.PresentationUnchanged
	}
	if !presentation.Valid() {
		return invalid("presentation", "is not a known instrument presentation")
	}
	_, err := p.pool.Exec(ctx, insertAttemptSQL,
		a.IncidentID, a.AttemptNumber, string(a.Action), string(rail), string(presentation),
		a.AmountPaisa, a.Succeeded, a.GatewayFeePaisa, a.FrictionPaisa, a.ErrorCode,
		timeParam(a.StartedAt), timeParam(a.CompletedAt))
	return classify("store: record attempt", err)
}

// ListAttempts returns an incident's attempts in execution order.
func (p *Postgres) ListAttempts(ctx context.Context, incidentID string) ([]domain.AttemptRecord, error) {
	if err := checkText("incident_id", incidentID, 1, maxIdentifierLen); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, listAttemptsSQL, incidentID)
	if err != nil {
		return nil, classify("store: list attempts", err)
	}
	defer rows.Close()

	out := make([]domain.AttemptRecord, 0, 4)
	for rows.Next() {
		var (
			a                          domain.AttemptRecord
			action, rail, presentation string
		)
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.AttemptNumber, &action, &rail, &presentation,
			&a.AmountPaisa, &a.Succeeded, &a.GatewayFeePaisa, &a.FrictionPaisa,
			&a.ErrorCode, &a.StartedAt, &a.CompletedAt); err != nil {
			return nil, classify("store: scan attempt", err)
		}
		a.Action = domain.Action(action)
		a.Rail = domain.Rail(rail)
		a.Presentation = domain.InstrumentPresentation(presentation)
		a.StartedAt = a.StartedAt.UTC()
		a.CompletedAt = a.CompletedAt.UTC()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("store: list attempts", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

const (
	insertSessionSQL = `
INSERT INTO sessions (id, order_id, token_hash, current_rail, amount_paisa, currency,
                      active, morph_count, created_at, expires_at, closed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()), $10, $11)`

	selectSessionSQL = `
SELECT id, order_id, token_hash, current_rail, amount_paisa, currency, active,
       morph_count, created_at, expires_at, closed_at
  FROM sessions WHERE id = $1`

	// A shopper who reloads checkout gets a new session for the same order, so
	// the live one is what a morph must target: active first, then newest.
	selectSessionByOrderSQL = `
SELECT id, order_id, token_hash, current_rail, amount_paisa, currency, active,
       morph_count, created_at, expires_at, closed_at
  FROM sessions WHERE order_id = $1 ORDER BY active DESC, created_at DESC LIMIT 1`

	// token_hash is only overwritten when a new one is supplied: a caller that
	// blanks the field must not be able to leave a session whose stored digest
	// is empty, because that turns the stream's bearer check into a comparison
	// against nothing.
	updateSessionSQL = `
UPDATE sessions SET
    order_id     = $2,
    token_hash   = CASE WHEN $3 = '' THEN token_hash ELSE $3 END,
    current_rail = $4,
    amount_paisa = $5,
    currency     = $6,
    active       = $7,
    morph_count  = $8,
    expires_at   = $9,
    closed_at    = $10
 WHERE id = $1`
)

// CreateSession records a live checkout. Only the token digest is stored, so a
// database read cannot be replayed against the SSE stream endpoint.
func (p *Postgres) CreateSession(ctx context.Context, s domain.SessionRecord) error {
	if err := validateSession(s); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, insertSessionSQL,
		s.ID, s.OrderID, s.TokenHash, string(railOrNone(s.CurrentRail)), s.AmountPaisa,
		s.Currency, s.Active, s.MorphCount, timeParam(s.CreatedAt), s.ExpiresAt.UTC(),
		timePtrParam(s.ClosedAt))
	return classify("store: create session", err)
}

// GetSession reads a session by id.
func (p *Postgres) GetSession(ctx context.Context, id string) (domain.SessionRecord, error) {
	if err := checkText("id", id, 1, maxIdentifierLen); err != nil {
		return domain.SessionRecord{}, err
	}
	s, err := scanSession(p.pool.QueryRow(ctx, selectSessionSQL, id))
	if err != nil {
		return domain.SessionRecord{}, classify("store: get session", err)
	}
	return s, nil
}

// GetSessionByOrder finds the session a rail morph should be delivered to.
func (p *Postgres) GetSessionByOrder(ctx context.Context, orderID string) (domain.SessionRecord, error) {
	if err := checkText("order_id", orderID, 1, maxIdentifierLen); err != nil {
		return domain.SessionRecord{}, err
	}
	s, err := scanSession(p.pool.QueryRow(ctx, selectSessionByOrderSQL, orderID))
	if err != nil {
		return domain.SessionRecord{}, classify("store: get session by order", err)
	}
	return s, nil
}

// UpdateSession persists rail morphs and closure.
func (p *Postgres) UpdateSession(ctx context.Context, s domain.SessionRecord) error {
	if err := checkText("id", s.ID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("order_id", s.OrderID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("currency", s.Currency, 1, maxCurrencyLen); err != nil {
		return err
	}
	if s.TokenHash != "" {
		if err := checkText("token_hash", s.TokenHash, 32, maxIdentifierLen); err != nil {
			return err
		}
	}
	if s.AmountPaisa < 0 || s.MorphCount < 0 {
		return invalid("amount_paisa", "is negative")
	}
	rail := railOrNone(s.CurrentRail)
	if !rail.Valid() {
		return invalid("current_rail", "is not a known rail")
	}
	tag, err := p.pool.Exec(ctx, updateSessionSQL,
		s.ID, s.OrderID, s.TokenHash, string(rail), s.AmountPaisa, s.Currency,
		s.Active, s.MorphCount, s.ExpiresAt.UTC(), timePtrParam(s.ClosedAt))
	if err != nil {
		return classify("store: update session", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: update session: %w", ErrNotFound)
	}
	return nil
}

func scanSession(s scanner) (domain.SessionRecord, error) {
	var (
		rec  domain.SessionRecord
		rail string
	)
	if err := s.Scan(&rec.ID, &rec.OrderID, &rec.TokenHash, &rail, &rec.AmountPaisa,
		&rec.Currency, &rec.Active, &rec.MorphCount, &rec.CreatedAt, &rec.ExpiresAt,
		&rec.ClosedAt); err != nil {
		return domain.SessionRecord{}, err
	}
	rec.CurrentRail = domain.Rail(rail)
	rec.CreatedAt = rec.CreatedAt.UTC()
	rec.ExpiresAt = rec.ExpiresAt.UTC()
	rec.ClosedAt = utcPtr(rec.ClosedAt)
	return rec, nil
}

func validateSession(s domain.SessionRecord) error {
	if err := checkText("id", s.ID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("order_id", s.OrderID, 1, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("token_hash", s.TokenHash, 32, maxIdentifierLen); err != nil {
		return err
	}
	if err := checkText("currency", s.Currency, 1, maxCurrencyLen); err != nil {
		return err
	}
	if s.AmountPaisa < 0 {
		return invalid("amount_paisa", "is negative")
	}
	if s.MorphCount < 0 {
		return invalid("morph_count", "is negative")
	}
	if s.ExpiresAt.IsZero() {
		return invalid("expires_at", "is unset")
	}
	if !railOrNone(s.CurrentRail).Valid() {
		return invalid("current_rail", "is not a known rail")
	}
	return nil
}

func railOrNone(r domain.Rail) domain.Rail {
	if r == "" {
		return domain.RailNone
	}
	return r
}

// ---------------------------------------------------------------------------
// Audit ledger
// ---------------------------------------------------------------------------

const (
	// auditHeadForAppendSQL fetches everything the next link needs in one round
	// trip: the current head (or the genesis anchor when the ledger is empty),
	// the canonical rendering of the detail document, and the server clock.
	//
	// The canonicalisation matters. JSONB is a parsed representation, so what
	// comes back out of the column is not the byte string that went in — keys
	// are reordered and whitespace is dropped. Hashing the caller's bytes would
	// therefore produce a digest that no later read can reproduce, and Verify
	// would report the whole ledger as tampered. Hashing what PostgreSQL will
	// actually store makes the chain reproducible by anyone reading the table.
	auditHeadForAppendSQL = `
SELECT COALESCE(h.seq, 0), COALESCE(h.hash, $1), $2::jsonb::text, clock_timestamp()
  FROM (VALUES (1)) AS anchor(x)
  LEFT JOIN (SELECT seq, hash FROM audit_ledger ORDER BY seq DESC LIMIT 1) AS h ON TRUE`

	insertAuditSQL = `
INSERT INTO audit_ledger (seq, incident_id, kind, actor, detail, occurred_at, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	selectAuditHeadSQL = `
SELECT seq, incident_id, kind, actor, detail, occurred_at, prev_hash, hash
  FROM audit_ledger ORDER BY seq DESC LIMIT 1`

	streamAuditSQL = `
SELECT seq, incident_id, kind, actor, detail, occurred_at, prev_hash, hash
  FROM audit_ledger ORDER BY seq ASC`

	listAuditByIncidentSQL = `
SELECT seq, incident_id, kind, actor, detail, occurred_at, prev_hash, hash
  FROM audit_ledger WHERE incident_id = $1 ORDER BY seq ASC LIMIT $2`

	mutateAuditDetailSQL = `UPDATE audit_ledger SET detail = $2 WHERE seq = $1`
)

// AppendAudit writes a ledger entry inside the caller's transaction, so a
// decision and its audit record commit together.
//
// Note that the advisory lock taken here is transaction-scoped: it is held
// until the enclosing transaction ends, which serialises every other appender
// in the fleet for that duration. That is the deliberate price of a linear
// chain, and the reason transactions that append audit entries should stay
// short.
//
// The domain.Tx contract returns only an error, so the allocated seq and hash
// are not visible to the caller here; use AppendAuditRow when they are needed.
func (t *pgTx) AppendAudit(ctx context.Context, e domain.AuditEntry) error {
	_, err := appendAudit(ctx, t.tx, e)
	return err
}

// AppendAuditRow appends one entry in its own transaction and returns it with
// the chain fields filled in.
//
// This is where the correctness of the whole ledger lives. Two appenders that
// read the head concurrently allocate the same seq and the same prev_hash: one
// insert then loses the primary key race and its decision goes unrecorded, or —
// if the chain were keyed any more loosely — both land and the chain forks into
// two entries claiming the same predecessor, which verifies fine in isolation
// and is undetectable afterwards. pg_advisory_xact_lock makes read-head and
// insert-entry a single critical section across every process on the database,
// and it is released automatically when the transaction ends, so a crashed
// appender cannot wedge the ledger.
func (p *Postgres) AppendAuditRow(ctx context.Context, e domain.AuditEntry) (domain.AuditEntry, error) {
	var out domain.AuditEntry
	err := p.runInTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = appendAudit(ctx, tx, e)
		return err
	})
	if err != nil {
		return domain.AuditEntry{}, err
	}
	return out, nil
}

func appendAudit(ctx context.Context, q queryer, e domain.AuditEntry) (domain.AuditEntry, error) {
	if err := checkText("kind", string(e.Kind), 1, maxKindLen); err != nil {
		return domain.AuditEntry{}, err
	}
	if err := checkText("actor", e.Actor, 1, maxActorLen); err != nil {
		return domain.AuditEntry{}, err
	}
	if err := checkText("incident_id", e.IncidentID, 0, maxIdentifierLen); err != nil {
		return domain.AuditEntry{}, err
	}
	detail := []byte(e.Detail)
	if len(detail) == 0 {
		detail = []byte("{}")
	}
	if err := checkJSON("detail", detail, maxAuditDetailBytes, true); err != nil {
		return domain.AuditEntry{}, err
	}

	// The lock is taken in its own round trip on purpose: folding it into the
	// head query as another select-list item would not order it before the
	// table read, because PostgreSQL evaluates the FROM clause first. The head
	// could then be read before the lock was held, which is exactly the race
	// this is here to prevent.
	if _, err := q.Exec(ctx, advisoryLockSQL, auditChainLockKey); err != nil {
		return domain.AuditEntry{}, classify("store: take audit chain lock", err)
	}

	var (
		headSeq   int64
		prevHash  string
		canonical string
		dbNow     time.Time
	)
	if err := q.QueryRow(ctx, auditHeadForAppendSQL, domain.GenesisHash, detail).
		Scan(&headSeq, &prevHash, &canonical, &dbNow); err != nil {
		return domain.AuditEntry{}, classify("store: read audit head", err)
	}

	at := e.At
	if at.IsZero() {
		at = dbNow
	}
	e.Seq = headSeq + 1
	e.PrevHash = prevHash
	e.Detail = domain.RawJSON(canonical)
	// TIMESTAMPTZ keeps microseconds; the domain hash absorbs nanoseconds.
	// Truncating before hashing is what stops every entry from failing
	// verification the moment it is read back from the database.
	e.At = at.UTC().Truncate(time.Microsecond)
	e.Hash = e.ComputeHash()

	if _, err := q.Exec(ctx, insertAuditSQL, e.Seq, e.IncidentID, string(e.Kind), e.Actor,
		[]byte(e.Detail), e.At, e.PrevHash, e.Hash); err != nil {
		return domain.AuditEntry{}, classify("store: insert audit entry", err)
	}
	return e, nil
}

// AuditHead returns the newest entry, or ErrNotFound on an empty ledger. It is
// the cheap health check for the chain and the anchor an operator compares
// against a previously published head hash.
func (p *Postgres) AuditHead(ctx context.Context) (domain.AuditEntry, error) {
	e, err := scanAuditEntry(p.pool.QueryRow(ctx, selectAuditHeadSQL))
	if err != nil {
		return domain.AuditEntry{}, classify("store: audit head", err)
	}
	return e, nil
}

// StreamAudit walks the entire ledger in seq order, calling fn for each entry.
//
// Verification has to be a streaming pass: loading a ledger that has been
// running for months into a slice to check it would make the check itself the
// outage. Rows are handed over as they arrive, and an error from fn stops the
// walk immediately so a broken link is reported at the link, not after a full
// scan.
func (p *Postgres) StreamAudit(ctx context.Context, fn func(domain.AuditEntry) error) error {
	rows, err := p.pool.Query(ctx, streamAuditSQL)
	if err != nil {
		return classify("store: stream audit", err)
	}
	defer rows.Close()

	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return classify("store: scan audit entry", err)
		}
		if err := fn(e); err != nil {
			return fmt.Errorf("store: stream audit at seq %d: %w", e.Seq, err)
		}
	}
	if err := rows.Err(); err != nil {
		return classify("store: stream audit", err)
	}
	return nil
}

// ListAuditByIncident returns one incident's trail in chain order. The cap is a
// memory bound for the console: an incident with more entries than this has a
// loop in it, and the full trail is still available through StreamAudit.
func (p *Postgres) ListAuditByIncident(ctx context.Context, incidentID string) ([]domain.AuditEntry, error) {
	if err := checkText("incident_id", incidentID, 1, maxIdentifierLen); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, listAuditByIncidentSQL, incidentID, maxAuditListEntries)
	if err != nil {
		return nil, classify("store: list audit by incident", err)
	}
	defer rows.Close()

	out := make([]domain.AuditEntry, 0, 8)
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return nil, classify("store: scan audit entry", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("store: list audit by incident", err)
	}
	return out, nil
}

// MutateAuditDetailForTest rewrites one entry's detail and leaves its hash
// alone, simulating an attacker with direct database access editing history.
//
// It exists so the tamper-detection proof is a demonstration rather than a
// claim: the harness calls this, then asks Verify to name the seq it broke. The
// name is deliberately unusable in production code, and every call is logged at
// warning level, because an out-of-band write to the ledger is precisely the
// event the ledger exists to make visible.
func (p *Postgres) MutateAuditDetailForTest(ctx context.Context, seq int64, detail []byte) error {
	if err := checkJSON("detail", detail, maxAuditDetailBytes, true); err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, mutateAuditDetailSQL, seq, detail)
	if err != nil {
		return classify("store: mutate audit detail", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: mutate audit detail: %w", ErrNotFound)
	}
	p.log.Warn("audit ledger detail mutated out of band", "seq", seq)
	return nil
}

func scanAuditEntry(s scanner) (domain.AuditEntry, error) {
	var (
		e      domain.AuditEntry
		kind   string
		detail []byte
	)
	if err := s.Scan(&e.Seq, &e.IncidentID, &kind, &e.Actor, &detail, &e.At,
		&e.PrevHash, &e.Hash); err != nil {
		return domain.AuditEntry{}, err
	}
	e.Kind = domain.AuditKind(kind)
	e.Detail = domain.RawJSON(detail)
	e.At = e.At.UTC()
	return e, nil
}

// ---------------------------------------------------------------------------
// Parameter helpers and input bounds
// ---------------------------------------------------------------------------

// timeParam hands the timestamp decision to the database when the caller has
// none. The store holds no Clock, and writing a Go zero time into a payment
// record would silently date it to year one.
func timeParam(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func timePtrParam(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// boundLimit keeps an operator- or config-supplied limit inside a range the
// database can serve without holding an unbounded number of row locks.
func boundLimit(limit, upper int) int {
	if limit < 1 {
		return 1
	}
	if limit > upper {
		return upper
	}
	return limit
}

// checkText enforces length in runes rather than bytes, matching PostgreSQL's
// char_length, so a value that passes here cannot be rejected by the table
// constraint and turn a validation failure into a transaction abort.
func checkText(field, v string, minLen, maxLen int) error {
	n := utf8.RuneCountInString(v)
	if n < minLen {
		return invalid(field, "is empty or too short")
	}
	if n > maxLen {
		return invalid(field, "exceeds its maximum length")
	}
	if !utf8.ValidString(v) {
		return invalid(field, "is not valid UTF-8")
	}
	return nil
}

// checkJSON validates the document before it reaches a JSONB column. Doing it
// here rather than letting PostgreSQL reject it keeps a malformed payload from
// aborting an otherwise-good transaction, and gives the caller an
// ErrInvalidInput it can classify instead of a driver error.
func checkJSON(field string, b []byte, maxBytes int, required bool) error {
	if len(b) == 0 {
		if required {
			return invalid(field, "is empty")
		}
		return nil
	}
	if len(b) > maxBytes {
		return invalid(field, "exceeds its maximum size")
	}
	if !json.Valid(b) {
		return invalid(field, "is not valid JSON")
	}
	return nil
}

// truncate bounds diagnostic free text on a rune boundary. Used only for fields
// whose loss of detail is preferable to losing the record: gateway error text
// and halt reasons.
func truncate(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	out := make([]rune, 0, maxLen)
	for _, r := range s {
		if len(out) == maxLen {
			break
		}
		out = append(out, r)
	}
	return string(out)
}

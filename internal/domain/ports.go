package domain

import (
	"context"
	"time"
)

// Ports are the seams between packages. Concrete implementations live in
// internal/<pkg>; nothing in this file knows how any of them work. Every port
// takes a context first and returns an error last, so cancellation and
// deadlines propagate uniformly from the HTTP edge down to the database.

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

// Clock exists so that cooling windows, backoff schedules, and breaker
// timeouts can be tested without sleeping. Every component that reasons about
// time takes one.
type Clock interface {
	Now() time.Time
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// Tx is a database transaction scope. The outbox guarantee depends on incident
// and outbox writes sharing one Tx, so the interface deliberately offers no way
// to commit a partial batch.
type Tx interface {
	InsertIncident(ctx context.Context, in Incident) error
	InsertOutboxEvent(ctx context.Context, ev OutboxEvent) error
	UpsertMandate(ctx context.Context, m MandateRecord) error
	AppendAudit(ctx context.Context, e AuditEntry) error
}

// Store is the durable state boundary.
type Store interface {
	// WithTx runs fn inside a single database transaction, committing on nil
	// error and rolling back otherwise.
	WithTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error

	GetIncident(ctx context.Context, id string) (Incident, error)
	GetIncidentByEventID(ctx context.Context, eventID string) (Incident, error)
	UpdateIncidentState(ctx context.Context, id string, state IncidentState) error
	IncrementIncidentAttempts(ctx context.Context, id string) (int, error)
	ListIncidents(ctx context.Context, limit int) ([]Incident, error)

	// ScheduleIncident defers an incident until at, recording the due time
	// durably. A deferred recovery that lives only in memory is lost on the
	// next deploy, and a deploy during an outage is exactly when the most work
	// is deferred.
	ScheduleIncident(ctx context.Context, id string, at time.Time) error
	// ClaimDueIncidents takes ownership of incidents whose schedule has
	// arrived. Implementations must use row-level locking that skips locked
	// rows, so several sweepers can run without claiming the same incident.
	ClaimDueIncidents(ctx context.Context, now time.Time, limit int) ([]Incident, error)
	// DueIncidentCount reports the past-due backlog, which is invisible from
	// queue depth: a sweeper that has stopped shows an empty queue.
	DueIncidentCount(ctx context.Context, now time.Time) (int, error)

	// ClaimOutboxBatch locks up to limit pending rows for this relay instance.
	// Implementations must use row-level locking that skips locked rows, so
	// multiple relays can run concurrently without double dispatch.
	ClaimOutboxBatch(ctx context.Context, limit int) ([]OutboxEvent, error)
	MarkOutboxDispatched(ctx context.Context, ids []int64) error
	// MarkOutboxFailed parks a row permanently. It is the terminal verdict and
	// must not be used for an ordinary publish failure.
	MarkOutboxFailed(ctx context.Context, id int64, cause string) error
	// RecordOutboxFailure charges one attempt and leaves the row PENDING, so a
	// failure attributable to the row counts towards its budget without
	// deciding the row's fate on the first try.
	RecordOutboxFailure(ctx context.Context, id int64, cause string) error
	// ReleaseOutboxClaim hands leased rows back uncharged, for when the queue
	// itself was unreachable and the failure says nothing about the rows.
	ReleaseOutboxClaim(ctx context.Context, ids []int64) error
	OutboxDepth(ctx context.Context) (pending int, failed int, err error)

	GetMandate(ctx context.Context, subscriptionID string) (MandateRecord, error)
	SaveMandate(ctx context.Context, m MandateRecord) error

	RecordAttempt(ctx context.Context, a AttemptRecord) error
	ListAttempts(ctx context.Context, incidentID string) ([]AttemptRecord, error)

	CreateSession(ctx context.Context, s SessionRecord) error
	GetSession(ctx context.Context, id string) (SessionRecord, error)
	GetSessionByOrder(ctx context.Context, orderID string) (SessionRecord, error)
	UpdateSession(ctx context.Context, s SessionRecord) error

	Ping(ctx context.Context) error
	Close() error
}

// AuditLedger is the append-only, hash-chained record of every consequential
// decision. Append is separate from Tx.AppendAudit because most call sites are
// outside a transaction; both paths write the same chain.
type AuditLedger interface {
	Append(ctx context.Context, kind AuditKind, incidentID, actor string, detail any) (AuditEntry, error)
	List(ctx context.Context, incidentID string) ([]AuditEntry, error)
	// Verify walks the entire chain and reports the first break, if any.
	Verify(ctx context.Context) (VerifyReport, error)
	Head(ctx context.Context) (AuditEntry, error)
}

// VerifyReport is the result of an audit chain walk.
type VerifyReport struct {
	Entries    int64     `json:"entries"`
	Valid      bool      `json:"valid"`
	BreakAtSeq int64     `json:"break_at_seq,omitempty"`
	BreakCause string    `json:"break_cause,omitempty"`
	HeadHash   string    `json:"head_hash"`
	CheckedAt  time.Time `json:"checked_at"`
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

// QueueMessage is one delivery from the stream.
type QueueMessage struct {
	ID         string
	IncidentID string
	Topic      string
	Payload    RawJSON
	Deliveries int
}

// Queue is the asynchronous work channel between the edge and the workers. The
// outbox relay is the only producer; workers are the only consumers.
type Queue interface {
	Publish(ctx context.Context, topic string, ev OutboxEvent) error
	// Consume blocks until messages are available, the context is cancelled, or
	// the block deadline elapses. Returned messages are owned by this consumer
	// until acked or reclaimed.
	Consume(ctx context.Context, group, consumer string, count int, block time.Duration) ([]QueueMessage, error)
	Ack(ctx context.Context, group string, ids ...string) error
	// Reclaim takes over messages stranded by a dead consumer.
	Reclaim(ctx context.Context, group, consumer string, minIdle time.Duration, count int) ([]QueueMessage, error)
	Depth(ctx context.Context) (int64, error)
	Ping(ctx context.Context) error
	Close() error
}

// ---------------------------------------------------------------------------
// Telemetry and ambient signal
// ---------------------------------------------------------------------------

// TelemetryRecorder maintains rolling per-issuer outcome windows.
type TelemetryRecorder interface {
	RecordOutcome(ctx context.Context, issuerKey, errorCode string, success bool, latency time.Duration) error
	Snapshot(ctx context.Context, issuerKey string) (TelemetrySnapshot, error)
	SnapshotAll(ctx context.Context) ([]TelemetrySnapshot, error)
}

// DowntimeSource supplies Razorpay downtime notices. The real implementation
// polls /v1/downtimes; the simulator serves the identical schema, so the
// consumer cannot tell them apart.
type DowntimeSource interface {
	Active(ctx context.Context) ([]DowntimeEntity, error)
	// MatchingIssuer returns only notices affecting the given telemetry key.
	MatchingIssuer(ctx context.Context, issuerKey string) ([]DowntimeEntity, error)
}

// BreakerState is the tri-state of a per-issuer circuit breaker.
type BreakerState string

const (
	BreakerClosed   BreakerState = "CLOSED"
	BreakerOpen     BreakerState = "OPEN"
	BreakerHalfOpen BreakerState = "HALF_OPEN"
)

// Breaker sheds load per issuer during an outage. When open, incidents skip
// inference entirely and route straight to backoff, which is what stops an
// outage from becoming an inference bill and a retry storm at the same time.
type Breaker interface {
	State(ctx context.Context, issuerKey string) (BreakerState, error)
	Allow(ctx context.Context, issuerKey string) (bool, error)
	Report(ctx context.Context, issuerKey string, success bool) error
	States(ctx context.Context) (map[string]BreakerState, error)
}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

// Diagnoser turns ambiguous failure evidence into an advisory proposal. It is
// the only probabilistic component in the system, and its output has no
// authority: the gatekeeper may discard any part of it.
type Diagnoser interface {
	Diagnose(ctx context.Context, dc DiagnosticContext) (DiagnosticProposal, error)
	// Describe names the active tier for the operator console and audit trail.
	Describe() string
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

// GateInput bundles everything the gatekeeper needs. It takes the verified
// payment entity rather than an incident id so it cannot be tricked into
// re-reading mutable state for the amount.
type GateInput struct {
	IncidentID     string
	Payment        PaymentEntity
	Proposal       DiagnosticProposal
	Telemetry      TelemetrySnapshot
	SessionActive  bool
	AttemptNumber  int
	Mandate        *MandateRecord
	AvailableRails []Rail
}

// Gatekeeper converts an advisory proposal into an authoritative command by
// applying deterministic invariants. It is pure with respect to its inputs:
// same input, same command, always.
type Gatekeeper interface {
	Decide(ctx context.Context, in GateInput) (SanitizedCommand, error)
}

// PolicyEngine computes the expected-value-optimal action parameters: which
// rail to morph to, and how long to wait before an async retry. This is
// arithmetic over hazard rates and the cost model, deliberately kept out of the
// model's hands.
type PolicyEngine interface {
	ChooseRail(ctx context.Context, current Rail, available []Rail, snapshots map[string]TelemetrySnapshot) (Rail, string)
	BackoffFor(ctx context.Context, attempt int, class FailureClass, snap TelemetrySnapshot) time.Duration
	ExpectedValue(ctx context.Context, amountPaisa int64, successProb float64, attempts int, costs CostModel) int64
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// SessionHub multiplexes live checkout sessions over SSE.
type SessionHub interface {
	// Subscribe registers a stream and returns a channel of encoded events plus
	// an unsubscribe func. The caller owns draining the channel.
	Subscribe(ctx context.Context, sessionID string) (<-chan SessionEvent, func(), error)
	Publish(ctx context.Context, sessionID string, ev SessionEvent) error
	Active(sessionID string) bool
	Count() int
}

// SessionEvent is one SSE frame delivered to a checkout client. Nothing
// sensitive travels here: the client already knows the order and amount, and
// the reason string is an operator-facing phrase from a fixed vocabulary, not
// model free text.
type SessionEvent struct {
	Type        string `json:"type"` // rail_morph | status | heartbeat | closed
	OrderID     string `json:"order_id,omitempty"`
	FromRail    Rail   `json:"from_rail,omitempty"`
	ToRail      Rail   `json:"to_rail,omitempty"`
	AmountPaisa int64  `json:"amount_paisa,omitempty"`
	Currency    string `json:"currency,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Sequence    int64  `json:"sequence"`
	At          int64  `json:"at"`
}

// Executor performs the outbound side effect a command calls for. The real
// implementation calls Razorpay; the simulator implements the same interface,
// which is what makes the benchmark reproducible without a payment account.
type Executor interface {
	Retry(ctx context.Context, cmd SanitizedCommand) (AttemptRecord, error)
	MorphRail(ctx context.Context, cmd SanitizedCommand) (AttemptRecord, error)
	NotifyPreDebit(ctx context.Context, cmd SanitizedCommand) error
}

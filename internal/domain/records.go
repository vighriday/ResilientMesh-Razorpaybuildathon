package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// Persistence records. These are the durable shapes; the store package owns
// their SQL representation but not their meaning.

// IncidentState is the lifecycle of a single failed-payment incident.
type IncidentState string

const (
	IncidentReceived  IncidentState = "RECEIVED"
	IncidentDiagnosed IncidentState = "DIAGNOSED"
	IncidentGated     IncidentState = "GATED"
	IncidentScheduled IncidentState = "SCHEDULED"
	IncidentExecuting IncidentState = "EXECUTING"
	IncidentRecovered IncidentState = "RECOVERED"
	IncidentAbandoned IncidentState = "ABANDONED"
	IncidentAbstained IncidentState = "ABSTAINED"
)

// Terminal reports whether no further transition is possible.
func (s IncidentState) Terminal() bool {
	switch s {
	case IncidentRecovered, IncidentAbandoned, IncidentAbstained:
		return true
	default:
		return false
	}
}

// Incident is the durable record of one failure and everything decided about
// it. RawPayload is the exact HMAC-verified bytes: it is the evidence the
// amount was never mutated, so it is stored verbatim and never rewritten.
type Incident struct {
	ID             string        `json:"id"`
	PaymentID      string        `json:"payment_id"`
	OrderID        string        `json:"order_id"`
	SubscriptionID string        `json:"subscription_id,omitempty"`
	EventID        string        `json:"event_id"` // X-Razorpay-Event-Id, idempotency key
	AmountPaisa    int64         `json:"amount_paisa"`
	Currency       string        `json:"currency"`
	Method         string        `json:"method"`
	IssuerKey      string        `json:"issuer_key"`
	ErrorCode      string        `json:"error_code"`
	State          IncidentState `json:"state"`
	AttemptCount   int           `json:"attempt_count"`
	IsRecurring    bool          `json:"is_recurring"`
	RawPayload     RawJSON       `json:"raw_payload"`
	ReceivedAt     time.Time     `json:"received_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// OutboxState tracks relay progress for a single event.
type OutboxState string

const (
	OutboxPending    OutboxState = "PENDING"
	OutboxDispatched OutboxState = "DISPATCHED"
	OutboxFailed     OutboxState = "FAILED"
)

// OutboxEvent is a row in the transactional outbox. It is written in the same
// database transaction as the incident it describes, which is what removes the
// dual-write failure mode: either both land or neither does.
type OutboxEvent struct {
	ID           int64       `json:"id"`
	IncidentID   string      `json:"incident_id"`
	Topic        string      `json:"topic"`
	Payload      RawJSON     `json:"payload"`
	State        OutboxState `json:"state"`
	Attempts     int         `json:"attempts"`
	LastError    string      `json:"last_error,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	DispatchedAt *time.Time  `json:"dispatched_at,omitempty"`
}

// MandateRecord tracks recurring-mandate compliance state. The RBI invariants
// are enforced against this record, not against in-memory counters, so a
// process restart cannot reset a cooling window.
type MandateRecord struct {
	SubscriptionID     string     `json:"subscription_id"`
	CustomerID         string     `json:"customer_id,omitempty"`
	AmountPaisa        int64      `json:"amount_paisa"`
	LastAttemptAt      *time.Time `json:"last_attempt_at,omitempty"`
	NextEligibleAt     *time.Time `json:"next_eligible_at,omitempty"`
	AttemptsInCycle    int        `json:"attempts_in_cycle"`
	PreDebitNotifiedAt *time.Time `json:"pre_debit_notified_at,omitempty"`
	CycleKey           string     `json:"cycle_key"`
	Halted             bool       `json:"halted"`
	HaltReason         string     `json:"halt_reason,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// AttemptRecord is one executed recovery attempt and its outcome. This is the
// table the NRCV benchmark aggregates over.
type AttemptRecord struct {
	ID              int64     `json:"id"`
	IncidentID      string    `json:"incident_id"`
	AttemptNumber   int       `json:"attempt_number"`
	Action          Action    `json:"action"`
	Rail            Rail      `json:"rail"`
	AmountPaisa     int64     `json:"amount_paisa"`
	Succeeded       bool      `json:"succeeded"`
	GatewayFeePaisa int64     `json:"gateway_fee_paisa"`
	FrictionPaisa   int64     `json:"friction_paisa"`
	ErrorCode       string    `json:"error_code,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
}

// SessionRecord is a live checkout session eligible for in-session healing.
// Token is the bearer credential for the SSE stream; only its hash is stored,
// so a database read cannot be replayed against the stream endpoint.
type SessionRecord struct {
	ID          string     `json:"id"`
	OrderID     string     `json:"order_id"`
	TokenHash   string     `json:"-"`
	CurrentRail Rail       `json:"current_rail"`
	AmountPaisa int64      `json:"amount_paisa"`
	Currency    string     `json:"currency"`
	Active      bool       `json:"active"`
	MorphCount  int        `json:"morph_count"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

// Expired reports whether the session may no longer be healed.
func (s SessionRecord) Expired(now time.Time) bool {
	return !s.Active || now.After(s.ExpiresAt)
}

// ---------------------------------------------------------------------------
// Tamper-evident audit ledger
// ---------------------------------------------------------------------------

// AuditKind classifies a ledger entry.
type AuditKind string

const (
	AuditWebhookAccepted AuditKind = "WEBHOOK_ACCEPTED"
	AuditWebhookRejected AuditKind = "WEBHOOK_REJECTED"
	AuditTerminalHalt    AuditKind = "TERMINAL_DECLINE_HALTED"
	AuditDiagnosis       AuditKind = "DIAGNOSIS_PROPOSED"
	AuditGateDecision    AuditKind = "GATE_DECISION"
	AuditInvariantBlock  AuditKind = "INVARIANT_BLOCKED"
	AuditAttemptStarted  AuditKind = "ATTEMPT_STARTED"
	AuditAttemptResult   AuditKind = "ATTEMPT_RESULT"
	AuditRailMorph       AuditKind = "RAIL_MORPHED"
	AuditPreDebitNotice  AuditKind = "PRE_DEBIT_NOTIFIED"
	AuditBreakerTripped  AuditKind = "BREAKER_TRIPPED"
	AuditBreakerClosed   AuditKind = "BREAKER_CLOSED"
	AuditIncidentClosed  AuditKind = "INCIDENT_CLOSED"
)

// AuditEntry is one link in a hash chain. Each entry commits to its
// predecessor, so removing, reordering, or editing any historical entry
// invalidates every entry after it. Verification is a single linear pass and is
// exposed as a CLI command, which makes the audit trail checkable by a reviewer
// rather than merely present.
type AuditEntry struct {
	Seq        int64     `json:"seq"`
	IncidentID string    `json:"incident_id,omitempty"`
	Kind       AuditKind `json:"kind"`
	Actor      string    `json:"actor"`
	Detail     RawJSON   `json:"detail"`
	At         time.Time `json:"at"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// GenesisHash is the chain anchor: the hash every ledger starts from.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ComputeHash derives the entry hash from its content and its predecessor.
//
// Fields are absorbed length-prefixed rather than concatenated, so no choice of
// field content can produce the same digest as a different field split. Naive
// concatenation would let an attacker who controls two adjacent fields forge a
// colliding entry by shifting the boundary between them.
func (e AuditEntry) ComputeHash() string {
	h := sha256.New()
	absorbUint(h, uint64(e.Seq))
	absorbStr(h, e.IncidentID)
	absorbStr(h, string(e.Kind))
	absorbStr(h, e.Actor)
	absorb(h, e.Detail)
	absorbUint(h, uint64(e.At.UTC().UnixNano()))
	absorbStr(h, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyAgainst checks this entry links correctly to prevHash and that its
// recorded digest matches its content.
func (e AuditEntry) VerifyAgainst(prevHash string) bool {
	if e.PrevHash != prevHash {
		return false
	}
	return e.Hash == e.ComputeHash()
}

type byteWriter interface{ Write([]byte) (int, error) }

func absorb(h byteWriter, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

func absorbStr(h byteWriter, s string) { absorb(h, []byte(s)) }

func absorbUint(h byteWriter, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	absorb(h, b[:])
}

// ---------------------------------------------------------------------------
// Economics
// ---------------------------------------------------------------------------

// CostModel holds the per-incident economics used by both the live policy
// engine and the offline benchmark. Both read the same struct so the numbers a
// reviewer sees in the benchmark are the numbers the running system optimises.
// All values are paisa.
type CostModel struct {
	GatewayFeePerAttemptPaisa int64 `json:"gateway_fee_per_attempt_paisa"`
	CommsCostPerMessagePaisa  int64 `json:"comms_cost_per_message_paisa"`
	CompliancePenaltyPaisa    int64 `json:"compliance_penalty_paisa"`
	SessionFrictionPaisa      int64 `json:"session_friction_paisa"`
}

// DefaultCostModel reflects the figures used in the evaluation harness:
// Rs 2.50 per gateway retry, Rs 0.60 per out-of-band message, Rs 500 per
// compliance violation, Rs 0.60 per in-session morph prompt.
func DefaultCostModel() CostModel {
	return CostModel{
		GatewayFeePerAttemptPaisa: 250,
		CommsCostPerMessagePaisa:  60,
		CompliancePenaltyPaisa:    50000,
		SessionFrictionPaisa:      60,
	}
}

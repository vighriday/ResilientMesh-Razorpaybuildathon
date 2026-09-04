package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file defines the trust boundary between probabilistic and deterministic
// components.
//
//	DiagnosticContext  -> what the model is allowed to see  (sanitised, no PII)
//	DiagnosticProposal -> what the model is allowed to say  (advisory only)
//	SanitizedCommand   -> what the system actually executes (authoritative)
//
// The one-way flow Context -> Proposal -> Gatekeeper -> Command is the core
// safety property: no money value, compliance verdict, or state transition ever
// originates from a model response.

// ---------------------------------------------------------------------------
// Action taxonomy
// ---------------------------------------------------------------------------

// Action is a recovery instruction. The set is closed: an unrecognised action
// from any source degrades to ActionAbstain rather than being executed.
type Action string

const (
	// ActionRailMorph switches the live checkout session to a healthy rail over
	// SSE without tearing down the session. Only legal while a session is open.
	ActionRailMorph Action = "IN_SESSION_RAIL_MORPH"

	// ActionAsyncRetry schedules an out-of-session retry on the original rail
	// after a computed backoff.
	ActionAsyncRetry Action = "ASYNC_EXPONENTIAL_RETRY"

	// ActionMandateCascade is the recurring-rail variant of a retry: it carries
	// the RBI cooling window and pre-debit notification obligations.
	ActionMandateCascade Action = "MANDATE_COMPLIANT_CASCADE"

	// ActionAbstain permanently stops recovery for this incident. It is the
	// safe default for every ambiguous or malformed input.
	ActionAbstain Action = "PERMANENT_ABSTAIN"
)

var allActions = map[Action]struct{}{
	ActionRailMorph: {}, ActionAsyncRetry: {},
	ActionMandateCascade: {}, ActionAbstain: {},
}

func (a Action) Valid() bool { _, ok := allActions[a]; return ok }

// ParseAction normalises model output into a known action. Anything
// unrecognised becomes ActionAbstain: the system fails closed, never open.
func ParseAction(s string) Action {
	a := Action(strings.ToUpper(strings.TrimSpace(s)))
	if a.Valid() {
		return a
	}
	return ActionAbstain
}

// FailureClass is the causal category assigned to an ambiguous failure.
type FailureClass string

const (
	ClassTransientDegradation FailureClass = "TRANSIENT_ISSUER_DEGRADATION"
	ClassIssuerOutage         FailureClass = "ISSUER_OUTAGE"
	ClassNetworkTimeout       FailureClass = "NETWORK_TIMEOUT"
	ClassPSPDegradation       FailureClass = "PSP_DEGRADATION"
	ClassCustomerAction       FailureClass = "CUSTOMER_ACTION_REQUIRED"
	ClassInsufficientFunds    FailureClass = "INSUFFICIENT_FUNDS"
	ClassPermanentInstrument  FailureClass = "PERMANENT_INSTRUMENT_FAILURE"
	ClassUnknown              FailureClass = "UNKNOWN"
)

var allClasses = map[FailureClass]struct{}{
	ClassTransientDegradation: {}, ClassIssuerOutage: {}, ClassNetworkTimeout: {},
	ClassPSPDegradation: {}, ClassCustomerAction: {}, ClassInsufficientFunds: {},
	ClassPermanentInstrument: {}, ClassUnknown: {},
}

func (c FailureClass) Valid() bool { _, ok := allClasses[c]; return ok }

func ParseFailureClass(s string) FailureClass {
	c := FailureClass(strings.ToUpper(strings.TrimSpace(s)))
	if c.Valid() {
		return c
	}
	return ClassUnknown
}

// Recoverable reports whether a class is worth spending a retry on at all.
func (c FailureClass) Recoverable() bool {
	switch c {
	case ClassPermanentInstrument, ClassUnknown:
		return false
	default:
		return true
	}
}

// ---------------------------------------------------------------------------
// Inference provenance
// ---------------------------------------------------------------------------

// InferenceMode records which tier of the inference stack produced a proposal.
// It is persisted on every incident so a benchmark run can never silently
// substitute one tier for another.
type InferenceMode string

const (
	// ModeLive is a real call to a hosted or local model.
	ModeLive InferenceMode = "LIVE"
	// ModeReplay is a deterministic cassette hit, keyed by context digest.
	ModeReplay InferenceMode = "REPLAY"
	// ModeHeuristic is the degraded deterministic classifier used when no model
	// is reachable and no cassette matches. Always audit-flagged.
	ModeHeuristic InferenceMode = "HEURISTIC"
	// ModeSkipped means the taxonomy resolved the incident without inference.
	ModeSkipped InferenceMode = "SKIPPED"
)

// ---------------------------------------------------------------------------
// Model input
// ---------------------------------------------------------------------------

// DiagnosticContext is the complete, sanitised view handed to the causal model.
//
// Security: this struct is the allowlist. Nothing reaches the model that is not
// a field here, so cardholder data, VPAs, contact details, and raw webhook
// bodies are structurally incapable of leaking into a prompt. Free-text fields
// are the only attacker-influenced surface and are length-capped and escaped by
// the prompt builder.
type DiagnosticContext struct {
	IncidentID string `json:"incident_id"`

	// Failure signal, verbatim from the HMAC-verified payload.
	ErrorCode   string `json:"error_code"`
	ErrorSource string `json:"error_source,omitempty"`
	ErrorStep   string `json:"error_step,omitempty"`
	ErrorReason string `json:"error_reason,omitempty"` // untrusted free text

	// Instrument shape. Amount is deliberately bucketed rather than exact: the
	// model has no legitimate use for the precise value, and bucketing removes
	// it as a prompt-injection and correlation vector.
	Method      string `json:"method"`
	IssuerKey   string `json:"issuer_key"`
	AmountBand  string `json:"amount_band"`
	IsRecurring bool   `json:"is_recurring"`

	// Session liveness decides whether an in-session morph is even available.
	SessionActive       bool   `json:"session_active"`
	SessionAgeSeconds   int    `json:"session_age_seconds,omitempty"`
	AttemptNumber       int    `json:"attempt_number"`
	PriorAttemptSummary string `json:"prior_attempt_summary,omitempty"`

	// Ambient evidence: the whole reason a model beats a static rule here.
	Telemetry TelemetrySnapshot `json:"telemetry"`
	Downtimes []DowntimeSignal  `json:"downtimes"`

	// AvailableRails is the merchant-enabled, currently-healthy rail set. The
	// model may only choose from this list.
	AvailableRails []Rail `json:"available_rails"`

	ObservedAt time.Time `json:"observed_at"`
}

// DowntimeSignal is the flattened downtime view given to the model.
type DowntimeSignal struct {
	TelemetryKey  string           `json:"telemetry_key"`
	Method        string           `json:"method"`
	Severity      DowntimeSeverity `json:"severity"`
	Status        DowntimeStatus   `json:"status"`
	Scheduled     bool             `json:"scheduled"`
	AgeSeconds    int64            `json:"age_seconds"`
	MatchesIssuer bool             `json:"matches_issuer"`
}

// AmountBand buckets a paisa amount into a coarse label. Used to keep exact
// money out of prompts while preserving the little signal amount carries
// (issuer limits and velocity rules are band-shaped, not value-shaped).
func AmountBand(paisa int64) string {
	rupees := paisa / 100
	switch {
	case rupees < 500:
		return "micro_lt_500"
	case rupees < 2000:
		return "small_500_2k"
	case rupees < 10000:
		return "mid_2k_10k"
	case rupees < 50000:
		return "large_10k_50k"
	default:
		return "xlarge_gte_50k"
	}
}

// ---------------------------------------------------------------------------
// Model output
// ---------------------------------------------------------------------------

// DiagnosticProposal is the strictly-typed output the model must emit. It is a
// proposal, not a decision: every field is re-validated, and the money-bearing
// and compliance-bearing fields are discarded and recomputed by the gatekeeper.
type DiagnosticProposal struct {
	IncidentID            string       `json:"incident_id"`
	InferredRootCause     string       `json:"inferred_root_cause"`
	FailureClassification FailureClass `json:"failure_classification"`
	ConfidenceScore       float64      `json:"confidence_score"`
	RecommendedAction     Action       `json:"recommended_action"`
	RecommendedDelaySec   int64        `json:"recommended_delay_seconds"`
	SuggestedFallbackRail Rail         `json:"suggested_fallback_rail"`
	ReasoningTrace        string       `json:"reasoning_trace"`

	// Provenance, filled by the agent layer rather than the model itself.
	Mode      InferenceMode `json:"mode"`
	Model     string        `json:"model,omitempty"`
	LatencyMS int64         `json:"latency_ms,omitempty"`
	Degraded  bool          `json:"degraded,omitempty"`
}

// Field bounds. Free text is capped because it is echoed into audit records and
// operator UIs; an unbounded model response is a storage and rendering hazard.
const (
	MaxRootCauseLen      = 240
	MaxReasoningLen      = 1200
	MaxRecommendedDelay  = int64(7 * 24 * 3600) // one week
	MinConfidenceToActOn = 0.55
)

var (
	ErrConfidenceOutOfRange = errors.New("domain: confidence score out of bounds [0.0, 1.0]")
	ErrDelayOutOfRange      = errors.New("domain: recommended delay out of bounds")
	ErrUnknownAction        = errors.New("domain: unknown recommended action")
	ErrUnknownRail          = errors.New("domain: unknown fallback rail")
	ErrIncidentMismatch     = errors.New("domain: proposal incident id does not match request")
)

// Validate enforces structural integrity of a model response before it is
// allowed anywhere near the gatekeeper. It rejects rather than repairs, so a
// malformed response is a visible failure instead of a silent coercion.
func (p *DiagnosticProposal) Validate() error {
	if p.ConfidenceScore < 0.0 || p.ConfidenceScore > 1.0 {
		return ErrConfidenceOutOfRange
	}
	if p.RecommendedDelaySec < 0 || p.RecommendedDelaySec > MaxRecommendedDelay {
		return ErrDelayOutOfRange
	}
	if !p.RecommendedAction.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownAction, p.RecommendedAction)
	}
	if !p.SuggestedFallbackRail.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownRail, p.SuggestedFallbackRail)
	}
	if !p.FailureClassification.Valid() {
		p.FailureClassification = ClassUnknown
	}
	return nil
}

// Clamp truncates unbounded free text in place. Applied after Validate so that
// oversized text is normalised rather than rejected: length is a formatting
// concern, unlike an out-of-range confidence which indicates a broken model.
func (p *DiagnosticProposal) Clamp() {
	p.InferredRootCause = truncate(p.InferredRootCause, MaxRootCauseLen)
	p.ReasoningTrace = truncate(p.ReasoningTrace, MaxReasoningLen)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Trim on a rune boundary so the result stays valid UTF-8.
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// AbstainProposal builds the safe-default proposal used whenever inference is
// unavailable, malformed, or untrusted.
func AbstainProposal(incidentID, reason string, mode InferenceMode) DiagnosticProposal {
	return DiagnosticProposal{
		IncidentID:            incidentID,
		InferredRootCause:     truncate(reason, MaxRootCauseLen),
		FailureClassification: ClassUnknown,
		ConfidenceScore:       0,
		RecommendedAction:     ActionAbstain,
		SuggestedFallbackRail: RailNone,
		ReasoningTrace:        truncate(reason, MaxReasoningLen),
		Mode:                  mode,
		Degraded:              true,
	}
}

// ---------------------------------------------------------------------------
// Authoritative command
// ---------------------------------------------------------------------------

// SanitizedCommand is the only structure the executor will act on. It is
// produced exclusively by the gatekeeper. Every money-bearing and
// compliance-bearing field is computed deterministically from the verified
// payload and durable state, never copied from a proposal.
type SanitizedCommand struct {
	IncidentID           string `json:"incident_id"`
	PaymentID            string `json:"payment_id"`
	OrderID              string `json:"order_id"`
	ImmutableAmountPaisa int64  `json:"immutable_amount_paisa"`
	Currency             string `json:"currency"`

	Action     Action `json:"action"`
	TargetRail Rail   `json:"target_rail"`

	// ExecuteAfter is absolute rather than relative so that a queued command
	// cannot drift if the worker restarts or the queue backs up.
	ExecuteAfter time.Time `json:"execute_after"`
	DelaySeconds int64     `json:"delay_seconds"`

	AttemptNumber int `json:"attempt_number"`
	MaxAttempts   int `json:"max_attempts"`

	PreDebitNotificationNeeded bool `json:"pre_debit_notification_needed"`

	// AppliedInvariants names every rule that fired, in order. This is what
	// makes the audit trail defensible rather than decorative: a reviewer can
	// see which constraint produced the outcome.
	AppliedInvariants []string `json:"applied_invariants"`
	AuditTrace        string   `json:"audit_trace"`

	// Provenance of the advisory input that preceded this command.
	ProposalMode       InferenceMode `json:"proposal_mode"`
	ProposalConfidence float64       `json:"proposal_confidence"`
	ProposalAction     Action        `json:"proposal_action"`
	OverrodeProposal   bool          `json:"overrode_proposal"`

	DecidedAt time.Time `json:"decided_at"`
}

// Executable reports whether this command results in an outbound attempt.
func (c SanitizedCommand) Executable() bool {
	return c.Action == ActionRailMorph || c.Action == ActionAsyncRetry || c.Action == ActionMandateCascade
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

// TelemetrySnapshot is an immutable read of the rolling failure window for one
// issuer, plus the portfolio-wide baseline it should be judged against. The
// baseline matters: a 60% success rate is catastrophic for UPI and normal for
// a small netbanking switch at 2 AM.
type TelemetrySnapshot struct {
	IssuerKey     string      `json:"issuer_key"`
	WindowSeconds int         `json:"window_seconds"`
	Attempts      int         `json:"attempts"`
	Successes     int         `json:"successes"`
	Failures      int         `json:"failures"`
	SuccessRate   float64     `json:"success_rate"`
	BaselineRate  float64     `json:"baseline_success_rate"`
	P95LatencyMS  int64       `json:"p95_latency_ms,omitempty"`
	BreakerState  string      `json:"breaker_state"`
	TopErrorCodes []CodeCount `json:"top_error_codes,omitempty"`
	SampledAt     time.Time   `json:"sampled_at"`
}

type CodeCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// Degraded reports whether the issuer is meaningfully below its own baseline
// with enough samples for the comparison to mean anything. The sample floor
// prevents a single failure in a quiet window from declaring an outage.
func (t TelemetrySnapshot) Degraded() bool {
	const minSamples = 8
	if t.Attempts < minSamples {
		return false
	}
	return t.SuccessRate < t.BaselineRate*0.5
}

// SortCodeCounts orders error codes by descending frequency, then by code, so
// snapshots serialise identically for the same underlying counts. Stability
// matters because the snapshot feeds the cassette digest.
func SortCodeCounts(cc []CodeCount) {
	sort.Slice(cc, func(i, j int) bool {
		if cc[i].Count != cc[j].Count {
			return cc[i].Count > cc[j].Count
		}
		return cc[i].Code < cc[j].Code
	})
}

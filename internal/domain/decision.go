package domain

import (
	"errors"
	"fmt"
	"math"
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

	// ActionInstrumentRefresh re-presents the same instrument through a
	// different credential form — typically a network token refreshed via the
	// account updater — rather than retrying the failed presentation unchanged.
	// It is the correct response to a decline that looks terminal but is really
	// a stale credential.
	ActionInstrumentRefresh Action = "INSTRUMENT_REFRESH"

	// ActionAbstain permanently stops recovery for this incident. It is the
	// safe default for every ambiguous or malformed input.
	ActionAbstain Action = "PERMANENT_ABSTAIN"
)

var allActions = map[Action]struct{}{
	ActionRailMorph: {}, ActionAsyncRetry: {}, ActionMandateCascade: {},
	ActionInstrumentRefresh: {}, ActionAbstain: {},
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
	ClassInstrumentStale      FailureClass = "INSTRUMENT_STALE"
	ClassPermanentInstrument  FailureClass = "PERMANENT_INSTRUMENT_FAILURE"
	ClassUnknown              FailureClass = "UNKNOWN"
)

var allClasses = map[FailureClass]struct{}{
	ClassTransientDegradation: {}, ClassIssuerOutage: {}, ClassNetworkTimeout: {},
	ClassPSPDegradation: {}, ClassCustomerAction: {}, ClassInsufficientFunds: {},
	ClassPermanentInstrument: {}, ClassInstrumentStale: {}, ClassUnknown: {},
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
//
// The switch enumerates the recoverable classes rather than the unrecoverable
// ones, so an unrecognised value — including one a model invented — is not
// recoverable. Defaulting the other way would let a fabricated classification
// buy a retry, which is a fail-open path on the money side.
func (c FailureClass) Recoverable() bool {
	switch c {
	case ClassTransientDegradation, ClassIssuerOutage, ClassNetworkTimeout,
		ClassPSPDegradation, ClassCustomerAction, ClassInsufficientFunds,
		ClassInstrumentStale:
		return true
	default:
		return false
	}
}

// InstrumentPresentation is how a stored instrument is offered to the issuer on
// an attempt.
//
// A retry that presents the same instrument the same way is a strictly weaker
// retry: if the presentation is what failed, repeating it cannot succeed.
// Making presentation part of the action space is what turns "try again" into
// "try differently".
type InstrumentPresentation string

const (
	PresentationUnchanged    InstrumentPresentation = "unchanged"
	PresentationNetworkToken InstrumentPresentation = "network_token"
	PresentationStoredCred   InstrumentPresentation = "stored_credential"
	PresentationFreshAuth    InstrumentPresentation = "fresh_authorisation"
)

var allPresentations = map[InstrumentPresentation]struct{}{
	PresentationUnchanged: {}, PresentationNetworkToken: {},
	PresentationStoredCred: {}, PresentationFreshAuth: {},
}

func (p InstrumentPresentation) Valid() bool { _, ok := allPresentations[p]; return ok }

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

	// Provenance, stamped by the agent layer after unmarshalling.
	//
	// These carry `json:"-"` deliberately. With live tags a model response
	// could set its own Mode and Degraded flags, forging the record of which
	// tier answered — the exact field the console and the benchmark rely on to
	// tell a live diagnosis from a degraded fallback. Making them
	// unmarshalable removes the forgery rather than defending against it.
	Mode      InferenceMode `json:"-"`
	Model     string        `json:"-"`
	LatencyMS int64         `json:"-"`
	Degraded  bool          `json:"-"`
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
	ErrConfidenceNotFinite  = errors.New("domain: confidence score is not a finite number")
	ErrDelayOutOfRange      = errors.New("domain: recommended delay out of bounds")
	ErrUnknownAction        = errors.New("domain: unknown recommended action")
	ErrUnknownRail          = errors.New("domain: unknown fallback rail")
	ErrIncidentMismatch     = errors.New("domain: proposal incident id does not match request")
)

// Validate enforces structural integrity of a model response before it is
// allowed anywhere near the gatekeeper. It rejects rather than repairs, so a
// malformed response is a visible failure instead of a silent coercion.
func (p *DiagnosticProposal) Validate() error {
	// NaN must be rejected explicitly: every ordered comparison against NaN is
	// false, so a NaN confidence would slip past a range check written as
	// (c < 0 || c > 1) and then read as *maximum* confidence at every
	// downstream `confidence < threshold` gate. It is also unmarshalable by
	// encoding/json, so it would fail the outbox and audit writes downstream.
	if math.IsNaN(p.ConfidenceScore) || math.IsInf(p.ConfidenceScore, 0) {
		return ErrConfidenceNotFinite
	}
	if !(p.ConfidenceScore >= 0.0 && p.ConfidenceScore <= 1.0) {
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

	// Presentation is how the instrument will be offered on this attempt.
	Presentation InstrumentPresentation `json:"presentation"`

	// ReleaseOnDowntimeResolution marks a command parked behind a confirmed
	// issuer outage. In this ecosystem issuer recovery is published rather than
	// inferred, so waiting for the resolution notice beats waiting out a timer;
	// DelaySeconds then acts as an upper bound rather than the mechanism.
	ReleaseOnDowntimeResolution bool   `json:"release_on_downtime_resolution"`
	AwaitingDowntimeKey         string `json:"awaiting_downtime_key,omitempty"`

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
	switch c.Action {
	case ActionRailMorph, ActionAsyncRetry, ActionMandateCascade, ActionInstrumentRefresh:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

// TelemetrySnapshot is an immutable read of the rolling failure window for one
// issuer, plus the portfolio-wide baseline it should be judged against. The
// baseline matters: a 60% success rate is catastrophic for UPI and normal for
// a small netbanking switch at 2 AM.
type TelemetrySnapshot struct {
	IssuerKey     string       `json:"issuer_key"`
	WindowSeconds int          `json:"window_seconds"`
	Attempts      int          `json:"attempts"`
	Successes     int          `json:"successes"`
	Failures      int          `json:"failures"`
	SuccessRate   float64      `json:"success_rate"`
	BaselineRate  float64      `json:"baseline_success_rate"`
	P95LatencyMS  int64        `json:"p95_latency_ms,omitempty"`
	BreakerState  BreakerState `json:"breaker_state"`
	TopErrorCodes []CodeCount  `json:"top_error_codes,omitempty"`
	SampledAt     time.Time    `json:"sampled_at"`
}

type CodeCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// DegradedMinSamples is the evidence floor below which no outage verdict is
// returned. It stops a single failure in a quiet window from declaring an
// issuer down.
const DegradedMinSamples = 8

// DegradedAbsoluteRate is the success rate below which an issuer is degraded
// regardless of the portfolio baseline.
//
// The baseline comparison alone is not enough: on a cold start, or in the first
// window after a restart, BaselineRate is 0, and `rate < baseline*0.5` is then
// false for every issuer no matter how badly it is failing. That is a silent
// blind spot at exactly the moment — just after a deploy — when an outage is
// most likely to be missed, so an absolute floor backs it up.
const DegradedAbsoluteRate = 0.35

// Degraded reports whether the issuer is meaningfully unhealthy, judged both
// against its peers and against an absolute floor.
func (t TelemetrySnapshot) Degraded() bool {
	if t.Attempts < DegradedMinSamples {
		return false
	}
	if t.SuccessRate < DegradedAbsoluteRate {
		return true
	}
	if t.BaselineRate <= 0 {
		// No usable peer signal; the absolute floor above is the only verdict
		// that can be justified from this data.
		return false
	}
	return t.SuccessRate < t.BaselineRate*0.5
}

// Fresh reports whether the snapshot is recent enough to act on.
//
// Degraded() deliberately says nothing about age, because a snapshot is a
// value rather than a live reading. A consumer that skips this check is
// trusting arbitrarily stale telemetry — which, after a worker stall, means
// routing traffic at an issuer using numbers from before the outage began.
func (t TelemetrySnapshot) Fresh(now time.Time, maxAge time.Duration) bool {
	if t.SampledAt.IsZero() {
		return false
	}
	age := now.Sub(t.SampledAt)
	// A snapshot from the future indicates clock skew between producer and
	// consumer; treat it as unusable rather than infinitely fresh.
	if age < 0 {
		return -age <= maxAge
	}
	return age <= maxAge
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

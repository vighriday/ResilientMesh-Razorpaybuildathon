// Package gatekeeper turns an advisory model proposal into the one
// authoritative command the executor is allowed to act on.
//
// It is the last component between attacker-influenced model text and a real
// debit, so every rule here is written to fail closed: any input the gate
// cannot fully understand degrades to PERMANENT_ABSTAIN rather than to a
// retry. It is also deterministic and free of I/O — same input plus same clock
// reading yields a byte-identical command — which is what lets a reviewer
// replay an incident months later and get the same verdict the ledger recorded.
package gatekeeper

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// The invariant vocabulary. These strings are persisted in
// SanitizedCommand.AppliedInvariants and in the audit ledger, so they are part
// of the system's wire contract: consumers match on them instead of parsing
// the human-readable trace.
//
// A rule name is appended when the rule materially applied to this input —
// because it changed the outcome, or (for the two unconditional enforcement
// steps) because it was executed on every decision. A rule that was evaluated
// and found irrelevant is deliberately absent: recording TERMINAL_DECLINE on a
// non-terminal decline would make the trail misleading rather than complete.
const (
	// RuleAmountPinned always fires: it is the record that the money fields
	// were taken from the verified payment and not from the proposal.
	RuleAmountPinned = "AMOUNT_PINNED"
	// RuleTerminalDecline marks a decline no retry can fix.
	RuleTerminalDecline = "TERMINAL_DECLINE"
	// RuleStopMaxAttempts marks the global retry ceiling being hit.
	RuleStopMaxAttempts = "STOP_RULE_MAX_ATTEMPTS"
	// RuleLowConfidence marks a proposal too weak (or too malformed) to act on.
	RuleLowConfidence = "LOW_CONFIDENCE_ABSTAIN"
	// RuleUnrecoverableClass marks a causal class retrying cannot help.
	RuleUnrecoverableClass = "UNRECOVERABLE_CLASS"
	// RuleSessionRequired marks a morph downgraded for want of a live session.
	RuleSessionRequired = "SESSION_REQUIRED_FOR_MORPH"
	// RuleRailAllowlist marks a morph target rejected by the merchant allowlist.
	RuleRailAllowlist = "RAIL_ALLOWLIST"
	// RuleMandateCooling marks the RBI cooling window being imposed.
	RuleMandateCooling = "RBI_MANDATE_COOLING"
	// RulePreDebitNotice marks an unmet pre-debit notification obligation.
	RulePreDebitNotice = "RBI_PRE_DEBIT_NOTICE"
	// RuleInstrumentRefresh marks a decline re-presented through a refreshed
	// credential rather than retried unchanged.
	RuleInstrumentRefresh = "INSTRUMENT_REFRESH_ALLOWED"
	// RuleAFACeiling marks a recurring debit above the additional-factor
	// ceiling for its mandate category.
	RuleAFACeiling = "RBI_AFA_CEILING"
	// RuleMandateHalted marks a mandate that must not be debited again.
	RuleMandateHalted = "MANDATE_HALTED"
	// RuleMandateCycleCap marks the per-cycle attempt cap being hit; its
	// presence obliges the caller to halt the mandate (see RequiresMandateHalt).
	RuleMandateCycleCap = "MANDATE_CYCLE_CAP"
	// RuleDelayBounds always fires: it is the record that the emitted schedule
	// is representable and that a non-executable command carries no schedule.
	RuleDelayBounds = "DELAY_BOUNDS"
)

// Defaults for Config. They match MESH_MAX_ATTEMPTS, the RBI 24-hour cooling
// window, and the three-strikes-per-cycle mandate ceiling.
const (
	DefaultMaxAttempts                 = 3
	DefaultMandateCoolingSeconds int64 = 86400
	DefaultMandateCycleCap             = 3
)

const (
	// maxTraceBytes bounds AuditTrace. The trace is written to the ledger and
	// rendered in the ops console; an unbounded string is a storage and
	// rendering hazard even when every component of it is already capped.
	maxTraceBytes = 4096
	// maxReasoningRunes caps the only attacker-reachable string in the trace.
	maxReasoningRunes = 240
	// maxTokenRunes caps identifiers echoed into the trace.
	maxTokenRunes = 64
	// maxRailsConsidered bounds the allowlist scan. The rail vocabulary is
	// closed and tiny, so a longer list is either a bug or an attempt to make
	// the gate expensive; the remainder is ignored rather than walked.
	maxRailsConsidered = 32
	// noticeValidity is how long a recorded pre-debit notice can license a
	// debit. Beyond it the notice belongs to an earlier billing cycle and
	// cannot be reused.
	noticeValidity = 30 * 24 * time.Hour
)

// maxSchedulableDuration is MaxRecommendedDelay expressed as a Duration. Every
// arithmetic path that could overflow is compared against it first.
const maxSchedulableDuration = time.Duration(domain.MaxRecommendedDelay) * time.Second

var (
	// ErrInvalidGateInput reports a structurally incomplete GateInput. This is
	// a caller construction bug rather than a data condition, so it surfaces as
	// an error instead of an abstain command: there is no incident to attach an
	// abstention to.
	ErrInvalidGateInput = errors.New("gatekeeper: gate input is structurally incomplete")

	// ErrMoneyTampered reports that a command's money fields diverged from the
	// verified payment between pinning and return. It is unreachable by
	// construction and exists so that a future edit which breaks that property
	// stops the payment instead of executing it.
	ErrMoneyTampered = errors.New("gatekeeper: command money fields diverged from the verified payment")
)

// Config carries the deployment-tunable ceilings. Every field has a safe
// default, so the zero value is usable and a partially-configured deployment
// cannot end up with a disabled invariant.
type Config struct {
	// MaxAttempts is the global retry ceiling per incident.
	MaxAttempts int
	// MandateCoolingSeconds is the minimum gap before a recurring re-debit.
	MandateCoolingSeconds int64
	// MandateCycleCap is the maximum attempts allowed within one billing cycle.
	MandateCycleCap int
	// MinConfidence is the floor a proposal must clear to be acted on.
	MinConfidence float64
}

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	// The cooling window is a regulatory floor, not a preference: a deployment
	// may lengthen it but may not configure its way under RBI's 24 hours.
	if c.MandateCoolingSeconds < DefaultMandateCoolingSeconds {
		c.MandateCoolingSeconds = DefaultMandateCoolingSeconds
	}
	if c.MandateCoolingSeconds > domain.MaxRecommendedDelay {
		c.MandateCoolingSeconds = domain.MaxRecommendedDelay
	}
	if c.MandateCycleCap <= 0 {
		c.MandateCycleCap = DefaultMandateCycleCap
	}
	// A zero or NaN threshold would let every proposal through, so an unset
	// value falls back to the domain floor rather than to "no floor".
	if math.IsNaN(c.MinConfidence) || c.MinConfidence <= 0 {
		c.MinConfidence = domain.MinConfidenceToActOn
	}
	if c.MinConfidence > 1 {
		c.MinConfidence = 1
	}
	return c
}

// Gatekeeper applies the deterministic invariant set. It holds no mutable
// state after construction, so a single instance is safe for concurrent use by
// every worker goroutine.
type Gatekeeper struct {
	clock  domain.Clock
	policy domain.PolicyEngine
	cfg    Config
}

var _ domain.Gatekeeper = (*Gatekeeper)(nil)

// New builds a gatekeeper. A nil clock or policy engine is tolerated rather
// than fatal: this component sits on the payment path, where degrading to a
// deterministic internal default is strictly safer than panicking mid-incident.
func New(clock domain.Clock, policy domain.PolicyEngine, cfg Config) *Gatekeeper {
	if clock == nil {
		clock = systemClock{}
	}
	return &Gatekeeper{clock: clock, policy: policy, cfg: cfg.withDefaults()}
}

// Config returns the effective configuration after defaulting, so the ops
// console can show the ceilings actually in force rather than the ones someone
// believes are in force.
func (g *Gatekeeper) Config() Config { return g.cfg }

// Decide applies the twelve invariants in their fixed order and returns the
// only structure the executor may act on. The sequence is deliberately written
// out linearly rather than decomposed: the order is the specification, and
// hiding it behind helpers would let a later edit reorder a veto without any
// reviewer noticing.
func (g *Gatekeeper) Decide(ctx context.Context, in domain.GateInput) (domain.SanitizedCommand, error) {
	if err := ctx.Err(); err != nil {
		// A cancelled caller has nobody left to execute the command; emitting
		// one anyway risks a debit that no worker is watching.
		return domain.SanitizedCommand{}, fmt.Errorf("gatekeeper: decision abandoned before evaluation: %w", err)
	}
	if in.IncidentID == "" || in.Payment.ID == "" {
		return domain.SanitizedCommand{}, fmt.Errorf("%w: incident_id=%q payment_id=%q",
			ErrInvalidGateInput,
			sanitizeToken(in.IncidentID, maxTokenRunes),
			sanitizeToken(in.Payment.ID, maxTokenRunes))
	}

	// Sampled once. Two Now() calls inside one decision could straddle a second
	// boundary and produce a command whose DecidedAt and ExecuteAfter disagree
	// about their own delay.
	now := g.clock.Now()

	recurring := in.Payment.IsRecurring()
	failingRail := domain.RailFromMethod(in.Payment.Method)

	// The proposal is untrusted input, so it is normalised into the closed
	// vocabularies before any rule reads it. ParseAction and ParseRail collapse
	// anything unrecognised onto the safe member of their set, which is what
	// makes an injected recommended_action harmless rather than merely unlikely.
	proposalAction := domain.ParseAction(string(in.Proposal.RecommendedAction))
	proposalRail := domain.ParseRail(string(in.Proposal.SuggestedFallbackRail))
	// FailureClass.Recoverable() answers true for any value outside the closed
	// set, so the class is re-parsed rather than used verbatim: an invented
	// classification must not be able to buy a retry.
	class := domain.ParseFailureClass(string(in.Proposal.FailureClassification))

	d := &decision{presentation: domain.PresentationUnchanged}

	proposalMalformed := !in.Proposal.RecommendedAction.Valid()
	if proposalMalformed {
		d.note("proposal action %q is not in the closed action set, coerced to %s",
			sanitizeToken(string(in.Proposal.RecommendedAction), 32), domain.ActionAbstain)
	}
	if !in.Proposal.SuggestedFallbackRail.Valid() {
		d.note("proposal rail %q is not in the closed rail set, coerced to %s",
			sanitizeToken(string(in.Proposal.SuggestedFallbackRail), 32), domain.RailNone)
	}

	working := proposalAction
	if in.Proposal.IncidentID != "" && in.Proposal.IncidentID != in.IncidentID {
		// A proposal carrying another incident's id is a replayed cassette or a
		// confused model. Either way it is not evidence about this payment, so
		// the whole proposal is discarded rather than partially trusted.
		d.note("proposal belongs to a different incident, discarded in full")
		working = domain.ActionAbstain
		proposalRail = domain.RailNone
		class = domain.ClassUnknown
	}
	if working == domain.ActionMandateCascade && !recurring {
		// Mandate semantics on a one-off payment would set a cooling window and
		// a notification obligation that no subscription exists to satisfy.
		d.note("mandate cascade proposed for a non-recurring payment, normalised to %s", domain.ActionAsyncRetry)
		working = domain.ActionAsyncRetry
	}

	d.action = working
	d.rail = failingRail
	if d.action == domain.ActionRailMorph {
		d.rail = proposalRail
	}

	// The attempt counter is durable state that a bug or a tamper could put out
	// of range. It is clamped for every downstream consumer, and the raw
	// observation is preserved in the trace so the clamp is never silent.
	attempt := in.AttemptNumber
	if attempt < 0 {
		attempt = 0
	}
	if attempt > g.cfg.MaxAttempts {
		attempt = g.cfg.MaxAttempts
	}
	if attempt != in.AttemptNumber {
		d.note("observed attempt number %d clamped to %d for scheduling", in.AttemptNumber, attempt)
	}

	// ---- 1. AMOUNT_PINNED -------------------------------------------------
	//
	// The money fields are copied from the HMAC-verified payment entity and
	// from nowhere else. DiagnosticProposal has no amount field, but that is a
	// shape guarantee rather than a runtime one: error_reason is
	// attacker-influenced free text that reaches the model, so any path that
	// let model output contribute to the amount would promote a prompt
	// injection into an arbitrary-value debit against a real card. These two
	// locals are assigned exactly once, here, and re-checked against
	// in.Payment immediately before the command leaves the package.
	amountPaisa := in.Payment.Amount
	currency := in.Payment.Currency
	pinWhy := fmt.Sprintf("amount=%d currency=%s pinned from verified payment %s",
		amountPaisa, sanitizeToken(currency, 8), sanitizeToken(in.Payment.ID, maxTokenRunes))
	if !chargeable(amountPaisa, currency) {
		// A non-positive amount or a non-ISO currency means the payload is not
		// the thing we think it is. Pin it verbatim for the record, then refuse
		// to schedule anything against it.
		d.action = domain.ActionAbstain
		pinWhy += "; not a chargeable money value, refusing to schedule"
	}
	d.fire(RuleAmountPinned, pinWhy)

	// ---- 2. TERMINAL_DECLINE ---------------------------------------------
	//
	// The taxonomy is keyed on Razorpay's canonical lower-case codes and looked
	// up exactly. The code is folded first so that a gateway that ever emits
	// "CARD_EXPIRED" or a trailing space does not buy an expired card three
	// more retries; folding can only ever move a decision towards abstaining.
	errorCode := strings.ToLower(strings.TrimSpace(in.Payment.ErrorCode))
	if domain.IsTerminalDecline(errorCode) {
		d.veto(RuleTerminalDecline, fmt.Sprintf("issuer decline %q is terminal (%s): a retry cannot succeed and still costs a gateway fee",
			sanitizeToken(errorCode, 48), domain.TerminalDeclineCodes[errorCode]))
	}

	// ---- 3. STOP_RULE_MAX_ATTEMPTS ---------------------------------------
	if in.AttemptNumber > g.cfg.MaxAttempts {
		d.veto(RuleStopMaxAttempts, fmt.Sprintf("attempt %d exceeds the ceiling of %d", in.AttemptNumber, g.cfg.MaxAttempts))
	}

	// ---- 4. LOW_CONFIDENCE_ABSTAIN ---------------------------------------
	//
	// Written as a positive assertion because every comparison against NaN is
	// false: `conf < min` would wave a NaN confidence straight through.
	conf := in.Proposal.ConfidenceScore
	if !(conf >= g.cfg.MinConfidence && conf <= 1.0) {
		d.veto(RuleLowConfidence, fmt.Sprintf("confidence %s is below the floor %s or outside [0,1]",
			strconv.FormatFloat(conf, 'f', 3, 64), strconv.FormatFloat(g.cfg.MinConfidence, 'f', 3, 64)))
	}

	// ---- 5. UNRECOVERABLE_CLASS ------------------------------------------
	if !class.Recoverable() {
		d.veto(RuleUnrecoverableClass, fmt.Sprintf("failure class %s is not recoverable by retrying", class))
	}

	// ---- 6. SESSION_REQUIRED_FOR_MORPH -----------------------------------
	if !d.abstained() && d.action == domain.ActionRailMorph && !in.SessionActive {
		d.action = domain.ActionAsyncRetry
		d.rail = failingRail
		d.fire(RuleSessionRequired, "no live checkout session to morph; downgraded to an async retry on the original rail")
	}

	// ---- 7. RAIL_ALLOWLIST -----------------------------------------------
	if !d.abstained() && d.action == domain.ActionRailMorph {
		if why, ok := morphTargetRejection(d.rail, failingRail, in.AvailableRails); !ok {
			d.action = domain.ActionAsyncRetry
			d.rail = failingRail
			d.fire(RuleRailAllowlist, why+"; downgraded to an async retry on the original rail")
		}
	}

	// Backoff is policy arithmetic, not an invariant: the gate only bounds it.
	// The clamped attempt is handed to the engine so a corrupted counter cannot
	// drive an exponential term inside it.
	switch d.action {
	case domain.ActionAsyncRetry, domain.ActionMandateCascade:
		d.delay = g.backoffSeconds(ctx, attempt, class, in.Telemetry)
		if p := in.Proposal.RecommendedDelaySec; p > d.delay && p <= domain.MaxRecommendedDelay {
			// The model is allowed to make us more patient and never more
			// aggressive: only the aggressive direction spends money and trips
			// issuer abuse heuristics.
			d.delay = p
			d.note("proposal asked for a longer wait (%ds) than policy computed; honoured", p)
		}
	case domain.ActionRailMorph:
		// A morph lands inside a live session. A delayed morph is a morph the
		// customer has already walked away from.
		d.delay = 0
	}

	// ---- 8. RBI_MANDATE_COOLING ------------------------------------------
	if !d.abstained() && recurring {
		required := g.cfg.MandateCoolingSeconds
		if in.Mandate != nil && in.Mandate.NextEligibleAt != nil {
			if wait := secondsUntil(*in.Mandate.NextEligibleAt, now); wait > required {
				required = wait
			}
		}
		why := fmt.Sprintf("recurring debit: action forced to %s, delay floored at %ds, pre-debit obligation set",
			domain.ActionMandateCascade, required)
		if required > domain.MaxRecommendedDelay {
			// The mandate is not eligible within the schedulable horizon. A
			// clamp here would move the debit earlier than the mandate allows,
			// so the incident is abandoned instead.
			d.veto(RuleMandateCooling, why+"; required wait exceeds the maximum schedulable horizon, refusing to schedule")
		} else {
			d.action = domain.ActionMandateCascade
			d.rail = failingRail
			d.preDebit = true
			if d.delay < required {
				d.delay = required
			}
			d.fire(RuleMandateCooling, why)
		}
	}

	// ---- 9. RBI_PRE_DEBIT_NOTICE -----------------------------------------
	//
	// The flag set by rule 8 asserts the obligation; it is never cleared by a
	// notice already on record, because the executor is the component that
	// dedupes delivery. A gate that cleared the flag from a stale mandate row
	// would silently authorise an unnotified debit.
	if !d.abstained() && recurring && !noticeSatisfied(in.Mandate, now) {
		d.preDebit = true
		d.fire(RulePreDebitNotice, "no valid pre-debit notice on record for the current cycle; notice must be delivered before this debit")
	}

	// ---- 9a. RBI_AFA_CEILING ---------------------------------------------
	//
	// A registered mandate may debit without a fresh additional factor only up
	// to a ceiling: Rs 15,000 in general, Rs 1,00,000 for insurance, mutual
	// fund and credit card bill mandates. Above it the debit needs
	// authentication and cannot simply be re-presented, so an automatic retry
	// there is not a suboptimal choice but a regulatory breach.
	//
	// The category is read from the mandate record when one is attached and
	// defaults to the general ceiling otherwise. Defaulting the strict way
	// matters: an unknown category must never widen a regulatory limit.
	if !d.abstained() && recurring {
		category := domain.CategoryGeneral
		if in.Mandate != nil && in.Mandate.Category != "" {
			category = domain.ParseMandateCategory(string(in.Mandate.Category))
		}
		if ceiling := category.AFACeilingPaisa(); in.Payment.Amount > ceiling {
			d.veto(RuleAFACeiling, fmt.Sprintf(
				"recurring debit of %d paisa exceeds the %s additional-factor ceiling of %d paisa; authentication is required and an automatic retry is not permitted",
				in.Payment.Amount, category, ceiling))
		}
	}

	// ---- 10. MANDATE_HALTED ----------------------------------------------
	//
	// Applied whenever a halted mandate is attached, recurring flag or not: a
	// halted mandate is a customer- or issuer-level stop, and a payment that
	// arrives carrying one is exactly the case where we must not guess.
	if in.Mandate != nil && in.Mandate.Halted {
		d.veto(RuleMandateHalted, fmt.Sprintf("mandate %s is halted (%s)",
			sanitizeToken(in.Mandate.SubscriptionID, maxTokenRunes),
			orDefault(sanitizeText(in.Mandate.HaltReason, 80), "reason unrecorded")))
	}

	// ---- 11. MANDATE_CYCLE_CAP -------------------------------------------
	if in.Mandate != nil && in.Mandate.AttemptsInCycle >= g.cfg.MandateCycleCap {
		d.veto(RuleMandateCycleCap, fmt.Sprintf("%d attempts already made in cycle %s (cap %d); mandate must be halted",
			in.Mandate.AttemptsInCycle, orDefault(sanitizeToken(in.Mandate.CycleKey, 32), "unkeyed"), g.cfg.MandateCycleCap))
	}

	// ---- 11a. INSTRUMENT_REFRESH_ALLOWED ---------------------------------
	//
	// A refresh re-presents the same instrument through a different credential
	// form; it does not move rails. The rail is therefore pinned to the
	// payment's own method rather than left unset, because an executable
	// command naming no rail would reach the gateway with nothing to present
	// on. The presentation is forced to a network token, which is the only
	// form that recovers a changed card number.
	//
	// Amount and currency are untouched here, and a test asserts it: a refresh
	// that could alter either would reintroduce exactly the hazard the pinned
	// amount exists to prevent.
	if d.action == domain.ActionInstrumentRefresh {
		if rail := domain.RailFromMethod(in.Payment.Method); rail != domain.RailNone {
			d.rail = rail
			d.presentation = domain.PresentationNetworkToken
			d.fire(RuleInstrumentRefresh, fmt.Sprintf(
				"re-presenting on %s as a network token; amount and mandate terms unchanged", rail))
		} else {
			d.veto(RuleInstrumentRefresh, fmt.Sprintf(
				"cannot refresh an instrument for method %q: no rail to present on",
				sanitizeToken(in.Payment.Method, maxTokenRunes)))
		}
	}

	// ---- 12. DELAY_BOUNDS ------------------------------------------------
	boundWhy := fmt.Sprintf("delay %ds bounded into [0,%d]", d.delay, domain.MaxRecommendedDelay)
	if d.delay < 0 {
		d.delay = 0
	}
	if d.delay > domain.MaxRecommendedDelay {
		d.delay = domain.MaxRecommendedDelay
	}
	if !executable(d.action) {
		// An abstained incident carries no schedule, no rail and no notice
		// obligation. Leaving them populated invites an executor bug to act on
		// a decision that said "do nothing".
		d.delay, d.rail, d.preDebit = 0, domain.RailNone, false
		d.presentation = domain.PresentationUnchanged
		boundWhy = fmt.Sprintf("action %s is not executable: schedule, rail and notice obligation cleared", d.action)
	}
	d.fire(RuleDelayBounds, boundWhy)

	cmd := domain.SanitizedCommand{
		IncidentID:                 in.IncidentID,
		PaymentID:                  in.Payment.ID,
		OrderID:                    in.Payment.OrderID,
		ImmutableAmountPaisa:       amountPaisa,
		Currency:                   currency,
		Action:                     d.action,
		TargetRail:                 d.rail,
		Presentation:               d.presentation,
		ExecuteAfter:               now.Add(time.Duration(d.delay) * time.Second),
		DelaySeconds:               d.delay,
		AttemptNumber:              attempt,
		MaxAttempts:                g.cfg.MaxAttempts,
		PreDebitNotificationNeeded: d.preDebit,
		AppliedInvariants:          d.ruleNames(),
		ProposalMode:               normaliseMode(in.Proposal.Mode),
		ProposalConfidence:         safeConfidence(in.Proposal.ConfidenceScore),
		ProposalAction:             proposalAction,
		// A recommendation we could not even parse counts as overridden: the
		// executed action was chosen by this package, not proposed.
		OverrodeProposal: proposalMalformed || d.action != proposalAction,
		DecidedAt:        now,
	}
	cmd.AuditTrace = buildTrace(in, cmd, d, class, recurring)

	if err := assertMoneyPinned(cmd, in.Payment); err != nil {
		return domain.SanitizedCommand{}, err
	}
	return cmd, nil
}

// RequiresMandateHalt reports whether a decision obliges the caller to halt the
// mandate. Decide never writes through in.Mandate — mutating a caller's record
// would make the gate impure and racy — so the cycle-cap verdict travels out
// through the command, and this is the supported way to read it.
func RequiresMandateHalt(cmd domain.SanitizedCommand) bool {
	for _, name := range cmd.AppliedInvariants {
		if name == RuleMandateCycleCap {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// decision accumulator
// ---------------------------------------------------------------------------

type firedRule struct {
	name string
	why  string
}

// decision is the mutable working state of one evaluation. It never escapes
// Decide, which is what keeps the Gatekeeper itself stateless.
type decision struct {
	action domain.Action
	rail   domain.Rail
	// presentation is how the instrument will be offered on this attempt. It
	// defaults to unchanged, so only a rule that deliberately re-presents can
	// move it.
	presentation domain.InstrumentPresentation
	delay        int64
	preDebit     bool
	fired        []firedRule
	notes        []string
}

func (d *decision) fire(name, why string) {
	d.fired = append(d.fired, firedRule{name: name, why: why})
}

// veto records a rule and forces abstention. Abstention is sticky: no later
// rule ever re-escalates an abstained decision into an executable one, which is
// what makes a terminal decline or an exhausted attempt budget final.
func (d *decision) veto(name, why string) {
	d.action = domain.ActionAbstain
	d.fire(name, why)
}

func (d *decision) abstained() bool { return d.action == domain.ActionAbstain }

func (d *decision) note(format string, args ...any) {
	d.notes = append(d.notes, fmt.Sprintf(format, args...))
}

func (d *decision) ruleNames() []string {
	names := make([]string, len(d.fired))
	for i, r := range d.fired {
		names[i] = r.name
	}
	return names
}

// ---------------------------------------------------------------------------
// rule helpers
// ---------------------------------------------------------------------------

// executable delegates to the domain rather than re-listing the actions.
//
// A local copy of this predicate silently fell out of date when a new action
// was added: the gatekeeper set a rail for an instrument refresh and then
// cleared it again, emitting an executable command naming no rail. Deriving it
// from the single definition removes the class of bug rather than the instance.
func executable(a domain.Action) bool {
	return domain.SanitizedCommand{Action: a}.Executable()
}

// chargeable rejects money values that cannot correspond to a real Razorpay
// payment. Currency is compared case-insensitively because the field is echoed
// from the payload rather than normalised by us.
func chargeable(paisa int64, currency string) bool {
	if paisa <= 0 {
		return false
	}
	if len(currency) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		c := currency[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// morphTargetRejection returns the reason a morph target is unacceptable. Rail
// morphing is the one action that changes where the customer's money goes, so
// the target must be a known rail, must be on the merchant's list, and must not
// be the rail that just failed.
func morphTargetRejection(target, failing domain.Rail, available []domain.Rail) (string, bool) {
	if !target.Valid() || target == domain.RailNone {
		return fmt.Sprintf("morph target %q is not a usable rail", sanitizeToken(string(target), 32)), false
	}
	if target == failing {
		return fmt.Sprintf("morph target %s is the rail that just failed", target), false
	}
	limit := len(available)
	if limit > maxRailsConsidered {
		limit = maxRailsConsidered
	}
	for i := 0; i < limit; i++ {
		// Entries are re-validated: the caller's list is configuration, and a
		// junk entry must not be matchable by anything.
		if available[i].Valid() && available[i] == target {
			return "", true
		}
	}
	return fmt.Sprintf("morph target %s is not in the merchant's available rail set", target), false
}

// noticeSatisfied reports whether a pre-debit notice already on record can
// license the next debit.
func noticeSatisfied(m *domain.MandateRecord, now time.Time) bool {
	if m == nil || m.PreDebitNotifiedAt == nil {
		return false
	}
	sent := *m.PreDebitNotifiedAt
	if sent.After(now) {
		// A notice dated in the future is corrupt state, not a valid notice.
		return false
	}
	return now.Sub(sent) <= noticeValidity
}

// backoffSeconds delegates to the policy engine, which owns the jitter. The
// gate stays deterministic with respect to its own inputs.
func (g *Gatekeeper) backoffSeconds(ctx context.Context, attempt int, class domain.FailureClass, snap domain.TelemetrySnapshot) int64 {
	if g.policy == nil {
		return fallbackBackoffSeconds(attempt)
	}
	return durationToSeconds(g.policy.BackoffFor(ctx, attempt, class, snap))
}

// fallbackBackoffSeconds is used only when a deployment supplied no policy
// engine. It is jitter-free on purpose: jitter is the policy engine's job, and
// a misconfigured deployment should still schedule something sane rather than
// hammering an issuer instantly.
func fallbackBackoffSeconds(attempt int) int64 {
	const base = 30
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 16 {
		attempt = 16
	}
	secs := int64(base) << uint(attempt)
	if secs > domain.MaxRecommendedDelay {
		return domain.MaxRecommendedDelay
	}
	return secs
}

// durationToSeconds converts a policy backoff into whole seconds, rounding up
// so a sub-second backoff never degenerates into an instant retry. The upper
// comparison happens before the rounding addition so the addition cannot
// overflow on a hostile duration.
func durationToSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	if d >= maxSchedulableDuration {
		return domain.MaxRecommendedDelay
	}
	return int64((d + time.Second - 1) / time.Second)
}

// secondsUntil returns the whole seconds from now to t, rounded up. A target
// beyond the schedulable horizon returns one second past the ceiling, which the
// caller reads as "cannot be scheduled" rather than silently clamping a mandate
// eligibility date earlier than the mandate allows.
func secondsUntil(t, now time.Time) int64 {
	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	if d > maxSchedulableDuration {
		return domain.MaxRecommendedDelay + 1
	}
	return int64((d + time.Second - 1) / time.Second)
}

// safeConfidence normalises the advisory score before it is stored.
// encoding/json refuses to marshal NaN and ±Inf, so an unnormalised score from
// a broken model would make the whole command unserialisable and take the audit
// write down with it. Zero is both the safe value and the fail-closed one.
func safeConfidence(c float64) float64 {
	if math.IsNaN(c) || math.IsInf(c, 0) || c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

// normaliseMode keeps provenance honest: a mode outside the known set is
// sanitised for safe rendering but not rewritten into a known one, because a
// falsified provenance is worse than an unfamiliar one.
func normaliseMode(m domain.InferenceMode) domain.InferenceMode {
	switch m {
	case domain.ModeLive, domain.ModeReplay, domain.ModeHeuristic, domain.ModeSkipped:
		return m
	default:
		return domain.InferenceMode(sanitizeToken(string(m), 24))
	}
}

// assertMoneyPinned is the final check before a command leaves the package. It
// is unreachable given the code above, and that is the point: it converts a
// future refactor that reintroduces a proposal-sourced amount from a silent
// arbitrary-value debit into a hard stop.
func assertMoneyPinned(cmd domain.SanitizedCommand, p domain.PaymentEntity) error {
	if cmd.ImmutableAmountPaisa != p.Amount || cmd.Currency != p.Currency {
		return fmt.Errorf("%w: command carries %d %s, verified payment carries %d %s",
			ErrMoneyTampered,
			cmd.ImmutableAmountPaisa, sanitizeToken(cmd.Currency, 8),
			p.Amount, sanitizeToken(p.Currency, 8))
	}
	return nil
}

// ---------------------------------------------------------------------------
// audit trace
// ---------------------------------------------------------------------------

// buildTrace renders the human-readable explanation stored on the command.
// Every line is system-generated; the single piece of model free text is
// sanitised, rune-capped and fenced, and the fence characters are stripped from
// the content so the model cannot forge its own closing delimiter and dictate
// the rest of the trace to whoever reads it.
func buildTrace(in domain.GateInput, cmd domain.SanitizedCommand, d *decision, class domain.FailureClass, recurring bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gate v1 incident=%s payment=%s order=%s amount=%d %s method=%s issuer=%s recurring=%t session=%t attempt=%d/%d\n",
		sanitizeToken(cmd.IncidentID, maxTokenRunes),
		sanitizeToken(cmd.PaymentID, maxTokenRunes),
		orDefault(sanitizeToken(cmd.OrderID, maxTokenRunes), "none"),
		cmd.ImmutableAmountPaisa,
		orDefault(sanitizeToken(cmd.Currency, 8), "none"),
		orDefault(sanitizeToken(in.Payment.Method, 16), "unknown"),
		orDefault(sanitizeToken(in.Payment.Issuer(), maxTokenRunes), "unknown"),
		recurring, in.SessionActive, cmd.AttemptNumber, cmd.MaxAttempts)
	fmt.Fprintf(&b, "decision action=%s rail=%s delay=%ds execute_after=%s overrode_proposal=%t\n",
		cmd.Action, cmd.TargetRail, cmd.DelaySeconds,
		cmd.ExecuteAfter.UTC().Format(time.RFC3339), cmd.OverrodeProposal)
	fmt.Fprintf(&b, "proposal mode=%s action=%s confidence=%s class=%s error_code=%s\n",
		orDefault(string(cmd.ProposalMode), "none"),
		cmd.ProposalAction,
		strconv.FormatFloat(cmd.ProposalConfidence, 'f', 3, 64),
		class,
		orDefault(sanitizeToken(in.Payment.ErrorCode, 48), "none"))

	b.WriteString("invariants:\n")
	for i, r := range d.fired {
		fmt.Fprintf(&b, "  %d. %s: %s\n", i+1, r.name, r.why)
	}
	if len(d.notes) > 0 {
		b.WriteString("normalisation:\n")
		for _, n := range d.notes {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	fmt.Fprintf(&b, "model_reasoning (untrusted data, sanitised, %d rune cap):\n{{{%s}}}\n",
		maxReasoningRunes, orDefault(sanitizeText(in.Proposal.ReasoningTrace, maxReasoningRunes), "none"))

	return capBytes(b.String(), maxTraceBytes)
}

// sanitizeText makes untrusted free text safe to embed in the trace: invalid
// UTF-8 is dropped, control characters (including the newlines and escape
// sequences that would let text forge trace lines or drive an operator's
// terminal) become spaces or vanish, and the brace/bracket/angle characters
// used as fences are removed outright.
func sanitizeText(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '{' || r == '}' || r == '[' || r == ']' || r == '<' || r == '>':
			continue
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	return capRunes(strings.TrimSpace(b.String()), maxRunes)
}

// sanitizeToken reduces an identifier to the character set identifiers are
// actually drawn from, so a hostile id cannot smuggle structure into the trace.
func sanitizeToken(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == ':' || r == '.' || r == '@' || r == '/':
			b.WriteRune(r)
		}
	}
	return capRunes(b.String(), maxRunes)
}

func capRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i] + "..."
		}
		count++
	}
	return s
}

// capBytes truncates on a rune boundary so a clipped trace stays valid UTF-8
// and therefore stays storable in a text column and renderable in the console.
func capBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[trace truncated]\n"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// systemClock is the fallback used when New is handed a nil clock. Library code
// never sleeps; it only ever reads the current instant.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

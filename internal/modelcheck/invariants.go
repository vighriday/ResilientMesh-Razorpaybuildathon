package modelcheck

import (
	"fmt"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
)

// The invariant names. They are part of this package's output contract: the
// CLI, CI gates and any report consumer match on them rather than parsing the
// human-readable detail string.
const (
	// InvAmountPinned is the money-safety property the whole trust boundary
	// exists for.
	InvAmountPinned = "AMOUNT_PINNED"
	// InvRecurringCooling is the RBI e-mandate 24-hour re-presentment window
	// together with the pre-debit notification obligation that rides with it.
	InvRecurringCooling = "RECURRING_COOLING_AND_NOTICE"
	// InvAttemptCap is the retry ceiling that keeps one incident from becoming
	// a retry storm.
	InvAttemptCap = "ATTEMPT_CAP"
	// InvAFACeiling is the additional-factor-authentication ceiling: above it a
	// recurring debit needs a fresh factor and may not simply be re-presented.
	InvAFACeiling = "AFA_CEILING"
	// InvClosedActionSet is the fail-closed property of the action vocabulary.
	InvClosedActionSet = "CLOSED_ACTION_SET"
	// InvRefreshPreservesTerms is the D1 rule that an instrument refresh may
	// change only how the instrument is presented.
	InvRefreshPreservesTerms = "REFRESH_PRESERVES_TERMS"
	// InvExecutableNamesRail asserts that a command the executor will act on
	// says where to act.
	InvExecutableNamesRail = "EXECUTABLE_NAMES_A_RAIL"
	// InvScheduleBounded asserts the emitted schedule is representable and
	// internally consistent.
	InvScheduleBounded = "SCHEDULE_BOUNDED"
	// InvGateError is not a property of a command but of the decision call: a
	// gatekeeper that errors on a well-formed input has failed to decide, and
	// silently skipping such a state would shrink the proof without saying so.
	InvGateError = "GATE_DECIDES_WITHOUT_ERROR"
)

// checkInput is everything an invariant may read about one explored state.
type checkInput struct {
	state State
	in    domain.GateInput
	cmd   domain.SanitizedCommand

	// maxAttempts is the ceiling the first decision of the run reported. The
	// gate's cap is configuration, not per-incident data, so a cap that varies
	// between states is itself the defect.
	maxAttempts int
}

// invariant is one property asserted at every reachable state.
type invariant struct {
	name string
	// why records the obligation the property discharges. It is carried into
	// the report so a reader who has never opened this file can tell whether a
	// violation is a compliance breach or a hygiene issue.
	why string
	// check returns the reason the property failed, or the empty string when it
	// holds. Returning the reason rather than a bool keeps the witness specific
	// enough to reproduce.
	check func(c checkInput) string
}

// invariants is the asserted property set, evaluated in this order at every
// state. The order is fixed so two runs produce identical reports.
var invariants = []invariant{
	{
		name: InvAmountPinned,
		why: "the executed amount and currency must come from the HMAC-verified payment and from nowhere else; " +
			"any path by which model output reaches them turns a prompt injection into an arbitrary-value debit",
		check: func(c checkInput) string {
			if c.cmd.ImmutableAmountPaisa != c.in.Payment.Amount {
				return fmt.Sprintf("command amount %d paisa != verified payment amount %d paisa",
					c.cmd.ImmutableAmountPaisa, c.in.Payment.Amount)
			}
			if c.cmd.Currency != c.in.Payment.Currency {
				return fmt.Sprintf("command currency %q != verified payment currency %q",
					c.cmd.Currency, c.in.Payment.Currency)
			}
			return ""
		},
	},
	{
		name: InvRecurringCooling,
		why: "RBI e-mandate rules forbid re-presenting a recurring debit inside 24 hours and require a pre-debit " +
			"notice before the debit; both obligations attach to any recurring command the executor will act on",
		check: func(c checkInput) string {
			if !c.in.Payment.IsRecurring() || !c.cmd.Executable() {
				return ""
			}
			if c.cmd.DelaySeconds < gatekeeper.DefaultMandateCoolingSeconds {
				return fmt.Sprintf("recurring executable command scheduled in %ds, inside the %ds cooling window",
					c.cmd.DelaySeconds, gatekeeper.DefaultMandateCoolingSeconds)
			}
			if !c.cmd.PreDebitNotificationNeeded {
				return "recurring executable command carries no pre-debit notification obligation"
			}
			return ""
		},
	},
	{
		name: InvAttemptCap,
		why: "the per-incident retry ceiling is what stops one failure from becoming a retry storm; a command may " +
			"never carry an attempt number above the cap it declares",
		check: func(c checkInput) string {
			if c.cmd.MaxAttempts <= 0 {
				return fmt.Sprintf("command declares a non-positive attempt ceiling of %d", c.cmd.MaxAttempts)
			}
			if c.maxAttempts > 0 && c.cmd.MaxAttempts != c.maxAttempts {
				return fmt.Sprintf("attempt ceiling %d differs from the %d reported elsewhere in this run; "+
					"the ceiling is configuration and must not vary per incident", c.cmd.MaxAttempts, c.maxAttempts)
			}
			if c.cmd.AttemptNumber < 0 || c.cmd.AttemptNumber > c.cmd.MaxAttempts {
				return fmt.Sprintf("command attempt %d is outside [0,%d]", c.cmd.AttemptNumber, c.cmd.MaxAttempts)
			}
			return ""
		},
	},
	{
		name: InvAFACeiling,
		why: "above its category's additional-factor ceiling a recurring debit requires fresh authentication; an " +
			"automatic re-presentment there is a regulatory breach, not a suboptimal choice",
		check: func(c checkInput) string {
			if !c.in.Payment.IsRecurring() || !c.cmd.Executable() {
				return ""
			}
			category := domain.CategoryGeneral
			if c.in.Mandate != nil {
				category = c.in.Mandate.Category
			}
			ceiling := category.AFACeilingPaisa()
			if c.cmd.ImmutableAmountPaisa > ceiling {
				return fmt.Sprintf("executable %s for %d paisa on a %q mandate whose AFA ceiling is %d paisa",
					c.cmd.Action, c.cmd.ImmutableAmountPaisa, category, ceiling)
			}
			return ""
		},
	},
	{
		name: InvClosedActionSet,
		why: "the action vocabulary is closed so that anything the gate cannot fully understand degrades to " +
			"PERMANENT_ABSTAIN; an action outside the set is an instruction nobody has reviewed",
		check: func(c checkInput) string {
			if !c.cmd.Action.Valid() {
				return fmt.Sprintf("command action %q is outside the closed action set", c.cmd.Action)
			}
			if !c.cmd.TargetRail.Valid() {
				return fmt.Sprintf("command rail %q is outside the closed rail set", c.cmd.TargetRail)
			}
			return ""
		},
	},
	{
		name: InvRefreshPreservesTerms,
		why: "an instrument refresh re-presents the same debit through a different credential form; if it could " +
			"also move the amount, the currency or the rail it would be a new authorisation wearing a refresh's name",
		check: func(c checkInput) string {
			if c.cmd.Action != domain.ActionInstrumentRefresh {
				return ""
			}
			if c.cmd.ImmutableAmountPaisa != c.in.Payment.Amount || c.cmd.Currency != c.in.Payment.Currency {
				return fmt.Sprintf("refresh altered money terms: %d %s against a verified %d %s",
					c.cmd.ImmutableAmountPaisa, c.cmd.Currency, c.in.Payment.Amount, c.in.Payment.Currency)
			}
			// RailNone is an absence rather than a switch, so it is not a term
			// change here; InvExecutableNamesRail is what objects to it.
			if c.cmd.TargetRail != domain.RailNone && c.cmd.TargetRail != failingRail {
				return fmt.Sprintf("refresh moved the debit from rail %s to rail %s", failingRail, c.cmd.TargetRail)
			}
			return ""
		},
	},
	{
		name: InvExecutableNamesRail,
		why: "a command the executor will act on must say which rail to act on; a command that says 'attempt' and " +
			"names no rail leaves the executor's behaviour undefined at the moment it touches money",
		check: func(c checkInput) string {
			if !c.cmd.Executable() {
				return ""
			}
			if c.cmd.TargetRail == domain.RailNone || !c.cmd.TargetRail.Valid() {
				return fmt.Sprintf("executable %s names rail %q", c.cmd.Action, c.cmd.TargetRail)
			}
			return ""
		},
	},
	{
		name: InvScheduleBounded,
		why: "the schedule is absolute so a queued command cannot drift across a restart; it must therefore be " +
			"representable, non-negative, and consistent with the delay it reports",
		check: func(c checkInput) string {
			if c.cmd.DelaySeconds < 0 || c.cmd.DelaySeconds > domain.MaxRecommendedDelay {
				return fmt.Sprintf("delay %ds is outside [0,%d]", c.cmd.DelaySeconds, domain.MaxRecommendedDelay)
			}
			want := c.cmd.DecidedAt.Add(secondsDuration(c.cmd.DelaySeconds))
			if !c.cmd.ExecuteAfter.Equal(want) {
				return fmt.Sprintf("execute_after %s does not equal decided_at %s plus %ds",
					c.cmd.ExecuteAfter.UTC().Format(timeLayout), c.cmd.DecidedAt.UTC().Format(timeLayout), c.cmd.DelaySeconds)
			}
			if !c.cmd.Executable() && c.cmd.DelaySeconds != 0 {
				return fmt.Sprintf("non-executable %s still carries a %ds schedule", c.cmd.Action, c.cmd.DelaySeconds)
			}
			return ""
		},
	},
}

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Confidence constants for the heuristic tier.
//
// These are coarse on purpose. They are an honest statement of how much a rule
// over three signals is worth, not calibrated posteriors, and inventing a third
// decimal place would dress up a lookup table as a model. All of them sit above
// domain.MinConfidenceToActOn (0.55) because a rule that fires at all has
// matched real evidence; everything the rules do not recognise abstains at 0.
const (
	// A high-severity downtime notice naming this exact issuer is Razorpay's own
	// statement that the rail is down. It is the strongest evidence available
	// offline, but it is still a broadcast about an institution rather than an
	// observation of this payment, so it stays well short of certainty.
	confDowntimeOutage = 0.80

	// The issuer is measurably below its own portfolio baseline over a window
	// with enough samples to mean something. Strong, but degradation and
	// recovery look identical at the moment of measurement.
	confIssuerDegraded = 0.65

	// A timeout against healthy telemetry is the textbook transient network
	// fault, and the cheapest failure in the taxonomy to be wrong about: a short
	// retry costs one gateway fee.
	confNetworkTimeout = 0.70

	// upi_psp_error names the PSP layer explicitly, which is a specific claim,
	// but PSP faults and issuer faults are routinely reported under the same
	// code, so it is not as informative as it looks.
	confPSPDegradation = 0.68

	// A soft decline states its own cause. The taxonomy calls this set
	// "recoverable but unambiguous", and acting on a stated cause is what a
	// rule table is actually good at, so these sit at the same level as a
	// measured degradation rather than below it.
	confSoftDecline = 0.66

	// An ambiguous infrastructure fault against telemetry that is not yet
	// informative. The code says a machine failed rather than a decision was
	// made, which is enough to justify one cheap retry and not enough to
	// justify more; the confidence says exactly that.
	confInfraFault = 0.60
)

// Backoff windows for the heuristic tier. The policy engine computes the real
// schedule; these are the tier's opinion, and the gatekeeper clamps them.
const (
	// Razorpay downtime windows resolve in tens of minutes. Retrying inside one
	// burns gateway fees and can trip an issuer's abuse heuristics, which is a
	// worse outcome than waiting.
	delayIssuerOutage = int64(900)

	// Degradation is partial: some attempts are succeeding, so a shorter probe
	// is justified than for a declared outage.
	delayIssuerDegraded = int64(120)

	// Short enough that an in-session payer may still be waiting.
	delayNetworkTimeout = int64(30)

	// PSP faults typically clear faster than issuer outages but slower than a
	// transient network blip.
	delayPSPDegradation = int64(180)

	// A stated soft decline needs the payer, not the issuer, to change
	// something: find funds, read a fresh OTP, approve a collect request. Ten
	// minutes is long enough for that and short enough to stay inside the
	// purchase intent.
	delaySoftDecline = int64(600)

	// Insufficient funds is the one soft decline where the payer cannot act
	// immediately. Retrying in minutes retries the same empty balance; six
	// hours crosses a salary credit or an incoming transfer, which is the event
	// that actually changes the outcome.
	delayInsufficientFunds = int64(6 * 3600)

	// An infrastructure fault is expected to clear on its own. Long enough to
	// miss the failing deploy or the restarting node, short enough that the
	// payer has not moved on.
	delayInfraFault = int64(60)
)

// infraFaultCodes are the ambiguous codes that name a machine failure rather
// than a decision. Every one of them is the payments equivalent of a 5xx: no
// party has declined anything, something upstream was unable to answer.
//
// They are kept as an explicit set rather than derived from IsAmbiguous because
// the two sets are not the same. "payment_pending" and "issuer_down" are also
// ambiguous, but the first is not a failure yet and the second is a declared
// outage; retrying either on a one-minute timer would be wrong.
var infraFaultCodes = map[string]struct{}{
	"bank_technical_error":    {},
	"gateway_technical_error": {},
	"gateway_error":           {},
	"server_error":            {},
}

// morphPreference is the deterministic order in which the heuristic offers an
// alternative rail. UPI intent first because it has the highest completion rate
// and lowest friction in India; card next; UPI collect last because it needs
// the payer to approve in another app, which is the most abandonment-prone step
// on the list. Deterministic ordering matters: a map iteration here would make
// the tier non-reproducible and its cassettes worthless.
var morphPreference = []domain.Rail{
	domain.RailUPIIntent,
	domain.RailCard,
	domain.RailNetbanking,
	domain.RailWallet,
	domain.RailUPICollect,
}

// Heuristic is the last tier: a deterministic classifier over the error code,
// the rolling telemetry window, and Razorpay's downtime notices.
//
// It exists so the system has an answer when no model is reachable and no
// cassette matches. Every proposal it produces is marked Degraded, so an
// operator reading the audit trail can always tell a rule-based answer from an
// inferred one, and a benchmark can never quietly count one as the other.
type Heuristic struct {
	log   *slog.Logger
	clock domain.Clock
}

var _ domain.Diagnoser = (*Heuristic)(nil)

// NewHeuristic builds the tier. It takes a clock for symmetry with the others
// and because latency accounting must stay deterministic under test.
func NewHeuristic(logger *slog.Logger, clock domain.Clock) *Heuristic {
	return &Heuristic{log: orDiscard(logger), clock: orSystemClock(clock)}
}

// Describe names the tier for the console and the audit trail.
func (h *Heuristic) Describe() string { return "heuristic" }

// Diagnose classifies the failure by fixed rules and never returns an error:
// it is the tier of last resort, so it must always terminate the stack with a
// usable proposal, and its safe answer is abstention.
func (h *Heuristic) Diagnose(_ context.Context, dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	start := h.clock.Now()
	p := h.classify(dc)

	p.Mode = domain.ModeHeuristic
	// Always degraded: this is a rule table, not an inference, and the
	// distinction is what keeps the benchmark honest.
	p.Degraded = true
	p.LatencyMS = elapsedMS(h.clock, start)

	if err := finalize(&p, dc); err != nil {
		// Unreachable for the rules above, which only emit values they took from
		// the context. If a future rule breaks that property, abstaining is the
		// safe failure and the log says which rule to look at.
		h.log.Warn("heuristic proposal failed its own validation, abstaining",
			"incident_id", dc.IncidentID, "error", err.Error())
		safe := domain.AbstainProposal(dc.IncidentID,
			"heuristic classifier produced an invalid proposal", domain.ModeHeuristic)
		safe.LatencyMS = elapsedMS(h.clock, start)
		return safe, nil
	}
	return p, nil
}

// classify applies the rules in priority order. The order encodes which
// evidence dominates: an explicit outage notice beats a measured rate, a
// measured rate beats a bare error code, and an unrecognised code loses.
func (h *Heuristic) classify(dc domain.DiagnosticContext) domain.DiagnosticProposal {
	issuer := sanitizeToken(dc.IssuerKey, maxIssuerLen)
	degraded := dc.Telemetry.Degraded()
	notice, hasNotice := matchingDowntime(dc.Downtimes)

	switch {
	case hasNotice && notice.Severity == domain.SeverityHigh:
		return domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassIssuerOutage,
			ConfidenceScore:       confDowntimeOutage,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delayIssuerOutage,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause: fmt.Sprintf(
				"high-severity downtime notice active for issuer %s", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=downtime_high_severity issuer=%s status=%s scheduled=%t; the issuer is declared down, "+
					"so recovery waits out the window instead of paying for attempts that cannot succeed",
				issuer, normStatus(notice.Status), notice.Scheduled),
		}

	case degraded || hasNotice:
		// A non-high-severity notice is evidence of degradation rather than a
		// declared outage, so it lands here with the measured-rate case.
		p := domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassTransientDegradation,
			ConfidenceScore:       confIssuerDegraded,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delayIssuerDegraded,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause: fmt.Sprintf(
				"issuer %s degraded against portfolio baseline", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=issuer_degraded issuer=%s attempts=%d success_rate=%.2f baseline=%.2f downtime_notice=%t",
				issuer, dc.Telemetry.Attempts, round3(dc.Telemetry.SuccessRate),
				round3(dc.Telemetry.BaselineRate), hasNotice),
		}
		return morphIfPossible(p, dc, "the payer is still in checkout, so moving rails now beats retrying later")

	case dc.ErrorCode == "payment_timed_out" && !degraded:
		return domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassNetworkTimeout,
			ConfidenceScore:       confNetworkTimeout,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delayNetworkTimeout,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause:     fmt.Sprintf("network timeout against healthy issuer %s", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=timeout_healthy_issuer issuer=%s attempts=%d success_rate=%.2f; telemetry shows the issuer "+
					"is fine, so the timeout is in transit and a short retry is the cheapest correct response",
				issuer, dc.Telemetry.Attempts, round3(dc.Telemetry.SuccessRate)),
		}

	case dc.ErrorCode == "upi_psp_error":
		p := domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassPSPDegradation,
			ConfidenceScore:       confPSPDegradation,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delayPSPDegradation,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause:     fmt.Sprintf("UPI PSP fault reported for handle %s", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=upi_psp_error issuer=%s; the PSP layer failed rather than the payer's bank, so a different "+
					"rail is likelier to succeed than the same one", issuer),
		}
		return morphIfPossible(p, dc, "a live session can be moved off the failing PSP immediately")

	case domain.IsRefreshable(dc.ErrorCode):
		// The instrument, not the transaction, is what failed. Retrying the
		// same credential repeats the same decline; re-presenting through a
		// network token is the only action that can change the outcome, and RBI
		// card-on-file tokenization means the token already exists.
		return domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassInstrumentStale,
			ConfidenceScore:       confSoftDecline,
			RecommendedAction:     domain.ActionInstrumentRefresh,
			RecommendedDelaySec:   0,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause: fmt.Sprintf(
				"stored credential for issuer %s is stale rather than invalid", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=instrument_refresh issuer=%s code=%s; the funding account did not go away, only the "+
					"credential did, so the network token is re-presented instead of the stored card",
				issuer, sanitizeToken(dc.ErrorCode, maxCodeLen)),
		}

	case domain.IsSoftDecline(dc.ErrorCode):
		// A soft decline states its cause, which is why the taxonomy comment
		// says the policy engine handles these without the model. What varies
		// is only when to come back, and that is a function of who has to act.
		delay, class, why := softDeclinePlan(dc.ErrorCode)
		p := domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: class,
			ConfidenceScore:       confSoftDecline,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delay,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause:     fmt.Sprintf("%s on issuer %s", why, issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=soft_decline code=%s issuer=%s delay=%ds; the decline names its own cause, so the only "+
					"open question is when the payer can act on it",
				sanitizeToken(dc.ErrorCode, maxCodeLen), issuer, delay),
		}
		// A live session is worth more than any schedule: a payer who is still
		// on the page can be moved to a rail that does not need the thing that
		// just failed.
		return morphIfPossible(p, dc, "the payer is still present, so a rail that avoids the failed step wins")

	case isInfraFault(dc.ErrorCode):
		// No party declined anything here; something upstream could not answer.
		// One cheap retry is the textbook response, and the gatekeeper's
		// attempt ceiling is what stops it becoming an unbounded one.
		p := domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.ClassTransientDegradation,
			ConfidenceScore:       confInfraFault,
			RecommendedAction:     domain.ActionAsyncRetry,
			RecommendedDelaySec:   delayInfraFault,
			SuggestedFallbackRail: domain.RailNone,
			InferredRootCause: fmt.Sprintf(
				"upstream infrastructure fault at %s with no decline decision recorded", issuer),
			ReasoningTrace: fmt.Sprintf(
				"rule=infra_fault code=%s issuer=%s attempts=%d success_rate=%.2f; the code reports an "+
					"inability to answer rather than a refusal, and telemetry is not yet informative enough "+
					"to say more",
				sanitizeToken(dc.ErrorCode, maxCodeLen), issuer, dc.Telemetry.Attempts,
				round3(dc.Telemetry.SuccessRate)),
		}
		return morphIfPossible(p, dc, "the failing path is upstream of the payer, so another rail avoids it")

	default:
		// Abstaining is the whole point of the tier's last branch: an
		// unrecognised code with no supporting evidence is not something a rule
		// table should be guessing about with a payer's money.
		return domain.AbstainProposal(dc.IncidentID,
			fmt.Sprintf("no heuristic rule matches error code %s with the available evidence",
				sanitizeToken(dc.ErrorCode, maxCodeLen)),
			domain.ModeHeuristic)
	}
}

// isInfraFault reports whether the code names a machine failure.
func isInfraFault(code string) bool {
	_, ok := infraFaultCodes[normToken(code, maxCodeLen)]
	return ok
}

// softDeclinePlan returns the delay, classification and phrasing for one soft
// decline.
//
// The delays differ because the actor differs. An OTP failure needs the payer
// to read a fresh message, which takes a minute; an empty balance needs money
// to arrive, which takes hours. A single delay for both would be wrong for one
// of them, and the one it would be wrong for is the expensive one.
func softDeclinePlan(code string) (delay int64, class domain.FailureClass, why string) {
	switch normToken(code, maxCodeLen) {
	case "insufficient_funds":
		return delayInsufficientFunds, domain.ClassInsufficientFunds,
			"balance was short at the moment of the debit"
	case "invalid_otp", "incorrect_otp", "authentication_failed":
		return delaySoftDecline, domain.ClassCustomerAction,
			"authentication step was not completed"
	case "upi_collect_expired":
		return delaySoftDecline, domain.ClassCustomerAction,
			"collect request expired before the payer approved it"
	case "mandate_not_active":
		// Not a payment problem at all: the mandate needs re-registration, and
		// no retry schedule fixes that. Classified as customer action so the
		// gatekeeper's recurring rules still apply.
		return delaySoftDecline, domain.ClassCustomerAction,
			"mandate is not currently active"
	default:
		// Reached only if SoftDeclineCodes gains a member this function has not
		// been taught about. The conservative delay is the right default: it is
		// wrong only in being slower than necessary.
		return delaySoftDecline, domain.ClassCustomerAction,
			"decline reported a payer-side cause"
	}
}

// morphIfPossible upgrades a retry to an in-session rail morph when a session
// is live and a different rail is actually on offer. A morph with no target is
// nonsense, and a morph with no session is a downgrade the gatekeeper would
// have to undo, so both cases stay as retries.
func morphIfPossible(p domain.DiagnosticProposal, dc domain.DiagnosticContext, why string) domain.DiagnosticProposal {
	if !dc.SessionActive {
		return p
	}
	target := pickMorphRail(dc)
	if target == domain.RailNone {
		return p
	}
	p.RecommendedAction = domain.ActionRailMorph
	p.SuggestedFallbackRail = target
	p.RecommendedDelaySec = 0
	p.ReasoningTrace += fmt.Sprintf("; morph=%s because %s", target, why)
	return p
}

// pickMorphRail returns the first offered rail that is not the one that just
// failed, in a fixed preference order.
func pickMorphRail(dc domain.DiagnosticContext) domain.Rail {
	failing := domain.RailFromMethod(dc.Method)
	offered := normRails(dc.AvailableRails)
	for _, candidate := range morphPreference {
		if candidate == failing {
			continue
		}
		for _, o := range offered {
			if o == candidate {
				return candidate
			}
		}
	}
	return domain.RailNone
}

// matchingDowntime returns the most severe active notice for this issuer.
// Scheduled maintenance counts: a payment failing inside an announced window
// fails for the announced reason.
func matchingDowntime(signals []domain.DowntimeSignal) (domain.DowntimeSignal, bool) {
	var best domain.DowntimeSignal
	found := false
	for _, s := range signals {
		if !s.MatchesIssuer || s.Status == domain.DowntimeResolved {
			continue
		}
		if !found || severityRank(s.Severity) > severityRank(best.Severity) {
			best, found = s, true
		}
	}
	return best, found
}

func severityRank(s domain.DowntimeSeverity) int {
	switch s {
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}

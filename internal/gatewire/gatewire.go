// Package gatewire is the JSON boundary around the gatekeeper.
//
// It exists so that the WebAssembly module a reader runs in their browser and
// the vector generator that produces the expected answers are literally the
// same code. Two encoders of the same decision would eventually disagree, and
// the disagreement would be indistinguishable from the thing the page exists to
// disprove, so there is exactly one.
//
// Nothing here decides anything. Every rule lives in internal/gatekeeper; this
// package decodes, calls, and encodes.
package gatewire

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
)

// fixedClock makes a decision a pure function of its input.
//
// The gatekeeper samples the clock once and derives every deadline from it, so
// handing it the host's wall clock would make two runs of the same input
// disagree about ExecuteAfter. The caller therefore names the instant.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// request is the wire shape the page sends. It mirrors domain.GateInput with
// the timestamps as strings, because a JSON number cannot hold a nanosecond
// timestamp without losing precision.
type Request struct {
	Now        string `json:"now"`
	MaxAttempt int    `json:"max_attempts"`

	IncidentID    string  `json:"incident_id"`
	AttemptNumber int     `json:"attempt_number"`
	SessionActive bool    `json:"session_active"`
	Seed          int64   `json:"seed"`
	MinConfidence float64 `json:"min_confidence"`

	Payment struct {
		ID             string `json:"id"`
		OrderID        string `json:"order_id"`
		SubscriptionID string `json:"subscription_id"`
		AmountPaisa    int64  `json:"amount_paisa"`
		Currency       string `json:"currency"`
		Method         string `json:"method"`
		Bank           string `json:"bank"`
		Wallet         string `json:"wallet"`
		VPA            string `json:"vpa"`
		ErrorCode      string `json:"error_code"`
		ErrorSource    string `json:"error_source"`
		ErrorStep      string `json:"error_step"`
		ErrorReason    string `json:"error_reason"`
	} `json:"payment"`

	// Proposal is what a model returned. Every field here is deliberately
	// caller-controlled, including ones a well-behaved model would never set,
	// because the interesting question is what happens when one does.
	Proposal struct {
		FailureClass    string  `json:"failure_class"`
		Action          string  `json:"recommended_action"`
		TargetRail      string  `json:"target_rail"`
		Confidence      float64 `json:"confidence_score"`
		RootCause       string  `json:"root_cause"`
		DelaySeconds    int64   `json:"delay_seconds"`
		IncidentID      string  `json:"incident_id"`
		ClaimedMode     string  `json:"mode"`
		ClaimedAmount   int64   `json:"amount_paisa"`
		ClaimedProvider string  `json:"model"`
	} `json:"proposal"`

	Telemetry struct {
		IssuerKey    string  `json:"issuer_key"`
		SuccessRate  float64 `json:"success_rate"`
		BaselineRate float64 `json:"baseline_rate"`
		Samples      int     `json:"samples"`
		Breaker      string  `json:"breaker_state"`
		SampledAt    string  `json:"sampled_at"`
	} `json:"telemetry"`

	Mandate *struct {
		SubscriptionID     string `json:"subscription_id"`
		AmountPaisa        int64  `json:"amount_paisa"`
		LastAttemptAt      string `json:"last_attempt_at"`
		NextEligibleAt     string `json:"next_eligible_at"`
		PreDebitNotifiedAt string `json:"pre_debit_notified_at"`
		AttemptsInCycle    int    `json:"attempts_in_cycle"`
		CycleKey           string `json:"cycle_key"`
		Category           string `json:"category"`
		Halted             bool   `json:"halted"`
		HaltReason         string `json:"halt_reason"`
	} `json:"mandate"`

	AvailableRails []string `json:"available_rails"`
}

// response reports what the gate decided and, more importantly, why.
type Response struct {
	OK bool `json:"ok"`

	Action            string   `json:"action"`
	TargetRail        string   `json:"target_rail"`
	AmountPaisa       int64    `json:"amount_paisa"`
	DelaySeconds      int64    `json:"delay_seconds"`
	ExecuteAfter      string   `json:"execute_after"`
	AttemptNumber     int      `json:"attempt_number"`
	MaxAttempts       int      `json:"max_attempts"`
	PreDebitNeeded    bool     `json:"pre_debit_notification_needed"`
	AppliedInvariants []string `json:"applied_invariants"`
	Reason            string   `json:"reason"`
	Executable        bool     `json:"executable"`
	Mode              string   `json:"mode"`
	OverrodeProposal  bool     `json:"overrode_proposal"`
	ProposalAction    string   `json:"proposal_action"`
	Presentation      string   `json:"presentation"`

	Error string `json:"error,omitempty"`
}

// DecideJSON is the single entry point both callers use.
//
// The browser module and the vector generator run this same function, so a
// difference between what a reader sees in the page and what the server
// produced would have to come from the platform rather than from two
// implementations drifting apart. There is only one implementation.
func DecideJSON(raw string) string {
	var req Request
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return fail("the request was not valid JSON: " + err.Error())
	}

	now, err := parseTime(req.Now, time.Now().UTC())
	if err != nil {
		return fail("now: " + err.Error())
	}

	in, err := buildInput(req, now)
	if err != nil {
		return fail(err.Error())
	}

	// The same policy engine the worker uses. Its randomness is seeded from the
	// request so a jittered backoff is reproducible for the caller.
	seed := req.Seed
	if seed == 0 {
		seed = 42
	}
	clock := fixedClock{at: now}
	gate := gatekeeper.New(clock, policy.New(clock, rand.New(rand.NewSource(seed))), gatekeeper.Config{
		MaxAttempts:   req.MaxAttempt,
		MinConfidence: req.MinConfidence,
	})

	cmd, err := gate.Decide(context.Background(), in)
	if err != nil {
		return fail(err.Error())
	}
	return encode(Response{
		OK:                true,
		Action:            string(cmd.Action),
		TargetRail:        string(cmd.TargetRail),
		AmountPaisa:       cmd.ImmutableAmountPaisa,
		DelaySeconds:      cmd.DelaySeconds,
		ExecuteAfter:      cmd.ExecuteAfter.UTC().Format(time.RFC3339),
		AttemptNumber:     cmd.AttemptNumber,
		MaxAttempts:       cmd.MaxAttempts,
		PreDebitNeeded:    cmd.PreDebitNotificationNeeded,
		AppliedInvariants: cmd.AppliedInvariants,
		Reason:            cmd.AuditTrace,
		Executable:        cmd.Executable(),
		Mode:              string(cmd.ProposalMode),
		OverrodeProposal:  cmd.OverrodeProposal,
		ProposalAction:    string(cmd.ProposalAction),
		Presentation:      string(cmd.Presentation),
	})
}

func buildInput(req Request, now time.Time) (domain.GateInput, error) {
	in := domain.GateInput{
		IncidentID:    orDefault(req.IncidentID, "inc_browser"),
		AttemptNumber: req.AttemptNumber,
		SessionActive: req.SessionActive,
	}

	in.Payment = domain.PaymentEntity{
		ID:             orDefault(req.Payment.ID, "pay_browser"),
		OrderID:        req.Payment.OrderID,
		SubscriptionID: req.Payment.SubscriptionID,
		Amount:         req.Payment.AmountPaisa,
		Currency:       orDefault(req.Payment.Currency, "INR"),
		Method:         req.Payment.Method,
		Bank:           req.Payment.Bank,
		Wallet:         req.Payment.Wallet,
		VPA:            req.Payment.VPA,
		ErrorCode:      req.Payment.ErrorCode,
		ErrorSource:    req.Payment.ErrorSource,
		ErrorStep:      req.Payment.ErrorStep,
		ErrorReason:    req.Payment.ErrorReason,
	}

	// Built through the ordinary struct rather than a constructor so a caller
	// can express a malformed proposal. That is the point of the exercise: the
	// gate has to survive input a well-behaved producer would never send, and a
	// builder that sanitised on the way in would be testing the builder.
	in.Proposal = domain.DiagnosticProposal{
		IncidentID:            req.Proposal.IncidentID,
		FailureClassification: domain.FailureClass(req.Proposal.FailureClass),
		RecommendedAction:     domain.Action(req.Proposal.Action),
		SuggestedFallbackRail: domain.Rail(req.Proposal.TargetRail),
		ConfidenceScore:       req.Proposal.Confidence,
		InferredRootCause:     req.Proposal.RootCause,
		RecommendedDelaySec:   req.Proposal.DelaySeconds,
	}

	sampledAt, err := parseTime(req.Telemetry.SampledAt, now)
	if err != nil {
		return domain.GateInput{}, fmt.Errorf("telemetry.sampled_at: %w", err)
	}
	in.Telemetry = domain.TelemetrySnapshot{
		IssuerKey:     req.Telemetry.IssuerKey,
		SuccessRate:   req.Telemetry.SuccessRate,
		BaselineRate:  req.Telemetry.BaselineRate,
		Attempts:      req.Telemetry.Samples,
		Successes:     int(float64(req.Telemetry.Samples) * req.Telemetry.SuccessRate),
		WindowSeconds: 300,
		BreakerState:  domain.BreakerState(orDefault(req.Telemetry.Breaker, string(domain.BreakerClosed))),
		SampledAt:     sampledAt,
	}
	in.Telemetry.Failures = in.Telemetry.Attempts - in.Telemetry.Successes

	if m := req.Mandate; m != nil {
		rec := domain.MandateRecord{
			SubscriptionID:  m.SubscriptionID,
			AmountPaisa:     m.AmountPaisa,
			AttemptsInCycle: m.AttemptsInCycle,
			CycleKey:        m.CycleKey,
			Category:        domain.MandateCategory(m.Category),
			Halted:          m.Halted,
			HaltReason:      m.HaltReason,
			UpdatedAt:       now,
		}
		for _, f := range []struct {
			raw string
			dst **time.Time
		}{
			{m.LastAttemptAt, &rec.LastAttemptAt},
			{m.NextEligibleAt, &rec.NextEligibleAt},
			{m.PreDebitNotifiedAt, &rec.PreDebitNotifiedAt},
		} {
			if f.raw == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, f.raw)
			if err != nil {
				return domain.GateInput{}, fmt.Errorf("mandate timestamp %q: %w", f.raw, err)
			}
			u := t.UTC()
			*f.dst = &u
		}
		in.Mandate = &rec
	}

	for _, r := range req.AvailableRails {
		in.AvailableRails = append(in.AvailableRails, domain.Rail(r))
	}
	return in, nil
}

func parseTime(raw string, fallback time.Time) (time.Time, error) {
	if raw == "" {
		return fallback, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func fail(msg string) string { return encode(Response{Error: msg}) }

func encode(r Response) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"error":"the decision could not be encoded"}`
	}
	return string(b)
}

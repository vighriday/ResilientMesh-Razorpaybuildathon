// Package lab is the environment in which the learning claims of this system
// are tested rather than asserted.
//
// Off-policy evaluation has a problem that is usually fatal to demonstrating
// it: there is no way to check the answer. The estimator says a policy would
// have earned more, and in production nobody ever finds out whether it would
// have, because the counterfactual is unobservable by definition. Every
// published result is therefore an argument from method rather than a
// measurement of accuracy.
//
// Here the counterfactual is observable. This package holds a world whose
// latent structure is known, so the exact value of any policy can be computed
// in closed form by enumeration. That makes a validation possible that
// production cannot support: estimate the value of policy B using nothing but a
// log produced by policy A, then compute what B is actually worth, and check
// whether the truth fell inside the interval. See Validate.
//
// # The planted rule
//
// One issuer in this world recovers far better in a particular window than
// anything about the issuer or the window would suggest, because it runs a
// settlement batch overnight. Nothing tells the policy this. It is not in the
// feature list, the prompt, the backoff table or the gate. It is in the outcome
// model and nowhere else, and the point of the exercise is that the system
// finds it anyway and proves statistically that it is real. Reveal returns the
// answer key, and it is used only after the discovery has been scored.
//
// # Fair comparison
//
// Outcomes are drawn once per (incident, arm) pair before any policy runs, so
// two policies that choose the same arm on the same incident get the same luck.
// That is the common-random-numbers construction, and it is what makes a
// comparison paired rather than merely run on the same inputs.
//
// # The gate is real
//
// The permitted arm set is not a list in this package. It is obtained by
// putting each incident in front of the actual gatekeeper from
// internal/gatekeeper, the same code path the worker uses, and keeping the
// arms it honours. A recurring debit therefore loses every arm inside the RBI
// cooling window, a terminal decline loses all of them, and the learner never
// sees an action it was not already allowed to take.
package lab

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
	"github.com/hriday/razorpay-resilient-mesh/internal/tuner"
)

// The action space: how long to wait before the next attempt.
//
// It is not defined here. The vocabulary, the delays behind it and the rule
// mapping a gate floor onto a permitted set all live in internal/tuner, which
// is the package the worker uses in production. Restating them in the test
// environment would let the two drift, and the whole point of this package is
// that what it measures is what runs.
const (
	ArmFast      = tuner.ArmFast
	ArmShort     = tuner.ArmShort
	ArmMedium    = tuner.ArmMedium
	ArmLong      = tuner.ArmLong
	ArmOvernight = tuner.ArmOvernight
)

// Arms is the closed action space in canonical order.
var Arms = tuner.Arms

// ArmSeconds is the delay an arm schedules.
func ArmSeconds(a bandit.Arm) int64 { return tuner.ArmSeconds(a) }

// ArmLabel renders an arm for an operator.
func ArmLabel(a bandit.Arm) string { return tuner.ArmLabel(a) }

// Economics of one attempt. Both figures are exact paisa.
const (
	// GatewayFeePaisa is charged for presenting a payment whether or not it is
	// authorised. It is what makes a wasted retry cost something, and therefore
	// what stops the optimal policy from being "retry everything forever".
	GatewayFeePaisa int64 = 300

	// MaxIncidents bounds a world.
	MaxIncidents = 500_000
)

var (
	// ErrInvalidConfig covers a malformed Config.
	ErrInvalidConfig = errors.New("lab: invalid configuration")

	// ErrNoActionableIncidents means the gatekeeper refused every incident, so
	// there is nothing for a policy to decide and nothing to learn from.
	ErrNoActionableIncidents = errors.New("lab: the gatekeeper permitted no action on any incident")
)

// Incident is what a policy is allowed to see. The latent truth behind it lives
// in an unexported parallel slice, so a policy cannot read the answer key even
// by accident.
type Incident struct {
	Index      int    `json:"index"`
	IncidentID string `json:"incident_id"`

	Payment domain.PaymentEntity `json:"payment"`

	// IssuerKey is the telemetry key, for example "netbanking:SBI".
	IssuerKey string `json:"issuer_key"`

	// Class is the causal classification the inference tier assigned. In this
	// world it is correct, because the question under test is what to do about
	// a failure rather than how to recognise one; internal/calib is where the
	// accuracy of that classification is measured.
	Class domain.FailureClass `json:"class"`

	// HourIST is the local hour the failure arrived, 0 to 23. It is the feature
	// through which the planted structure becomes discoverable, and it is
	// present for every incident whether or not it matters.
	HourIST int `json:"hour_ist"`

	AttemptNumber int  `json:"attempt_number"`
	Recurring     bool `json:"recurring"`

	Telemetry      domain.TelemetrySnapshot `json:"telemetry"`
	AvailableRails []domain.Rail            `json:"available_rails"`
	ArrivedAt      time.Time                `json:"arrived_at"`
}

// AmountPaisa is the verified amount, which is the only place a value comes
// from anywhere in this system.
func (i Incident) AmountPaisa() int64 { return i.Payment.Amount }

// Cell is the context bucket a learner keys on.
//
// It is built from four observable facts and nothing else. Hours are bucketed
// into three-hour blocks rather than kept exact, which is the usual trade: too
// fine and every cell holds four observations, too coarse and a three-hour
// batch window is averaged away into nothing.
func (i Incident) Cell() bandit.Cell {
	return tuner.CellFor(i.IssuerKey, i.Class, i.HourIST, i.AttemptNumber)
}

// Features are the tokens the reward model is fitted on. The arm is included
// because the model has to predict the value of actions that were not taken.
func (i Incident) Features(arm bandit.Arm) []string {
	return []string{
		"issuer=" + i.IssuerKey,
		"class=" + string(i.Class),
		fmt.Sprintf("hourblock=%d", i.HourIST/3),
		fmt.Sprintf("attempt=%d", min(i.AttemptNumber, 3)),
		fmt.Sprintf("recurring=%t", i.Recurring),
		"band=" + domain.AmountBand(i.Payment.Amount),
		"arm=" + string(arm),
		"issuer_arm=" + i.IssuerKey + "|" + string(arm),
		fmt.Sprintf("issuer_hour_arm=%s|%d|%s", i.IssuerKey, i.HourIST/3, arm),
	}
}

// Planted is the latent rule the discovery loop has to find.
type Planted struct {
	// IssuerKey names the institution the rule applies to.
	IssuerKey string `json:"issuer_key"`

	// FromHour and ToHour bound the local window, inclusive of FromHour and
	// exclusive of ToHour.
	FromHour int `json:"from_hour"`
	ToHour   int `json:"to_hour"`

	// Arm is the delay that lands on the far side of the batch.
	Arm bandit.Arm `json:"arm"`

	// Probability is the recovery rate inside the rule.
	Probability float64 `json:"probability"`

	// Otherwise is the recovery rate for the same issuer in the same window on
	// any other arm. The gap between the two is the entire prize.
	Otherwise float64 `json:"otherwise"`

	// Description is the sentence a human would write if they already knew.
	Description string `json:"description"`
}

// DefaultPlanted is the rule used unless a caller supplies another.
//
// It is stated as a fact about the world rather than a hint about the model:
// a mid-sized public-sector bank clears its netbanking queue in a nightly
// settlement window, so a failure raised late in the evening recovers if the
// retry lands after the batch and mostly does not if it lands before.
var DefaultPlanted = Planted{
	IssuerKey:   "netbanking:SBI",
	FromHour:    21,
	ToHour:      24,
	Arm:         ArmLong,
	Probability: 0.71,
	Otherwise:   0.19,
	Description: "netbanking:SBI failures raised between 21:00 and midnight IST recover at 71% when the retry waits six hours, against 19% on every other delay, because the issuer clears its queue in an overnight settlement batch",
}

// Matches reports whether an incident falls inside the rule context.
func (p Planted) Matches(i Incident) bool {
	return i.IssuerKey == p.IssuerKey && i.HourIST >= p.FromHour && i.HourIST < p.ToHour
}

// Config describes a world.
type Config struct {
	// Incidents is how many failures to generate.
	Incidents int

	// Seed fixes the incidents, the latent truth and the outcome draws.
	Seed int64

	// Planted overrides DefaultPlanted. The zero value uses the default.
	Planted *Planted

	// Gate overrides the gatekeeper configuration. The zero value is the
	// production default, which is what should normally be used: the point of
	// running the real gate is that it is the real gate.
	Gate gatekeeper.Config
}

// World is a generated corpus together with its latent truth.
type World struct {
	cfg       Config
	planted   Planted
	incidents []Incident

	// truth[i][arm] is the exact probability that arm recovers incident i.
	truth []map[bandit.Arm]float64

	// draws[i][arm] is the uniform this pair is resolved against, drawn before
	// any policy runs so every policy meets the same luck.
	draws []map[bandit.Arm]float64

	// permitted[i] is what the gatekeeper allowed, in canonical order.
	permitted [][]bandit.Arm

	// gateFloor[i] is the delay the gate computed on its own, which is the
	// reason short arms are missing where they are missing.
	gateFloor []int64

	// gateVeto[i] names the invariant that removed every arm, if one did.
	gateVeto []string

	// actionable indexes the incidents a policy actually decides. Averages are
	// taken over these, so a policy is never credited or blamed for incidents
	// on which it had no choice.
	actionable []int
}

// New generates a world and runs every incident through the real gatekeeper.
func New(cfg Config) (*World, error) {
	switch {
	case cfg.Incidents < 1 || cfg.Incidents > MaxIncidents:
		return nil, fmt.Errorf("%w: incident count %d outside [1, %d]", ErrInvalidConfig, cfg.Incidents, MaxIncidents)
	case cfg.Seed < 0:
		return nil, fmt.Errorf("%w: seed %d is negative", ErrInvalidConfig, cfg.Seed)
	}
	planted := DefaultPlanted
	if cfg.Planted != nil {
		planted = *cfg.Planted
		switch {
		case planted.IssuerKey == "":
			return nil, fmt.Errorf("%w: planted rule has no issuer", ErrInvalidConfig)
		case planted.FromHour < 0 || planted.ToHour > 24 || planted.FromHour >= planted.ToHour:
			return nil, fmt.Errorf("%w: planted window [%d, %d) is not a range of hours", ErrInvalidConfig, planted.FromHour, planted.ToHour)
		case tuner.ArmSeconds(planted.Arm) == 0:
			return nil, fmt.Errorf("%w: planted arm %q is not in the action space", ErrInvalidConfig, planted.Arm)
		case planted.Probability < 0 || planted.Probability > 1 || planted.Otherwise < 0 || planted.Otherwise > 1:
			return nil, fmt.Errorf("%w: planted probabilities are not in [0,1]", ErrInvalidConfig)
		}
	}

	w := &World{cfg: cfg, planted: planted}
	rng := rand.New(rand.NewSource(cfg.Seed))
	w.generate(rng)
	if err := w.applyGate(); err != nil {
		return nil, err
	}
	if len(w.actionable) == 0 {
		return nil, ErrNoActionableIncidents
	}
	return w, nil
}

// Incidents returns the observable corpus.
func (w *World) Incidents() []Incident { return w.incidents }

// Actionable returns the indices of incidents on which the gatekeeper permitted
// at least one arm.
func (w *World) Actionable() []int { return append([]int(nil), w.actionable...) }

// Permitted returns the arms the gatekeeper allowed for incident i.
func (w *World) Permitted(i int) []bandit.Arm {
	if i < 0 || i >= len(w.permitted) {
		return nil
	}
	return append([]bandit.Arm(nil), w.permitted[i]...)
}

// GateFloor returns the delay the gatekeeper computed unaided for incident i,
// which is the reason any shorter arm is unavailable.
func (w *World) GateFloor(i int) int64 { return w.gateFloor[i] }

// Reveal returns the latent rule. It exists to be called after a discovery has
// already been scored, never before.
func (w *World) Reveal() Planted { return w.planted }

// Resolve plays one arm on one incident and returns what happened.
//
// The draw is fixed per (incident, arm), so calling this twice returns the same
// answer and two different policies choosing the same arm share the same
// outcome. That is what makes a comparison between them paired.
func (w *World) Resolve(i int, arm bandit.Arm) (recovered bool, rewardPaisa int64) {
	p := w.truth[i][arm]
	recovered = w.draws[i][arm] < p
	if recovered {
		return true, w.incidents[i].AmountPaisa() - GatewayFeePaisa
	}
	return false, -GatewayFeePaisa
}

// TrueProbability exposes the latent recovery probability of one pair. It is
// the answer key and is used by ExactValue and by the tests, never by a policy.
func (w *World) TrueProbability(i int, arm bandit.Arm) float64 { return w.truth[i][arm] }

// ExpectedRewardPaisa is the exact expected value of playing one arm, in paisa.
func (w *World) ExpectedRewardPaisa(i int, arm bandit.Arm) float64 {
	amount := float64(w.incidents[i].AmountPaisa())
	return w.truth[i][arm]*amount - float64(GatewayFeePaisa)
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

type issuerSpec struct {
	key    string
	method string
	bank   string
	vpa    string
	weight int
	// base is the recovery rate this issuer offers before any delay effect.
	base float64
}

// The institutions in this world, weighted by share of failures rather than by
// share of payments.
//
// Those two mixes are not the same and the difference matters here. UPI carries
// most Indian volume, so it dominates either way. Netbanking carries far less
// volume and fails far more often, so it is over-represented among failures
// relative to what a payments-mix table would suggest, and a recovery corpus is
// made entirely of failures. Weighting by volume instead would leave the one
// institution with interesting structure too rare for anything to be provable
// about it, which would say more about the corpus than about the method.
var issuers = []issuerSpec{
	{key: "upi:okhdfcbank", method: "upi", vpa: "customer@okhdfcbank", weight: 260, base: 0.46},
	{key: "upi:ybl", method: "upi", vpa: "customer@ybl", weight: 180, base: 0.41},
	{key: "upi:paytm", method: "upi", vpa: "customer@paytm", weight: 110, base: 0.38},
	{key: "card:HDFC", method: "card", bank: "HDFC", weight: 120, base: 0.34},
	{key: "card:ICICI", method: "card", bank: "ICICI", weight: 90, base: 0.31},
	{key: "netbanking:SBI", method: "netbanking", bank: "SBI", weight: 170, base: 0.24},
	{key: "netbanking:AXIS", method: "netbanking", bank: "AXIS", weight: 70, base: 0.29},
}

type classSpec struct {
	class  domain.FailureClass
	code   string
	weight int
}

// The recoverable classes only. Terminal declines are generated too, below,
// because the gatekeeper refusing them is part of what this world demonstrates.
var classes = []classSpec{
	{domain.ClassTransientDegradation, "gateway_error", 300},
	{domain.ClassIssuerOutage, "issuer_down", 220},
	{domain.ClassInsufficientFunds, "insufficient_funds", 210},
	{domain.ClassCustomerAction, "payment_timeout", 150},
	{domain.ClassNetworkTimeout, "gateway_timeout", 70},
	{domain.ClassPermanentInstrument, "card_lost_or_stolen", 50},
}

func (w *World) generate(rng *rand.Rand) {
	n := w.cfg.Incidents
	w.incidents = make([]Incident, n)
	w.truth = make([]map[bandit.Arm]float64, n)
	w.draws = make([]map[bandit.Arm]float64, n)

	// A fixed origin so a generated world does not change with the wall clock.
	origin := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < n; i++ {
		iss := pickIssuer(rng)
		cls := pickClass(rng)
		hour := rng.Intn(24)
		recurring := rng.Float64() < 0.18
		attempt := 1 + rng.Intn(2)
		amount := drawAmount(rng, recurring)

		pay := domain.PaymentEntity{
			ID:        fmt.Sprintf("pay_lab%06d", i),
			Amount:    amount,
			Currency:  "INR",
			Status:    "failed",
			OrderID:   fmt.Sprintf("order_lab%06d", i),
			Method:    iss.method,
			Bank:      iss.bank,
			VPA:       iss.vpa,
			ErrorCode: cls.code,
		}
		if recurring {
			pay.SubscriptionID = fmt.Sprintf("sub_lab%06d", i)
		}

		inc := Incident{
			Index:          i,
			IncidentID:     fmt.Sprintf("inc_lab%06d", i),
			Payment:        pay,
			IssuerKey:      iss.key,
			Class:          cls.class,
			HourIST:        hour,
			AttemptNumber:  attempt,
			Recurring:      recurring,
			AvailableRails: []domain.Rail{domain.RailUPIIntent, domain.RailCard, domain.RailNetbanking},
			ArrivedAt:      origin.Add(time.Duration(i) * time.Minute),
		}
		inc.Telemetry = telemetryFor(iss, cls.class, inc.ArrivedAt)

		w.incidents[i] = inc
		w.truth[i] = w.trueProbabilities(inc, iss, rng)
		w.draws[i] = make(map[bandit.Arm]float64, len(Arms))
		for _, a := range Arms {
			w.draws[i][a] = rng.Float64()
		}
	}
}

// trueProbabilities is the latent outcome model: the shape of the experiment.
//
// It is written out flat rather than parameterised, because every branch here
// is a claim about how payment recovery behaves and each one should be
// arguable on its own. An issuer outage resolves on its own schedule and no
// amount of promptness helps. An empty account refills on a human timescale. A
// customer who walked away is gone whatever the issuer does. And one issuer
// clears its queue overnight, which is the fact nobody told the policy.
func (w *World) trueProbabilities(inc Incident, iss issuerSpec, rng *rand.Rand) map[bandit.Arm]float64 {
	out := make(map[bandit.Arm]float64, len(Arms))

	// How long this particular outage has left to run, drawn once and hidden.
	outageRemaining := int64(0)
	if inc.Class == domain.ClassIssuerOutage {
		outageRemaining = int64(15*60 + rng.Intn(5*3600))
	}
	// Where this particular payer sits on the abandonment curve.
	halfLife := abandonmentHalfLife(inc.Class, rng)
	planted := w.planted.Matches(inc)

	for _, arm := range Arms {
		delay := tuner.ArmSeconds(arm)
		var p float64

		switch {
		case planted:
			// The whole point: inside the rule the delay is what matters, and
			// the issuer base rate says nothing useful.
			p = w.planted.Otherwise
			if arm == w.planted.Arm {
				p = w.planted.Probability
			}

		case inc.Class == domain.ClassPermanentInstrument:
			p = 0

		case inc.Class == domain.ClassIssuerOutage:
			// Retrying inside the outage is close to worthless; retrying after
			// it has cleared is close to a fresh attempt.
			if delay >= outageRemaining {
				p = iss.base * 1.55
			} else {
				p = iss.base * 0.12
			}

		case inc.Class == domain.ClassInsufficientFunds:
			// Money does not appear because the retry was prompt.
			switch arm {
			case ArmOvernight:
				p = iss.base * 1.30
			case ArmLong:
				p = iss.base * 0.55
			default:
				p = iss.base * 0.16
			}

		case inc.Class == domain.ClassCustomerAction:
			// A payer who has stopped paying attention is not persuaded by a
			// different schedule, only by being caught early.
			p = iss.base * 0.70

		case inc.Class == domain.ClassNetworkTimeout:
			// Probably already over by the time anything is scheduled.
			p = iss.base * 1.20

		default: // transient degradation
			// Recovers gradually, with most of the benefit landing early.
			p = iss.base * (0.55 + 0.45*math.Min(1, float64(delay)/float64(2*3600)))
		}

		// Abandonment applies on top of whatever the issuer would have done.
		// It is what stops the answer from always being the longest wait.
		p *= math.Exp(-float64(delay) / halfLife)
		out[arm] = math.Max(0, math.Min(1, p))
	}
	return out
}

// abandonmentHalfLife is how long the payer stays recoverable. The spread
// between classes is deliberate: somebody whose card was declined for funds
// will come back next week, somebody who abandoned a checkout will not.
func abandonmentHalfLife(class domain.FailureClass, rng *rand.Rand) float64 {
	var lo, hi float64
	switch class {
	case domain.ClassCustomerAction:
		lo, hi = 2*3600, 8*3600
	case domain.ClassInsufficientFunds:
		lo, hi = 10*24*3600, 20*24*3600
	case domain.ClassIssuerOutage:
		lo, hi = 24*3600, 72*3600
	default:
		lo, hi = 12*3600, 48*3600
	}
	return lo + rng.Float64()*(hi-lo)
}

func pickIssuer(rng *rand.Rand) issuerSpec {
	total := 0
	for _, s := range issuers {
		total += s.weight
	}
	r := rng.Intn(total)
	for _, s := range issuers {
		if r < s.weight {
			return s
		}
		r -= s.weight
	}
	return issuers[len(issuers)-1]
}

func pickClass(rng *rand.Rand) classSpec {
	total := 0
	for _, s := range classes {
		total += s.weight
	}
	r := rng.Intn(total)
	for _, s := range classes {
		if r < s.weight {
			return s
		}
		r -= s.weight
	}
	return classes[len(classes)-1]
}

// drawAmount produces a plausible Indian ticket size in paisa. Recurring
// mandates cluster low, because the ones that cluster high are insurance
// premiums and they are a different animal.
func drawAmount(rng *rand.Rand, recurring bool) int64 {
	if recurring {
		return int64(9900 + rng.Intn(240_000))
	}
	switch r := rng.Intn(100); {
	case r < 45:
		return int64(5_000 + rng.Intn(45_000))
	case r < 80:
		return int64(50_000 + rng.Intn(150_000))
	case r < 96:
		return int64(200_000 + rng.Intn(800_000))
	default:
		return int64(1_000_000 + rng.Intn(4_000_000))
	}
}

// telemetryFor builds a snapshot consistent with the class, so the gatekeeper
// and the policy engine see the same story the outcome model is telling.
func telemetryFor(iss issuerSpec, class domain.FailureClass, at time.Time) domain.TelemetrySnapshot {
	snap := domain.TelemetrySnapshot{
		IssuerKey:     iss.key,
		WindowSeconds: 300,
		Attempts:      420,
		BaselineRate:  0.72,
		BreakerState:  domain.BreakerClosed,
		SampledAt:     at,
	}
	rate := 0.68
	if class == domain.ClassIssuerOutage {
		rate = 0.09
		snap.BreakerState = domain.BreakerOpen
	} else if class == domain.ClassTransientDegradation {
		rate = 0.31
	}
	snap.Successes = int(float64(snap.Attempts) * rate)
	snap.Failures = snap.Attempts - snap.Successes
	snap.SuccessRate = rate
	return snap
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// applyGate runs every incident through the production gatekeeper and records
// what it allowed.
//
// The gate is asked once per incident, with a proposal that recommends no delay
// at all. What comes back is the delay the deterministic policy engine computed
// on its own, and that is the floor. The gate honours a proposed delay only
// when it is longer than its own; a shorter one is discarded. So the arms a
// learner may explore are exactly those at or above that floor, and the arms
// below it were never available to any component of this system.
//
// That asymmetry is not an accident of this package. It is the gatekeeper rule
// that a model may make the system more patient and never more aggressive, and
// it is what allows exploration to be bounded by a property that has been
// checked exhaustively rather than by a hyperparameter.
func (w *World) applyGate() error {
	engine := policy.New(fixedClock{w.incidents[0].ArrivedAt}, rand.New(rand.NewSource(w.cfg.Seed^0x5eed)))
	gate := gatekeeper.New(fixedClock{w.incidents[0].ArrivedAt}, engine, w.cfg.Gate)

	n := len(w.incidents)
	w.permitted = make([][]bandit.Arm, n)
	w.gateFloor = make([]int64, n)
	w.gateVeto = make([]string, n)

	for i, inc := range w.incidents {
		in := domain.GateInput{
			IncidentID:     inc.IncidentID,
			Payment:        inc.Payment,
			Proposal:       probeProposal(inc),
			Telemetry:      inc.Telemetry,
			AttemptNumber:  inc.AttemptNumber,
			AvailableRails: inc.AvailableRails,
		}
		cmd, err := gate.Decide(context.Background(), in)
		if err != nil {
			return fmt.Errorf("lab: gatekeeper refused incident %s: %w", inc.IncidentID, err)
		}
		if !cmd.Executable() {
			w.gateVeto[i] = vetoReason(cmd)
			continue
		}
		w.gateFloor[i] = cmd.DelaySeconds
		allowed := tuner.PermittedFor(cmd.DelaySeconds)
		if len(allowed) == 0 {
			// Every arm is shorter than the floor the gate insists on. There is
			// no action inside the action space that is also inside the rules,
			// which is a refusal even though no invariant vetoed outright. It
			// is overwhelmingly the compound case: a recurring debit carries
			// the RBI cooling window, and an insufficient-funds classification
			// on a second attempt already schedules beyond a day, so the two
			// together push the floor past the longest delay this system can
			// express.
			w.gateVeto[i] = "DELAY_EXCEEDS_ACTION_SPACE"
			continue
		}
		w.permitted[i] = allowed
		w.actionable = append(w.actionable, i)
	}
	return nil
}

// probeProposal is the advisory input used to ask the gate what it would allow.
//
// The confidence is high and the delay is zero on purpose. A zero delay lets
// the gate answer with its own computed floor rather than with anything this
// package suggested, and a high confidence keeps the LOW_CONFIDENCE_ABSTAIN
// invariant from masking the constraints actually under study. Where confidence
// itself is the subject, see internal/calib.
func probeProposal(inc Incident) domain.DiagnosticProposal {
	return domain.DiagnosticProposal{
		IncidentID:            inc.IncidentID,
		FailureClassification: inc.Class,
		ConfidenceScore:       0.9,
		RecommendedAction:     domain.ActionAsyncRetry,
		RecommendedDelaySec:   0,
		SuggestedFallbackRail: domain.RailNone,
		Mode:                  domain.ModeReplay,
	}
}

// vetoReason names the invariant that refused, so a refusal is legible rather
// than merely a missing row.
func vetoReason(cmd domain.SanitizedCommand) string {
	for _, r := range cmd.AppliedInvariants {
		switch r {
		case gatekeeper.RuleTerminalDecline, gatekeeper.RuleUnrecoverableClass,
			gatekeeper.RuleStopMaxAttempts, gatekeeper.RuleLowConfidence,
			gatekeeper.RuleMandateCooling, gatekeeper.RuleMandateCycleCap,
			gatekeeper.RuleMandateHalted, gatekeeper.RuleAFACeiling:
			return r
		}
	}
	return "gatekeeper abstained"
}

// VetoReason returns the invariant that removed every arm from incident i, or
// the empty string if the incident is actionable.
func (w *World) VetoReason(i int) string { return w.gateVeto[i] }

// GateSummary counts how the gate disposed of the corpus.
type GateSummary struct {
	Incidents  int            `json:"incidents"`
	Actionable int            `json:"actionable"`
	Refused    int            `json:"refused"`
	ByReason   map[string]int `json:"by_reason"`

	// ArmsAvailable counts how many incidents had each arm available, which is
	// where the effect of the RBI cooling window on the action space becomes
	// visible.
	ArmsAvailable map[bandit.Arm]int `json:"arms_available"`
}

// Gate reports what the gatekeeper did to this corpus.
func (w *World) Gate() GateSummary {
	s := GateSummary{
		Incidents:     len(w.incidents),
		Actionable:    len(w.actionable),
		ByReason:      map[string]int{},
		ArmsAvailable: map[bandit.Arm]int{},
	}
	s.Refused = s.Incidents - s.Actionable
	for i := range w.incidents {
		if r := w.gateVeto[i]; r != "" {
			s.ByReason[r]++
		}
		for _, a := range w.permitted[i] {
			s.ArmsAvailable[a]++
		}
	}
	return s
}

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

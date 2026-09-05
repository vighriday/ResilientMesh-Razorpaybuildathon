package lab

import (
	"errors"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/ope"
	"github.com/hriday/razorpay-resilient-mesh/internal/reward"
)

func newWorld(t *testing.T, incidents int, seed int64) *World {
	t.Helper()
	w, err := New(Config{Incidents: incidents, Seed: seed})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func newBandit(t *testing.T, seed int64, floor float64, draws int) *Bandit {
	t.Helper()
	m, err := bandit.New(bandit.Config{Arms: Arms, Floor: floor, Seed: seed, Draws: draws})
	if err != nil {
		t.Fatalf("bandit.New: %v", err)
	}
	return NewBandit(m, "thompson")
}

func TestConfigIsValidated(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]Config{
		"no incidents":      {Incidents: 0},
		"too many":          {Incidents: MaxIncidents + 1},
		"negative seed":     {Incidents: 10, Seed: -1},
		"planted no arm":    {Incidents: 10, Planted: &Planted{IssuerKey: "netbanking:SBI", FromHour: 1, ToHour: 2}},
		"planted no hours":  {Incidents: 10, Planted: &Planted{IssuerKey: "netbanking:SBI", Arm: ArmLong, FromHour: 5, ToHour: 5}},
		"planted no issuer": {Incidents: 10, Planted: &Planted{Arm: ArmLong, FromHour: 1, ToHour: 2}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// A world that changes between runs cannot support any of the claims made from
// it, so this is the first thing asserted.
func TestWorldIsReproducible(t *testing.T) {
	t.Parallel()
	a := newWorld(t, 2_000, 7)
	b := newWorld(t, 2_000, 7)

	if len(a.Actionable()) != len(b.Actionable()) {
		t.Fatalf("actionable counts differ: %d vs %d", len(a.Actionable()), len(b.Actionable()))
	}
	for i := range a.incidents {
		if a.incidents[i].IncidentID != b.incidents[i].IncidentID ||
			a.incidents[i].Payment != b.incidents[i].Payment ||
			a.incidents[i].Class != b.incidents[i].Class ||
			a.incidents[i].HourIST != b.incidents[i].HourIST ||
			a.incidents[i].IssuerKey != b.incidents[i].IssuerKey {
			t.Fatalf("incident %d differs between two identical worlds", i)
		}
		for _, arm := range Arms {
			if a.TrueProbability(i, arm) != b.TrueProbability(i, arm) {
				t.Fatalf("latent probability for incident %d arm %s differs", i, arm)
			}
			ra, _ := a.Resolve(i, arm)
			rb, _ := b.Resolve(i, arm)
			if ra != rb {
				t.Fatalf("outcome for incident %d arm %s differs", i, arm)
			}
		}
	}

	c := newWorld(t, 2_000, 8)
	if c.incidents[0].Payment == a.incidents[0].Payment && c.incidents[0].HourIST == a.incidents[0].HourIST {
		t.Fatal("changing the seed produced the same world")
	}
}

// Common random numbers: the same pair always resolves the same way, so two
// policies are compared on identical luck rather than on separate coin flips.
func TestOutcomesArePreDrawnPerArm(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 500, 3)
	for _, i := range w.Actionable()[:50] {
		for _, arm := range Arms {
			first, firstPaisa := w.Resolve(i, arm)
			second, secondPaisa := w.Resolve(i, arm)
			if first != second || firstPaisa != secondPaisa {
				t.Fatalf("incident %d arm %s resolved differently on a second call", i, arm)
			}
		}
	}
}

// The safety claim, stated as a property of the corpus rather than of the
// prose: exploration is bounded by the invariants, and the boundary is drawn by
// the production gatekeeper.
func TestExplorationIsBoundedByTheRealGatekeeper(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 5_000, 11)
	summary := w.Gate()

	if summary.Actionable == 0 || summary.Refused == 0 {
		t.Fatalf("expected the gate to both permit and refuse: %+v", summary)
	}
	if summary.ByReason[gatekeeperRuleTerminal] == 0 {
		t.Fatalf("no incident was refused for a terminal decline: %+v", summary.ByReason)
	}

	var recurringSeen int
	for _, i := range w.Actionable() {
		inc := w.Incidents()[i]
		permitted := w.Permitted(i)

		// Nothing shorter than the delay the gate computed may ever be offered
		// to a learner.
		for _, a := range permitted {
			if ArmSeconds(a) < w.GateFloor(i) {
				t.Fatalf("incident %s offers %s, below the gate floor of %ds", inc.IncidentID, a, w.GateFloor(i))
			}
		}
		if inc.Recurring {
			recurringSeen++
			// The RBI cooling window is twenty-four hours, so a recurring debit
			// cannot be retried on any arm below it.
			for _, a := range permitted {
				if ArmSeconds(a) < 24*3600 {
					t.Fatalf("recurring incident %s was offered %s, inside the RBI cooling window", inc.IncidentID, a)
				}
			}
		}
		// A terminal decline must never reach a learner at all.
		if domain.IsTerminalDecline(inc.Payment.ErrorCode) {
			t.Fatalf("terminal decline %s was left actionable", inc.Payment.ErrorCode)
		}
	}
	if recurringSeen == 0 {
		t.Fatal("no recurring incident survived the gate, so the cooling assertion proved nothing")
	}
}

const gatekeeperRuleTerminal = "TERMINAL_DECLINE"

// The argument for spending recoveries on exploration, made by the estimator
// refusing rather than by anybody asserting it.
//
// A deterministic logging policy produces a log with no information about any
// other action. Off-policy evaluation against it is not merely imprecise, it is
// undefined, and a system that returned a number here would be inventing one.
func TestADeterministicLogCannotBeEvaluated(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 3_000, 13)

	run, err := w.Run(Backoff{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewSegment(Hypothesis{
		ID: "probe", IssuerKey: w.Reveal().IssuerKey, Arm: ArmOvernight,
	}, Backoff{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.ValidateAgainstLog(run, target, EvalOptions{Seed: 1, Bootstrap: 100})
	if !errors.Is(err, ope.ErrNoOverlap) {
		t.Fatalf("got %v, want ErrNoOverlap: a log with no exploration cannot support a counterfactual", err)
	}

	// And the fix: the same world, the same target, a logging policy that keeps
	// a floor of probability on every permitted arm.
	explorer := newBandit(t, 5, 0.05, 60)
	exploringRun, err := w.Run(explorer, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ValidateAgainstLog(exploringRun, target, EvalOptions{Seed: 1, Bootstrap: 100}); err != nil {
		t.Fatalf("an exploring log should be evaluable: %v", err)
	}
}

// The experiment production cannot run.
//
// Estimate the value of a policy that was never executed, using only a log
// produced by a different one, then open the answer key and check. Repeated
// across independent worlds, a 95% interval has to contain the truth about 95%
// of the time. Nothing else in this repository would catch an estimator that is
// confidently and consistently wrong, and running this is how two real defects
// were found: a lift built by self-normalising one side of a difference, and a
// percentile bootstrap that misplaced its interval on skewed data.
//
// The candidate is a delta: carry on exactly as the deployed policy does,
// except inside one segment. That is the shape a real proposal takes and the
// shape that keeps importance weights near one.
//
// The corpus is forty thousand incidents because the segment under test is
// about one and a half percent of traffic, so a smaller corpus leaves a few
// dozen decisions carrying the entire estimate. Coverage degrades smoothly as
// that number falls, which is a property of the question rather than of the
// implementation, and it is why ope.Lift reports how many decisions actually
// differ.
func TestOffPolicyEstimatesCoverTheTruth(t *testing.T) {
	t.Parallel()
	const (
		worlds = 24
		size   = 40_000
	)

	var covered, liftCovered int
	relative := make([]float64, 0, worlds)
	for s := 0; s < worlds; s++ {
		w := newWorld(t, size, int64(1_000+s))

		run, err := w.Run(Uniform{}, int64(s))
		if err != nil {
			t.Fatalf("world %d: %v", s, err)
		}
		base, err := runPolicyOf(run, w)
		if err != nil {
			t.Fatal(err)
		}
		target, err := NewSegment(Hypothesis{
			ID: "overnight-sbi", IssuerKey: "netbanking:SBI", FromHour: 21, ToHour: 24, Arm: ArmLong,
		}, base)
		if err != nil {
			t.Fatal(err)
		}

		v, err := w.ValidateAgainstLog(run, target, EvalOptions{Seed: int64(s), Bootstrap: 400})
		if err != nil {
			t.Fatalf("world %d: %v", s, err)
		}
		if v.Covered {
			covered++
		}
		if v.LiftCovered {
			liftCovered++
		}
		if v.Lift.Influential < ope.MinInfluentialDecisions {
			t.Fatalf("world %d: only %d influential decisions, so this test is measuring the wrong regime", s, v.Lift.Influential)
		}
		relative = append(relative, math.Abs(v.RelativeError))
	}

	if rate := float64(covered) / worlds; rate < 0.85 {
		t.Fatalf("the value interval contained the truth in only %.0f%% of %d worlds", 100*rate, worlds)
	}
	if rate := float64(liftCovered) / worlds; rate < 0.83 {
		t.Fatalf("the lift interval contained the truth in only %.0f%% of %d worlds", 100*rate, worlds)
	}
	sort.Float64s(relative)
	if median := relative[len(relative)/2]; median > 0.03 {
		t.Fatalf("median relative error across %d worlds was %.1f%%", worlds, 100*median)
	}
}

// The measurement behind the estimator choice in ope.LiftEstimator, kept as a
// test so the table in its documentation cannot quietly stop being true.
//
// Doubly-robust estimation is the standard variance-reduction recommendation
// and it was nearly rejected here on the strength of one run against a small
// corpus, where the reward model had no skill and the residual it subtracted
// was noise. Measured across sizes it covers better at every one of them.
func TestDoublyRobustLiftCoversBetterThanThePlainDifference(t *testing.T) {
	t.Parallel()
	const (
		worlds = 20
		size   = 20_000
	)

	var ipsCovered, drCovered int
	var ipsWidth, drWidth float64
	for s := 0; s < worlds; s++ {
		w := newWorld(t, size, int64(7_000+s))
		run, err := w.Run(Uniform{}, int64(s))
		if err != nil {
			t.Fatal(err)
		}
		base, err := runPolicyOf(run, w)
		if err != nil {
			t.Fatal(err)
		}
		target, err := NewSegment(Hypothesis{
			ID: "overnight-sbi", IssuerKey: "netbanking:SBI", FromHour: 21, ToHour: 24, Arm: ArmLong,
		}, base)
		if err != nil {
			t.Fatal(err)
		}

		model, _, err := FitRewardModel(run.Log, w.Incidents(), reward.Options{Seed: int64(s)})
		if err != nil {
			t.Fatal(err)
		}
		samples, err := w.Samples(run.Log, target, model)
		if err != nil {
			t.Fatal(err)
		}

		targetValue, err := w.ExactValue(target)
		if err != nil {
			t.Fatal(err)
		}
		baseValue, err := w.ExactValue(base)
		if err != nil {
			t.Fatal(err)
		}
		truth := targetValue - baseValue

		plain, _, err := ope.EvaluateLift(samples, ope.Options{Bootstrap: 400, Seed: int64(s)})
		if err != nil {
			t.Fatal(err)
		}
		robust, _, err := ope.EvaluateLift(samples, ope.Options{
			Bootstrap: 400, Seed: int64(s), WithOutcomeModel: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if plain.Estimator != string(ope.LiftIPS) {
			t.Fatalf("expected the plain difference, got %q", plain.Estimator)
		}
		if robust.Estimator != string(ope.LiftDoublyRobust) {
			t.Fatalf("supplying an outcome model should select the doubly-robust difference, got %q", robust.Estimator)
		}

		if plain.Lower <= truth && truth <= plain.Upper {
			ipsCovered++
		}
		if robust.Lower <= truth && truth <= robust.Upper {
			drCovered++
		}
		ipsWidth += plain.Upper - plain.Lower
		drWidth += robust.Upper - robust.Lower
	}

	if drCovered < ipsCovered {
		t.Fatalf("doubly-robust covered %d of %d against %d for the plain difference; "+
			"if this now holds, the table on ope.LiftEstimator needs revisiting", drCovered, worlds, ipsCovered)
	}
	if drWidth >= ipsWidth {
		t.Fatalf("doubly-robust averaged a width of %.0f against %.0f for the plain difference",
			drWidth/worlds, ipsWidth/worlds)
	}
	if float64(drCovered)/worlds < 0.80 {
		t.Fatalf("doubly-robust coverage was %.0f%%", 100*float64(drCovered)/worlds)
	}
}

// The same estimator asked a much harder question: what is a policy worth that
// differs from the log everywhere rather than in one segment?
//
// The interval still has to contain the truth, because that is what an interval
// is for, but the point estimate is far less precise and the effective sample
// size collapses. Recording that here keeps the headline claim honest: this
// method measures small changes well and wholesale replacements badly, and the
// difference is visible in the diagnostics rather than hidden in the prose.
func TestWholesaleReplacementIsCoveredButImprecise(t *testing.T) {
	t.Parallel()
	const worlds = 30

	target, err := NewSegment(Hypothesis{
		ID: "sbi-everything", IssuerKey: "netbanking:SBI", Arm: ArmLong,
	}, Backoff{})
	if err != nil {
		t.Fatal(err)
	}

	var covered int
	relative := make([]float64, 0, worlds)
	essFraction := 0.0
	for s := 0; s < worlds; s++ {
		w := newWorld(t, 6_000, int64(4_000+s))
		v, err := Validate(w, Uniform{}, target, EvalOptions{Seed: int64(s), Bootstrap: 400})
		if err != nil {
			t.Fatalf("world %d: %v", s, err)
		}
		if v.Covered {
			covered++
		}
		relative = append(relative, math.Abs(v.RelativeError))
		essFraction += v.Estimated.Diagnostics.ESSFraction
	}

	if rate := float64(covered) / worlds; rate < 0.80 {
		t.Fatalf("even a wholesale replacement must be covered: %.0f%% of %d worlds", 100*rate, worlds)
	}
	sort.Float64s(relative)
	median := relative[len(relative)/2]
	if median > 0.35 {
		t.Fatalf("median relative error %.1f%% is worse than heavy tails explain", 100*median)
	}
	if median < 0.02 {
		t.Fatalf("a wholesale replacement estimated to %.2f%% would mean this test is not exercising the hard case", 100*median)
	}
	if avg := essFraction / worlds; avg > 0.6 {
		t.Fatalf("effective sample size fraction averaged %.2f, so the log overlaps the target far more than expected", avg)
	}
}

// The same experiment against a log a learner produced, which is the realistic
// case: the exploration that makes the log evaluable is the exploration the
// bandit was doing anyway.
func TestABanditLogSupportsACounterfactual(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 8_000, 21)

	logger := newBandit(t, 4, 0.05, 80)
	run, err := w.Run(logger, 2)
	if err != nil {
		t.Fatal(err)
	}

	target, err := NewSegment(Hypothesis{
		ID: "sbi-evening-batch", IssuerKey: "netbanking:SBI", FromHour: 21, ToHour: 24, Arm: ArmLong,
	}, Backoff{})
	if err != nil {
		t.Fatal(err)
	}

	v, err := w.ValidateAgainstLog(run, target, EvalOptions{
		Seed: 3, Bootstrap: 600, WithOutcomeModel: true,
		RewardOptions: reward.Options{Seed: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Covered {
		t.Fatalf("interval [%.1f, %.1f] missed the true value %.1f",
			v.Estimated.SNIPS.Lower, v.Estimated.SNIPS.Upper, v.TrueTargetValue)
	}
	if v.Estimated.DR == nil {
		t.Fatal("the doubly-robust estimate was requested and not produced")
	}
	if v.RewardModel == nil || v.RewardModel.Skill <= 0 {
		t.Fatalf("the outcome model has no held-out skill, so the doubly-robust term is worthless: %+v", v.RewardModel)
	}
	if v.Estimated.Diagnostics.ESSFraction < 0.05 {
		t.Fatalf("effective sample size fraction %.3f is too low for this estimate to mean anything",
			v.Estimated.Diagnostics.ESSFraction)
	}
}

// The whole loop, end to end: a set of candidate segments is scored against a
// log with no access to the latent model, and only afterwards is the answer key
// opened to see whether the surviving one is the rule that was planted.
func TestTheLoopDiscoversThePlantedRule(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 40_000, 31)

	logger := newBandit(t, 9, 0.06, 40)
	run, err := w.Run(logger, 4)
	if err != nil {
		t.Fatal(err)
	}

	// Candidates as a proposer would emit them: one that happens to be right,
	// and several that are plausible and wrong. Nothing here knows which.
	candidates := []Hypothesis{
		{ID: "h1", Description: "SBI netbanking late evening waits for the overnight batch",
			IssuerKey: "netbanking:SBI", FromHour: 21, ToHour: 24, Arm: ArmLong},
		{ID: "h2", Description: "SBI netbanking is simply slow, all day",
			IssuerKey: "netbanking:SBI", Arm: ArmLong},
		{ID: "h3", Description: "late evening is bad everywhere, wait overnight",
			FromHour: 21, ToHour: 24, Arm: ArmOvernight},
		{ID: "h4", Description: "HDFC UPI recovers fastest if retried immediately",
			IssuerKey: "upi:okhdfcbank", Arm: ArmFast},
		{ID: "h5", Description: "insufficient funds always deserves a full day",
			Class: domain.ClassInsufficientFunds, Arm: ArmOvernight},
		{ID: "h6", Description: "SBI netbanking in the small hours wants six hours too",
			IssuerKey: "netbanking:SBI", FromHour: 0, ToHour: 6, Arm: ArmLong},
	}

	scores := make([]HypothesisScore, 0, len(candidates))
	for _, h := range candidates {
		s, err := w.ScoreHypothesis(run, h, nil, EvalOptions{Seed: 5, Bootstrap: 500})
		if err != nil {
			t.Fatalf("scoring %s: %v", h.ID, err)
		}
		scores = append(scores, s)
	}
	RankScores(scores)

	winner := scores[0]
	if !winner.Survived {
		t.Fatalf("no hypothesis survived; the strongest was %s with lift [%.1f, %.1f]",
			winner.Hypothesis.ID, winner.Lift.Lower, winner.Lift.Upper)
	}

	// Only now is the answer key opened.
	truth := w.Reveal()
	if winner.Hypothesis.IssuerKey != truth.IssuerKey {
		t.Fatalf("the surviving hypothesis names %s, the planted rule is about %s",
			winner.Hypothesis.IssuerKey, truth.IssuerKey)
	}
	if winner.Hypothesis.Arm != truth.Arm {
		t.Fatalf("the surviving hypothesis prescribes %s, the planted rule is %s",
			winner.Hypothesis.Arm, truth.Arm)
	}
	if winner.Hypothesis.FromHour != truth.FromHour || winner.Hypothesis.ToHour != truth.ToHour {
		t.Fatalf("the surviving hypothesis covers %d-%d, the planted window is %d-%d",
			winner.Hypothesis.FromHour, winner.Hypothesis.ToHour, truth.FromHour, truth.ToHour)
	}

	// And the estimate has to be right, not merely pointing the right way.
	base, err := runPolicyOf(run, w)
	if err != nil {
		t.Fatal(err)
	}
	seg, err := NewSegment(winner.Hypothesis, base)
	if err != nil {
		t.Fatal(err)
	}
	v, err := w.ValidateAgainstLog(run, seg, EvalOptions{Seed: 5, Bootstrap: 500})
	if err != nil {
		t.Fatal(err)
	}
	// The claim under test is the decision, not one draw of one interval. A
	// single 95% interval misses one time in twenty by construction, so
	// asserting coverage on one instance would be asserting that a random
	// variable is never unlucky. Coverage is measured properly, over many
	// independent worlds, in TestOffPolicyEstimatesCoverTheTruth. What must
	// hold here is that the surviving hypothesis is genuinely worth adopting
	// and that the estimate points the right way by a sensible margin.
	if v.TrueLift <= 0 {
		t.Fatalf("the surviving hypothesis is actually worth %.1f paisa a decision", v.TrueLift)
	}
	if v.Lift.Value <= 0 {
		t.Fatalf("the estimate says %.1f for a change genuinely worth %.1f", v.Lift.Value, v.TrueLift)
	}
	if ratio := v.Lift.Value / v.TrueLift; ratio < 0.4 || ratio > 2.5 {
		t.Fatalf("the estimate %.1f is %.1fx the true lift %.1f", v.Lift.Value, ratio, v.TrueLift)
	}

	// The decoy that names the wrong hours must not have survived, or the
	// procedure is not discriminating, it is just agreeing.
	for _, s := range scores {
		if s.Hypothesis.ID == "h6" && s.Survived {
			t.Fatalf("a hypothesis about the wrong window survived with lift [%.1f, %.1f]", s.Lift.Lower, s.Lift.Upper)
		}
	}
	var refuted int
	for _, s := range scores {
		if s.Refuted {
			refuted++
		}
	}
	if refuted == 0 {
		t.Fatal("every candidate survived, so nothing was actually being tested")
	}
}

// The learner has to beat the schedule it replaces, or none of the machinery
// around it is worth its cost.
func TestTheBanditBeatsTheBackoffSchedule(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 30_000, 41)

	base, err := w.Run(Backoff{}, 6)
	if err != nil {
		t.Fatal(err)
	}
	learner := newBandit(t, 12, 0.03, 60)
	learned, err := w.Run(learner, 6)
	if err != nil {
		t.Fatal(err)
	}

	if learned.NetPaisa <= base.NetPaisa {
		t.Fatalf("the bandit recovered %d paisa net against the schedule %d", learned.NetPaisa, base.NetPaisa)
	}
	if learned.RecoveryRate <= base.RecoveryRate {
		t.Fatalf("recovery rate %.4f did not beat %.4f", learned.RecoveryRate, base.RecoveryRate)
	}

	// It also has to have learned the planted rule specifically, rather than
	// simply having discovered that waiting longer is usually better.
	frozen, err := learner.Freeze("thompson-frozen")
	if err != nil {
		t.Fatal(err)
	}
	truth := w.Reveal()
	var inside, matching int
	for _, i := range w.Actionable() {
		inc := w.Incidents()[i]
		if !truth.Matches(inc) || !allowed(w.Permitted(i), truth.Arm) {
			continue
		}
		inside++
		d, err := frozen.Distribution(inc, w.Permitted(i))
		if err != nil {
			t.Fatal(err)
		}
		best := bandit.Arm("")
		bestP := -1.0
		for a, p := range d {
			if p > bestP {
				best, bestP = a, p
			}
		}
		if best == truth.Arm {
			matching++
		}
	}
	if inside == 0 {
		t.Fatal("no incident inside the planted rule survived the gate")
	}
	if share := float64(matching) / float64(inside); share < 0.7 {
		t.Fatalf("inside the planted segment the bandit favours the right arm only %.0f%% of the time", 100*share)
	}
	if frozen.Digest() == "" {
		t.Fatal("a frozen policy must name the belief state it came from")
	}
}

// A closed-form check on the answer key itself, so an error in the enumeration
// cannot quietly validate an error in the estimator.
func TestExactValueMatchesALongRun(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 20_000, 51)

	exact, err := w.ExactValue(Uniform{})
	if err != nil {
		t.Fatal(err)
	}
	run, err := w.Run(Uniform{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	// Twenty thousand incidents of a heavy-tailed amount distribution leave a
	// wide standard error, so this checks the two agree in scale rather than to
	// the paisa.
	if math.Abs(exact-run.MeanNetPaisa) > 0.15*math.Abs(exact)+200 {
		t.Fatalf("exact value %.1f and realised mean %.1f disagree", exact, run.MeanNetPaisa)
	}

	// Backoff and Uniform must differ, or the action space is doing nothing.
	backoff, err := w.ExactValue(Backoff{})
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(backoff-exact) < 1 {
		t.Fatalf("two very different policies score the same: %.2f and %.2f", backoff, exact)
	}
}

// A hypothesis is a claim written by a language model reading an audit log, so
// it is treated as hostile input.
func TestHypothesisValidationIsClosed(t *testing.T) {
	t.Parallel()
	cases := map[string]Hypothesis{
		"no id":            {Arm: ArmLong, IssuerKey: "netbanking:SBI"},
		"unknown arm":      {ID: "x", Arm: "drop table payments", IssuerKey: "netbanking:SBI"},
		"unknown issuer":   {ID: "x", Arm: ArmLong, IssuerKey: "netbanking:ATTACKER"},
		"impossible hours": {ID: "x", Arm: ArmLong, FromHour: 20, ToHour: 3},
		"hours past a day": {ID: "x", Arm: ArmLong, FromHour: 1, ToHour: 99},
		"unknown class":    {ID: "x", Arm: ArmLong, Class: domain.FailureClass("MAKE_ME_RICH")},
		"no filters":       {ID: "x", Arm: ArmLong},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := h.Validate(); !errors.Is(err, ErrBadHypothesis) {
				t.Fatalf("got %v, want ErrBadHypothesis", err)
			}
		})
	}

	// Free text and identifiers are sanitised rather than trusted.
	h := Hypothesis{
		ID:          "id/../../etc/passwd\x00",
		Description: "line one\nline two\x07 and a very long tail " + strings.Repeat("x", 900),
		IssuerKey:   "netbanking:SBI",
		Arm:         ArmLong,
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/", "\x00", "\n", "\x07"} {
		if strings.Contains(h.ID, bad) || strings.Contains(h.Description, bad) {
			t.Fatalf("sanitisation left %q in %q / %q", bad, h.ID, h.Description)
		}
	}
	if len(h.Description) > MaxHypothesisTextLen {
		t.Fatalf("description is %d bytes, over the cap", len(h.Description))
	}
}

// A segment policy may narrow behaviour inside the rules; it may never widen
// them.
func TestASegmentCannotEscapeTheGate(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 4_000, 61)

	// A hypothesis prescribing a five-minute retry for recurring debits, which
	// the RBI cooling window forbids.
	seg, err := NewSegment(Hypothesis{
		ID: "illegal", Class: domain.ClassInsufficientFunds, Arm: ArmFast,
	}, Backoff{})
	if err != nil {
		t.Fatal(err)
	}
	var recurring int
	for _, i := range w.Actionable() {
		inc := w.Incidents()[i]
		permitted := w.Permitted(i)
		d, err := seg.Distribution(inc, permitted)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckDistribution(d, permitted); err != nil {
			t.Fatalf("incident %s: %v", inc.IncidentID, err)
		}
		if inc.Recurring {
			recurring++
			if d[ArmFast] != 0 {
				t.Fatalf("incident %s was given a five-minute retry inside the cooling window", inc.IncidentID)
			}
		}
	}
	if recurring == 0 {
		t.Fatal("no recurring incident was actionable, so this proved nothing")
	}
}

func TestDistributionCheckCatchesMalformedPolicies(t *testing.T) {
	t.Parallel()
	permitted := []bandit.Arm{ArmLong, ArmOvernight}
	if err := CheckDistribution(nil, nil); !errors.Is(err, ErrEmptyPermitted) {
		t.Fatalf("got %v, want ErrEmptyPermitted", err)
	}
	for name, d := range map[string]map[bandit.Arm]float64{
		"does not sum to one": {ArmLong: 0.5, ArmOvernight: 0.2},
		"unpermitted arm":     {ArmLong: 0.5, ArmFast: 0.5},
		"negative mass":       {ArmLong: 1.5, ArmOvernight: -0.5},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := CheckDistribution(d, permitted); !errors.Is(err, ErrBadDistribution) {
				t.Fatalf("got %v, want ErrBadDistribution", err)
			}
		})
	}
	if err := CheckDistribution(map[bandit.Arm]float64{ArmLong: 0.25, ArmOvernight: 0.75}, permitted); err != nil {
		t.Fatalf("a valid distribution was rejected: %v", err)
	}
}

// A segment nobody has evidence about must be refused rather than scored.
func TestThinSegmentsAreRefusedRatherThanScored(t *testing.T) {
	t.Parallel()
	w := newWorld(t, 2_000, 71)
	run, err := w.Run(newBandit(t, 3, 0.05, 40), 9)
	if err != nil {
		t.Fatal(err)
	}
	s, err := w.ScoreHypothesis(run, Hypothesis{
		ID: "tiny", IssuerKey: "netbanking:AXIS", FromHour: 3, ToHour: 4, Arm: ArmLong,
	}, nil, EvalOptions{Seed: 1, Bootstrap: 100})
	if err != nil {
		t.Fatal(err)
	}
	if s.Survived {
		t.Fatalf("a segment covering %d decisions was allowed to survive", s.Coverage)
	}
	if !strings.Contains(s.Error, "below the floor") {
		t.Fatalf("the refusal did not say why: %q", s.Error)
	}
}

func TestArmMetadataIsComplete(t *testing.T) {
	t.Parallel()
	for _, a := range Arms {
		if ArmSeconds(a) <= 0 {
			t.Errorf("arm %q has no delay", a)
		}
		if ArmLabel(a) == string(a) {
			t.Errorf("arm %q has no human label", a)
		}
	}
	if len(Issuers()) != len(issuers) {
		t.Fatal("the issuer list is incomplete")
	}
}

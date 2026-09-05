package ope

import (
	"errors"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// A closed-form world used by most of the tests below.
//
// Two contexts, two actions, rewards in paisa. Every quantity a test asserts on
// can be computed by hand from these six numbers, which is the point: an
// estimator tested only against its own output is tested against nothing.
//
//	success pays  successPaisa
//	failure costs failurePaisa (a gateway fee is charged either way)
//
//	P(success | context, action)
//	          action 0   action 1
//	context 0     0.20       0.50
//	context 1     0.60       0.30
//
// The logging policy is a coin flip, so every propensity is exactly 0.5.
// The target policy plays the better arm in each context with certainty.
const (
	successPaisa = 10_000
	failurePaisa = -100
)

var successProb = [2][2]float64{
	{0.20, 0.50},
	{0.60, 0.30},
}

// bestArm is the target policy: deterministic, and different from the logging
// policy in both contexts, so the estimate is a genuine extrapolation rather
// than a restatement of the log.
var bestArm = [2]int{1, 0}

// armValue is the exact expected reward of one (context, action) pair.
func armValue(ctx, arm int) float64 {
	p := successProb[ctx][arm]
	return p*successPaisa + (1-p)*failurePaisa
}

// truthTarget and truthLogging are the exact values of the two policies under a
// uniform context distribution, worked out from the table above.
func truthTarget() float64 {
	return 0.5 * (armValue(0, bestArm[0]) + armValue(1, bestArm[1]))
}

func truthLogging() float64 {
	var sum float64
	for ctx := 0; ctx < 2; ctx++ {
		sum += 0.5 * (armValue(ctx, 0) + armValue(ctx, 1))
	}
	return sum / 2
}

// drawLog simulates n decisions under the coin-flip logging policy.
func drawLog(rng *rand.Rand, n int) []Sample {
	out := make([]Sample, n)
	for i := range out {
		ctx := rng.Intn(2)
		arm := rng.Intn(2)
		reward := int64(failurePaisa)
		if rng.Float64() < successProb[ctx][arm] {
			reward = successPaisa
		}
		target := 0.0
		if arm == bestArm[ctx] {
			target = 1.0
		}
		out[i] = Sample{Logged: 0.5, Target: target, RewardPaisa: reward}
	}
	return out
}

func TestEvaluateRejectsEmptyLog(t *testing.T) {
	t.Parallel()
	if _, err := Evaluate(nil, Options{}); !errors.Is(err, ErrNoSamples) {
		t.Fatalf("empty log: got %v, want ErrNoSamples", err)
	}
}

func TestEvaluateRejectsMalformedSamples(t *testing.T) {
	t.Parallel()
	cases := map[string]Sample{
		"zero propensity on a taken action": {Logged: 0, Target: 1},
		"propensity above one":              {Logged: 1.5, Target: 1},
		"negative target probability":       {Logged: 0.5, Target: -0.1},
		"target probability above one":      {Logged: 0.5, Target: 1.1},
		"NaN propensity":                    {Logged: math.NaN(), Target: 1},
		"NaN target":                        {Logged: 0.5, Target: math.NaN()},
		"infinite baseline":                 {Logged: 0.5, Target: 1, Baseline: math.Inf(1)},
		"infinite target mean":              {Logged: 0.5, Target: 1, TargetMean: math.Inf(-1)},
		"unsupported mass above one":        {Logged: 0.5, Target: 1, Unsupported: 1.2},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Evaluate([]Sample{s}, Options{}); !errors.Is(err, ErrInvalidSample) {
				t.Fatalf("got %v, want ErrInvalidSample", err)
			}
		})
	}
}

// A propensity below the floor is not a wide interval, it is an undefined
// quantity, and the package has to say so rather than divide by it.
func TestEvaluateRefusesWhenPropensityIsBelowTheFloor(t *testing.T) {
	t.Parallel()
	samples := []Sample{
		{Logged: 0.5, Target: 0.5, RewardPaisa: 100},
		{Logged: 1e-9, Target: 1.0, RewardPaisa: 900_000},
	}
	rep, err := Evaluate(samples, Options{})
	if !errors.Is(err, ErrNoOverlap) {
		t.Fatalf("got %v, want ErrNoOverlap", err)
	}
	if rep.Diagnostics.OverlapViolations != 1 {
		t.Fatalf("violations = %d, want 1", rep.Diagnostics.OverlapViolations)
	}
	// The refusal has to carry its evidence, or an operator cannot tell a
	// broken log from a merely unlucky one.
	if rep.Diagnostics.Samples != 2 {
		t.Fatalf("diagnostics were not populated alongside the refusal: %+v", rep.Diagnostics)
	}
}

// The half of the overlap assumption that no log can reveal: the target policy
// wants an action the logging policy could never have produced. Only the caller
// knows this, so the caller reports it and the estimator must honour it.
func TestEvaluateRefusesUnsupportedTargetMass(t *testing.T) {
	t.Parallel()
	samples := []Sample{
		{Logged: 0.5, Target: 0.5, RewardPaisa: 100},
		{Logged: 0.5, Target: 0.2, RewardPaisa: 100, Unsupported: 0.3},
	}
	_, err := Evaluate(samples, Options{})
	if !errors.Is(err, ErrNoOverlap) {
		t.Fatalf("got %v, want ErrNoOverlap", err)
	}
}

// When the target policy is the logging policy, off-policy evaluation must
// reduce to the plain average. Anything else is a bug in the weighting.
func TestSelfEvaluationReducesToTheObservedMean(t *testing.T) {
	t.Parallel()
	samples := []Sample{
		{Logged: 0.25, Target: 0.25, RewardPaisa: 400},
		{Logged: 0.75, Target: 0.75, RewardPaisa: -100},
		{Logged: 0.5, Target: 0.5, RewardPaisa: 900},
	}
	rep, err := Evaluate(samples, Options{Bootstrap: 0})
	if err != nil {
		t.Fatal(err)
	}
	want := (400.0 - 100 + 900) / 3
	for name, got := range map[string]float64{"logged": rep.Logged.Value, "ips": rep.IPS.Value, "snips": rep.SNIPS.Value} {
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if math.Abs(rep.Diagnostics.EffectiveSampleSize-3) > 1e-9 {
		t.Errorf("uniform weights should give ESS = n, got %v", rep.Diagnostics.EffectiveSampleSize)
	}
}

// IPS is unbiased under overlap. Averaged over many independent logs its error
// has to vanish, and the rate has to look like Monte-Carlo noise rather than a
// constant offset.
func TestIPSIsUnbiased(t *testing.T) {
	t.Parallel()
	const (
		trials  = 400
		perLog  = 600
		tolPais = 60 // roughly 1% of the true value
	)
	var sum float64
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 1))
		rep, err := Evaluate(drawLog(rng, perLog), Options{Bootstrap: 0})
		if err != nil {
			t.Fatal(err)
		}
		sum += rep.IPS.Value
	}
	got, want := sum/trials, truthTarget()
	if math.Abs(got-want) > tolPais {
		t.Fatalf("mean IPS estimate over %d logs = %.1f paisa, true value %.1f, drift %.1f exceeds %d",
			trials, got, want, got-want, tolPais)
	}
}

// SNIPS trades a vanishing bias for a large variance reduction. The variance
// claim is the reason it is the default, so it is asserted rather than assumed.
func TestSNIPSHasLowerVarianceThanIPS(t *testing.T) {
	t.Parallel()
	const (
		trials = 300
		perLog = 300
	)
	ipsVals := make([]float64, 0, trials)
	snipsVals := make([]float64, 0, trials)
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 9_000))
		rep, err := Evaluate(drawLog(rng, perLog), Options{Bootstrap: 0})
		if err != nil {
			t.Fatal(err)
		}
		ipsVals = append(ipsVals, rep.IPS.Value)
		snipsVals = append(snipsVals, rep.SNIPS.Value)
	}
	vi, vs := variance(ipsVals), variance(snipsVals)
	if vs >= vi {
		t.Fatalf("SNIPS variance %.1f is not below IPS variance %.1f", vs, vi)
	}
}

// SNIPS cannot report a value outside the range of rewards that were actually
// observed. IPS can, and the contrast is the practical argument for SNIPS.
func TestSNIPSStaysInsideTheObservedRewardRange(t *testing.T) {
	t.Parallel()
	for trial := 0; trial < 50; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 4_100))
		samples := drawLog(rng, 200)
		rep, err := Evaluate(samples, Options{Bootstrap: 0})
		if err != nil {
			t.Fatal(err)
		}
		lo, hi := float64(failurePaisa), float64(successPaisa)
		if rep.SNIPS.Value < lo-1e-9 || rep.SNIPS.Value > hi+1e-9 {
			t.Fatalf("SNIPS %v escaped the observed reward range [%v, %v]", rep.SNIPS.Value, lo, hi)
		}
	}
}

// With no outcome model supplied, DR must collapse onto IPS exactly. Any other
// result means zero-valued model fields are being read as information.
func TestDoublyRobustWithoutAModelIsExactlyIPS(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(77))
	samples := drawLog(rng, 500)
	rep, err := Evaluate(samples, Options{Bootstrap: 0, WithOutcomeModel: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.DR == nil {
		t.Fatal("DR estimate missing")
	}
	if math.Abs(rep.DR.Value-rep.IPS.Value) > 1e-9 {
		t.Fatalf("DR %v differs from IPS %v with an all-zero model", rep.DR.Value, rep.IPS.Value)
	}
}

// The doubly-robust promise: given correct propensities, a good outcome model
// buys a much tighter interval without moving the estimate off the truth.
func TestDoublyRobustBeatsIPSWhenTheModelIsGood(t *testing.T) {
	t.Parallel()
	const (
		trials = 200
		perLog = 250
	)
	ipsVals := make([]float64, 0, trials)
	drVals := make([]float64, 0, trials)
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 31_337))
		samples := make([]Sample, perLog)
		for i := range samples {
			ctx := rng.Intn(2)
			arm := rng.Intn(2)
			reward := int64(failurePaisa)
			if rng.Float64() < successProb[ctx][arm] {
				reward = successPaisa
			}
			target := 0.0
			if arm == bestArm[ctx] {
				target = 1.0
			}
			samples[i] = Sample{
				Logged:      0.5,
				Target:      target,
				RewardPaisa: reward,
				Baseline:    armValue(ctx, arm),
				TargetMean:  armValue(ctx, bestArm[ctx]),
			}
		}
		rep, err := Evaluate(samples, Options{Bootstrap: 0, WithOutcomeModel: true})
		if err != nil {
			t.Fatal(err)
		}
		ipsVals = append(ipsVals, rep.IPS.Value)
		drVals = append(drVals, rep.DR.Value)
	}
	truth := truthTarget()
	if got := mean(drVals); math.Abs(got-truth) > 60 {
		t.Fatalf("DR mean %.1f is off the true value %.1f", got, truth)
	}
	if variance(drVals) >= variance(ipsVals) {
		t.Fatalf("DR variance %.1f did not improve on IPS variance %.1f", variance(drVals), variance(ipsVals))
	}
}

// Doubly robust means either component may be wrong. Here the propensities are
// right and the outcome model has the arms backwards, and the estimate must
// still land on the truth.
func TestDoublyRobustSurvivesAWrongOutcomeModel(t *testing.T) {
	t.Parallel()
	const (
		trials = 300
		perLog = 400
	)
	vals := make([]float64, 0, trials)
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 5_150))
		samples := make([]Sample, perLog)
		for i := range samples {
			ctx := rng.Intn(2)
			arm := rng.Intn(2)
			reward := int64(failurePaisa)
			if rng.Float64() < successProb[ctx][arm] {
				reward = successPaisa
			}
			target := 0.0
			if arm == bestArm[ctx] {
				target = 1.0
			}
			// A model that has learned the arms the wrong way round: right
			// scale, inverted preference. The importance-weighted residual
			// undoes it.
			samples[i] = Sample{
				Logged: 0.5, Target: target, RewardPaisa: reward,
				Baseline:   armValue(ctx, 1-arm),
				TargetMean: armValue(ctx, 1-bestArm[ctx]),
			}
		}
		rep, err := Evaluate(samples, Options{Bootstrap: 0, WithOutcomeModel: true})
		if err != nil {
			t.Fatal(err)
		}
		vals = append(vals, rep.DR.Value)
	}
	if got, want := mean(vals), truthTarget(); math.Abs(got-want) > 150 {
		t.Fatalf("DR with an inverted model = %.1f, true value %.1f", got, want)
	}
}

// The limit of that robustness, recorded because it is the failure mode that
// bites in production and is almost never stated.
//
// DR is unbiased whenever the propensities are right, no matter how wrong the
// model is. It is not stable. A model whose predictions are off by an order of
// magnitude leaves a residual of the same magnitude, the importance weights
// amplify it, and the estimate becomes correct on average and worthless on any
// single log. Bias and variance are different promises and only the first one
// is doubly robust.
func TestDoublyRobustVarianceExplodesWhenTheModelIsBadlyScaled(t *testing.T) {
	t.Parallel()
	const (
		trials = 200
		perLog = 400
		absurd = 500_000 // fifty times the largest reward that can occur
	)
	drVals := make([]float64, 0, trials)
	snipsVals := make([]float64, 0, trials)
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 12_000))
		samples := drawLog(rng, perLog)
		for i := range samples {
			samples[i].Baseline = absurd
			samples[i].TargetMean = absurd
		}
		rep, err := Evaluate(samples, Options{Bootstrap: 0, WithOutcomeModel: true})
		if err != nil {
			t.Fatal(err)
		}
		drVals = append(drVals, rep.DR.Value)
		snipsVals = append(snipsVals, rep.SNIPS.Value)
	}
	// Still unbiased, given enough independent logs to average over.
	if got, want := mean(drVals), truthTarget(); math.Abs(got-want) > 4_000 {
		t.Fatalf("DR lost its unbiasedness: %.1f against a true value of %.1f", got, want)
	}
	// And useless on any one of them.
	if variance(drVals) < 100*variance(snipsVals) {
		t.Fatalf("expected a badly scaled model to blow up DR variance; DR %.0f vs SNIPS %.0f",
			variance(drVals), variance(snipsVals))
	}
}

// The property that makes an interval worth printing: over repeated
// experiments, a 95% interval contains the truth about 95% of the time.
//
// This is the test that would catch a bootstrap that resamples wrong, a
// percentile read off by one, or an interval built from a different set of
// resamples than the point estimate.
func TestBootstrapIntervalsCoverTheTruth(t *testing.T) {
	t.Parallel()
	const (
		trials = 240
		perLog = 500
	)
	truth := truthTarget()
	covered := 0
	for trial := 0; trial < trials; trial++ {
		rng := rand.New(rand.NewSource(int64(trial) + 600_000))
		rep, err := Evaluate(drawLog(rng, perLog), Options{Bootstrap: 400, Seed: int64(trial)})
		if err != nil {
			t.Fatal(err)
		}
		if rep.SNIPS.Lower <= truth && truth <= rep.SNIPS.Upper {
			covered++
		}
	}
	rate := float64(covered) / trials
	// Nominal coverage is 0.95. The band allows for Monte-Carlo error at this
	// trial count plus the known finite-sample conservatism of the percentile
	// bootstrap; a broken interval fails it by a mile in either direction.
	if rate < 0.88 || rate > 0.995 {
		t.Fatalf("95%% interval covered the truth %.1f%% of the time over %d trials", 100*rate, trials)
	}
}

// A quoted interval has to be re-derivable by whoever is being asked to believe
// it, so the whole report must be a pure function of the inputs and the seed.
func TestReportIsDeterministicGivenASeed(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(2_024))
	samples := drawLog(rng, 300)
	opts := Options{Bootstrap: 250, Seed: 99, WithOutcomeModel: true}
	first, err := Evaluate(samples, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(samples, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two evaluations of the same log with the same seed disagreed")
	}
	third, err := Evaluate(samples, Options{Bootstrap: 250, Seed: 100, WithOutcomeModel: true})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first.SNIPS, third.SNIPS) {
		t.Fatal("changing the seed left the interval unchanged, so the seed is not reaching the bootstrap")
	}
	if math.Abs(first.SNIPS.Value-third.SNIPS.Value) > 1e-9 {
		t.Fatal("the seed moved the point estimate, which must not depend on the bootstrap")
	}
}

// The lift is what a reviewer acts on, so its interval must be paired: built
// from the difference on each resample rather than from two separate intervals.
func TestLiftIsPairedAndTighterThanSubtractingTwoIntervals(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(8_800))
	samples := drawLog(rng, 800)
	opts := Options{Bootstrap: 600, Seed: 5}

	lift, rep, err := EvaluateLift(samples, opts)
	if err != nil {
		t.Fatal(err)
	}
	trueLift := truthTarget() - truthLogging()
	if math.Abs(lift.Value-trueLift) > 400 {
		t.Fatalf("lift point estimate %.1f is far from the true lift %.1f", lift.Value, trueLift)
	}
	naive := (rep.IPS.Upper - rep.Logged.Lower) - (rep.IPS.Lower - rep.Logged.Upper)
	paired := lift.Upper - lift.Lower
	if paired >= naive {
		t.Fatalf("paired interval width %.1f is not tighter than the unpaired %.1f", paired, naive)
	}
	if !lift.Significant {
		t.Fatalf("a real lift of %.1f paisa over %d incidents was not significant: [%.1f, %.1f]",
			trueLift, len(samples), lift.Lower, lift.Upper)
	}
}

// Diagnostics exist to stop a number being believed. A log where the target
// policy almost never agrees with the logger must say so loudly.
func TestDiagnosticsFlagThinOverlap(t *testing.T) {
	t.Parallel()
	samples := make([]Sample, 500)
	for i := range samples {
		s := Sample{Logged: 0.99, Target: 0, RewardPaisa: 10}
		if i%100 == 0 {
			s = Sample{Logged: 0.01, Target: 1, RewardPaisa: 10_000}
		}
		samples[i] = s
	}
	rep, err := Evaluate(samples, Options{Bootstrap: 0, PropensityFloor: 1e-4})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Diagnostics.ESSFraction > 0.05 {
		t.Fatalf("ESS fraction %.3f should be tiny here", rep.Diagnostics.ESSFraction)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("a log with five usable incidents out of five hundred produced no warnings")
	}
	if rep.Diagnostics.SupportedSamples != 5 {
		t.Fatalf("supported samples = %d, want 5", rep.Diagnostics.SupportedSamples)
	}
}

// Clipping is legitimate and it is also a thumb on the scale, so it must be
// counted and named.
func TestWeightCapIsCountedAndAnnounced(t *testing.T) {
	t.Parallel()
	samples := []Sample{
		{Logged: 0.01, Target: 1, RewardPaisa: 10_000},
		{Logged: 0.90, Target: 1, RewardPaisa: 10},
	}
	rep, err := Evaluate(samples, Options{Bootstrap: 0, PropensityFloor: 1e-4, WeightCap: 5})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Diagnostics.ClippedSamples != 1 {
		t.Fatalf("clipped = %d, want 1", rep.Diagnostics.ClippedSamples)
	}
	if math.Abs(rep.Diagnostics.MaxWeight-5) > 1e-9 {
		t.Fatalf("max weight = %v, want the cap 5", rep.Diagnostics.MaxWeight)
	}
	var announced bool
	for _, w := range rep.Warnings {
		if strings.Contains(w, "truncated") {
			announced = true
		}
	}
	if !announced {
		t.Fatalf("clipping was not announced in the warnings: %v", rep.Warnings)
	}
}

func TestOptionsAreValidated(t *testing.T) {
	t.Parallel()
	s := []Sample{{Logged: 0.5, Target: 0.5, RewardPaisa: 1}}
	for name, opts := range map[string]Options{
		"confidence at one":     {Confidence: 1},
		"confidence negative":   {Confidence: -0.5},
		"negative weight cap":   {WeightCap: -1},
		"bootstrap too large":   {Bootstrap: MaxBootstrapRounds + 1},
		"floor at one":          {PropensityFloor: 1},
		"bootstrap negative":    {Bootstrap: -1},
		"propensity floor high": {PropensityFloor: 1.5},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Evaluate(s, opts); err == nil {
				t.Fatal("invalid options were accepted")
			}
		})
	}
}

func TestEstimateHelpers(t *testing.T) {
	t.Parallel()
	e := Estimate{Value: 412.6, Lower: 400, Upper: 425}
	if got := e.TotalPaisa(1_000); got != 412_600 {
		t.Fatalf("TotalPaisa = %d, want 412600", got)
	}
	if !e.Beats(Estimate{Value: 399}) {
		t.Fatal("an interval entirely above the comparison should beat it")
	}
	if e.Beats(Estimate{Value: 401}) {
		t.Fatal("an interval straddling the comparison must not beat it")
	}
}

func mean(v []float64) float64 {
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func variance(v []float64) float64 {
	m := mean(v)
	var s float64
	for _, x := range v {
		s += (x - m) * (x - m)
	}
	return s / float64(len(v)-1)
}

package calib

import (
	"errors"
	"math"
	"math/rand"
	"testing"
)

// binCentres are the ten values a confidence takes in most of these tests. They
// sit at the centre of the default bins, so the forecast is constant within
// each bin and the Murphy decomposition holds exactly rather than approximately.
var binCentres = []float64{0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95}

// drawCalibrated produces observations whose stated confidence is the truth.
func drawCalibrated(rng *rand.Rand, n int) []Observation {
	out := make([]Observation, n)
	for i := range out {
		c := binCentres[rng.Intn(len(binCentres))]
		out[i] = Observation{Confidence: c, Correct: rng.Float64() < c}
	}
	return out
}

// drawOverconfident produces the failure mode this package exists to find: the
// model states a high number and is right far less often than it claims. The
// distortion is monotone, which is what isotonic regression can undo.
func drawOverconfident(rng *rand.Rand, n int) []Observation {
	out := make([]Observation, n)
	for i := range out {
		c := binCentres[rng.Intn(len(binCentres))]
		out[i] = Observation{Confidence: c, Correct: rng.Float64() < c*c}
	}
	return out
}

func TestMeasureRejectsBadInput(t *testing.T) {
	t.Parallel()
	if _, err := Measure(nil, Options{}); !errors.Is(err, ErrNoObservations) {
		t.Fatalf("got %v, want ErrNoObservations", err)
	}
	for name, o := range map[string]Observation{
		"above one": {Confidence: 1.2},
		"negative":  {Confidence: -0.1},
		"NaN":       {Confidence: math.NaN()},
		"infinite":  {Confidence: math.Inf(1)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Measure([]Observation{o}, Options{}); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("got %v, want ErrInvalidObservation", err)
			}
		})
	}
	for name, opts := range map[string]Options{
		"one bin":        {Bins: 1},
		"too many bins":  {Bins: maxBins + 1},
		"one fold":       {Folds: 1},
		"too many folds": {Folds: maxFolds + 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Measure([]Observation{{Confidence: 0.5}}, opts); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("got %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestCalibratedInputScoresNearZeroError(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	rep, err := Measure(drawCalibrated(rng, 60_000), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ECE > 0.01 {
		t.Fatalf("a perfectly calibrated corpus scored an expected calibration error of %.4f", rep.ECE)
	}
	if math.Abs(rep.MeanConfidence-rep.Accuracy) > 0.01 {
		t.Fatalf("mean confidence %.4f and accuracy %.4f should agree", rep.MeanConfidence, rep.Accuracy)
	}
	if len(rep.Warnings) != 0 {
		t.Fatalf("unexpected warnings on a large clean corpus: %v", rep.Warnings)
	}
}

func TestOverconfidenceIsDetectedAndNamed(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(2))
	rep, err := Measure(drawOverconfident(rng, 60_000), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Overconfident {
		t.Fatal("a model right half as often as it claims was not flagged as overconfident")
	}
	if rep.ECE < 0.10 {
		t.Fatalf("expected calibration error %.4f is too small for this much distortion", rep.ECE)
	}
	if rep.MCE < rep.ECE {
		t.Fatalf("maximum error %.4f cannot be below the mean error %.4f", rep.MCE, rep.ECE)
	}
	// Every populated bin should overstate, since the distortion is monotone.
	for _, b := range rep.Bins {
		if b.Count > 0 && b.Lower >= 0.2 && b.Gap <= 0 {
			t.Errorf("bin [%.2f, %.2f) has gap %.4f, expected the model to overstate", b.Lower, b.Upper, b.Gap)
		}
	}
}

// The Murphy decomposition is an identity, not an approximation, when the
// forecast is constant inside each bin. Asserting it catches a weighting error
// in any of the three terms.
func TestBrierDecompositionIsAnIdentity(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(3))
	for _, draw := range []func(*rand.Rand, int) []Observation{drawCalibrated, drawOverconfident} {
		rep, err := Measure(draw(rng, 40_000), Options{Bins: 10})
		if err != nil {
			t.Fatal(err)
		}
		got := rep.Reliability - rep.Resolution + rep.Uncertainty
		if math.Abs(got-rep.Brier) > 1e-9 {
			t.Fatalf("reliability %.9f - resolution %.9f + uncertainty %.9f = %.9f, but Brier is %.9f",
				rep.Reliability, rep.Resolution, rep.Uncertainty, got, rep.Brier)
		}
	}
}

func TestThinBinsAreFlagged(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(4))
	rep, err := Measure(drawCalibrated(rng, 40), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("forty observations across ten bins produced no warning")
	}
	var thin int
	for _, b := range rep.Bins {
		if b.Thin {
			thin++
		}
	}
	if thin == 0 {
		t.Fatal("no bin was marked thin")
	}
}

// Isotonic regression must produce a monotone map, because the point of using
// it over a free-form fit is that it cannot reorder the model judgements.
func TestFittedCalibratorIsMonotone(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(5))
	c, err := Fit(drawOverconfident(rng, 5_000))
	if err != nil {
		t.Fatal(err)
	}
	prev := -1.0
	for x := 0.0; x <= 1.0; x += 0.001 {
		v := c.Apply(x)
		if v < prev-1e-12 {
			t.Fatalf("calibrated confidence fell from %.6f to %.6f at x=%.3f", prev, v, x)
		}
		if v < 0 || v > 1 {
			t.Fatalf("calibrated value %v at x=%.3f is not a probability", v, x)
		}
		prev = v
	}
	if len(c.Steps()) == 0 {
		t.Fatal("the fitted calibrator has no steps")
	}
}

// The correction has to recover the truth it was hidden behind.
func TestCalibratorRecoversTheTrueFrequency(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(6))
	c, err := Fit(drawOverconfident(rng, 200_000))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range binCentres {
		if got, want := c.Apply(x), x*x; math.Abs(got-want) > 0.03 {
			t.Errorf("stated %.2f: calibrated to %.3f, true frequency %.3f", x, got, want)
		}
	}
}

// When the stated confidence carries no information at all, the only monotone
// fit is a constant, and that constant has to be the base rate.
func TestCalibratorFlattensAnUninformativeSignal(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(7))
	obs := make([]Observation, 20_000)
	for i := range obs {
		obs[i] = Observation{Confidence: rng.Float64(), Correct: rng.Float64() < 0.4}
	}
	c, err := Fit(obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []float64{0.05, 0.5, 0.95} {
		if got := c.Apply(x); math.Abs(got-0.4) > 0.05 {
			t.Errorf("uninformative confidence %.2f calibrated to %.3f, want the base rate 0.4", x, got)
		}
	}
}

// The headline claim: cross-fitted correction genuinely reduces calibration
// error on observations the calibrator never saw.
func TestRepairImprovesCalibrationOutOfSample(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(8))
	rep, err := FitAndMeasure(drawOverconfident(rng, 30_000), Options{Seed: 3})
	if err != nil {
		t.Fatal(err)
	}
	if rep.After.ECE >= rep.Before.ECE {
		t.Fatalf("correction did not help: %.4f before, %.4f after", rep.Before.ECE, rep.After.ECE)
	}
	if rep.Improvement < 0.5 {
		t.Fatalf("only %.1f%% of the calibration error was removed", 100*rep.Improvement)
	}
	if rep.After.Overconfident && rep.After.ECE > 0.02 {
		t.Fatalf("the corrected corpus is still overconfident by %.4f", rep.After.ECE)
	}
	if rep.Calibrator == nil {
		t.Fatal("no deployable calibrator was returned")
	}
	if rep.Folds != DefaultFolds {
		t.Fatalf("folds = %d, want %d", rep.Folds, DefaultFolds)
	}
}

// Correcting something that is already correct must not be reported as a win.
//
// The subtlety this pins down: the improvement ratio is large here, and it is
// meaningless, because the error it divides by was never real. Expected
// calibration error is an average of absolute values, so a flawless model still
// scores a few thousandths from sampling noise alone, and any correction fitted
// against the observed frequencies removes that. What has to be true is that the
// absolute movement is negligible and that the result is labelled insignificant.
func TestRepairClaimsLittleOnAlreadyCalibratedData(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(9))
	rep, err := FitAndMeasure(drawCalibrated(rng, 30_000), Options{Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Significant {
		t.Fatalf("a calibrated corpus was reported as miscalibrated: error %.4f against a noise floor of %.4f",
			rep.Before.ECE, rep.NoiseFloor)
	}
	if rep.Reduction > 0.01 {
		t.Fatalf("correction moved a clean corpus by %.4f, which is not nothing", rep.Reduction)
	}
	if rep.After.ECE > 0.02 {
		t.Fatalf("correction damaged a clean corpus: %.4f", rep.After.ECE)
	}
	if rep.NoiseFloor <= 0 {
		t.Fatalf("noise floor was not measured: %v", rep.NoiseFloor)
	}
}

// And the contrast: genuine miscalibration must clear the same floor easily.
func TestGenuineMiscalibrationIsSignificant(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(21))
	rep, err := FitAndMeasure(drawOverconfident(rng, 30_000), Options{Seed: 6})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Significant {
		t.Fatalf("real overconfidence of %.4f did not clear a noise floor of %.4f", rep.Before.ECE, rep.NoiseFloor)
	}
	if rep.Reduction <= 0.05 {
		t.Fatalf("absolute reduction was only %.4f", rep.Reduction)
	}
}

// The floor has to shrink as the corpus grows, or it is not measuring what it
// claims to.
func TestNoiseFloorFallsWithCorpusSize(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(22))
	small, err := NoiseFloor(drawCalibrated(rng, 300), Options{Seed: 1}, 100)
	if err != nil {
		t.Fatal(err)
	}
	large, err := NoiseFloor(drawCalibrated(rng, 30_000), Options{Seed: 1}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if small <= large {
		t.Fatalf("noise floor did not fall with size: %.4f at 300, %.4f at 30000", small, large)
	}
	if _, err := NoiseFloor(drawCalibrated(rng, 100), Options{}, maxNoiseFloorRounds+1); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("got %v, want ErrInvalidOptions", err)
	}
}

// Cross-fitting is the difference between a measurement and a boast, so the gap
// between the honest and the in-sample number has to exist.
func TestInSampleCorrectionLooksBetterThanTheHonestOne(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(10))
	obs := make([]Observation, 600)
	for i := range obs {
		obs[i] = Observation{Confidence: rng.Float64(), Correct: rng.Float64() < 0.35}
	}
	rep, err := FitAndMeasure(obs, Options{Seed: 5})
	if err != nil {
		t.Fatal(err)
	}
	if rep.InSample.ECE > rep.After.ECE {
		t.Fatalf("in-sample error %.4f should not exceed the held-out error %.4f", rep.InSample.ECE, rep.After.ECE)
	}
}

func TestRepairNeedsEnoughObservations(t *testing.T) {
	t.Parallel()
	obs := []Observation{{Confidence: 0.5, Correct: true}, {Confidence: 0.6}}
	if _, err := FitAndMeasure(obs, Options{Folds: 5}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("got %v, want ErrInvalidOptions", err)
	}
}

// The measurement that replaces the chosen constant.
func TestThresholdForFindsTheLowestQualifyingCut(t *testing.T) {
	t.Parallel()
	// Twenty at 0.9 of which eighteen are correct, twenty at 0.5 of which six
	// are. Demanding 0.85 accuracy must accept only the high group.
	var obs []Observation
	for i := 0; i < 20; i++ {
		obs = append(obs, Observation{Confidence: 0.9, Correct: i < 18})
	}
	for i := 0; i < 20; i++ {
		obs = append(obs, Observation{Confidence: 0.5, Correct: i < 6})
	}

	th, err := ThresholdFor(obs, 0.85)
	if err != nil {
		t.Fatal(err)
	}
	if th.Confidence != 0.9 {
		t.Fatalf("threshold = %v, want 0.9", th.Confidence)
	}
	if th.Accepted != 20 || th.Correct != 18 {
		t.Fatalf("accepted %d of which %d correct, want 20 and 18", th.Accepted, th.Correct)
	}
	if math.Abs(th.Coverage-0.5) > 1e-12 {
		t.Fatalf("coverage = %v, want 0.5", th.Coverage)
	}
	if math.Abs(th.Accuracy-0.9) > 1e-12 {
		t.Fatalf("accuracy = %v, want 0.9", th.Accuracy)
	}

	// A target nothing reaches is an answer, not a crash.
	if _, err := ThresholdFor(obs, 0.99); !errors.Is(err, ErrUnreachableTarget) {
		t.Fatalf("got %v, want ErrUnreachableTarget", err)
	}
	if _, err := ThresholdFor(obs, 0); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("got %v, want ErrInvalidOptions for a zero target", err)
	}
}

// A threshold cannot separate two predictions that stated the same confidence,
// so the sweep must only stop at the end of a run of equal values.
func TestThresholdDoesNotSplitEqualConfidences(t *testing.T) {
	t.Parallel()
	obs := []Observation{
		{Confidence: 0.8, Correct: true},
		{Confidence: 0.8, Correct: false},
		{Confidence: 0.8, Correct: true},
		{Confidence: 0.2, Correct: false},
	}
	th, err := ThresholdFor(obs, 0.6)
	if err != nil {
		t.Fatal(err)
	}
	if th.Accepted != 3 {
		t.Fatalf("accepted %d, want all three predictions at 0.8", th.Accepted)
	}
	if _, err := ThresholdFor(obs, 0.8); !errors.Is(err, ErrUnreachableTarget) {
		t.Fatal("a target above the best equal-confidence group should be unreachable")
	}
}

func TestAccuracyAtReportsADeployedThreshold(t *testing.T) {
	t.Parallel()
	obs := []Observation{
		{Confidence: 0.95, Correct: true},
		{Confidence: 0.85, Correct: true},
		{Confidence: 0.80, Correct: false},
		{Confidence: 0.40, Correct: true},
	}
	th, err := AccuracyAt(obs, 0.80)
	if err != nil {
		t.Fatal(err)
	}
	if th.Accepted != 3 || th.Correct != 2 {
		t.Fatalf("accepted %d correct %d, want 3 and 2", th.Accepted, th.Correct)
	}
	if math.Abs(th.Accuracy-2.0/3) > 1e-12 {
		t.Fatalf("accuracy = %v", th.Accuracy)
	}
	if math.Abs(th.Coverage-0.75) > 1e-12 {
		t.Fatalf("coverage = %v, want 0.75", th.Coverage)
	}
	// A threshold nothing clears reports zero accepted rather than dividing by
	// zero.
	empty, err := AccuracyAt(obs, 1.1)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Accepted != 0 || empty.Accuracy != 0 || empty.Coverage != 0 {
		t.Fatalf("an unreachable threshold reported %+v", empty)
	}
}

// A calibration figure quoted in an audit record has to be re-derivable.
func TestResultsAreDeterministic(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(11))
	obs := drawOverconfident(rng, 4_000)

	a, err := FitAndMeasure(obs, Options{Seed: 21})
	if err != nil {
		t.Fatal(err)
	}
	b, err := FitAndMeasure(obs, Options{Seed: 21})
	if err != nil {
		t.Fatal(err)
	}
	if a.After.ECE != b.After.ECE || a.Improvement != b.Improvement {
		t.Fatal("two identical repairs disagreed")
	}

	// The fit must depend on the multiset of observations, not on the order the
	// caller collected them in.
	shuffled := append([]Observation(nil), obs...)
	rand.New(rand.NewSource(99)).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	c1, err := Fit(obs)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Fit(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range binCentres {
		if c1.Apply(x) != c2.Apply(x) {
			t.Fatalf("reordering the input changed the fit at %.2f: %v vs %v", x, c1.Apply(x), c2.Apply(x))
		}
	}
}

func TestApplyHandlesEdges(t *testing.T) {
	t.Parallel()
	c, err := Fit([]Observation{
		{Confidence: 0.2, Correct: false},
		{Confidence: 0.8, Correct: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Apply(0); got != 0 {
		t.Fatalf("Apply(0) = %v, want the lowest block value 0", got)
	}
	if got := c.Apply(1); got != 1 {
		t.Fatalf("Apply(1) = %v, want the highest block value 1", got)
	}
	if got := c.Apply(math.NaN()); !math.IsNaN(got) {
		t.Fatalf("Apply(NaN) = %v, want NaN passed through", got)
	}
	empty := &Calibrator{}
	if got := empty.Apply(0.42); got != 0.42 {
		t.Fatalf("an unfitted calibrator changed the value to %v", got)
	}
}

package reward

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"testing"
)

// A synthetic recovery world with a structure the model has to find: the issuer
// sets a base rate, and one particular combination of issuer and delay recovers
// far better than the rest. That interaction is the sort of thing this system
// exists to discover, so it is what the model is tested on.
var issuerBase = map[string]float64{
	"upi:okhdfcbank": 0.45,
	"netbanking:SBI": 0.20,
	"card:ICICI":     0.35,
}

var delays = []string{"5m", "1h", "6h", "24h"}

func trueProbability(issuer, delay string) float64 {
	p := issuerBase[issuer]
	if issuer == "netbanking:SBI" && delay == "6h" {
		// The planted structure: this issuer runs a batch overnight, so a
		// six-hour wait catches it on the other side.
		p = 0.62
	}
	if delay == "5m" {
		p *= 0.55 // retrying immediately mostly fails again
	}
	return p
}

func drawExamples(rng *rand.Rand, n int) []Example {
	issuers := []string{"upi:okhdfcbank", "netbanking:SBI", "card:ICICI"}
	out := make([]Example, n)
	for i := range out {
		issuer := issuers[rng.Intn(len(issuers))]
		delay := delays[rng.Intn(len(delays))]
		out[i] = Example{
			Features: []string{"issuer=" + issuer, "delay=" + delay, "issuer_delay=" + issuer + "|" + delay},
			Label:    rng.Float64() < trueProbability(issuer, delay),
		}
	}
	return out
}

func TestOptionsAreValidated(t *testing.T) {
	t.Parallel()
	ex := []Example{{Features: []string{"a"}, Label: true}, {Features: []string{"b"}, Label: false}}
	cases := map[string]Options{
		"dimensions not a power of two":        {Dimensions: 1000},
		"dimensions too small":                 {Dimensions: 8},
		"epochs too many":                      {Epochs: maxEpochs + 1},
		"epochs zero is fine, negative is not": {Epochs: -1},
		"learning rate negative":               {LearningRate: -1},
		"learning rate absurd":                 {LearningRate: 100},
		"L2 out of range":                      {L2: 2},
		"one fold":                             {Folds: 1},
		"too many folds":                       {Folds: maxFolds + 1},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Fit(ex, opts); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("got %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestFitRejectsUnlearnableInput(t *testing.T) {
	t.Parallel()
	if _, _, err := Fit(nil, Options{}); !errors.Is(err, ErrNoExamples) {
		t.Fatalf("got %v, want ErrNoExamples", err)
	}
	same := []Example{
		{Features: []string{"a"}, Label: true},
		{Features: []string{"b"}, Label: true},
	}
	if _, _, err := Fit(same, Options{}); !errors.Is(err, ErrDegenerate) {
		t.Fatalf("got %v, want ErrDegenerate", err)
	}
}

// The model has to beat the base rate on data it has not seen. Everything else
// in this package is machinery in service of that one claim.
func TestCrossFittedModelBeatsTheBaseRate(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	examples := drawExamples(rng, 12_000)

	_, rep, err := CrossFit(examples, Options{Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skill <= 0.02 {
		t.Fatalf("held-out skill %.4f: the model did not improve on predicting the base rate", rep.Skill)
	}
	if rep.AUC <= 0.60 {
		t.Fatalf("held-out AUC %.3f is barely better than a coin flip", rep.AUC)
	}
	if rep.LogLoss >= rep.BaselineLogLoss {
		t.Fatalf("log loss %.4f is not below the baseline %.4f", rep.LogLoss, rep.BaselineLogLoss)
	}
	if rep.Folds != DefaultFolds {
		t.Fatalf("folds = %d, want %d", rep.Folds, DefaultFolds)
	}
}

// The predictions have to be calibrated, not merely ranked, because the
// doubly-robust estimator subtracts them from observed rewards. A model with a
// perfect ranking and a constant offset would corrupt every residual.
func TestPredictionsAreCalibratedAgainstTheTruth(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(2))
	examples := drawExamples(rng, 40_000)
	m, _, err := Fit(examples, Options{Seed: 3, Epochs: 20})
	if err != nil {
		t.Fatal(err)
	}
	for issuer := range issuerBase {
		for _, delay := range delays {
			got := m.Predict([]string{"issuer=" + issuer, "delay=" + delay, "issuer_delay=" + issuer + "|" + delay})
			want := trueProbability(issuer, delay)
			if math.Abs(got-want) > 0.05 {
				t.Errorf("%s at %s: predicted %.3f, true %.3f", issuer, delay, got, want)
			}
		}
	}
}

// The interaction is the whole reason a model is here rather than a lookup on
// the issuer. If it cannot separate the planted segment from its own issuer
// base rate, it is not adding anything a group-by would not.
func TestModelFindsThePlantedInteraction(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(4))
	m, _, err := Fit(drawExamples(rng, 40_000), Options{Seed: 5, Epochs: 20})
	if err != nil {
		t.Fatal(err)
	}
	batch := m.Predict([]string{"issuer=netbanking:SBI", "delay=6h", "issuer_delay=netbanking:SBI|6h"})
	ordinary := m.Predict([]string{"issuer=netbanking:SBI", "delay=1h", "issuer_delay=netbanking:SBI|1h"})
	if batch <= ordinary+0.15 {
		t.Fatalf("the planted segment was not separated: 6h predicts %.3f, 1h predicts %.3f", batch, ordinary)
	}
}

// The test that stops this package from lying. On data with no structure, the
// held-out skill must be near zero. A positive number here would mean the
// cross-fitting is leaking and every doubly-robust estimate downstream is
// contaminated.
func TestNoiseYieldsNoHeldOutSkill(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(6))
	examples := make([]Example, 8_000)
	for i := range examples {
		examples[i] = Example{
			Features: []string{
				fmt.Sprintf("noise_a=%d", rng.Intn(50)),
				fmt.Sprintf("noise_b=%d", rng.Intn(50)),
			},
			Label: rng.Float64() < 0.3,
		}
	}
	_, rep, err := CrossFit(examples, Options{Seed: 8})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skill > 0.02 {
		t.Fatalf("held-out skill %.4f on pure noise: the folds are leaking", rep.Skill)
	}

	// And the contrast that proves the test is capable of firing: fitting and
	// scoring on the same data does find phantom structure.
	_, inSample, err := Fit(examples, Options{Seed: 8})
	if err != nil {
		t.Fatal(err)
	}
	if inSample.Skill <= rep.Skill {
		t.Fatalf("in-sample skill %.4f did not exceed held-out skill %.4f, so this test proves nothing",
			inSample.Skill, rep.Skill)
	}
}

// A cross-fitted prediction must come from a model that never saw the example.
func TestPredictForRoutesAwayFromTheOwningFold(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(9))
	examples := drawExamples(rng, 2_000)
	cf, _, err := CrossFit(examples, Options{Seed: 11, Folds: 4})
	if err != nil {
		t.Fatal(err)
	}
	if cf.Folds() != 4 {
		t.Fatalf("Folds = %d, want 4", cf.Folds())
	}
	// Every fold must own a share of the data, or cross-fitting is a fiction.
	counts := make([]int, 4)
	for _, f := range cf.fold {
		counts[f]++
	}
	for f, c := range counts {
		if c < len(examples)/8 {
			t.Fatalf("fold %d holds only %d of %d examples", f, c, len(examples))
		}
	}
	if _, err := cf.PredictFor(-1, nil); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("got %v, want ErrOutOfRange", err)
	}
	if _, err := cf.PredictFor(len(examples), nil); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("got %v, want ErrOutOfRange", err)
	}
	// A counterfactual action for an existing incident is still routed by the
	// incident, which is the property the doubly-robust estimator relies on.
	p, err := cf.PredictFor(0, []string{"issuer=card:ICICI", "delay=24h"})
	if err != nil {
		t.Fatal(err)
	}
	if p < 0 || p > 1 {
		t.Fatalf("prediction %v is not a probability", p)
	}
}

// A model that cannot be reproduced cannot be committed to an audit record.
func TestTrainingIsReproducible(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(12))
	examples := drawExamples(rng, 3_000)

	a, repA, err := Fit(examples, Options{Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	b, repB, err := Fit(examples, Options{Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	if repA != repB {
		t.Fatalf("reports differ: %+v vs %+v", repA, repB)
	}
	for i := range a.weights {
		if a.weights[i] != b.weights[i] {
			t.Fatalf("weight %d differs between identical runs", i)
		}
	}
	c, _, err := Fit(examples, Options{Seed: 100})
	if err != nil {
		t.Fatal(err)
	}
	if a.bias == c.bias && a.weights[0] == c.weights[0] {
		t.Fatal("changing the seed left the model unchanged, so the seed is not reaching training")
	}
}

func TestAUCHasTheRightEndpoints(t *testing.T) {
	t.Parallel()
	labels := []Example{{Label: true}, {Label: false}, {Label: true}, {Label: false}}

	if got := auc(labels, []float64{0.5, 0.5, 0.5, 0.5}); math.Abs(got-0.5) > 1e-12 {
		t.Fatalf("a constant predictor scored %v, want exactly 0.5", got)
	}
	if got := auc(labels, []float64{0.9, 0.1, 0.8, 0.2}); math.Abs(got-1) > 1e-12 {
		t.Fatalf("a perfect ranking scored %v, want 1", got)
	}
	if got := auc(labels, []float64{0.1, 0.9, 0.2, 0.8}); math.Abs(got) > 1e-12 {
		t.Fatalf("an inverted ranking scored %v, want 0", got)
	}
	if got := auc([]Example{{Label: true}}, []float64{0.7}); got != 0.5 {
		t.Fatalf("a single-class set scored %v, want the uninformative 0.5", got)
	}
}

func TestScoreHandlesAConstantPredictor(t *testing.T) {
	t.Parallel()
	examples := []Example{{Label: true}, {Label: false}, {Label: true}, {Label: true}}
	base := 0.75
	preds := []float64{base, base, base, base}
	rep := score(examples, preds, 1)
	if math.Abs(rep.BaseRate-base) > 1e-12 {
		t.Fatalf("base rate = %v, want %v", rep.BaseRate, base)
	}
	if math.Abs(rep.Skill) > 1e-9 {
		t.Fatalf("predicting the base rate should have exactly zero skill, got %v", rep.Skill)
	}
	if math.Abs(rep.LogLoss-rep.BaselineLogLoss) > 1e-12 {
		t.Fatal("predicting the base rate should match the baseline log loss")
	}
}

func TestWeightsAreRankedAndReadable(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(14))
	m, _, err := Fit(drawExamples(rng, 20_000), Options{Seed: 15, Epochs: 20})
	if err != nil {
		t.Fatal(err)
	}
	vocab := []string{
		"issuer=upi:okhdfcbank", "issuer=netbanking:SBI", "issuer=card:ICICI",
		"delay=5m", "delay=1h", "delay=6h", "delay=24h",
		"issuer_delay=netbanking:SBI|6h", "issuer_delay=netbanking:SBI|6h",
	}
	w := m.Weights(vocab, 4)
	if len(w) != 4 {
		t.Fatalf("asked for the top 4, got %d", len(w))
	}
	for i := 1; i < len(w); i++ {
		if math.Abs(w[i-1].Value) < math.Abs(w[i].Value) {
			t.Fatalf("weights are not ordered by magnitude: %+v", w)
		}
	}
	// The immediate retry is the strongest negative signal in the generator, so
	// it has to show up somewhere near the top.
	var sawImmediate bool
	for _, x := range m.Weights(vocab, 0) {
		if x.Token == "delay=5m" && x.Value < 0 {
			sawImmediate = true
		}
	}
	if !sawImmediate {
		t.Fatalf("the model did not learn that an immediate retry hurts: %+v", m.Weights(vocab, 0))
	}
}

// Feature vectors arrive from a caller that assembles them from webhook data,
// so oversized, empty and duplicated tokens must all be survivable.
func TestFeatureHandlingIsBounded(t *testing.T) {
	t.Parallel()
	long := make([]byte, MaxTokenLen+10)
	for i := range long {
		long[i] = 'x'
	}
	many := make([]string, MaxFeaturesPerExample*3)
	for i := range many {
		many[i] = fmt.Sprintf("f=%d", i)
	}
	examples := []Example{
		{Features: append([]string{"a", "a", "", string(long)}, many...), Label: true},
		{Features: []string{"b"}, Label: false},
	}
	m, _, err := Fit(examples, Options{Seed: 1, Epochs: 2})
	if err != nil {
		t.Fatal(err)
	}
	p := m.Predict(append([]string{"", string(long)}, many...))
	if math.IsNaN(p) || p < 0 || p > 1 {
		t.Fatalf("prediction %v is not a probability", p)
	}
	if p := m.Predict(nil); math.IsNaN(p) {
		t.Fatal("an empty feature vector produced NaN")
	}
}

func TestLogitClamping(t *testing.T) {
	t.Parallel()
	if got := clampLogit(math.NaN()); got != 0 {
		t.Fatalf("NaN score became %v, want 0", got)
	}
	if got := clampLogit(1e300); got != 30 {
		t.Fatalf("clampLogit(1e300) = %v, want 30", got)
	}
	if got := clampLogit(-1e300); got != -30 {
		t.Fatalf("clampLogit(-1e300) = %v, want -30", got)
	}
	if p := sigmoid(clampLogit(1e300)); p >= 1 {
		t.Fatalf("sigmoid saturated to %v, which makes the log loss infinite", p)
	}
}

func TestBiasTracksTheBaseRate(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(16))
	examples := make([]Example, 20_000)
	for i := range examples {
		examples[i] = Example{Features: []string{"constant"}, Label: rng.Float64() < 0.3}
	}
	m, _, err := Fit(examples, Options{Seed: 17, Epochs: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Predict([]string{"constant"}); math.Abs(got-0.3) > 0.03 {
		t.Fatalf("with one feature and a base rate of 0.3 the model predicts %v", got)
	}
	if math.IsNaN(m.Bias()) {
		t.Fatal("bias is NaN")
	}
}

// Package calib measures whether a stated confidence means anything, and fixes
// it when it does not.
//
// The gatekeeper refuses any proposal below a confidence threshold. That
// threshold was a number someone chose. It is the sort of number that gets
// chosen once, written into a constant, quoted in a design document, and never
// checked against an outcome again, and for most of this system that would be
// unacceptable: every other rule here is either derived or exhaustively
// verified. This package closes that gap.
//
// # Calibration
//
// A model is calibrated when the things it calls 80% likely happen 80% of the
// time. Nothing about training a classifier produces this. Models trained to
// minimise log loss on imbalanced data are systematically overconfident, and
// language models asked to state a confidence are worse still, because the
// number is generated text rather than a posterior. An uncalibrated 0.8 is not
// a probability, it is a mood, and thresholding on it means the refusal rate is
// whatever the model happens to feel that day.
//
// Measure quantifies this: it bins predictions by stated confidence and
// compares each bin against the accuracy actually observed there. The headline
// figure is expected calibration error, the average gap weighted by how much
// traffic falls in each bin.
//
// # Repair
//
// Isotonic regression fixes what the measurement finds. It fits the
// least-squares monotone step function from stated confidence to observed
// frequency, which is the strongest correction available that cannot reorder
// the model judgements: if the model said A is more likely than B, the
// calibrated version still says so. It only changes what the numbers mean, not
// what they rank.
//
// # Honesty
//
// Fitting a calibrator and then reporting the improvement on the same data
// measures the calibrator ability to memorise, not to generalise. Every
// before-and-after figure this package publishes comes from cross-fitting: the
// correction applied to each observation was fitted without it. The in-sample
// number is available too, and the gap between them is itself informative.
//
// # The threshold
//
// ThresholdFor answers the question the constant was guessing at: what stated
// confidence actually buys a given accuracy, and how much traffic is left after
// demanding it. That turns a tuning parameter into a measurement with a
// coverage cost attached.
package calib

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// Defaults and bounds.
const (
	// DefaultBins is the reliability-diagram resolution. Ten is the convention
	// in the calibration literature and it keeps each bin populated enough for
	// its accuracy to mean something at corpus sizes in the low thousands.
	DefaultBins = 10

	// DefaultFolds is the cross-fitting partition for honest before-and-after
	// numbers.
	DefaultFolds = 5

	// MinBinCount is the smallest bin population whose accuracy is reported
	// without a warning. Below it, one observation moves the bin by more than
	// the error being measured.
	MinBinCount = 20

	// DefaultNoiseFloorRounds is the parametric bootstrap budget behind
	// NoiseFloor. Two hundred redraws settle the mean well inside a thousandth
	// of a confidence point, which is finer than any decision made on it.
	DefaultNoiseFloorRounds = 200

	MaxObservations     = 5_000_000
	maxBins             = 200
	maxFolds            = 32
	maxNoiseFloorRounds = 20_000
)

var (
	// ErrNoObservations means there was nothing to measure.
	ErrNoObservations = errors.New("calib: no observations")

	// ErrInvalidObservation means a confidence was outside [0,1] or not finite.
	ErrInvalidObservation = errors.New("calib: invalid observation")

	// ErrInvalidOptions covers malformed parameters.
	ErrInvalidOptions = errors.New("calib: invalid options")

	// ErrUnreachableTarget means no confidence threshold achieves the requested
	// accuracy, which is a real answer and not a failure: it means the model
	// cannot be made that reliable by thresholding alone.
	ErrUnreachableTarget = errors.New("calib: no threshold reaches the requested accuracy")
)

// Observation is one prediction and what happened.
type Observation struct {
	// Confidence is what the model claimed, in [0,1].
	Confidence float64 `json:"confidence"`

	// Correct is whether the prediction turned out to be right. For this
	// system that means the failure class the inference tier assigned matched
	// the class the outcome revealed.
	Correct bool `json:"correct"`
}

func (o Observation) validate() error {
	if math.IsNaN(o.Confidence) || math.IsInf(o.Confidence, 0) {
		return fmt.Errorf("%w: confidence is not a finite number", ErrInvalidObservation)
	}
	if o.Confidence < 0 || o.Confidence > 1 {
		return fmt.Errorf("%w: confidence %g is outside [0,1]", ErrInvalidObservation, o.Confidence)
	}
	return nil
}

// Bin is one bucket of a reliability diagram.
type Bin struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
	Count int     `json:"count"`

	// MeanConfidence is what the model claimed inside this bin.
	MeanConfidence float64 `json:"mean_confidence"`

	// Accuracy is what actually happened inside this bin.
	Accuracy float64 `json:"accuracy"`

	// Gap is MeanConfidence minus Accuracy. Positive is overconfidence, which
	// is the direction that matters here: an overconfident model gets past a
	// threshold it has not earned.
	Gap float64 `json:"gap"`

	// Thin marks a bin with too few observations for its accuracy to be read
	// as anything but noise.
	Thin bool `json:"thin,omitempty"`
}

// Report is a calibration measurement.
type Report struct {
	Observations int   `json:"observations"`
	Bins         []Bin `json:"bins"`

	// ECE is the expected calibration error: the traffic-weighted mean of the
	// absolute gaps. It is the single number to quote, and it is in the same
	// units as the confidence, so an ECE of 0.11 means the stated confidence is
	// off by eleven points on average.
	ECE float64 `json:"ece"`

	// MCE is the largest gap in any populated bin. ECE can look acceptable
	// while one heavily-used bin is badly wrong, and MCE is what catches that.
	MCE float64 `json:"mce"`

	// Brier is the mean squared error of the stated confidences.
	Brier float64 `json:"brier"`

	// The Murphy decomposition of Brier: reliability is the calibration term
	// and is the part this package can remove, resolution is the part that
	// comes from the model actually discriminating, and uncertainty is the
	// irreducible variance of the outcome. Reliability minus resolution plus
	// uncertainty equals Brier, which is asserted in the tests.
	Reliability float64 `json:"reliability"`
	Resolution  float64 `json:"resolution"`
	Uncertainty float64 `json:"uncertainty"`

	MeanConfidence float64 `json:"mean_confidence"`
	Accuracy       float64 `json:"accuracy"`

	// Overconfident reports the direction of the average error.
	Overconfident bool `json:"overconfident"`

	// Warnings name conditions that make the figures above less trustworthy.
	Warnings []string `json:"warnings,omitempty"`
}

// Options tunes a measurement.
type Options struct {
	// Bins is the reliability-diagram resolution. Zero means DefaultBins.
	Bins int

	// Folds is the cross-fitting partition used by Repair. Zero means
	// DefaultFolds.
	Folds int

	// Seed fixes the fold assignment.
	Seed int64
}

func (o Options) normalise() (Options, error) {
	if o.Bins == 0 {
		o.Bins = DefaultBins
	}
	if o.Folds == 0 {
		o.Folds = DefaultFolds
	}
	switch {
	case o.Bins < 2 || o.Bins > maxBins:
		return o, fmt.Errorf("%w: bins %d outside [2, %d]", ErrInvalidOptions, o.Bins, maxBins)
	case o.Folds < 2 || o.Folds > maxFolds:
		return o, fmt.Errorf("%w: folds %d outside [2, %d]", ErrInvalidOptions, o.Folds, maxFolds)
	}
	return o, nil
}

// Measure builds a reliability diagram and its summary statistics.
func Measure(obs []Observation, opts Options) (Report, error) {
	opts, err := opts.normalise()
	if err != nil {
		return Report{}, err
	}
	if err := check(obs); err != nil {
		return Report{}, err
	}
	return measure(obs, opts.Bins), nil
}

func measure(obs []Observation, bins int) Report {
	rep := Report{Observations: len(obs), Bins: make([]Bin, bins)}

	width := 1 / float64(bins)
	sums := make([]float64, bins)
	hits := make([]float64, bins)
	counts := make([]int, bins)

	var totalConf, totalHits, brier float64
	for _, o := range obs {
		// The last bin is closed at 1 so a confidence of exactly 1 lands
		// somewhere rather than falling off the end.
		b := int(o.Confidence / width)
		if b >= bins {
			b = bins - 1
		}
		counts[b]++
		sums[b] += o.Confidence
		totalConf += o.Confidence
		d := o.Confidence
		if o.Correct {
			hits[b]++
			totalHits++
			d = 1 - o.Confidence
		}
		brier += d * d
	}

	n := float64(len(obs))
	rep.MeanConfidence = totalConf / n
	rep.Accuracy = totalHits / n
	rep.Brier = brier / n
	rep.Overconfident = rep.MeanConfidence > rep.Accuracy
	rep.Uncertainty = rep.Accuracy * (1 - rep.Accuracy)

	var thin int
	for b := 0; b < bins; b++ {
		bin := Bin{Lower: float64(b) * width, Upper: float64(b+1) * width, Count: counts[b]}
		if counts[b] > 0 {
			c := float64(counts[b])
			bin.MeanConfidence = sums[b] / c
			bin.Accuracy = hits[b] / c
			bin.Gap = bin.MeanConfidence - bin.Accuracy
			bin.Thin = counts[b] < MinBinCount

			weight := c / n
			rep.ECE += weight * math.Abs(bin.Gap)
			rep.MCE = math.Max(rep.MCE, math.Abs(bin.Gap))
			// Murphy: reliability penalises the gap between claim and outcome
			// inside a bin, resolution rewards a bin whose outcome differs from
			// the overall base rate.
			rep.Reliability += weight * bin.Gap * bin.Gap
			rep.Resolution += weight * (bin.Accuracy - rep.Accuracy) * (bin.Accuracy - rep.Accuracy)
			if bin.Thin {
				thin++
			}
		}
		rep.Bins[b] = bin
	}

	if thin > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"%d of %d populated bins hold fewer than %d observations, so their accuracy is mostly noise",
			thin, populated(rep.Bins), MinBinCount))
	}
	if len(obs) < bins*MinBinCount {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"%d observations across %d bins is thin for a calibration estimate; expected calibration error is biased upwards at this size",
			len(obs), bins))
	}
	return rep
}

func populated(bins []Bin) int {
	var n int
	for _, b := range bins {
		if b.Count > 0 {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Isotonic regression
// ---------------------------------------------------------------------------

// Calibrator maps a stated confidence onto a corrected one.
type Calibrator struct {
	// Each block is a maximal run of the sorted input over which the fitted
	// value is constant. upper[i] is the largest confidence in block i.
	upper []float64
	value []float64
}

// Fit runs pool-adjacent-violators to obtain the isotonic regression of
// correctness on stated confidence.
//
// The algorithm is the whole of the method: walk the distinct confidences in
// order, then repeatedly merge any adjacent pair whose fitted values run
// downhill, taking the weighted mean. What is left is the monotone step
// function closest to the data in squared error, and it is exact rather than
// iterative, so there is no convergence criterion to get wrong.
//
// Observations sharing a confidence are pooled into a single weighted point
// before the walk begins. Skipping that step is a real and subtle bug rather
// than an optimisation: a run of equal confidences whose outcomes happen to
// arrive as failures then successes is already non-decreasing, so the merge
// loop never touches it, and the run survives as several blocks with identical
// upper bounds. A later lookup then lands on whichever of them comes first and
// reads back the failures alone. It cost an afternoon here, and it presented as
// a calibrator that was confidently wrong by exactly one bin. Pooling makes the
// fitted value a function of the confidence, which is what a calibration map is
// supposed to be.
func Fit(obs []Observation) (*Calibrator, error) {
	if err := check(obs); err != nil {
		return nil, err
	}

	type point struct {
		x      float64
		sum    float64 // number correct at this confidence
		weight float64 // observations at this confidence
	}
	byConfidence := make(map[float64]*point, len(obs))
	for _, o := range obs {
		p, ok := byConfidence[o.Confidence]
		if !ok {
			p = &point{x: o.Confidence}
			byConfidence[o.Confidence] = p
		}
		p.weight++
		if o.Correct {
			p.sum++
		}
	}
	points := make([]point, 0, len(byConfidence))
	for _, p := range byConfidence {
		points = append(points, *p)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].x < points[j].x })

	blocks := make([]point, 0, len(points))
	for _, p := range points {
		blocks = append(blocks, p)
		// Merge downhill neighbours until the sequence is non-decreasing again.
		for len(blocks) > 1 {
			last := blocks[len(blocks)-1]
			prev := blocks[len(blocks)-2]
			if prev.sum/prev.weight <= last.sum/last.weight {
				break
			}
			merged := point{x: last.x, sum: prev.sum + last.sum, weight: prev.weight + last.weight}
			blocks = blocks[:len(blocks)-2]
			blocks = append(blocks, merged)
		}
	}

	c := &Calibrator{upper: make([]float64, len(blocks)), value: make([]float64, len(blocks))}
	for i, b := range blocks {
		c.upper[i] = b.x
		c.value[i] = b.sum / b.weight
	}
	return c, nil
}

// Apply corrects one stated confidence.
//
// The result is piecewise constant rather than interpolated. Interpolation
// would produce smoother pictures and would also invent calibrated values at
// confidences no observation ever occupied, which is exactly the sort of
// invented number this package exists to remove.
func (c *Calibrator) Apply(confidence float64) float64 {
	if len(c.value) == 0 || math.IsNaN(confidence) {
		return confidence
	}
	i := sort.SearchFloat64s(c.upper, confidence)
	if i >= len(c.value) {
		i = len(c.value) - 1
	}
	return c.value[i]
}

// Steps returns the fitted step function, for plotting or for an audit record.
func (c *Calibrator) Steps() []Step {
	out := make([]Step, len(c.value))
	for i := range c.value {
		out[i] = Step{UpTo: c.upper[i], Calibrated: c.value[i]}
	}
	return out
}

// Step is one constant piece of a fitted calibrator.
type Step struct {
	UpTo       float64 `json:"up_to"`
	Calibrated float64 `json:"calibrated"`
}

// ---------------------------------------------------------------------------
// Repair
// ---------------------------------------------------------------------------

// Repair is a before-and-after calibration result.
type Repair struct {
	Before Report `json:"before"`

	// After is measured on cross-fitted corrections, so every observation was
	// corrected by a calibrator that had not seen it.
	After Report `json:"after"`

	// InSample is the same measurement with the calibrator fitted on
	// everything, including the observation it is correcting. It is reported
	// only so the gap against After is visible: a large gap means the
	// calibrator is memorising rather than generalising.
	InSample Report `json:"in_sample"`

	// Improvement is the share of the original expected calibration error the
	// honest correction removed. Negative means the correction made things
	// worse, which happens when there was little to fix and the folds are
	// small.
	//
	// Read it next to Reduction and NoiseFloor, never alone. A ratio computed
	// against a baseline that was already at the noise floor is close to
	// meaningless, and it will happily report ninety-eight percent for a change
	// of four thousandths.
	Improvement float64 `json:"improvement"`

	// Reduction is the absolute fall in expected calibration error, in the same
	// units as the confidence itself.
	Reduction float64 `json:"reduction"`

	// NoiseFloor is the expected calibration error a perfectly calibrated model
	// of this corpus size would still show. See NoiseFloor.
	NoiseFloor float64 `json:"noise_floor"`

	// Significant reports whether the measured error before correction stood
	// clear of that floor. When it is false, there was no miscalibration to fix
	// and any improvement is arithmetic on noise.
	Significant bool `json:"significant"`

	Folds int `json:"folds"`

	// Calibrator fitted on all observations, which is the one to deploy.
	Calibrator *Calibrator `json:"-"`
}

// FitAndMeasure fits a calibrator and reports what it is honestly worth.
func FitAndMeasure(obs []Observation, opts Options) (Repair, error) {
	opts, err := opts.normalise()
	if err != nil {
		return Repair{}, err
	}
	if err := check(obs); err != nil {
		return Repair{}, err
	}
	if len(obs) < opts.Folds*2 {
		return Repair{}, fmt.Errorf("%w: %d observations cannot support %d folds", ErrInvalidOptions, len(obs), opts.Folds)
	}

	rep := Repair{Before: measure(obs, opts.Bins), Folds: opts.Folds}

	full, err := Fit(obs)
	if err != nil {
		return Repair{}, err
	}
	rep.Calibrator = full

	inSample := make([]Observation, len(obs))
	for i, o := range obs {
		inSample[i] = Observation{Confidence: full.Apply(o.Confidence), Correct: o.Correct}
	}
	rep.InSample = measure(inSample, opts.Bins)

	assign := folds(len(obs), opts)
	corrected := make([]Observation, len(obs))
	for f := 0; f < opts.Folds; f++ {
		var train []Observation
		for i, fold := range assign {
			if fold != f {
				train = append(train, obs[i])
			}
		}
		if len(train) == 0 {
			return Repair{}, fmt.Errorf("%w: fold %d left no training data", ErrInvalidOptions, f)
		}
		c, err := Fit(train)
		if err != nil {
			return Repair{}, err
		}
		for i, fold := range assign {
			if fold == f {
				corrected[i] = Observation{Confidence: c.Apply(obs[i].Confidence), Correct: obs[i].Correct}
			}
		}
	}
	rep.After = measure(corrected, opts.Bins)
	rep.Reduction = rep.Before.ECE - rep.After.ECE
	if rep.Before.ECE > 0 {
		rep.Improvement = rep.Reduction / rep.Before.ECE
	}

	floor, err := NoiseFloor(obs, opts, 0)
	if err != nil {
		return Repair{}, err
	}
	rep.NoiseFloor = floor
	rep.Significant = rep.Before.ECE > 2*floor
	return rep, nil
}

// NoiseFloor estimates the expected calibration error a perfectly calibrated
// model of this size would still show.
//
// Expected calibration error is a biased statistic: it is an average of
// absolute values, so sampling noise inside each bin can only push it up, never
// down. On a small corpus a flawless model still scores several points of
// error, and quoting that number as a defect is a mistake almost everyone
// makes.
//
// The floor is measured rather than approximated in closed form. Each round
// keeps the stated confidences and redraws every outcome from them, which is
// exactly the perfectly-calibrated null hypothesis, and then measures the result
// the same way Measure would. The mean over rounds is what a model that was
// right by construction would have scored on data this size and this shaped.
func NoiseFloor(obs []Observation, opts Options, rounds int) (float64, error) {
	opts, err := opts.normalise()
	if err != nil {
		return 0, err
	}
	if err := check(obs); err != nil {
		return 0, err
	}
	if rounds == 0 {
		rounds = DefaultNoiseFloorRounds
	}
	if rounds < 1 || rounds > maxNoiseFloorRounds {
		return 0, fmt.Errorf("%w: noise floor rounds %d outside [1, %d]", ErrInvalidOptions, rounds, maxNoiseFloorRounds)
	}

	rng := rand.New(rand.NewSource(opts.Seed ^ 0x9e3779b9))
	null := make([]Observation, len(obs))
	var total float64
	for r := 0; r < rounds; r++ {
		for i, o := range obs {
			null[i] = Observation{Confidence: o.Confidence, Correct: rng.Float64() < o.Confidence}
		}
		total += measure(null, opts.Bins).ECE
	}
	return total / float64(rounds), nil
}

func folds(n int, opts Options) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	rng := rand.New(rand.NewSource(opts.Seed ^ 0x2545f491))
	rng.Shuffle(n, func(i, j int) { order[i], order[j] = order[j], order[i] })
	assign := make([]int, n)
	for pos, i := range order {
		assign[i] = pos % opts.Folds
	}
	return assign
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

// Threshold is a confidence cut-off and what it costs.
type Threshold struct {
	// Confidence is the smallest stated confidence that meets the target.
	Confidence float64 `json:"confidence"`

	// Accuracy is the share of accepted predictions that were correct.
	Accuracy float64 `json:"accuracy"`

	// Coverage is the share of all predictions this threshold accepts. It is
	// the price of the accuracy, and quoting one without the other is how a
	// system ends up refusing almost everything and calling it precision.
	Coverage float64 `json:"coverage"`

	// Accepted and Correct are the raw counts behind the two rates.
	Accepted int `json:"accepted"`
	Correct  int `json:"correct"`
}

// ThresholdFor finds the lowest confidence at which accepted predictions reach
// the target accuracy.
//
// This is the measurement that replaces a chosen constant. It sweeps every
// distinct confidence in the corpus rather than a grid, so the answer is a
// value the model actually produces, and it returns the coverage alongside so
// the trade is explicit.
func ThresholdFor(obs []Observation, target float64) (Threshold, error) {
	if err := check(obs); err != nil {
		return Threshold{}, err
	}
	if target <= 0 || target > 1 || math.IsNaN(target) {
		return Threshold{}, fmt.Errorf("%w: target accuracy %g outside (0,1]", ErrInvalidOptions, target)
	}

	sorted := append([]Observation(nil), obs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Confidence > sorted[j].Confidence })

	total := len(sorted)
	best := Threshold{}
	found := false
	var accepted, correct int
	for i, o := range sorted {
		accepted++
		if o.Correct {
			correct++
		}
		// Only evaluate at the end of a run of equal confidences: a threshold
		// cannot separate two predictions that stated the same number.
		if i+1 < total && sorted[i+1].Confidence == o.Confidence {
			continue
		}
		if float64(correct)/float64(accepted) >= target {
			best = Threshold{
				Confidence: o.Confidence,
				Accuracy:   float64(correct) / float64(accepted),
				Coverage:   float64(accepted) / float64(total),
				Accepted:   accepted,
				Correct:    correct,
			}
			found = true
		}
	}
	if !found {
		return Threshold{}, fmt.Errorf("%w: %.2f accuracy is not reached at any confidence in this corpus", ErrUnreachableTarget, target)
	}
	return best, nil
}

// AccuracyAt reports what a given threshold actually delivers, which is the
// question to ask of a threshold that is already deployed.
func AccuracyAt(obs []Observation, threshold float64) (Threshold, error) {
	if err := check(obs); err != nil {
		return Threshold{}, err
	}
	if math.IsNaN(threshold) {
		return Threshold{}, fmt.Errorf("%w: threshold is not a number", ErrInvalidOptions)
	}
	out := Threshold{Confidence: threshold}
	for _, o := range obs {
		if o.Confidence >= threshold {
			out.Accepted++
			if o.Correct {
				out.Correct++
			}
		}
	}
	if out.Accepted > 0 {
		out.Accuracy = float64(out.Correct) / float64(out.Accepted)
	}
	out.Coverage = float64(out.Accepted) / float64(len(obs))
	return out, nil
}

func check(obs []Observation) error {
	if len(obs) == 0 {
		return ErrNoObservations
	}
	if len(obs) > MaxObservations {
		return fmt.Errorf("calib: %d observations exceeds the %d limit", len(obs), MaxObservations)
	}
	for i, o := range obs {
		if err := o.validate(); err != nil {
			return fmt.Errorf("calib: observation %d: %w", i, err)
		}
	}
	return nil
}

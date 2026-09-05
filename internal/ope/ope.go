// Package ope answers a question no experiment can answer after the fact: what
// would a different recovery policy have earned on traffic that has already
// happened?
//
// A payment fails once. The system takes one action, observes one outcome, and
// the outcomes of the actions it did not take are gone forever. That is why
// every recovery vendor's headline number is unfalsifiable: "we recovered 34%"
// measures the traffic mix as much as the policy, and there is no held-out arm
// to compare it against. Running a live experiment is the usual answer, and it
// costs real money on real customers to learn that the new policy was worse.
//
// Off-policy evaluation is the alternative. If, at the moment of each decision,
// the system recorded the probability it assigned to the action it chose, the
// propensity, then the log is not merely a history. It is a weighted sample
// from which the value of a different policy can be estimated without bias.
//
// Three estimators are computed here, in increasing order of how much they
// assume:
//
//	IPS    reweights each logged reward by pi_e/pi_0. Unbiased, high variance.
//	SNIPS  divides by the sum of weights instead of n. Slightly biased,
//	       dramatically lower variance, and bounded by the observed reward
//	       range, which IPS is not.
//	DR     subtracts a learned reward model prediction and adds it back under
//	       the target policy. Unbiased if either the propensities or the model
//	       are right, hence "doubly robust".
//
// This package is deliberately numeric and dependency-free. It never sees an
// incident, an issuer, or an action name. The caller reduces each logged
// decision to five numbers, which keeps the statistics testable against closed
// forms and keeps the estimator honest about what it does not know.
//
// # Floating point
//
// The rest of this system bans float64 from money paths, because paisa are
// exact and float addition is not associative. That ban does not apply here and
// the distinction matters. An estimator does not compute an amount, it computes
// a statistic about a hypothetical, and it is reported with a confidence
// interval wider than any rounding difference by several orders of magnitude.
// Rewards enter as exact int64 paisa and are converted once. What leaves is an
// interval, never a figure anyone is charged.
//
// # The assumption that can invalidate everything
//
// All three estimators require overlap: the logging policy must have had a real
// chance of taking every action the target policy would take. Where it did not,
// the target policy value is not identified by this data at all, and no amount
// of arithmetic recovers it. Most implementations quietly divide by a small
// number and emit a confident, meaningless figure. This one refuses. See
// Sample.Unsupported and ErrNoOverlap.
package ope

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// Defaults for Options.
const (
	// DefaultBootstrapRounds is the resample count behind every interval. Two
	// thousand puts the Monte-Carlo error on a 95% percentile bound well below
	// the sampling error it is measuring, which is the only reason to spend
	// more than a few hundred.
	DefaultBootstrapRounds = 2000

	// DefaultConfidence is the two-sided coverage of the reported interval.
	DefaultConfidence = 0.95

	// DefaultPropensityFloor is the smallest logging probability treated as a
	// real chance. Below it the importance weight exceeds a thousand and one
	// incident would dominate the estimate, which is indistinguishable from
	// having no data about that region of the context space.
	DefaultPropensityFloor = 1e-3

	// MaxSamples bounds an evaluation so a corrupt or hostile log cannot turn
	// a bootstrap into an unbounded allocation.
	MaxSamples = 5_000_000

	// MaxBootstrapRounds bounds the same allocation from the other direction.
	MaxBootstrapRounds = 100_000
)

// Errors that stop an evaluation rather than degrading it. Each one means the
// requested estimate is not identified by the data supplied, which is a
// different and more serious condition than a wide interval.
var (
	// ErrNoSamples means the log was empty. There is nothing to estimate.
	ErrNoSamples = errors.New("ope: no samples")

	// ErrNoOverlap means the target policy puts probability on actions the
	// logging policy could not have taken. The estimand does not exist in this
	// data. Reporting a number here is the single most common way an
	// off-policy result is wrong, so it is a hard failure.
	ErrNoOverlap = errors.New("ope: target policy is not supported by the logging policy")

	// ErrInvalidSample means a probability was outside [0,1], was NaN, or a
	// logged propensity was zero for an action that was actually taken, which
	// cannot happen in a correctly instrumented logger and usually means the
	// propensity was reconstructed after the fact rather than recorded.
	ErrInvalidSample = errors.New("ope: invalid sample")
)

// Sample is one logged decision, reduced to the only quantities an estimator
// needs. The caller owns the mapping from an incident to these numbers.
type Sample struct {
	// Logged is pi_0(a | x): the probability the deployed policy assigned to
	// the action it actually took, recorded at decision time. It must be
	// strictly positive, because the action was taken.
	//
	// Recording this before the outcome is known is the entire foundation. A
	// propensity reconstructed afterwards can be tuned until the answer is
	// flattering, which is why this system commits it to a hash-chained ledger
	// at the moment of the decision. See internal/audit.
	Logged float64 `json:"logged"`

	// Target is pi_e(a | x): the probability the policy under evaluation would
	// have assigned to that same action. Zero is legal and simply means the
	// target policy would not have done this, so the sample contributes
	// nothing to IPS.
	Target float64 `json:"target"`

	// RewardPaisa is the realised net value of the logged action: recovered
	// amount less the costs the attempt incurred. Negative is legal and
	// meaningful, since a retry that fails still costs a gateway fee.
	RewardPaisa int64 `json:"reward_paisa"`

	// Baseline is rhat(x, a): a reward model prediction for the action that
	// was actually taken. Used only by the doubly-robust estimator.
	Baseline float64 `json:"baseline"`

	// TargetMean is E_{a ~ pi_e(.|x)}[rhat(x, a)]: the reward model expected
	// value under the target policy in this context, over the whole action set
	// rather than the one action observed. Used only by DR.
	TargetMean float64 `json:"target_mean"`

	// LoggedMean is the same expectation under the logging policy,
	// E_{a ~ pi_0(.|x)}[rhat(x, a)]. It is used only by the doubly-robust lift,
	// where it is what makes the estimator see nothing at all outside the
	// region the candidate policy changes.
	LoggedMean float64 `json:"logged_mean"`

	// Unsupported is the target policy total probability mass, in this
	// context, on actions the logging policy assigns zero probability.
	//
	// This field exists because the other half of the overlap assumption is
	// invisible from the log. A sample only reveals the action that was taken;
	// it says nothing about an action the target policy loves and the logger
	// would never have tried. Only the caller holds both policies and can see
	// that gap, so the caller is required to report it. Leaving this at zero
	// when it is not zero produces a confident number about a quantity the
	// data does not contain.
	Unsupported float64 `json:"unsupported"`
}

func (s Sample) validate() error {
	switch {
	case math.IsNaN(s.Logged) || math.IsInf(s.Logged, 0):
		return fmt.Errorf("%w: logged propensity is not a finite number", ErrInvalidSample)
	case math.IsNaN(s.Target) || math.IsInf(s.Target, 0):
		return fmt.Errorf("%w: target probability is not a finite number", ErrInvalidSample)
	case s.Logged <= 0:
		return fmt.Errorf("%w: logged propensity %g is not positive, but the action was taken", ErrInvalidSample, s.Logged)
	case s.Logged > 1:
		return fmt.Errorf("%w: logged propensity %g exceeds 1", ErrInvalidSample, s.Logged)
	case s.Target < 0 || s.Target > 1:
		return fmt.Errorf("%w: target probability %g is outside [0,1]", ErrInvalidSample, s.Target)
	case s.Unsupported < 0 || s.Unsupported > 1:
		return fmt.Errorf("%w: unsupported mass %g is outside [0,1]", ErrInvalidSample, s.Unsupported)
	case math.IsNaN(s.Baseline) || math.IsInf(s.Baseline, 0):
		return fmt.Errorf("%w: baseline prediction is not a finite number", ErrInvalidSample)
	case math.IsNaN(s.TargetMean) || math.IsInf(s.TargetMean, 0):
		return fmt.Errorf("%w: target-mean prediction is not a finite number", ErrInvalidSample)
	case math.IsNaN(s.LoggedMean) || math.IsInf(s.LoggedMean, 0):
		return fmt.Errorf("%w: logged-mean prediction is not a finite number", ErrInvalidSample)
	}
	return nil
}

// Options tunes an evaluation. The zero value is valid and uses the defaults.
type Options struct {
	// Bootstrap is the number of resamples behind each interval.
	Bootstrap int

	// Seed makes the bootstrap reproducible. Two runs with the same samples
	// and the same seed produce byte-identical intervals, which is what allows
	// an interval to be quoted in an audit record.
	Seed int64

	// Confidence is the two-sided coverage, in (0,1).
	Confidence float64

	// PropensityFloor is the smallest logging probability accepted before the
	// sample counts as an overlap violation.
	PropensityFloor float64

	// WeightCap truncates importance weights at this value. Zero disables it.
	//
	// Capping trades a known bias for a large variance reduction and is
	// standard practice, but it is off by default here: a capped estimate that
	// is not labelled as capped is a quiet thumb on the scale. When it is on,
	// Diagnostics.ClippedSamples reports exactly how many rewards were
	// discounted and Report.Warnings says so in words.
	WeightCap float64

	// WithOutcomeModel enables the doubly-robust estimator. It is off by
	// default because DR computed over zero-valued Baseline and TargetMean
	// fields silently degrades to IPS while looking like a third opinion.
	WithOutcomeModel bool

	// IntervalMethod selects how the bootstrap distribution becomes an
	// interval. The zero value is IntervalBCa, which is the one to use. See
	// bootstrap.go for why the plain percentile interval was not good enough.
	IntervalMethod IntervalMethod

	// LiftEstimator selects how EvaluateLift builds the difference. The zero
	// value picks LiftDoublyRobust when WithOutcomeModel is set and LiftIPS
	// otherwise, which is the choice the measurement below supports.
	LiftEstimator LiftEstimator
}

// LiftEstimator selects the construction EvaluateLift uses.
//
// # Which one, and how that was settled
//
// Both were run against a world whose exact answer is known, over independent
// corpora, counting how often a nominal 95% interval actually contained the
// truth. The table is from internal/lab, and the test that produces it is still
// in the suite so these numbers cannot quietly stop being true.
//
//	corpus   IPS coverage  IPS width   DR coverage  DR width   model skill
//	 6,000        70%         2021         85%        2094        0.028
//	20,000        80%         2067         90%        1659        0.058
//	40,000        95%         1441         95%        1132        0.066
//
// The doubly-robust difference covers better at every size and is narrower once
// the reward model has enough data to be worth anything. That is the opposite
// of the conclusion drawn here first, from a single run on a small corpus where
// the model had almost no skill and the residual it subtracted was pure noise.
// The first reading was written up as a finding before it had been measured
// across sizes, which is the mistake, not the estimator.
type LiftEstimator string

const (
	// LiftIPS is the plain difference of importance-weighted rewards: the mean
	// of (w-1)*r. Unbiased, depends on no model, and for a candidate that
	// changes one segment it reads only the decisions in that segment. It is
	// the right choice when no outcome model is available or when one cannot be
	// trusted.
	LiftIPS LiftEstimator = "ips-difference"

	// LiftDoublyRobust subtracts a reward model prediction before weighting:
	// the mean of (rhat under the candidate - rhat under the deployed policy)
	// plus (w-1)(r - rhat).
	//
	// It stays unbiased if either the propensities or the model are right, and
	// on a segment-sized sample it is the difference between an interval that
	// covers and one that does not. It needs a cross-fitted model, or the
	// residual it corrects by has already seen its own outcome and the
	// correction shrinks towards zero. See internal/reward.
	LiftDoublyRobust LiftEstimator = "doubly-robust-difference"
)

func (o Options) normalise() (Options, error) {
	if o.Bootstrap == 0 {
		o.Bootstrap = DefaultBootstrapRounds
	}
	if o.Confidence == 0 {
		o.Confidence = DefaultConfidence
	}
	if o.PropensityFloor == 0 {
		o.PropensityFloor = DefaultPropensityFloor
	}
	switch {
	case o.Bootstrap < 0 || o.Bootstrap > MaxBootstrapRounds:
		return o, fmt.Errorf("ope: bootstrap rounds %d outside [0, %d]", o.Bootstrap, MaxBootstrapRounds)
	case o.Confidence <= 0 || o.Confidence >= 1:
		return o, fmt.Errorf("ope: confidence %g outside (0,1)", o.Confidence)
	case o.PropensityFloor < 0 || o.PropensityFloor >= 1:
		return o, fmt.Errorf("ope: propensity floor %g outside [0,1)", o.PropensityFloor)
	case o.WeightCap < 0:
		return o, fmt.Errorf("ope: weight cap %g is negative", o.WeightCap)
	}
	switch o.IntervalMethod {
	case "":
		o.IntervalMethod = IntervalBCa
	case IntervalBCa, IntervalPercentile:
	default:
		return o, fmt.Errorf("ope: unknown interval method %q", o.IntervalMethod)
	}
	switch o.LiftEstimator {
	case "":
		// Use the model when there is one. A caller that supplied an outcome
		// model and got the estimator that ignores it would be paying for a
		// fit and throwing the result away.
		o.LiftEstimator = LiftIPS
		if o.WithOutcomeModel {
			o.LiftEstimator = LiftDoublyRobust
		}
	case LiftIPS, LiftDoublyRobust:
	default:
		return o, fmt.Errorf("ope: unknown lift estimator %q", o.LiftEstimator)
	}
	return o, nil
}

// Estimate is a point estimate with a bootstrap interval, all in paisa per
// incident. Reading Value without reading Lower and Upper is the mistake this
// type exists to make awkward.
type Estimate struct {
	// Value is the mean net recovery per incident, in paisa.
	Value float64 `json:"value_paisa"`

	// Lower and Upper bound Value at Options.Confidence coverage.
	Lower float64 `json:"lower_paisa"`
	Upper float64 `json:"upper_paisa"`

	// Confidence is the coverage the bounds were computed at.
	Confidence float64 `json:"confidence"`
}

// TotalPaisa scales the per-incident figure to a corpus of n incidents and
// rounds to the nearest paisa. It rounds rather than truncating because the
// figure is an estimate in both directions, and it is exposed as a helper so no
// caller invents its own scaling.
func (e Estimate) TotalPaisa(n int) int64 { return int64(math.Round(e.Value * float64(n))) }

// Beats reports whether the whole interval sits above other's point estimate.
// It is the only comparison this package endorses, because comparing two point
// estimates while ignoring two intervals is how a policy change gets shipped on
// noise.
func (e Estimate) Beats(other Estimate) bool { return e.Lower > other.Value }

// Diagnostics describes how much the estimate should be trusted. Every field
// here is a way an off-policy number goes wrong in practice.
type Diagnostics struct {
	Samples int `json:"samples"`

	// EffectiveSampleSize is (sum w)^2 / sum(w^2): the number of equally
	// weighted incidents this estimate is really standing on. A five thousand
	// incident log with an ESS of nine is one anecdote wearing a lab coat.
	EffectiveSampleSize float64 `json:"effective_sample_size"`

	// ESSFraction is EffectiveSampleSize / Samples, which is the number to
	// look at first.
	ESSFraction float64 `json:"ess_fraction"`

	MeanWeight float64 `json:"mean_weight"`
	MaxWeight  float64 `json:"max_weight"`
	P99Weight  float64 `json:"p99_weight"`

	// ClippedSamples counts weights truncated by Options.WeightCap.
	ClippedSamples int `json:"clipped_samples"`

	// OverlapViolations counts samples whose logged propensity fell below the
	// floor while the target policy still wanted that action, plus samples
	// reporting unsupported target mass.
	OverlapViolations int `json:"overlap_violations"`

	// UnsupportedMass is the mean target probability, across all samples, that
	// sits on actions the logging policy could never have taken. Any positive
	// value means part of the target policy behaviour is unmeasured.
	UnsupportedMass float64 `json:"unsupported_mass"`

	// SupportedSamples counts samples the target policy would ever produce. A
	// target policy that agrees with the logger on two incidents out of five
	// thousand is not being evaluated, it is being guessed at.
	SupportedSamples int `json:"supported_samples"`
}

// Report is the full result of one evaluation.
type Report struct {
	// Logged is the plain unweighted mean of the observed rewards: what the
	// logging policy actually earned. It is included so the counterfactual is
	// always read next to the fact it is being compared against.
	Logged Estimate `json:"logged"`

	IPS   Estimate  `json:"ips"`
	SNIPS Estimate  `json:"snips"`
	DR    *Estimate `json:"dr,omitempty"`

	Diagnostics Diagnostics `json:"diagnostics"`

	// Warnings are plain-language conditions that weaken the result without
	// invalidating it. They are strings rather than codes because they are read
	// by an operator deciding whether to believe a number, not by a machine.
	Warnings []string `json:"warnings,omitempty"`
}

// Lift is the difference between a target estimate and the logged baseline,
// with an interval, and is the quantity anyone actually wants: not "the new
// policy is worth 412 paisa an incident" but "the new policy is worth 47 to 96
// paisa an incident more than what we run today".
type Lift struct {
	Estimate

	// Significant reports whether the whole interval lies above zero.
	Significant bool `json:"significant"`

	// Estimator names which construction produced this number, because the two
	// have very different precision and quoting one as the other would be
	// misleading.
	Estimator string `json:"estimator"`

	// Influential counts the logged decisions where the candidate and the
	// deployed policy actually disagree. Every other decision contributes
	// exactly nothing to a lift, so this rather than the corpus size is the
	// sample size a reader should judge the interval against. A lift measured
	// over five influential decisions is a rumour whatever its interval says.
	Influential int `json:"influential"`

	// Warning is set when the estimate is technically valid and practically
	// not worth much. It is prose because it is read by a person deciding
	// whether to act.
	Warning string `json:"warning,omitempty"`
}

// Evaluate estimates the per-incident value of the target policy from samples
// logged under a different policy.
//
// It fails rather than degrades when the estimand is not identified. Callers
// that want a number regardless should not be using off-policy evaluation.
func Evaluate(samples []Sample, opts Options) (Report, error) {
	opts, err := opts.normalise()
	if err != nil {
		return Report{}, err
	}
	if len(samples) == 0 {
		return Report{}, ErrNoSamples
	}
	if len(samples) > MaxSamples {
		return Report{}, fmt.Errorf("ope: %d samples exceeds the %d limit", len(samples), MaxSamples)
	}
	for i, s := range samples {
		if err := s.validate(); err != nil {
			return Report{}, fmt.Errorf("ope: sample %d: %w", i, err)
		}
	}

	n := len(samples)
	weights := make([]float64, n)
	rewards := make([]float64, n)
	base := make([]float64, n)
	targetMean := make([]float64, n)

	var (
		diag         Diagnostics
		unsupported  float64
		sumWeight    float64
		sumSquare    float64
		hardFailures int
	)
	diag.Samples = n

	for i, s := range samples {
		rewards[i] = float64(s.RewardPaisa)
		base[i] = s.Baseline
		targetMean[i] = s.TargetMean
		unsupported += s.Unsupported

		if s.Target > 0 {
			diag.SupportedSamples++
		}
		// Two distinct violations, deliberately counted together and reported
		// separately in the error. The first is a target action the logger
		// took so rarely the weight is meaningless; the second is a target
		// action the logger structurally could not take, which no sample size
		// fixes.
		if s.Target > 0 && s.Logged < opts.PropensityFloor {
			diag.OverlapViolations++
			hardFailures++
		}
		if s.Unsupported > 0 {
			diag.OverlapViolations++
			hardFailures++
		}

		w := s.Target / s.Logged
		if opts.WeightCap > 0 && w > opts.WeightCap {
			w = opts.WeightCap
			diag.ClippedSamples++
		}
		weights[i] = w
		sumWeight += w
		sumSquare += w * w
	}

	diag.UnsupportedMass = unsupported / float64(n)
	diag.MeanWeight = sumWeight / float64(n)
	diag.MaxWeight, diag.P99Weight = maxAndP99(weights)
	if sumSquare > 0 {
		diag.EffectiveSampleSize = sumWeight * sumWeight / sumSquare
		diag.ESSFraction = diag.EffectiveSampleSize / float64(n)
	}

	if hardFailures > 0 {
		return Report{Diagnostics: diag}, fmt.Errorf(
			"%w: %d of %d samples violate overlap (mean unsupported target mass %.4f); "+
				"the value of this policy is not identified by this log and no estimator recovers it",
			ErrNoOverlap, diag.OverlapViolations, n, diag.UnsupportedMass)
	}

	rep := Report{Diagnostics: diag}
	rep.Warnings = warnings(diag, opts)

	// One shared set of resample indices for every estimator, so the three
	// intervals describe the same resampled worlds and are comparable to each
	// other rather than to three independent Monte-Carlo runs.
	draws := bootstrapIndices(n, opts)

	rep.Logged = intervalFrom(pointMean(rewards), draws, opts,
		func(idx []int) float64 { return meanOver(idx, rewards) },
		func() []float64 { return jackknifeMean(rewards) })

	rep.IPS = intervalFrom(ips(weights, rewards), draws, opts,
		func(idx []int) float64 { return ipsOver(idx, weights, rewards) },
		func() []float64 { return jackknifeWeightedMean(weights, rewards) })

	rep.SNIPS = intervalFrom(snips(weights, rewards), draws, opts,
		func(idx []int) float64 { return snipsOver(idx, weights, rewards) },
		func() []float64 { return jackknifeRatio(weights, rewards) })

	if opts.WithOutcomeModel {
		terms := make([]float64, n)
		for i := range terms {
			terms[i] = targetMean[i] + weights[i]*(rewards[i]-base[i])
		}
		dr := intervalFrom(doublyRobust(weights, rewards, base, targetMean), draws, opts,
			func(idx []int) float64 { return drOver(idx, weights, rewards, base, targetMean) },
			func() []float64 { return jackknifeMean(terms) })
		rep.DR = &dr
	}
	return rep, nil
}

// ---------------------------------------------------------------------------
// Leave-one-out values
// ---------------------------------------------------------------------------
//
// Every estimator here is a ratio of sums, so dropping one observation is a
// subtraction rather than a re-run and the whole jackknife costs one pass. That
// is what makes the accelerated interval affordable at this sample size.

func jackknifeMean(v []float64) []float64 {
	n := len(v)
	if n < 2 {
		return nil
	}
	var total float64
	for _, x := range v {
		total += x
	}
	out := make([]float64, n)
	for i, x := range v {
		out[i] = (total - x) / float64(n-1)
	}
	return out
}

func jackknifeWeightedMean(w, r []float64) []float64 {
	n := len(w)
	if n < 2 {
		return nil
	}
	var total float64
	for i := range w {
		total += w[i] * r[i]
	}
	out := make([]float64, n)
	for i := range w {
		out[i] = (total - w[i]*r[i]) / float64(n-1)
	}
	return out
}

func jackknifeRatio(w, r []float64) []float64 {
	n := len(w)
	if n < 2 {
		return nil
	}
	var num, den float64
	for i := range w {
		num += w[i] * r[i]
		den += w[i]
	}
	out := make([]float64, n)
	for i := range w {
		d := den - w[i]
		if d == 0 {
			out[i] = 0
			continue
		}
		out[i] = (num - w[i]*r[i]) / d
	}
	return out
}

// EvaluateLift reports the target policy advantage over the logging policy with
// a paired interval.
//
// It is paired on purpose. Bootstrapping the two estimates separately and
// subtracting their bounds produces an interval far wider than the truth,
// because the same incidents drive both quantities and their errors cancel.
// Resampling the difference keeps that cancellation.
//
// The difference is built from IPS rather than SNIPS, which is the opposite of
// the recommendation for estimating a level, and the reason is worth stating
// because getting it wrong is silent.
//
// The lift is the mean of (w_i - 1) * r_i. Under overlap that is exactly
// unbiased, and for the case that matters most here, a candidate policy that
// changes behaviour in one segment and matches the deployed policy everywhere
// else, the weight is exactly one outside the segment and the term vanishes.
// The estimator then reads only the decisions the change actually touches, with
// no contribution and no variance from the rest of the corpus.
//
// Self-normalising instead divides the weighted term by the realised weight
// mass while leaving the subtracted mean undivided. The two halves are then
// scaled differently, the O(1/n) bias of SNIPS no longer cancels against
// anything, and on a small segment that residual is the same size as the effect
// being measured. The symptom is an interval that looks respectable and covers
// the truth about three quarters of the time instead of ninety five percent,
// which is exactly how it was found here.
func EvaluateLift(samples []Sample, opts Options) (Lift, Report, error) {
	rep, err := Evaluate(samples, opts)
	if err != nil {
		return Lift{}, rep, err
	}
	norm, err := opts.normalise()
	if err != nil {
		return Lift{}, rep, err
	}

	n := len(samples)
	weights := make([]float64, n)
	rewards := make([]float64, n)
	for i, s := range samples {
		w := s.Target / s.Logged
		if norm.WeightCap > 0 && w > norm.WeightCap {
			w = norm.WeightCap
		}
		weights[i] = w
		rewards[i] = float64(s.RewardPaisa)
	}

	// The per-decision contribution to the lift.
	//
	// Without a reward model this is (w-1)*r: unbiased, and carrying the whole
	// variance of a heavy-tailed reward on the handful of decisions where the
	// two policies differ. Indian ticket sizes span four orders of magnitude,
	// so one large recovery landing on a weight of four can move a segment
	// estimate by a factor of three, and no interval method rescues an average
	// of five such terms.
	//
	// With a reward model the same quantity is written as
	//
	//	(rhat under the candidate - rhat under the deployed policy) + (w-1)(r - rhat)
	//
	// which is the doubly-robust form of a difference. The first term is the
	// model prediction of the effect and is nearly noiseless. The second is the
	// correction that keeps the whole thing unbiased when the model is wrong,
	// and it is driven by the residual r - rhat rather than by r, so the tail
	// that was doing the damage has already been subtracted off. Outside the
	// region the candidate changes, both terms are exactly zero and the
	// estimator correctly sees nothing at all.
	terms := make([]float64, n)
	var influential int
	for i, sm := range samples {
		if math.Abs(weights[i]-1) > 1e-12 {
			influential++
		}
		if norm.LiftEstimator == LiftDoublyRobust {
			terms[i] = (sm.TargetMean - sm.LoggedMean) + (weights[i]-1)*(rewards[i]-sm.Baseline)
			continue
		}
		terms[i] = (weights[i] - 1) * rewards[i]
	}

	stat := func(idx []int) float64 { return meanOver(idx, terms) }
	draws := bootstrapIndices(n, norm)
	est := intervalFrom(pointMean(terms), draws, norm, stat,
		func() []float64 { return jackknifeMean(terms) })

	lift := Lift{
		Estimate:    est,
		Significant: est.Lower > 0,
		Estimator:   string(norm.LiftEstimator),
		Influential: influential,
	}
	if influential < MinInfluentialDecisions {
		lift.Warning = fmt.Sprintf(
			"only %d of %d logged decisions differ between the two policies; below %d the interval is unreliable however narrow it looks",
			influential, n, MinInfluentialDecisions)
	}
	return lift, rep, nil
}

// MinInfluentialDecisions is the point below which a lift is annotated as
// unreliable.
//
// It is not a hard refusal, because the number is still the best estimate
// available and a caller may have other evidence. It is a label, and it exists
// because the failure it names is invisible: a candidate that differs from the
// deployed policy on thirty decisions out of thirty thousand produces an
// interval that looks like every other interval, and it will contain the truth
// far less often than its stated confidence. That was measured on a world with
// a known answer and the coverage was closer to two thirds than to nineteen
// twentieths. See internal/lab.
const MinInfluentialDecisions = 150

// ---------------------------------------------------------------------------
// Estimators
// ---------------------------------------------------------------------------

// ips is the Horvitz-Thompson estimator: an unbiased mean under overlap, and
// the one whose variance can be unbounded when a weight is large.
func ips(w, r []float64) float64 {
	var sum float64
	for i := range w {
		sum += w[i] * r[i]
	}
	return sum / float64(len(w))
}

// snips normalises by the realised weight mass rather than by n.
//
// The bias it introduces is O(1/n) and the variance it removes is the reason
// anyone uses off-policy evaluation in practice. The intuition: if the target
// policy agrees with the logger on a tenth of the traffic, IPS divides a tenth
// of the reward by all of n and reports a value near zero; SNIPS divides by the
// weight actually accumulated and reports the value of the traffic it can see.
// SNIPS also stays inside the observed reward range, which IPS does not, so it
// cannot claim a recovery larger than any recovery that happened.
func snips(w, r []float64) float64 {
	var num, den float64
	for i := range w {
		num += w[i] * r[i]
		den += w[i]
	}
	if den == 0 {
		// The target policy would never have taken any logged action. There is
		// no traffic in common, so zero is the honest answer and the overlap
		// diagnostics carry the reason.
		return 0
	}
	return num / den
}

// doublyRobust combines the reward model with the importance weights so that
// either one being correct is enough for the estimate to be unbiased.
//
// The shape is: start from what the model predicts the target policy earns,
// then correct it by the observed residual, reweighted. Where the model is good
// the residual is small and the high-variance weighted term barely contributes.
// Where the model is bad the residual carries the estimate and the result falls
// back towards IPS. Neither has to be right, only one of them.
func doublyRobust(w, r, base, targetMean []float64) float64 {
	var sum float64
	for i := range w {
		sum += targetMean[i] + w[i]*(r[i]-base[i])
	}
	return sum / float64(len(w))
}

func pointMean(r []float64) float64 {
	var sum float64
	for _, v := range r {
		sum += v
	}
	return sum / float64(len(r))
}

func meanOver(idx []int, r []float64) float64 {
	var sum float64
	for _, i := range idx {
		sum += r[i]
	}
	return sum / float64(len(idx))
}

func ipsOver(idx []int, w, r []float64) float64 {
	var sum float64
	for _, i := range idx {
		sum += w[i] * r[i]
	}
	return sum / float64(len(idx))
}

func snipsOver(idx []int, w, r []float64) float64 {
	var num, den float64
	for _, i := range idx {
		num += w[i] * r[i]
		den += w[i]
	}
	if den == 0 {
		return 0
	}
	return num / den
}

func drOver(idx []int, w, r, base, targetMean []float64) float64 {
	var sum float64
	for _, i := range idx {
		sum += targetMean[i] + w[i]*(r[i]-base[i])
	}
	return sum / float64(len(idx))
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// bootstrapIndices draws Options.Bootstrap resamples of n indices with
// replacement, from a generator seeded only by Options.Seed.
//
// The draws are materialised once and shared by every estimator rather than
// redrawn per estimator. That makes the intervals mutually comparable and makes
// the whole report a pure function of (samples, options), which is what lets a
// counterfactual claim be committed to the audit ledger and re-derived later by
// someone who does not trust the person who published it.
func bootstrapIndices(n int, opts Options) [][]int {
	if opts.Bootstrap <= 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	draws := make([][]int, opts.Bootstrap)
	for b := range draws {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = rng.Intn(n)
		}
		draws[b] = idx
	}
	return draws
}

func maxAndP99(w []float64) (maxWeight, p99 float64) {
	if len(w) == 0 {
		return 0, 0
	}
	cp := append([]float64(nil), w...)
	sort.Float64s(cp)
	return cp[len(cp)-1], percentile(cp, 0.99)
}

// ---------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------

// Thresholds behind Report.Warnings. They are conventional rather than derived,
// and they are named so a reader can disagree with a specific number instead of
// with an opaque verdict.
const (
	weakESSFraction     = 0.10
	severeESSFraction   = 0.02
	heavyTailWeight     = 50.0
	thinSupportFraction = 0.20
)

func warnings(d Diagnostics, opts Options) []string {
	var out []string
	if d.ESSFraction > 0 && d.ESSFraction < severeESSFraction {
		out = append(out, fmt.Sprintf(
			"effective sample size is %.1f of %d incidents (%.1f%%): this estimate rests on a handful of logged decisions and its interval is optimistic",
			d.EffectiveSampleSize, d.Samples, 100*d.ESSFraction))
	} else if d.ESSFraction > 0 && d.ESSFraction < weakESSFraction {
		out = append(out, fmt.Sprintf(
			"effective sample size is %.1f of %d incidents (%.1f%%): the two policies overlap on a small slice of traffic",
			d.EffectiveSampleSize, d.Samples, 100*d.ESSFraction))
	}
	if d.MaxWeight > heavyTailWeight {
		out = append(out, fmt.Sprintf(
			"heaviest importance weight is %.1f: one logged incident carries %.1f times the influence of an average one",
			d.MaxWeight, d.MaxWeight/math.Max(d.MeanWeight, 1e-12)))
	}
	if d.Samples > 0 {
		if frac := float64(d.SupportedSamples) / float64(d.Samples); frac < thinSupportFraction {
			out = append(out, fmt.Sprintf(
				"the target policy would have repeated only %d of %d logged actions (%.1f%%): most of this log says nothing about it",
				d.SupportedSamples, d.Samples, 100*frac))
		}
	}
	if d.ClippedSamples > 0 {
		out = append(out, fmt.Sprintf(
			"%d importance weights were truncated at %.1f: the estimate is biased towards the logging policy by construction",
			d.ClippedSamples, opts.WeightCap))
	}
	return out
}

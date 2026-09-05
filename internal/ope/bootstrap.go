package ope

import (
	"math"
	"sort"
)

// This file holds the interval machinery, and it exists because the obvious
// version of it was wrong.
//
// The first implementation took the 2.5th and 97.5th percentiles of the
// bootstrap distribution and called them a 95% interval. That is the textbook
// percentile bootstrap and it is correct asymptotically. On the estimates this
// system actually produces it under-covered badly: a segment-level lift
// measured over a few dozen decisions, with Indian ticket sizes spanning four
// orders of magnitude, contained the truth about half the time rather than
// nineteen times in twenty. It was found by running the estimator against a
// world whose answer key is known and counting, which is the only way it could
// have been found, and the count is now a test.
//
// The cause is skew. A percentile interval is symmetric in the bootstrap
// distribution and takes no view on whether that distribution is centred on the
// estimate or leaning to one side. Where a handful of large recoveries carry
// most of the signal, it leans hard, and the interval is placed in the wrong
// position rather than merely being the wrong width.
//
// The correction is the bias-corrected and accelerated bootstrap of Efron. It
// moves the two percentiles by two quantities read off the data: how much of
// the bootstrap distribution sits below the point estimate, which measures
// median bias, and how quickly the variance of the statistic changes as
// observations are dropped, which measures skew. Both are cheap here because
// every estimator in this package is a ratio of sums, so a leave-one-out value
// costs a subtraction rather than a re-run.

// IntervalMethod selects how a bootstrap distribution becomes an interval.
type IntervalMethod string

const (
	// IntervalBCa is the default: bias-corrected and accelerated.
	IntervalBCa IntervalMethod = "bca"

	// IntervalPercentile is the plain percentile interval. It is kept so the
	// two can be compared on the same data, which is how the defect above was
	// diagnosed, and so a caller who wants the simpler object can have it.
	IntervalPercentile IntervalMethod = "percentile"
)

// jackknife carries the leave-one-out values of a statistic.
//
// Efron acceleration is defined in terms of them, and computing them by
// re-running the estimator n times would be quadratic. Every estimator here is
// a ratio of sums over the samples, so the caller supplies a closure that
// removes one term from the running totals instead.
type jackknife func() []float64

// intervalFrom attaches a confidence interval to a point estimate.
func intervalFrom(point float64, draws [][]int, opts Options, stat func([]int) float64, jack jackknife) Estimate {
	est := Estimate{Value: point, Lower: point, Upper: point, Confidence: opts.Confidence}
	if len(draws) == 0 {
		return est
	}

	vals := make([]float64, 0, len(draws))
	var below int
	for _, idx := range draws {
		v := stat(idx)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		if v < point {
			below++
		}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return est
	}
	sort.Float64s(vals)

	tail := (1 - opts.Confidence) / 2
	lo, hi := tail, 1-tail

	if opts.IntervalMethod != IntervalPercentile && jack != nil {
		if adjLo, adjHi, ok := bcaLevels(float64(below)/float64(len(vals)), jack(), tail); ok {
			lo, hi = adjLo, adjHi
		}
	}

	est.Lower = percentile(vals, lo)
	est.Upper = percentile(vals, hi)
	return est
}

// bcaLevels converts the nominal tail probabilities into the adjusted ones.
//
// It returns ok=false whenever the correction is not well defined, in which
// case the caller keeps the plain percentile levels. That happens when the
// bootstrap distribution lies entirely on one side of the estimate, or when the
// acceleration term would push the transformation through its own singularity.
// Falling back is the right response: a slightly conservative interval is a
// smaller problem than a confidently misplaced one.
func bcaLevels(proportionBelow float64, jack []float64, tail float64) (lo, hi float64, ok bool) {
	if len(jack) < 3 {
		return 0, 0, false
	}
	// Bias correction: where the bootstrap distribution sits relative to the
	// estimate. Zero means perfectly centred and no shift is applied.
	if proportionBelow <= 0 || proportionBelow >= 1 {
		return 0, 0, false
	}
	z0 := normInv(proportionBelow)
	if math.IsNaN(z0) || math.IsInf(z0, 0) {
		return 0, 0, false
	}

	// Acceleration: the standardised third moment of the leave-one-out values,
	// which is how fast the variance of the statistic changes with the data.
	var mean float64
	for _, v := range jack {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, 0, false
		}
		mean += v
	}
	mean /= float64(len(jack))

	var num, den float64
	for _, v := range jack {
		d := mean - v
		num += d * d * d
		den += d * d
	}
	if den <= 0 {
		return 0, 0, false
	}
	a := num / (6 * math.Pow(den, 1.5))
	if math.IsNaN(a) || math.IsInf(a, 0) {
		return 0, 0, false
	}

	adjust := func(p float64) (float64, bool) {
		z := normInv(p)
		d := 1 - a*(z0+z)
		if d == 0 || math.IsNaN(d) {
			return 0, false
		}
		out := normCDF(z0 + (z0+z)/d)
		if math.IsNaN(out) || out <= 0 || out >= 1 {
			return 0, false
		}
		return out, true
	}

	lo, okLo := adjust(tail)
	hi, okHi := adjust(1 - tail)
	if !okLo || !okHi || lo >= hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// percentile reads a sorted slice at fraction p using nearest-rank, which needs
// no interpolation and so returns a value that actually occurred in the
// resample distribution.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// normCDF is the standard normal distribution function.
func normCDF(z float64) float64 { return 0.5 * math.Erfc(-z/math.Sqrt2) }

// normInv is its inverse, by the Acklam rational approximation followed by one
// Halley refinement.
//
// The approximation alone is good to about one part in a billion, which is
// already far finer than a bootstrap percentile can resolve. The refinement
// costs one erfc call and removes the question entirely, so the adjusted levels
// are limited by the resample count rather than by this function.
func normInv(p float64) float64 {
	if p <= 0 || p >= 1 || math.IsNaN(p) {
		return math.NaN()
	}

	const (
		a1, a2, a3 = -3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02
		a4, a5, a6 = 1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00

		b1, b2, b3 = -5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02
		b4, b5     = 6.680131188771972e+01, -1.328068155288572e+01

		c1, c2, c3 = -7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00
		c4, c5, c6 = -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00

		d1, d2 = 7.784695709041462e-03, 3.224671290700398e-01
		d3, d4 = 2.445134137142996e+00, 3.754408661907416e+00

		plow  = 0.02425
		phigh = 1 - plow
	)

	var x float64
	switch {
	case p < plow:
		q := math.Sqrt(-2 * math.Log(p))
		x = (((((c1*q+c2)*q+c3)*q+c4)*q+c5)*q + c6) / ((((d1*q+d2)*q+d3)*q+d4)*q + 1)
	case p > phigh:
		q := math.Sqrt(-2 * math.Log(1-p))
		x = -(((((c1*q+c2)*q+c3)*q+c4)*q+c5)*q + c6) / ((((d1*q+d2)*q+d3)*q+d4)*q + 1)
	default:
		q := p - 0.5
		r := q * q
		x = (((((a1*r+a2)*r+a3)*r+a4)*r+a5)*r + a6) * q /
			(((((b1*r+b2)*r+b3)*r+b4)*r+b5)*r + 1)
	}

	// One Halley step against the true CDF.
	e := normCDF(x) - p
	u := e * math.Sqrt(2*math.Pi) * math.Exp(x*x/2)
	return x - u/(1+x*u/2)
}

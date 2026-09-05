// Package reward learns how likely a recovery attempt is to succeed.
//
// It exists to serve two callers with one model.
//
// The first is the doubly-robust estimator in internal/ope, which needs a
// prediction of the reward for actions that were never taken. Importance
// weighting alone can answer that question but only with the variance of a
// quantity divided by a small probability; a reward model absorbs most of that
// variance and leaves the weights to correct whatever the model got wrong.
//
// The second is the policy engine, whose ExpectedValue is currently priced off
// a probability the inference tier asserts. An asserted probability is a guess
// with a confident face on it. A fitted one has a held-out log loss, a
// calibration curve and an area under the ROC that anyone can check, and this
// package reports all three rather than claiming the model is good.
//
// # Why this model and not a bigger one
//
// Logistic regression over hashed features is not the most accurate model that
// could be fitted here, and that is the point. It is convex, so training has
// one answer rather than a seed-dependent one; it is linear, so the
// contribution of every feature can be read off and argued with; and it is
// small enough that the whole model fits in an audit record. A payments
// regulator asking why a customer was retried at 06:00 gets a list of weights,
// not an embedding.
//
// # Cross-fitting
//
// Fitting a reward model on the same incidents the estimator then evaluates
// makes the estimate biased towards whatever the model overfitted. The standard
// remedy is cross-fitting: partition the log, fit on the other folds, predict
// only on the held-out one, so no prediction has ever seen its own outcome.
// CrossFit does that, and it is the entry point internal/ope callers should
// use. Fit is exported for the case where the model is being trained for
// deployment rather than for evaluation.
//
// # Money
//
// This package returns probabilities and never paisa. Turning a probability
// into a value is exact integer arithmetic and belongs to internal/policy, for
// the same reason it does in internal/bandit: no learned parameter is allowed
// to be an amount.
package reward

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"sort"
)

// Defaults and bounds.
const (
	// DefaultDimensions is the hashed feature space. Sixteen thousand buckets
	// against the few thousand distinct tokens this system produces keeps the
	// collision rate near a percent, which the signed hashing below turns into
	// noise rather than bias.
	DefaultDimensions = 1 << 14

	// DefaultEpochs is the number of passes over the training data.
	DefaultEpochs = 12

	// DefaultLearningRate is the AdaGrad step size.
	DefaultLearningRate = 0.15

	// DefaultL2 is the ridge penalty. It is small because the hashing already
	// limits capacity, and because a heavily regularised model would flatten
	// exactly the rare, high-value segments this system is trying to find.
	DefaultL2 = 1e-6

	// DefaultFolds is the cross-fitting partition count.
	DefaultFolds = 5

	MaxExamples           = 5_000_000
	MaxFeaturesPerExample = 64
	MaxTokenLen           = 128
	maxDimensions         = 1 << 22
	maxEpochs             = 500
	maxFolds              = 32

	// adagradEpsilon keeps the first step of each coordinate finite.
	adagradEpsilon = 1e-8
)

var (
	// ErrNoExamples means there was nothing to fit.
	ErrNoExamples = errors.New("reward: no training examples")

	// ErrDegenerate means every label was identical. A model fitted on one
	// class predicts that class for everything and its log loss looks superb,
	// which is the most common way a reward model silently poisons a
	// doubly-robust estimate.
	ErrDegenerate = errors.New("reward: every training label is identical, so nothing can be learned")

	// ErrInvalidOptions covers a malformed Options.
	ErrInvalidOptions = errors.New("reward: invalid options")

	// ErrOutOfRange means a cross-fitted prediction was requested for an index
	// that was not part of the training set.
	ErrOutOfRange = errors.New("reward: example index is outside the fitted set")
)

// Example is one observed attempt.
type Example struct {
	// Features are the tokens describing the context and the action taken, in
	// the caller vocabulary: "issuer=upi:okhdfcbank", "class=ISSUER_OUTAGE",
	// "arm=delay_6h". Order does not matter and duplicates are counted once.
	Features []string

	// Label is whether the attempt recovered the payment.
	Label bool
}

// Options tunes training. The zero value is valid.
type Options struct {
	Dimensions   int
	Epochs       int
	LearningRate float64
	L2           float64
	Folds        int

	// Seed fixes the example order used by stochastic gradient descent. The
	// objective is convex so the optimum does not depend on it, but the
	// finite-epoch approximation does, and a model whose weights move between
	// runs cannot be committed to an audit record.
	Seed int64
}

func (o Options) normalise() (Options, error) {
	if o.Dimensions == 0 {
		o.Dimensions = DefaultDimensions
	}
	if o.Epochs == 0 {
		o.Epochs = DefaultEpochs
	}
	if o.LearningRate == 0 {
		o.LearningRate = DefaultLearningRate
	}
	if o.L2 == 0 {
		o.L2 = DefaultL2
	}
	if o.Folds == 0 {
		o.Folds = DefaultFolds
	}
	switch {
	case o.Dimensions < 16 || o.Dimensions > maxDimensions:
		return o, fmt.Errorf("%w: dimensions %d outside [16, %d]", ErrInvalidOptions, o.Dimensions, maxDimensions)
	case o.Dimensions&(o.Dimensions-1) != 0:
		// A power of two lets the bucket be masked rather than divided, which
		// keeps the index independent of the modulo bias a non-power-of-two
		// range would introduce.
		return o, fmt.Errorf("%w: dimensions %d is not a power of two", ErrInvalidOptions, o.Dimensions)
	case o.Epochs < 1 || o.Epochs > maxEpochs:
		return o, fmt.Errorf("%w: epochs %d outside [1, %d]", ErrInvalidOptions, o.Epochs, maxEpochs)
	case o.LearningRate <= 0 || o.LearningRate > 10 || math.IsNaN(o.LearningRate):
		return o, fmt.Errorf("%w: learning rate %g outside (0, 10]", ErrInvalidOptions, o.LearningRate)
	case o.L2 < 0 || o.L2 > 1 || math.IsNaN(o.L2):
		return o, fmt.Errorf("%w: L2 penalty %g outside [0, 1]", ErrInvalidOptions, o.L2)
	case o.Folds < 2 || o.Folds > maxFolds:
		return o, fmt.Errorf("%w: folds %d outside [2, %d]", ErrInvalidOptions, o.Folds, maxFolds)
	}
	return o, nil
}

// Model is a fitted logistic regression over hashed features.
type Model struct {
	dim     int
	weights []float64
	bias    float64
}

// Report describes how well a model actually predicts, on data it was not
// fitted on. Every figure here is one an operator can use to decide whether the
// doubly-robust term is worth anything.
type Report struct {
	Examples  int `json:"examples"`
	Positives int `json:"positives"`
	Folds     int `json:"folds"`

	// BaseRate is the share of attempts that recovered. It is the score to
	// beat: a model whose log loss does not improve on always predicting the
	// base rate has learned nothing.
	BaseRate float64 `json:"base_rate"`

	// BaselineLogLoss is the log loss of predicting BaseRate for everything.
	BaselineLogLoss float64 `json:"baseline_log_loss"`

	// LogLoss is the held-out log loss of the model.
	LogLoss float64 `json:"log_loss"`

	// Skill is 1 - LogLoss/BaselineLogLoss: the share of the baseline loss the
	// model removed. Zero means useless, one means perfect, negative means the
	// model is worse than knowing nothing.
	Skill float64 `json:"skill"`

	// AUC is the probability the model ranks a random recovered attempt above
	// a random failed one. Unlike log loss it is insensitive to calibration,
	// so a model can have good AUC and useless probabilities, which is why
	// both are reported.
	AUC float64 `json:"auc"`

	// Brier is the mean squared error of the predicted probabilities.
	Brier float64 `json:"brier"`
}

// Fit trains a single model on every example.
//
// The returned Report is measured on the training data and is therefore
// optimistic. It is included because a model that cannot fit its own training
// set has a bug, not because it says anything about generalisation. For an
// honest number, use CrossFit.
func Fit(examples []Example, opts Options) (*Model, Report, error) {
	opts, err := opts.normalise()
	if err != nil {
		return nil, Report{}, err
	}
	if err := checkExamples(examples); err != nil {
		return nil, Report{}, err
	}
	m := train(examples, allIndices(len(examples)), opts)
	preds := make([]float64, len(examples))
	for i, ex := range examples {
		preds[i] = m.Predict(ex.Features)
	}
	return m, score(examples, preds, 1), nil
}

// CrossFit partitions the examples and fits one model per fold, so that every
// prediction comes from a model that never saw that example.
//
// This is the form the doubly-robust estimator needs. Without it, the residual
// the estimator corrects by is the residual of a model that has already seen
// the answer, which is systematically too small, and the correction term
// silently shrinks towards zero.
func CrossFit(examples []Example, opts Options) (*CrossFitted, Report, error) {
	opts, err := opts.normalise()
	if err != nil {
		return nil, Report{}, err
	}
	if err := checkExamples(examples); err != nil {
		return nil, Report{}, err
	}
	if len(examples) < opts.Folds {
		return nil, Report{}, fmt.Errorf("%w: %d examples cannot be split into %d folds", ErrInvalidOptions, len(examples), opts.Folds)
	}

	assign := foldAssignment(len(examples), opts)
	cf := &CrossFitted{fold: assign, folds: opts.Folds, models: make([]*Model, opts.Folds)}
	preds := make([]float64, len(examples))

	for f := 0; f < opts.Folds; f++ {
		var train_ []int
		for i, fold := range assign {
			if fold != f {
				train_ = append(train_, i)
			}
		}
		if len(train_) == 0 {
			return nil, Report{}, fmt.Errorf("%w: fold %d left no training data", ErrInvalidOptions, f)
		}
		cf.models[f] = train(examples, train_, opts)
	}
	for i, ex := range examples {
		preds[i] = cf.models[assign[i]].Predict(ex.Features)
	}
	return cf, score(examples, preds, opts.Folds), nil
}

// CrossFitted holds one model per fold together with the partition that
// produced them.
type CrossFitted struct {
	models []*Model
	fold   []int
	folds  int
}

// PredictFor scores features using the model that did not see example index.
//
// The index rather than the features decides which model answers, because the
// caller needs predictions for actions that were never taken and those have no
// example of their own. Routing by index keeps every prediction about incident
// i, taken or counterfactual, out of the model that trained on incident i.
func (c *CrossFitted) PredictFor(index int, features []string) (float64, error) {
	if index < 0 || index >= len(c.fold) {
		return 0, fmt.Errorf("%w: %d", ErrOutOfRange, index)
	}
	return c.models[c.fold[index]].Predict(features), nil
}

// Folds reports the partition count.
func (c *CrossFitted) Folds() int { return c.folds }

// Predict returns the probability that an attempt with these features recovers.
func (m *Model) Predict(features []string) float64 {
	return sigmoid(m.score(features))
}

// Weights returns the largest-magnitude coefficients with the tokens that map
// onto them, so a fitted model can be read rather than merely used.
//
// Hashing means a bucket can hold more than one token, so this is an
// explanation of the model rather than a proof about it, and the collision
// caveat is why the method returns tokens the caller supplied instead of
// pretending to invert the hash.
func (m *Model) Weights(vocabulary []string, top int) []Weight {
	seen := make(map[string]struct{}, len(vocabulary))
	out := make([]Weight, 0, len(vocabulary))
	for _, tok := range vocabulary {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		idx, sign := bucket(tok, m.dim)
		out = append(out, Weight{Token: tok, Value: sign * m.weights[idx]})
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := math.Abs(out[i].Value), math.Abs(out[j].Value); a != b {
			return a > b
		}
		return out[i].Token < out[j].Token
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// Weight is one token contribution to the log-odds of recovery.
type Weight struct {
	Token string  `json:"token"`
	Value float64 `json:"value"`
}

// Bias is the intercept, which is the model view of the base rate in log-odds.
func (m *Model) Bias() float64 { return m.bias }

func (m *Model) score(features []string) float64 {
	z := m.bias
	seen := make(map[int]struct{}, len(features))
	for i, tok := range features {
		if i >= MaxFeaturesPerExample || len(tok) == 0 || len(tok) > MaxTokenLen {
			continue
		}
		idx, sign := bucket(tok, m.dim)
		if _, dup := seen[idx]; dup {
			continue
		}
		seen[idx] = struct{}{}
		z += sign * m.weights[idx]
	}
	return clampLogit(z)
}

// ---------------------------------------------------------------------------
// Training
// ---------------------------------------------------------------------------

// train runs AdaGrad stochastic gradient descent over the given example indices.
//
// AdaGrad rather than a fixed step size because the feature frequencies here
// span four orders of magnitude: an issuer seen once an hour and a failure
// class seen on every incident cannot share a learning rate without either
// under-fitting the rare one or oscillating on the common one. Per-coordinate
// adaptation is the cheapest correct answer.
func train(examples []Example, indices []int, opts Options) *Model {
	m := &Model{dim: opts.Dimensions, weights: make([]float64, opts.Dimensions)}
	accum := make([]float64, opts.Dimensions)
	var biasAccum float64

	order := append([]int(nil), indices...)
	rng := rand.New(rand.NewSource(opts.Seed))

	buf := make([]int, 0, MaxFeaturesPerExample)
	signs := make([]float64, 0, MaxFeaturesPerExample)

	for epoch := 0; epoch < opts.Epochs; epoch++ {
		// A fresh shuffle each epoch, drawn from the seeded generator, so the
		// pass order is varied (which SGD needs) and reproducible (which an
		// audit record needs).
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

		for _, i := range order {
			ex := examples[i]
			buf, signs = features(ex.Features, m.dim, buf[:0], signs[:0])

			z := m.bias
			for k, idx := range buf {
				z += signs[k] * m.weights[idx]
			}
			p := sigmoid(clampLogit(z))

			label := 0.0
			if ex.Label {
				label = 1.0
			}
			// The gradient of the log loss with respect to the score. The
			// familiar cancellation: the sigmoid derivative and the log loss
			// denominator divide out, leaving the residual.
			g := p - label

			biasAccum += g * g
			m.bias -= opts.LearningRate * g / (math.Sqrt(biasAccum) + adagradEpsilon)

			for k, idx := range buf {
				grad := g*signs[k] + opts.L2*m.weights[idx]
				accum[idx] += grad * grad
				m.weights[idx] -= opts.LearningRate * grad / (math.Sqrt(accum[idx]) + adagradEpsilon)
			}
		}
	}
	return m
}

// features resolves an example tokens into deduplicated buckets and signs.
//
// The sign comes from a bit of the hash rather than being always positive. Two
// tokens colliding in the same bucket then cancel in expectation instead of
// adding, which turns a collision from a systematic bias into noise. It is the
// standard hashing-trick correction and it is why the bucket count can be this
// small.
func features(tokens []string, dim int, buf []int, signs []float64) ([]int, []float64) {
	seen := make(map[int]struct{}, len(tokens))
	for i, tok := range tokens {
		if i >= MaxFeaturesPerExample || len(tok) == 0 || len(tok) > MaxTokenLen {
			continue
		}
		idx, sign := bucket(tok, dim)
		if _, dup := seen[idx]; dup {
			continue
		}
		seen[idx] = struct{}{}
		buf = append(buf, idx)
		signs = append(signs, sign)
	}
	return buf, signs
}

// bucket maps a token onto a coordinate and a sign.
func bucket(tok string, dim int) (int, float64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(tok))
	sum := h.Sum64()
	idx := int(sum & uint64(dim-1))
	if sum>>63&1 == 1 {
		return idx, -1
	}
	return idx, 1
}

func allIndices(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// foldAssignment partitions examples into folds deterministically.
//
// The partition is a seeded shuffle rather than a contiguous block, because a
// log is ordered by time and contiguous folds would train on the past and test
// on the future for four folds out of five, mixing a distribution shift into
// what is supposed to be a measure of fit.
func foldAssignment(n int, opts Options) []int {
	order := allIndices(n)
	rng := rand.New(rand.NewSource(opts.Seed ^ 0x5f3759df))
	rng.Shuffle(n, func(i, j int) { order[i], order[j] = order[j], order[i] })
	assign := make([]int, n)
	for pos, i := range order {
		assign[i] = pos % opts.Folds
	}
	return assign
}

func checkExamples(examples []Example) error {
	if len(examples) == 0 {
		return ErrNoExamples
	}
	if len(examples) > MaxExamples {
		return fmt.Errorf("reward: %d examples exceeds the %d limit", len(examples), MaxExamples)
	}
	first := examples[0].Label
	for _, ex := range examples {
		if ex.Label != first {
			return nil
		}
	}
	return fmt.Errorf("%w (all %v)", ErrDegenerate, first)
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

func score(examples []Example, preds []float64, folds int) Report {
	rep := Report{Examples: len(examples), Folds: folds}
	for _, ex := range examples {
		if ex.Label {
			rep.Positives++
		}
	}
	rep.BaseRate = float64(rep.Positives) / float64(len(examples))

	var loss, baseline, brier float64
	for i, ex := range examples {
		loss += logLoss(preds[i], ex.Label)
		baseline += logLoss(rep.BaseRate, ex.Label)
		d := preds[i]
		if ex.Label {
			d = 1 - d
		}
		brier += d * d
	}
	n := float64(len(examples))
	rep.LogLoss = loss / n
	rep.BaselineLogLoss = baseline / n
	rep.Brier = brier / n
	if rep.BaselineLogLoss > 0 {
		rep.Skill = 1 - rep.LogLoss/rep.BaselineLogLoss
	}
	rep.AUC = auc(examples, preds)
	return rep
}

// logLoss is clamped away from the asymptote so a single confident mistake
// cannot make the whole average infinite, which would hide every other number
// in the report behind one outlier.
func logLoss(p float64, label bool) float64 {
	const eps = 1e-12
	p = math.Max(eps, math.Min(1-eps, p))
	if label {
		return -math.Log(p)
	}
	return -math.Log(1 - p)
}

// auc computes the area under the ROC curve by the rank identity, with ties
// given their average rank so a model that predicts a constant scores exactly
// 0.5 rather than 1.0.
func auc(examples []Example, preds []float64) float64 {
	type row struct {
		score float64
		label bool
	}
	rows := make([]row, len(examples))
	for i, ex := range examples {
		rows[i] = row{preds[i], ex.Label}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].score < rows[j].score })

	ranks := make([]float64, len(rows))
	for i := 0; i < len(rows); {
		j := i
		for j < len(rows) && rows[j].score == rows[i].score {
			j++
		}
		avg := float64(i+j+1) / 2 // average of the 1-based ranks i+1 .. j
		for k := i; k < j; k++ {
			ranks[k] = avg
		}
		i = j
	}

	var positives, negatives, rankSum float64
	for i, r := range rows {
		if r.label {
			positives++
			rankSum += ranks[i]
		} else {
			negatives++
		}
	}
	if positives == 0 || negatives == 0 {
		return 0.5
	}
	return (rankSum - positives*(positives+1)/2) / (positives * negatives)
}

// clampLogit bounds the score before it reaches the sigmoid. Beyond this the
// sigmoid saturates to exactly zero or one in float64, the log loss becomes
// infinite, and the gradient vanishes, which stalls training on precisely the
// examples it is getting most wrong.
func clampLogit(z float64) float64 {
	const limit = 30
	switch {
	case math.IsNaN(z):
		return 0
	case z > limit:
		return limit
	case z < -limit:
		return -limit
	}
	return z
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

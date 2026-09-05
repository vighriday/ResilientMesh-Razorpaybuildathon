// Package bandit is the part of ResilientMesh that learns.
//
// Everything else in this system is deliberately fixed: the gatekeeper enforces
// the same fourteen invariants forever, the policy engine computes the same
// backoff from the same inputs, and that rigidity is what makes the audit trail
// worth reading. This package is the one place where behaviour changes in
// response to what happened, and it is contained accordingly.
//
// # What it learns
//
// Issuer recovery is a hazard function, not a constant. A netbanking failure at
// an issuer running a nightly settlement batch recovers on a completely
// different schedule from the same failure at noon, and no exponential backoff
// curve written by hand knows that. The bandit holds a Beta posterior over the
// recovery probability of each (context cell, arm) pair and updates it from
// observed outcomes, so the schedule is estimated from evidence rather than
// guessed from a doubling rule.
//
// # Why Thompson sampling
//
// The alternative to exploring is never learning that a different delay would
// have worked. The alternative to exploiting is spending real recoveries on
// arms already known to be bad. Thompson sampling resolves this by drawing one
// value from each arm posterior and playing the winner, which allocates
// exploration in proportion to the probability an arm is genuinely best. It
// needs no schedule, no decaying epsilon and no tuning, and its regret bound is
// the reason it survived sixty years of better-marketed alternatives.
//
// # Two design decisions that matter more than the algorithm
//
// First, the action is drawn from an explicitly computed distribution rather
// than from a single posterior draw. Ordinary Thompson sampling takes one
// sample per arm and plays the argmax, which means the probability it assigned
// to the action it took is never known, only estimable afterwards. Here the
// distribution over arms is materialised first, by Monte-Carlo over the
// posteriors, and the action is then drawn from it. The logged propensity is
// therefore exact rather than reconstructed, which is precisely what
// off-policy evaluation needs and almost never gets. See internal/ope.
//
// Second, that distribution keeps a floor of probability on every permitted
// arm. A logging policy that collapses onto one action produces a log from
// which nothing else can ever be evaluated: the data has no support anywhere
// else, so tomorrow's candidate policy is unmeasurable and has to be tested on
// live traffic. Spending a small, bounded share of decisions maintaining
// support is what buys the ability to answer questions that have not been asked
// yet. See Config.Floor.
//
// # Safety
//
// The bandit never chooses from the whole action space. Select takes the set of
// arms the gatekeeper has already permitted for this incident, and it cannot
// widen it: an arm outside the permitted set is a hard error, not a clamp.
// Exploration therefore cannot breach an RBI cooling window, exceed an
// additional-factor ceiling, or retry a terminal decline, because those actions
// were removed before this package saw them. The exploration is bounded by a
// property that has been checked exhaustively over the reachable state space
// rather than by a hyperparameter someone tuned. See internal/gatekeeper and
// internal/modelcheck.
package bandit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
)

// Arm is one option the bandit can choose between. It is an opaque string so
// this package stays free of the recovery domain: the caller maps arms onto
// actions, delays and rails, and this package only ever counts them.
type Arm string

// Cell is a context bucket. Contexts are discretised rather than embedded
// because a Beta posterior per cell is auditable and a learned embedding is
// not: an operator can be shown the exact evidence behind a decision, and every
// cell is a phrase in English rather than a coordinate.
type Cell string

// Bounds. Every one of these exists because a cell key or an arm list can
// ultimately trace back to a webhook payload.
const (
	// DefaultDraws is the Monte-Carlo budget behind each action distribution.
	// Two hundred and fifty draws put the standard error of a per-arm
	// probability near three percent, which is far below the floor that
	// guarantees support and far below the resolution any policy comparison
	// needs.
	DefaultDraws = 250

	// DefaultFloor is the minimum probability held on each permitted arm.
	// Two percent across a handful of arms costs a few percent of recoveries
	// and is what keeps the log usable for evaluating policies that do not
	// exist yet.
	DefaultFloor = 0.02

	// MaxArms bounds the action space.
	MaxArms = 32

	// MaxCells bounds memory. Past it, new contexts share the overflow cell
	// rather than being rejected, so an unexpected traffic pattern degrades
	// the bandit into a less specific learner instead of failing a payment.
	MaxCells = 100_000

	// OverflowCell is where contexts land once MaxCells is reached. It is a
	// legal cell and it learns; it simply pools contexts that would otherwise
	// each have had their own posterior.
	OverflowCell Cell = "__overflow__"

	maxCellKeyLen = 160
	maxArmLen     = 64
	maxDraws      = 20_000

	// maxCount caps a posterior parameter. Beta(alpha, beta) with counts this
	// large is numerically settled, and the cap means a runaway update loop
	// cannot drive the sampler into a region where the gamma variate loses
	// precision.
	maxCount = 1e9
)

var (
	// ErrNoPermittedArms means the gatekeeper permitted nothing. That is a
	// legitimate and common outcome, and it is the caller's job to abstain.
	ErrNoPermittedArms = errors.New("bandit: no permitted arms")

	// ErrUnknownArm means the caller offered an arm the model was not
	// configured with. It is an error rather than a silent drop: a typo that
	// quietly removed an arm from consideration would show up as a policy that
	// mysteriously stopped exploring.
	ErrUnknownArm = errors.New("bandit: arm is not in the configured action space")

	// ErrInvalidConfig covers a malformed Config.
	ErrInvalidConfig = errors.New("bandit: invalid configuration")
)

// Posterior is a Beta distribution over one arm recovery probability.
//
// Alpha is one plus the observed successes and Beta is one plus the observed
// failures, so the uniform prior Beta(1,1) is the honest starting point: before
// any evidence, every recovery rate from zero to one is equally plausible.
type Posterior struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
}

// Mean is the posterior expected recovery probability.
func (p Posterior) Mean() float64 {
	den := p.Alpha + p.Beta
	if den <= 0 {
		return 0
	}
	return p.Alpha / den
}

// Observations is how many outcomes this posterior has actually seen, which is
// the number an operator needs in order to know whether to believe Mean.
func (p Posterior) Observations() float64 { return math.Max(0, p.Alpha+p.Beta-2) }

func (p Posterior) valid() bool {
	return p.Alpha > 0 && p.Beta > 0 &&
		!math.IsNaN(p.Alpha) && !math.IsNaN(p.Beta) &&
		!math.IsInf(p.Alpha, 0) && !math.IsInf(p.Beta, 0)
}

// Valuation prices the arms for one decision.
//
// The bandit learns probabilities and nothing else. Turning a probability into
// a ranking needs money, and money in this system is exact integer paisa
// computed by deterministic code, so it is supplied by the caller rather than
// learned here. That split is deliberate: a model that learned to value a
// payment would be a model with an opinion about an amount, and no model in
// this system is allowed one.
type Valuation struct {
	// GrossPaisa is what a successful recovery is worth. It comes from the
	// HMAC-verified webhook payload, never from inference.
	GrossPaisa int64

	// CostPaisa is charged for attempting an arm whether or not it succeeds:
	// a gateway fee, an out-of-band message, the friction of interrupting a
	// customer. A missing entry is zero.
	CostPaisa map[Arm]int64
}

func (v Valuation) expected(arm Arm, prob float64) float64 {
	gross := float64(0)
	if v.GrossPaisa > 0 {
		gross = float64(v.GrossPaisa)
	}
	return prob*gross - float64(v.CostPaisa[arm])
}

// Config describes an action space and how much of each decision is spent
// keeping the log usable.
type Config struct {
	// Arms is the closed action space. Order is irrelevant; it is canonicalised.
	Arms []Arm

	// Prior is the starting posterior for every unseen pair. The zero value
	// means Beta(1,1).
	Prior Posterior

	// Floor is the minimum probability placed on each permitted arm. Set it to
	// zero for a pure exploiter, which produces better recoveries today and a
	// log worth nothing tomorrow.
	Floor float64

	// Draws is the Monte-Carlo budget per decision. Zero means DefaultDraws.
	Draws int

	// Seed makes every decision reproducible. Two runs from the same seed over
	// the same incidents produce identical actions, identical propensities and
	// an identical model digest, which is what allows a learned policy to be
	// replayed by someone auditing it.
	Seed int64

	// MaxCells bounds the number of distinct contexts tracked. Zero means
	// MaxCells.
	MaxCells int
}

func (c Config) normalise() (Config, error) {
	if c.Prior == (Posterior{}) {
		c.Prior = Posterior{Alpha: 1, Beta: 1}
	}
	if c.Draws == 0 {
		c.Draws = DefaultDraws
	}
	if c.MaxCells == 0 {
		c.MaxCells = MaxCells
	}
	switch {
	case len(c.Arms) == 0:
		return c, fmt.Errorf("%w: no arms", ErrInvalidConfig)
	case len(c.Arms) > MaxArms:
		return c, fmt.Errorf("%w: %d arms exceeds the limit of %d", ErrInvalidConfig, len(c.Arms), MaxArms)
	case !c.Prior.valid():
		return c, fmt.Errorf("%w: prior Beta(%g, %g) is not a distribution", ErrInvalidConfig, c.Prior.Alpha, c.Prior.Beta)
	case c.Floor < 0 || c.Floor >= 1:
		return c, fmt.Errorf("%w: floor %g outside [0,1)", ErrInvalidConfig, c.Floor)
	case c.Draws < 1 || c.Draws > maxDraws:
		return c, fmt.Errorf("%w: draws %d outside [1, %d]", ErrInvalidConfig, c.Draws, maxDraws)
	case c.MaxCells < 1:
		return c, fmt.Errorf("%w: max cells %d is not positive", ErrInvalidConfig, c.MaxCells)
	}
	seen := make(map[Arm]struct{}, len(c.Arms))
	for _, a := range c.Arms {
		switch {
		case a == "":
			return c, fmt.Errorf("%w: empty arm name", ErrInvalidConfig)
		case len(a) > maxArmLen:
			return c, fmt.Errorf("%w: arm name longer than %d bytes", ErrInvalidConfig, maxArmLen)
		}
		if _, dup := seen[a]; dup {
			return c, fmt.Errorf("%w: duplicate arm %q", ErrInvalidConfig, a)
		}
		seen[a] = struct{}{}
	}
	c.Arms = append([]Arm(nil), c.Arms...)
	sort.Slice(c.Arms, func(i, j int) bool { return c.Arms[i] < c.Arms[j] })
	return c, nil
}

// Decision is one action together with everything needed to audit it and to
// evaluate a different policy against it later.
type Decision struct {
	// Arm is the action drawn.
	Arm Arm `json:"arm"`

	// Propensity is the exact probability this arm was drawn with. It is not
	// an estimate of the sampling probability, it is the sampling probability,
	// because the distribution was materialised before the draw.
	Propensity float64 `json:"propensity"`

	// Distribution is the full action distribution, over permitted arms only.
	// It is recorded rather than recomputed because the posteriors move with
	// every update and a distribution reconstructed tomorrow is a different
	// distribution.
	Distribution map[Arm]float64 `json:"distribution"`

	// Posteriors snapshots the belief state the decision was made under, so an
	// auditor can see the evidence rather than the conclusion.
	Posteriors map[Arm]Posterior `json:"posteriors"`

	// Cell is the context bucket used, after any overflow substitution.
	Cell Cell `json:"cell"`

	// Explored reports whether the chosen arm was not the one the model
	// considered best. It is the honest label for a decision that spent a
	// recovery on learning.
	Explored bool `json:"explored"`

	// Greedy is the arm the model would have played with no exploration.
	Greedy Arm `json:"greedy"`
}

// Model is a contextual Thompson sampler. It is safe for concurrent use.
type Model struct {
	cfg  Config
	mu   sync.Mutex
	rng  *rand.Rand
	post map[Cell]map[Arm]Posterior
}

// New builds a Model from cfg.
func New(cfg Config) (*Model, error) {
	cfg, err := cfg.normalise()
	if err != nil {
		return nil, err
	}
	return &Model{
		cfg:  cfg,
		rng:  rand.New(rand.NewSource(cfg.Seed)),
		post: make(map[Cell]map[Arm]Posterior),
	}, nil
}

// Arms returns the configured action space in canonical order.
func (m *Model) Arms() []Arm { return append([]Arm(nil), m.cfg.Arms...) }

// Select draws an action for one incident.
//
// permitted is the set the gatekeeper allowed. It is intersected with the
// configured action space rather than trusted, and an arm outside that space is
// an error, because a permitted set that has drifted from the model is a bug
// that would otherwise show up months later as an unexplained loss of
// exploration.
func (m *Model) Select(cell Cell, permitted []Arm, val Valuation) (Decision, error) {
	arms, err := m.canonicalPermitted(permitted)
	if err != nil {
		return Decision{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.cellKeyLocked(cell)
	posts := make(map[Arm]Posterior, len(arms))
	for _, a := range arms {
		posts[a] = m.posteriorLocked(key, a)
	}

	dist, greedy := m.distributionLocked(arms, posts, val)
	arm := sampleCategorical(m.rng, arms, dist)

	return Decision{
		Arm:          arm,
		Propensity:   dist[arm],
		Distribution: dist,
		Posteriors:   posts,
		Cell:         key,
		Explored:     arm != greedy,
		Greedy:       greedy,
	}, nil
}

// Distribution returns the action distribution Select would draw from, without
// drawing and without advancing the generator.
//
// This is what makes a learned policy evaluable. Off-policy evaluation needs
// pi_e(a | x) for actions that were logged under a different policy, so the
// distribution has to be readable independently of taking an action. It also
// makes the sampler testable: the distribution is the thing with a property
// worth asserting, and the draw is just a categorical.
func (m *Model) Distribution(cell Cell, permitted []Arm, val Valuation) (map[Arm]float64, error) {
	arms, err := m.canonicalPermitted(permitted)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.cellKeyLocked(cell)
	posts := make(map[Arm]Posterior, len(arms))
	for _, a := range arms {
		posts[a] = m.posteriorLocked(key, a)
	}
	dist, _ := m.distributionLocked(arms, posts, val)
	return dist, nil
}

// Update folds one observed outcome into the posterior for (cell, arm).
//
// It takes a boolean rather than a reward because the quantity being learned is
// a probability. Whether a given recovery was worth having is arithmetic the
// policy engine does in exact paisa, and mixing the two would put a money
// judgement inside a learned parameter.
func (m *Model) Update(cell Cell, arm Arm, recovered bool) error {
	if !m.known(arm) {
		return fmt.Errorf("%w: %q", ErrUnknownArm, arm)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.cellKeyLocked(cell)
	p := m.posteriorLocked(key, arm)
	if recovered {
		p.Alpha = math.Min(p.Alpha+1, maxCount)
	} else {
		p.Beta = math.Min(p.Beta+1, maxCount)
	}
	if m.post[key] == nil {
		m.post[key] = make(map[Arm]Posterior, len(m.cfg.Arms))
	}
	m.post[key][arm] = p
	return nil
}

// ---------------------------------------------------------------------------
// The distribution
// ---------------------------------------------------------------------------

// distributionLocked materialises the Thompson distribution over arms.
//
// The Monte-Carlo loop is the definition of Thompson sampling written out
// rather than approximated: draw one recovery probability from every arm
// posterior, price them with the caller valuation, and record which arm won.
// Repeating that Draws times gives the probability each arm is best, which is
// exactly the probability plain Thompson sampling would have played it with.
//
// The floor is then mixed in. Note the order: the floor is applied to the
// finished distribution, so it moves probability towards under-explored arms
// without ever taking an arm to zero and without distorting the ranking among
// arms that already have support.
func (m *Model) distributionLocked(arms []Arm, posts map[Arm]Posterior, val Valuation) (map[Arm]float64, Arm) {
	wins := make(map[Arm]float64, len(arms))
	for d := 0; d < m.cfg.Draws; d++ {
		best, bestVal := Arm(""), math.Inf(-1)
		for _, a := range arms {
			p := posts[a]
			v := val.expected(a, betaSample(m.rng, p.Alpha, p.Beta))
			// Strict improvement plus a name tie-break: without the second
			// clause, two arms with identical draws would be split by map
			// iteration order and the distribution would not be reproducible.
			if v > bestVal || (v == bestVal && a < best) {
				best, bestVal = a, v
			}
		}
		wins[best]++
	}

	dist := make(map[Arm]float64, len(arms))
	total := float64(m.cfg.Draws)
	for _, a := range arms {
		dist[a] = wins[a] / total
	}

	// A floor of f on each of k arms costs f*k of the mass; the rest is left to
	// the sampler. Capping f at 1/k keeps this a mixture rather than an
	// over-subscription when the permitted set is small.
	if f := math.Min(m.cfg.Floor, 1/float64(len(arms))); f > 0 {
		keep := 1 - f*float64(len(arms))
		for _, a := range arms {
			dist[a] = f + keep*dist[a]
		}
	}
	renormalise(arms, dist)
	return dist, greedyArm(arms, posts, val)
}

// greedyArm is the arm the model would play with no exploration at all: the one
// with the highest expected value at the posterior mean. It is reported so a
// decision can be labelled as exploration honestly, rather than inferred later
// from a distribution that has since moved.
func greedyArm(arms []Arm, posts map[Arm]Posterior, val Valuation) Arm {
	best, bestVal := Arm(""), math.Inf(-1)
	for _, a := range arms {
		if v := val.expected(a, posts[a].Mean()); v > bestVal || (v == bestVal && a < best) {
			best, bestVal = a, v
		}
	}
	return best
}

// renormalise removes the float drift left by the mixture so the distribution
// sums to one. The residual is pushed onto the largest arm, which is the only
// choice that cannot take a small probability negative.
func renormalise(arms []Arm, dist map[Arm]float64) {
	var sum float64
	for _, a := range arms {
		if dist[a] < 0 {
			dist[a] = 0
		}
		sum += dist[a]
	}
	if sum <= 0 {
		// Every arm scored zero, which can only happen if Draws produced no
		// winner and the floor is off. A uniform draw is the honest fallback.
		for _, a := range arms {
			dist[a] = 1 / float64(len(arms))
		}
		return
	}
	var largest Arm
	var largestVal float64
	var renormalised float64
	for _, a := range arms {
		dist[a] /= sum
		renormalised += dist[a]
		if dist[a] > largestVal {
			largest, largestVal = a, dist[a]
		}
	}
	dist[largest] += 1 - renormalised
}

// sampleCategorical draws one arm. The arms are visited in canonical order so
// the same generator state yields the same arm on every platform.
func sampleCategorical(rng *rand.Rand, arms []Arm, dist map[Arm]float64) Arm {
	u := rng.Float64()
	var cum float64
	for _, a := range arms {
		cum += dist[a]
		if u < cum {
			return a
		}
	}
	return arms[len(arms)-1]
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

// betaSample draws from Beta(a, b) as the ratio of two gamma variates, which is
// the standard construction and needs no rejection loop of its own.
func betaSample(rng *rand.Rand, a, b float64) float64 {
	x := gammaSample(rng, a)
	y := gammaSample(rng, b)
	if x+y <= 0 {
		// Both variates underflowed, which requires both shapes to be
		// vanishingly small. Half is the mean of the uniform prior and is the
		// only answer here that favours neither arm.
		return 0.5
	}
	return x / (x + y)
}

// gammaSample draws from Gamma(shape, 1) by Marsaglia and Tsang squeeze
// rejection.
//
// The method is used rather than a library because Go has no gamma variate in
// the standard library and because the sampler has to be reproducible: this one
// consumes the injected generator in a fixed order, so a seed replays exactly.
// Shapes below one are handled by the standard boost, since the squeeze is only
// valid for shape at least one.
func gammaSample(rng *rand.Rand, shape float64) float64 {
	if shape <= 0 || math.IsNaN(shape) {
		return 0
	}
	if shape < 1 {
		// Gamma(a) == Gamma(a+1) * U^(1/a). Drawing the uniform first keeps the
		// consumption order fixed regardless of the boost path.
		u := rng.Float64()
		if u <= 0 {
			u = math.SmallestNonzeroFloat64
		}
		return gammaSample(rng, shape+1) * math.Pow(u, 1/shape)
	}
	d := shape - 1.0/3.0
	c := 1 / math.Sqrt(9*d)
	for {
		var x, v float64
		for {
			x = rng.NormFloat64()
			v = 1 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := rng.Float64()
		if u < 1-0.0331*x*x*x*x {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// ---------------------------------------------------------------------------
// Cells and posteriors
// ---------------------------------------------------------------------------

func (m *Model) known(a Arm) bool {
	for _, x := range m.cfg.Arms {
		if x == a {
			return true
		}
	}
	return false
}

// canonicalPermitted validates the gatekeeper permitted set and returns it in
// canonical order, deduplicated.
func (m *Model) canonicalPermitted(permitted []Arm) ([]Arm, error) {
	if len(permitted) == 0 {
		return nil, ErrNoPermittedArms
	}
	seen := make(map[Arm]struct{}, len(permitted))
	out := make([]Arm, 0, len(permitted))
	for _, a := range permitted {
		if !m.known(a) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownArm, a)
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// cellKeyLocked sanitises a context key and applies the cell budget.
func (m *Model) cellKeyLocked(cell Cell) Cell {
	key := Cell(sanitizeCell(string(cell)))
	if _, ok := m.post[key]; ok {
		return key
	}
	if len(m.post) >= m.cfg.MaxCells {
		return OverflowCell
	}
	return key
}

// sanitizeCell bounds a cell key and restricts it to an alphabet safe to render
// in an ops console and to embed in an audit record. Cell keys are assembled
// from issuer codes and failure classes that originate in webhook payloads, so
// they are treated as hostile. Characters outside the set are dropped rather
// than escaped: no legitimate key needs them, and dropping cannot be undone by
// a downstream decoder.
func sanitizeCell(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxCellKeyLen; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == ':', c == '_', c == '-', c == '.', c == '|', c == '=':
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func (m *Model) posteriorLocked(cell Cell, arm Arm) Posterior {
	if cells, ok := m.post[cell]; ok {
		if p, ok := cells[arm]; ok {
			return p
		}
	}
	return m.cfg.Prior
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// CellState is one context bucket worth of learned belief.
type CellState struct {
	Cell       Cell              `json:"cell"`
	Posteriors map[Arm]Posterior `json:"posteriors"`
}

// State is the whole learned model, in a form that round-trips exactly.
type State struct {
	Arms  []Arm       `json:"arms"`
	Prior Posterior   `json:"prior"`
	Cells []CellState `json:"cells"`
}

// Snapshot exports the learned state in canonical order.
func (m *Model) Snapshot() State {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := State{Arms: append([]Arm(nil), m.cfg.Arms...), Prior: m.cfg.Prior}
	keys := make([]Cell, 0, len(m.post))
	for c := range m.post {
		keys = append(keys, c)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, c := range keys {
		cs := CellState{Cell: c, Posteriors: make(map[Arm]Posterior, len(m.post[c]))}
		for a, p := range m.post[c] {
			cs.Posteriors[a] = p
		}
		st.Cells = append(st.Cells, cs)
	}
	return st
}

// Restore loads a snapshot, replacing any learned state. Unknown arms are
// rejected so a snapshot taken against a different action space cannot be
// silently half-applied.
func (m *Model) Restore(st State) error {
	next := make(map[Cell]map[Arm]Posterior, len(st.Cells))
	for _, cs := range st.Cells {
		key := Cell(sanitizeCell(string(cs.Cell)))
		if _, dup := next[key]; dup {
			return fmt.Errorf("bandit: duplicate cell %q in snapshot", key)
		}
		cells := make(map[Arm]Posterior, len(cs.Posteriors))
		for a, p := range cs.Posteriors {
			if !m.known(a) {
				return fmt.Errorf("%w: %q in snapshot for cell %q", ErrUnknownArm, a, key)
			}
			if !p.valid() {
				return fmt.Errorf("bandit: cell %q arm %q holds an invalid posterior Beta(%g, %g)", key, a, p.Alpha, p.Beta)
			}
			cells[a] = p
		}
		next[key] = cells
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.post = next
	return nil
}

// Digest is a stable hash of the learned state.
//
// It exists so a policy can be named by what it believes rather than by when it
// was saved. Committing this digest to the audit ledger alongside a decision
// pins the exact belief state that produced it, which is what allows the
// decision to be re-derived years later by someone who does not trust the
// person presenting it. Fields are absorbed length-prefixed, matching
// internal/audit, so no rearrangement of cell and arm names can produce a
// second state with the same digest.
func (m *Model) Digest() string {
	st := m.Snapshot()
	h := sha256.New()
	absorb(h, "resilientmesh.bandit.v1")
	absorb(h, fmt.Sprintf("%g:%g", st.Prior.Alpha, st.Prior.Beta))
	for _, a := range st.Arms {
		absorb(h, string(a))
	}
	for _, cs := range st.Cells {
		absorb(h, string(cs.Cell))
		arms := make([]Arm, 0, len(cs.Posteriors))
		for a := range cs.Posteriors {
			arms = append(arms, a)
		}
		sort.Slice(arms, func(i, j int) bool { return arms[i] < arms[j] })
		for _, a := range arms {
			p := cs.Posteriors[a]
			absorb(h, string(a))
			absorb(h, fmt.Sprintf("%g:%g", p.Alpha, p.Beta))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func absorb(h interface{ Write([]byte) (int, error) }, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

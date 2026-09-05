// Package tuner is the production seat for the learner.
//
// internal/bandit knows how to hold a posterior and draw from it. It knows
// nothing about payments. This package is the small amount of glue that turns
// that into a recovery schedule: it owns the delay vocabulary, it works out
// which of those delays the gatekeeper has already agreed to, and it produces a
// decision with the propensity attached so the choice can be evaluated later.
//
// # How the gate bounds it
//
// The gatekeeper computes a delay of its own from the deterministic policy
// engine, and it will honour a proposal that asks for a longer wait while
// discarding one that asks for a shorter one. That asymmetry exists because
// only the aggressive direction spends money and trips issuer abuse
// heuristics, and it happens to be exactly the containment a learner needs. The
// permitted set is therefore every delay at or above whatever the gate said,
// and it is derived by asking the gate rather than by reimplementing it.
//
// The consequence is worth stating plainly: a recurring debit inside the RBI
// cooling window has one permitted arm, a terminal decline has none, and no
// amount of exploration can produce an attempt the invariants would have
// refused. Exploration is bounded by a property that has been checked
// exhaustively over 510,720 reachable states rather than by a hyperparameter.
//
// # What gets written down
//
// Decision carries the probability the chosen delay was drawn with. Committing
// that to the hash-chained ledger at decision time, before the outcome of the
// attempt exists, is what makes the log usable for off-policy evaluation months
// later. A propensity reconstructed after the outcomes are known can be tuned
// until the answer flatters whoever is presenting it, and there is no way to
// tell from the numbers alone. See internal/audit and internal/ope.
package tuner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// The delay vocabulary.
//
// Five buckets spanning five minutes to a day. Fewer would not resolve an
// issuer settlement window; more would split the evidence until no cell had
// enough of it. They are named rather than numeric so an audit record reads as
// a decision rather than as an integer.
const (
	ArmFast      bandit.Arm = "retry_after_5m"
	ArmShort     bandit.Arm = "retry_after_30m"
	ArmMedium    bandit.Arm = "retry_after_2h"
	ArmLong      bandit.Arm = "retry_after_6h"
	ArmOvernight bandit.Arm = "retry_after_24h"
)

// Arms is the closed action space in canonical order.
var Arms = []bandit.Arm{ArmFast, ArmShort, ArmMedium, ArmLong, ArmOvernight}

var armSeconds = map[bandit.Arm]int64{
	ArmFast:      5 * 60,
	ArmShort:     30 * 60,
	ArmMedium:    2 * 3600,
	ArmLong:      6 * 3600,
	ArmOvernight: 24 * 3600,
}

var armLabels = map[bandit.Arm]string{
	ArmFast:      "5 minutes",
	ArmShort:     "30 minutes",
	ArmMedium:    "2 hours",
	ArmLong:      "6 hours",
	ArmOvernight: "24 hours",
}

// ArmSeconds is the delay an arm schedules. An unknown arm returns zero, which
// no caller may treat as a legal delay.
func ArmSeconds(a bandit.Arm) int64 { return armSeconds[a] }

// ArmLabel renders an arm for an operator.
func ArmLabel(a bandit.Arm) string {
	if l, ok := armLabels[a]; ok {
		return l
	}
	return string(a)
}

// PermittedFor returns the arms at or above the delay the gatekeeper computed.
//
// Below that floor the gate discards a proposal and substitutes its own value,
// so an arm shorter than the floor is not a choice the system can make. It is
// excluded here rather than offered and then silently overridden, because an
// action that is logged as chosen and never taken corrupts the propensity
// record for every future evaluation.
func PermittedFor(gateFloorSeconds int64) []bandit.Arm {
	out := make([]bandit.Arm, 0, len(Arms))
	for _, a := range Arms {
		if armSeconds[a] >= gateFloorSeconds {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CellFor buckets an incident into the context the learner keys on.
//
// Four observable facts and nothing else: which institution declined, what kind
// of failure it was, roughly when in the local day, and how many attempts have
// already been spent. Hours are grouped into three-hour blocks, which is coarse
// enough that a cell accumulates evidence within a week and fine enough to
// express a settlement window.
//
// Every component is already a bounded token elsewhere in this system, and the
// cell key is sanitised again inside internal/bandit, because the issuer
// component ultimately derives from a webhook payload.
func CellFor(issuerKey string, class domain.FailureClass, hour, attempt int) bandit.Cell {
	if hour < 0 || hour > 23 {
		hour = 0
	}
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 3 {
		attempt = 3
	}
	return bandit.Cell(fmt.Sprintf("issuer=%s|class=%s|hb=%d|att=%d", issuerKey, class, hour/3, attempt))
}

// Config describes a tuner.
type Config struct {
	// Floor is the minimum probability held on each permitted arm. It is the
	// price of keeping the log evaluable, and setting it to zero buys a few
	// more recoveries today in exchange for a log from which no future policy
	// can ever be assessed without shipping it to production first.
	Floor float64

	// Draws is the Monte-Carlo budget behind each decision.
	Draws int

	// Seed makes the schedule reproducible.
	Seed int64

	// Prior is the starting belief for an unseen pair. The zero value is the
	// uniform Beta(1,1), which is the honest position before any evidence.
	Prior bandit.Posterior
}

// DefaultFloor is the exploration floor used when Config leaves it unset.
//
// Two percent on each of up to five arms costs a few percent of recoveries and
// buys the ability to answer, at any point in the future, what a policy that
// does not exist yet would have earned. That trade is only obviously worth
// making if the second half is written down, so it is.
const DefaultFloor = 0.02

// Tuner chooses a retry delay and remembers how it went.
type Tuner struct {
	model *bandit.Model

	// mu guards nothing in the model, which is already safe for concurrent
	// use, but does guard the counters below.
	mu       sync.Mutex
	decided  uint64
	explored uint64
}

// New builds a Tuner over the delay vocabulary.
func New(cfg Config) (*Tuner, error) {
	if cfg.Floor == 0 {
		cfg.Floor = DefaultFloor
	}
	m, err := bandit.New(bandit.Config{
		Arms:  Arms,
		Prior: cfg.Prior,
		Floor: cfg.Floor,
		Draws: cfg.Draws,
		Seed:  cfg.Seed,
	})
	if err != nil {
		return nil, err
	}
	return &Tuner{model: m}, nil
}

// Decision is one scheduling choice and everything needed to audit or
// re-evaluate it.
type Decision struct {
	Cell       bandit.Cell            `json:"cell"`
	Arm        bandit.Arm             `json:"arm"`
	DelaySec   int64                  `json:"delay_seconds"`
	Propensity float64                `json:"propensity"`
	Dist       map[bandit.Arm]float64 `json:"distribution"`
	Permitted  []bandit.Arm           `json:"permitted"`
	Explored   bool                   `json:"explored"`
	Greedy     bandit.Arm             `json:"greedy_arm"`

	// ModelDigest pins the belief state this decision was drawn from, so the
	// decision can be re-derived by someone who does not trust the person
	// presenting it.
	ModelDigest string `json:"model_digest"`
}

// Choose draws a delay for one incident.
//
// gateFloorSeconds is what the gatekeeper computed unaided. amountPaisa is the
// verified amount and feePaisa the cost of an attempt; both are exact integers
// from the payment and neither is ever learned.
func (t *Tuner) Choose(cell bandit.Cell, gateFloorSeconds, amountPaisa, feePaisa int64) (Decision, error) {
	permitted := PermittedFor(gateFloorSeconds)
	if len(permitted) == 0 {
		return Decision{}, bandit.ErrNoPermittedArms
	}

	costs := make(map[bandit.Arm]int64, len(permitted))
	for _, a := range permitted {
		costs[a] = feePaisa
	}
	d, err := t.model.Select(cell, permitted, bandit.Valuation{GrossPaisa: amountPaisa, CostPaisa: costs})
	if err != nil {
		return Decision{}, err
	}

	t.mu.Lock()
	t.decided++
	if d.Explored {
		t.explored++
	}
	t.mu.Unlock()

	return Decision{
		Cell:        d.Cell,
		Arm:         d.Arm,
		DelaySec:    armSeconds[d.Arm],
		Propensity:  d.Propensity,
		Dist:        d.Distribution,
		Permitted:   permitted,
		Explored:    d.Explored,
		Greedy:      d.Greedy,
		ModelDigest: t.model.Digest(),
	}, nil
}

// Observe folds one outcome back into the posterior.
func (t *Tuner) Observe(cell bandit.Cell, arm bandit.Arm, recovered bool) error {
	return t.model.Update(cell, arm, recovered)
}

// Stats reports how much of the traffic has been spent on exploration, which is
// the number an operator wants when deciding whether the floor is set right.
type Stats struct {
	Decisions   uint64  `json:"decisions"`
	Explored    uint64  `json:"explored"`
	ExploreRate float64 `json:"explore_rate"`
	Digest      string  `json:"model_digest"`
}

// Stats returns a snapshot of the counters and the belief digest.
func (t *Tuner) Stats() Stats {
	t.mu.Lock()
	decided, explored := t.decided, t.explored
	t.mu.Unlock()

	s := Stats{Decisions: decided, Explored: explored, Digest: t.model.Digest()}
	if decided > 0 {
		s.ExploreRate = float64(explored) / float64(decided)
	}
	return s
}

// Snapshot exports the learned state for persistence or for an audit record.
func (t *Tuner) Snapshot() bandit.State { return t.model.Snapshot() }

// Restore loads a previously exported state.
func (t *Tuner) Restore(st bandit.State) error { return t.model.Restore(st) }

// Digest identifies the current belief state.
func (t *Tuner) Digest() string { return t.model.Digest() }

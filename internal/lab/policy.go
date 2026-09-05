package lab

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/tuner"
)

// Policy is a distribution over permitted arms.
//
// It returns a distribution rather than an action, and that is the whole
// design. A policy that returns an action can be run but cannot be evaluated:
// off-policy evaluation needs the probability a policy would have assigned to
// an action it did not take, on an incident it never saw. Making the
// distribution the primitive and the draw a consequence means every policy in
// this system is evaluable by construction.
type Policy interface {
	Name() string

	// Distribution must return a probability for every permitted arm and for
	// no others. Implementations may assume permitted is non-empty and in
	// canonical order.
	Distribution(inc Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error)
}

// Learner is a policy that changes as outcomes arrive.
//
// The distinction is load-bearing. A learner is not a fixed policy, so the
// value it will have tomorrow is not the value it has today, and evaluating one
// off-policy is a strictly harder problem than the estimators in internal/ope
// solve. What can be evaluated honestly is a frozen snapshot of what it
// currently believes. See Freeze.
type Learner interface {
	Policy
	Observe(inc Incident, arm bandit.Arm, recovered bool) error
}

var (
	// ErrEmptyPermitted means a policy was asked to decide with no legal
	// action, which is the caller failing to check the gate.
	ErrEmptyPermitted = errors.New("lab: policy asked to choose from an empty permitted set")

	// ErrBadDistribution means a policy returned something that is not a
	// probability distribution over the permitted arms.
	ErrBadDistribution = errors.New("lab: policy returned a malformed distribution")
)

// CheckDistribution validates a policy output.
//
// Every distribution crossing a package boundary here is checked, because a
// distribution that does not sum to one silently corrupts every importance
// weight computed from it, and the resulting off-policy number looks entirely
// reasonable.
func CheckDistribution(dist map[bandit.Arm]float64, permitted []bandit.Arm) error {
	if len(permitted) == 0 {
		return ErrEmptyPermitted
	}
	allowed := make(map[bandit.Arm]struct{}, len(permitted))
	for _, a := range permitted {
		allowed[a] = struct{}{}
	}
	var sum float64
	for a, p := range dist {
		if _, ok := allowed[a]; !ok {
			return fmt.Errorf("%w: arm %q is not permitted", ErrBadDistribution, a)
		}
		if p < 0 || p > 1 {
			return fmt.Errorf("%w: arm %q has probability %g", ErrBadDistribution, a, p)
		}
		sum += p
	}
	if sum < 1-1e-9 || sum > 1+1e-9 {
		return fmt.Errorf("%w: probabilities sum to %g", ErrBadDistribution, sum)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Backoff: the status quo
// ---------------------------------------------------------------------------

// Backoff plays the shortest arm the gatekeeper allows, every time.
//
// This is what the system does today, and what almost every recovery stack
// does: take the delay the deterministic policy engine computed and use it. It
// is included as the baseline every other policy is measured against, and as
// the demonstration of why a deterministic logging policy is a dead end. A log
// produced by this policy contains no information about any other arm, so
// nothing can ever be evaluated against it without shipping it to production
// first. internal/ope refuses such a log rather than guessing, which is the
// behaviour to want.
type Backoff struct{}

func (Backoff) Name() string { return "backoff" }

func (Backoff) Distribution(_ Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	if len(permitted) == 0 {
		return nil, ErrEmptyPermitted
	}
	out := make(map[bandit.Arm]float64, len(permitted))
	for _, a := range permitted {
		out[a] = 0
	}
	out[shortest(permitted)] = 1
	return out, nil
}

// ---------------------------------------------------------------------------
// Uniform: maximal support, minimal intelligence
// ---------------------------------------------------------------------------

// Uniform spreads evenly over the permitted arms.
//
// It recovers less than anything else here and it produces the most informative
// log possible, which is the trade every exploration scheme is negotiating. It
// is useful as an upper bound on how much a log can be worth.
type Uniform struct{}

func (Uniform) Name() string { return "uniform" }

func (Uniform) Distribution(_ Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	if len(permitted) == 0 {
		return nil, ErrEmptyPermitted
	}
	out := make(map[bandit.Arm]float64, len(permitted))
	for _, a := range permitted {
		out[a] = 1 / float64(len(permitted))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Bandit
// ---------------------------------------------------------------------------

// Bandit is the Thompson sampler from internal/bandit driving this world.
type Bandit struct {
	Model *bandit.Model
	label string
}

// NewBandit wraps a model.
func NewBandit(m *bandit.Model, label string) *Bandit {
	if label == "" {
		label = "bandit"
	}
	return &Bandit{Model: m, label: label}
}

func (b *Bandit) Name() string { return b.label }

func (b *Bandit) Distribution(inc Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	return b.Model.Distribution(inc.Cell(), permitted, valuation(inc))
}

// Observe folds one outcome back into the posteriors.
func (b *Bandit) Observe(inc Incident, arm bandit.Arm, recovered bool) error {
	return b.Model.Update(inc.Cell(), arm, recovered)
}

// Freeze captures what the bandit currently believes as a fixed policy.
//
// A learner cannot be the target of an off-policy estimate, because the thing
// being estimated has to be a function and a learner is a process. Freezing it
// makes the question well posed: not "what will this bandit be worth" but "what
// is what it has learned so far worth". That is also the honest thing to deploy
// behind a review, since a frozen policy is one an operator can read.
func (b *Bandit) Freeze(label string) (*Frozen, error) {
	snap := b.Model.Snapshot()
	clone, err := bandit.New(bandit.Config{
		Arms:  snap.Arms,
		Prior: snap.Prior,
		Floor: 0, // a frozen policy is being evaluated, not gathering evidence
		Seed:  0,
	})
	if err != nil {
		return nil, err
	}
	if err := clone.Restore(snap); err != nil {
		return nil, err
	}
	if label == "" {
		label = b.label + "-frozen"
	}
	return &Frozen{model: clone, label: label, digest: b.Model.Digest()}, nil
}

// Frozen is a bandit belief state with the learning switched off.
type Frozen struct {
	model  *bandit.Model
	label  string
	digest string
}

func (f *Frozen) Name() string { return f.label }

// Digest identifies the belief state this policy was frozen from, so a
// counterfactual claim can name the exact model it was made about.
func (f *Frozen) Digest() string { return f.digest }

func (f *Frozen) Distribution(inc Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	return f.model.Distribution(inc.Cell(), permitted, valuation(inc))
}

// valuation prices the arms for one incident.
//
// The gross figure is the verified amount and the cost is the gateway fee. Both
// are exact paisa taken from the payment, never from a model, which keeps the
// learned component a probability and nothing else.
func valuation(inc Incident) bandit.Valuation {
	costs := make(map[bandit.Arm]int64, len(Arms))
	for _, a := range Arms {
		costs[a] = GatewayFeePaisa
	}
	return bandit.Valuation{GrossPaisa: inc.AmountPaisa(), CostPaisa: costs}
}

// ---------------------------------------------------------------------------
// Hypotheses
// ---------------------------------------------------------------------------

// Hypothesis is a claim that one slice of traffic should be treated
// differently, expressed in a closed grammar.
//
// The grammar is the containment. A hypothesis is generated by a language model
// reading an audit log, and a free-form one would be an instruction from an
// untrusted source to a system that moves money. This type is the only shape
// such a suggestion can take: three optional filters over fields that already
// exist, and one arm from the closed action space. There is no field here in
// which a model could express an amount, a customer, a rail, or a rule. The
// worst a malicious or hallucinated hypothesis can do is name a segment that
// does not exist, which fails its significance test and is recorded as refuted.
type Hypothesis struct {
	// ID is a short stable handle.
	ID string `json:"id"`

	// Description is the model own words, kept for the record and never parsed.
	Description string `json:"description"`

	// IssuerKey restricts the segment to one institution. Empty means any.
	IssuerKey string `json:"issuer_key,omitempty"`

	// FromHour and ToHour restrict it to a local window, inclusive of FromHour
	// and exclusive of ToHour. Both zero means any hour.
	FromHour int `json:"from_hour,omitempty"`
	ToHour   int `json:"to_hour,omitempty"`

	// Class restricts it to one causal classification. Empty means any.
	Class domain.FailureClass `json:"class,omitempty"`

	// Arm is what to do inside the segment.
	Arm bandit.Arm `json:"arm"`
}

// MaxHypothesisTextLen bounds the free text carried alongside a hypothesis.
const MaxHypothesisTextLen = 400

// Validate rejects a hypothesis that is malformed, unbounded, or names
// something outside the closed vocabularies.
//
// It rejects rather than repairs. A hypothesis that has been quietly corrected
// is no longer the one the model proposed, and the audit record would then
// attribute a claim to a model that never made it.
func (h *Hypothesis) Validate() error {
	h.ID = sanitiseHandle(h.ID, 48)
	h.Description = clampText(h.Description, MaxHypothesisTextLen)
	if h.ID == "" {
		return fmt.Errorf("%w: hypothesis has no usable id", ErrBadHypothesis)
	}
	if tuner.ArmSeconds(h.Arm) == 0 {
		return fmt.Errorf("%w: arm %q is not in the action space", ErrBadHypothesis, sanitiseHandle(string(h.Arm), 32))
	}
	if h.IssuerKey != "" {
		h.IssuerKey = sanitiseHandle(h.IssuerKey, 64)
		if !knownIssuer(h.IssuerKey) {
			return fmt.Errorf("%w: issuer %q does not appear in this corpus", ErrBadHypothesis, h.IssuerKey)
		}
	}
	if h.Class != "" {
		if h.Class = domain.ParseFailureClass(string(h.Class)); h.Class == domain.ClassUnknown {
			return fmt.Errorf("%w: failure class is not in the closed set", ErrBadHypothesis)
		}
	}
	if h.FromHour != 0 || h.ToHour != 0 {
		if h.FromHour < 0 || h.ToHour > 24 || h.FromHour >= h.ToHour {
			return fmt.Errorf("%w: window [%d, %d) is not a range of hours", ErrBadHypothesis, h.FromHour, h.ToHour)
		}
	}
	if h.IssuerKey == "" && h.Class == "" && h.FromHour == 0 && h.ToHour == 0 {
		// A hypothesis with no filters is not a segment, it is a wholesale
		// policy change wearing a segment costume.
		return fmt.Errorf("%w: a hypothesis must restrict at least one of issuer, class or hour", ErrBadHypothesis)
	}
	return nil
}

// ErrBadHypothesis means a proposed segment did not survive validation.
var ErrBadHypothesis = errors.New("lab: malformed hypothesis")

// Matches reports whether an incident falls inside the segment.
func (h Hypothesis) Matches(inc Incident) bool {
	if h.IssuerKey != "" && inc.IssuerKey != h.IssuerKey {
		return false
	}
	if h.Class != "" && inc.Class != h.Class {
		return false
	}
	if h.FromHour != 0 || h.ToHour != 0 {
		if inc.HourIST < h.FromHour || inc.HourIST >= h.ToHour {
			return false
		}
	}
	return true
}

// String renders the segment as a phrase an operator can check.
func (h Hypothesis) String() string {
	var parts []string
	if h.IssuerKey != "" {
		parts = append(parts, h.IssuerKey)
	}
	if h.Class != "" {
		parts = append(parts, string(h.Class))
	}
	if h.FromHour != 0 || h.ToHour != 0 {
		parts = append(parts, fmt.Sprintf("%02d:00-%02d:00", h.FromHour, h.ToHour))
	}
	if len(parts) == 0 {
		parts = append(parts, "all traffic")
	}
	return strings.Join(parts, " ") + " retried after " + ArmLabel(h.Arm)
}

// Segment is the policy a hypothesis induces: inside the segment play the
// nominated arm, outside it defer to the base policy unchanged.
//
// The deferral matters for evaluation as much as for behaviour. A candidate
// policy that differs from the deployed one everywhere overlaps with the log
// almost nowhere, and the estimate collapses to noise. Changing one slice and
// leaving the rest alone keeps the effective sample size high, which is the
// difference between a measurable proposal and an unmeasurable one.
type Segment struct {
	H    Hypothesis
	Base Policy
}

// NewSegment builds the policy a hypothesis describes.
func NewSegment(h Hypothesis, base Policy) (*Segment, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	if base == nil {
		base = Backoff{}
	}
	return &Segment{H: h, Base: base}, nil
}

func (s *Segment) Name() string { return "segment:" + s.H.ID }

func (s *Segment) Distribution(inc Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	if len(permitted) == 0 {
		return nil, ErrEmptyPermitted
	}
	if !s.H.Matches(inc) || !allowed(permitted, s.H.Arm) {
		// Outside the segment, or inside it but with the nominated arm removed
		// by the gate, the hypothesis has nothing to say and the base policy
		// stands. A segment policy that overrode the gate would not be a
		// hypothesis, it would be a bypass.
		return s.Base.Distribution(inc, permitted)
	}
	out := make(map[bandit.Arm]float64, len(permitted))
	for _, a := range permitted {
		out[a] = 0
	}
	out[s.H.Arm] = 1
	return out, nil
}

// Covers reports how many of the given incidents fall inside the segment, which
// is the first thing to check about a proposal: a hypothesis about eleven
// payments is not worth evaluating however large its effect looks.
func (s *Segment) Covers(incidents []Incident) int {
	var n int
	for _, inc := range incidents {
		if s.H.Matches(inc) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func shortest(permitted []bandit.Arm) bandit.Arm {
	best, bestSec := permitted[0], tuner.ArmSeconds(permitted[0])
	for _, a := range permitted[1:] {
		if s := tuner.ArmSeconds(a); s < bestSec || (s == bestSec && a < best) {
			best, bestSec = a, s
		}
	}
	return best
}

func allowed(permitted []bandit.Arm, a bandit.Arm) bool {
	for _, p := range permitted {
		if p == a {
			return true
		}
	}
	return false
}

func knownIssuer(key string) bool {
	for _, s := range issuers {
		if s.key == key {
			return true
		}
	}
	return false
}

// Issuers lists the institutions present in this world, for a proposer that
// needs to know what it is allowed to name.
func Issuers() []string {
	out := make([]string, 0, len(issuers))
	for _, s := range issuers {
		out = append(out, s.key)
	}
	sort.Strings(out)
	return out
}

// sanitiseHandle restricts an identifier that may have arrived from a model to
// a rendering-safe alphabet, dropping anything else. Dropping rather than
// escaping is the same choice made everywhere else in this system: no
// legitimate value needs those bytes, and a drop cannot be undone by a
// downstream decoder the way an escape can.
func sanitiseHandle(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == ':', c == '_', c == '-', c == '.':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// clampText bounds free text from a model and strips control characters, since
// the result is rendered in an operator console and written to the ledger.
func clampText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

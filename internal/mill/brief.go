// Package mill is where the model stops classifying and starts proposing.
//
// Everywhere else in this system a language model answers a question that has
// one right answer: what kind of failure is this. It is a classifier, it is
// contained by a gatekeeper, and it never learns anything. That is defensible
// and it is also not much of an AI system.
//
// This package gives the model the job it is actually good at and that nobody
// else in the stack can do: reading a large, boring log and noticing that one
// slice of it does not behave like the rest. It proposes; it does not decide.
// Every proposal is a typed segment drawn from a closed grammar, and every one
// is put through an off-policy estimator that either finds a significant effect
// on data the model never influenced or refutes it. The model cannot make a
// claim true by asserting it confidently, which is the failure mode that makes
// language models unusable for analysis everywhere else.
//
// The division of labour:
//
//	the model      proposes where to look
//	internal/ope   decides whether the proposal survives contact with the data
//	the gatekeeper bounds what any surviving proposal is allowed to do
//	internal/audit records both the survivors and the refutations
//
// # Why this is worth doing
//
// A contextual bandit learns weights inside a feature space someone chose. That
// someone is a person, the choice is slow, and it goes stale: the segment that
// matters this quarter is a bank that changed its settlement window last month.
// Automating the proposal step is the difference between a system that
// optimises what it was told to optimise and one that finds the thing nobody
// thought to measure.
//
// # Containment
//
// The model sees Brief and nothing else. A brief is counts and rates over
// issuer keys, failure classes, hour blocks and delay buckets: no payment id,
// no amount, no customer, no free text from any payload. There is therefore no
// text in the prompt that an attacker who controls a webhook body could have
// written. The output is parsed into lab.Hypothesis, which has three optional
// filters and one arm from a closed set, and anything that fails validation is
// discarded rather than repaired. The worst a compromised or hallucinating
// model can achieve is to waste a significance test.
//
// # Multiple comparisons
//
// Testing twenty hypotheses at 95% confidence produces one false discovery per
// round, reliably, forever. Run widens every interval by the number of
// hypotheses under test so the chance of any false survivor stays at the stated
// level. It is the single most important line in this package and it is one
// line. See Options.FamilyAlpha.
//
// The specificity of that is tested against a world built with the planted
// effect flattened, so a hypothesis naming it is a claim about something that
// is not there and has to be refused. Permuting the outcomes of a real world
// would have been the obvious null and is not one: it removes the covariance
// the bootstrap resamples while leaving a finite-sample offset in the point
// estimate, so the interval narrows around a value that did not move.
package mill

import (
	"context"
	"fmt"
	"sort"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/lab"
)

// Evidence thresholds. A cell below these is noise being described in
// confident language, so it never reaches the model at all.
const (
	// MinCellPlays is the number of decisions a segment needs before it appears
	// in a brief.
	MinCellPlays = 60

	// MinArmPlays is the number of times one arm must have been played inside a
	// segment for its observed rate to be quoted.
	MinArmPlays = 15

	// MaxBriefSegments bounds the brief. A prompt containing every cell would
	// be mostly noise and would cost more than the discovery is worth; the
	// segments are ranked by how much evidence they carry before truncation.
	MaxBriefSegments = 48
)

// ArmStat is how one delay performed across the whole log.
type ArmStat struct {
	Arm      bandit.Arm `json:"arm"`
	Label    string     `json:"label"`
	Plays    int        `json:"plays"`
	Recovery float64    `json:"recovery_rate"`
}

// SegmentStat is how the arms performed inside one context bucket.
//
// The bucket is (issuer, hour block), which is the coarsest grouping that can
// still express a settlement window. Finer buckets would produce more segments
// and less evidence in each.
type SegmentStat struct {
	IssuerKey string `json:"issuer_key"`
	HourBlock int    `json:"hour_block"`
	FromHour  int    `json:"from_hour"`
	ToHour    int    `json:"to_hour"`
	Plays     int    `json:"plays"`

	// Recovery is the segment overall rate, which is the number each arm below
	// should be read against.
	Recovery float64 `json:"recovery_rate"`

	// Arms holds only the delays with enough plays inside this segment for
	// their rate to mean anything.
	Arms []ArmStat `json:"arms"`
}

// ClassStat is how the arms performed for one causal classification.
type ClassStat struct {
	Class    string    `json:"class"`
	Plays    int       `json:"plays"`
	Recovery float64   `json:"recovery_rate"`
	Arms     []ArmStat `json:"arms"`
}

// Brief is everything the proposer is allowed to see.
//
// It is aggregate by construction. Nothing here identifies a payment, a
// customer or an amount, and nothing here is free text that arrived in a
// webhook. That is what makes it safe to put in a prompt, and it is the same
// argument domain.DiagnosticContext makes for the classification path.
type Brief struct {
	Decisions int     `json:"decisions"`
	Recovery  float64 `json:"overall_recovery_rate"`

	// Vocabulary is the closed set the proposer may name. Anything outside it
	// is rejected by lab.Hypothesis.Validate, so stating it up front turns a
	// rejection into a non-event.
	Issuers []string     `json:"issuers"`
	Classes []string     `json:"classes"`
	Arms    []ArmStat    `json:"arms"`
	Hours   []HourWindow `json:"hour_blocks"`

	Segments  []SegmentStat `json:"segments"`
	Classwise []ClassStat   `json:"classwise"`
}

// HourWindow names one three-hour block, matching the bucketing in
// lab.Incident.Cell so a proposal can be expressed in the same units the
// learner keys on.
type HourWindow struct {
	Block int `json:"block"`
	From  int `json:"from_hour"`
	To    int `json:"to_hour"`
}

// BuildBrief aggregates a log into the evidence a proposer works from.
//
// It reads outcomes, which is the whole point: a proposer that could only see
// the corpus shape would be guessing. It never reads the latent model, so the
// brief contains exactly what a real merchant log would contain.
func BuildBrief(w *lab.World, run lab.RunResult) Brief {
	incidents := w.Incidents()

	b := Brief{
		Decisions: len(run.Log),
		Recovery:  run.RecoveryRate,
		Issuers:   lab.Issuers(),
		Classes:   classVocabulary(),
	}
	for block := 0; block < 8; block++ {
		b.Hours = append(b.Hours, HourWindow{Block: block, From: block * 3, To: block*3 + 3})
	}

	type counter struct {
		plays, wins int
	}
	overallArm := map[bandit.Arm]*counter{}
	type segKey struct {
		issuer string
		block  int
	}
	segTotals := map[segKey]*counter{}
	segArms := map[segKey]map[bandit.Arm]*counter{}
	classTotals := map[string]*counter{}
	classArms := map[string]map[bandit.Arm]*counter{}

	bump := func(c *counter, won bool) {
		c.plays++
		if won {
			c.wins++
		}
	}
	get := func(m map[bandit.Arm]*counter, a bandit.Arm) *counter {
		if c, ok := m[a]; ok {
			return c
		}
		c := &counter{}
		m[a] = c
		return c
	}

	for _, e := range run.Log {
		inc := incidents[e.Index]
		bump(get(overallArm, e.Arm), e.Recovered)

		sk := segKey{inc.IssuerKey, inc.HourIST / 3}
		if segTotals[sk] == nil {
			segTotals[sk] = &counter{}
			segArms[sk] = map[bandit.Arm]*counter{}
		}
		bump(segTotals[sk], e.Recovered)
		bump(get(segArms[sk], e.Arm), e.Recovered)

		cls := string(inc.Class)
		if classTotals[cls] == nil {
			classTotals[cls] = &counter{}
			classArms[cls] = map[bandit.Arm]*counter{}
		}
		bump(classTotals[cls], e.Recovered)
		bump(get(classArms[cls], e.Arm), e.Recovered)
	}

	for _, a := range lab.Arms {
		if c := overallArm[a]; c != nil && c.plays > 0 {
			b.Arms = append(b.Arms, ArmStat{
				Arm: a, Label: lab.ArmLabel(a), Plays: c.plays, Recovery: rate(c.wins, c.plays),
			})
		}
	}

	keys := make([]segKey, 0, len(segTotals))
	for k := range segTotals {
		keys = append(keys, k)
	}
	// Sorted before truncation so a brief is a pure function of the log rather
	// than of Go map iteration order, which would make a discovery run
	// unreproducible for no reason at all.
	sort.Slice(keys, func(i, j int) bool {
		a, bb := segTotals[keys[i]], segTotals[keys[j]]
		if a.plays != bb.plays {
			return a.plays > bb.plays
		}
		if keys[i].issuer != keys[j].issuer {
			return keys[i].issuer < keys[j].issuer
		}
		return keys[i].block < keys[j].block
	})

	for _, k := range keys {
		total := segTotals[k]
		if total.plays < MinCellPlays {
			continue
		}
		if len(b.Segments) >= MaxBriefSegments {
			break
		}
		seg := SegmentStat{
			IssuerKey: k.issuer,
			HourBlock: k.block,
			FromHour:  k.block * 3,
			ToHour:    k.block*3 + 3,
			Plays:     total.plays,
			Recovery:  rate(total.wins, total.plays),
		}
		for _, a := range lab.Arms {
			c := segArms[k][a]
			if c == nil || c.plays < MinArmPlays {
				continue
			}
			seg.Arms = append(seg.Arms, ArmStat{
				Arm: a, Label: lab.ArmLabel(a), Plays: c.plays, Recovery: rate(c.wins, c.plays),
			})
		}
		if len(seg.Arms) < 2 {
			// One arm cannot be compared against anything, so the row would
			// only invite a proposal with no basis.
			continue
		}
		b.Segments = append(b.Segments, seg)
	}

	classes := make([]string, 0, len(classTotals))
	for c := range classTotals {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, cls := range classes {
		total := classTotals[cls]
		if total.plays < MinCellPlays {
			continue
		}
		cs := ClassStat{Class: cls, Plays: total.plays, Recovery: rate(total.wins, total.plays)}
		for _, a := range lab.Arms {
			c := classArms[cls][a]
			if c == nil || c.plays < MinArmPlays {
				continue
			}
			cs.Arms = append(cs.Arms, ArmStat{
				Arm: a, Label: lab.ArmLabel(a), Plays: c.plays, Recovery: rate(c.wins, c.plays),
			})
		}
		if len(cs.Arms) < 2 {
			continue
		}
		b.Classwise = append(b.Classwise, cs)
	}
	return b
}

func rate(wins, plays int) float64 {
	if plays <= 0 {
		return 0
	}
	// Rounded to four places so a brief serialises identically on every
	// platform and a cassette recorded on one machine replays on another.
	return float64(int(float64(wins)/float64(plays)*10000+0.5)) / 10000
}

func classVocabulary() []string {
	return []string{
		"TRANSIENT_ISSUER_DEGRADATION",
		"ISSUER_OUTAGE",
		"NETWORK_TIMEOUT",
		"PSP_DEGRADATION",
		"CUSTOMER_ACTION_REQUIRED",
		"INSUFFICIENT_FUNDS",
		"INSTRUMENT_STALE",
	}
}

// ---------------------------------------------------------------------------
// The deterministic proposer
// ---------------------------------------------------------------------------

// Heuristic proposes segments by enumeration and arithmetic.
//
// It exists for three reasons. It is the fallback when no model is reachable,
// matching the three-tier degradation the rest of this system uses, so a judge
// with no API key still sees the whole loop run. It is the control that says
// how much the model is actually adding, which is a question most systems built
// around a model carefully avoid asking. And it is deterministic, so the
// discovery half of a demonstration replays exactly even when the model half
// cannot.
//
// It is not a weak strawman. Ranking cells by observed lift times evidence is
// close to what a competent analyst would do with a pivot table, and on a
// corpus this size it finds real structure. What it cannot do is notice that a
// pattern spans two adjacent hour blocks, or that a segment is interesting for
// a reason that is not the largest number on the page, which is where the model
// earns its place.
type Heuristic struct{}

// Name identifies the proposer in an audit record.
func (Heuristic) Name() string { return "heuristic" }

// Propose returns up to n candidate segments, best evidence first.
//
// Candidates are ranked within a granularity and then interleaved across
// granularities, rather than ranked together in one list. The two are not
// comparable: a failure class covers thousands of decisions and an issuer in a
// three-hour window covers a few hundred, so a single ranking by evidence puts
// every class above every segment and the narrow findings never get tested.
//
// The narrow ones are the valuable ones. "Insufficient funds does better on a
// long wait" is something a payments team already knows and has already built
// a rule for. "This one bank, late in the evening, wants six hours" is the
// finding that is worth money precisely because nobody has noticed it, and it
// lives in a cell that a rank-by-total ordering will never reach. Reserving
// most of the budget for the fine granularity is what makes this a discovery
// procedure rather than a restatement.
func (Heuristic) Propose(_ context.Context, b Brief, n int) ([]lab.Hypothesis, error) {
	segments := rankSegmentCandidates(b)
	classes := rankClassCandidates(b)

	out := make([]lab.Hypothesis, 0, n)
	seen := map[string]struct{}{}
	add := func(h lab.Hypothesis) bool {
		if len(out) >= n {
			return false
		}
		if err := h.Validate(); err != nil {
			return false
		}
		key := fingerprint(h)
		if _, dup := seen[key]; dup {
			return false
		}
		seen[key] = struct{}{}
		out = append(out, h)
		return true
	}

	// Two fine-grained candidates for every coarse one, then whatever is left
	// over from either list once the other runs dry.
	var si, ci int
	for len(out) < n && (si < len(segments) || ci < len(classes)) {
		for k := 0; k < 2 && si < len(segments); k++ {
			add(segments[si])
			si++
		}
		if ci < len(classes) {
			add(classes[ci])
			ci++
		}
	}
	return out, nil
}

type scored struct {
	h     lab.Hypothesis
	score float64
}

func rankSegmentCandidates(b Brief) []lab.Hypothesis {
	var cands []scored
	for _, seg := range b.Segments {
		for _, arm := range seg.Arms {
			delta := arm.Recovery - seg.Recovery
			if delta <= 0 {
				continue
			}
			cands = append(cands, scored{
				h: lab.Hypothesis{
					ID: fmt.Sprintf("heur-%s-%d-%s", shortIssuer(seg.IssuerKey), seg.HourBlock, shortArm(arm.Arm)),
					Description: fmt.Sprintf(
						"%s between %02d:00 and %02d:00 recovers at %.0f%% on a %s wait against %.0f%% overall in that window",
						seg.IssuerKey, seg.FromHour, seg.ToHour, 100*arm.Recovery, arm.Label, 100*seg.Recovery),
					IssuerKey: seg.IssuerKey,
					FromHour:  seg.FromHour,
					ToHour:    seg.ToHour,
					Arm:       arm.Arm,
				},
				score: delta * sqrt(float64(arm.Plays)),
			})
		}
	}
	return order(cands)
}

func rankClassCandidates(b Brief) []lab.Hypothesis {
	var cands []scored
	for _, cs := range b.Classwise {
		for _, arm := range cs.Arms {
			delta := arm.Recovery - cs.Recovery
			if delta <= 0 {
				continue
			}
			cands = append(cands, scored{
				h: lab.Hypothesis{
					ID: fmt.Sprintf("heur-%s-%s", shortClass(cs.Class), shortArm(arm.Arm)),
					Description: fmt.Sprintf(
						"%s failures recover at %.0f%% on a %s wait against %.0f%% for the class overall",
						cs.Class, 100*arm.Recovery, arm.Label, 100*cs.Recovery),
					Class: parseClass(cs.Class),
					Arm:   arm.Arm,
				},
				score: delta * sqrt(float64(arm.Plays)),
			})
		}
	}
	return order(cands)
}

// order sorts by observed lift weighted by the square root of the evidence
// behind it.
//
// The square root rather than the count itself because the standard error of a
// rate falls that way, so this ranks by roughly how many standard errors the
// gap is rather than by how large the group happens to be. Ranking by the raw
// count would put every common case first for the second time in one function.
func order(cands []scored) []lab.Hypothesis {
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].h.ID < cands[j].h.ID
	})
	out := make([]lab.Hypothesis, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.h)
	}
	return out
}

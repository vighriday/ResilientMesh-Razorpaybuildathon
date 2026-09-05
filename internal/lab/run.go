package lab

import (
	"fmt"
	"math"
	"math/rand"
	"sort"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/ope"
	"github.com/hriday/razorpay-resilient-mesh/internal/reward"
)

// LogEntry is one decision as it would be written to the audit ledger.
//
// The fields that matter for evaluation are the ones recorded before the
// outcome exists: the distribution the policy was drawing from and the
// probability of the arm it drew. Everything downstream in internal/ope rests
// on those two having been fixed at decision time rather than reconstructed
// afterwards, which is why this system commits them to a hash chain. A log
// whose propensities can be edited once the outcomes are known can be made to
// support any conclusion at all.
type LogEntry struct {
	Index      int         `json:"index"`
	IncidentID string      `json:"incident_id"`
	Cell       bandit.Cell `json:"cell"`

	Arm          bandit.Arm             `json:"arm"`
	Propensity   float64                `json:"propensity"`
	Distribution map[bandit.Arm]float64 `json:"distribution"`
	Permitted    []bandit.Arm           `json:"permitted"`
	GateFloorSec int64                  `json:"gate_floor_seconds"`

	Recovered   bool  `json:"recovered"`
	RewardPaisa int64 `json:"reward_paisa"`
	AmountPaisa int64 `json:"amount_paisa"`
}

// RunResult summarises one pass of a policy over a world.
type RunResult struct {
	Policy    string     `json:"policy"`
	Log       []LogEntry `json:"-"`
	Decisions int        `json:"decisions"`

	Recovered      int   `json:"recovered"`
	RecoveredPaisa int64 `json:"recovered_paisa"`
	FeesPaisa      int64 `json:"fees_paisa"`
	NetPaisa       int64 `json:"net_paisa"`

	// MeanNetPaisa is the realised value per decision, which is the quantity
	// every estimate in this package is trying to predict for a policy that was
	// never run.
	MeanNetPaisa float64 `json:"mean_net_paisa"`

	// RecoveryRate is the share of decisions that recovered the payment.
	RecoveryRate float64 `json:"recovery_rate"`
}

// Run executes a policy across every actionable incident and returns the log.
//
// The draw is taken from a generator seeded only by seed, so a run replays
// exactly. Outcomes come from the pre-drawn per-arm tape rather than from this
// generator, so two policies that pick the same arm on the same incident get
// the same result and the comparison between them is paired.
func (w *World) Run(p Policy, seed int64) (RunResult, error) {
	if p == nil {
		return RunResult{}, fmt.Errorf("lab: no policy")
	}
	learner, learns := p.(Learner)

	rng := rand.New(rand.NewSource(seed))
	res := RunResult{Policy: p.Name(), Log: make([]LogEntry, 0, len(w.actionable))}

	for _, i := range w.actionable {
		inc := w.incidents[i]
		permitted := w.permitted[i]

		dist, err := p.Distribution(inc, permitted)
		if err != nil {
			return RunResult{}, fmt.Errorf("lab: policy %s on incident %s: %w", p.Name(), inc.IncidentID, err)
		}
		if err := CheckDistribution(dist, permitted); err != nil {
			return RunResult{}, fmt.Errorf("lab: policy %s on incident %s: %w", p.Name(), inc.IncidentID, err)
		}

		arm := draw(rng, permitted, dist)
		recovered, rewardPaisa := w.Resolve(i, arm)

		res.Log = append(res.Log, LogEntry{
			Index:        i,
			IncidentID:   inc.IncidentID,
			Cell:         inc.Cell(),
			Arm:          arm,
			Propensity:   dist[arm],
			Distribution: copyDist(dist),
			Permitted:    append([]bandit.Arm(nil), permitted...),
			GateFloorSec: w.gateFloor[i],
			Recovered:    recovered,
			RewardPaisa:  rewardPaisa,
			AmountPaisa:  inc.AmountPaisa(),
		})

		res.FeesPaisa += GatewayFeePaisa
		if recovered {
			res.Recovered++
			res.RecoveredPaisa += inc.AmountPaisa()
		}
		res.NetPaisa += rewardPaisa

		if learns {
			if err := learner.Observe(inc, arm, recovered); err != nil {
				return RunResult{}, fmt.Errorf("lab: policy %s could not observe incident %s: %w", p.Name(), inc.IncidentID, err)
			}
		}
	}

	res.Decisions = len(res.Log)
	if res.Decisions > 0 {
		res.MeanNetPaisa = float64(res.NetPaisa) / float64(res.Decisions)
		res.RecoveryRate = float64(res.Recovered) / float64(res.Decisions)
	}
	return res, nil
}

// draw samples one arm from a distribution, visiting the arms in canonical
// order so the same generator state yields the same arm everywhere.
func draw(rng *rand.Rand, permitted []bandit.Arm, dist map[bandit.Arm]float64) bandit.Arm {
	u := rng.Float64()
	var cum float64
	for _, a := range permitted {
		cum += dist[a]
		if u < cum {
			return a
		}
	}
	return permitted[len(permitted)-1]
}

func copyDist(d map[bandit.Arm]float64) map[bandit.Arm]float64 {
	out := make(map[bandit.Arm]float64, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// The answer key
// ---------------------------------------------------------------------------

// ExactValue computes what a policy is really worth, in paisa per decision.
//
// It is exact rather than sampled: the latent recovery probability of every
// (incident, arm) pair is known here, so the value of a policy is a sum over
// the whole action space weighted by the probabilities the policy assigns, with
// no Monte-Carlo error at all. This is the number an off-policy estimate is
// trying to recover, and having it in closed form is what turns a demonstration
// of the method into a measurement of its accuracy.
//
// Nothing outside this package and its tests may call it on data a policy is
// being evaluated against. It is the answer key.
func (w *World) ExactValue(p Policy) (float64, error) {
	if p == nil {
		return 0, fmt.Errorf("lab: no policy")
	}
	var total float64
	for _, i := range w.actionable {
		inc := w.incidents[i]
		permitted := w.permitted[i]
		dist, err := p.Distribution(inc, permitted)
		if err != nil {
			return 0, fmt.Errorf("lab: policy %s on incident %s: %w", p.Name(), inc.IncidentID, err)
		}
		if err := CheckDistribution(dist, permitted); err != nil {
			return 0, fmt.Errorf("lab: policy %s on incident %s: %w", p.Name(), inc.IncidentID, err)
		}
		for _, a := range permitted {
			total += dist[a] * w.ExpectedRewardPaisa(i, a)
		}
	}
	return total / float64(len(w.actionable)), nil
}

// ---------------------------------------------------------------------------
// Turning a log into an estimate
// ---------------------------------------------------------------------------

// FitRewardModel trains the cross-fitted outcome model used by the
// doubly-robust estimator.
//
// The examples are the logged attempts and nothing else, which is the honest
// constraint: the model may only learn from actions that were actually taken,
// exactly as it would in production. It then predicts for actions that were
// not, which is the job.
func FitRewardModel(log []LogEntry, incidents []Incident, opts reward.Options) (*reward.CrossFitted, reward.Report, error) {
	examples := make([]reward.Example, len(log))
	for k, e := range log {
		examples[k] = reward.Example{
			Features: incidents[e.Index].Features(e.Arm),
			Label:    e.Recovered,
		}
	}
	return reward.CrossFit(examples, opts)
}

// Samples reduces a log and a target policy to the five numbers internal/ope
// needs per decision.
//
// The unsupported mass is computed here rather than assumed to be zero. For
// every arm the target policy would play with positive probability, this checks
// whether the logging policy could have played it at all; where it could not,
// that probability is reported and the estimator refuses to produce a number.
// A deterministic logging policy fails this immediately and by design.
func (w *World) Samples(log []LogEntry, target Policy, model *reward.CrossFitted) ([]ope.Sample, error) {
	if target == nil {
		return nil, fmt.Errorf("lab: no target policy")
	}
	out := make([]ope.Sample, len(log))
	for k, e := range log {
		inc := w.incidents[e.Index]
		td, err := target.Distribution(inc, e.Permitted)
		if err != nil {
			return nil, fmt.Errorf("lab: target %s on incident %s: %w", target.Name(), inc.IncidentID, err)
		}
		if err := CheckDistribution(td, e.Permitted); err != nil {
			return nil, fmt.Errorf("lab: target %s on incident %s: %w", target.Name(), inc.IncidentID, err)
		}

		s := ope.Sample{
			Logged:      e.Propensity,
			Target:      td[e.Arm],
			RewardPaisa: e.RewardPaisa,
		}
		for a, q := range td {
			if q > 0 && e.Distribution[a] <= 0 {
				s.Unsupported += q
			}
		}

		if model != nil {
			p, err := model.PredictFor(k, inc.Features(e.Arm))
			if err != nil {
				return nil, err
			}
			s.Baseline = predictedRewardPaisa(p, inc.AmountPaisa())
			// Both expectations are taken over the same predictions, so where
			// the two policies agree the doubly-robust difference cancels to
			// exactly zero rather than to something small.
			for _, a := range e.Permitted {
				if td[a] <= 0 && e.Distribution[a] <= 0 {
					continue
				}
				q, err := model.PredictFor(k, inc.Features(a))
				if err != nil {
					return nil, err
				}
				v := predictedRewardPaisa(q, inc.AmountPaisa())
				s.TargetMean += td[a] * v
				s.LoggedMean += e.Distribution[a] * v
			}
		}
		out[k] = s
	}
	return out, nil
}

// predictedRewardPaisa converts a learned probability into an expected value.
//
// The multiplication happens here, at the boundary, and the amount comes from
// the verified payment. The model contributes a probability and never a figure
// in paisa, which is the same separation internal/bandit and internal/policy
// keep.
func predictedRewardPaisa(prob float64, amountPaisa int64) float64 {
	if math.IsNaN(prob) {
		prob = 0
	}
	return math.Max(0, math.Min(1, prob))*float64(amountPaisa) - float64(GatewayFeePaisa)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// EvalOptions tunes an off-policy evaluation of this world.
type EvalOptions struct {
	// Seed fixes the bootstrap and the reward model fit.
	Seed int64

	// Bootstrap is the resample count. Zero uses the ope default.
	Bootstrap int

	// Confidence is the two-sided coverage of every interval. Zero uses the
	// ope default of 0.95.
	//
	// It is a parameter rather than a constant because a discovery loop testing
	// many hypotheses at once has to widen each interval to keep the chance of
	// any false discovery at the level it claims. See internal/mill.
	Confidence float64

	// WithOutcomeModel enables the doubly-robust estimator, which requires
	// fitting the cross-fitted reward model over the log.
	WithOutcomeModel bool

	// RewardOptions tunes that model.
	RewardOptions reward.Options

	// RewardModel supplies an already cross-fitted outcome model.
	//
	// A discovery round scores many candidate policies against one log, and the
	// model depends only on the log. Refitting it per candidate costs the same
	// work repeatedly and, worse, invites a caller to fit it on data that
	// includes the candidate under test. Fitting once and passing it in is both
	// faster and the only arrangement in which every candidate is judged
	// against the same predictions.
	RewardModel *reward.CrossFitted
}

// Validation is the experiment production cannot run: an off-policy estimate
// checked against the truth.
type Validation struct {
	LoggingPolicy string `json:"logging_policy"`
	TargetPolicy  string `json:"target_policy"`
	Decisions     int    `json:"decisions"`

	// Estimated is what the estimators concluded from the log alone.
	Estimated ope.Report `json:"estimated"`

	// Lift is the paired estimate of the advantage over the logging policy. It
	// is the number a reviewer acts on: not what the candidate is worth, but
	// what changing to it would gain over what is deployed today.
	Lift ope.Lift `json:"lift"`

	// TrueTargetValue and TrueLoggingValue are computed by enumeration over the
	// latent outcome model, so they carry no sampling error whatsoever.
	TrueTargetValue  float64 `json:"true_target_value_paisa"`
	TrueLoggingValue float64 `json:"true_logging_value_paisa"`
	TrueLift         float64 `json:"true_lift_paisa"`

	// Covered reports whether the interval contained the truth. This is the
	// single result the whole package exists to produce.
	Covered     bool `json:"covered"`
	LiftCovered bool `json:"lift_covered"`

	// AbsoluteError and RelativeError describe the point estimate.
	AbsoluteError float64 `json:"absolute_error_paisa"`
	RelativeError float64 `json:"relative_error"`

	// RewardModel is the held-out quality of the outcome model, when one was
	// fitted. A doubly-robust number should never be quoted without it.
	RewardModel *reward.Report `json:"reward_model,omitempty"`
}

// Validate estimates the value of target from a log produced by logger, then
// computes what target is actually worth and reports whether the estimate was
// right.
//
// The order is the point. The estimate is produced from the log and nothing
// else, with no access to the latent outcome model; only afterwards is the
// truth consulted, and only to score the estimate. That is the experiment
// nobody can run on live traffic, because on live traffic the second half never
// happens.
func Validate(w *World, logger, target Policy, opts EvalOptions) (Validation, error) {
	run, err := w.Run(logger, opts.Seed)
	if err != nil {
		return Validation{}, err
	}
	return w.ValidateAgainstLog(run, target, opts)
}

// ValidateAgainstLog is Validate against a log that already exists, which is
// what the discovery loop uses: one log, many candidate policies scored from it.
func (w *World) ValidateAgainstLog(run RunResult, target Policy, opts EvalOptions) (Validation, error) {
	v := Validation{
		LoggingPolicy: run.Policy,
		TargetPolicy:  target.Name(),
		Decisions:     len(run.Log),
	}

	model := opts.RewardModel
	if opts.WithOutcomeModel && model == nil {
		ro := opts.RewardOptions
		if ro.Seed == 0 {
			ro.Seed = opts.Seed
		}
		m, rep, err := FitRewardModel(run.Log, w.incidents, ro)
		if err != nil {
			return Validation{}, fmt.Errorf("lab: fitting the outcome model: %w", err)
		}
		model, v.RewardModel = m, &rep
	}

	samples, err := w.Samples(run.Log, target, model)
	if err != nil {
		return Validation{}, err
	}

	evalOpts := ope.Options{
		Bootstrap:        opts.Bootstrap,
		Seed:             opts.Seed,
		Confidence:       opts.Confidence,
		WithOutcomeModel: opts.WithOutcomeModel,
	}
	lift, rep, err := ope.EvaluateLift(samples, evalOpts)
	if err != nil {
		// The refusal is a result, so the diagnostics that justify it are
		// returned alongside the error rather than discarded.
		v.Estimated = rep
		return v, err
	}
	v.Estimated, v.Lift = rep, lift

	// Only now is the answer key opened.
	if v.TrueTargetValue, err = w.ExactValue(target); err != nil {
		return v, err
	}
	loggingPolicy, err := runPolicyOf(run, w)
	if err != nil {
		return v, err
	}
	if v.TrueLoggingValue, err = w.ExactValue(loggingPolicy); err != nil {
		return v, err
	}
	v.TrueLift = v.TrueTargetValue - v.TrueLoggingValue

	point := rep.SNIPS
	v.Covered = point.Lower <= v.TrueTargetValue && v.TrueTargetValue <= point.Upper
	v.LiftCovered = lift.Lower <= v.TrueLift && v.TrueLift <= lift.Upper
	v.AbsoluteError = point.Value - v.TrueTargetValue
	if v.TrueTargetValue != 0 {
		v.RelativeError = v.AbsoluteError / math.Abs(v.TrueTargetValue)
	}
	return v, nil
}

// ReplayOf recovers the policy a log actually followed, as a fixed distribution.
//
// It is the right base for any candidate policy: a hypothesis is a change to
// what is deployed, so the candidate has to be "carry on exactly as before,
// except here". Scoring against anything else measures the difference between
// two whole policies and drowns the segment in it.
func ReplayOf(run RunResult, w *World) (Policy, error) { return runPolicyOf(run, w) }

// runPolicyOf recovers the logging policy as a fixed distribution so its exact
// value can be computed the same way the target one is.
//
// A learner cannot be handed back for this, because by the end of the run it is
// no longer the policy that produced the earlier half of the log. What is
// reconstructed instead is the empirical policy the log actually followed:
// the distribution recorded on each decision, replayed. That is exactly the
// mixture the logged rewards were drawn from, so it is the right comparison.
func runPolicyOf(run RunResult, w *World) (Policy, error) {
	byIndex := make(map[int]map[bandit.Arm]float64, len(run.Log))
	for _, e := range run.Log {
		byIndex[e.Index] = e.Distribution
	}
	return &replayed{name: run.Policy + "-as-logged", byIndex: byIndex, fallback: Backoff{}}, nil
}

type replayed struct {
	name     string
	byIndex  map[int]map[bandit.Arm]float64
	fallback Policy
}

func (r *replayed) Name() string { return r.name }

func (r *replayed) Distribution(inc Incident, permitted []bandit.Arm) (map[bandit.Arm]float64, error) {
	if d, ok := r.byIndex[inc.Index]; ok {
		return copyDist(d), nil
	}
	return r.fallback.Distribution(inc, permitted)
}

// ---------------------------------------------------------------------------
// Scoring a hypothesis
// ---------------------------------------------------------------------------

// HypothesisScore is the verdict on one proposed segment.
type HypothesisScore struct {
	Hypothesis Hypothesis `json:"hypothesis"`
	Statement  string     `json:"statement"`

	// Coverage is how many logged decisions fall inside the segment. A
	// hypothesis covering a handful of incidents cannot be significant however
	// large its apparent effect, and reporting the count stops that argument
	// before it starts.
	Coverage int `json:"coverage"`

	// Lift is the paired off-policy estimate of the advantage in paisa per
	// decision across the whole corpus, which is what adopting the change would
	// be worth in total.
	Lift ope.Lift `json:"lift"`

	// SegmentLiftPaisa concentrates that same estimate onto the decisions the
	// segment actually touches.
	//
	// Both numbers are needed and they answer different questions. A weak
	// change applied to a fifth of the traffic can be worth more in total than
	// a transformative one applied to a hundredth, so the corpus figure is the
	// one a finance team cares about. But discovery is about finding real
	// structure, and structure lives in the second figure: a segment where the
	// right action is worth four hundred rupees more per attempt is a fact
	// about an issuer, while the same total spread thinly is usually a fact
	// about arithmetic.
	SegmentLiftPaisa float64 `json:"segment_lift_paisa"`

	// Diagnostics carries the overlap and effective-sample-size evidence.
	Diagnostics ope.Diagnostics `json:"diagnostics"`

	// Survived is the verdict: the whole interval above zero. It is the only
	// thing that admits a hypothesis into the action space.
	Survived bool `json:"survived"`

	// Refuted records a hypothesis that was tested and lost, which is kept
	// rather than discarded: a record of what did not work is most of what
	// makes a record of what did credible.
	Refuted bool `json:"refuted"`

	// Warnings are the estimator caveats, verbatim.
	Warnings []string `json:"warnings,omitempty"`

	// Error names why a hypothesis could not be scored at all, most often
	// because the log has no support for it.
	Error string `json:"error,omitempty"`
}

// MinCoverage is the smallest number of logged decisions a hypothesis must
// touch before it is worth testing. Below it the interval is so wide that
// nothing can clear zero, and the attempt only spends a multiple-comparison
// budget.
const MinCoverage = 40

// ScoreHypothesis evaluates a proposed segment against an existing log.
//
// Nothing about the latent truth is consulted. The verdict comes from the log
// and the estimator alone, exactly as it would on a real merchant corpus where
// no answer key exists.
//
// A nil base means the policy that produced the log, and that is almost always
// the right choice. A hypothesis is a proposed change to what is deployed
// today, so the candidate has to be "carry on exactly as before, except here",
// and the lift then measures the segment and nothing else. Scoring it against
// some other baseline instead measures the difference between two policies
// across the whole corpus, drowns the segment in it, and produces a confidently
// negative verdict on a hypothesis that was correct. That mistake was made
// here first and is the reason this paragraph exists.
func (w *World) ScoreHypothesis(run RunResult, h Hypothesis, base Policy, opts EvalOptions) (HypothesisScore, error) {
	if base == nil {
		var err error
		if base, err = runPolicyOf(run, w); err != nil {
			return HypothesisScore{Hypothesis: h, Error: err.Error()}, err
		}
	}
	seg, err := NewSegment(h, base)
	if err != nil {
		return HypothesisScore{Hypothesis: h, Error: err.Error()}, err
	}
	score := HypothesisScore{Hypothesis: seg.H, Statement: seg.H.String()}

	for _, e := range run.Log {
		if seg.H.Matches(w.incidents[e.Index]) {
			score.Coverage++
		}
	}
	if score.Coverage < MinCoverage {
		score.Error = fmt.Sprintf("segment covers only %d logged decisions, below the floor of %d", score.Coverage, MinCoverage)
		score.Refuted = true
		return score, nil
	}

	model := opts.RewardModel
	if opts.WithOutcomeModel && model == nil {
		ro := opts.RewardOptions
		if ro.Seed == 0 {
			ro.Seed = opts.Seed
		}
		m, _, err := FitRewardModel(run.Log, w.incidents, ro)
		if err != nil {
			score.Error = err.Error()
			return score, nil
		}
		model = m
	}
	samples, err := w.Samples(run.Log, seg, model)
	if err != nil {
		score.Error = err.Error()
		return score, nil
	}
	lift, rep, err := ope.EvaluateLift(samples, ope.Options{
		Bootstrap:        opts.Bootstrap,
		Seed:             opts.Seed,
		Confidence:       opts.Confidence,
		WithOutcomeModel: opts.WithOutcomeModel,
	})
	score.Diagnostics = rep.Diagnostics
	if err != nil {
		score.Error = err.Error()
		score.Refuted = true
		return score, nil
	}
	score.Lift = lift
	score.Warnings = rep.Warnings
	if lift.Warning != "" {
		score.Warnings = append(score.Warnings, lift.Warning)
	}
	score.Survived = lift.Significant
	score.Refuted = !lift.Significant
	if score.Coverage > 0 {
		score.SegmentLiftPaisa = lift.Value * float64(len(run.Log)) / float64(score.Coverage)
	}
	return score, nil
}

// RankScores orders verdicts: survivors first, then by how strong the effect is
// inside the segment. Refuted hypotheses stay in the list rather than being
// dropped, because a record of what was tried and failed is most of what makes
// a record of what worked believable.
//
// Ranking on the segment effect rather than on the corpus total is deliberate.
// The corpus total rewards breadth, so a marginal change to a fifth of the
// traffic outranks a decisive one to a hundredth, and a discovery loop ranked
// that way spends its life rediscovering that most payments are ordinary. The
// significance test still has to pass first, and MinCoverage still applies, so
// ranking by effect size cannot promote a segment nobody has evidence about.
func RankScores(scores []HypothesisScore) {
	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].Survived != scores[j].Survived {
			return scores[i].Survived
		}
		if scores[i].SegmentLiftPaisa != scores[j].SegmentLiftPaisa {
			return scores[i].SegmentLiftPaisa > scores[j].SegmentLiftPaisa
		}
		return scores[i].Hypothesis.ID < scores[j].Hypothesis.ID
	})
}

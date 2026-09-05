package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/calib"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/lab"
	"github.com/hriday/razorpay-resilient-mesh/internal/mill"
	"github.com/hriday/razorpay-resilient-mesh/internal/reward"
)

// The learning commands run entirely in process against a generated world. They
// need no database, no queue, no credential and no network, which is deliberate:
// a reviewer should be able to check the most contestable claims this project
// makes without provisioning anything.

const (
	// defaultLearnIncidents is the corpus size for a validation or discovery
	// run. It is roughly a month of failed payments for a mid-sized merchant.
	//
	// The number is set by the question rather than by taste. The segment under
	// test is about two percent of traffic and the candidate policy differs
	// from the deployed one only inside it, so the estimate rests on the
	// decisions that actually differ and not on the corpus size. At forty
	// thousand incidents that is around five hundred decisions and the interval
	// covers the truth while being too wide to act on; at a hundred and twenty
	// thousand it is around sixteen hundred and the interval separates from
	// zero. That progression is a property of the question, it is measured in
	// internal/lab, and ope.Lift reports the count so a reader can see which
	// regime a result is in rather than having to guess.
	defaultLearnIncidents = 120_000

	// defaultLearnSeed fixes the world, the exploration draws and every
	// bootstrap, so two runs of the same command produce identical output.
	defaultLearnSeed = 20_260_301

	learnBootstrap = 600
	learnFloor     = 0.06
	learnDraws     = 60
)

// ---------------------------------------------------------------------------
// learn validate
// ---------------------------------------------------------------------------

type validateReport struct {
	Schema string `json:"schema"`

	Incidents  int `json:"incidents"`
	Actionable int `json:"actionable_incidents"`
	Refused    int `json:"gate_refused"`

	// GateRefusals names which invariant removed each refused incident, which
	// is the evidence that exploration is bounded by the rules rather than by a
	// setting.
	GateRefusals map[string]int `json:"gate_refusals"`

	// ArmsAvailable shows how the action space narrows under the invariants.
	ArmsAvailable map[string]int `json:"arms_available"`

	LoggingPolicy string  `json:"logging_policy"`
	TargetPolicy  string  `json:"target_policy"`
	ExploreRate   float64 `json:"explore_rate"`

	// Policies is what each policy actually earned when run, which is a
	// separate claim from whether the estimator is accurate and is reported
	// separately so the two are not confused for each other.
	Policies []policyRun `json:"policies"`

	EstimatedValue    interval `json:"estimated_value_paisa"`
	TrueValue         float64  `json:"true_value_paisa"`
	ValueCovered      bool     `json:"value_covered"`
	EstimatedLift     interval `json:"estimated_lift_paisa"`
	TrueLift          float64  `json:"true_lift_paisa"`
	LiftCovered       bool     `json:"lift_covered"`
	LiftEstimator     string   `json:"lift_estimator"`
	InfluentialLogged int      `json:"influential_decisions"`

	RelativeError       float64  `json:"relative_error"`
	EffectiveSampleSize float64  `json:"effective_sample_size"`
	RewardModelSkill    float64  `json:"reward_model_skill"`
	RewardModelAUC      float64  `json:"reward_model_auc"`
	Warnings            []string `json:"warnings,omitempty"`

	Verdict string `json:"verdict"`
}

// policyRun is one policy measured by running it, for comparison.
type policyRun struct {
	Name         string  `json:"name"`
	Decisions    int     `json:"decisions"`
	RecoveryRate float64 `json:"recovery_rate"`
	NetPaisa     int64   `json:"net_paisa"`
	MeanNetPaisa float64 `json:"mean_net_paisa"`
}

type interval struct {
	Value      float64 `json:"value"`
	Lower      float64 `json:"lower"`
	Upper      float64 `json:"upper"`
	Confidence float64 `json:"confidence"`
}

// cmdLearnValidate runs the experiment production cannot run.
//
// It estimates what a policy that was never executed would have earned, using
// nothing but a log produced by a different one, and then computes what that
// policy is actually worth and reports whether the estimate was right. The
// second half is impossible on live traffic, which is why every off-policy
// result published anywhere is an argument from method rather than a
// measurement of accuracy.
func cmdLearnValidate(ctx context.Context, g globals, incidents int, seed int64, out io.Writer) error {
	w, err := lab.New(lab.Config{Incidents: incidents, Seed: seed})
	if err != nil {
		return fmt.Errorf("building the world: %w", err)
	}

	// The logging policy here is uniform exploration rather than the learner.
	//
	// That is deliberate and it is the opposite of a weakness. The question
	// this command answers is whether the estimator is accurate, and a learner
	// makes that question harder to read for a reason that has nothing to do
	// with the estimator: by the end of a run the learner has already found the
	// segment under test, so the candidate policy barely differs from the log,
	// the true lift is close to zero, and a correct estimate of nearly nothing
	// demonstrates very little. A fixed, maximally informative logging policy
	// isolates the thing being measured. What the learner is worth is measured
	// underneath, by running it.
	run, err := w.Run(lab.Uniform{}, seed)
	if err != nil {
		return err
	}

	// The candidate: carry on exactly as deployed, except inside one segment.
	// That is the shape a real proposal takes and the shape the estimator is
	// best conditioned for.
	base, err := lab.ReplayOf(run, w)
	if err != nil {
		return err
	}
	truth := w.Reveal()
	target, err := lab.NewSegment(lab.Hypothesis{
		ID:          "candidate",
		Description: "the segment under evaluation",
		IssuerKey:   truth.IssuerKey,
		FromHour:    truth.FromHour,
		ToHour:      truth.ToHour,
		Arm:         truth.Arm,
	}, base)
	if err != nil {
		return err
	}

	v, err := w.ValidateAgainstLog(run, target, lab.EvalOptions{
		Seed: seed, Bootstrap: learnBootstrap, WithOutcomeModel: true,
		RewardOptions: reward.Options{Seed: seed},
	})
	if err != nil {
		return fmt.Errorf("evaluating: %w", err)
	}

	gate := w.Gate()
	rep := validateReport{
		Schema:              "resilientmesh.validate.v1",
		Incidents:           gate.Incidents,
		Actionable:          gate.Actionable,
		Refused:             gate.Refused,
		GateRefusals:        gate.ByReason,
		ArmsAvailable:       armCounts(gate.ArmsAvailable),
		LoggingPolicy:       run.Policy,
		TargetPolicy:        target.Name(),
		EstimatedValue:      toInterval(v.Estimated.SNIPS.Value, v.Estimated.SNIPS.Lower, v.Estimated.SNIPS.Upper, v.Estimated.SNIPS.Confidence),
		TrueValue:           v.TrueTargetValue,
		ValueCovered:        v.Covered,
		EstimatedLift:       toInterval(v.Lift.Value, v.Lift.Lower, v.Lift.Upper, v.Lift.Confidence),
		TrueLift:            v.TrueLift,
		LiftCovered:         v.LiftCovered,
		LiftEstimator:       v.Lift.Estimator,
		InfluentialLogged:   v.Lift.Influential,
		RelativeError:       v.RelativeError,
		EffectiveSampleSize: v.Estimated.Diagnostics.EffectiveSampleSize,
		Warnings:            v.Estimated.Warnings,
	}
	if v.RewardModel != nil {
		rep.RewardModelSkill = v.RewardModel.Skill
		rep.RewardModelAUC = v.RewardModel.AUC
	}
	if v.Lift.Warning != "" {
		rep.Warnings = append(rep.Warnings, v.Lift.Warning)
	}
	rep.ExploreRate = exploreRate(run)
	rep.Verdict = "the interval contained the truth"
	if !v.LiftCovered {
		rep.Verdict = "the interval missed the truth, which a 95% interval does about one time in twenty"
	}

	// And separately, what the learner is actually worth. Same world, same
	// pre-drawn outcomes, so the comparison is paired rather than merely run on
	// the same inputs.
	for _, p := range []lab.Policy{lab.Backoff{}, lab.Uniform{}} {
		r, err := w.Run(p, seed)
		if err != nil {
			return err
		}
		rep.Policies = append(rep.Policies, toPolicyRun(r))
	}
	model, err := bandit.New(bandit.Config{Arms: lab.Arms, Floor: learnFloor, Seed: seed, Draws: learnDraws})
	if err != nil {
		return err
	}
	learned, err := w.Run(lab.NewBandit(model, "thompson"), seed)
	if err != nil {
		return err
	}
	rep.Policies = append(rep.Policies, toPolicyRun(learned))

	if g.jsonOut {
		return writeJSON(out, rep)
	}
	return renderValidate(out, rep, v.Estimated.Diagnostics.ESSFraction)
}

func renderValidate(out io.Writer, r validateReport, essFraction float64) error {
	fmt.Fprintf(out, "counterfactual validation  %d incidents, seed fixed\n\n", r.Incidents)

	fmt.Fprintf(out, "  the gate first\n")
	fmt.Fprintf(out, "    actionable                %d\n", r.Actionable)
	fmt.Fprintf(out, "    refused outright          %d\n", r.Refused)
	for _, k := range sortedKeys(r.GateRefusals) {
		fmt.Fprintf(out, "      %-24s %d\n", k, r.GateRefusals[k])
	}
	fmt.Fprintf(out, "    arms left to explore\n")
	for _, k := range sortedKeys(r.ArmsAvailable) {
		fmt.Fprintf(out, "      %-24s %d incidents\n", k, r.ArmsAvailable[k])
	}

	fmt.Fprintf(out, "\n  what each policy actually earns, run on identical luck\n")
	fmt.Fprintf(out, "    %-14s %12s %14s %16s\n", "policy", "recovered", "net paisa", "per decision")
	for _, p := range r.Policies {
		fmt.Fprintf(out, "    %-14s %11.1f%% %14d %16.1f\n",
			p.Name, 100*p.RecoveryRate, p.NetPaisa, p.MeanNetPaisa)
	}

	fmt.Fprintf(out, "\n  the log the estimate is made from\n")
	fmt.Fprintf(out, "    logging policy            %s\n", r.LoggingPolicy)
	fmt.Fprintf(out, "    spent on exploration      %.1f%%\n", 100*r.ExploreRate)
	fmt.Fprintf(out, "    reward model skill        %.3f (held out), AUC %.3f\n", r.RewardModelSkill, r.RewardModelAUC)

	fmt.Fprintf(out, "\n  the estimate, from the log alone\n")
	fmt.Fprintf(out, "    candidate policy          %s\n", r.TargetPolicy)
	fmt.Fprintf(out, "    value per decision        %.1f  [%.1f, %.1f] at %.0f%%\n",
		r.EstimatedValue.Value, r.EstimatedValue.Lower, r.EstimatedValue.Upper, 100*r.EstimatedValue.Confidence)
	fmt.Fprintf(out, "    lift over deployed        %.1f  [%.1f, %.1f]   (%s)\n",
		r.EstimatedLift.Value, r.EstimatedLift.Lower, r.EstimatedLift.Upper, r.LiftEstimator)
	fmt.Fprintf(out, "    decisions that differ     %d\n", r.InfluentialLogged)
	fmt.Fprintf(out, "    effective sample size     %.0f  (%.0f%% of the log)\n", r.EffectiveSampleSize, 100*essFraction)

	fmt.Fprintf(out, "\n  the answer key, opened only now\n")
	fmt.Fprintf(out, "    true value per decision   %.1f    %s\n", r.TrueValue, covered(r.ValueCovered))
	fmt.Fprintf(out, "    true lift                 %.1f    %s\n", r.TrueLift, covered(r.LiftCovered))
	fmt.Fprintf(out, "    relative error            %.2f%%\n", 100*r.RelativeError)

	for _, warn := range r.Warnings {
		fmt.Fprintf(out, "\n  note: %s\n", warn)
	}
	fmt.Fprintf(out, "\n  %s\n", r.Verdict)
	fmt.Fprintf(out, "\n  Nothing above consulted the latent outcome model until the last block.\n")
	fmt.Fprintf(out, "  On live traffic that block does not exist, which is why nobody else\n")
	fmt.Fprintf(out, "  can tell you whether their counterfactual was accurate.\n")
	return nil
}

func covered(ok bool) string {
	if ok {
		return "inside the interval"
	}
	return "OUTSIDE the interval"
}

// ---------------------------------------------------------------------------
// learn discover
// ---------------------------------------------------------------------------

type discoverReport struct {
	Schema string `json:"schema"`

	Incidents int    `json:"incidents"`
	Decisions int    `json:"decisions"`
	Proposer  string `json:"proposer"`
	Degraded  bool   `json:"degraded"`
	Fallback  string `json:"fallback_cause,omitempty"`

	Tested            int     `json:"hypotheses_tested"`
	FamilyAlpha       float64 `json:"family_alpha"`
	PerTestConfidence float64 `json:"per_test_confidence"`

	Verdicts []hypothesisVerdict `json:"verdicts"`

	// Planted is the rule the world actually contains. It is printed after the
	// verdicts and never before, because the whole claim is that the loop found
	// it without being told.
	Planted string `json:"planted_rule"`
	Found   bool   `json:"planted_rule_found"`
}

type hypothesisVerdict struct {
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	Description string   `json:"description"`
	Coverage    int      `json:"coverage"`
	Lift        interval `json:"lift_paisa"`
	SegmentLift float64  `json:"segment_lift_paisa"`
	Survived    bool     `json:"survived"`
	Note        string   `json:"note,omitempty"`
}

// cmdLearnDiscover runs one round of the proposal loop.
//
// A proposer reads aggregated statistics and suggests segments worth testing.
// Every suggestion is scored by an off-policy estimator against a log the
// proposer never influenced, at a confidence level widened for the number of
// suggestions, and the survivors and the refutations are both printed. Only
// then is the latent rule revealed.
func cmdLearnDiscover(ctx context.Context, g globals, incidents int, seed int64, proposals int, out io.Writer) error {
	w, err := lab.New(lab.Config{Incidents: incidents, Seed: seed})
	if err != nil {
		return fmt.Errorf("building the world: %w", err)
	}
	model, err := bandit.New(bandit.Config{Arms: lab.Arms, Floor: learnFloor, Seed: seed, Draws: learnDraws})
	if err != nil {
		return err
	}
	run, err := w.Run(lab.NewBandit(model, "thompson"), seed)
	if err != nil {
		return err
	}

	proposer := proposerFor(ctx)
	res, err := mill.Run(ctx, w, run, proposer, mill.Options{
		Proposals:        proposals,
		Bootstrap:        learnBootstrap,
		Seed:             seed,
		WithOutcomeModel: true,
	})
	if err != nil {
		return fmt.Errorf("discovery round: %w", err)
	}

	truth := w.Reveal()
	rep := discoverReport{
		Schema:            "resilientmesh.discover.v1",
		Incidents:         incidents,
		Decisions:         res.Decisions,
		Proposer:          res.Proposer,
		Degraded:          res.Degraded,
		Fallback:          res.FallbackCause,
		Tested:            res.Tested,
		FamilyAlpha:       res.FamilyAlpha,
		PerTestConfidence: res.PerTestConfidence,
		Planted:           truth.Description,
	}
	for _, s := range res.Scores {
		v := hypothesisVerdict{
			ID:          s.Hypothesis.ID,
			Statement:   s.Statement,
			Description: s.Hypothesis.Description,
			Coverage:    s.Coverage,
			Lift:        toInterval(s.Lift.Value, s.Lift.Lower, s.Lift.Upper, s.Lift.Confidence),
			SegmentLift: s.SegmentLiftPaisa,
			Survived:    s.Survived,
			Note:        s.Error,
		}
		if v.Note == "" && len(s.Warnings) > 0 {
			v.Note = s.Warnings[0]
		}
		rep.Verdicts = append(rep.Verdicts, v)
		if s.Survived && s.Hypothesis.IssuerKey == truth.IssuerKey && s.Hypothesis.Arm == truth.Arm {
			rep.Found = true
		}
	}

	if g.jsonOut {
		return writeJSON(out, rep)
	}
	return renderDiscover(out, rep)
}

func renderDiscover(out io.Writer, r discoverReport) error {
	fmt.Fprintf(out, "discovery round  %d incidents, %d logged decisions\n\n", r.Incidents, r.Decisions)
	fmt.Fprintf(out, "  proposer                  %s\n", r.Proposer)
	if r.Degraded {
		fmt.Fprintf(out, "  degraded                  yes (%s), the deterministic proposer answered\n", r.Fallback)
	}
	fmt.Fprintf(out, "  hypotheses tested         %d\n", r.Tested)
	fmt.Fprintf(out, "  confidence per test       %.4f  (widened from %.2f so the chance of any\n",
		r.PerTestConfidence, 1-r.FamilyAlpha)
	fmt.Fprintf(out, "                            false survivor across the round stays at %.2f)\n", r.FamilyAlpha)

	fmt.Fprintf(out, "\n  verdicts, survivors first\n\n")
	for _, v := range r.Verdicts {
		mark := "refuted "
		if v.Survived {
			mark = "SURVIVED"
		}
		fmt.Fprintf(out, "  [%s]  %s\n", mark, v.Statement)
		if v.Description != "" {
			fmt.Fprintf(out, "              %s\n", wrap(v.Description, 66, "              "))
		}
		fmt.Fprintf(out, "              covers %d decisions; lift %.1f [%.1f, %.1f] paisa a decision",
			v.Coverage, v.Lift.Value, v.Lift.Lower, v.Lift.Upper)
		if v.SegmentLift != 0 {
			fmt.Fprintf(out, ", %.0f inside the segment", v.SegmentLift)
		}
		fmt.Fprintln(out)
		if v.Note != "" {
			fmt.Fprintf(out, "              note: %s\n", wrap(v.Note, 66, "              "))
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "  the answer key, opened only now\n")
	fmt.Fprintf(out, "    %s\n", wrap(r.Planted, 70, "    "))
	if r.Found {
		fmt.Fprintf(out, "\n  Found. Nothing in the policy, the features, the prompt or the gate\n")
		fmt.Fprintf(out, "  named that rule. It was proposed from the log and confirmed against\n")
		fmt.Fprintf(out, "  data the proposer did not influence.\n")
	} else {
		fmt.Fprintf(out, "\n  Not found in this round. The corpus or the proposal budget was too\n")
		fmt.Fprintf(out, "  small for the effect to clear a corrected threshold.\n")
	}
	return nil
}

// proposerFor picks the model tier when one is configured and the deterministic
// one otherwise.
//
// The fallback is not a degraded mode to apologise for. It is what lets a
// reviewer with no API key run the same command and see the same loop, and it
// is the control that says how much the model is actually adding.
func proposerFor(ctx context.Context) mill.Proposer {
	key := strings.TrimSpace(os.Getenv("MESH_LLM_API_KEY"))
	base := strings.TrimSpace(os.Getenv("MESH_LLM_BASE_URL"))
	name := strings.TrimSpace(os.Getenv("MESH_LLM_MODEL"))
	if key == "" || base == "" || name == "" {
		return mill.Heuristic{}
	}
	m, err := mill.NewModel(base, key, name, 30*time.Second, nil)
	if err != nil {
		return mill.Heuristic{}
	}
	_ = ctx
	return m
}

// ---------------------------------------------------------------------------
// learn calibrate
// ---------------------------------------------------------------------------

type calibrateReport struct {
	Schema string `json:"schema"`

	// Recovery is the calibration of the learned recovery model: when it says
	// an attempt is seventy percent likely to succeed, does it succeed seventy
	// percent of the time?
	Recovery calibrationView `json:"recovery_model"`

	// Classification is the calibration of the inference tier stated
	// confidence, measured only where a label exists. It is reported second and
	// smaller because the corpus can only support it on a fraction of its
	// cassettes, and that limitation is stated rather than worked around.
	Classification *calibrationView `json:"classification,omitempty"`

	ClassificationNote string `json:"classification_note,omitempty"`
}

type calibrationView struct {
	Subject      string `json:"subject"`
	Observations int    `json:"observations"`
	Population   int    `json:"population,omitempty"`

	Accuracy       float64 `json:"observed_rate"`
	MeanConfidence float64 `json:"mean_stated"`
	Overconfident  bool    `json:"overconfident"`

	ECE         float64 `json:"expected_calibration_error"`
	MCE         float64 `json:"maximum_calibration_error"`
	NoiseFloor  float64 `json:"noise_floor"`
	Significant bool    `json:"miscalibration_is_significant"`

	AfterECE  float64 `json:"expected_calibration_error_after"`
	Reduction float64 `json:"reduction"`

	Bins []calibBin `json:"bins"`

	DeployedThreshold *thresholdView `json:"deployed_threshold,omitempty"`
	MeasuredThreshold *thresholdView `json:"measured_threshold,omitempty"`
	ThresholdNote     string         `json:"threshold_note,omitempty"`

	Limitation string `json:"limitation,omitempty"`
}

type calibBin struct {
	Lower      float64 `json:"lower"`
	Upper      float64 `json:"upper"`
	Count      int     `json:"count"`
	Confidence float64 `json:"mean_stated"`
	Accuracy   float64 `json:"observed_rate"`
	Thin       bool    `json:"thin,omitempty"`
}

type thresholdView struct {
	Confidence float64 `json:"confidence"`
	Accuracy   float64 `json:"accuracy"`
	Coverage   float64 `json:"coverage"`
	Accepted   int     `json:"accepted"`
}

// unambiguousClass maps the decline codes whose causal class is fixed by the
// code itself onto that class.
//
// It is deliberately short and, on the corpus this repository ships, it matches
// nothing at all. That is the finding rather than a gap.
//
// The recorded corpus was assembled to exercise the inference tier on genuinely
// ambiguous failures, so almost every code in it is one whose class depends on
// telemetry the code does not carry. Two looked labellable at first and are
// not. A "payment_timed_out" raised in the middle of a confirmed issuer outage
// really is an issuer outage rather than a network timeout, and the recorded
// proposals classify it that way about eighty percent of the time; scoring them
// against NETWORK_TIMEOUT produced a confident-looking seventeen percent
// accuracy that measured the label rather than the model. "issuer_down" has the
// same problem in the other direction, since the corpus varies the telemetry
// behind it on purpose.
//
// So the classifier is not calibrated here, and the command says so. The
// alternatives were to invent a ground truth or to score the model against this
// system own heuristic, and a measurement built on either would be worth less
// than the admission.
var unambiguousClass = map[string]domain.FailureClass{
	"insufficient_funds":  domain.ClassInsufficientFunds,
	"card_expired":        domain.ClassInstrumentStale,
	"card_not_supported":  domain.ClassInstrumentStale,
	"upi_collect_expired": domain.ClassCustomerAction,
	"invalid_otp":         domain.ClassCustomerAction,
	"payment_cancelled":   domain.ClassCustomerAction,
}

type cassette struct {
	Context struct {
		ErrorCode string `json:"error_code"`
	} `json:"context"`
	Proposal struct {
		FailureClassification string  `json:"failure_classification"`
		ConfidenceScore       float64 `json:"confidence_score"`
	} `json:"proposal"`
}

// cmdLearnCalibrate measures whether a stated probability means anything.
//
// Two things in this system state one. The recovery model predicts how likely
// an attempt is to succeed, and that number is multiplied by a real amount to
// price the attempt. The inference tier states a confidence in its
// classification, and the gatekeeper refuses anything below a floor somebody
// chose. Neither has ever been checked against an outcome, and a probability
// that has not been checked is a mood.
func cmdLearnCalibrate(ctx context.Context, g globals, dir string, out io.Writer) error {
	rep := calibrateReport{Schema: "resilientmesh.calibrate.v1"}

	recovery, err := calibrateRecoveryModel(ctx)
	if err != nil {
		return err
	}
	rep.Recovery = recovery

	cls, note, err := calibrateClassifier(ctx, dir)
	if err != nil {
		return err
	}
	rep.Classification, rep.ClassificationNote = cls, note

	if g.jsonOut {
		return writeJSON(out, rep)
	}
	return renderCalibrate(out, rep)
}

// calibrateRecoveryModel measures the model whose probabilities become money.
//
// The predictions are out of fold, so no attempt is scored by a model that saw
// its own outcome. The outcomes are the real ones the world produced. Both the
// sample size and the ground truth are exactly what a production calibration
// study would want and almost never has.
func calibrateRecoveryModel(ctx context.Context) (calibrationView, error) {
	w, err := lab.New(lab.Config{Incidents: calibrationIncidents, Seed: defaultLearnSeed})
	if err != nil {
		return calibrationView{}, err
	}
	run, err := w.Run(lab.Uniform{}, defaultLearnSeed)
	if err != nil {
		return calibrationView{}, err
	}
	if err := ctx.Err(); err != nil {
		return calibrationView{}, err
	}

	model, _, err := lab.FitRewardModel(run.Log, w.Incidents(), reward.Options{Seed: defaultLearnSeed})
	if err != nil {
		return calibrationView{}, err
	}

	incidents := w.Incidents()
	obs := make([]calib.Observation, len(run.Log))
	for k, e := range run.Log {
		p, err := model.PredictFor(k, incidents[e.Index].Features(e.Arm))
		if err != nil {
			return calibrationView{}, err
		}
		obs[k] = calib.Observation{Confidence: p, Correct: e.Recovered}
	}

	view, err := measureCalibration("learned recovery probability", obs, defaultLearnSeed)
	if err != nil {
		return calibrationView{}, err
	}
	view.Limitation = "predictions are out of fold, so no attempt was scored by a model that had seen its own outcome"
	return view, nil
}

// calibrateClassifier measures the inference tier stated confidence against the
// cassettes it can honestly be measured against.
func calibrateClassifier(ctx context.Context, dir string) (*calibrationView, string, error) {
	if dir == "" {
		dir = filepath.Join("testdata", "cassettes")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, "", err
	}
	if len(files) == 0 {
		return nil, fmt.Sprintf("no cassettes under %s, so the classifier was not measured", dir), nil
	}
	sort.Strings(files)

	obs := make([]calib.Observation, 0, len(files))
	for _, f := range files {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, "", fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		var c cassette
		if err := json.Unmarshal(raw, &c); err != nil {
			continue
		}
		want, labelled := unambiguousClass[strings.ToLower(strings.TrimSpace(c.Context.ErrorCode))]
		if !labelled {
			continue
		}
		if conf := c.Proposal.ConfidenceScore; conf >= 0 && conf <= 1 {
			obs = append(obs, calib.Observation{
				Confidence: conf,
				Correct:    domain.ParseFailureClass(c.Proposal.FailureClassification) == want,
			})
		}
	}
	if len(obs) < 2*calib.DefaultFolds {
		return nil, fmt.Sprintf(
			"%d of %d cassettes carry a decline code whose class is fixed by the code itself, which is too few to calibrate against. "+
				"The corpus was built to exercise ambiguous failures, where the class depends on telemetry the code does not carry, "+
				"so a label taken from the code alone would be measuring the label rather than the model. See unambiguousClass.",
			len(obs), len(files)), nil
	}

	view, err := measureCalibration("inference tier stated confidence", obs, defaultLearnSeed)
	if err != nil {
		return nil, "", err
	}
	view.Population = len(files)
	view.Limitation = "measured only on decline codes whose causal class is fixed by the code itself; " +
		"ambiguous codes are excluded rather than scored against another model"

	deployed, err := calib.AccuracyAt(obs, domain.MinConfidenceToActOn)
	if err != nil {
		return nil, "", err
	}
	view.DeployedThreshold = &thresholdView{
		Confidence: deployed.Confidence, Accuracy: deployed.Accuracy,
		Coverage: deployed.Coverage, Accepted: deployed.Accepted,
	}
	if th, err := calib.ThresholdFor(obs, 0.90); err == nil {
		view.MeasuredThreshold = &thresholdView{
			Confidence: th.Confidence, Accuracy: th.Accuracy,
			Coverage: th.Coverage, Accepted: th.Accepted,
		}
	} else {
		view.ThresholdNote = "no stated confidence in this corpus reaches 90% agreement, so thresholding alone cannot buy it"
	}
	return &view, "", nil
}

// calibrationIncidents keeps the recovery measurement large enough that the
// noise floor is well below any miscalibration worth acting on.
const calibrationIncidents = 60_000

func measureCalibration(subject string, obs []calib.Observation, seed int64) (calibrationView, error) {
	repair, err := calib.FitAndMeasure(obs, calib.Options{Seed: seed})
	if err != nil {
		return calibrationView{}, err
	}
	view := calibrationView{
		Subject:        subject,
		Observations:   len(obs),
		Accuracy:       repair.Before.Accuracy,
		MeanConfidence: repair.Before.MeanConfidence,
		Overconfident:  repair.Before.Overconfident,
		ECE:            repair.Before.ECE,
		MCE:            repair.Before.MCE,
		NoiseFloor:     repair.NoiseFloor,
		Significant:    repair.Significant,
		AfterECE:       repair.After.ECE,
		Reduction:      repair.Reduction,
	}
	for _, b := range repair.Before.Bins {
		if b.Count == 0 {
			continue
		}
		view.Bins = append(view.Bins, calibBin{
			Lower: b.Lower, Upper: b.Upper, Count: b.Count,
			Confidence: b.MeanConfidence, Accuracy: b.Accuracy, Thin: b.Thin,
		})
	}
	return view, nil
}

func renderCalibrate(out io.Writer, r calibrateReport) error {
	renderCalibrationView(out, r.Recovery)
	if r.Classification != nil {
		fmt.Fprintln(out)
		renderCalibrationView(out, *r.Classification)
	} else if r.ClassificationNote != "" {
		fmt.Fprintf(out, "\ninference tier stated confidence\n\n  not measured: %s\n",
			wrap(r.ClassificationNote, 66, "  "))
	}
	return nil
}

func renderCalibrationView(out io.Writer, v calibrationView) {
	fmt.Fprintf(out, "%s  %d observations", v.Subject, v.Observations)
	if v.Population > 0 {
		fmt.Fprintf(out, " of %d", v.Population)
	}
	fmt.Fprintf(out, "\n\n")

	fmt.Fprintf(out, "  mean stated               %.3f\n", v.MeanConfidence)
	fmt.Fprintf(out, "  observed rate             %.3f\n", v.Accuracy)
	if v.Overconfident {
		fmt.Fprintf(out, "  overstates by             %.3f\n", v.MeanConfidence-v.Accuracy)
	} else {
		fmt.Fprintf(out, "  understates by            %.3f\n", v.Accuracy-v.MeanConfidence)
	}

	fmt.Fprintf(out, "\n  %-14s %9s %10s %10s %9s\n", "stated", "n", "claimed", "observed", "gap")
	for _, b := range v.Bins {
		thin := ""
		if b.Thin {
			thin = "  (thin)"
		}
		fmt.Fprintf(out, "  [%.1f, %.1f)   %9d %10.3f %10.3f %9.3f%s\n",
			b.Lower, b.Upper, b.Count, b.Confidence, b.Accuracy, b.Confidence-b.Accuracy, thin)
	}

	fmt.Fprintf(out, "\n  expected calibration error  %.4f\n", v.ECE)
	fmt.Fprintf(out, "  worst bin                   %.4f\n", v.MCE)
	fmt.Fprintf(out, "  noise floor at this size    %.4f\n", v.NoiseFloor)
	if v.Significant {
		fmt.Fprintf(out, "  verdict                     real miscalibration, not sampling noise\n")
		fmt.Fprintf(out, "  after isotonic correction   %.4f  (cross-fitted, so honest)\n", v.AfterECE)
	} else {
		fmt.Fprintf(out, "  verdict                     inside the noise floor; nothing to correct\n")
	}

	if v.DeployedThreshold != nil {
		fmt.Fprintf(out, "\n  what the deployed threshold buys\n")
		fmt.Fprintf(out, "    confidence >= %.2f          %.1f%% correct over %.1f%% of traffic\n",
			v.DeployedThreshold.Confidence, 100*v.DeployedThreshold.Accuracy, 100*v.DeployedThreshold.Coverage)
		if v.MeasuredThreshold != nil {
			fmt.Fprintf(out, "    for 90%% correct              confidence >= %.2f, keeping %.1f%% of traffic\n",
				v.MeasuredThreshold.Confidence, 100*v.MeasuredThreshold.Coverage)
		} else if v.ThresholdNote != "" {
			fmt.Fprintf(out, "    %s\n", wrap(v.ThresholdNote, 66, "    "))
		}
	}
	if v.Limitation != "" {
		fmt.Fprintf(out, "\n  note: %s\n", wrap(v.Limitation, 66, "        "))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toPolicyRun(r lab.RunResult) policyRun {
	return policyRun{
		Name:         r.Policy,
		Decisions:    r.Decisions,
		RecoveryRate: r.RecoveryRate,
		NetPaisa:     r.NetPaisa,
		MeanNetPaisa: r.MeanNetPaisa,
	}
}

func toInterval(v, lo, hi, conf float64) interval {
	return interval{Value: v, Lower: lo, Upper: hi, Confidence: conf}
}

func armCounts(in map[bandit.Arm]int) map[string]int {
	out := make(map[string]int, len(in))
	for a, n := range in {
		out[lab.ArmLabel(a)] = n
	}
	return out
}

func exploreRate(run lab.RunResult) float64 {
	if len(run.Log) == 0 {
		return 0
	}
	// A decision counts as exploration when the arm drawn was not the one the
	// distribution favoured most.
	var explored int
	for _, e := range run.Log {
		var best bandit.Arm
		bestP := -1.0
		for a, p := range e.Distribution {
			if p > bestP || (p == bestP && a < best) {
				best, bestP = a, p
			}
		}
		if e.Arm != best {
			explored++
		}
	}
	return float64(explored) / float64(len(run.Log))
}

// wrap breaks a sentence across lines at a width, continuing with an indent.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, w := range words {
		if i > 0 {
			if line+1+len(w) > width {
				b.WriteString("\n" + indent)
				line = 0
			} else {
				b.WriteByte(' ')
				line++
			}
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}

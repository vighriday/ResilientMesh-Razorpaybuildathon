package modelcheck

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
)

// A full exploration takes seconds, so every test that only reads its result
// shares one run. The determinism test compares a second, independent run
// against it.
var (
	sharedOnce   sync.Once
	sharedReport Report
	sharedErr    error
)

// exploreConfig is the configuration the shared run and the determinism run
// both use. Under the race detector it is bounded: this package explores in a
// single goroutine on purpose, so the detector has nothing to find and would
// only multiply a five-second sweep into minutes of CI time.
func exploreConfig() Config {
	if raceEnabled {
		return Config{MaxStates: 100_000}
	}
	return Config{}
}

func sharedRun(t *testing.T) Report {
	t.Helper()
	sharedOnce.Do(func() { sharedReport, sharedErr = Run(exploreConfig()) })
	if sharedErr != nil {
		t.Fatalf("Run: %v", sharedErr)
	}
	return sharedReport
}

// fullRun is sharedRun for the tests whose claims only mean something over the
// complete space.
func fullRun(t *testing.T) Report {
	t.Helper()
	if raceEnabled {
		t.Skip("the exhaustive sweep is single-goroutine; -race adds no signal and costs minutes")
	}
	return sharedRun(t)
}

// ---------------------------------------------------------------------------
// The exploration itself
// ---------------------------------------------------------------------------

func TestRunIsDeterministic(t *testing.T) {
	a := sharedRun(t)
	b, err := Run(exploreConfig())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	// The digest commits to the counts, the per-invariant verdicts and the
	// witness selection. Comparing it is the whole determinism claim in one
	// line; the individual comparisons below exist to make a failure readable.
	if a.Digest != b.Digest {
		t.Errorf("digest differs between runs: %s vs %s", a.Digest, b.Digest)
	}
	if a.ReachableStates != b.ReachableStates {
		t.Errorf("reachable states differ: %d vs %d", a.ReachableStates, b.ReachableStates)
	}
	if a.Transitions != b.Transitions {
		t.Errorf("transitions differ: %d vs %d", a.Transitions, b.Transitions)
	}
	if a.TotalViolations != b.TotalViolations {
		t.Errorf("violations differ: %d vs %d", a.TotalViolations, b.TotalViolations)
	}
	if len(a.Violations) != len(b.Violations) {
		t.Fatalf("witness count differs: %d vs %d", len(a.Violations), len(b.Violations))
	}
	for i := range a.Violations {
		if a.Violations[i].State.Key != b.Violations[i].State.Key ||
			a.Violations[i].Invariant != b.Violations[i].Invariant {
			t.Fatalf("witness %d differs: %+v vs %+v", i, a.Violations[i], b.Violations[i])
		}
	}
}

func TestExplorationIsComplete(t *testing.T) {
	r := fullRun(t)
	if !r.Complete() {
		t.Fatalf("exploration was bounded, so it proves nothing over the whole space: %s", r.BoundNote)
	}
	if r.Decisions != r.ReachableStates {
		t.Errorf("the gate was driven at %d states but %d were reachable; every reachable state must be decided",
			r.Decisions, r.ReachableStates)
	}
	if r.ReachableStates >= r.AbstractStates {
		t.Errorf("reachable %d is not a strict subset of the abstract product %d; the transition relation has "+
			"stopped constraining anything and the BFS has degenerated into enumeration",
			r.ReachableStates, r.AbstractStates)
	}
	for _, inv := range r.Invariants {
		if inv.Checked != r.ReachableStates {
			t.Errorf("invariant %s was checked at %d states, not all %d", inv.Name, inv.Checked, r.ReachableStates)
		}
	}
}

// TestReachableSetHasTheRightShape asserts what the system's dynamics can and
// cannot produce. These are structural claims rather than a pinned count: a
// count would drift with any change to the gate and would say nothing about why
// it moved, whereas each of these is a safety property with its own argument.
func TestReachableSetHasTheRightShape(t *testing.T) {
	r := fullRun(t)
	reach := r.Reachability

	// The headline result. The only transition that increments the per-cycle
	// counter is an executable command, and the gate refuses to emit one at the
	// cap, so no reachable state carries an over-cap count.
	if maxCycleAttempts <= gatekeeper.DefaultMandateCycleCap {
		t.Fatalf("the abstraction must contain an out-of-range attempt count to prove it unreachable: "+
			"maxCycleAttempts=%d cap=%d", maxCycleAttempts, gatekeeper.DefaultMandateCycleCap)
	}
	for attempts := gatekeeper.DefaultMandateCycleCap + 1; attempts <= maxCycleAttempts; attempts++ {
		if n := reach.AttemptHistogram[attempts]; n != 0 {
			t.Errorf("%d states reachable with %d attempts in cycle, above the cap of %d",
				n, attempts, gatekeeper.DefaultMandateCycleCap)
		}
	}
	// ...and every count at or below the cap is reachable, so the result above
	// is a proof rather than an artefact of the exploration stalling early.
	for attempts := 0; attempts <= gatekeeper.DefaultMandateCycleCap; attempts++ {
		if reach.AttemptHistogram[attempts] == 0 {
			t.Errorf("no state reachable with %d attempts in cycle; the exploration never got off the ground",
				attempts)
		}
	}

	// A mandate is halted by the cycle-cap verdict and never un-halted, so a
	// halted state below the cap would mean something else halted it.
	if reach.HaltedBelowCycleCap != 0 {
		t.Errorf("%d halted states are below the cycle cap", reach.HaltedBelowCycleCap)
	}
	if reach.HaltedStates == 0 {
		t.Error("no halted state is reachable, so the cycle-cap halt path was never exercised")
	}

	// An attempt resets the clock to the present, so nothing that has attempted
	// anything can still be observing a future-dated mandate row.
	if reach.PostAttemptClockSkew != 0 {
		t.Errorf("%d states have attempted a debit yet still observe a future-dated mandate row",
			reach.PostAttemptClockSkew)
	}

	t.Logf("reachable=%d of %d abstract; transitions=%d; attempts histogram=%v; halted=%d",
		r.ReachableStates, r.AbstractStates, r.Transitions, reach.AttemptHistogram, reach.HaltedStates)
}

// TestGateNeverExecutesAtTheCycleCap is the local half of the argument above:
// the exploration shows the over-cap state is never reached, and this shows why
// — the gate refuses to emit an executable command from any state at the cap.
func TestGateNeverExecutesAtTheCycleCap(t *testing.T) {
	for _, k := range seed() {
		if s := StateFromKey(k); s.Attempts != 0 {
			t.Fatalf("seed state %d does not model a fresh mandate", k)
		}
	}
	g := gatekeeper.New(fixedClock{at: DefaultClockAt}, nil, gatekeeper.Config{})
	ctx := context.Background()
	for _, k := range seed() {
		s := StateFromKey(k)
		s.Attempts = gatekeeper.DefaultMandateCycleCap
		cmd, err := g.Decide(ctx, s.GateInput(DefaultClockAt))
		if err != nil {
			t.Fatalf("Decide at the cycle cap: %v", err)
		}
		if cmd.Executable() {
			t.Fatalf("gate emitted executable %s at the cycle cap from state %+v", cmd.Action, s.View())
		}
		if !gatekeeper.RequiresMandateHalt(cmd) {
			t.Fatalf("gate did not oblige a halt at the cycle cap from state %+v", s.View())
		}
	}
}

// ---------------------------------------------------------------------------
// Non-vacuity: a checker that has never seen a violation is indistinguishable
// from one that cannot see any.
// ---------------------------------------------------------------------------

// brokenGate is a deliberately unsafe gatekeeper. Every defect it exhibits is
// one an invariant in this package claims to catch: money sourced from model
// output, an out-of-set action echoed straight through, an attempt counter past
// the ceiling, a negative schedule, a recurring debit with neither a cooling
// window nor a notice, a refresh that moves rails.
type brokenGate struct{ clock domain.Clock }

func (g brokenGate) Decide(ctx context.Context, in domain.GateInput) (domain.SanitizedCommand, error) {
	if err := ctx.Err(); err != nil {
		return domain.SanitizedCommand{}, err
	}
	now := g.clock.Now()
	cmd := domain.SanitizedCommand{
		IncidentID: in.IncidentID,
		PaymentID:  in.Payment.ID,
		OrderID:    in.Payment.OrderID,
		// Sourced from the proposal rather than the verified payment.
		ImmutableAmountPaisa: in.Payment.Amount + in.Proposal.RecommendedDelaySec + 1,
		Currency:             "XX",
		Action:               domain.ActionAsyncRetry,
		TargetRail:           domain.RailNone,
		DelaySeconds:         -1,
		ExecuteAfter:         now,
		DecidedAt:            now,
		AttemptNumber:        in.AttemptNumber + 99,
		MaxAttempts:          gatekeeper.DefaultMaxAttempts,
	}
	switch {
	case !in.Proposal.RecommendedAction.Valid():
		cmd.Action = in.Proposal.RecommendedAction
	case in.Proposal.RecommendedAction == domain.ActionInstrumentRefresh:
		cmd.Action = domain.ActionInstrumentRefresh
		cmd.TargetRail = domain.RailNetbanking
	}
	return cmd, nil
}

func TestCheckerDetectsEveryInjectedDefect(t *testing.T) {
	r, err := Run(Config{
		// The seed set alone already covers every proposal, amount, category
		// and recurring flag, so a bound at its size exercises all eight
		// properties without paying for the full reachability closure.
		MaxStates: len(seed()),
		Gate:      func(clock domain.Clock) domain.Gatekeeper { return brokenGate{clock: clock} },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, inv := range r.Invariants {
		if inv.Name == InvGateError {
			if inv.Violations != 0 {
				t.Errorf("broken gate reported a decision error it was not supposed to: %d", inv.Violations)
			}
			continue
		}
		if inv.Violations == 0 {
			t.Errorf("invariant %s reported no violation against a gate that violates it; the check is vacuous",
				inv.Name)
		}
	}
	if len(r.Violations) == 0 {
		t.Fatal("no counterexamples recorded")
	}
}

// TestCheckerRecordsDecisionFailures proves the remaining reporting path: a
// gate that errors is recorded rather than skipped, because a skipped state is
// a hole in the proof that nothing in the report would mention.
func TestCheckerRecordsDecisionFailures(t *testing.T) {
	sentinel := errors.New("gate unavailable")
	r, err := Run(Config{
		MaxStates: 64,
		Gate: func(domain.Clock) domain.Gatekeeper {
			return erroringGate{err: sentinel}
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var reported int64
	for _, inv := range r.Invariants {
		if inv.Name == InvGateError {
			reported = inv.Violations
		}
	}
	if reported != r.Decisions {
		t.Fatalf("recorded %d decision failures over %d decisions; every failure must be reported",
			reported, r.Decisions)
	}
	if r.Passed() {
		t.Fatal("a run in which the gate never decided must not pass")
	}
	if len(r.Violations) == 0 || !strings.Contains(r.Violations[0].Detail, sentinel.Error()) {
		t.Fatalf("witness does not carry the decision error: %+v", r.Violations)
	}
}

type erroringGate struct{ err error }

func (g erroringGate) Decide(context.Context, domain.GateInput) (domain.SanitizedCommand, error) {
	return domain.SanitizedCommand{}, g.err
}

// ---------------------------------------------------------------------------
// The known state of the real gatekeeper
// ---------------------------------------------------------------------------

// knownOpenFindings is the escape hatch for an invariant the shipped
// gatekeeper does not yet satisfy: the recorded number is an upper bound, so a
// count that grows fails as a regression while a count that falls to zero —
// because the gap was closed — passes.
//
// It is empty, and that is the result worth stating. It was not always: the
// first exhaustive sweep of this space reported 28,560 states in which a
// recurring debit above its category's additional-factor ceiling was scheduled
// as an ordinary mandate cascade (the D1 RBI_AFA_CEILING rule was absent), and
// 29,952 in which an INSTRUMENT_REFRESH command left the gate with its rail
// stripped to "none" yet still reported itself executable, because the gate's
// internal executable() helper and domain.SanitizedCommand.Executable()
// disagreed about that action. Both are now fixed upstream. Anything added back
// here needs the same treatment: a named gap with a bound, never a silent pass.
var knownOpenFindings = map[string]int64{}

func TestEveryInvariantHoldsAtEveryReachableState(t *testing.T) {
	r := fullRun(t)
	for _, inv := range r.Invariants {
		limit, known := knownOpenFindings[inv.Name]
		switch {
		case !known && inv.Violations != 0:
			t.Errorf("invariant %s: %d violations over %d states, expected none.\nwhy it matters: %s",
				inv.Name, inv.Violations, inv.Checked, inv.Why)
		case known && inv.Violations > limit:
			t.Errorf("invariant %s regressed: %d violations, previously bounded at %d",
				inv.Name, inv.Violations, limit)
		case known:
			t.Logf("known open finding %s: %d violations over %d states (upstream gap in internal/gatekeeper)",
				inv.Name, inv.Violations, inv.Checked)
		}
	}
	if r.TotalViolations > 0 && len(r.Violations) == 0 {
		t.Fatal("violations counted but no counterexample recorded; the report is unactionable")
	}
	if len(knownOpenFindings) == 0 && !r.Passed() {
		t.Errorf("%d violations with no gap recorded for them", r.TotalViolations)
	}
}

// ---------------------------------------------------------------------------
// Soundness of the abstraction
// ---------------------------------------------------------------------------

// TestVetoOnlyDimensionsAreSound discharges the reduction claimed in the
// package comment: the error code, the failure class and the confidence score
// are pinned rather than enumerated because each can only force an abstention,
// and an abstained command satisfies every property here. Left as prose the
// claim is an assumption; checked against the real gate it is a lemma.
func TestVetoOnlyDimensionsAreSound(t *testing.T) {
	g := gatekeeper.New(fixedClock{at: DefaultClockAt}, nil, gatekeeper.Config{})
	ctx := context.Background()

	type override struct {
		name  string
		apply func(*domain.GateInput)
	}
	overrides := []override{
		{"terminal_decline", func(in *domain.GateInput) { in.Payment.ErrorCode = "card_lost_or_stolen" }},
		{"terminal_decline_mixed_case", func(in *domain.GateInput) { in.Payment.ErrorCode = "  MANDATE_REVOKED " }},
		{"unrecoverable_class", func(in *domain.GateInput) {
			in.Proposal.FailureClassification = domain.ClassPermanentInstrument
		}},
		{"invented_class", func(in *domain.GateInput) {
			in.Proposal.FailureClassification = domain.FailureClass("DEFINITELY_RECOVERABLE")
		}},
		{"sub_floor_confidence", func(in *domain.GateInput) { in.Proposal.ConfidenceScore = 0.1 }},
		{"nan_confidence", func(in *domain.GateInput) { in.Proposal.ConfidenceScore = nan() }},
	}

	// A stride over the seed set rather than the whole set: the claim is about
	// every dimension appearing, not about every combination, and the stride is
	// coprime with all of the domain sizes so it walks each of them.
	seeds := seed()
	const stride = 997
	for _, ov := range overrides {
		checked := 0
		for i := 0; i < len(seeds); i += stride {
			s := StateFromKey(seeds[i])
			for attempts := uint8(0); attempts <= maxCycleAttempts; attempts++ {
				s.Attempts = attempts
				in := s.GateInput(DefaultClockAt)
				ov.apply(&in)
				cmd, err := g.Decide(ctx, in)
				if err != nil {
					t.Fatalf("%s: Decide: %v", ov.name, err)
				}
				if cmd.Action != domain.ActionAbstain {
					t.Fatalf("%s at state %+v produced %s, not an abstention; the reduction in the package "+
						"comment is unsound and the dimension must be enumerated", ov.name, s.View(), cmd.Action)
				}
				c := checkInput{state: s, in: in, cmd: cmd, maxAttempts: cmd.MaxAttempts}
				for _, inv := range invariants {
					if detail := inv.check(c); detail != "" {
						t.Fatalf("%s: abstained command violates %s: %s", ov.name, inv.name, detail)
					}
				}
				checked++
			}
		}
		if checked == 0 {
			t.Fatalf("%s: nothing was checked", ov.name)
		}
	}
}

func nan() float64 {
	var zero float64
	return zero / zero
}

// TestPolicyBackoffRangeIsBracketed discharges the second reduction: the real
// policy engine's backoff is replaced by a three-value proposal-delay
// dimension, which is only sound if the engine's entire output range lies
// inside the interval those values bracket.
func TestPolicyBackoffRangeIsBracketed(t *testing.T) {
	lo := proposalDelaysSec[0]
	hi := proposalDelaysSec[len(proposalDelaysSec)-1]
	if lo != 0 || hi != domain.MaxRecommendedDelay {
		t.Fatalf("the delay dimension no longer brackets [0,%d]: %v", domain.MaxRecommendedDelay, proposalDelaysSec)
	}

	classes := []domain.FailureClass{
		domain.ClassTransientDegradation, domain.ClassIssuerOutage, domain.ClassNetworkTimeout,
		domain.ClassPSPDegradation, domain.ClassCustomerAction, domain.ClassInsufficientFunds,
		domain.ClassInstrumentStale, domain.ClassPermanentInstrument, domain.ClassUnknown,
	}
	snap := domain.TelemetrySnapshot{Attempts: 40, Successes: 1, Failures: 39, SuccessRate: 0.025}
	for _, class := range classes {
		for attempt := -1; attempt <= maxCycleAttempts+2; attempt++ {
			d := policy.BackoffCeiling(attempt, class, snap)
			if d < policy.MinBackoff {
				t.Errorf("class %s attempt %d: ceiling %s below the floor %s", class, attempt, d, policy.MinBackoff)
			}
			if d > policy.MaxBackoff {
				t.Errorf("class %s attempt %d: ceiling %s above the schedulable horizon %s",
					class, attempt, d, policy.MaxBackoff)
			}
			if secs := int64(d / time.Second); secs < lo || secs > hi {
				t.Errorf("class %s attempt %d: %ds falls outside the bracketed [%d,%d]", class, attempt, secs, lo, hi)
			}
		}
	}
}

// TestCategoriesPartitionIntoTwoCeilings records why enumerating all four
// mandate categories is redundant today and why the redundancy is kept: the
// moment one of them gets its own ceiling, this test changes and the state
// space already covers it.
func TestCategoriesPartitionIntoTwoCeilings(t *testing.T) {
	seen := map[int64][]domain.MandateCategory{}
	for _, c := range categories {
		seen[c.AFACeilingPaisa()] = append(seen[c.AFACeilingPaisa()], c)
	}
	if len(seen) != 2 {
		t.Fatalf("categories now map onto %d ceilings, not 2: %v", len(seen), seen)
	}
	if _, ok := seen[domain.AFACeilingGeneralPaisa]; !ok {
		t.Errorf("no category maps to the general ceiling %d", domain.AFACeilingGeneralPaisa)
	}
	if _, ok := seen[domain.AFACeilingElevatedPaisa]; !ok {
		t.Errorf("no category maps to the elevated ceiling %d", domain.AFACeilingElevatedPaisa)
	}
}

// TestAmountsStraddleEveryCeiling and TestHourBucketsStraddleEveryThreshold are
// the abstraction's own regression tests: a bucket set that drifts off a
// threshold stops covering the branch it was chosen for, silently.
func TestAmountsStraddleEveryCeiling(t *testing.T) {
	for _, ceiling := range []int64{domain.AFACeilingGeneralPaisa, domain.AFACeilingElevatedPaisa} {
		var below, at, above bool
		for _, a := range amountsPaisa {
			switch {
			case a < ceiling:
				below = true
			case a == ceiling:
				at = true
			default:
				above = true
			}
		}
		if !below || !at || !above {
			t.Errorf("ceiling %d is not straddled (below=%t at=%t above=%t) by %v",
				ceiling, below, at, above, amountsPaisa)
		}
	}
}

func TestHourBucketsStraddleEveryThreshold(t *testing.T) {
	const noticeValidityHours = 30 * 24
	const coolingHours = 24
	thresholds := map[string]int{
		"pre-debit notice validity": noticeValidityHours,
		"RBI cooling window":        coolingHours,
		"clock skew (now)":          0,
	}
	for name, threshold := range thresholds {
		var below, at, above bool
		for _, h := range hourBuckets {
			switch {
			case h < threshold:
				below = true
			case h == threshold:
				at = true
			default:
				above = true
			}
		}
		if !below || !at || !above {
			t.Errorf("%s at %dh is not straddled (below=%t at=%t above=%t) by %v",
				name, threshold, below, at, above, hourBuckets)
		}
	}
	if hourBuckets[hourZeroIndex] != 0 {
		t.Fatalf("hourZeroIndex points at %dh, not the instant an attempt resets to", hourBuckets[hourZeroIndex])
	}
}

func TestProposalsCoverTheClosedActionSetAndOneOutsideIt(t *testing.T) {
	covered := map[domain.Action]bool{}
	outside := 0
	for _, p := range proposals {
		if p.action.Valid() {
			covered[p.action] = true
			continue
		}
		outside++
	}
	for _, a := range []domain.Action{
		domain.ActionRailMorph, domain.ActionAsyncRetry, domain.ActionMandateCascade,
		domain.ActionInstrumentRefresh, domain.ActionAbstain,
	} {
		if !covered[a] {
			t.Errorf("proposal dimension never offers %s", a)
		}
	}
	if outside == 0 {
		t.Error("proposal dimension offers nothing outside the closed set, so the fail-closed path is untested")
	}
}

// ---------------------------------------------------------------------------
// State encoding
// ---------------------------------------------------------------------------

func TestKeyRoundTripsOverTheWholeSpace(t *testing.T) {
	const keySpace = 1 << 23
	var valid int64
	for k := uint32(0); k < keySpace; k++ {
		s := StateFromKey(k)
		if !s.valid() {
			continue
		}
		valid++
		if got := s.Key(); got != k {
			t.Fatalf("key %d unpacked to %+v which repacks to %d", k, s, got)
		}
	}
	if valid != AbstractStateCount() {
		t.Fatalf("the key space holds %d valid states, AbstractStateCount reports %d", valid, AbstractStateCount())
	}
}

func TestSeedSetIsSortedUniqueAndFresh(t *testing.T) {
	seeds := seed()
	if len(seeds) == 0 {
		t.Fatal("no seed states")
	}
	for i := 1; i < len(seeds); i++ {
		if seeds[i-1] >= seeds[i] {
			t.Fatalf("seed set is not strictly ascending at %d: %d then %d", i, seeds[i-1], seeds[i])
		}
	}
	for _, k := range seeds {
		s := StateFromKey(k)
		if !s.valid() {
			t.Fatalf("seed %d is not a valid state", k)
		}
		if s.Attempts != 0 || s.Notified || s.Halted {
			t.Fatalf("seed %d is not a fresh mandate: %+v", k, s.View())
		}
	}
}

func TestSuccessorsAreSortedDeduplicatedAndLoopFree(t *testing.T) {
	g := gatekeeper.New(fixedClock{at: DefaultClockAt}, nil, gatekeeper.Config{})
	ex := &explorer{cfg: Config{}.withDefaults(), gate: g, now: DefaultClockAt}
	ctx := context.Background()

	seeds := seed()
	const stride = 601
	for i := 0; i < len(seeds); i += stride {
		s := StateFromKey(seeds[i])
		cmd, err := g.Decide(ctx, s.GateInput(DefaultClockAt))
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		succ := ex.successors(s, cmd, nil)
		for j := 1; j < len(succ); j++ {
			if succ[j-1] >= succ[j] {
				t.Fatalf("successors of %d are not strictly ascending: %v", s.Key(), succ)
			}
		}
		for _, k := range succ {
			if k == s.Key() {
				t.Fatalf("successors of %d contain a self-loop", s.Key())
			}
			if !StateFromKey(k).valid() {
				t.Fatalf("successor %d of %d is not a valid state", k, s.Key())
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Bounding and cancellation
// ---------------------------------------------------------------------------

func TestBoundedRunSaysSoInsteadOfTruncatingSilently(t *testing.T) {
	r, err := Run(Config{MaxStates: 1000})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !r.Bounded {
		t.Fatal("a run bounded to 1000 states did not report itself bounded")
	}
	if r.Complete() {
		t.Fatal("a bounded run must not report itself complete")
	}
	if r.BoundNote == "" {
		t.Fatal("bounded run carries no explanation")
	}
	if r.ReachableStates > 1000 {
		t.Fatalf("bound of 1000 was exceeded: %d states", r.ReachableStates)
	}
	if !strings.Contains(r.BoundNote, "1000") {
		t.Errorf("bound note does not name the bound: %q", r.BoundNote)
	}
}

func TestCancellationStopsTheExploration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunContext(ctx, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run returned %v, want a wrapped context.Canceled", err)
	}
}

func TestNilGateIsRejected(t *testing.T) {
	_, err := Run(Config{Gate: func(domain.Clock) domain.Gatekeeper { return nil }})
	if err == nil {
		t.Fatal("a Config that supplies no gatekeeper must fail rather than explore nothing and pass")
	}
}

// ---------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------

func TestReportCarriesEveryInvariantWithItsRationale(t *testing.T) {
	r := sharedRun(t)
	if len(r.Invariants) != len(invariants)+1 {
		t.Fatalf("report lists %d invariants, want %d", len(r.Invariants), len(invariants)+1)
	}
	seen := map[string]bool{}
	for _, inv := range r.Invariants {
		if inv.Name == "" {
			t.Error("invariant with no name")
		}
		if inv.Why == "" {
			t.Errorf("invariant %s carries no rationale, so a violation cannot be triaged from the report alone",
				inv.Name)
		}
		if seen[inv.Name] {
			t.Errorf("invariant %s reported twice", inv.Name)
		}
		seen[inv.Name] = true
	}
	if r.Digest == "" || len(r.Digest) != 64 {
		t.Errorf("digest %q is not a sha256 hex string", r.Digest)
	}
	if r.MaxAttempts != gatekeeper.DefaultMaxAttempts {
		t.Errorf("report says the gate ceiling is %d, want %d", r.MaxAttempts, gatekeeper.DefaultMaxAttempts)
	}
}

func TestRunCompletesWellInsideTheBudget(t *testing.T) {
	// The specification budget is 60 s. Asserting it here keeps a change that
	// multiplies the state space from turning a proof into a CI timeout. The
	// measurement is the shared run's own, so the assertion costs nothing.
	r := fullRun(t)
	const budgetMS = 60_000
	if r.ElapsedMS > budgetMS {
		t.Fatalf("exhaustive exploration took %d ms, over the %d ms budget", r.ElapsedMS, budgetMS)
	}
	t.Logf("exhaustive exploration of %d reachable states and %d transitions in %d ms",
		r.ReachableStates, r.Transitions, r.ElapsedMS)
}

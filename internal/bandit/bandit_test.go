package bandit

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"testing"
)

func newTestModel(t *testing.T, cfg Config) *Model {
	t.Helper()
	if len(cfg.Arms) == 0 {
		cfg.Arms = []Arm{"a", "b", "c"}
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestConfigIsValidated(t *testing.T) {
	t.Parallel()
	cases := map[string]Config{
		"no arms":            {},
		"empty arm name":     {Arms: []Arm{"a", ""}},
		"duplicate arm":      {Arms: []Arm{"a", "a"}},
		"floor at one":       {Arms: []Arm{"a"}, Floor: 1},
		"negative floor":     {Arms: []Arm{"a"}, Floor: -0.1},
		"draws too many":     {Arms: []Arm{"a"}, Draws: maxDraws + 1},
		"draws negative":     {Arms: []Arm{"a"}, Draws: -1},
		"impossible prior":   {Arms: []Arm{"a"}, Prior: Posterior{Alpha: 0, Beta: 1}},
		"negative max cells": {Arms: []Arm{"a"}, MaxCells: -1},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
	if _, err := New(Config{Arms: []Arm{"a", "b"}}); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}
}

// The gamma variate is hand-rolled, so its distribution is asserted against the
// closed form rather than assumed from the citation.
func TestGammaSamplerMatchesItsMoments(t *testing.T) {
	t.Parallel()
	for _, shape := range []float64{0.3, 1, 2.5, 9} {
		rng := rand.New(rand.NewSource(int64(shape * 1000)))
		const n = 200_000
		var sum, sumSq float64
		for i := 0; i < n; i++ {
			x := gammaSample(rng, shape)
			sum += x
			sumSq += x * x
		}
		mean := sum / n
		variance := sumSq/n - mean*mean
		// Gamma(k, 1) has mean k and variance k. Three standard errors on the
		// mean is sqrt(k/n)*3, which is tiny at this sample count; the bands
		// below are deliberately looser so this cannot flake.
		if math.Abs(mean-shape) > 0.03*shape+0.01 {
			t.Errorf("Gamma(%v) mean = %.4f, want %.4f", shape, mean, shape)
		}
		if math.Abs(variance-shape) > 0.06*shape+0.02 {
			t.Errorf("Gamma(%v) variance = %.4f, want %.4f", shape, variance, shape)
		}
	}
}

func TestBetaSamplerMatchesItsMoments(t *testing.T) {
	t.Parallel()
	for _, ab := range [][2]float64{{1, 1}, {2, 5}, {8, 3}, {0.5, 0.5}} {
		a, b := ab[0], ab[1]
		rng := rand.New(rand.NewSource(int64(a*100 + b)))
		const n = 200_000
		var sum, sumSq float64
		for i := 0; i < n; i++ {
			x := betaSample(rng, a, b)
			if x < 0 || x > 1 {
				t.Fatalf("Beta(%v,%v) produced %v, outside [0,1]", a, b, x)
			}
			sum += x
			sumSq += x * x
		}
		mean := sum / n
		variance := sumSq/n - mean*mean
		wantMean := a / (a + b)
		wantVar := a * b / ((a + b) * (a + b) * (a + b + 1))
		if math.Abs(mean-wantMean) > 0.01 {
			t.Errorf("Beta(%v,%v) mean = %.4f, want %.4f", a, b, mean, wantMean)
		}
		if math.Abs(variance-wantVar) > 0.01 {
			t.Errorf("Beta(%v,%v) variance = %.4f, want %.4f", a, b, variance, wantVar)
		}
	}
}

// The distribution is the artefact that gets logged, so it has to be a
// distribution: non-negative, summing to one, over exactly the permitted arms.
func TestDistributionIsWellFormedOverThePermittedSetOnly(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c", "d"}, Floor: 0.05, Seed: 7})
	permitted := []Arm{"b", "d"}
	dist, err := m.Distribution("cell", permitted, Valuation{GrossPaisa: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	if len(dist) != 2 {
		t.Fatalf("distribution covers %d arms, want the 2 permitted", len(dist))
	}
	var sum float64
	for a, p := range dist {
		if a != "b" && a != "d" {
			t.Fatalf("distribution contains %q, which was not permitted", a)
		}
		if p < 0 || p > 1 {
			t.Fatalf("arm %q has probability %v", a, p)
		}
		sum += p
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Fatalf("distribution sums to %.15f", sum)
	}
}

// The floor is the property that makes tomorrow's off-policy evaluation
// possible, so it is asserted directly: no permitted arm may ever fall to a
// probability that would make its importance weight explode.
func TestFloorKeepsEveryPermittedArmSupported(t *testing.T) {
	t.Parallel()
	const floor = 0.05
	m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c"}, Floor: floor, Seed: 11})

	// Drive one arm to overwhelming dominance. A pure exploiter would collapse
	// onto it and the log would stop saying anything about the others.
	for i := 0; i < 500; i++ {
		if err := m.Update("cell", "a", true); err != nil {
			t.Fatal(err)
		}
		if err := m.Update("cell", "b", false); err != nil {
			t.Fatal(err)
		}
		if err := m.Update("cell", "c", false); err != nil {
			t.Fatal(err)
		}
	}
	dist, err := m.Distribution("cell", []Arm{"a", "b", "c"}, Valuation{GrossPaisa: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []Arm{"a", "b", "c"} {
		if dist[a] < floor-1e-9 {
			t.Fatalf("arm %q fell to %v, below the floor of %v: the log would lose support here", a, dist[a], floor)
		}
	}
	if dist["a"] < 0.7 {
		t.Fatalf("the dominant arm only reached %v: the floor is swamping the learning", dist["a"])
	}
}

// Without a floor, a confident model is free to collapse. That is the behaviour
// the floor exists to prevent, and it is worth pinning so the trade-off is
// visible rather than implied.
func TestWithoutAFloorTheDistributionCollapses(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Floor: 0, Seed: 3, Draws: 500})
	for i := 0; i < 800; i++ {
		if err := m.Update("cell", "a", true); err != nil {
			t.Fatal(err)
		}
		if err := m.Update("cell", "b", false); err != nil {
			t.Fatal(err)
		}
	}
	dist, err := m.Distribution("cell", []Arm{"a", "b"}, Valuation{GrossPaisa: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	if dist["b"] > 0.01 {
		t.Fatalf("expected the losing arm to be starved without a floor, got %v", dist["b"])
	}
}

// The logged propensity has to be the probability the action was actually drawn
// with. If it were an estimate, every downstream off-policy number would carry
// an unquantified error.
func TestPropensityIsTheSamplingProbability(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c"}, Floor: 0.1, Seed: 42})
	counts := map[Arm]int{}
	claimed := map[Arm]float64{}
	const rounds = 20_000
	for i := 0; i < rounds; i++ {
		d, err := m.Select("cell", []Arm{"a", "b", "c"}, Valuation{GrossPaisa: 10_000})
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(d.Propensity-d.Distribution[d.Arm]) > 1e-12 {
			t.Fatalf("propensity %v does not match the distribution entry %v", d.Propensity, d.Distribution[d.Arm])
		}
		counts[d.Arm]++
		claimed[d.Arm] += d.Propensity
	}
	// With no updates the posteriors never move, so the empirical frequency of
	// each arm must match the propensity it was logged with.
	for _, a := range []Arm{"a", "b", "c"} {
		empirical := float64(counts[a]) / rounds
		average := claimed[a] / float64(max(counts[a], 1))
		if math.Abs(empirical-average) > 0.02 {
			t.Errorf("arm %q was drawn %.3f of the time but logged a propensity of %.3f", a, empirical, average)
		}
	}
}

// The claim that this thing learns, tested the only way it can be: against a
// policy that does not.
func TestBanditOutperformsUniformExploration(t *testing.T) {
	t.Parallel()
	trueProb := map[Arm]float64{"slow": 0.20, "medium": 0.55, "fast": 0.30}
	arms := []Arm{"fast", "medium", "slow"}
	const rounds = 4_000

	m := newTestModel(t, Config{Arms: arms, Floor: 0.02, Seed: 5, Draws: 120})
	outcomes := rand.New(rand.NewSource(999))
	var learned int
	for i := 0; i < rounds; i++ {
		d, err := m.Select("cell", arms, Valuation{GrossPaisa: 10_000})
		if err != nil {
			t.Fatal(err)
		}
		ok := outcomes.Float64() < trueProb[d.Arm]
		if ok {
			learned++
		}
		if err := m.Update("cell", d.Arm, ok); err != nil {
			t.Fatal(err)
		}
	}

	uniform := rand.New(rand.NewSource(999))
	pick := rand.New(rand.NewSource(1_234))
	var baseline int
	for i := 0; i < rounds; i++ {
		if uniform.Float64() < trueProb[arms[pick.Intn(len(arms))]] {
			baseline++
		}
	}

	// Uniform play recovers the average arm, roughly 35%. The best arm is 55%.
	// A learner that has not closed most of that gap is not learning.
	if learned <= baseline {
		t.Fatalf("bandit recovered %d of %d, uniform recovered %d: no learning", learned, rounds, baseline)
	}
	rate := float64(learned) / rounds
	if rate < 0.50 {
		t.Fatalf("bandit converged to a %.1f%% recovery rate; the best arm pays 55%%", 100*rate)
	}
	post := m.Snapshot().Cells[0].Posteriors
	if post["medium"].Observations() < post["slow"].Observations() {
		t.Fatalf("the bandit spent more attempts on the worst arm than the best: %+v", post)
	}
}

// Money is not learned. A cheap arm and an expensive arm with identical
// recovery odds must be separated by the caller valuation, not by the model.
func TestValuationSeparatesArmsWithEqualOdds(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"cheap", "expensive"}, Floor: 0, Seed: 17, Draws: 400})
	for i := 0; i < 300; i++ {
		if err := m.Update("cell", "cheap", i%2 == 0); err != nil {
			t.Fatal(err)
		}
		if err := m.Update("cell", "expensive", i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	dist, err := m.Distribution("cell", []Arm{"cheap", "expensive"}, Valuation{
		GrossPaisa: 10_000,
		CostPaisa:  map[Arm]int64{"expensive": 4_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dist["cheap"] <= dist["expensive"] {
		t.Fatalf("the priced arm did not lose: %+v", dist)
	}
}

// Exploration is bounded by the permitted set, and the boundary is enforced by
// refusing rather than by clamping.
func TestSelectRefusesArmsOutsideTheActionSpace(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Seed: 1})
	if _, err := m.Select("cell", []Arm{"a", "z"}, Valuation{}); !errors.Is(err, ErrUnknownArm) {
		t.Fatalf("got %v, want ErrUnknownArm", err)
	}
	if _, err := m.Select("cell", nil, Valuation{}); !errors.Is(err, ErrNoPermittedArms) {
		t.Fatalf("got %v, want ErrNoPermittedArms", err)
	}
	if err := m.Update("cell", "z", true); !errors.Is(err, ErrUnknownArm) {
		t.Fatalf("Update accepted an unknown arm: %v", err)
	}
}

func TestSelectNeverLeavesThePermittedSet(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c", "d", "e"}, Floor: 0.1, Seed: 23})
	permitted := []Arm{"b", "c"}
	allowed := map[Arm]bool{"b": true, "c": true}
	for i := 0; i < 5_000; i++ {
		d, err := m.Select("cell", permitted, Valuation{GrossPaisa: 5_000})
		if err != nil {
			t.Fatal(err)
		}
		if !allowed[d.Arm] {
			t.Fatalf("round %d selected %q, outside the permitted set", i, d.Arm)
		}
	}
}

// A learned policy that cannot be replayed cannot be audited.
func TestSelectionIsReproducibleFromTheSeed(t *testing.T) {
	t.Parallel()
	run := func() ([]Arm, []float64, string) {
		m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c"}, Floor: 0.05, Seed: 20_260_301})
		var arms []Arm
		var props []float64
		outcomes := rand.New(rand.NewSource(4))
		for i := 0; i < 400; i++ {
			d, err := m.Select(Cell("cell-"+string(rune('a'+i%5))), []Arm{"a", "b", "c"}, Valuation{GrossPaisa: 10_000})
			if err != nil {
				t.Fatal(err)
			}
			arms = append(arms, d.Arm)
			props = append(props, d.Propensity)
			if err := m.Update(d.Cell, d.Arm, outcomes.Float64() < 0.4); err != nil {
				t.Fatal(err)
			}
		}
		return arms, props, m.Digest()
	}
	armsA, propsA, digestA := run()
	armsB, propsB, digestB := run()
	for i := range armsA {
		if armsA[i] != armsB[i] || propsA[i] != propsB[i] {
			t.Fatalf("run diverged at decision %d: %q@%v vs %q@%v", i, armsA[i], propsA[i], armsB[i], propsB[i])
		}
	}
	if digestA != digestB {
		t.Fatalf("identical runs produced different digests:\n%s\n%s", digestA, digestB)
	}
}

func TestSnapshotRoundTrips(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Seed: 8})
	for i := 0; i < 50; i++ {
		if err := m.Update(Cell("cell-"+string(rune('a'+i%3))), "a", i%3 == 0); err != nil {
			t.Fatal(err)
		}
	}
	before := m.Digest()
	st := m.Snapshot()

	restored := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Seed: 8})
	if err := restored.Restore(st); err != nil {
		t.Fatal(err)
	}
	if after := restored.Digest(); after != before {
		t.Fatalf("digest changed across a snapshot round trip:\n%s\n%s", before, after)
	}
}

func TestRestoreRejectsForeignState(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Seed: 8})
	err := m.Restore(State{Cells: []CellState{{Cell: "c", Posteriors: map[Arm]Posterior{"zzz": {Alpha: 1, Beta: 1}}}}})
	if !errors.Is(err, ErrUnknownArm) {
		t.Fatalf("got %v, want ErrUnknownArm", err)
	}
	if err := m.Restore(State{Cells: []CellState{{Cell: "c", Posteriors: map[Arm]Posterior{"a": {Alpha: 0, Beta: -1}}}}}); err == nil {
		t.Fatal("an impossible posterior was accepted")
	}
}

// The same length-prefixing argument the audit ledger makes: without it, a cell
// named "ab" holding arm "c" and a cell named "a" holding arm "bc" absorb the
// same bytes and collide.
func TestDigestCannotBeForgedByShiftingABoundary(t *testing.T) {
	t.Parallel()
	build := func(cell Cell, arm Arm) string {
		m := newTestModel(t, Config{Arms: []Arm{"c", "bc"}, Seed: 1})
		if err := m.Restore(State{Cells: []CellState{{Cell: cell, Posteriors: map[Arm]Posterior{arm: {Alpha: 3, Beta: 4}}}}}); err != nil {
			t.Fatal(err)
		}
		return m.Digest()
	}
	if build("ab", "c") == build("a", "bc") {
		t.Fatal("two different states produced the same digest")
	}
}

func TestDigestMovesWithTheBelief(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Seed: 2})
	before := m.Digest()
	if err := m.Update("cell", "a", true); err != nil {
		t.Fatal(err)
	}
	if m.Digest() == before {
		t.Fatal("an observation left the digest unchanged")
	}
}

// An unbounded cell space is an unbounded map keyed by data that traces back to
// a webhook. It degrades into a shared cell rather than growing without limit.
func TestCellBudgetOverflowsRatherThanGrowing(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a"}, Seed: 1, MaxCells: 4})
	for i := 0; i < 50; i++ {
		if err := m.Update(Cell("cell-"+string(rune('A'+i%50))), "a", true); err != nil {
			t.Fatal(err)
		}
	}
	st := m.Snapshot()
	if len(st.Cells) > 5 { // four real cells plus the overflow bucket
		t.Fatalf("cell budget was not enforced: %d cells", len(st.Cells))
	}
	var sawOverflow bool
	for _, c := range st.Cells {
		if c.Cell == OverflowCell {
			sawOverflow = true
		}
	}
	if !sawOverflow {
		t.Fatal("contexts past the budget did not land in the overflow cell")
	}
}

// Cell keys are assembled from issuer codes that arrive in webhook payloads.
func TestCellKeysAreSanitised(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a"}, Seed: 1})
	if err := m.Update(Cell("issuer:HDFC\n<script>alert(1)</script>"), "a", true); err != nil {
		t.Fatal(err)
	}
	got := string(m.Snapshot().Cells[0].Cell)
	for _, bad := range []string{"<", ">", "(", ")", "\n"} {
		if contains(got, bad) {
			t.Fatalf("cell key %q retained %q", got, bad)
		}
	}
	if err := m.Update(Cell("\x00\x01"), "a", true); err != nil {
		t.Fatal(err)
	}
}

func TestModelIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b", "c"}, Floor: 0.05, Seed: 6, Draws: 20})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d, err := m.Select(Cell("cell-"+string(rune('a'+i%4))), []Arm{"a", "b", "c"}, Valuation{GrossPaisa: 1_000})
				if err != nil {
					t.Error(err)
					return
				}
				if err := m.Update(d.Cell, d.Arm, (g+i)%3 == 0); err != nil {
					t.Error(err)
					return
				}
				_ = m.Snapshot()
			}
		}(g)
	}
	wg.Wait()
}

func TestPosteriorHelpers(t *testing.T) {
	t.Parallel()
	p := Posterior{Alpha: 4, Beta: 6}
	if got := p.Mean(); math.Abs(got-0.4) > 1e-12 {
		t.Fatalf("Mean = %v, want 0.4", got)
	}
	if got := p.Observations(); got != 8 {
		t.Fatalf("Observations = %v, want 8", got)
	}
	if got := (Posterior{Alpha: 1, Beta: 1}).Observations(); got != 0 {
		t.Fatalf("an untouched prior claims %v observations", got)
	}
}

func TestExploredLabelIsHonest(t *testing.T) {
	t.Parallel()
	m := newTestModel(t, Config{Arms: []Arm{"a", "b"}, Floor: 0.4, Seed: 13, Draws: 100})
	for i := 0; i < 200; i++ {
		if err := m.Update("cell", "a", true); err != nil {
			t.Fatal(err)
		}
		if err := m.Update("cell", "b", false); err != nil {
			t.Fatal(err)
		}
	}
	var explored int
	for i := 0; i < 1_000; i++ {
		d, err := m.Select("cell", []Arm{"a", "b"}, Valuation{GrossPaisa: 10_000})
		if err != nil {
			t.Fatal(err)
		}
		if d.Greedy != "a" {
			t.Fatalf("greedy arm is %q, but a has 200 successes and b has 200 failures", d.Greedy)
		}
		if d.Explored != (d.Arm != d.Greedy) {
			t.Fatal("the explored label disagrees with the arm that was played")
		}
		if d.Explored {
			explored++
		}
	}
	if explored == 0 {
		t.Fatal("a floor of 0.4 produced no exploration at all")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

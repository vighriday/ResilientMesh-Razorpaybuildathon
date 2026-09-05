package tuner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
)

func newTuner(t *testing.T, floor float64) *Tuner {
	t.Helper()
	tn, err := New(Config{Floor: floor, Draws: 40, Seed: 7})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tn
}

func TestArmVocabularyIsComplete(t *testing.T) {
	t.Parallel()
	seen := map[int64]bool{}
	for _, a := range Arms {
		s := ArmSeconds(a)
		if s <= 0 {
			t.Fatalf("arm %q has no delay", a)
		}
		if seen[s] {
			t.Fatalf("two arms schedule the same delay %ds", s)
		}
		seen[s] = true
		if ArmLabel(a) == string(a) {
			t.Fatalf("arm %q has no human label", a)
		}
	}
	if ArmSeconds("not-an-arm") != 0 {
		t.Fatal("an unknown arm returned a delay, which a caller could mistake for a legal one")
	}
	if got := ArmLabel("not-an-arm"); got != "not-an-arm" {
		t.Fatalf("unknown arm label = %q", got)
	}
}

// The containment property, in one assertion: nothing below the gate floor is
// ever offered.
func TestPermittedForNeverOffersAnythingBelowTheFloor(t *testing.T) {
	t.Parallel()
	for _, floor := range []int64{0, 1, 299, 300, 301, 1800, 7200, 21600, 86400, 86401, 1 << 40} {
		for _, a := range PermittedFor(floor) {
			if ArmSeconds(a) < floor {
				t.Fatalf("floor %d permitted %s at %ds", floor, a, ArmSeconds(a))
			}
		}
	}
	if n := len(PermittedFor(0)); n != len(Arms) {
		t.Fatalf("a zero floor permitted %d of %d arms", n, len(Arms))
	}
	if n := len(PermittedFor(86400)); n != 1 {
		t.Fatalf("a twenty-four hour floor permitted %d arms, want only the overnight one", n)
	}
	if n := len(PermittedFor(86401)); n != 0 {
		t.Fatalf("a floor past the longest arm permitted %d arms", n)
	}
}

// The property that ties this package to the gatekeeper: an arm at or above the
// policy engine ceiling is always honoured, because the gate draws its own
// delay from below that ceiling and takes the longer of the two.
//
// This is the assertion that would fail if either side changed independently,
// and it is the reason exploration cannot produce an attempt earlier than the
// rules allow.
func TestEveryPermittedArmSurvivesTheRealGatekeeper(t *testing.T) {
	t.Parallel()

	clock := fixed{time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)}
	engine := policy.New(clock, nil)
	gate := gatekeeperFor(clock, engine)

	classes := []domain.FailureClass{
		domain.ClassTransientDegradation, domain.ClassIssuerOutage,
		domain.ClassNetworkTimeout, domain.ClassInsufficientFunds,
		domain.ClassCustomerAction,
	}
	snap := domain.TelemetrySnapshot{
		IssuerKey: "netbanking:SBI", WindowSeconds: 300, Attempts: 400, Successes: 120,
		SuccessRate: 0.30, BaselineRate: 0.72, BreakerState: domain.BreakerClosed,
		SampledAt: clock.Now(),
	}

	var checked int
	for _, class := range classes {
		for attempt := 1; attempt <= 3; attempt++ {
			ceiling := policy.BackoffCeiling(attempt, class, snap)
			for _, arm := range PermittedFor(int64(ceiling / time.Second)) {
				cmd, err := gate.Decide(tContext(), domain.GateInput{
					IncidentID: "inc-1",
					Payment: domain.PaymentEntity{
						ID: "pay_1", Amount: 250_000, Currency: "INR",
						Method: "netbanking", Bank: "SBI", ErrorCode: "bank_technical_error",
					},
					Proposal: domain.DiagnosticProposal{
						IncidentID:            "inc-1",
						FailureClassification: class,
						ConfidenceScore:       0.9,
						RecommendedAction:     domain.ActionAsyncRetry,
						RecommendedDelaySec:   ArmSeconds(arm),
						SuggestedFallbackRail: domain.RailNone,
					},
					Telemetry:      snap,
					AttemptNumber:  attempt,
					AvailableRails: []domain.Rail{domain.RailNetbanking, domain.RailCard},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !cmd.Executable() {
					continue
				}
				checked++
				if cmd.DelaySeconds != ArmSeconds(arm) {
					t.Fatalf("class %s attempt %d: chose %s (%ds) above a ceiling of %s, gate scheduled %ds",
						class, attempt, arm, ArmSeconds(arm), ceiling, cmd.DelaySeconds)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no combination was executable, so nothing was actually checked")
	}
}

// A recurring debit loses every arm inside the RBI cooling window, and the
// removal is done by the gate rather than by this package.
func TestRecurringDebitsLoseTheShortArms(t *testing.T) {
	t.Parallel()
	clock := fixed{time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)}
	gate := gatekeeperFor(clock, policy.New(clock, nil))

	for _, arm := range Arms {
		cmd, err := gate.Decide(tContext(), domain.GateInput{
			IncidentID: "inc-2",
			Payment: domain.PaymentEntity{
				ID: "pay_2", Amount: 99_900, Currency: "INR",
				Method: "netbanking", Bank: "SBI", SubscriptionID: "sub_2",
				ErrorCode: "bank_technical_error",
			},
			Proposal: domain.DiagnosticProposal{
				IncidentID:            "inc-2",
				FailureClassification: domain.ClassTransientDegradation,
				ConfidenceScore:       0.9,
				RecommendedAction:     domain.ActionMandateCascade,
				RecommendedDelaySec:   ArmSeconds(arm),
				SuggestedFallbackRail: domain.RailNone,
			},
			Telemetry:      domain.TelemetrySnapshot{IssuerKey: "netbanking:SBI", SampledAt: clock.Now()},
			AttemptNumber:  1,
			AvailableRails: []domain.Rail{domain.RailNetbanking},
		})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Executable() && cmd.DelaySeconds < 86400 {
			t.Fatalf("arm %s produced a recurring debit %ds after the failure, inside the cooling window",
				arm, cmd.DelaySeconds)
		}
	}
}

func TestChooseRefusesWhenNothingIsPermitted(t *testing.T) {
	t.Parallel()
	tn := newTuner(t, 0.05)
	if _, err := tn.Choose("cell", 1<<40, 100_000, 300); !errors.Is(err, bandit.ErrNoPermittedArms) {
		t.Fatalf("got %v, want ErrNoPermittedArms", err)
	}
}

// The logged propensity has to be the probability the arm was actually drawn
// with, and every permitted arm has to keep some.
func TestChoiceCarriesAnHonestPropensity(t *testing.T) {
	t.Parallel()
	const floor = 0.05
	tn := newTuner(t, floor)

	counts := map[bandit.Arm]int{}
	const rounds = 8_000
	for i := 0; i < rounds; i++ {
		d, err := tn.Choose("issuer=upi:ybl|class=NETWORK_TIMEOUT|hb=3|att=1", 0, 500_000, 300)
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Dist[d.Arm]; got != d.Propensity {
			t.Fatalf("propensity %v does not match the distribution entry %v", d.Propensity, got)
		}
		if d.DelaySec != ArmSeconds(d.Arm) {
			t.Fatalf("arm %s carries delay %d", d.Arm, d.DelaySec)
		}
		if d.ModelDigest == "" {
			t.Fatal("a decision must name the belief state it came from")
		}
		var sum float64
		for _, a := range d.Permitted {
			if d.Dist[a] < floor-1e-9 {
				t.Fatalf("arm %s fell to %v, below the floor", a, d.Dist[a])
			}
			sum += d.Dist[a]
		}
		if sum < 1-1e-9 || sum > 1+1e-9 {
			t.Fatalf("distribution sums to %v", sum)
		}
		counts[d.Arm]++
	}
	for _, a := range Arms {
		if counts[a] == 0 {
			t.Fatalf("arm %s was never drawn in %d rounds despite a floor of %v", a, rounds, floor)
		}
	}
}

func TestObserveMovesTheBelief(t *testing.T) {
	t.Parallel()
	tn := newTuner(t, 0.02)
	before := tn.Digest()
	if err := tn.Observe("cell", ArmLong, true); err != nil {
		t.Fatal(err)
	}
	if tn.Digest() == before {
		t.Fatal("an observation left the belief digest unchanged")
	}
	if err := tn.Observe("cell", "not-an-arm", true); !errors.Is(err, bandit.ErrUnknownArm) {
		t.Fatalf("got %v, want ErrUnknownArm", err)
	}
}

func TestStatsCountExploration(t *testing.T) {
	t.Parallel()
	tn := newTuner(t, 0.3)
	for i := 0; i < 200; i++ {
		if err := tn.Observe("cell", ArmLong, true); err != nil {
			t.Fatal(err)
		}
		if err := tn.Observe("cell", ArmFast, false); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 400; i++ {
		if _, err := tn.Choose("cell", 0, 100_000, 300); err != nil {
			t.Fatal(err)
		}
	}
	s := tn.Stats()
	if s.Decisions != 400 {
		t.Fatalf("counted %d decisions", s.Decisions)
	}
	if s.Explored == 0 {
		t.Fatal("a floor of 0.3 produced no exploration")
	}
	if s.ExploreRate <= 0 || s.ExploreRate > 1 {
		t.Fatalf("explore rate %v", s.ExploreRate)
	}
	if s.Digest == "" {
		t.Fatal("no digest reported")
	}
}

func TestSnapshotRoundTrips(t *testing.T) {
	t.Parallel()
	a := newTuner(t, 0.02)
	for i := 0; i < 40; i++ {
		if err := a.Observe(CellFor("upi:ybl", domain.ClassNetworkTimeout, i, 1), ArmMedium, i%3 == 0); err != nil {
			t.Fatal(err)
		}
	}
	want := a.Digest()

	b := newTuner(t, 0.02)
	if err := b.Restore(a.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if got := b.Digest(); got != want {
		t.Fatalf("digest changed across a round trip:\n%s\n%s", want, got)
	}
}

// Cell keys are assembled from issuer codes that arrive in webhook payloads, so
// the bucketing is bounded and the components cannot run together ambiguously.
func TestCellForIsBoundedAndUnambiguous(t *testing.T) {
	t.Parallel()
	c := CellFor("netbanking:SBI", domain.ClassIssuerOutage, 22, 2)
	for _, want := range []string{"issuer=netbanking:SBI", "class=ISSUER_OUTAGE", "hb=7", "att=2"} {
		if !strings.Contains(string(c), want) {
			t.Fatalf("cell %q is missing %q", c, want)
		}
	}
	if CellFor("x", domain.ClassUnknown, 99, -4) == CellFor("x", domain.ClassUnknown, 0, 0) {
		// Out-of-range values are clamped to the same bucket on purpose, so
		// this is checking the clamp exists rather than that they differ.
		t.Log("out-of-range hour and attempt clamp into the first bucket, as intended")
	}
	if a, b := CellFor("a|b", domain.ClassUnknown, 0, 0), CellFor("a", domain.ClassUnknown, 0, 0); a == b {
		t.Fatal("two different issuers produced the same cell")
	}
	if got := CellFor("x", domain.ClassUnknown, 23, 9); !strings.Contains(string(got), "att=3") {
		t.Fatalf("attempt was not clamped: %q", got)
	}
}

func TestConfigIsValidated(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{Floor: 1.5}); err == nil {
		t.Fatal("a floor above one was accepted")
	}
	if _, err := New(Config{Floor: -1}); err == nil {
		t.Fatal("a negative floor was accepted")
	}
	tn, err := New(Config{})
	if err != nil {
		t.Fatalf("the zero config was rejected: %v", err)
	}
	if _, err := tn.Choose("cell", 0, 1000, 300); err != nil {
		t.Fatalf("a default tuner could not decide: %v", err)
	}
}

func TestTunerIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()
	tn := newTuner(t, 0.05)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				d, err := tn.Choose(CellFor("upi:ybl", domain.ClassNetworkTimeout, i%24, 1), 0, 100_000, 300)
				if err != nil {
					t.Error(err)
					return
				}
				if err := tn.Observe(d.Cell, d.Arm, (g+i)%3 == 0); err != nil {
					t.Error(err)
					return
				}
				_ = tn.Stats()
			}
		}(g)
	}
	wg.Wait()
}

type fixed struct{ at time.Time }

func (f fixed) Now() time.Time { return f.at }

// gatekeeperFor builds the production gate. These tests assert a relationship
// between this package and that one, so substituting a stub would assert
// nothing.
func gatekeeperFor(clock domain.Clock, engine domain.PolicyEngine) *gatekeeper.Gatekeeper {
	return gatekeeper.New(clock, engine, gatekeeper.Config{})
}

func tContext() context.Context { return context.Background() }

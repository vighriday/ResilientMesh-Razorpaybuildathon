package policy

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var testNow = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func newTestEngine(seed int64) *Engine {
	return New(fixedClock{t: testNow}, rand.New(rand.NewSource(seed)))
}

// mkSnap derives SuccessRate from the counters so a fixture can never claim a
// rate its own counts contradict.
func mkSnap(key string, attempts, successes int, baseline float64, breaker domain.BreakerState) domain.TelemetrySnapshot {
	rate := 0.0
	if attempts > 0 {
		rate = float64(successes) / float64(attempts)
	}
	return domain.TelemetrySnapshot{
		IssuerKey:     key,
		WindowSeconds: 300,
		Attempts:      attempts,
		Successes:     successes,
		Failures:      attempts - successes,
		SuccessRate:   rate,
		BaselineRate:  baseline,
		BreakerState:  breaker,
	}
}

func snapsOf(ss ...domain.TelemetrySnapshot) map[string]domain.TelemetrySnapshot {
	m := make(map[string]domain.TelemetrySnapshot, len(ss))
	for _, s := range ss {
		m[s.IssuerKey] = s
	}
	return m
}

const closed = domain.BreakerClosed
const open = domain.BreakerOpen

// ---------------------------------------------------------------------------
// ChooseRail: Laplace smoothing
// ---------------------------------------------------------------------------

// TestChooseRail_LaplaceSmoothingBeatsNaiveRate is the central claim of the
// package: a rail with a perfect but tiny sample must lose to a rail with a
// worse but well-evidenced one.
func TestChooseRail_LaplaceSmoothingBeatsNaiveRate(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(1)

	small := mkSnap("upi:okhdfcbank", 1, 1, 0.85, closed) // naive 100%
	large := mkSnap("netbanking:HDFC", 500, 400, 0.85, closed)

	if small.Degraded() || large.Degraded() {
		t.Fatalf("fixture invalid: neither snapshot may be degraded (small=%v large=%v)",
			small.Degraded(), large.Degraded())
	}

	// The naive comparison this smoothing exists to defeat.
	if !(small.SuccessRate > large.SuccessRate) {
		t.Fatalf("fixture invalid: naive rate must favour the one-sample rail, got %v vs %v",
			small.SuccessRate, large.SuccessRate)
	}
	// The smoothed comparison, computed the same integer way the engine does.
	smallScore := smoothedPct(1, 1)     // (1+1)/(1+2) = 66.7%
	largeScore := smoothedPct(400, 500) // (400+1)/(500+2) = 79.9%
	if smallScore != 67 || largeScore != 80 {
		t.Fatalf("smoothed estimates changed: small=%d%% large=%d%%", smallScore, largeScore)
	}

	rail, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailUPIIntent, domain.RailNetbanking},
		snapsOf(small, large))

	if rail != domain.RailNetbanking {
		t.Fatalf("Laplace smoothing not applied: got rail %q, want %q (reason %q)",
			rail, domain.RailNetbanking, reason)
	}
	if want := "netbanking healthy at 80% over 500 samples"; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
}

// TestChooseRail_SmoothingHoldsAsEvidenceAccumulates checks the estimator does
// eventually let a genuinely better rail win, so the smoothing is a prior and
// not a permanent handicap.
func TestChooseRail_SmoothingHoldsAsEvidenceAccumulates(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(2)
	baseline := mkSnap("netbanking:HDFC", 500, 400, 0.85, closed)

	// 90% over 200 samples smooths to (181/202) = 89.6%, which clears 79.9%.
	strong := mkSnap("upi:okhdfcbank", 200, 180, 0.85, closed)
	rail, _ := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailUPIIntent, domain.RailNetbanking},
		snapsOf(strong, baseline))
	if rail != domain.RailUPIIntent {
		t.Fatalf("well-evidenced 90%% rail should win, got %q", rail)
	}
}

// ---------------------------------------------------------------------------
// ChooseRail: exclusions
// ---------------------------------------------------------------------------

func TestChooseRail_ExcludesOpenBreakerAndDegraded(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(3)

	card := mkSnap("card:HDFC", 500, 400, 0.85, closed)
	degraded := mkSnap("netbanking:HDFC", 50, 4, 0.85, closed) // 8% vs 85% baseline
	breakerOpen := mkSnap("wallet:paytm", 100, 90, 0.85, open) // healthy rate, tripped

	if !degraded.Degraded() {
		t.Fatal("fixture invalid: netbanking snapshot must be degraded")
	}
	if breakerOpen.Degraded() {
		t.Fatal("fixture invalid: wallet must be excluded by the breaker, not by rate")
	}

	rail, reason := eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailCard, domain.RailNetbanking, domain.RailWallet, domain.RailUPIIntent},
		snapsOf(card, degraded, breakerOpen))

	if rail != domain.RailCard {
		t.Fatalf("got rail %q, want card (reason %q)", rail, reason)
	}
	for _, want := range []string{
		"card healthy at 80% over 500 samples",
		"wallet:paytm breaker open",
		"netbanking:HDFC degraded to 8%",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q missing %q", reason, want)
		}
	}
}

func TestChooseRail_NoEligibleRailReturnsNone(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(4)

	rail, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailNetbanking, domain.RailWallet},
		snapsOf(
			mkSnap("netbanking:HDFC", 50, 4, 0.85, closed),
			mkSnap("wallet:paytm", 100, 90, 0.85, open),
		))

	if rail != domain.RailNone {
		t.Fatalf("got rail %q, want none", rail)
	}
	if !strings.HasPrefix(reason, reasonNoRail) {
		t.Fatalf("reason %q must start with the fixed no-rail phrase", reason)
	}
	if !strings.Contains(reason, "netbanking:HDFC degraded to 8%") {
		t.Errorf("reason %q should still explain the exclusions", reason)
	}
}

func TestChooseRail_ExcludesCurrentRail(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(5)
	ss := snapsOf(
		mkSnap("card:HDFC", 500, 500, 0.85, closed), // best by far
		mkSnap("wallet:paytm", 20, 10, 0.85, closed),
	)

	rail, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailCard, domain.RailWallet}, ss)
	if rail != domain.RailWallet {
		t.Fatalf("failing rail must be excluded even when it scores best: got %q (%s)", rail, reason)
	}

	rail, _ = eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailCard, domain.RailNone, domain.Rail("teleport")}, ss)
	if rail != domain.RailNone {
		t.Fatalf("only the current, none, and invalid rails offered: got %q", rail)
	}
}

// TestChooseRail_PartiallyDegradedRailSurvives records the deliberate choice
// that one sick issuer does not condemn its whole rail.
func TestChooseRail_PartiallyDegradedRailSurvives(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(6)

	rail, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailNetbanking},
		snapsOf(
			mkSnap("netbanking:HDFC", 50, 4, 0.85, closed),    // degraded, skipped
			mkSnap("netbanking:ICICI", 100, 95, 0.85, closed), // healthy, counted
		))

	if rail != domain.RailNetbanking {
		t.Fatalf("got %q, want netbanking to survive one degraded issuer", rail)
	}
	// Only the healthy issuer's 100 samples feed the score.
	if !strings.Contains(reason, "over 100 samples") {
		t.Errorf("reason %q should score on the healthy issuer only", reason)
	}
	if !strings.Contains(reason, "netbanking:HDFC degraded to 8%") {
		t.Errorf("reason %q should still name the degraded issuer", reason)
	}
}

func TestChooseRail_AllIssuersOfRailBlocked(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(7)

	rail, _ := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailNetbanking},
		snapsOf(
			mkSnap("netbanking:HDFC", 50, 4, 0.85, closed),
			mkSnap("netbanking:ICICI", 60, 3, 0.85, open),
		))
	if rail != domain.RailNone {
		t.Fatalf("every issuer on the rail is blocked, got %q", rail)
	}
}

// ---------------------------------------------------------------------------
// ChooseRail: determinism
// ---------------------------------------------------------------------------

func TestChooseRail_DeterministicTieBreakByRailName(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(8)

	// Identical counters on three rails: only the name can break the tie.
	ss := snapsOf(
		mkSnap("card:HDFC", 20, 10, 0.85, closed),
		mkSnap("netbanking:HDFC", 20, 10, 0.85, closed),
		mkSnap("wallet:paytm", 20, 10, 0.85, closed),
	)
	orders := [][]domain.Rail{
		{domain.RailCard, domain.RailNetbanking, domain.RailWallet},
		{domain.RailWallet, domain.RailNetbanking, domain.RailCard},
		{domain.RailNetbanking, domain.RailWallet, domain.RailCard},
	}

	wantRail := domain.RailCard
	wantReason := "card healthy at 50% over 20 samples"

	// Repeated so Go's randomised map iteration gets many chances to leak in.
	for i := 0; i < 200; i++ {
		for j, order := range orders {
			rail, reason := eng.ChooseRail(context.Background(), domain.RailUPIIntent, order, ss)
			if rail != wantRail || reason != wantReason {
				t.Fatalf("iteration %d order %d: got (%q, %q), want (%q, %q)",
					i, j, rail, reason, wantRail, wantReason)
			}
		}
	}
}

func TestChooseRail_ExclusionClauseOrderIsStable(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(9)
	ss := snapsOf(
		mkSnap("card:HDFC", 500, 400, 0.85, closed),
		mkSnap("netbanking:HDFC", 50, 4, 0.85, closed),
		mkSnap("netbanking:ICICI", 40, 2, 0.85, closed),
		mkSnap("wallet:paytm", 100, 90, 0.85, open),
	)
	avail := []domain.Rail{domain.RailCard, domain.RailNetbanking, domain.RailWallet}

	_, first := eng.ChooseRail(context.Background(), domain.RailUPIIntent, avail, ss)
	for i := 0; i < 200; i++ {
		if _, got := eng.ChooseRail(context.Background(), domain.RailUPIIntent, avail, ss); got != first {
			t.Fatalf("reason drifted on iteration %d: %q != %q", i, got, first)
		}
	}
	// Breaker trips are the more severe signal, so they are reported first.
	openAt := strings.Index(first, "breaker open")
	degAt := strings.Index(first, "degraded to")
	if openAt < 0 || degAt < 0 || openAt > degAt {
		t.Fatalf("expected breaker clause before degraded clause in %q", first)
	}
}

// ---------------------------------------------------------------------------
// ChooseRail: priors, staleness, cancellation
// ---------------------------------------------------------------------------

func TestChooseRail_UnknownRailScoresOnPrior(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(10)

	rail, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailWallet}, nil)
	if rail != domain.RailWallet {
		t.Fatalf("a rail with no telemetry must still be selectable, got %q", rail)
	}
	if want := "wallet selected on prior, no recent samples"; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}

	// The 0.5 prior loses to demonstrated health...
	rail, _ = eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailWallet, domain.RailCard},
		snapsOf(mkSnap("card:HDFC", 500, 400, 0.85, closed)))
	if rail != domain.RailCard {
		t.Fatalf("prior should lose to a proven rail, got %q", rail)
	}

	// ...and beats a weak rail that is not yet degraded enough to exclude.
	// 40% observed against a 0.70 peer baseline: above the absolute floor and
	// above half the baseline, so admissible, but its Laplace-smoothed score
	// (5/12) still loses to the 0.5 prior of an unobserved rail.
	weak := mkSnap("netbanking:HDFC", 10, 4, 0.70, closed)
	if weak.Degraded() {
		t.Fatal("fixture invalid: weak rail must not be degraded")
	}
	rail, _ = eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailWallet, domain.RailNetbanking}, snapsOf(weak))
	if rail != domain.RailWallet {
		t.Fatalf("prior should beat a 40%% rail, got %q", rail)
	}
}

func TestChooseRail_StaleCountsIgnoredButVerdictHonoured(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(11)

	stalePerfect := mkSnap("wallet:paytm", 500, 500, 0.85, closed)
	stalePerfect.SampledAt = testNow.Add(-SnapshotStaleAfter - time.Minute)
	fresh := mkSnap("card:HDFC", 500, 400, 0.85, closed)
	fresh.SampledAt = testNow.Add(-time.Minute)

	rail, reason := eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailWallet, domain.RailCard}, snapsOf(stalePerfect, fresh))
	if rail != domain.RailCard {
		t.Fatalf("stale perfect counts must not outrank fresh evidence, got %q (%s)", rail, reason)
	}

	// Stale bad news is still the last thing observed, so it still excludes.
	staleOpen := mkSnap("wallet:paytm", 500, 500, 0.85, open)
	staleOpen.SampledAt = testNow.Add(-24 * time.Hour)
	rail, _ = eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailWallet}, snapsOf(staleOpen))
	if rail != domain.RailNone {
		t.Fatalf("stale open breaker must still exclude the rail, got %q", rail)
	}
}

func TestChooseRail_CancelledContextFailsClosed(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(12)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rail, reason := eng.ChooseRail(ctx, domain.RailCard,
		[]domain.Rail{domain.RailWallet},
		snapsOf(mkSnap("wallet:paytm", 500, 500, 0.85, closed)))
	if rail != domain.RailNone || reason != reasonCancelled {
		t.Fatalf("got (%q, %q), want (none, %q)", rail, reason, reasonCancelled)
	}
}

// ---------------------------------------------------------------------------
// Reason strings are bounded, sanitised, fixed vocabulary
// ---------------------------------------------------------------------------

func TestReason_SanitisesAttackerControlledIssuerKey(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(13)

	// Issuer keys are built from webhook-supplied bank codes and VPA handles.
	hostile := "netbanking:HDFC\n<script>x</script> "
	_, reason := eng.ChooseRail(context.Background(), domain.RailCard,
		[]domain.Rail{domain.RailNetbanking},
		snapsOf(mkSnap(hostile, 50, 4, 0.85, closed)))

	for _, bad := range []string{"<", ">", "/", "\n", "script>"} {
		if strings.Contains(reason, bad) {
			t.Fatalf("reason %q leaked %q from the issuer key", reason, bad)
		}
	}
	if !strings.Contains(reason, "netbanking:HDFCscriptxscript degraded to 8%") {
		t.Fatalf("reason %q did not render the sanitised key", reason)
	}
}

func TestReason_LengthBounded(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(14)

	ss := snapsOf(mkSnap("card:HDFC", 500, 400, 0.85, closed))
	for _, suffix := range []string{"A", "B", "C", "D", "E"} {
		key := "netbanking:" + strings.Repeat(suffix, 100)
		ss[key] = mkSnap(key, 50, 4, 0.85, closed)
	}

	_, reason := eng.ChooseRail(context.Background(), domain.RailUPIIntent,
		[]domain.Rail{domain.RailCard, domain.RailNetbanking}, ss)

	if len(reason) > maxReasonLen {
		t.Fatalf("reason of %d bytes exceeds the %d byte bound: %q", len(reason), maxReasonLen, reason)
	}
	if !utf8.ValidString(reason) {
		t.Fatalf("reason is not valid UTF-8: %q", reason)
	}
	if strings.Count(reason, "degraded to") > maxExclusionClauses {
		t.Fatalf("more than %d exclusion clauses survived: %q", maxExclusionClauses, reason)
	}
}

func TestSanitizeIssuerKey(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"upi:okhdfcbank", "upi:okhdfcbank"},
		{"netbanking:HDFC", "netbanking:HDFC"},
		{"card:ICICI-2", "card:ICICI-2"},
		{"wallet:pay.tm_1", "wallet:pay.tm_1"},
		{"a b\tc\r\n", "abc"},
		{"<>%$#@!", "unknown"},
		{"", "unknown"},
		{strings.Repeat("z", 200), strings.Repeat("z", maxRenderedKeyLen)},
	}
	for _, c := range cases {
		if got := sanitizeIssuerKey(c.in); got != c.want {
			t.Errorf("sanitizeIssuerKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RailIssuerKeys
// ---------------------------------------------------------------------------

func TestRailIssuerKeys(t *testing.T) {
	t.Parallel()
	ss := snapsOf(
		mkSnap("upi:okhdfcbank", 1, 1, 0.85, closed),
		mkSnap("upi:okaxis", 1, 1, 0.85, closed),
		mkSnap("card:HDFC", 1, 1, 0.85, closed),
		mkSnap("emi:HDFC", 1, 1, 0.85, closed),
		mkSnap("netbanking:HDFC", 1, 1, 0.85, closed),
		mkSnap("wallet:paytm", 1, 1, 0.85, closed),
	)
	oversized := "netbanking:" + strings.Repeat("x", maxIssuerKeyLen)
	ss[oversized] = mkSnap(oversized, 1, 1, 0.85, closed)

	cases := []struct {
		rail domain.Rail
		want []string
	}{
		// Both UPI flows read the same handle-scoped window.
		{domain.RailUPIIntent, []string{"upi:okaxis", "upi:okhdfcbank"}},
		{domain.RailUPICollect, []string{"upi:okaxis", "upi:okhdfcbank"}},
		{domain.RailCard, []string{"card:HDFC", "emi:HDFC"}},
		{domain.RailNetbanking, []string{"netbanking:HDFC"}}, // oversized key dropped
		{domain.RailWallet, []string{"wallet:paytm"}},
		{domain.RailNone, nil},
		{domain.Rail("nonsense"), nil},
	}
	for _, c := range cases {
		got := RailIssuerKeys(c.rail, ss)
		if len(got) != len(c.want) {
			t.Errorf("RailIssuerKeys(%q) = %v, want %v", c.rail, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("RailIssuerKeys(%q) = %v, want %v", c.rail, got, c.want)
				break
			}
		}
	}

	if got := RailIssuerKeys(domain.RailCard, nil); got != nil {
		t.Errorf("RailIssuerKeys on a nil map = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

var allClasses = []domain.FailureClass{
	domain.ClassNetworkTimeout,
	domain.ClassTransientDegradation,
	domain.ClassPSPDegradation,
	domain.ClassIssuerOutage,
	domain.ClassCustomerAction,
	domain.ClassInsufficientFunds,
	domain.ClassPermanentInstrument,
	domain.ClassUnknown,
}

func TestBackoffCeiling_BaseDelayPerClass(t *testing.T) {
	t.Parallel()
	healthy := mkSnap("card:HDFC", 100, 95, 0.85, closed)
	cases := []struct {
		class domain.FailureClass
		want  time.Duration
	}{
		{domain.ClassNetworkTimeout, 15 * time.Second},
		{domain.ClassTransientDegradation, 60 * time.Second},
		{domain.ClassPSPDegradation, 300 * time.Second},
		{domain.ClassIssuerOutage, 900 * time.Second},
		{domain.ClassCustomerAction, 3600 * time.Second},
		{domain.ClassInsufficientFunds, 86400 * time.Second},
		// Not Recoverable(): the longest the system can express, not a fast retry.
		{domain.ClassPermanentInstrument, MaxBackoff},
		{domain.ClassUnknown, MaxBackoff},
	}
	for _, c := range cases {
		if got := BackoffCeiling(1, c.class, healthy); got != c.want {
			t.Errorf("BackoffCeiling(1, %q) = %v, want %v", c.class, got, c.want)
		}
	}
}

func TestBackoffCeiling_MonotoneInAttemptAndClamped(t *testing.T) {
	t.Parallel()
	snaps := []domain.TelemetrySnapshot{
		mkSnap("card:HDFC", 100, 95, 0.85, closed),
		mkSnap("card:HDFC", 100, 2, 0.85, open),
		{},
	}
	for _, class := range allClasses {
		for _, snap := range snaps {
			prev := time.Duration(-1)
			for attempt := -3; attempt <= 40; attempt++ {
				got := BackoffCeiling(attempt, class, snap)
				if got < MinBackoff || got > MaxBackoff {
					t.Fatalf("BackoffCeiling(%d, %q) = %v, outside [%v, %v]",
						attempt, class, got, MinBackoff, MaxBackoff)
				}
				if got < prev {
					t.Fatalf("BackoffCeiling not monotone for %q: attempt %d gave %v after %v",
						class, attempt, got, prev)
				}
				prev = got
			}
		}
	}
}

func TestBackoffCeiling_ExponentialDoubling(t *testing.T) {
	t.Parallel()
	healthy := mkSnap("card:HDFC", 100, 95, 0.85, closed)
	// 2^(attempt-1) on a 60 s base until the one-week ceiling bites.
	for attempt, want := range map[int]time.Duration{
		1: 60 * time.Second,
		2: 120 * time.Second,
		3: 240 * time.Second,
		4: 480 * time.Second,
		5: 960 * time.Second,
	} {
		if got := BackoffCeiling(attempt, domain.ClassTransientDegradation, healthy); got != want {
			t.Errorf("BackoffCeiling(%d, transient) = %v, want %v", attempt, got, want)
		}
	}
	if got := BackoffCeiling(30, domain.ClassTransientDegradation, healthy); got != MaxBackoff {
		t.Errorf("BackoffCeiling(30, transient) = %v, want the %v clamp", got, MaxBackoff)
	}
}

func TestBackoffCeiling_DeepOutageScaling(t *testing.T) {
	t.Parallel()
	shallow := mkSnap("card:HDFC", 100, 10, 0.85, closed) // 10%: degraded, not gone
	deep := mkSnap("card:HDFC", 100, 2, 0.85, closed)     // 2%: gone
	tripped := mkSnap("card:HDFC", 100, 90, 0.85, open)   // breaker already concluded
	fine := mkSnap("card:HDFC", 100, 90, 0.85, closed)

	if !shallow.Degraded() || !deep.Degraded() || fine.Degraded() {
		t.Fatal("fixtures invalid for the degraded/healthy split")
	}

	cases := []struct {
		name string
		snap domain.TelemetrySnapshot
		want time.Duration
	}{
		{"healthy", fine, 900 * time.Second},
		{"shallow", shallow, 1800 * time.Second},
		{"deep", deep, 3600 * time.Second},
		{"breaker open", tripped, 3600 * time.Second},
	}
	for _, c := range cases {
		if got := BackoffCeiling(1, domain.ClassIssuerOutage, c.snap); got != c.want {
			t.Errorf("outage %s: BackoffCeiling = %v, want %v", c.name, got, c.want)
		}
	}

	// The depth multiplier is an outage-specific rule and must not leak into
	// the other classes, whose bases already encode their own urgency.
	if got := BackoffCeiling(1, domain.ClassTransientDegradation, tripped); got != 60*time.Second {
		t.Errorf("depth scaling leaked into transient class: %v", got)
	}
}

// TestBackoffFor_TenThousandSeededDrawsStayInClamp is the property that matters
// operationally: no draw, ever, escapes [MinBackoff, ceiling].
func TestBackoffFor_TenThousandSeededDrawsStayInClamp(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(20260904)
	ctx := context.Background()
	snaps := []domain.TelemetrySnapshot{
		mkSnap("card:HDFC", 100, 95, 0.85, closed),
		mkSnap("card:HDFC", 100, 2, 0.85, open),
	}

	const draws = 10000
	seen := 0
	for seen < draws {
		for _, class := range allClasses {
			for attempt := 1; attempt <= 10 && seen < draws; attempt++ {
				snap := snaps[seen%len(snaps)]
				ceiling := BackoffCeiling(attempt, class, snap)
				got := eng.BackoffFor(ctx, attempt, class, snap)
				if got < MinBackoff {
					t.Fatalf("draw %d (%q attempt %d) = %v, below floor %v", seen, class, attempt, got, MinBackoff)
				}
				if got > ceiling {
					t.Fatalf("draw %d (%q attempt %d) = %v, above ceiling %v", seen, class, attempt, got, ceiling)
				}
				if got > MaxBackoff {
					t.Fatalf("draw %d (%q attempt %d) = %v, above clamp %v", seen, class, attempt, got, MaxBackoff)
				}
				seen++
			}
		}
	}
	if seen != draws {
		t.Fatalf("took %d draws, want %d", seen, draws)
	}
}

// TestBackoffFor_DistributionRisesWithAttempt is the jittered analogue of
// monotonicity: individual full-jitter draws are not ordered, the distribution
// they come from is.
func TestBackoffFor_DistributionRisesWithAttempt(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(77)
	ctx := context.Background()
	snap := mkSnap("card:HDFC", 100, 95, 0.85, closed)

	mean := func(attempt int) time.Duration {
		var total time.Duration
		const n = 2000
		for i := 0; i < n; i++ {
			total += eng.BackoffFor(ctx, attempt, domain.ClassTransientDegradation, snap)
		}
		return total / n
	}
	m1, m3, m5 := mean(1), mean(3), mean(5)
	if !(m1 < m3 && m3 < m5) {
		t.Fatalf("mean backoff not rising with attempt: %v, %v, %v", m1, m3, m5)
	}
}

// TestBackoffFor_SpreadsAcrossTheWindow guards the reason the floor is folded
// into the sampling range: clamping after the draw would pile a third of a
// short-base class onto exactly MinBackoff.
func TestBackoffFor_SpreadsAcrossTheWindow(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(99)
	ctx := context.Background()
	snap := mkSnap("card:HDFC", 100, 95, 0.85, closed)

	atFloor := 0
	const n = 5000
	for i := 0; i < n; i++ {
		if eng.BackoffFor(ctx, 1, domain.ClassNetworkTimeout, snap) == MinBackoff {
			atFloor++
		}
	}
	if atFloor > n/100 {
		t.Fatalf("%d/%d draws landed exactly on the floor; jitter is being clamped, not sampled", atFloor, n)
	}
}

func TestBackoffFor_DeterministicForASeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	snap := mkSnap("card:HDFC", 100, 95, 0.85, closed)

	a, b := newTestEngine(4242), newTestEngine(4242)
	for i := 1; i <= 200; i++ {
		class := allClasses[i%len(allClasses)]
		da := a.BackoffFor(ctx, i%8+1, class, snap)
		db := b.BackoffFor(ctx, i%8+1, class, snap)
		if da != db {
			t.Fatalf("draw %d diverged for the same seed: %v vs %v", i, da, db)
		}
	}

	c := newTestEngine(4243)
	differs := false
	for i := 1; i <= 200 && !differs; i++ {
		if c.BackoffFor(ctx, 5, domain.ClassIssuerOutage, snap) !=
			a.BackoffFor(ctx, 5, domain.ClassIssuerOutage, snap) {
			differs = true
		}
	}
	if !differs {
		t.Fatal("different seeds produced an identical sequence; the seed is not reaching the generator")
	}
}

func TestBackoffFor_CancelledContextReturnsCeiling(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(15)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snap := mkSnap("card:HDFC", 100, 95, 0.85, closed)
	want := BackoffCeiling(3, domain.ClassPSPDegradation, snap)
	if got := eng.BackoffFor(ctx, 3, domain.ClassPSPDegradation, snap); got != want {
		t.Fatalf("cancelled BackoffFor = %v, want the full ceiling %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// ExpectedValue
// ---------------------------------------------------------------------------

func TestExpectedValue_HandComputed(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(16)
	ctx := context.Background()
	def := domain.DefaultCostModel() // fee 250, friction 60
	free := domain.CostModel{}

	cases := []struct {
		name     string
		amount   int64
		prob     float64
		attempts int
		costs    domain.CostModel
		want     int64
	}{
		{
			// 100000 * 5000/10000 = 50000; minus 2*250 minus 60.
			name: "half odds on Rs 1000", amount: 100_000, prob: 0.5,
			attempts: 2, costs: def, want: 49_440,
		},
		{
			// 99999 * 3330 = 332996670; /10000 = 33299.667 -> 33299 (rounds down).
			name: "gross truncates toward zero", amount: 99_999, prob: 0.333,
			attempts: 1, costs: def, want: 32_989,
		},
		{
			// 999 * 9990 = 9980010; /10000 = 998.001 -> 998.
			name: "fractional paisa discarded", amount: 999, prob: 0.999,
			attempts: 0, costs: free, want: 998,
		},
		{
			// 100 * 1/10000 = 0.01 -> 0. A retry worth a hundredth of a paisa
			// is worth nothing, and must not round up into one.
			name: "sub-paisa expectation floors to zero", amount: 100, prob: 0.0001,
			attempts: 0, costs: free, want: 0,
		},
		{
			name: "certainty on one paisa", amount: 1, prob: 1.0,
			attempts: 0, costs: free, want: 1,
		},
		{
			// probability rounds half up: 0.123456 -> 1235 bps.
			name: "probability to basis points", amount: 1_000_000, prob: 0.123456,
			attempts: 0, costs: free, want: 123_500,
		},
		{
			name: "hopeless retry is negative", amount: 12_345, prob: 0.0,
			attempts: 3, costs: def, want: -810,
		},
		{
			name: "NaN probability contributes nothing", amount: 1_000, prob: nan(),
			attempts: 1, costs: def, want: -310,
		},
		{
			name: "probability above one clamps to certainty", amount: 500, prob: 5.0,
			attempts: 0, costs: free, want: 500,
		},
		{
			name: "probability below zero clamps to impossible", amount: 500, prob: -3.0,
			attempts: 0, costs: free, want: 0,
		},
		{
			name: "negative amount clamps to zero", amount: -1_000, prob: 1.0,
			attempts: 0, costs: free, want: 0,
		},
		{
			name: "negative attempts charge nothing", amount: 10_000, prob: 1.0,
			attempts: -5, costs: domain.CostModel{GatewayFeePerAttemptPaisa: 250}, want: 10_000,
		},
		{
			name: "negative costs cannot manufacture value", amount: 10_000, prob: 1.0,
			attempts: 2, costs: domain.CostModel{GatewayFeePerAttemptPaisa: -1000, SessionFrictionPaisa: -500},
			want: 10_000,
		},
		{
			// Above the internal bound; must clamp rather than overflow.
			name: "absurd amount clamps", amount: 900_000_000_000_000, prob: 1.0,
			attempts: 0, costs: free, want: maxAmountPaisa,
		},
	}

	for _, c := range cases {
		if got := eng.ExpectedValue(ctx, c.amount, c.prob, c.attempts, c.costs); got != c.want {
			t.Errorf("%s: ExpectedValue = %d, want %d", c.name, got, c.want)
		}
	}
}

func nan() float64 {
	zero := 0.0
	return zero / zero
}

// TestExpectedValue_SumIsOrderIndependent is the concrete reason floats are
// banned here: a float total over the same incidents depends on summation order,
// and a benchmark headline figure that moves with goroutine scheduling is not
// evidence of anything.
func TestExpectedValue_SumIsOrderIndependent(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(17)
	ctx := context.Background()
	costs := domain.DefaultCostModel()

	type row struct {
		amount int64
		prob   float64
	}
	rows := make([]row, 0, 500)
	for i := 0; i < 500; i++ {
		rows = append(rows, row{amount: int64(1_000 + i*997), prob: float64(i%100) / 100.0})
	}

	var forward, backward int64
	for _, r := range rows {
		forward += eng.ExpectedValue(ctx, r.amount, r.prob, 1, costs)
	}
	for i := len(rows) - 1; i >= 0; i-- {
		backward += eng.ExpectedValue(ctx, rows[i].amount, rows[i].prob, 1, costs)
	}
	if forward != backward {
		t.Fatalf("integer totals diverged with summation order: %d vs %d", forward, backward)
	}
}

func TestExpectedValue_CancelledContextDropsUpside(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(18)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := eng.ExpectedValue(ctx, 1_000_000, 1.0, 1, domain.DefaultCostModel())
	if got != -310 { // 0 gross - 250 fee - 60 friction
		t.Fatalf("cancelled ExpectedValue = %d, want -310 (costs only)", got)
	}
}

func TestProbToBasisPoints(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   float64
		want int64
	}{
		{0, 0}, {1, 10000}, {0.5, 5000}, {0.9712, 9712},
		{-0.0, 0}, {2, 10000}, {-1, 0}, {nan(), 0},
	}
	for _, c := range cases {
		if got := probToBasisPoints(c.in); got != c.want {
			t.Errorf("probToBasisPoints(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Construction and concurrency
// ---------------------------------------------------------------------------

func TestNew_NilDependenciesUseProductionDefaults(t *testing.T) {
	t.Parallel()
	eng := New(nil, nil)
	ctx := context.Background()
	snap := mkSnap("card:HDFC", 100, 95, 0.85, closed)

	d := eng.BackoffFor(ctx, 2, domain.ClassNetworkTimeout, snap)
	if d < MinBackoff || d > BackoffCeiling(2, domain.ClassNetworkTimeout, snap) {
		t.Fatalf("default engine produced an out-of-range delay: %v", d)
	}
	if rail, _ := eng.ChooseRail(ctx, domain.RailUPIIntent, []domain.Rail{domain.RailCard}, snapsOf(snap)); rail != domain.RailCard {
		t.Fatalf("default engine chose %q, want card", rail)
	}
}

// TestEngine_ConcurrentUse exercises the shared rand.Rand under -race; the
// Engine is a process-wide singleton in the worker pool.
func TestEngine_ConcurrentUse(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(19)
	ctx := context.Background()
	ss := snapsOf(
		mkSnap("card:HDFC", 500, 400, 0.85, closed),
		mkSnap("netbanking:HDFC", 50, 4, 0.85, closed),
		mkSnap("wallet:paytm", 100, 90, 0.85, open),
	)
	avail := []domain.Rail{domain.RailCard, domain.RailNetbanking, domain.RailWallet}

	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if d := eng.BackoffFor(ctx, i%6+1, allClasses[i%len(allClasses)], ss["card:HDFC"]); d < MinBackoff {
					t.Errorf("goroutine %d: delay %v below floor", g, d)
					return
				}
				if rail, _ := eng.ChooseRail(ctx, domain.RailUPIIntent, avail, ss); rail != domain.RailCard {
					t.Errorf("goroutine %d: chose %q, want card", g, rail)
					return
				}
				if ev := eng.ExpectedValue(ctx, 100_000, 0.5, 2, domain.DefaultCostModel()); ev != 49_440 {
					t.Errorf("goroutine %d: expected value %d", g, ev)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

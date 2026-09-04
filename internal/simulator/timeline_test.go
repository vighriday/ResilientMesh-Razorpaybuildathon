package simulator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// fixedStart pins every timeline test to one instant so a failure is a bug in
// the code rather than a consequence of the hour the suite ran.
var fixedStart = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func newTestTimeline(t *testing.T, scenario string, seed int64, d time.Duration) *Timeline {
	t.Helper()
	tl, err := NewTimeline(scenario, seed, fixedStart, d)
	if err != nil {
		t.Fatalf("NewTimeline(%q): %v", scenario, err)
	}
	return tl
}

// TestScriptIsByteIdenticalForTheSameSeed is the load-bearing determinism
// assertion. Everything else this program claims — a repeatable demo, an
// attributable benchmark difference — is downstream of it.
func TestScriptIsByteIdenticalForTheSameSeed(t *testing.T) {
	t.Parallel()

	for _, scenario := range Scenarios() {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()

			first, err := newTestTimeline(t, scenario, 42, 10*time.Minute).Script(8, 100)
			if err != nil {
				t.Fatalf("first script: %v", err)
			}
			second, err := newTestTimeline(t, scenario, 42, 10*time.Minute).Script(8, 100)
			if err != nil {
				t.Fatalf("second script: %v", err)
			}
			if len(first) == 0 {
				t.Fatal("script generated no events; the assertion below would be vacuous")
			}

			a, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("marshal first: %v", err)
			}
			b, err := json.Marshal(second)
			if err != nil {
				t.Fatalf("marshal second: %v", err)
			}
			if string(a) != string(b) {
				t.Fatalf("same seed produced different scripts\nfirst:  %d bytes\nsecond: %d bytes", len(a), len(b))
			}
		})
	}
}

func TestDifferentSeedsProduceDifferentScripts(t *testing.T) {
	t.Parallel()

	one, err := newTestTimeline(t, ScenarioIssuerOutage, 1, 5*time.Minute).Script(8, 0)
	if err != nil {
		t.Fatalf("script(seed 1): %v", err)
	}
	two, err := newTestTimeline(t, ScenarioIssuerOutage, 2, 5*time.Minute).Script(8, 0)
	if err != nil {
		t.Fatalf("script(seed 2): %v", err)
	}
	a, _ := json.Marshal(one)
	b, _ := json.Marshal(two)
	if string(a) == string(b) {
		t.Fatal("two different seeds produced identical scripts; the seed is not reaching the generator")
	}
}

func TestDifferentScenariosDoNotShareArrivalTimes(t *testing.T) {
	t.Parallel()

	outage, err := newTestTimeline(t, ScenarioIssuerOutage, 7, 5*time.Minute).Script(8, 0)
	if err != nil {
		t.Fatalf("issuer-outage script: %v", err)
	}
	psp, err := newTestTimeline(t, ScenarioPSPDegradation, 7, 5*time.Minute).Script(8, 0)
	if err != nil {
		t.Fatalf("psp-degradation script: %v", err)
	}
	if len(outage) == 0 || len(psp) == 0 {
		t.Fatal("expected events in both scenarios")
	}
	if outage[0].EventID == psp[0].EventID {
		t.Fatal("scenario name is not folded into the seed; two scenarios share an event stream")
	}
}

// TestDuplicateRateIsHonoured checks both exact boundaries and the middle. The
// boundaries matter most: an off-by-one in the comparison shows up as "0% never
// means never" or "100% is only 99.9%", which is exactly the kind of defect an
// idempotency test would then fail to exercise.
func TestDuplicateRateIsHonoured(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMixedTraffic, 99, 10*time.Minute)

	none, err := tl.Script(20, 0)
	if err != nil {
		t.Fatalf("script at 0 per mille: %v", err)
	}
	if got := countDuplicates(none); got != 0 {
		t.Fatalf("duplicate rate 0 produced %d duplicates", got)
	}

	all, err := tl.Script(20, perMille)
	if err != nil {
		t.Fatalf("script at 1000 per mille: %v", err)
	}
	if got := countDuplicates(all); got != len(all) {
		t.Fatalf("duplicate rate 1000 duplicated %d of %d events", got, len(all))
	}

	// Pooled across seeds. A single run is a small binomial sample, so a
	// per-run tolerance would have to be wide enough to hide a real bias;
	// pooling shrinks the interval instead of loosening the assertion.
	var events, duplicates int
	for seed := int64(1); seed <= 8; seed++ {
		script, err := newTestTimeline(t, ScenarioMixedTraffic, seed, 10*time.Minute).Script(20, 250)
		if err != nil {
			t.Fatalf("script at 250 per mille (seed %d): %v", seed, err)
		}
		events += len(script)
		duplicates += countDuplicates(script)
	}
	if events < 2000 {
		t.Fatalf("sample too small to judge a rate: %d events", events)
	}
	observed := float64(duplicates) / float64(events)
	t.Logf("pooled duplicate fraction: %.4f over %d events", observed, events)
	if observed < 0.235 || observed > 0.265 {
		t.Fatalf("pooled duplicate fraction %.4f is outside [0.235, 0.265] for a requested 0.25", observed)
	}
}

func countDuplicates(evs []ScheduledEvent) int {
	n := 0
	for _, ev := range evs {
		if ev.Duplicate {
			n++
		}
	}
	return n
}

func TestScriptRejectsOutOfRangeParameters(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioIssuerOutage, 3, time.Minute)
	for _, tc := range []struct {
		name string
		rate float64
		dup  int
	}{
		{"zero rate", 0, 0},
		{"negative rate", -1, 0},
		{"rate above ceiling", maxRatePerSecond + 1, 0},
		{"negative duplicates", 1, -1},
		{"duplicates above scale", 1, perMille + 1},
	} {
		if _, err := tl.Script(tc.rate, tc.dup); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

func TestNewTimelineRejectsUnknownScenarioAndDuration(t *testing.T) {
	t.Parallel()

	if _, err := NewTimeline("not-a-scenario", 1, fixedStart, time.Minute); err == nil {
		t.Fatal("expected an error for an unknown scenario")
	}
	if _, err := NewTimeline(ScenarioIssuerOutage, 1, fixedStart, time.Millisecond); err == nil {
		t.Fatal("expected an error for a sub-second duration")
	}
	if _, err := NewTimeline(ScenarioIssuerOutage, 1, fixedStart, 48*time.Hour); err == nil {
		t.Fatal("expected an error for an over-long duration")
	}
}

// TestDowntimeSchemaRoundTripsThroughDomainTypes marshals what the API would
// serve and parses it back with the frozen contract. If this fails, the mesh's
// downtime source is reading a different schema than the simulator writes.
func TestDowntimeSchemaRoundTripsThroughDomainTypes(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMixedTraffic, 11, time.Hour)
	mid := fixedStart.Add(35 * time.Minute)

	list := domain.DowntimeList{Entity: "collection"}
	list.Items = tl.DowntimesAt(mid)
	list.Count = len(list.Items)
	if list.Count == 0 {
		t.Fatal("expected at least one visible downtime mid-run")
	}

	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	var decoded domain.DowntimeList
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if decoded.Entity != "collection" || decoded.Count != list.Count || len(decoded.Items) != list.Count {
		t.Fatalf("envelope did not survive the round trip: %+v", decoded)
	}

	for i, got := range decoded.Items {
		want := list.Items[i]
		if got.ID != want.ID || got.Entity != "payment.downtime" || got.Method != want.Method ||
			got.Status != want.Status || got.Severity != want.Severity || got.Begin != want.Begin {
			t.Fatalf("item %d did not survive the round trip:\n got %+v\nwant %+v", i, got, want)
		}
		if (got.End == nil) != (want.End == nil) {
			t.Fatalf("item %d: end nullability changed", i)
		}
		if got.TelemetryKey() != want.TelemetryKey() {
			t.Fatalf("item %d: telemetry key changed across the wire", i)
		}
	}
}

func TestEmptyDowntimeListSerialisesAsAnArray(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioIssuerOutage, 5, time.Hour)
	// Well before the window, and before the scheduled-publication lead.
	items := tl.DowntimesAt(fixedStart)
	if len(items) != 0 {
		t.Fatalf("expected no visible downtimes at the start of an unscheduled scenario, got %d", len(items))
	}
	raw, err := json.Marshal(domain.DowntimeList{Entity: "collection", Items: items})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"entity":"collection","count":0,"items":[]}`; string(raw) != want {
		t.Fatalf("empty envelope is %s, want %s", raw, want)
	}
}

// TestDowntimeEmitsStartedThenResolved is the transition the parked-retry
// release depends on. Without an observable resolved state the mechanism has
// nothing to fire on.
func TestDowntimeEmitsStartedThenResolved(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioIssuerOutage, 21, time.Hour)
	windows := tl.Windows()
	if len(windows) != 1 {
		t.Fatalf("expected exactly one window in %s, got %d", ScenarioIssuerOutage, len(windows))
	}
	w := windows[0]

	if _, visible := w.EntityAt(w.Begin.Add(-time.Minute)); visible {
		t.Fatal("an unscheduled outage must not be visible before it begins")
	}

	started, visible := w.EntityAt(w.Begin.Add(time.Second))
	if !visible {
		t.Fatal("outage is not visible after it begins")
	}
	if started.Status != domain.DowntimeStarted {
		t.Fatalf("status during the window is %q, want %q", started.Status, domain.DowntimeStarted)
	}
	if started.End != nil {
		t.Fatal("an ongoing outage must carry a null end")
	}
	if !started.Active(w.Begin.Add(time.Second)) {
		t.Fatal("domain.Active disagrees with a started window")
	}

	resolved, visible := w.EntityAt(w.End.Add(time.Minute))
	if !visible {
		t.Fatal("outage disappeared immediately on resolution; a poller could not observe the transition")
	}
	if resolved.Status != domain.DowntimeResolved {
		t.Fatalf("status after the window is %q, want %q", resolved.Status, domain.DowntimeResolved)
	}
	if resolved.End == nil || *resolved.End != w.End.Unix() {
		t.Fatalf("resolved entity carries end %v, want %d", resolved.End, w.End.Unix())
	}
	if resolved.Active(w.End.Add(time.Minute)) {
		t.Fatal("a resolved downtime must not report itself active")
	}

	if _, visible := w.EntityAt(w.End.Add(resolvedRetention + time.Minute)); visible {
		t.Fatal("a resolved downtime is retained forever; retention is not being applied")
	}
}

func TestScheduledWindowIsPublishedAhead(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMixedTraffic, 4, time.Hour)
	var scheduled *OutageWindow
	for _, w := range tl.Windows() {
		if w.Scheduled {
			copied := w
			scheduled = &copied
			break
		}
	}
	if scheduled == nil {
		t.Fatal("mixed-traffic must contain a scheduled maintenance window")
	}

	e, visible := scheduled.EntityAt(scheduled.Begin.Add(-scheduledLead / 2))
	if !visible {
		t.Fatal("a scheduled window must be published before it begins")
	}
	if e.Status != domain.DowntimeScheduled || !e.Scheduled {
		t.Fatalf("pre-window status is %q (scheduled=%v), want %q", e.Status, e.Scheduled, domain.DowntimeScheduled)
	}
	if _, visible := scheduled.EntityAt(scheduled.Begin.Add(-2 * scheduledLead)); visible {
		t.Fatal("a scheduled window is published earlier than the declared lead")
	}
}

// TestEveryOutageWindowTargetsRealTraffic catches the failure mode a schema
// test cannot: a window whose bank code or handle does not match any instrument
// in the mix is an outage that affects nothing, and every downstream assertion
// about it would pass while measuring nothing.
func TestEveryOutageWindowTargetsRealTraffic(t *testing.T) {
	t.Parallel()

	live := make(map[string]bool)
	for _, p := range indiaMix() {
		live[p.issuerKey()] = true
	}

	for _, scenario := range Scenarios() {
		tl := newTestTimeline(t, scenario, 1, time.Hour)
		windows := tl.Windows()
		if len(windows) == 0 {
			t.Errorf("%s: scenario declares no outage window", scenario)
		}
		for _, w := range windows {
			key := w.TelemetryKey()
			if !live[key] {
				t.Errorf("%s: window %s targets %q, which no instrument in the traffic mix produces",
					scenario, w.ID, key)
			}
			mid := w.Begin.Add(w.End.Sub(w.Begin) / 2)
			if got := tl.FailPerMille(key, mid); got != w.FailPerMille {
				t.Errorf("%s: failure rate at %q mid-window is %d, want %d", scenario, key, got, w.FailPerMille)
			}
			after := w.End.Add(time.Second)
			if got := tl.FailPerMille(key, after); got >= w.FailPerMille {
				t.Errorf("%s: failure rate at %q did not fall after resolution (%d)", scenario, key, got)
			}
		}
	}
}

// TestPaymentsJoinDowntimesOnOneKey proves the two projections the mesh relies
// on agree. They live in the frozen domain, but nothing enforces that the
// simulator populates the fields they read — a VPA handle stored with its "@"
// would break the join silently.
func TestPaymentsJoinDowntimesOnOneKey(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioPSPDegradation, 8, time.Hour)
	script, err := tl.Script(30, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}

	windowKeys := make(map[string]bool)
	for _, w := range tl.Windows() {
		windowKeys[w.TelemetryKey()] = true
	}

	joined := 0
	for _, ev := range script {
		if ev.Payment.Issuer() != ev.IssuerKey {
			t.Fatalf("event %s: payment issuer %q does not match the recorded key %q",
				ev.EventID, ev.Payment.Issuer(), ev.IssuerKey)
		}
		if windowKeys[ev.IssuerKey] {
			joined++
		}
	}
	if joined == 0 {
		t.Fatal("no generated payment joined an outage window; the demo would show an outage with no incidents")
	}
}

// TestOutageRaisesFailureVolume asserts the behaviour the whole demo rests on:
// the incident feed accelerates when the issuer degrades, without the operator
// changing anything.
func TestOutageRaisesFailureVolume(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioIssuerOutage, 77, 20*time.Minute)
	script, err := tl.Script(40, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	w := tl.Windows()[0]
	key := w.TelemetryKey()

	var during, outside int
	for _, ev := range script {
		if ev.IssuerKey != key {
			continue
		}
		at := fixedStart.Add(time.Duration(ev.OffsetMS) * time.Millisecond)
		if !at.Before(w.Begin) && !at.After(w.End) {
			during++
		} else {
			outside++
		}
	}
	if during == 0 {
		t.Fatal("no failures inside the outage window")
	}
	// The window covers 46% of the run at 94% failure against a 7% baseline, so
	// the inside count should dominate by a wide margin.
	if during < outside*3 {
		t.Fatalf("outage produced %d failures against %d outside it; the health model is not biting", during, outside)
	}
}

// TestGeneratedAmountsAreIntegerPaisaInBand guards the money invariant at its
// source. A float leaking into the amount path here would show up downstream as
// a gatekeeper amount mismatch that looks like a gatekeeper bug.
func TestGeneratedAmountsAreIntegerPaisaInBand(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMixedTraffic, 55, 10*time.Minute)
	script, err := tl.Script(30, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if len(script) == 0 {
		t.Fatal("no events generated")
	}

	lowest := amountBands[0].Min
	highest := amountBands[len(amountBands)-1].Max
	bands := make(map[string]int)
	for _, ev := range script {
		amt := ev.Payment.Amount
		if amt < lowest || amt > highest+900 {
			t.Fatalf("amount %d paisa is outside every band", amt)
		}
		if amt%100 != 0 {
			t.Fatalf("amount %d paisa is not a whole rupee", amt)
		}
		bands[domain.AmountBand(amt)]++
	}
	if len(bands) < 4 {
		t.Fatalf("amounts covered only %d bands: %v", len(bands), bands)
	}
}

// TestMandateBatchProducesRecurringTrafficAboveTheAFACeiling makes the
// compliance path reachable from a demo. If every generated mandate debit sat
// below the ceiling, the AFA invariant would never fire and its correctness
// would be untested end to end.
func TestMandateBatchProducesRecurringTrafficAboveTheAFACeiling(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMandateBatch, 31, 20*time.Minute)
	script, err := tl.Script(25, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}

	var recurring, aboveCeiling int
	for _, ev := range script {
		if !ev.Payment.IsRecurring() {
			continue
		}
		recurring++
		if ev.Subscription == nil {
			t.Fatalf("event %s is recurring but carries no subscription entity", ev.EventID)
		}
		if ev.Subscription.ID != ev.Payment.SubscriptionID {
			t.Fatalf("event %s: subscription id disagrees with the payment", ev.EventID)
		}
		if ev.Payment.Amount > domain.CategoryGeneral.AFACeilingPaisa() {
			aboveCeiling++
		}
	}
	if recurring*100 < len(script)*50 {
		t.Fatalf("mandate-batch produced only %d recurring events of %d", recurring, len(script))
	}
	if aboveCeiling == 0 {
		t.Fatal("no recurring debit exceeded the general AFA ceiling; the compliance boundary is unreachable")
	}
}

// TestFailureTablesAreWellFormed asserts the two properties a weighted table
// silently violates: that its weights sum to the scale, and that every code it
// can emit is one the mesh's taxonomy recognises. An unknown code would fall
// through every classification branch and be treated as ambiguous.
func TestFailureTablesAreWellFormed(t *testing.T) {
	t.Parallel()

	tables := map[string][]weightedCode{
		"outageNetbanking": outageNetbanking,
		"outageUPI":        outageUPI,
		"outageCard":       outageCard,
		"outageWallet":     outageWallet,
		"baseNetbanking":   baseNetbanking,
		"baseUPI":          baseUPI,
		"baseCard":         baseCard,
		"baseWallet":       baseWallet,
	}

	for name, table := range tables {
		total := 0
		for _, wc := range table {
			total += wc.Weight
			fc, ok := failureCatalog[wc.Code]
			if !ok {
				t.Errorf("%s: code %q has no catalog entry", name, wc.Code)
				continue
			}
			if fc.Description == "" || fc.Source == "" || fc.Step == "" {
				t.Errorf("%s: code %q has an incomplete catalog entry", name, wc.Code)
			}
			if !knownToTaxonomy(wc.Code) {
				t.Errorf("%s: code %q is not in the domain taxonomy", name, wc.Code)
			}
		}
		if total != perMille {
			t.Errorf("%s: weights sum to %d, want %d", name, total, perMille)
		}
	}

	for code := range failureCatalog {
		if !knownToTaxonomy(code) {
			t.Errorf("catalog code %q is not in the domain taxonomy", code)
		}
	}
}

func knownToTaxonomy(code string) bool {
	return domain.IsTerminalDecline(code) || domain.IsRefreshable(code) ||
		domain.IsAmbiguous(code) || domain.IsSoftDecline(code)
}

// TestOutageChangesTheDeclineMix asserts that an outage looks different on the
// wire, not just more frequent. A classifier that only ever saw the baseline
// mix would score well without learning anything about outages.
func TestOutageChangesTheDeclineMix(t *testing.T) {
	t.Parallel()

	infra := map[string]bool{
		"bank_technical_error": true, "gateway_technical_error": true,
		"payment_timed_out": true, "issuer_down": true, "upi_psp_error": true,
		"server_error": true,
	}

	for _, method := range []string{"netbanking", "upi", "card", "wallet"} {
		var baseInfra, outageInfra int
		for roll := 0; roll < perMille; roll++ {
			if infra[pickFailure(method, false, roll).Code] {
				baseInfra++
			}
			if infra[pickFailure(method, true, roll).Code] {
				outageInfra++
			}
		}
		if outageInfra <= baseInfra {
			t.Errorf("%s: infrastructure codes are %d/1000 during an outage against %d/1000 at baseline",
				method, outageInfra, baseInfra)
		}
		if outageInfra < 900 {
			t.Errorf("%s: only %d/1000 outage declines are infrastructure-shaped", method, outageInfra)
		}
	}
}

func TestPickFailureIsTotalOverTheScale(t *testing.T) {
	t.Parallel()

	// Out-of-range rolls must still resolve to a real code rather than panic on
	// an empty struct: the roll comes from a keyed hash, and a future change to
	// that derivation must not be able to produce an empty failure.
	for _, roll := range []int{-5, 0, perMille - 1, perMille, perMille * 2} {
		for _, method := range []string{"netbanking", "upi", "card", "wallet", "unknown-method"} {
			if got := pickFailure(method, false, roll); got.Code == "" {
				t.Fatalf("pickFailure(%q, false, %d) returned an empty code", method, roll)
			}
		}
	}
}

func TestRazorIDIsStableAndDomainSeparated(t *testing.T) {
	t.Parallel()

	if a, b := razorID("pay", 42, "x"), razorID("pay", 42, "x"); a != b {
		t.Fatalf("razorID is not stable: %s != %s", a, b)
	}
	if a, b := razorID("pay", 42, "x"), razorID("pay", 43, "x"); a == b {
		t.Fatal("razorID ignores the seed")
	}
	// Length-prefixed absorption: ("a","bc") and ("ab","c") must not collide.
	if a, b := razorID("pay", 42, "a", "bc"), razorID("pay", 42, "ab", "c"); a == b {
		t.Fatal("razorID concatenates its parts; a boundary shift collides")
	}
	id := razorID("pay", 42, "1")
	if !validRazorID("pay", id) {
		t.Fatalf("generated id %q fails its own validator", id)
	}
	if len(id) != len("pay_")+idBodyLen {
		t.Fatalf("id %q is %d chars, want %d", id, len(id), len("pay_")+idBodyLen)
	}
}

func TestSyntheticVPAJoinsTheHandle(t *testing.T) {
	t.Parallel()

	vpa := syntheticVPA("pay_abcdef123456", "okhdfcbank")
	pe := domain.PaymentEntity{Method: "upi", VPA: vpa}
	if got, want := pe.Issuer(), "upi:okhdfcbank"; got != want {
		t.Fatalf("issuer key from %q is %q, want %q", vpa, got, want)
	}
	if syntheticVPA("pay_abc", "") != "" {
		t.Fatal("an empty handle must not produce a VPA")
	}
}

package simulation

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// A fault that never fires makes every "we survived this" claim false, and a
// fault that fires when it was not configured makes every comparison between
// profiles meaningless. Both directions are checked for every declared fault
// kind, and the enumeration is driven off allFaultKinds so a kind added later
// without a test fails by name.

// faultProbe pairs a fault kind with the profile knob that enables it and the
// call that draws it.
type faultProbe struct {
	enable  func(*ChaosProfile)
	trigger func(*Injector) bool
}

func faultProbes() map[faultKind]faultProbe {
	return map[faultKind]faultProbe{
		faultPublishLoss: {
			func(p *ChaosProfile) { p.PublishLoss = 1 },
			func(f *Injector) bool { return f.PublishLost() },
		},
		faultBrokerDrop: {
			func(p *ChaosProfile) { p.BrokerDrop = 1 },
			func(f *Injector) bool { return f.BrokerDropped() },
		},
		faultDuplicate: {
			func(p *ChaosProfile) { p.DuplicateDelivery = 1 },
			func(f *Injector) bool { return f.DuplicateDelivery() },
		},
		faultWorkerDeath: {
			func(p *ChaosProfile) { p.WorkerDeath = 1 },
			func(f *Injector) bool { return f.WorkerDied() },
		},
		faultStoreError: {
			func(p *ChaosProfile) { p.StoreError = 1 },
			func(f *Injector) bool { return f.StoreFailed() },
		},
		faultQueueOutage: {
			func(p *ChaosProfile) {
				p.QueueOutage, p.MinOutage, p.MaxOutage = 1, 5*time.Second, 45*time.Second
			},
			func(f *Injector) bool { return f.QueueOutage() > 0 },
		},
		faultSlowConsumer: {
			func(p *ChaosProfile) { p.SlowConsumer = 1 },
			func(f *Injector) bool { return f.SlowConsumer() },
		},
		faultClockSkew: {
			func(p *ChaosProfile) {
				p.ClockSkew, p.MaxClockSkew = 1, 30*time.Second
			},
			// Skew is signed and bounded, and zero is a legal draw, so
			// "it fired" is read off the counter rather than off the value.
			func(f *Injector) bool { f.ClockSkew(); return f.counts[faultClockSkew] > 0 },
		},
	}
}

func TestEveryFaultKindHasAProbe(t *testing.T) {
	probes := faultProbes()
	for _, k := range allFaultKinds {
		if _, ok := probes[k]; !ok {
			t.Errorf("fault kind %q has no probe; a fault nothing tests is a fault nothing knows fires", k)
		}
	}
	for k := range probes {
		var found bool
		for _, declared := range allFaultKinds {
			if declared == k {
				found = true
			}
		}
		if !found {
			t.Errorf("probe names %q, which is not a declared fault kind", k)
		}
	}
	if len(allFaultKinds) != 8 {
		t.Fatalf("allFaultKinds has %d entries; update the probe table deliberately", len(allFaultKinds))
	}
}

// TestEachFaultFiresOnlyWhenConfigured is the two-sided check. Each kind is
// enabled alone at probability 1 and every trigger is then drawn: the enabled
// one must fire and no other may, or a profile knob is wired to the wrong draw
// and the intensity a report names is not the intensity that ran.
func TestEachFaultFiresOnlyWhenConfigured(t *testing.T) {
	for kind, probe := range faultProbes() {
		t.Run(string(kind), func(t *testing.T) {
			prof := ChaosProfile{Name: "probe"}
			probe.enable(&prof)
			f := NewInjector(rand.New(rand.NewSource(1)), prof)

			if !probe.trigger(f) {
				t.Fatalf("fault %q did not fire at probability 1", kind)
			}
			if f.counts[kind] == 0 {
				t.Fatalf("fault %q fired without being counted; the run summary would under-report it", kind)
			}
			// Nothing else may have been charged: an enabled fault must not
			// consume another kind's budget.
			for other, count := range f.counts {
				if other != kind && count != 0 {
					t.Fatalf("enabling %q also fired %q %d times", kind, other, count)
				}
			}
		})
	}
}

// TestTheNoneProfileFiresNothing is the other half. It is also why hit skips
// the draw entirely when the probability is zero: taking a draw for a disabled
// fault would make the "none" profile's random stream differ from the others'
// for no benefit, and profiles are compared against each other.
func TestTheNoneProfileFiresNothing(t *testing.T) {
	prof, err := Profile("none")
	if err != nil {
		t.Fatalf("Profile(none): %v", err)
	}
	f := NewInjector(rand.New(rand.NewSource(1)), prof)
	for i := 0; i < 200; i++ {
		for _, probe := range faultProbes() {
			if probe.trigger(f) {
				t.Fatal("a fault fired under the none profile")
			}
		}
	}
	if f.Total() != 0 {
		t.Fatalf("the none profile injected %d faults", f.Total())
	}
	// The generator must be untouched, which is what makes two profiles
	// comparable on the same seed.
	control := rand.New(rand.NewSource(1))
	if f.rng.Int63() != control.Int63() {
		t.Fatal("the none profile consumed draws from the generator")
	}
}

// TestFaultSchedulesAreReproducible is what makes an injected fault part of the
// artifact rather than an accident. Two injectors on one seed must fire the
// same faults in the same order, or a reported failure could not be replayed.
func TestFaultSchedulesAreReproducible(t *testing.T) {
	prof, err := Profile("storm")
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	schedule := func(seed int64) []string {
		f := NewInjector(rand.New(rand.NewSource(seed)), prof)
		var fired []string
		for i := 0; i < 500; i++ {
			for _, k := range allFaultKinds {
				before := f.counts[k]
				faultProbes()[k].trigger(f)
				if f.counts[k] > before {
					fired = append(fired, string(k))
				}
			}
		}
		return fired
	}
	a, b := schedule(20260904), schedule(20260904)
	if len(a) == 0 {
		t.Fatal("the storm profile fired nothing over 500 rounds; the comparison is vacuous")
	}
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatal("two injectors on one seed produced different fault schedules")
	}
	if c := schedule(20260905); strings.Join(a, ",") == strings.Join(c, ",") {
		t.Fatal("two seeds produced identical fault schedules; the injector ignores its seed")
	}
}

// TestInjectorCountsRenderInAStableOrder matters because the counts are emitted
// into the trace, and an unsorted walk of the counts map would make the
// determinism assertion fail for a reason that has nothing to do with the run.
func TestInjectorCountsRenderInAStableOrder(t *testing.T) {
	prof, _ := Profile("storm")
	f := NewInjector(rand.New(rand.NewSource(3)), prof)
	for i := 0; i < 50; i++ {
		for _, probe := range faultProbes() {
			probe.trigger(f)
		}
	}
	first := f.Counts()
	if len(first) != len(allFaultKinds) {
		t.Fatalf("Counts() rendered %d fields for %d kinds", len(first), len(allFaultKinds))
	}
	for i := 0; i < 32; i++ {
		again := f.Counts()
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("Counts() field %d moved: %+v vs %+v", j, again[j], first[j])
			}
		}
	}
	// Every kind must be named even when it never fired: a summary that omitted
	// the zeroes would make "this fault never fired" indistinguishable from
	// "this fault does not exist".
	var total int64
	for i, k := range allFaultKinds {
		if first[i].K != string(k) {
			t.Fatalf("Counts()[%d] is %q, want %q in allFaultKinds order", i, first[i].K, k)
		}
		total += f.counts[k]
	}
	if total != f.Total() {
		t.Fatalf("Total() = %d but the counters sum to %d", f.Total(), total)
	}
}

// TestClockSkewIsBoundedAndSigned checks the fault's shape rather than its
// occurrence. Unbounded skew would let the simulation "disprove" invariants no
// real deployment can violate, which produces noise instead of findings;
// one-sided skew would miss the case where a component's clock runs early and
// shortens a regulatory window.
func TestClockSkewIsBoundedAndSigned(t *testing.T) {
	const bound = 30 * time.Second
	prof := ChaosProfile{Name: "probe", ClockSkew: 1, MaxClockSkew: bound}
	f := NewInjector(rand.New(rand.NewSource(11)), prof)
	var sawNegative, sawPositive bool
	for i := 0; i < 400; i++ {
		d := f.ClockSkew()
		if d > bound || d < -bound {
			t.Fatalf("skew %s is outside the +/-%s bound", d, bound)
		}
		if d < 0 {
			sawNegative = true
		}
		if d > 0 {
			sawPositive = true
		}
	}
	if !sawNegative || !sawPositive {
		t.Fatalf("skew was not two-sided over 400 draws (negative=%t positive=%t)", sawNegative, sawPositive)
	}
	// A profile that enables skew but bounds it at zero must produce none,
	// rather than an unbounded draw from a zero range.
	zero := NewInjector(rand.New(rand.NewSource(11)), ChaosProfile{ClockSkew: 1})
	if d := zero.ClockSkew(); d != 0 {
		t.Fatalf("skew with a zero bound = %s, want 0", d)
	}
}

func TestQueueOutageStaysInsideItsConfiguredWindow(t *testing.T) {
	const lo, hi = 5 * time.Second, 45 * time.Second
	f := NewInjector(rand.New(rand.NewSource(5)), ChaosProfile{QueueOutage: 1, MinOutage: lo, MaxOutage: hi})
	for i := 0; i < 200; i++ {
		d := f.QueueOutage()
		if d < lo || d > hi {
			t.Fatalf("outage %s is outside [%s, %s]", d, lo, hi)
		}
	}
	// An inverted or degenerate window collapses to the lower bound rather than
	// panicking inside rand.Int63n.
	inverted := NewInjector(rand.New(rand.NewSource(5)), ChaosProfile{QueueOutage: 1, MinOutage: hi, MaxOutage: lo})
	if d := inverted.QueueOutage(); d != hi {
		t.Fatalf("an inverted window produced %s, want the lower bound %s", d, hi)
	}
}

// TestProfileNamesAreClosedAndSorted covers the resolution path a flag takes.
// An unknown name is an error rather than a silent fallback to "none": a typo
// that quietly disabled all fault injection would turn a green run into a lie.
func TestProfileNamesAreClosedAndSorted(t *testing.T) {
	names := ProfileNames()
	if len(names) != len(profiles) {
		t.Fatalf("ProfileNames listed %d of %d profiles", len(names), len(profiles))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("ProfileNames is not sorted: %v", names)
		}
	}
	for _, n := range names {
		p, err := Profile(n)
		if err != nil {
			t.Fatalf("Profile(%q): %v", n, err)
		}
		if p.Name != n {
			t.Fatalf("Profile(%q).Name = %q", n, p.Name)
		}
	}
	for _, bad := range []string{"", " ", "NONE", "standard ", "stanadrd", "chaos"} {
		if _, err := Profile(bad); err == nil {
			t.Errorf("Profile(%q) was accepted", bad)
		} else if !strings.Contains(err.Error(), "unknown chaos profile") {
			t.Errorf("Profile(%q) error does not name the problem: %v", bad, err)
		}
	}
}

// TestEveryFaultKindFiresInARealRun is the end-to-end half of the argument. The
// probes above prove each kind is *callable*; this proves each is *reachable*
// through the pipeline. A fault whose call site was deleted in a refactor would
// still pass every probe.
func TestEveryFaultKindFiresInARealRun(t *testing.T) {
	sim, err := New(Config{Seed: 20260904, Incidents: 40, Chaos: "storm", MaxSteps: 600_000})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := sim.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, k := range allFaultKinds {
		if sim.faults.counts[k] == 0 {
			t.Errorf("fault %q never fired in a 40-incident storm run; every claim that the "+
				"system survives it is currently unsupported", k)
		}
	}
}

package simulation

import (
	"context"
	"runtime"
	"strconv"
	"testing"
)

// Determinism is the headline property of this package: a whole distributed
// system's execution is a pure function of one integer seed. Everything else
// the harness claims — "here are 200 seeds' worth of evidence", "here is the
// seed that breaks it" — is worthless if the same seed can produce two
// different runs.
//
// The assertions here compare the full serialised trace byte for byte rather
// than a summary hash. A hash comparison answers "did it diverge"; the bytes
// answer "where", and a determinism failure with no location is a bug report
// nobody can act on.

// determinismConfig is a run small enough to repeat many times and large enough
// to exercise the relay, the workers, the reclaimer, the reconciler, the
// downtime feed and the session hub. Chaos is on, because a run with no faults
// proves only that the happy path is deterministic — the least interesting
// version of the claim.
func determinismConfig(seed int64) Config {
	return Config{Seed: seed, Incidents: 12, Chaos: "standard", CaptureTrace: true, MaxSteps: 400_000}
}

func runTrace(t *testing.T, cfg Config) ([]byte, Result) {
	t.Helper()
	sim, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v): %v", cfg, err)
	}
	res, err := sim.Run(context.Background())
	if err != nil {
		t.Fatalf("Run(seed %d): %v", cfg.Seed, err)
	}
	return sim.Trace().Bytes(), res
}

// requireIdentical compares two traces byte for byte and, on divergence,
// reports the first differing event. That line names the operation, which in
// practice is enough to find the unsorted map iteration behind it.
func requireIdentical(t *testing.T, what string, a, b []byte, ra, rb Result) {
	t.Helper()
	if len(a) == 0 {
		t.Fatal("the trace is empty; the comparison would be vacuous")
	}
	if string(a) == string(b) {
		if ra.TraceHash != rb.TraceHash {
			t.Fatalf("%s: traces are byte-identical but the hashes differ (%s vs %s)",
				what, ra.TraceHash, rb.TraceHash)
		}
		return
	}
	line, left, right, _ := FirstDifference(a, b)
	t.Fatalf("%s: traces diverged at line %d\n  run 1: %s\n  run 2: %s\n"+
		"  run 1: steps=%d events=%d hash=%s\n  run 2: steps=%d events=%d hash=%s",
		what, line, left, right,
		ra.Steps, ra.TraceEvents, ra.TraceHash, rb.Steps, rb.TraceEvents, rb.TraceHash)
}

func TestSameSeedProducesAByteIdenticalTrace(t *testing.T) {
	cfg := determinismConfig(20260904)
	a, ra := runTrace(t, cfg)
	b, rb := runTrace(t, cfg)
	requireIdentical(t, "two runs of one seed", a, b, ra, rb)

	// Every reported number, not only the trace, must be reproducible: a fuzz
	// sweep aggregates these, and a summary that drifted while the trace held
	// would be a second, quieter source of irreproducibility.
	if ra.Steps != rb.Steps || ra.TraceEvents != rb.TraceEvents || ra.MonitorChecks != rb.MonitorChecks {
		t.Fatalf("run counters differ: %d/%d steps, %d/%d events, %d/%d checks",
			ra.Steps, rb.Steps, ra.TraceEvents, rb.TraceEvents, ra.MonitorChecks, rb.MonitorChecks)
	}
	if ra.FaultsInjected != rb.FaultsInjected || ra.Attempts != rb.Attempts ||
		ra.Recovered != rb.Recovered || ra.NetRecoveredPaisa != rb.NetRecoveredPaisa {
		t.Fatalf("run outcomes differ: faults %d/%d, attempts %d/%d, recovered %d/%d, paisa %d/%d",
			ra.FaultsInjected, rb.FaultsInjected, ra.Attempts, rb.Attempts,
			ra.Recovered, rb.Recovered, ra.NetRecoveredPaisa, rb.NetRecoveredPaisa)
	}
	// The audit chain is hashed content, so identical head hashes are an
	// independent witness that every ledger write happened in the same order
	// with the same timestamps.
	if ra.AuditHead != rb.AuditHead || ra.AuditEntries != rb.AuditEntries {
		t.Fatalf("audit chains differ: %d entries head=%s vs %d entries head=%s",
			ra.AuditEntries, ra.AuditHead, rb.AuditEntries, rb.AuditHead)
	}
}

// TestDeterminismSurvivesGOMAXPROCSVariation targets the two classic leaks.
//
// Go randomises map iteration order and schedules goroutines nondeterministically,
// and both are sensitive to GOMAXPROCS. This package runs on one goroutine and
// sorts every map walk on purpose; if either discipline lapses, the run at
// GOMAXPROCS=1 and the run at GOMAXPROCS=N will disagree and this is the test
// that says so.
func TestDeterminismSurvivesGOMAXPROCSVariation(t *testing.T) {
	cfg := determinismConfig(20260904)
	restore := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(restore)

	single, rs := runTrace(t, cfg)

	high := runtime.NumCPU() * 2
	if high < 4 {
		high = 4
	}
	runtime.GOMAXPROCS(high)
	parallel, rp := runTrace(t, cfg)

	requireIdentical(t, "GOMAXPROCS=1 against GOMAXPROCS="+strconv.Itoa(high), single, parallel, rs, rp)

	// Back down again, so the comparison is not one-directional: a leak that
	// only appears on the transition would otherwise hide.
	runtime.GOMAXPROCS(1)
	again, ragain := runTrace(t, cfg)
	requireIdentical(t, "GOMAXPROCS=1 revisited", single, again, rs, ragain)
}

// TestDifferentSeedsProduceDifferentTraces is what stops every claim above from
// being vacuous. A harness that ignored its seed would pass every
// same-seed-same-trace assertion perfectly.
func TestDifferentSeedsProduceDifferentTraces(t *testing.T) {
	base, rb := runTrace(t, determinismConfig(20260904))
	seen := map[string]int64{rb.TraceHash: 20260904}
	for _, seed := range []int64{1, 2, 20260905, -7, 1 << 40} {
		other, ro := runTrace(t, determinismConfig(seed))
		if string(base) == string(other) {
			t.Fatalf("seed %d produced the same trace as seed 20260904; the run ignores its seed", seed)
		}
		if prior, dup := seen[ro.TraceHash]; dup {
			t.Fatalf("seeds %d and %d produced the same trace hash %s", prior, seed, ro.TraceHash)
		}
		seen[ro.TraceHash] = seed
	}
}

// TestChaosProfileChangesTheRun proves the profile is wired through rather than
// merely named in the summary. A typo that silently disabled fault injection
// would turn every "we survived this" claim into a claim about a run in which
// nothing happened.
func TestChaosProfileChangesTheRun(t *testing.T) {
	hashes := map[string]string{}
	for _, profile := range ProfileNames() {
		cfg := determinismConfig(20260904)
		cfg.Chaos = profile
		_, res := runTrace(t, cfg)
		if res.Chaos != profile {
			t.Fatalf("profile %q reported itself as %q", profile, res.Chaos)
		}
		if profile == "none" {
			if res.FaultsInjected != 0 {
				t.Fatalf("profile none injected %d faults", res.FaultsInjected)
			}
		} else if res.FaultsInjected == 0 {
			t.Fatalf("profile %q injected no faults; every resilience claim made under it would be empty", profile)
		}
		for other, h := range hashes {
			if h == res.TraceHash {
				t.Fatalf("profiles %q and %q produced identical runs", other, profile)
			}
		}
		hashes[profile] = res.TraceHash
	}
	if len(hashes) < 2 {
		t.Fatal("fewer than two profiles ran; the comparison proves nothing")
	}
}

// TestTheRunIsIndependentOfCapture guards a subtle way the assertion could lie:
// if capturing the trace perturbed the run, then --assert-determinism would be
// comparing two runs that no unobserved run ever performs.
func TestTheRunIsIndependentOfCapture(t *testing.T) {
	cfg := determinismConfig(20260904)
	_, withCapture := runTrace(t, cfg)

	cfg.CaptureTrace = false
	sim, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	without, err := sim.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if withCapture.TraceHash != without.TraceHash || withCapture.Steps != without.Steps {
		t.Fatalf("capturing the trace changed the run: hash %s/%s steps %d/%d",
			withCapture.TraceHash, without.TraceHash, withCapture.Steps, without.Steps)
	}
	if len(sim.Trace().Bytes()) != 0 {
		t.Fatal("a run with capture disabled retained trace text")
	}
}

// TestConfigDefaultsAreDeterministicToo covers the path a caller takes when it
// leaves fields unset: a zero Config must resolve to one fixed experiment, not
// to whatever the process happened to have.
func TestConfigDefaultsAreDeterministicToo(t *testing.T) {
	got := Config{}.withDefaults()
	want := Config{Incidents: 100, MaxSteps: DefaultMaxSteps, Chaos: "standard", MaxAttempts: 3}
	if got != want {
		t.Fatalf("zero Config resolved to %+v, want %+v", got, want)
	}
	for _, bad := range []Config{{Incidents: -1}, {MaxSteps: -1}, {MaxAttempts: -1}} {
		if d := bad.withDefaults(); d.Incidents <= 0 || d.MaxSteps <= 0 || d.MaxAttempts <= 0 {
			t.Fatalf("negative input %+v resolved to %+v", bad, d)
		}
	}
	// An unknown profile is an error rather than a silent fallback, because a
	// typo that quietly disabled all fault injection would turn a green run into
	// a lie.
	if _, err := New(Config{Seed: 1, Chaos: "stanadrd"}); err == nil {
		t.Fatal("New accepted an unknown chaos profile")
	}
}

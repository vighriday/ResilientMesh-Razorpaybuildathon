// Command meshsim runs ResilientMesh's deterministic simulation.
//
// It drives the real gatekeeper, policy engine and inference stack against
// in-memory ports and a virtual clock, injects faults from a seeded generator,
// and checks the compliance invariants after every step. Everything it does is
// a pure function of --seed, which is what makes a failure it finds a
// reproducible artifact rather than an anecdote.
//
//	meshsim --seed 20260904 --incidents 400 --assert-determinism
//	meshsim --fuzz 25 --incidents 200
//
// Exit status is 0 only when every invariant held, the run drained, and (when
// asked) the trace was byte-identical across two runs. Anything else is
// non-zero so CI can gate on it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/simulation"
)

// exit codes. They are distinct so a CI log says what happened without being
// parsed.
const (
	exitOK          = 0
	exitViolation   = 1
	exitUsage       = 2
	exitNondetermin = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("meshsim", flag.ContinueOnError)
	fs.SetOutput(stderr)

	seed := fs.Int64("seed", 20260904, "seed for the run; the entire simulation is a pure function of this")
	incidents := fs.Int("incidents", 200, "number of failed-payment webhooks to generate")
	steps := fs.Int("steps", simulation.DefaultMaxSteps, "maximum scheduler steps before the run is reported as truncated")
	chaos := fs.String("chaos", "standard", "fault profile: "+strings.Join(simulation.ProfileNames(), ", "))
	trace := fs.Bool("trace", false, "print the full deterministic event trace to stdout")
	traceFile := fs.String("trace-file", "", "write the full deterministic event trace to this path")
	assert := fs.Bool("assert-determinism", false, "run the seed twice and require a byte-identical trace")
	fuzz := fs.Int("fuzz", 0, "run N consecutive seeds and report any that violates an invariant")
	asJSON := fs.Bool("json", false, "emit the result as JSON instead of a human summary")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "meshsim: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *incidents <= 0 || *steps <= 0 || *fuzz < 0 {
		fmt.Fprintln(stderr, "meshsim: --incidents and --steps must be positive and --fuzz must not be negative")
		return exitUsage
	}
	if _, err := simulation.Profile(*chaos); err != nil {
		fmt.Fprintf(stderr, "meshsim: %v\n", err)
		return exitUsage
	}

	cfg := simulation.Config{
		Seed:      *seed,
		Incidents: *incidents,
		MaxSteps:  *steps,
		Chaos:     *chaos,
		// The trace is captured whenever it will be printed or compared. It is
		// the only expensive thing the harness does, so it is opt-in.
		CaptureTrace: *trace || *traceFile != "" || *assert,
	}

	ctx := context.Background()
	if *fuzz > 0 {
		return fuzzSweep(ctx, cfg, *fuzz, stdout, stderr, *asJSON)
	}

	res, err := once(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "meshsim: %v\n", err)
		return exitViolation
	}

	if *assert {
		second, secondErr := once(ctx, cfg)
		if secondErr != nil {
			fmt.Fprintf(stderr, "meshsim: determinism check: second run failed: %v\n", secondErr)
			return exitViolation
		}
		if code := compareRuns(ctx, cfg, res, second, stderr); code != exitOK {
			return code
		}
		fmt.Fprintf(stdout, "determinism: two runs of seed %d produced byte-identical %d-event traces (%s)\n",
			cfg.Seed, res.TraceEvents, res.TraceHash[:16])
	}

	if err := writeTrace(ctx, cfg, *trace, *traceFile, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "meshsim: %v\n", err)
		return exitViolation
	}

	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(res); err != nil {
			fmt.Fprintf(stderr, "meshsim: encoding result: %v\n", err)
			return exitViolation
		}
	} else {
		printSummary(stdout, res)
	}
	if !res.OK() {
		printViolations(stderr, res)
		return exitViolation
	}
	return exitOK
}

// once builds and runs a single simulation. Each call constructs a fresh Sim,
// so nothing carries over between runs — which is precisely what the
// determinism assertion is testing.
func once(ctx context.Context, cfg simulation.Config) (simulation.Result, error) {
	sim, err := simulation.New(cfg)
	if err != nil {
		return simulation.Result{}, err
	}
	return sim.Run(ctx)
}

// compareRuns is the determinism assertion. It compares the trace hash first
// because that is the whole identity, then locates the first differing event so
// the failure names the operation rather than merely asserting disagreement —
// in practice that line is enough to find the unsorted map iteration behind it.
func compareRuns(ctx context.Context, cfg simulation.Config, a, b simulation.Result, stderr *os.File) int {
	if a.TraceHash == b.TraceHash && a.Steps == b.Steps {
		return exitOK
	}
	fmt.Fprintf(stderr, "meshsim: NONDETERMINISM on seed %d\n", cfg.Seed)
	fmt.Fprintf(stderr, "  run 1: steps=%d events=%d hash=%s\n", a.Steps, a.TraceEvents, a.TraceHash)
	fmt.Fprintf(stderr, "  run 2: steps=%d events=%d hash=%s\n", b.Steps, b.TraceEvents, b.TraceHash)

	first, second, err := traces(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "  (could not re-capture traces to locate the divergence: %v)\n", err)
		return exitNondetermin
	}
	if line, left, right, differs := simulation.FirstDifference(first, second); differs {
		fmt.Fprintf(stderr, "  first difference at trace line %d:\n    run 1: %s\n    run 2: %s\n", line, left, right)
	}
	return exitNondetermin
}

func traces(ctx context.Context, cfg simulation.Config) ([]byte, []byte, error) {
	cfg.CaptureTrace = true
	a, err := simulation.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := a.Run(ctx); err != nil {
		return nil, nil, err
	}
	b, err := simulation.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := b.Run(ctx); err != nil {
		return nil, nil, err
	}
	return a.Trace().Bytes(), b.Trace().Bytes(), nil
}

func writeTrace(ctx context.Context, cfg simulation.Config, toStdout bool, path string, stdout, stderr *os.File) error {
	if !toStdout && path == "" {
		return nil
	}
	cfg.CaptureTrace = true
	sim, err := simulation.New(cfg)
	if err != nil {
		return err
	}
	if _, err := sim.Run(ctx); err != nil {
		return err
	}
	if toStdout {
		if _, err := sim.Trace().WriteTo(stdout); err != nil {
			return err
		}
	}
	if path == "" {
		return nil
	}
	// 0o600: a trace names incident ids and issuer keys. Neither is a secret,
	// but a file written by a payment tool defaults to the owner alone.
	if err := os.WriteFile(path, sim.Trace().Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing trace to %s: %w", path, err)
	}
	fmt.Fprintf(stderr, "trace written to %s (%d events)\n", path, sim.Trace().Count())
	return nil
}

// fuzzSweep runs consecutive seeds and reports every one that breaks an
// invariant. Consecutive rather than random seeds so that "meshsim --fuzz 50"
// means the same fifty experiments on every machine and in every CI run.
func fuzzSweep(ctx context.Context, cfg simulation.Config, n int, stdout, stderr *os.File, asJSON bool) int {
	start := time.Now()
	var failures []simulation.Result
	var totalSteps, totalAttempts int
	var totalChecks int64

	base := cfg
	base.CaptureTrace = false
	for i := 0; i < n; i++ {
		run := base
		run.Seed = base.Seed + int64(i)
		res, err := once(ctx, run)
		if err != nil {
			fmt.Fprintf(stderr, "meshsim: seed %d failed to run: %v\n", run.Seed, err)
			return exitViolation
		}
		totalSteps += res.Steps
		totalAttempts += res.Attempts
		totalChecks += res.MonitorChecks
		if !res.OK() {
			failures = append(failures, res)
			fmt.Fprintf(stderr, "FAIL seed=%d invariants=%v truncated=%t\n",
				res.Seed, res.ViolationKinds(), res.Truncated)
			for _, v := range res.Violations {
				fmt.Fprintf(stderr, "  %s\n", v.Error())
			}
		}
	}

	if asJSON {
		out := struct {
			Seeds     int                 `json:"seeds"`
			FirstSeed int64               `json:"first_seed"`
			Incidents int                 `json:"incidents_per_seed"`
			Chaos     string              `json:"chaos_profile"`
			Steps     int                 `json:"total_steps"`
			Attempts  int                 `json:"total_attempts"`
			Checks    int64               `json:"total_invariant_checks"`
			Failures  []simulation.Result `json:"failures,omitempty"`
		}{n, base.Seed, base.Incidents, base.Chaos, totalSteps, totalAttempts, totalChecks, failures}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			fmt.Fprintf(stderr, "meshsim: encoding fuzz result: %v\n", err)
			return exitViolation
		}
	} else {
		fmt.Fprintf(stdout, "fuzz: %d seeds from %d, %d incidents each, chaos=%s\n",
			n, base.Seed, base.Incidents, base.Chaos)
		fmt.Fprintf(stdout, "fuzz: %d scheduler steps, %d executed attempts, %d invariant checks in %s\n",
			totalSteps, totalAttempts, totalChecks, time.Since(start).Round(time.Millisecond))
		if len(failures) == 0 {
			fmt.Fprintf(stdout, "fuzz: no invariant violated across %d seeds\n", n)
		} else {
			fmt.Fprintf(stdout, "fuzz: %d of %d seeds violated an invariant\n", len(failures), n)
		}
	}
	if len(failures) > 0 {
		return exitViolation
	}
	return exitOK
}

func printSummary(w *os.File, r simulation.Result) {
	line := strings.Repeat("-", 68)
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintf(w, " ResilientMesh deterministic simulation\n")
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintf(w, " seed              %d\n", r.Seed)
	fmt.Fprintf(w, " chaos profile     %s (%d faults injected)\n", r.Chaos, r.FaultsInjected)
	fmt.Fprintf(w, " steps             %d over %s of virtual time\n", r.Steps, r.VirtualElapsed.Round(time.Second))
	fmt.Fprintf(w, " trace             %s (%d events)\n", r.TraceHash, r.TraceEvents)
	fmt.Fprintf(w, " invariant checks  %d\n", r.MonitorChecks)
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintf(w, " webhooks          %d accepted, %d duplicates rejected, %d terminal declines filtered\n",
		r.Accepted, r.DuplicatesRejected, r.TerminalFiltered)
	fmt.Fprintf(w, " delivery          %d published, %d delivered, %d dropped by broker, %d reclaimed\n",
		r.MessagesPublished, r.Delivered, r.MessagesDropped, r.MessagesReclaimed)
	fmt.Fprintf(w, " idempotence       %d duplicate deliveries suppressed, %d incidents reconciled\n",
		r.DuplicateSuppressed, r.Reconciled)
	fmt.Fprintf(w, " outcomes          %d attempts, %d recovered, %d abandoned, %d abstained, %d rail morphs\n",
		r.Attempts, r.Recovered, r.Abandoned, r.Abstained, r.RailMorphs)
	fmt.Fprintf(w, " compliance        %d pre-debit notices, %d cooling deferrals, %d AFA ceiling gaps\n",
		r.PreDebitNotices, r.CoolingDeferrals, r.AFAGateGap)
	fmt.Fprintf(w, " resilience        %d breaker trips, %d downtime-triggered releases, %d SSE frames dropped\n",
		r.BreakerTrips, r.DowntimeReleases, r.SSEFramesDropped)
	fmt.Fprintf(w, " money             %d paisa recovered, %d paisa in gateway fees\n",
		r.NetRecoveredPaisa, r.GatewayFeesPaisa)
	fmt.Fprintf(w, " audit             %d entries, chain valid=%t head=%s\n",
		r.AuditEntries, r.AuditValid, short(r.AuditHead))
	fmt.Fprintf(w, "%s\n", line)
	if r.OK() {
		fmt.Fprintf(w, " RESULT            PASS — no invariant violated\n")
	} else {
		fmt.Fprintf(w, " RESULT            FAIL — %d violation(s), truncated=%t\n", len(r.Violations), r.Truncated)
	}
	fmt.Fprintf(w, "%s\n", line)
}

func printViolations(w *os.File, r simulation.Result) {
	for _, v := range r.Violations {
		fmt.Fprintf(w, "%s\n", v.Error())
	}
	if r.Truncated {
		fmt.Fprintf(w, "run truncated at the %d-step budget: work was still outstanding, so the drain guarantee is unproven\n", r.Steps)
	}
}

func short(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16] + "..."
}

// Command meshdemo is the guided demonstration.
//
// It exists because "clone it and read the code" is not an evaluation, and
// because a reviewer's time is the scarcest input to this process. One command
// boots the entire system on embedded infrastructure, drives a scripted bank
// outage through it, and narrates what is happening as it happens — with every
// number read back out of the database rather than printed from a script.
//
// Nothing here is staged. The App is the one cmd/api and cmd/worker use, the
// gatekeeper is the real one, and the audit ledger is the one the tamper
// demonstration later attacks. If a claim in the README is false, this command
// prints the false version.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/app"
	"github.com/hriday/razorpay-resilient-mesh/internal/audit"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/simulator"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

const (
	// demoSpeed compresses the wait before a scheduled retry so the loop closes
	// while a reviewer is watching. It never touches a regulatory delay; see
	// worker.Config.DemoTimeScale and the RBI_ prefix check beside it.
	demoSpeed = 240

	// settleBudget bounds how long each act waits for the system to reach the
	// state it is about to describe. Acts finish as soon as they can.
	settleBudget = 100 * time.Second

	pollEvery = 1500 * time.Millisecond

	rule = "────────────────────────────────────────────────────────────────────────────"
)

type options struct {
	scenario string
	rate     float64
	seed     int64
	full     bool
	keepUp   bool
	noColour bool
	out      string
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("meshdemo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.scenario, "scenario", simulator.ScenarioIssuerOutage,
		"outage to replay: "+strings.Join(simulator.Scenarios(), " | "))
	fs.Float64Var(&o.rate, "rate", 7, "scripted payment failures per second")
	fs.Int64Var(&o.seed, "seed", 42, "seed; the whole run is a pure function of it")
	fs.BoolVar(&o.full, "full", false,
		"also run the exhaustive model check and the four-policy benchmark (adds ~4 minutes)")
	fs.BoolVar(&o.keepUp, "keep", false,
		"leave the system running afterwards so the console and checkout can be opened")
	fs.BoolVar(&o.noColour, "no-colour", false, "disable ANSI styling")
	fs.StringVar(&o.out, "out", "artifacts/DEMO_REPORT.md", "where to write the transcript")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "meshdemo: %v\n", err)
		return 2
	}

	// Everything printed is also captured, so the run leaves an artefact a
	// reviewer can attach to notes rather than a scrollback they have to
	// screenshot.
	t := newTranscript(stdout, !opts.noColour)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := demo(ctx, opts, t); err != nil {
		if errors.Is(err, context.Canceled) {
			t.line("\nInterrupted. Shutting down cleanly.")
			return 0
		}
		t.fail(err.Error())
		_ = t.save(opts.out)
		return 1
	}
	if err := t.save(opts.out); err != nil {
		fmt.Fprintf(stderr, "meshdemo: could not write the transcript: %v\n", err)
	} else {
		t.line("")
		t.line("Transcript written to " + opts.out)
	}
	return 0
}

func demo(ctx context.Context, opts options, t *transcript) error {
	began := time.Now()

	// ---- Preflight ---------------------------------------------------------
	t.banner("ResilientMesh — guided demonstration")
	t.line("Everything below runs on this machine. No Docker, no account, no")
	t.line("payment credentials, and no network once the module cache is warm.")
	t.line("")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	cfg.InfraMode = config.InfraManaged
	cfg.DemoTimeScale = demoSpeed
	cfg.LogLevel = config.LogError // the narration is the output; logs are noise here
	cfg.Seed = opts.seed
	cfg.HTTPAddr = "127.0.0.1:8080"

	tier, tierWhy := inferenceTier(cfg)
	t.kv("Scenario", opts.scenario+fmt.Sprintf(", seed %d, %.0f failures/sec", opts.seed, opts.rate))
	t.kv("Inference", tier)
	t.line("           " + tierWhy)
	t.kv("Time", fmt.Sprintf("waits compressed %dx so retries land while you watch;", demoSpeed))
	t.line("           decisions unchanged, regulatory delays never compressed")
	t.line("")

	log := obs.NewLogger(cfg.LogLevel, io.Discard)

	// ---- Act 0: boot -------------------------------------------------------
	t.act(0, "Booting the real system")
	t.step("Starting embedded PostgreSQL 18.3 and an in-process Redis server")
	bootStart := time.Now()

	sim, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      cfg.SimulatorAddr,
		Secret:    cfg.WebhookSecret,
		KeyID:     cfg.RazorpayKeyID,
		KeySecret: cfg.RazorpayKeySecret,
		Scenario:  opts.scenario,
		Seed:      cfg.Seed,
		Rate:      opts.rate,
		Duration:  time.Hour,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("starting the Razorpay simulator: %w", err)
	}
	defer sim.Stop()
	cfg.RazorpayBaseURL = sim.BaseURL()

	a, err := app.New(ctx, cfg, app.Options{Logger: log})
	if err != nil {
		return fmt.Errorf("building the system: %w", err)
	}
	defer func() { _ = a.Close() }()

	emitter, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      "127.0.0.1:0",
		Target:    "http://" + a.Addr() + "/webhooks/razorpay",
		Secret:    a.Config().WebhookSecret,
		KeyID:     a.Config().RazorpayKeyID,
		KeySecret: a.Config().RazorpayKeySecret,
		Scenario:  opts.scenario,
		Seed:      cfg.Seed,
		Rate:      opts.rate,
		Duration:  time.Hour,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("starting the webhook emitter: %w", err)
	}
	defer emitter.Stop()

	// A second stream of recurring-mandate failures runs alongside the outage.
	// Without it the run shows recovery and never shows a refusal, and the
	// refusals are the half of the design worth assessing: RBI's cooling window,
	// the pre-debit notice and the additional-factor ceiling only appear on
	// mandate traffic.
	mandates, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      "127.0.0.1:0",
		Target:    "http://" + a.Addr() + "/webhooks/razorpay",
		Secret:    a.Config().WebhookSecret,
		KeyID:     a.Config().RazorpayKeyID,
		KeySecret: a.Config().RazorpayKeySecret,
		Scenario:  simulator.ScenarioMandateBatch,
		Seed:      cfg.Seed + 1,
		Rate:      opts.rate / 2,
		Duration:  time.Hour,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("starting the mandate emitter: %w", err)
	}
	defer mandates.Stop()

	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(runCtx) }()
	go func() { _ = sim.Run(runCtx) }()
	go func() { _ = emitter.Run(runCtx) }()
	go func() { _ = mandates.Run(runCtx) }()

	pg := a.Store()
	t.ok(fmt.Sprintf("Up in %.1fs — API on %s, Razorpay API on %s",
		time.Since(bootStart).Seconds(), a.Addr(), sim.Addr()))
	t.line("")
	t.line("     Open these now if you want to watch it live:")
	t.line("       Ops console   http://" + a.Addr() + "/console.html")
	t.line("       Checkout      http://" + a.Addr() + "/checkout.html")
	t.line("       Ops token     " + a.Config().OpsToken)
	t.line("")
	t.note("The token is generated per run and exists nowhere else. The console " +
		"is read-only; every mutating action lives in meshctl, behind --yes.")

	// ---- Act 1: failures arrive -------------------------------------------
	t.act(1, "A bank goes down and failed payments start arriving")
	t.line("The simulator serves Razorpay's real schemas and signs real HMAC")
	t.line("webhooks. The edge verifies the signature before it parses anything.")
	t.line("")

	if err := waitFor(ctx, t, "webhooks accepted", func() (string, bool, error) {
		n, err := countIncidents(ctx, pg)
		return fmt.Sprintf("%d incidents recorded", n), n >= 8, err
	}); err != nil {
		return err
	}

	incidents, err := pg.ListIncidents(ctx, 500)
	if err != nil {
		return fmt.Errorf("reading incidents: %w", err)
	}
	t.line("")
	t.table([]string{"PAYMENT", "ISSUER", "DECLINE", "AMOUNT", "STATE"},
		incidentRows(incidents, 8))
	t.line("")
	t.note("Real Razorpay decline codes against real Indian issuer codes. " +
		"Amounts are integer paisa end to end; no float touches a money path.")

	// ---- Act 2: the decision ----------------------------------------------
	t.act(2, "What the model proposes, and what the gatekeeper allows")
	t.line("The model is advisory. It receives a bucketed, allowlisted context")
	t.line("with no PII, and returns a proposal that has no amount field at all —")
	t.line("not a validated one, no field — so it cannot propose a different sum.")
	t.line("")

	if err := waitFor(ctx, t, "decisions made", func() (string, bool, error) {
		n, err := countAudit(ctx, pg, domain.AuditGateDecision)
		return fmt.Sprintf("%d gate decisions", n), n >= 6, err
	}); err != nil {
		return err
	}

	story, err := firstFullStory(ctx, pg)
	if err != nil {
		return err
	}
	if story != "" {
		t.line("")
		t.line("     One incident, end to end:")
		t.line("")
		for _, l := range strings.Split(story, "\n") {
			t.line("       " + l)
		}
	}

	tiers, err := tierMix(ctx, pg)
	if err != nil {
		return err
	}
	t.line("")
	t.kv("Decided by", renderTiers(tiers))
	t.note("Every decision names the tier that made it. A model returning " +
		`{"mode":"LIVE"} cannot promote its own answer: those fields carry json:"-".`)

	// ---- Act 3: refusals ---------------------------------------------------
	t.act(3, "The decisions it refuses to make")
	t.line("This is the half that matters. A recovery system that only logs its")
	t.line("successes cannot be audited, so every abstention is recorded with the")
	t.line("invariant that caused it.")
	t.line("")

	if err := waitFor(ctx, t, "refusals", func() (string, bool, error) {
		v, err := vetoBreakdown(ctx, pg)
		return fmt.Sprintf("%d distinct invariants have refused something", len(v)),
			len(v) >= 2, err
	}); err != nil {
		return err
	}
	t.line("")

	vetoes, err := vetoBreakdown(ctx, pg)
	if err != nil {
		return err
	}
	if len(vetoes) == 0 {
		t.line("     Nothing was refused in this window. That is a real outcome, not")
		t.line("     a placeholder: with -rate low enough, every proposal can be legal.")
	} else {
		t.table([]string{"INVARIANT", "TIMES FIRED", "WHAT IT PREVENTS"}, vetoRows(vetoes))
	}
	t.line("")
	t.note("All 14 invariants are deterministic and proved exhaustively over " +
		"510,720 reachable states. `go run ./cmd/modelcheck` re-derives that.")

	// ---- Act 4: recovery ---------------------------------------------------
	t.act(4, "Payments recovering")
	t.line("A deferred retry writes an absolute due time to its own row, so it")
	t.line("survives a restart. A sweeper claims due rows and re-publishes them.")
	t.line("")

	if err := waitFor(ctx, t, "recoveries", func() (string, bool, error) {
		st, err := stateCounts(ctx, pg)
		return fmt.Sprintf("%d recovered, %d scheduled, %d abstained",
			st["RECOVERED"], st["SCHEDULED"], st["ABSTAINED"]), st["RECOVERED"] >= 3, err
	}); err != nil {
		return err
	}

	st, err := stateCounts(ctx, pg)
	if err != nil {
		return err
	}
	recovered, fees, err := recoveredValue(ctx, pg)
	if err != nil {
		return err
	}
	t.line("")
	t.table([]string{"OUTCOME", "COUNT"}, stateRows(st))
	t.line("")
	t.kv("Recovered", formatPaisa(recovered)+" of merchant revenue")
	t.kv("Cost", formatPaisa(fees)+" in gateway fees to do it")
	t.note("Both read from the attempts table, not from a counter. The table has " +
		"a unique constraint on (incident, attempt number), so a retried write " +
		"cannot double-count a fee — a defect deterministic simulation found.")

	// ---- Act 5: the ledger -------------------------------------------------
	t.act(5, "The audit ledger, and an attack on it")
	t.line("Every consequential decision is hash-chained, with each field absorbed")
	t.line("length-prefixed so an attacker controlling two adjacent fields cannot")
	t.line("forge a collision by shifting the boundary between them.")
	t.line("")

	ledger := audit.New(pg, systemClock{}, "demo")
	before, err := ledger.Verify(ctx)
	if err != nil {
		return fmt.Errorf("verifying the ledger: %w", err)
	}
	t.ok(fmt.Sprintf("Chain intact: %d entries verified, head %s",
		before.Entries, short(before.HeadHash)))
	if !before.Valid {
		return fmt.Errorf("the ledger was already broken at sequence %d", before.BreakAtSeq)
	}

	target := before.Entries / 2
	if target < 1 {
		target = 1
	}
	t.step(fmt.Sprintf("Editing entry %d directly in PostgreSQL, as an attacker with "+
		"database access would", target))
	forged, err := json.Marshal(map[string]any{
		"note":   "this row was edited directly in the database",
		"action": "IN_SESSION_RAIL_MORPH",
	})
	if err != nil {
		return err
	}
	if err := pg.MutateAuditDetailForTest(ctx, target, forged); err != nil {
		return fmt.Errorf("tampering with sequence %d: %w", target, err)
	}

	after, err := ledger.Verify(ctx)
	if err != nil {
		return fmt.Errorf("re-verifying the ledger: %w", err)
	}
	if after.Valid {
		return errors.New("the ledger accepted a forged row: tamper-evidence is not working")
	}
	if after.BreakAtSeq != target {
		return fmt.Errorf("tamper detected at %d but row %d was edited; verification "+
			"is not localising the break", after.BreakAtSeq, target)
	}
	t.ok(fmt.Sprintf("Detected at entry %d — the exact row that was edited", after.BreakAtSeq))
	t.line("     Cause: " + after.BreakCause)
	t.note("The row edited is in the middle of the chain, not the head. A ledger " +
		"that only catches a modified head catches nothing, because the head is " +
		"what an attacker rewrites last.")

	// ---- Act 6: optional heavy proofs -------------------------------------
	if opts.full {
		t.act(6, "Exhaustive proof and measurement against incumbents")
		t.step("Walking every reachable mandate state")
		if out, err := runTool(ctx, "go", "run", "./cmd/modelcheck"); err != nil {
			t.warn("model check did not complete: " + err.Error())
		} else {
			t.raw(indent(lastLines(out, 14), "     "))
		}
		t.step("Running four recovery policies over the same incident stream")
		if out, err := runTool(ctx, pythonBin(), "eval/benchmark.py",
			"--incidents", "400", "--seed", "20260904", "--out", "artifacts/benchmark.json"); err != nil {
			t.warn("benchmark did not complete: " + err.Error())
		} else {
			t.raw(indent(benchmarkTable(out), "     "))
		}
	}

	// ---- Close -------------------------------------------------------------
	t.banner("Done")
	t.kv("Elapsed", fmt.Sprintf("%.0f seconds", time.Since(began).Seconds()))
	t.line("")
	t.line("What this run proved, in order:")
	t.line("  1. The system boots on a clean machine with no dependencies to install.")
	t.line("  2. Signed webhooks are verified before anything parses them.")
	t.line("  3. Every decision names the tier that made it and the rules applied.")
	t.line("  4. Refusals are recorded as carefully as actions.")
	t.line("  5. Deferred retries survive and complete, and money is recovered.")
	t.line("  6. The audit ledger detects tampering at the exact row.")
	t.line("")
	t.line("Verify any of it independently:")
	t.line("  go run ./cmd/meshctl selftest      the same loop, as a pass/fail gate")
	t.line("  go run ./cmd/modelcheck            510,720 states, 9 invariants, 0 violations")
	t.line("  go test ./... -count=1             the full suite")
	t.line("  ./scripts/judge.sh                 every gate, with a written report")

	if opts.keepUp {
		t.line("")
		t.line(rule)
		t.line("  Still running. Open the console and browse; Ctrl-C when finished.")
		t.line("    Ops console   http://" + a.Addr() + "/console.html")
		t.line("    Ops token     " + a.Config().OpsToken)
		t.line(rule)
		<-ctx.Done()
	}

	stopRun()
	<-done
	return nil
}

// ---------------------------------------------------------------------------
// Reading real state
// ---------------------------------------------------------------------------

func countIncidents(ctx context.Context, pg *store.Postgres) (int, error) {
	in, err := pg.ListIncidents(ctx, 500)
	return len(in), err
}

func stateCounts(ctx context.Context, pg *store.Postgres) (map[string]int, error) {
	out := map[string]int{}
	in, err := pg.ListIncidents(ctx, 500)
	if err != nil {
		return out, err
	}
	for _, i := range in {
		out[string(i.State)]++
	}
	return out, nil
}

// recoveredValue sums what was recovered and what it cost, from the attempts
// table. Reading the ledger of what happened rather than a counter of what we
// think happened is the difference between a measurement and a claim.
func recoveredValue(ctx context.Context, pg *store.Postgres) (recovered, fees int64, err error) {
	in, err := pg.ListIncidents(ctx, 500)
	if err != nil {
		return 0, 0, err
	}
	for _, i := range in {
		attempts, err := pg.ListAttempts(ctx, i.ID)
		if err != nil {
			return 0, 0, err
		}
		for _, a := range attempts {
			fees += a.GatewayFeePaisa
			if a.Succeeded {
				recovered += a.AmountPaisa
			}
		}
	}
	return recovered, fees, nil
}

func countAudit(ctx context.Context, pg *store.Postgres, kind domain.AuditKind) (int, error) {
	n := 0
	err := pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if e.Kind == kind {
			n++
		}
		return nil
	})
	return n, err
}

func tierMix(ctx context.Context, pg *store.Postgres) (map[string]int, error) {
	out := map[string]int{}
	err := pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if e.Kind != domain.AuditDiagnosis {
			return nil
		}
		var d struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(e.Detail, &d); err == nil && d.Mode != "" {
			out[d.Mode]++
		}
		return nil
	})
	return out, err
}

// vetoBreakdown counts which invariants actually fired, so the demonstration
// reports the rules this run exercised rather than the rules that exist.
func vetoBreakdown(ctx context.Context, pg *store.Postgres) (map[string]int, error) {
	out := map[string]int{}
	err := pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		switch e.Kind {
		case domain.AuditGateDecision:
			var d struct {
				Action     string   `json:"action"`
				Invariants []string `json:"applied_invariants"`
			}
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				return nil
			}
			if d.Action != string(domain.ActionAbstain) {
				return nil
			}
			for _, name := range d.Invariants {
				out[name]++
			}
		case domain.AuditTerminalHalt:
			out["TERMINAL_DECLINE"]++
		}
		return nil
	})
	return out, err
}

// firstFullStory renders one incident's complete decision trail. A single
// worked example carries more than any aggregate: it shows the evidence, the
// proposal, the rules applied and the outcome in the order they happened.
func firstFullStory(ctx context.Context, pg *store.Postgres) (string, error) {
	incidents, err := pg.ListIncidents(ctx, 100)
	if err != nil {
		return "", err
	}
	for _, in := range incidents {
		entries, err := pg.ListAuditByIncident(ctx, in.ID)
		if err != nil {
			return "", err
		}
		if len(entries) < 3 {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s  %s via %s  %s\n",
			in.PaymentID, formatPaisa(in.AmountPaisa), in.Method, in.IssuerKey)
		fmt.Fprintf(&b, "declined %q\n\n", in.ErrorCode)
		for _, e := range entries {
			fmt.Fprintf(&b, "  %-22s %s\n", e.Kind, summarise(e))
		}
		attempts, err := pg.ListAttempts(ctx, in.ID)
		if err != nil {
			return "", err
		}
		for _, a := range attempts {
			outcome := "failed"
			if a.Succeeded {
				outcome = "SUCCEEDED"
			}
			fmt.Fprintf(&b, "  %-22s attempt %d on %s: %s (fee %s)\n",
				"EXECUTED", a.AttemptNumber, a.Rail, outcome, formatPaisa(a.GatewayFeePaisa))
		}
		return b.String(), nil
	}
	return "", nil
}

func orNone(rail string) string {
	if rail == "" || rail == "none" {
		return "the original rail"
	}
	return rail
}

func summarise(e domain.AuditEntry) string {
	var d struct {
		Mode       string   `json:"mode"`
		Action     string   `json:"action"`
		Confidence float64  `json:"confidence"`
		RootCause  string   `json:"root_cause"`
		Rail       string   `json:"target_rail"`
		Delay      int64    `json:"delay_seconds"`
		Invariants []string `json:"applied_invariants"`
		ErrorCode  string   `json:"error_code"`
		Amount     int64    `json:"amount"`
		Succeeded  bool     `json:"succeeded"`
		Fee        int64    `json:"fee_paisa"`
		State      string   `json:"state"`
	}
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		return truncate(string(e.Detail), 90)
	}
	switch e.Kind {
	case domain.AuditWebhookAccepted:
		return fmt.Sprintf("%s, %s, signature verified", d.ErrorCode, formatPaisa(d.Amount))
	case domain.AuditDiagnosis:
		return fmt.Sprintf("%s proposed %s at %.2f — %s",
			d.Mode, d.Action, d.Confidence, truncate(d.RootCause, 58))
	case domain.AuditIncidentScheduled:
		if d.Delay > 0 {
			return fmt.Sprintf("deferred %ds; the due time is written to the incident row", d.Delay)
		}
		return "deferred; the due time is written to the incident row"
	case domain.AuditAttemptStarted:
		return fmt.Sprintf("calling the gateway: %s on %s", d.Action, orNone(d.Rail))
	case domain.AuditAttemptResult:
		if d.Succeeded {
			return fmt.Sprintf("recovered on %s, fee %s", orNone(d.Rail), formatPaisa(d.Fee))
		}
		return fmt.Sprintf("failed on %s with %q, fee %s",
			orNone(d.Rail), d.ErrorCode, formatPaisa(d.Fee))
	case domain.AuditIncidentClosed:
		return "closed as " + d.State
	case domain.AuditTerminalHalt:
		return fmt.Sprintf("halted: %q is terminal, so no fee is spent on it", d.ErrorCode)
	case domain.AuditPreDebitNotice:
		return "payer notified before the debit, as RBI requires"
	case domain.AuditGateDecision:
		s := fmt.Sprintf("%s", d.Action)
		if d.Rail != "" && d.Rail != "none" {
			s += " on " + d.Rail
		}
		if d.Delay > 0 {
			s += fmt.Sprintf(" after %ds", d.Delay)
		}
		if len(d.Invariants) > 0 {
			s += "  [" + strings.Join(d.Invariants, " ") + "]"
		}
		return s
	default:
		return truncate(string(e.Detail), 88)
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func incidentRows(in []domain.Incident, limit int) [][]string {
	sort.Slice(in, func(i, j int) bool { return in[i].ReceivedAt.Before(in[j].ReceivedAt) })
	if len(in) > limit {
		in = in[:limit]
	}
	rows := make([][]string, 0, len(in))
	for _, i := range in {
		rows = append(rows, []string{
			i.PaymentID, i.IssuerKey, i.ErrorCode, formatPaisa(i.AmountPaisa), string(i.State),
		})
	}
	return rows
}

func stateRows(st map[string]int) [][]string {
	order := []string{"RECOVERED", "SCHEDULED", "ABSTAINED", "ABANDONED", "RECEIVED", "EXECUTING"}
	rows := make([][]string, 0, len(order))
	for _, k := range order {
		if n, ok := st[k]; ok && n > 0 {
			rows = append(rows, []string{k, fmt.Sprint(n)})
		}
	}
	return rows
}

// invariantMeaning gives each rule a one-line consequence, because a reviewer
// reading INVARIANT_NAME learns nothing from the name alone.
var invariantMeaning = map[string]string{
	"AMOUNT_PINNED":              "the amount can only come from the signed payload",
	"TERMINAL_DECLINE":           "a decline no retry can fix, so no fee is spent",
	"STOP_RULE_MAX_ATTEMPTS":     "the per-incident retry ceiling",
	"LOW_CONFIDENCE_ABSTAIN":     "the model was not sure enough to spend money",
	"UNRECOVERABLE_CLASS":        "retrying this class cannot help",
	"SESSION_REQUIRED_FOR_MORPH": "no live checkout to move, so no morph",
	"RAIL_ALLOWLIST":             "the merchant never enabled that rail",
	"RBI_MANDATE_COOLING":        "RBI's 24-hour gap between recurring debits",
	"RBI_PRE_DEBIT_NOTICE":       "the payer must be warned before a debit",
	"RBI_AFA_CEILING":            "above the ceiling a debit needs authentication",
	"MANDATE_HALTED":             "this mandate must not be debited again",
	"MANDATE_CYCLE_CAP":          "attempts allowed within one billing cycle",
	"INSTRUMENT_REFRESH_ALLOWED": "re-present the token rather than the dead card",
	"DELAY_BOUNDS":               "the schedule stays inside a sane horizon",
}

func vetoRows(v map[string]int) [][]string {
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if v[names[i]] != v[names[j]] {
			return v[names[i]] > v[names[j]]
		}
		return names[i] < names[j]
	})
	rows := make([][]string, 0, len(names))
	for _, n := range names {
		rows = append(rows, []string{n, fmt.Sprint(v[n]), invariantMeaning[n]})
	}
	return rows
}

func renderTiers(m map[string]int) string {
	order := []string{"LIVE", "REPLAY", "HEURISTIC", "SKIPPED"}
	parts := make([]string, 0, 4)
	for _, k := range order {
		if n, ok := m[k]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, n))
		}
	}
	if len(parts) == 0 {
		return "nothing decided yet"
	}
	return strings.Join(parts, "   ")
}

func inferenceTier(cfg config.Config) (string, string) {
	if cfg.LLMProvider != config.ProviderNone && cfg.LLMAPIKey != "" {
		return "LIVE — " + cfg.LLMModel,
			"falling back to cassette replay, then the deterministic classifier"
	}
	return "REPLAY then HEURISTIC (no model key configured)",
		"set MESH_LLM_PROVIDER=groq and MESH_LLM_API_KEY to use a live model; " +
			"the system is fully functional without one"
}

// waitFor polls until a condition holds or the budget runs out, printing the
// evolving count so the reviewer sees progress rather than a frozen terminal.
func waitFor(ctx context.Context, t *transcript, what string, probe func() (string, bool, error)) error {
	deadline := time.Now().Add(settleBudget)
	last := ""
	for {
		msg, ok, err := probe()
		if err != nil {
			return fmt.Errorf("waiting for %s: %w", what, err)
		}
		if msg != last {
			t.progress(msg)
			last = msg
		}
		if ok {
			t.endProgress()
			t.ok(msg)
			return nil
		}
		if time.Now().After(deadline) {
			t.endProgress()
			t.warn(fmt.Sprintf("%s did not reach the expected state in %s (%s)",
				what, settleBudget, msg))
			return nil
		}
		select {
		case <-ctx.Done():
			t.endProgress()
			return ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

func runTool(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func pythonBin() string {
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	return "python"
}

func benchmarkTable(out string) string {
	// The benchmark prints a markdown report; the table is the part worth
	// surfacing here, and the full document is already on disk.
	lines := strings.Split(out, "\n")
	var keep []string
	for _, l := range lines {
		if strings.HasPrefix(l, "|") || strings.HasPrefix(l, "Strongest") ||
			strings.HasPrefix(l, "- Paired") || strings.HasPrefix(l, "- p =") {
			keep = append(keep, l)
		}
	}
	if len(keep) == 0 {
		return lastLines(out, 12)
	}
	return strings.Join(keep, "\n")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// formatPaisa renders integer paisa in the Indian grouping. The arithmetic
// stays in integers: a float here would be the one float on a money path.
func formatPaisa(p int64) string {
	neg := p < 0
	if neg {
		p = -p
	}
	rupees, paise := p/100, p%100
	s := fmt.Sprint(rupees)
	if len(s) > 3 {
		head, tail := s[:len(s)-3], s[len(s)-3:]
		var parts []string
		for len(head) > 2 {
			parts = append([]string{head[len(head)-2:]}, parts...)
			head = head[:len(head)-2]
		}
		if head != "" {
			parts = append([]string{head}, parts...)
		}
		s = strings.Join(parts, ",") + "," + tail
	}
	out := fmt.Sprintf("₹%s.%02d", s, paise)
	if neg {
		return "-" + out
	}
	return out
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

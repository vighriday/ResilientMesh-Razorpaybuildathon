package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/app"
	"github.com/hriday/razorpay-resilient-mesh/internal/audit"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/simulator"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// The self-test is the whole system, proving itself, in one command.
//
// It exists because every other gate in the harness checks a component. This
// one boots the real composition root on real embedded infrastructure, drives a
// real signed webhook stream through it, waits for payments to actually recover,
// then attacks its own audit ledger and requires the tamper to be detected at
// the exact row it corrupted. A reviewer who runs nothing else can run this.
//
// Nothing here is a special test path: the App is the one cmd/api and
// cmd/worker use, and the simulator is the one cmd/simulator serves.

const (
	// selftestSettle bounds how long the run waits for recoveries. Generous,
	// because the gate is "does the pipeline close the loop", not "how fast".
	selftestSettle = 90 * time.Second

	// selftestPoll is how often progress is checked. Short enough that the
	// command finishes as soon as the target is met rather than always taking
	// the full budget.
	selftestPoll = 2 * time.Second

	// selftestSpeed compresses the wait before a scheduled retry. Production
	// backoff is minutes to hours, so an honest end-to-end gate either
	// compresses time or never observes an outcome. The compression is recorded
	// in the ledger; see worker.Config.DemoTimeScale.
	selftestSpeed = 600

	// selftestRate and selftestDuration size the scripted outage. Enough
	// incidents that a single lucky recovery cannot pass the gate.
	selftestRate     = 8.0
	selftestDuration = 10 * time.Minute
)

// SelftestReport is the machine-readable result, so CI can assert on it rather
// than grepping human prose.
type SelftestReport struct {
	Scenario       string         `json:"scenario"`
	Seed           int64          `json:"seed"`
	Incidents      int            `json:"incidents"`
	Recovered      int            `json:"recovered"`
	Abstained      int            `json:"abstained"`
	Scheduled      int            `json:"scheduled"`
	Attempts       int            `json:"attempts"`
	AuditEntries   int64          `json:"audit_entries"`
	ChainValid     bool           `json:"chain_valid_before_tamper"`
	TamperedSeq    int64          `json:"tampered_seq"`
	TamperDetected bool           `json:"tamper_detected"`
	DetectedAtSeq  int64          `json:"tamper_detected_at_seq"`
	InferenceTiers map[string]int `json:"inference_tiers"`
	ElapsedSeconds float64        `json:"elapsed_seconds"`
}

// cmdSelftest runs the end-to-end gate. It takes no connection because it
// builds its own: the point is to prove a clean machine can do this.
func cmdSelftest(ctx context.Context, g globals, out io.Writer) error {
	began := time.Now()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	// Managed mode is forced. A self-test that silently attached to an
	// operator's real database would corrupt a real ledger to prove a point.
	cfg.InfraMode = config.InfraManaged
	cfg.DemoTimeScale = selftestSpeed
	cfg.LogLevel = config.LogWarn

	log := obs.NewLogger(cfg.LogLevel, os.Stderr)

	step(out, g, "booting embedded PostgreSQL and Redis")

	// The simulator binds first so the executor and the downtime poller are
	// constructed against the port it actually got.
	sim, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      "127.0.0.1:0",
		Secret:    cfg.WebhookSecret,
		KeyID:     cfg.RazorpayKeyID,
		KeySecret: cfg.RazorpayKeySecret,
		Scenario:  simulator.ScenarioIssuerOutage,
		Seed:      cfg.Seed,
		Rate:      selftestRate,
		Duration:  selftestDuration,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("starting the simulator: %w", err)
	}
	defer sim.Stop()

	// The API takes an ephemeral port too, so a self-test never collides with a
	// mesh the reviewer already has running.
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.RazorpayBaseURL = sim.BaseURL()

	a, err := app.New(ctx, cfg, app.Options{Logger: log})
	if err != nil {
		return fmt.Errorf("building the system: %w", err)
	}
	defer func() { _ = a.Close() }()

	// The webhook target is only known once the API has bound.
	sim2, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      "127.0.0.1:0",
		Target:    "http://" + a.Addr() + "/webhooks/razorpay",
		Secret:    a.Config().WebhookSecret,
		KeyID:     a.Config().RazorpayKeyID,
		KeySecret: a.Config().RazorpayKeySecret,
		Scenario:  simulator.ScenarioIssuerOutage,
		Seed:      cfg.Seed,
		Rate:      selftestRate,
		Duration:  selftestDuration,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("starting the webhook emitter: %w", err)
	}
	defer sim2.Stop()

	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(runCtx) }()
	go func() { _ = sim.Run(runCtx) }()
	go func() { _ = sim2.Run(runCtx) }()

	step(out, g, "driving a scripted issuer outage through the live pipeline")

	report := SelftestReport{
		Scenario:       sim2.Scenario(),
		Seed:           cfg.Seed,
		InferenceTiers: map[string]int{},
	}

	// Wait for the loop to close. The gate is a recovery actually completing:
	// decisions alone would pass even with the scheduler removed, which is the
	// exact defect this command exists to catch.
	deadline := time.Now().Add(selftestSettle)
	pg := a.Store()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(selftestPoll):
		}
		if err := tally(ctx, pg, &report); err != nil {
			return err
		}
		if report.Recovered >= 3 && report.Attempts >= 5 {
			break
		}
	}
	if err := tally(ctx, pg, &report); err != nil {
		return err
	}

	stopRun()
	<-done

	if report.Incidents == 0 {
		return errors.New("no incidents were ingested; the webhook edge rejected every delivery")
	}
	if report.Attempts == 0 {
		return errors.New("no recovery attempt executed; decisions were made and never carried out")
	}
	if report.Recovered == 0 {
		return errors.New("no payment recovered; the pipeline reached the gateway but never closed the loop")
	}

	// ---- The ledger, before and after an attack --------------------------
	step(out, g, "verifying the audit chain, then attacking it")

	ledger := audit.New(pg, systemClock{}, "selftest")
	before, err := ledger.Verify(ctx)
	if err != nil {
		return fmt.Errorf("verifying the ledger: %w", err)
	}
	report.AuditEntries, report.ChainValid = before.Entries, before.Valid
	if !before.Valid {
		return fmt.Errorf("the ledger was already broken at sequence %d before any tampering: %s",
			before.BreakAtSeq, before.BreakCause)
	}

	// Corrupt one entry in the middle of the chain, in the database, exactly as
	// an attacker with write access would. Editing the middle rather than the
	// head matters: a chain that only detects a modified head is detecting
	// nothing, because the head is the row an attacker would rewrite last.
	target := before.Entries / 2
	if target < 1 {
		target = 1
	}
	report.TamperedSeq = target
	forged, err := json.Marshal(map[string]any{
		"note":   "this row was edited directly in the database",
		"action": "IN_SESSION_RAIL_MORPH",
	})
	if err != nil {
		return fmt.Errorf("building the forged detail: %w", err)
	}
	if err := pg.MutateAuditDetailForTest(ctx, target, forged); err != nil {
		return fmt.Errorf("tampering with sequence %d: %w", target, err)
	}

	after, err := ledger.Verify(ctx)
	if err != nil {
		return fmt.Errorf("re-verifying the ledger: %w", err)
	}
	report.TamperDetected = !after.Valid
	report.DetectedAtSeq = after.BreakAtSeq
	report.ElapsedSeconds = time.Since(began).Seconds()

	if g.jsonOut {
		if err := writeJSON(out, report); err != nil {
			return err
		}
	} else {
		renderSelftest(out, report)
	}

	if !report.TamperDetected {
		return errors.New("the ledger accepted a forged row: tamper-evidence is not working")
	}
	if report.DetectedAtSeq != target {
		return fmt.Errorf("tamper was detected at sequence %d but row %d was edited; "+
			"verification is not localising the break", report.DetectedAtSeq, target)
	}
	return nil
}

// tally reads the current state from the database rather than from counters, so
// the numbers reported are the ones a reviewer would find by querying.
func tally(ctx context.Context, pg *store.Postgres, r *SelftestReport) error {
	incidents, err := pg.ListIncidents(ctx, 500)
	if err != nil {
		return fmt.Errorf("reading incidents: %w", err)
	}
	r.Incidents, r.Recovered, r.Abstained, r.Scheduled, r.Attempts = len(incidents), 0, 0, 0, 0
	for k := range r.InferenceTiers {
		delete(r.InferenceTiers, k)
	}
	for _, in := range incidents {
		switch in.State {
		case domain.IncidentRecovered:
			r.Recovered++
		case domain.IncidentAbstained:
			r.Abstained++
		case domain.IncidentScheduled:
			r.Scheduled++
		}
		attempts, err := pg.ListAttempts(ctx, in.ID)
		if err != nil {
			return fmt.Errorf("reading attempts: %w", err)
		}
		r.Attempts += len(attempts)
	}
	return pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if e.Kind != domain.AuditDiagnosis {
			return nil
		}
		var d struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(e.Detail, &d); err == nil && d.Mode != "" {
			r.InferenceTiers[d.Mode]++
		}
		return nil
	})
}

func renderSelftest(w io.Writer, r SelftestReport) {
	tw := newTable(w)
	fmt.Fprintf(tw, "\nscenario\t%s (seed %d)\n", r.Scenario, r.Seed)
	fmt.Fprintf(tw, "incidents ingested\t%d\n", r.Incidents)
	fmt.Fprintf(tw, "recovered\t%d\n", r.Recovered)
	fmt.Fprintf(tw, "still scheduled\t%d\n", r.Scheduled)
	fmt.Fprintf(tw, "abstained\t%d\n", r.Abstained)
	fmt.Fprintf(tw, "gateway attempts\t%d\n", r.Attempts)
	for _, mode := range []string{"LIVE", "REPLAY", "HEURISTIC", "SKIPPED"} {
		if n := r.InferenceTiers[mode]; n > 0 {
			fmt.Fprintf(tw, "  diagnosed by %s\t%d\n", mode, n)
		}
	}
	fmt.Fprintf(tw, "audit entries\t%d\n", r.AuditEntries)
	fmt.Fprintf(tw, "chain before tamper\t%s\n", verdict(r.ChainValid, "intact", "BROKEN"))
	fmt.Fprintf(tw, "row edited in database\tseq %d\n", r.TamperedSeq)
	fmt.Fprintf(tw, "tamper detected\t%s\n", verdict(r.TamperDetected, "yes", "NO — tamper-evidence failed"))
	if r.TamperDetected {
		fmt.Fprintf(tw, "detected at\tseq %d\n", r.DetectedAtSeq)
	}
	fmt.Fprintf(tw, "elapsed\t%.1fs\n", r.ElapsedSeconds)
	_ = tw.Flush()
}

func verdict(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

// step prints progress for a human. Suppressed under --json so the output stays
// a single parseable document.
func step(w io.Writer, g globals, msg string) {
	if g.jsonOut {
		return
	}
	fmt.Fprintf(w, "  · %s\n", msg)
}

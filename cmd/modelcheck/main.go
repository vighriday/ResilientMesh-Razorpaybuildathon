// Command modelcheck exhaustively explores the abstract mandate state space,
// drives the real gatekeeper at every state, and reports which compliance
// invariants held.
//
// It exists as its own binary because cmd/meshctl does not yet exist. When it
// does, its `verify-model` subcommand should call modelcheck.Run and reuse the
// exit codes below rather than reimplementing the reporting; this main is a
// thin shell over the library for exactly that reason.
//
// Exit codes are the contract CI gates on:
//
//	0  every asserted invariant held at every reachable state
//	1  at least one invariant was violated
//	2  the run could not be completed at all
//	3  the invariants held, but exploration stopped at the state bound, so the
//	   result is a check over a subset rather than a proof over the space
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/modelcheck"
)

const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
	exitBounded   = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("modelcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: modelcheck [flags]\n\n"+
			"Exhaustively explores the abstract mandate/incident state space, driving the real\n"+
			"gatekeeper at every reachable state, and asserts the money and RBI e-mandate\n"+
			"invariants. Exits 1 on any violation, 3 if exploration hit the state bound.\n\n")
		fs.PrintDefaults()
	}

	var (
		asJSON     = fs.Bool("json", false, "emit the full report as JSON instead of a summary")
		maxStates  = fs.Int("max-states", modelcheck.DefaultMaxStates, "bound on distinct states admitted to the frontier")
		witnesses  = fs.Int("witnesses", modelcheck.DefaultMaxWitnesses, "counterexamples recorded per violated invariant")
		maxAttempt = fs.Int("max-attempts", gatekeeper.DefaultMaxAttempts, "gatekeeper retry ceiling to verify against")
		cycleCap   = fs.Int("cycle-cap", gatekeeper.DefaultMandateCycleCap, "gatekeeper per-cycle mandate attempt cap")
		timeout    = fs.Duration("timeout", 5*time.Minute, "abandon the exploration after this long")
	)
	if err := fs.Parse(args); err != nil {
		// flag has already reported the problem to stderr.
		return exitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "modelcheck: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	report, err := modelcheck.RunContext(ctx, modelcheck.Config{
		MaxStates:    *maxStates,
		MaxWitnesses: *witnesses,
		GateConfig: gatekeeper.Config{
			MaxAttempts:     *maxAttempt,
			MandateCycleCap: *cycleCap,
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "modelcheck: %v\n", err)
		return exitError
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "modelcheck: encoding report: %v\n", err)
			return exitError
		}
	} else {
		fmt.Fprint(stdout, summarise(report))
	}

	switch {
	case !report.Passed():
		return exitViolation
	case !report.Complete():
		return exitBounded
	default:
		return exitOK
	}
}

// summarise renders the operator-facing view. It leads with the numbers a
// reviewer needs to judge whether the run proved anything — how much of the
// space was reachable and whether the exploration finished — before the
// per-invariant verdicts.
func summarise(r modelcheck.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "modelcheck: exhaustive state-space verification of internal/gatekeeper\n")
	fmt.Fprintf(&b, "  virtual clock       %s\n", r.ClockAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "  abstract states     %d\n", r.AbstractStates)
	fmt.Fprintf(&b, "  initial states      %d\n", r.InitialStates)
	fmt.Fprintf(&b, "  reachable states    %d\n", r.ReachableStates)
	fmt.Fprintf(&b, "  unreachable states  %d (proved unreachable from a fresh mandate)\n", r.UnreachedStates)
	fmt.Fprintf(&b, "  transitions         %d\n", r.Transitions)
	fmt.Fprintf(&b, "  gate decisions      %d (retry ceiling %d)\n", r.Decisions, r.MaxAttempts)
	fmt.Fprintf(&b, "  attempts in cycle   %v reachable states per count, halted %d\n",
		r.Reachability.AttemptHistogram, r.Reachability.HaltedStates)
	fmt.Fprintf(&b, "  elapsed             %d ms\n", r.ElapsedMS)
	fmt.Fprintf(&b, "  digest              %s\n", r.Digest)
	if r.Bounded {
		fmt.Fprintf(&b, "\n  BOUNDED: %s\n", r.BoundNote)
	}

	fmt.Fprintf(&b, "\ninvariants\n")
	for _, inv := range r.Invariants {
		status := "HOLDS "
		if inv.Violations > 0 {
			status = "FAILED"
		}
		fmt.Fprintf(&b, "  [%s] %-28s %10d checked  %10d violations\n",
			status, inv.Name, inv.Checked, inv.Violations)
	}

	if len(r.Violations) > 0 {
		fmt.Fprintf(&b, "\ncounterexamples (first %d per invariant)\n", modelcheck.DefaultMaxWitnesses)
		for _, v := range r.Violations {
			fmt.Fprintf(&b, "  %s @ state %d\n", v.Invariant, v.State.Key)
			fmt.Fprintf(&b, "    %s\n", v.Detail)
			fmt.Fprintf(&b, "    state:   recurring=%t category=%s amount=%d paisa (ceiling %d) attempts=%d "+
				"hours_since=%d notified=%t halted=%t breaker=%s session=%t proposal=%s proposal_delay=%ds\n",
				v.State.Recurring, v.State.Category, v.State.AmountPaisa, v.State.AFACeilingPaisa,
				v.State.AttemptsInCycle, v.State.HoursSinceLast, v.State.PreDebitNotice, v.State.Halted,
				v.State.Breaker, v.State.SessionLive, v.State.Proposal, v.State.ProposalDelay)
			fmt.Fprintf(&b, "    command: action=%s rail=%s executable=%t amount=%d %s delay=%ds "+
				"attempt=%d/%d pre_debit=%t invariants=%s\n",
				v.Command.Action, v.Command.TargetRail, v.Command.Executable, v.Command.AmountPaisa,
				v.Command.Currency, v.Command.DelaySeconds, v.Command.AttemptNumber, v.Command.MaxAttempts,
				v.Command.PreDebitNeeded, strings.Join(v.Command.AppliedInvariants, ","))
		}
	}

	fmt.Fprintf(&b, "\ntotal violations %d\n", r.TotalViolations)
	return b.String()
}

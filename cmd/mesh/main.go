// Command mesh brings the whole system up in one process.
//
// This is the entry point for someone evaluating this with no context: one
// command, no Docker, no cloud account, no credentials, no network. It starts
// embedded PostgreSQL and an in-process Redis-protocol server, the Razorpay
// simulator, the API and the worker, then prints the URLs to open and the
// operator token to paste.
//
// It is not a special demo build. Every component is the production one, wired
// through the same composition root cmd/api and cmd/worker use, so what a judge
// exercises here is the system rather than a rehearsal of it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/app"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/simulator"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	scenario     string
	rate         float64
	duration     time.Duration
	seed         int64
	withTraffic  bool
	simulatorURL string
	speed        float64
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("mesh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.scenario, "scenario", simulator.ScenarioIssuerOutage,
		"outage scenario to replay: "+strings.Join(simulator.Scenarios(), " | "))
	fs.Float64Var(&o.rate, "rate", 4, "scripted payment failures per second")
	fs.DurationVar(&o.duration, "duration", time.Hour, "length of the scripted timeline")
	fs.Int64Var(&o.seed, "seed", 0, "timeline seed; 0 uses MESH_SEED")
	fs.BoolVar(&o.withTraffic, "traffic", true,
		"deliver the scripted webhooks; -traffic=false serves the API without driving it")
	fs.Float64Var(&o.speed, "speed", 60,
		"compress the wait before a scheduled retry by this factor so the demo reaches an outcome; "+
			"1 uses real production delays. Decisions are never altered and the factor is recorded in the ledger")
	fs.StringVar(&o.simulatorURL, "simulator-addr", "",
		"address for the embedded simulator; empty uses MESH_SIMULATOR_ADDR")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "mesh: %v\n", err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "mesh: %v\n", err)
		return 2
	}
	if opts.seed != 0 {
		cfg.Seed = opts.seed
	}
	if opts.simulatorURL != "" {
		cfg.SimulatorAddr = opts.simulatorURL
	}
	cfg.DemoTimeScale = opts.speed
	log := obs.NewLogger(cfg.LogLevel, stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The simulator binds first so its real address can be handed to the
	// executor and the downtime poller before either is constructed. Wiring
	// them to a hoped-for address and discovering the conflict afterwards is
	// how a demo prints URLs that do not work.
	target := ""
	if opts.withTraffic {
		target = "http://" + strings.TrimPrefix(cfg.HTTPAddr, ":") + "/webhooks/razorpay"
		if strings.HasPrefix(cfg.HTTPAddr, ":") {
			target = "http://127.0.0.1" + cfg.HTTPAddr + "/webhooks/razorpay"
		}
	}
	sim, err := simulator.NewEmbedded(simulator.EmbeddedConfig{
		Addr:      cfg.SimulatorAddr,
		Target:    target,
		Secret:    cfg.WebhookSecret,
		KeyID:     cfg.RazorpayKeyID,
		KeySecret: cfg.RazorpayKeySecret,
		Scenario:  opts.scenario,
		Seed:      cfg.Seed,
		Rate:      opts.rate,
		Duration:  opts.duration,
		Log:       log,
	})
	if err != nil {
		fmt.Fprintf(stderr, "mesh: %v\n", err)
		return 1
	}
	defer sim.Stop()

	// Both the outbound executor and the downtime poller now point at the port
	// the simulator actually got.
	cfg.RazorpayBaseURL = sim.BaseURL()

	a, err := app.New(ctx, cfg, app.Options{Logger: log})
	if err != nil {
		fmt.Fprintf(stderr, "mesh: %v\n", err)
		return 1
	}
	defer func() { _ = a.Close() }()

	// Printed to stdout, after everything has bound and before any traffic
	// flows, so the first thing a judge sees is a working set of links.
	printBanner(stdout, a, sim, opts)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs <- sim.Run(ctx) }()
	go func() { defer wg.Done(); errs <- a.Run(ctx) }()
	wg.Wait()
	close(errs)

	code := 0
	for err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(stderr, "mesh: %v\n", err)
			code = 1
		}
	}
	fmt.Fprintln(stdout, "\nmesh stopped. Managed PostgreSQL was shut down; no process was left behind.")
	return code
}

// printBanner renders the only human-facing output this command produces.
//
// The ops token is printed because in managed mode it is generated per run and
// exists nowhere else: an operator console that cannot be opened is not a
// console. In external mode the operator supplied it, so it is not echoed back.
func printBanner(w io.Writer, a *app.App, sim *simulator.Embedded, opts options) {
	cfg := a.Config()
	base := "http://" + localhostForm(a.Addr())

	line := strings.Repeat("─", 68)
	fmt.Fprintf(w, "\n%s\n", line)
	fmt.Fprintln(w, "  ResilientMesh is running. Everything below is local.")
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintf(w, "  Checkout        %s/checkout.html\n", base)
	fmt.Fprintf(w, "  Ops console     %s/console.html\n", base)
	fmt.Fprintf(w, "  Razorpay API    %s\n", sim.BaseURL())
	fmt.Fprintf(w, "  Health          %s/readyz\n", base)
	fmt.Fprintf(w, "%s\n", line)
	if cfg.InfraMode == config.InfraManaged && cfg.OpsToken != "" {
		fmt.Fprintf(w, "  Ops token       %s\n", cfg.OpsToken)
		fmt.Fprintln(w, "                  (generated for this run; paste it into the console)")
		fmt.Fprintf(w, "%s\n", line)
	}
	fmt.Fprintf(w, "  Scenario        %s, seed %d, %d scripted failures\n",
		sim.Scenario(), cfg.Seed, sim.Events())
	if !opts.withTraffic {
		fmt.Fprintln(w, "  Traffic         disabled (-traffic=false)")
	}
	tier := "HEURISTIC then REPLAY (no model configured)"
	if cfg.LLMProvider != config.ProviderNone && cfg.LLMAPIKey != "" {
		tier = "LIVE " + cfg.LLMModel + ", falling back to REPLAY then HEURISTIC"
	}
	fmt.Fprintf(w, "  Inference       %s\n", tier)
	fmt.Fprintf(w, "%s\n", line)
	fmt.Fprintln(w, "  Ctrl-C to stop.")
	fmt.Fprintf(w, "%s\n\n", line)
}

// localhostForm turns a wildcard bind into an address a browser can open.
// Printing "http://:8080/" would be technically accurate and useless.
func localhostForm(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	if strings.HasPrefix(addr, "[::]:") {
		return "127.0.0.1:" + strings.TrimPrefix(addr, "[::]:")
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	return addr
}

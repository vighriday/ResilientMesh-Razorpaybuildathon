// Command worker runs the recovery pipeline: the queue consumers, the outbox
// relay, the downtime poller and the reclaim loop.
//
// It serves no HTTP. A worker that also answers requests is a worker whose
// recovery latency depends on request load, which is exactly backwards during
// the outage it exists to handle.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hriday/razorpay-resilient-mesh/internal/app"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mesh-worker: %v\n", err)
		return 2
	}
	log := obs.NewLogger(cfg.LogLevel, os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, app.Options{Roles: []app.Role{app.RoleWorker}, Logger: log})
	if err != nil {
		log.Error("could not start", "error", err)
		return 1
	}
	defer func() { _ = a.Close() }()

	log.Info("mesh-worker starting",
		"concurrency", cfg.WorkerConcurrency, "infra_mode", cfg.InfraMode)
	if err := a.Run(ctx); err != nil {
		log.Error("stopped with an error", "error", err)
		return 1
	}
	log.Info("mesh-worker stopped cleanly")
	return 0
}

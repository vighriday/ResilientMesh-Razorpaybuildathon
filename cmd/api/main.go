// Command api serves the public HTTP surface: the webhook trust boundary, the
// checkout event stream, the operator API and the static console.
//
// It runs no recovery work. Separating the edge from the pipeline is what lets
// each scale on its own signal — the edge on request volume, the worker on
// incident volume — and those two numbers are unrelated: one very large outage
// produces few requests and many incidents.
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
		// Printed rather than logged: the logger's level comes from the
		// configuration that just failed to load.
		fmt.Fprintf(os.Stderr, "mesh-api: %v\n", err)
		return 2
	}
	log := obs.NewLogger(cfg.LogLevel, os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, app.Options{Roles: []app.Role{app.RoleAPI}, Logger: log})
	if err != nil {
		log.Error("could not start", "error", err)
		return 1
	}
	defer func() { _ = a.Close() }()

	log.Info("mesh-api starting", "addr", a.Addr(), "infra_mode", cfg.InfraMode)
	if err := a.Run(ctx); err != nil {
		log.Error("stopped with an error", "error", err)
		return 1
	}
	log.Info("mesh-api stopped cleanly")
	return 0
}

// Command simulator serves a Razorpay-compatible API and drives a scripted
// outage against it.
//
// The behaviour lives in internal/simulator so that cmd/mesh can embed the same
// server in-process rather than shelling out to this binary. A demo that
// depends on two processes finding each other is a demo with a failure mode
// that has nothing to do with the system being demonstrated.
package main

import (
	"os"

	"github.com/hriday/razorpay-resilient-mesh/internal/simulator"
)

func main() {
	os.Exit(simulator.Main(os.Args[1:], os.Stdout, os.Stderr))
}

//go:build js && wasm

// Command meshwasm exposes the real gatekeeper to a browser.
//
// The published evidence page argues that a language model cannot talk its way
// past this system's invariants. That is a claim about code, and a claim about
// code is worth exactly as much as a reader's ability to test it. So the
// gatekeeper is compiled to WebAssembly and handed to the reader, who can put
// any proposal they like in front of it, including proposals no model would ever
// produce, and watch the same fourteen rules that run in production decide.
//
// Two properties make this evidence rather than a toy.
//
// It is the production package. Every rule lives in internal/gatekeeper, reached
// through internal/gatewire, which is the same function the vector generator
// calls when it records the expected answers. There is no second implementation
// to drift, and a rule changed in the worker changes here in the same commit.
//
// It is deterministic. The clock is supplied by the caller rather than read from
// the host, so the same input produces the same decision on every machine, which
// is what lets the page re-derive recorded decisions and compare them.
//
// This file is the platform binding and nothing else: it moves strings across
// the JavaScript boundary.
package main

import (
	"syscall/js"

	"github.com/hriday/razorpay-resilient-mesh/internal/gatewire"
)

func main() {
	js.Global().Set("resilientMeshDecide", js.FuncOf(decide))
	js.Global().Set("resilientMeshReady", js.ValueOf(true))
	// The Go runtime exits when main returns, taking the exported function with
	// it, so the module parks here for the lifetime of the page.
	select {}
}

func decide(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return `{"error":"decide expects exactly one JSON argument"}`
	}
	return gatewire.DecideJSON(args[0].String())
}

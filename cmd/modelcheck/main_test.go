package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hriday/razorpay-resilient-mesh/internal/modelcheck"
)

// Every case below bounds the exploration. The exhaustive sweep is covered by
// internal/modelcheck's own suite; what needs testing here is the shell around
// it — flag handling, rendering, and the exit codes CI gates on.
const boundedArgs = "-max-states=2000"

func TestBoundedRunReportsBoundedExitCode(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{boundedArgs}, &out, &errOut)

	if got := out.String(); !strings.Contains(got, "BOUNDED:") {
		t.Errorf("summary does not flag the truncated exploration:\n%s", got)
	}
	if errOut.Len() != 0 {
		t.Errorf("unexpected stderr: %s", errOut.String())
	}
	// A bounded run that found nothing has not proved anything, so it must not
	// report success. Whether it exits bounded or violation depends on what the
	// gate under test does within the bound; both are non-zero and neither is
	// exitOK.
	if code == exitOK {
		t.Fatalf("a bounded run exited %d (OK); an incomplete exploration must not report success", code)
	}
	if code != exitBounded && code != exitViolation {
		t.Fatalf("unexpected exit code %d", code)
	}
}

func TestJSONOutputIsAWholeReport(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{boundedArgs, "-json"}, &out, &errOut); code == exitError {
		t.Fatalf("run failed: %s", errOut.String())
	}

	var report modelcheck.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decoding report: %v\n%s", err, out.String())
	}
	if report.Digest == "" {
		t.Error("report carries no digest, so two runs cannot be compared")
	}
	if len(report.Invariants) == 0 {
		t.Error("report names no invariants")
	}
	for _, inv := range report.Invariants {
		if inv.Why == "" {
			t.Errorf("invariant %s ships without its rationale", inv.Name)
		}
	}
	if report.Violations == nil {
		t.Error("violations is null rather than a list; a consumer should not have to special-case it")
	}
}

func TestUnknownFlagAndStrayArgumentAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"-not-a-flag"},
		{boundedArgs, "unexpected"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitError {
			t.Errorf("args %v exited %d, want %d", args, code, exitError)
		}
		if errOut.Len() == 0 {
			t.Errorf("args %v produced no diagnostic", args)
		}
	}
}

func TestSummaryNamesEveryInvariantAndItsVerdict(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{boundedArgs}, &out, &errOut); code == exitError {
		t.Fatalf("run failed: %s", errOut.String())
	}
	text := out.String()
	for _, name := range []string{
		modelcheck.InvAmountPinned,
		modelcheck.InvRecurringCooling,
		modelcheck.InvAttemptCap,
		modelcheck.InvAFACeiling,
		modelcheck.InvClosedActionSet,
		modelcheck.InvRefreshPreservesTerms,
		modelcheck.InvExecutableNamesRail,
		modelcheck.InvScheduleBounded,
		modelcheck.InvGateError,
	} {
		if !strings.Contains(text, name) {
			t.Errorf("summary omits invariant %s:\n%s", name, text)
		}
	}
	if !strings.Contains(text, "reachable states") || !strings.Contains(text, "transitions") {
		t.Errorf("summary omits the exploration counts:\n%s", text)
	}
}

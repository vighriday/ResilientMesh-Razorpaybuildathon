package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// In-process harness
// ---------------------------------------------------------------------------

// run takes *os.File rather than io.Writer, so the in-process tests give it
// real temporary files and read them back. That is closer to what the binary
// does than a bytes.Buffer would be, and it exercises the same WriteTo path.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	defer out.Close()
	errf, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}
	defer errf.Close()

	code = run(args, out, errf)

	o, err := os.ReadFile(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	e, err := os.ReadFile(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return code, string(o), string(e)
}

// fastRun is small enough to invoke many times and still exercises the whole
// pipeline.
var fastRun = []string{"--seed", "20260904", "--incidents", "8", "--chaos", "light"}

func withArgs(extra ...string) []string {
	return append(append([]string(nil), fastRun...), extra...)
}

// ---------------------------------------------------------------------------
// Flags and exit codes
// ---------------------------------------------------------------------------

// TestUsageErrorsExitTwoAndSayWhy keeps the three failure classes distinct. CI
// gates on the code, and a usage mistake that exited 1 would be indistinguishable
// from a real invariant violation — which is the one signal the harness exists
// to produce.
func TestUsageErrorsExitTwoAndSayWhy(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown flag", []string{"--nope"}, "flag provided but not defined"},
		{"unexpected positional argument", []string{"extra"}, "unexpected argument"},
		{"unknown chaos profile", []string{"--chaos", "stanadrd"}, "unknown chaos profile"},
		{"chaos profile in the wrong case", []string{"--chaos", "STANDARD"}, "unknown chaos profile"},
		{"zero incidents", []string{"--incidents", "0"}, "must be positive"},
		{"negative incidents", []string{"--incidents", "-1"}, "must be positive"},
		{"zero steps", []string{"--steps", "0"}, "must be positive"},
		{"negative fuzz", []string{"--fuzz", "-1"}, "must not be negative"},
		{"non-numeric seed", []string{"--seed", "abc"}, "invalid value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUsage, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr does not explain the problem (%q missing): %s", tc.want, stderr)
			}
			if stdout != "" {
				t.Fatalf("a usage error wrote to stdout: %s", stdout)
			}
		})
	}
	// The exit codes are distinct on purpose, so a CI log says what happened
	// without being parsed.
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok": exitOK, "violation": exitViolation, "usage": exitUsage, "nondeterminism": exitNondetermin,
	} {
		if prior, dup := seen[code]; dup {
			t.Fatalf("exit codes %s and %s are both %d", prior, name, code)
		}
		seen[code] = name
	}
}

// TestACleanRunExitsZeroAndPrintsAUsableSummary covers the success path and the
// contents of what an operator actually reads.
func TestACleanRunExitsZeroAndPrintsAUsableSummary(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--seed", "20260904", "--incidents", "8", "--chaos", "none")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout, stderr)
	}
	for _, want := range []string{
		"seed", "chaos profile", "steps", "trace", "invariant checks",
		"webhooks", "delivery", "outcomes", "compliance", "audit",
		"RESULT", "PASS",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("summary omits %q:\n%s", want, stdout)
		}
	}
	// A green run must state how much verification happened, or "PASS" is
	// indistinguishable from "checked nothing".
	if strings.Contains(stdout, "invariant checks  0") {
		t.Fatalf("a passing run reported zero invariant checks:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("a clean run wrote to stderr: %s", stderr)
	}
}

// TestAFailedRunExitsNonZero is the property that makes the harness visible in
// CI at all. A harness that exits 0 after finding a problem is worse than no
// harness: it converts a finding into a false assurance.
//
// A one-step budget is the deterministic way to reach the failure path from the
// command line: work is still outstanding, so the drain guarantee is unproven
// and Result.OK() is false.
func TestAFailedRunExitsNonZero(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--seed", "20260904", "--incidents", "8", "--chaos", "none", "--steps", "1")
	if code != exitViolation {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitViolation, stdout, stderr)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Fatalf("the summary of a failed run does not say FAIL:\n%s", stdout)
	}
	// The reason has to reach stderr, or a CI log shows a non-zero exit with no
	// diagnosis.
	if !strings.Contains(stderr, "truncated") {
		t.Fatalf("stderr does not explain the failure: %s", stderr)
	}
}

// TestTheJSONReportIsStableAndComplete covers the machine-readable path. The
// judge harness and any CI aggregation read this, so the field names are a
// contract and the bytes must be reproducible for one seed.
func TestTheJSONReportIsStableAndComplete(t *testing.T) {
	code, stdout, stderr := runCLI(t, withArgs("--json")...)
	if code != exitOK && code != exitViolation {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, stdout)
	}
	for _, key := range []string{
		"seed", "chaos_profile", "incidents_generated", "steps", "trace_hash",
		"trace_events", "monitor_checks", "webhooks_accepted", "attempts_executed",
		"incidents_recovered", "audit_chain_valid", "audit_head_hash",
		"net_recovered_paisa", "step_budget_exhausted",
	} {
		if _, ok := report[key]; !ok {
			t.Errorf("the JSON report omits %q; a consumer cannot ask for it later", key)
		}
	}
	if got := report["seed"]; got != float64(20260904) {
		t.Fatalf("the report names seed %v, want the one that was asked for", got)
	}
	// Byte-identical across invocations of one seed: a report that drifted
	// would break every stored comparison.
	_, again, _ := runCLI(t, withArgs("--json")...)
	if stdout != again {
		t.Fatalf("two JSON reports for one seed differ:\n%s\n%s", stdout, again)
	}
}

func TestTheDeterminismAssertionRunsTheSeedTwice(t *testing.T) {
	code, stdout, stderr := runCLI(t, withArgs("--assert-determinism")...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "byte-identical") {
		t.Fatalf("the determinism assertion did not report a comparison:\n%s", stdout)
	}
	if !strings.Contains(stdout, "determinism: two runs of seed 20260904") {
		t.Fatalf("the determinism line does not name the seed it checked:\n%s", stdout)
	}
}

func TestTraceFileIsWrittenAndMatchesTheRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.txt")
	code, _, stderr := runCLI(t, withArgs("--trace-file", path)...)
	if code != exitOK && code != exitViolation {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the trace file was not written: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("the trace file is empty")
	}
	if !strings.HasPrefix(string(body), "rmesh-sim-trace-v1\n") {
		t.Fatalf("the trace does not open with its version line: %.40q", body)
	}
	if !strings.Contains(stderr, "trace written to") {
		t.Fatalf("stderr does not report where the trace went: %s", stderr)
	}
	// Writing the trace again for the same seed must produce the same bytes,
	// which is the file-level statement of the determinism property.
	second := filepath.Join(dir, "trace2.txt")
	if code, _, stderr := runCLI(t, withArgs("--trace-file", second)...); code != exitOK && code != exitViolation {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}
	other, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("read second trace: %v", err)
	}
	if !bytes.Equal(body, other) {
		t.Fatal("two trace files for one seed differ")
	}
}

func TestFuzzSweepsConsecutiveSeeds(t *testing.T) {
	code, stdout, stderr := runCLI(t,
		"--seed", "20260904", "--incidents", "5", "--chaos", "none", "--fuzz", "3", "--json")
	if code != exitOK && code != exitViolation {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr)
	}
	var report struct {
		Seeds     int    `json:"seeds"`
		FirstSeed int64  `json:"first_seed"`
		Incidents int    `json:"incidents_per_seed"`
		Chaos     string `json:"chaos_profile"`
		Steps     int    `json:"total_steps"`
		Checks    int64  `json:"total_invariant_checks"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("the fuzz report does not parse: %v\n%s", err, stdout)
	}
	if report.Seeds != 3 || report.FirstSeed != 20260904 || report.Incidents != 5 {
		t.Fatalf("the fuzz report describes a different experiment: %+v", report)
	}
	// Consecutive rather than random seeds, so "--fuzz 3" means the same three
	// experiments on every machine and in every CI run.
	if report.Steps == 0 || report.Checks == 0 {
		t.Fatalf("the sweep reported %d steps and %d checks", report.Steps, report.Checks)
	}
	// Zero is a legal sweep size and must not be treated as an error.
	if code, _, _ := runCLI(t, withArgs("--fuzz", "0")...); code != exitOK && code != exitViolation {
		t.Fatalf("--fuzz 0 exited %d", code)
	}
}

// TestAFuzzSweepThatFindsAFailureExitsNonZero is the same visibility property
// as the single-run case, on the path CI is most likely to use.
func TestAFuzzSweepThatFindsAFailureExitsNonZero(t *testing.T) {
	code, stdout, stderr := runCLI(t,
		"--seed", "20260904", "--incidents", "5", "--chaos", "none", "--fuzz", "2", "--steps", "1")
	if code != exitViolation {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitViolation, stdout, stderr)
	}
	if !strings.Contains(stderr, "FAIL seed=") {
		t.Fatalf("the sweep did not name the failing seed: %s", stderr)
	}
	if !strings.Contains(stdout, "violated an invariant") {
		t.Fatalf("the summary does not report the failure count:\n%s", stdout)
	}
}

func TestShortHashHelper(t *testing.T) {
	// The summary abbreviates the audit head. A helper that mangled a short
	// hash would make the one line an operator copies out of a CI log wrong.
	long := strings.Repeat("a", 64)
	if got := short(long); got != long[:16]+"..." {
		t.Fatalf("short(64 chars) = %q", got)
	}
	for _, s := range []string{"", "abc", strings.Repeat("b", 16)} {
		if got := short(s); got != s {
			t.Fatalf("short(%q) = %q, want it unchanged", s, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Cross-process determinism
// ---------------------------------------------------------------------------

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// meshsimBinary builds the command once for the whole test binary. Repeating an
// in-process run cannot establish the property these tests are for: a fresh
// process re-randomises Go's map hash seed and starts a new goroutine
// scheduler, which is precisely where nondeterminism hides.
func meshsimBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "meshsim-bin")
		if err != nil {
			binErr = err
			return
		}
		out := filepath.Join(dir, "meshsim")
		if os.PathSeparator == '\\' {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out,
			"github.com/hriday/razorpay-resilient-mesh/cmd/meshsim")
		if combined, err := cmd.CombinedOutput(); err != nil {
			binErr = errors.New("go build: " + err.Error() + ": " + string(combined))
			return
		}
		binPath = out
	})
	if binErr != nil {
		t.Fatalf("building meshsim: %v", binErr)
	}
	return binPath
}

// traceFromProcess runs the built binary and returns the trace it wrote.
func traceFromProcess(t *testing.T, gomaxprocs int, args ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.txt")
	cmd := exec.Command(meshsimBinary(t), append(args, "--trace-file", path)...)
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(gomaxprocs))
	out, err := cmd.CombinedOutput()
	if err != nil {
		// A non-zero exit is a legitimate outcome for a run that violated an
		// invariant; the trace is still written and still comparable. Only a
		// failure to produce a trace is fatal here.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running meshsim: %v\n%s", err, out)
		}
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("meshsim wrote no trace: %v\n%s", readErr, out)
	}
	if len(body) == 0 {
		t.Fatalf("meshsim wrote an empty trace\n%s", out)
	}
	return body
}

func compareTraces(t *testing.T, what string, a, b []byte) {
	t.Helper()
	if bytes.Equal(a, b) {
		return
	}
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		if al[i] != bl[i] {
			t.Fatalf("%s: traces diverged at line %d\n  run 1: %s\n  run 2: %s", what, i+1, al[i], bl[i])
		}
	}
	t.Fatalf("%s: traces have different lengths (%d and %d lines)", what, len(al), len(bl))
}

// TestTwoProcessesOnOneSeedProduceIdenticalTraces is the strongest form of the
// determinism claim. In-process repetition shares a map hash seed, a warmed
// allocator and one goroutine scheduler; two processes share none of that, so a
// leak that survives here is a leak that survives everything.
func TestTwoProcessesOnOneSeedProduceIdenticalTraces(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-process determinism needs a build; -short skips it")
	}
	args := []string{"--seed", "20260904", "--incidents", "10", "--chaos", "standard"}
	first := traceFromProcess(t, 0, args...)
	second := traceFromProcess(t, 0, args...)
	compareTraces(t, "two independent processes on seed 20260904", first, second)
}

// TestCrossProcessDeterminismSurvivesGOMAXPROCS varies the one setting that
// most changes Go's runtime behaviour between processes. Map iteration order
// and goroutine scheduling are the two classic ways nondeterminism reaches a
// trace, and both are sensitive to this.
func TestCrossProcessDeterminismSurvivesGOMAXPROCS(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-process determinism needs a build; -short skips it")
	}
	args := []string{"--seed", "20260904", "--incidents", "10", "--chaos", "standard"}
	single := traceFromProcess(t, 1, args...)
	many := traceFromProcess(t, 8, args...)
	compareTraces(t, "GOMAXPROCS=1 against GOMAXPROCS=8, separate processes", single, many)

	// And the reverse transition, so a leak that only appears on one direction
	// of the change cannot hide.
	again := traceFromProcess(t, 1, args...)
	compareTraces(t, "GOMAXPROCS=1 revisited in a third process", single, again)
}

// TestDifferentSeedsProduceDifferentTracesAcrossProcesses stops the two tests
// above from being vacuous: a binary that ignored --seed would satisfy both
// perfectly.
func TestDifferentSeedsProduceDifferentTracesAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-process determinism needs a build; -short skips it")
	}
	base := traceFromProcess(t, 0, "--seed", "20260904", "--incidents", "10", "--chaos", "standard")
	other := traceFromProcess(t, 0, "--seed", "20260905", "--incidents", "10", "--chaos", "standard")
	if bytes.Equal(base, other) {
		t.Fatal("two different seeds produced identical traces across processes")
	}
}

// TestTheBinaryAssertsItsOwnDeterminism exercises the flag CI actually gates
// on, in a real process, and requires the zero exit that gate depends on.
func TestTheBinaryAssertsItsOwnDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a build; -short skips it")
	}
	cmd := exec.Command(meshsimBinary(t),
		"--seed", "20260904", "--incidents", "8", "--chaos", "light", "--assert-determinism")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("meshsim --assert-determinism exited non-zero: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "byte-identical") {
		t.Fatalf("the binary did not report a byte-identical comparison:\n%s", out)
	}
}

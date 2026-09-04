package simulation

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

// TestVirtualTimeNeverMovesBackwards is the property every other claim in this
// package rests on. A cooling window, a backoff, an attempt fence and an audit
// timestamp are all differences between two readings of this clock; if the
// clock can go backwards, every one of them can be satisfied by accident.
func TestVirtualTimeNeverMovesBackwards(t *testing.T) {
	s := NewScheduler()
	// Deliberately scheduled out of order, including work that re-schedules
	// more work from inside itself, which is how the real pipeline behaves.
	for _, d := range []time.Duration{5 * time.Second, 0, 2 * time.Second, time.Hour, time.Millisecond} {
		delay := d
		s.After(delay, "seed", func() error {
			s.After(delay/2, "nested", func() error { return nil })
			return nil
		})
	}
	prev := s.NowNanos()
	for s.Pending() > 0 {
		if _, ran, err := s.Step(); err != nil || !ran {
			t.Fatalf("Step: ran=%t err=%v", ran, err)
		}
		if now := s.NowNanos(); now < prev {
			t.Fatalf("virtual time moved backwards: %d then %d", prev, now)
		} else {
			prev = now
		}
	}
}

// TestEarlierWorkAlwaysRunsFirst checks the heap is ordering by timestamp and
// not by insertion. Out-of-order execution would let a retry fire before the
// downtime notice that should have parked it.
func TestEarlierWorkAlwaysRunsFirst(t *testing.T) {
	s := NewScheduler()
	var ranAt []int64
	// Insert in descending order so insertion order and time order disagree
	// everywhere.
	for i := 20; i >= 1; i-- {
		s.After(time.Duration(i)*time.Second, fmt.Sprintf("op-%d", i), func() error {
			ranAt = append(ranAt, s.NowNanos())
			return nil
		})
	}
	for s.Pending() > 0 {
		if _, _, err := s.Step(); err != nil {
			t.Fatalf("Step: %v", err)
		}
	}
	if len(ranAt) != 20 {
		t.Fatalf("ran %d operations, want 20", len(ranAt))
	}
	for i := 1; i < len(ranAt); i++ {
		if ranAt[i] < ranAt[i-1] {
			t.Fatalf("operation %d ran at %d, before its predecessor at %d", i, ranAt[i], ranAt[i-1])
		}
	}
}

// TestTiesBreakOnInsertionOrderAndAreStable is the load-bearing tiebreak.
// Simulated work lands on identical virtual timestamps constantly — two relay
// ticks at the same instant, four retries released by one downtime resolution —
// and container/heap is not a stable sort. Without the sequence tiebreak the
// run order would depend on heap layout, which depends on insertion history in
// ways that are easy to perturb accidentally and impossible to notice.
func TestTiesBreakOnInsertionOrderAndAreStable(t *testing.T) {
	order := func() []string {
		s := NewScheduler()
		var got []string
		// A mixture of interleaved timestamps so the heap actually has to
		// restructure between the tied entries rather than holding them in
		// insertion order by luck.
		for i := 0; i < 40; i++ {
			name := fmt.Sprintf("tied-%02d", i)
			s.After(time.Second, name, func() error { got = append(got, name); return nil })
			s.After(time.Duration(40-i)*time.Millisecond, "filler", func() error { return nil })
		}
		for s.Pending() > 0 {
			if _, _, err := s.Step(); err != nil {
				t.Fatalf("Step: %v", err)
			}
		}
		return got
	}
	first := order()
	if len(first) != 40 {
		t.Fatalf("ran %d tied operations, want 40", len(first))
	}
	for i, name := range first {
		if want := fmt.Sprintf("tied-%02d", i); name != want {
			t.Fatalf("tied operation %d was %q, want %q: ties must break on insertion sequence", i, name, want)
		}
	}
	// Stability across constructions: the same schedule built again must run in
	// the same order, or two runs of one seed would diverge here.
	for round := 0; round < 8; round++ {
		again := order()
		for i := range first {
			if again[i] != first[i] {
				t.Fatalf("round %d diverged at position %d: %q vs %q", round, i, again[i], first[i])
			}
		}
	}
}

// TestSchedulerClampsHostileDelays covers the two ways a delay computed from
// attacker-influenced telemetry can be absurd. The scheduler is the wrong place
// to *discover* that, but it is exactly the right place to refuse to be steered
// by it: a negative delay must not run work in the past, and a delay past the
// horizon must not park work beyond any plausible run while the harness reports
// itself healthy.
func TestSchedulerClampsHostileDelays(t *testing.T) {
	s := NewScheduler()
	s.After(-time.Hour, "negative", func() error { return nil })
	if _, _, err := s.Step(); err != nil {
		t.Fatalf("Step: %v", err)
	}
	if s.NowNanos() != 0 {
		t.Fatalf("a negative delay moved virtual time to %d, want 0", s.NowNanos())
	}

	s = NewScheduler()
	s.After(200*365*24*time.Hour, "absurd", func() error { return nil })
	if _, _, err := s.Step(); err != nil {
		t.Fatalf("Step: %v", err)
	}
	if got := time.Duration(s.NowNanos()); got != maxHorizon {
		t.Fatalf("a two-century delay landed at %s, want the %s horizon", got, maxHorizon)
	}

	// At schedules an absolute instant and must never be earlier than now.
	s = NewScheduler()
	s.After(time.Minute, "advance", func() error { return nil })
	if _, _, err := s.Step(); err != nil {
		t.Fatalf("Step: %v", err)
	}
	before := s.NowNanos()
	s.At(Origin, "in the past", func() error { return nil })
	if _, _, err := s.Step(); err != nil {
		t.Fatalf("Step: %v", err)
	}
	if s.NowNanos() != before {
		t.Fatalf("At(Origin) moved virtual time from %d to %d", before, s.NowNanos())
	}
}

// TestStepReportsAnOperationFailureWithItsContext matters because an operation
// error means the harness itself is broken — the fakes report injected faults
// through their return values, not through this channel — and a run that
// swallowed it would report a green result for a run that never happened.
func TestStepReportsAnOperationFailureWithItsContext(t *testing.T) {
	sentinel := errors.New("harness broken")
	s := NewScheduler()
	s.After(3*time.Second, "exploding_op", func() error { return sentinel })
	name, ran, err := s.Step()
	if !ran {
		t.Fatal("Step reported nothing ran")
	}
	if name != "exploding_op" {
		t.Fatalf("Step returned name %q", name)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Step error = %v, want it to wrap the sentinel", err)
	}
	for _, want := range []string{"exploding_op", "step 1", "2026-01-01T00:00:03Z"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not locate the failure (%q missing)", err, want)
		}
	}
}

func TestEmptySchedulerTerminates(t *testing.T) {
	s := NewScheduler()
	name, ran, err := s.Step()
	if ran || err != nil || name != "" {
		t.Fatalf("Step on an empty queue = (%q, %t, %v), want a clean no-op", name, ran, err)
	}
	if s.Steps() != 0 || s.Pending() != 0 {
		t.Fatalf("an empty scheduler counted %d steps and %d pending", s.Steps(), s.Pending())
	}
	if !s.Now().Equal(Origin) {
		t.Fatalf("a fresh scheduler is at %s, want the fixed epoch %s", s.Now(), Origin)
	}
}

// TestABoundedBudgetTerminatesAnInfiniteLoop is why Run carries a step budget.
// A stage that reschedules itself unconditionally is a livelock; without a
// budget the test process hangs and CI reports a timeout with no diagnosis,
// which is strictly worse than a failure. The budget turns it into a bounded,
// reportable condition — the same mechanism Result.Truncated exposes.
func TestABoundedBudgetTerminatesAnInfiniteLoop(t *testing.T) {
	s := NewScheduler()
	var spin func()
	spin = func() {
		s.After(time.Millisecond, "spinner", func() error { spin(); return nil })
	}
	spin()

	const budget = 5000
	for s.Pending() > 0 && s.Steps() < budget {
		if _, _, err := s.Step(); err != nil {
			t.Fatalf("Step: %v", err)
		}
	}
	if s.Steps() != budget {
		t.Fatalf("the spinner stopped after %d steps; the test no longer exercises a livelock", s.Steps())
	}
	if s.Pending() == 0 {
		t.Fatal("the spinner drained, so the budget was not what stopped it")
	}
	// Virtual time advanced with the steps, so a truncated run can still say
	// how far it got rather than reporting an instant that never moved.
	if s.NowNanos() != int64(budget)*int64(time.Millisecond) {
		t.Fatalf("virtual elapsed = %s after %d one-millisecond steps", time.Duration(s.NowNanos()), budget)
	}
}

// TestSkewedClockMovesOnlyItself is what makes injected clock skew a usable
// fault. The component under test reasons about a wrong time while the
// invariant monitor keeps checking against the authoritative one; if skew moved
// both, a regulatory window shortened by skew would look satisfied to the
// checker as well and the fault would prove nothing.
func TestSkewedClockMovesOnlyItself(t *testing.T) {
	s := NewScheduler()
	c := &skewedClock{sched: s}
	if !c.Now().Equal(s.Now()) {
		t.Fatal("an unskewed clock disagrees with the scheduler")
	}
	for _, offset := range []time.Duration{30 * time.Second, -30 * time.Second, 5 * time.Minute, 0} {
		c.setOffset(offset)
		if got, want := c.Now(), s.Now().Add(offset); !got.Equal(want) {
			t.Fatalf("skewed clock = %s, want %s", got, want)
		}
		if !s.Now().Equal(Origin) {
			t.Fatalf("setting a component's offset moved the authoritative clock to %s", s.Now())
		}
	}
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

// TestTraceHashIsIndependentOfCapture is what lets --assert-determinism stay
// cheap. The hash always sees every byte; capture may stop. If truncating the
// capture also truncated the hash, a long run would compare only its prefix and
// a divergence past the cap would go unreported.
func TestTraceHashIsIndependentOfCapture(t *testing.T) {
	emit := func(tr *Trace) {
		for i := 0; i < 500; i++ {
			tr.Emit(i, Origin.Add(time.Duration(i)*time.Second), "kind", fmt.Sprintf("key-%d", i),
				Fi("n", int64(i)), F("s", "value"), Fb("flag", i%2 == 0))
		}
	}
	captured, silent := NewTrace(true), NewTrace(false)
	emit(captured)
	emit(silent)
	if captured.Hash() != silent.Hash() {
		t.Fatal("capture changed the trace hash; identity must not depend on whether anyone is watching")
	}
	if captured.Count() != silent.Count() || captured.Count() != 500 {
		t.Fatalf("event counts = %d and %d, want 500", captured.Count(), silent.Count())
	}
	if len(silent.Bytes()) != 0 {
		t.Fatal("a non-capturing trace retained text")
	}
	if len(captured.Bytes()) == 0 {
		t.Fatal("a capturing trace retained nothing")
	}
	// The version line is absorbed first, so a rendering change cannot make a
	// new run's hash collide with an old stored one.
	if !strings.HasPrefix(string(captured.Bytes()), traceVersion+"\n") {
		t.Fatalf("trace does not open with its version line: %.40q", captured.Bytes())
	}
	// Two empty traces must agree for the same reason: identity is the event
	// stream, and an empty stream is a legitimate, comparable identity.
	if NewTrace(false).Hash() != NewTrace(true).Hash() {
		t.Fatal("two empty traces disagree")
	}
}

// TestTraceFieldsAreSortedByKey removes a whole class of nondeterminism before
// it can be written: a future caller building fields from a map would otherwise
// make the trace, and therefore the determinism assertion, depend on Go's
// randomised map iteration order.
func TestTraceFieldsAreSortedByKey(t *testing.T) {
	a, b := NewTrace(true), NewTrace(true)
	a.Emit(1, Origin, "kind", "key", F("zebra", "1"), F("alpha", "2"), F("mike", "3"))
	b.Emit(1, Origin, "kind", "key", F("mike", "3"), F("zebra", "1"), F("alpha", "2"))
	if string(a.Bytes()) != string(b.Bytes()) {
		t.Fatalf("field order changed the rendering:\n%s\n%s", a.Bytes(), b.Bytes())
	}
	line := strings.Split(strings.TrimSpace(string(a.Bytes())), "\n")[1]
	if !strings.Contains(line, "alpha=2 mike=3 zebra=1") {
		t.Fatalf("fields are not rendered in key order: %s", line)
	}
}

// TestTraceValuesCannotForgeAFieldOrAnEventBoundary is the trace's own
// injection defence. Values carry issuer keys, error codes and audit reasons,
// all of which originate in payload text; a value containing a newline could
// otherwise fabricate an entire trace event, and one containing a space or an
// equals sign could fabricate a field.
func TestTraceValuesCannotForgeAFieldOrAnEventBoundary(t *testing.T) {
	hostile := map[string]string{
		"newline":         "a\nb",
		"carriage return": "a\rb",
		"tab":             "a\tb",
		"space":           "a b",
		"equals":          "a=b",
		"forged event":    "x\n000001 000000000000 recovered inc_evil",
		"forged field":    "x invariant=NONE",
		"control bytes":   "a\x00\x07\x1bb",
		"delete":          "a\x7fb",
	}
	for name, value := range hostile {
		t.Run(name, func(t *testing.T) {
			tr := NewTrace(true)
			tr.Emit(1, Origin, "kind", value, F("k", value))
			body := strings.TrimSuffix(string(tr.Bytes()), "\n")
			lines := strings.Split(body, "\n")
			if len(lines) != 2 { // version line plus exactly one event
				t.Fatalf("value %q produced %d lines, want 2:\n%s", value, len(lines), body)
			}
			ev := lines[1]
			if strings.Count(ev, "=") != 1 {
				t.Fatalf("value %q forged a field: %s", value, ev)
			}
			for _, c := range []string{"\n", "\r", "\t", "\x00", "\x1b", "\x7f"} {
				if strings.Contains(ev, c) {
					t.Fatalf("rendered event retains a separator or control byte: %q", ev)
				}
			}
		})
	}
	// An empty value renders as a placeholder rather than as nothing, so a
	// missing value cannot shift every following field one position left.
	tr := NewTrace(true)
	tr.Emit(1, Origin, "", "", F("k", ""))
	if !strings.Contains(string(tr.Bytes()), "- - k=-") {
		t.Fatalf("empty values do not render as placeholders: %q", tr.Bytes())
	}
}

func TestTraceValuesAreLengthCappedOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("₹", 500) // three bytes each, so the cap lands mid-rune
	tr := NewTrace(true)
	tr.Emit(1, Origin, "kind", long, F("k", long))
	for _, field := range strings.Fields(strings.Split(string(tr.Bytes()), "\n")[1])[2:] {
		if len(field) > maxFieldBytes+len("k=")+1 {
			t.Fatalf("field is %d bytes, past the %d-byte cap: %.40q", len(field), maxFieldBytes, field)
		}
	}
	rendered := sanitizeTraceValue(long)
	if len(rendered) > maxFieldBytes+1 {
		t.Fatalf("sanitised value is %d bytes, want at most %d", len(rendered), maxFieldBytes+1)
	}
	if !strings.HasSuffix(rendered, "~") {
		t.Fatal("a truncated value does not announce that it was truncated")
	}
	// The remaining text must still be valid UTF-8: a cut through a rune would
	// make the trace unreadable in exactly the place someone is debugging.
	if strings.ContainsRune(strings.TrimSuffix(rendered, "~"), '�') {
		t.Fatal("truncation cut through a rune")
	}
}

// TestFirstDifferenceLocatesTheDivergence is what turns a determinism failure
// from an assertion into a diagnosis. "Hashes differ" tells an engineer
// nothing; the offending line almost always names the unsorted map iteration
// behind it.
func TestFirstDifferenceLocatesTheDivergence(t *testing.T) {
	base := "v1\nalpha\nbravo\ncharlie\n"
	cases := []struct {
		name       string
		other      string
		wantLine   int
		wantDiffer bool
	}{
		{"identical", base, 0, false},
		{"middle line differs", "v1\nalpha\nBRAVO\ncharlie\n", 3, true},
		{"first line differs", "v2\nalpha\nbravo\ncharlie\n", 1, true},
		{"left is a prefix of right", base + "delta\n", 5, true},
		{"right is a prefix of left", "v1\nalpha\nbravo\n", 4, true},
		{"both empty", "", 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, left, right, differs := FirstDifference([]byte(base), []byte(tc.other))
			if differs != tc.wantDiffer {
				t.Fatalf("differs = %t, want %t", differs, tc.wantDiffer)
			}
			if !differs {
				return
			}
			if line != tc.wantLine {
				t.Fatalf("line = %d, want %d (left=%q right=%q)", line, tc.wantLine, left, right)
			}
			if left == right {
				t.Fatalf("reported identical lines at the divergence: %q", left)
			}
		})
	}
	// When one trace is a strict prefix of the other and neither ends in a
	// newline, the shorter side must be named explicitly rather than reported as
	// an empty line: the report has to say which run stopped early.
	line, left, right, differs := FirstDifference([]byte("a\nb"), []byte("a\nb\nc"))
	if !differs || line != 3 || left != "(end of trace)" || right != "c" {
		t.Fatalf("FirstDifference on a strict prefix = (%d, %q, %q, %t), want (3, end-of-trace, c, true)",
			line, left, right, differs)
	}
}

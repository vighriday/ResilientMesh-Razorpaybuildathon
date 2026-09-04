// Package simulation runs the real ResilientMesh decision path — the actual
// internal/gatekeeper, internal/policy and internal/agent code — against
// in-memory implementations of every domain port, driven by a single-goroutine
// deterministic scheduler over virtual time.
//
// The point is not "a test with fakes". The point is that a whole distributed
// system's execution becomes a pure function of one integer seed: the same seed
// replays the same interleaving, the same fault injections, the same backoff
// draws and the same audit hashes, byte for byte. That turns a heisenbug into a
// reproducible artifact and turns "we think the compliance invariants hold"
// into "here are 200 seeds' worth of evidence, and here is the seed that
// breaks it".
//
// Three disciplines make that true, and every file in the package is written to
// preserve them:
//
//  1. No goroutines, no wall clock, no time.Sleep. Time only advances when the
//     scheduler pops an operation.
//  2. One *rand.Rand seeded once. Every other generator in the run is seeded
//     from a draw off that one, so the whole run has a single entropy root.
//  3. No unordered map iteration on any path that can affect ordering. Go
//     randomises map range order, which is the most common accidental source of
//     nondeterminism in exactly this kind of code, so every map walk here is
//     sorted first and the determinism self-test exists to catch a regression.
package simulation

import (
	"container/heap"
	"fmt"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Origin is the virtual epoch. It is a fixed instant rather than time.Now() so
// that every timestamp the run produces — audit entries, execute-after
// schedules, the trace itself — is identical across machines and across years.
var Origin = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// maxHorizon bounds how far into the future an operation may be scheduled. A
// backoff computed from corrupted state could otherwise park an operation
// beyond any plausible run and stall the simulation while looking healthy.
const maxHorizon = 90 * 24 * time.Hour

// opFunc is one unit of simulated work. Returning an error aborts the run: the
// fakes report expected, injected faults through their own return values, so an
// error out of an operation means the harness itself is broken.
type opFunc func() error

type op struct {
	at   int64 // virtual nanoseconds since Origin
	seq  uint64
	name string
	fn   opFunc
}

// opHeap orders by virtual time, then by insertion sequence.
//
// The sequence tiebreak is load-bearing rather than cosmetic. Simulated work
// lands on identical virtual timestamps constantly — a relay tick and a worker
// tick scheduled at the same instant, four retries released by one downtime
// resolution — and container/heap is not a stable sort. Without a total order
// the run would depend on heap layout, which depends on insertion history in
// ways that are easy to perturb accidentally.
type opHeap []*op

func (h opHeap) Len() int { return len(h) }

func (h opHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}

func (h opHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *opHeap) Push(x any) { *h = append(*h, x.(*op)) }

func (h *opHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}

// Scheduler is the simulated world's only clock and only executor. Everything
// that would be a goroutine, a timer, or a network round trip in production is
// an entry in this priority queue.
type Scheduler struct {
	now   int64 // virtual nanoseconds since Origin
	seq   uint64
	queue opHeap
	steps int
}

var _ domain.Clock = (*Scheduler)(nil)

// NewScheduler returns a scheduler positioned at Origin with no pending work.
func NewScheduler() *Scheduler {
	s := &Scheduler{queue: opHeap{}}
	heap.Init(&s.queue)
	return s
}

// Now implements domain.Clock. Every component under simulation reads time
// through this, which is why a 24-hour RBI cooling window costs microseconds to
// test instead of a day.
func (s *Scheduler) Now() time.Time {
	return Origin.Add(time.Duration(s.now))
}

// NowNanos is the raw virtual offset, used by the trace and the fault injector
// where a monotonic integer is cheaper and more stable to render than a
// formatted time.
func (s *Scheduler) NowNanos() int64 { return s.now }

// After schedules fn to run d from now. A negative or absurd delay is clamped
// rather than rejected: delays arrive from policy arithmetic over
// attacker-influenced telemetry, and the scheduler is the wrong place to
// discover that, but it is exactly the right place to refuse to be steered by
// it.
func (s *Scheduler) After(d time.Duration, name string, fn opFunc) {
	if d < 0 {
		d = 0
	}
	if d > maxHorizon {
		d = maxHorizon
	}
	s.seq++
	heap.Push(&s.queue, &op{at: s.now + int64(d), seq: s.seq, name: name, fn: fn})
}

// At schedules fn for an absolute virtual instant, never earlier than now.
func (s *Scheduler) At(t time.Time, name string, fn opFunc) {
	s.After(t.Sub(s.Now()), name, fn)
}

// Pending reports how much work remains, which is the run's termination
// condition.
func (s *Scheduler) Pending() int { return s.queue.Len() }

// Steps is the number of operations executed so far. It is the step index
// reported alongside a violation, and it is stable for a given seed.
func (s *Scheduler) Steps() int { return s.steps }

// Step runs the earliest pending operation and returns its name. Virtual time
// jumps straight to that operation's timestamp: there is no idle time to
// simulate, which is what makes a multi-day mandate schedule finish in
// milliseconds.
func (s *Scheduler) Step() (string, bool, error) {
	if s.queue.Len() == 0 {
		return "", false, nil
	}
	o := heap.Pop(&s.queue).(*op)
	if o.at > s.now {
		s.now = o.at
	}
	s.steps++
	if err := o.fn(); err != nil {
		return o.name, true, fmt.Errorf("simulation: operation %q failed at step %d (t=%s): %w",
			o.name, s.steps, s.Now().UTC().Format(time.RFC3339Nano), err)
	}
	return o.name, true, nil
}

// skewedClock is a component's own, possibly wrong, view of the time. Injected
// clock skew is a first-class fault because a payment system that derives a
// regulatory cooling window from a skewed absolute timestamp will breach it
// while every unit test still passes.
type skewedClock struct {
	sched  *Scheduler
	offset time.Duration
}

var _ domain.Clock = (*skewedClock)(nil)

func (c *skewedClock) Now() time.Time { return c.sched.Now().Add(c.offset) }

// setOffset moves this component's clock relative to the authoritative one.
func (c *skewedClock) setOffset(d time.Duration) { c.offset = d }

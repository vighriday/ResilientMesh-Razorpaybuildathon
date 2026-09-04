package breaker

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Tests run against miniredis over TCP with the real go-redis client, so the
// Lua scripts, the EVALSHA fallback, and the RESP encoding of every script
// return value are all exercised rather than mocked. Time is injected, so no
// test sleeps and the cooldown boundaries are asserted to the millisecond.

const testIssuer = "card:HDFC"

// go-redis reports pool dial failures through a package-level logger that
// writes to stderr, and one test below kills its server on purpose. Discarding
// keeps the failure that test asserts on from reading as noise in an otherwise
// green run.
func TestMain(m *testing.M) {
	redis.SetLogger(discardRedisLogger{})
	os.Exit(m.Run())
}

type discardRedisLogger struct{}

func (discardRedisLogger) Printf(context.Context, string, ...any) {}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, time.March, 14, 10, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// transitionLog captures callback deliveries. It is mutex-guarded because the
// callback fires on whichever goroutine observed the transition.
type transitionLog struct {
	mu    sync.Mutex
	items []Transition
}

func (l *transitionLog) record(_ context.Context, t Transition) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = append(l.items, t)
}

func (l *transitionLog) all() []Transition {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Transition, len(l.items))
	copy(out, l.items)
	return out
}

func (l *transitionLog) count(from, to domain.BreakerState) int {
	n := 0
	for _, t := range l.all() {
		if t.From == from && t.To == to {
			n++
		}
	}
	return n
}

type harness struct {
	t     *testing.T
	b     *Breaker
	mr    *miniredis.Miniredis
	clock *testClock
	log   *transitionLog
	cfg   Config
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("closing redis client: %v", err)
		}
	})
	clock := newTestClock()
	tl := &transitionLog{}
	cfg := Config{
		TripRate:       0.20,
		MinSamples:     10,
		Cooldown:       60 * time.Second,
		HalfOpenProbes: 3,
		WindowSize:     50,
		OnTransition:   tl.record,
		Namespace:      "test:breaker",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return &harness{t: t, b: New(rdb, clock, cfg), mr: mr, clock: clock, log: tl, cfg: cfg.withDefaults()}
}

func (h *harness) report(key string, success bool) {
	h.t.Helper()
	if err := h.b.Report(context.Background(), key, success); err != nil {
		h.t.Fatalf("Report(%q, %v): %v", key, success, err)
	}
}

func (h *harness) reportN(key string, success bool, n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		h.report(key, success)
	}
}

func (h *harness) state(key string) domain.BreakerState {
	h.t.Helper()
	st, err := h.b.State(context.Background(), key)
	if err != nil {
		h.t.Fatalf("State(%q): %v", key, err)
	}
	return st
}

func (h *harness) allow(key string) bool {
	h.t.Helper()
	ok, err := h.b.Allow(context.Background(), key)
	if err != nil {
		h.t.Fatalf("Allow(%q): %v", key, err)
	}
	return ok
}

// trip drives the breaker from closed to open using exactly MinSamples
// failures, and asserts it got there.
func (h *harness) trip(key string) {
	h.t.Helper()
	h.reportN(key, false, h.cfg.MinSamples)
	if got := h.state(key); got != domain.BreakerOpen {
		h.t.Fatalf("after %d failures state = %s, want OPEN", h.cfg.MinSamples, got)
	}
}

func (h *harness) requireState(key string, want domain.BreakerState, when string) {
	h.t.Helper()
	if got := h.state(key); got != want {
		h.t.Fatalf("state %s, want %s (%s)", got, want, when)
	}
}

// ---------------------------------------------------------------------------
// Tripping
// ---------------------------------------------------------------------------

func TestTripsExactlyAtMinSamplesAndNotOneSampleEarlier(t *testing.T) {
	h := newHarness(t, nil)

	for i := 1; i < h.cfg.MinSamples; i++ {
		h.report(testIssuer, false)
		if got := h.state(testIssuer); got != domain.BreakerClosed {
			t.Fatalf("after %d consecutive failures state = %s, want CLOSED", i, got)
		}
		if !h.allow(testIssuer) {
			t.Fatalf("after %d consecutive failures Allow = false, want true", i)
		}
	}

	h.report(testIssuer, false)
	if got := h.state(testIssuer); got != domain.BreakerOpen {
		t.Fatalf("on sample %d state = %s, want OPEN", h.cfg.MinSamples, got)
	}
	if h.allow(testIssuer) {
		t.Fatal("Allow = true on an open breaker")
	}

	trips := h.log.all()
	if len(trips) != 1 {
		t.Fatalf("got %d transitions, want exactly 1: %+v", len(trips), trips)
	}
	tr := trips[0]
	if tr.From != domain.BreakerClosed || tr.To != domain.BreakerOpen {
		t.Fatalf("transition %s -> %s, want CLOSED -> OPEN", tr.From, tr.To)
	}
	if tr.Reason != ReasonTripRateBreached {
		t.Fatalf("reason = %q, want %q", tr.Reason, ReasonTripRateBreached)
	}
	if tr.Samples != h.cfg.MinSamples || tr.Successes != 0 {
		t.Fatalf("transition window = %d/%d samples/successes, want %d/0", tr.Samples, tr.Successes, h.cfg.MinSamples)
	}
	if tr.IssuerKey != testIssuer {
		t.Fatalf("issuer key = %q, want %q", tr.IssuerKey, testIssuer)
	}
	if !tr.At.Equal(h.clock.Now()) {
		t.Fatalf("transition at %s, want %s", tr.At, h.clock.Now())
	}
}

func TestDoesNotTripBelowMinSamplesEvenAtZeroSuccess(t *testing.T) {
	h := newHarness(t, nil)

	h.reportN(testIssuer, false, h.cfg.MinSamples-1)

	h.requireState(testIssuer, domain.BreakerClosed, "one sample short of the floor at 0% success")
	if !h.allow(testIssuer) {
		t.Fatal("Allow = false below MinSamples")
	}
	if n := len(h.log.all()); n != 0 {
		t.Fatalf("got %d transitions below MinSamples, want 0", n)
	}
}

// The trip test is "rate strictly below TripRate", so a window sitting exactly
// on the threshold must stay closed. This is the boundary an operator tunes
// against, and getting it backwards would shut off a healthy issuer.
func TestTripRateBoundaryIsExclusive(t *testing.T) {
	t.Run("exactly at the rate stays closed", func(t *testing.T) {
		h := newHarness(t, nil)
		h.reportN(testIssuer, true, 2) // 2/10 == 0.20 == TripRate
		h.reportN(testIssuer, false, 8)
		h.requireState(testIssuer, domain.BreakerClosed, "success rate exactly equal to the trip rate")
	})

	t.Run("one success below the rate trips", func(t *testing.T) {
		h := newHarness(t, nil)
		h.reportN(testIssuer, true, 1) // 1/10 == 0.10 < TripRate
		h.reportN(testIssuer, false, 9)
		h.requireState(testIssuer, domain.BreakerOpen, "success rate below the trip rate")
	})
}

func TestWindowIsCappedAtWindowSize(t *testing.T) {
	// A window of 10: the eleventh sample evicts the first, so what decides the
	// verdict is the last ten outcomes and not the lifetime tally. Without the
	// cap none of the states below would trip at all — 10 successes against 9
	// failures is a 53% issuer.
	h := newHarness(t, func(c *Config) {
		c.WindowSize = 10
		c.MinSamples = 10
	})

	h.reportN(testIssuer, true, 10)
	h.requireState(testIssuer, domain.BreakerClosed, "ten successes")

	h.reportN(testIssuer, false, 8)
	h.requireState(testIssuer, domain.BreakerClosed, "8 failures leave 2 successes in a 10-wide window: exactly the trip rate")

	h.report(testIssuer, false)
	h.requireState(testIssuer, domain.BreakerOpen, "the ninth failure evicts one more success and crosses the rate")
}

func TestTripClearsTheWindow(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)

	if h.mr.Exists(h.b.windowKey(testIssuer)) {
		t.Fatal("window key survived the trip; stale samples would re-open the breaker after the next close")
	}
}

// ---------------------------------------------------------------------------
// Cooldown
// ---------------------------------------------------------------------------

func TestHalfOpensOnlyAfterTheCooldown(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)

	h.clock.Advance(h.cfg.Cooldown - time.Millisecond)
	h.requireState(testIssuer, domain.BreakerOpen, "one millisecond before the cooldown elapses")
	if h.allow(testIssuer) {
		t.Fatal("Allow = true one millisecond before the cooldown elapses")
	}

	h.clock.Advance(time.Millisecond)
	h.requireState(testIssuer, domain.BreakerHalfOpen, "exactly on the cooldown boundary")
	if !h.allow(testIssuer) {
		t.Fatal("Allow = false on the cooldown boundary")
	}

	if n := h.log.count(domain.BreakerOpen, domain.BreakerHalfOpen); n != 1 {
		t.Fatalf("got %d OPEN -> HALF_OPEN transitions, want 1", n)
	}
}

// State must not consume the recovery attempt: an ops console polling every
// second would otherwise spend every probe the issuer is given.
func TestStateReadDoesNotPersistTheHalfOpenFlip(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)
	h.clock.Advance(h.cfg.Cooldown)

	for i := 0; i < 5; i++ {
		h.requireState(testIssuer, domain.BreakerHalfOpen, "cooldown elapsed")
	}
	if stored := h.mr.HGet(h.b.stateKey(testIssuer), fieldState); stored != string(domain.BreakerOpen) {
		t.Fatalf("stored state = %q after %d reads, want OPEN", stored, 5)
	}
	if n := len(h.log.all()); n != 1 {
		t.Fatalf("got %d transitions, want only the original trip", n)
	}

	allowed := 0
	for i := 0; i < h.cfg.HalfOpenProbes+5; i++ {
		if h.allow(testIssuer) {
			allowed++
		}
	}
	if allowed != h.cfg.HalfOpenProbes {
		t.Fatalf("%d probes admitted after the state reads, want %d", allowed, h.cfg.HalfOpenProbes)
	}
}

// ---------------------------------------------------------------------------
// Half-open probe budget
// ---------------------------------------------------------------------------

func TestProbeBudgetHoldsUnderConcurrentAllow(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)
	h.clock.Advance(h.cfg.Cooldown)

	const goroutines = 50
	var (
		admitted atomic.Int64
		failures atomic.Int64
		start    = make(chan struct{})
		wg       sync.WaitGroup
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			ok, err := h.b.Allow(context.Background(), testIssuer)
			if err != nil {
				failures.Add(1)
				return
			}
			if ok {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Fatalf("%d concurrent Allow calls failed", n)
	}
	if got := admitted.Load(); got != int64(h.cfg.HalfOpenProbes) {
		t.Fatalf("%d of %d goroutines admitted, want exactly %d: the probe budget was not decremented atomically",
			got, goroutines, h.cfg.HalfOpenProbes)
	}
	// Exactly one caller may observe the OPEN -> HALF_OPEN transition, or the
	// audit ledger gets one entry per worker for a single event.
	if n := h.log.count(domain.BreakerOpen, domain.BreakerHalfOpen); n != 1 {
		t.Fatalf("got %d OPEN -> HALF_OPEN transitions across %d goroutines, want 1", n, goroutines)
	}
}

// A probe whose worker dies never reports, so without a lease the budget would
// stay spent and the issuer would be wedged shut forever.
func TestAbandonedProbeEpisodeExpires(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)
	h.clock.Advance(h.cfg.Cooldown)

	for i := 0; i < h.cfg.HalfOpenProbes; i++ {
		if !h.allow(testIssuer) {
			t.Fatalf("probe %d denied while budget remained", i)
		}
	}
	if h.allow(testIssuer) {
		t.Fatal("Allow = true with the probe budget exhausted")
	}

	// No probe ever reports back.
	h.clock.Advance(h.cfg.Cooldown - time.Millisecond)
	if h.allow(testIssuer) {
		t.Fatal("Allow = true before the probe lease expired")
	}
	h.clock.Advance(time.Millisecond)
	if !h.allow(testIssuer) {
		t.Fatal("Allow = false after the probe lease expired: the breaker is wedged")
	}
}

func TestProbeSuccessClosesAndStartsAFreshWindow(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)
	h.clock.Advance(h.cfg.Cooldown)

	if !h.allow(testIssuer) {
		t.Fatal("Allow = false at the cooldown boundary")
	}
	h.report(testIssuer, true)

	h.requireState(testIssuer, domain.BreakerClosed, "after a successful probe")
	if n := h.log.count(domain.BreakerHalfOpen, domain.BreakerClosed); n != 1 {
		t.Fatalf("got %d HALF_OPEN -> CLOSED transitions, want 1", n)
	}

	// Closed means closed: admission is no longer rationed.
	for i := 0; i < h.cfg.HalfOpenProbes+5; i++ {
		if !h.allow(testIssuer) {
			t.Fatalf("Allow = false on call %d of a closed breaker", i)
		}
	}

	// The window restarts empty, so the pre-trip failures cannot re-trip it.
	h.reportN(testIssuer, false, h.cfg.MinSamples-1)
	h.requireState(testIssuer, domain.BreakerClosed, "one sample short of the floor in the fresh window")
	h.report(testIssuer, false)
	h.requireState(testIssuer, domain.BreakerOpen, "the fresh window reached the floor")
}

func TestProbeFailureReopensAndRestartsTheCooldown(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)

	h.clock.Advance(h.cfg.Cooldown)
	if !h.allow(testIssuer) {
		t.Fatal("Allow = false at the cooldown boundary")
	}
	h.report(testIssuer, false)

	h.requireState(testIssuer, domain.BreakerOpen, "after a failed probe")
	if n := h.log.count(domain.BreakerHalfOpen, domain.BreakerOpen); n != 1 {
		t.Fatalf("got %d HALF_OPEN -> OPEN transitions, want 1", n)
	}

	// The cooldown must run from the failed probe, not from the original trip:
	// re-opening on the old timer would half-open again immediately and put the
	// fleet straight back onto a dead issuer.
	h.clock.Advance(h.cfg.Cooldown - time.Millisecond)
	h.requireState(testIssuer, domain.BreakerOpen, "one millisecond before the restarted cooldown elapses")
	if h.allow(testIssuer) {
		t.Fatal("Allow = true before the restarted cooldown elapsed")
	}

	h.clock.Advance(time.Millisecond)
	h.requireState(testIssuer, domain.BreakerHalfOpen, "the restarted cooldown elapsed")
	if !h.allow(testIssuer) {
		t.Fatal("Allow = false after the restarted cooldown elapsed")
	}
}

// While open the breaker is shedding load, so surviving outcomes are not a
// sample of issuer health. Counting them would let stray successes close the
// breaker without ever spending a probe.
func TestOutcomesReportedWhileOpenAreIgnored(t *testing.T) {
	h := newHarness(t, nil)
	h.trip(testIssuer)

	h.reportN(testIssuer, true, 100)

	h.requireState(testIssuer, domain.BreakerOpen, "after 100 successes reported while open")
	if h.allow(testIssuer) {
		t.Fatal("Allow = true after successes reported while open")
	}
	if h.mr.Exists(h.b.windowKey(testIssuer)) {
		t.Fatal("outcomes reported while open were written to the window")
	}
	if n := len(h.log.all()); n != 1 {
		t.Fatalf("got %d transitions, want only the original trip", n)
	}
}

// ---------------------------------------------------------------------------
// States, for the ops console
// ---------------------------------------------------------------------------

func TestStatesReportsEveryTrackedIssuer(t *testing.T) {
	h := newHarness(t, nil)
	const (
		open   = "card:HDFC"
		closed = "upi:okaxis"
	)

	h.trip(open)
	h.reportN(closed, true, 5)

	got, err := h.b.States(context.Background())
	if err != nil {
		t.Fatalf("States: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("States returned %d issuers, want 2: %v", len(got), got)
	}
	if got[open] != domain.BreakerOpen {
		t.Fatalf("States[%q] = %s, want OPEN", open, got[open])
	}
	if got[closed] != domain.BreakerClosed {
		t.Fatalf("States[%q] = %s, want CLOSED", closed, got[closed])
	}

	// The console view must agree with State, including the unpersisted
	// promotion of an elapsed cooldown.
	h.clock.Advance(h.cfg.Cooldown)
	got, err = h.b.States(context.Background())
	if err != nil {
		t.Fatalf("States after cooldown: %v", err)
	}
	if got[open] != domain.BreakerHalfOpen {
		t.Fatalf("States[%q] = %s after the cooldown, want HALF_OPEN", open, got[open])
	}
	if stored := h.mr.HGet(h.b.stateKey(open), fieldState); stored != string(domain.BreakerOpen) {
		t.Fatalf("States persisted a transition: stored state = %q, want OPEN", stored)
	}
}

func TestStatesIsEmptyBeforeAnyTraffic(t *testing.T) {
	h := newHarness(t, nil)
	got, err := h.b.States(context.Background())
	if err != nil {
		t.Fatalf("States: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("States returned %v, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour
// ---------------------------------------------------------------------------

func TestInvalidIssuerKeysAreRejected(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	cases := map[string]string{
		"empty":            "",
		"oversize":         strings.Repeat("a", maxIssuerKeyLen+1),
		"newline":          "card:HD\nFC",
		"nul":              "card:HD\x00FC",
		"opening brace":    "card:{HDFC",
		"closing brace":    "card:HDFC}",
		"invalid utf-8":    "card:\xff\xfe",
		"delete character": "card:HDFC\x7f",
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			allowed, err := h.b.Allow(ctx, key)
			if !errors.Is(err, ErrInvalidIssuerKey) {
				t.Fatalf("Allow error = %v, want ErrInvalidIssuerKey", err)
			}
			if allowed {
				t.Fatal("Allow = true for a rejected key: the breaker failed open")
			}
			if err := h.b.Report(ctx, key, false); !errors.Is(err, ErrInvalidIssuerKey) {
				t.Fatalf("Report error = %v, want ErrInvalidIssuerKey", err)
			}
			st, err := h.b.State(ctx, key)
			if !errors.Is(err, ErrInvalidIssuerKey) {
				t.Fatalf("State error = %v, want ErrInvalidIssuerKey", err)
			}
			if st != domain.BreakerOpen {
				t.Fatalf("State = %s for a rejected key, want OPEN", st)
			}
		})
	}
}

func TestRedisFailureDeniesAdmission(t *testing.T) {
	mr := miniredis.RunT(t)
	// No retries and a short dial timeout: what is under test is the verdict
	// when Redis is unreachable, not how long go-redis waits before saying so.
	rdb := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("closing redis client: %v", err)
		}
	})
	h := &harness{t: t, b: New(rdb, newTestClock(), Config{Namespace: "test:breaker"}), mr: mr}
	h.mr.Close()

	allowed, err := h.b.Allow(context.Background(), testIssuer)
	if err == nil {
		t.Fatal("Allow returned no error with Redis down")
	}
	if allowed {
		t.Fatal("Allow = true with Redis down: the breaker failed open")
	}

	st, err := h.b.State(context.Background(), testIssuer)
	if err == nil {
		t.Fatal("State returned no error with Redis down")
	}
	if st != domain.BreakerOpen {
		t.Fatalf("State = %s with Redis down, want OPEN", st)
	}

	if err := h.b.Report(context.Background(), testIssuer, false); err == nil {
		t.Fatal("Report returned no error with Redis down")
	}
	if _, err := h.b.States(context.Background()); err == nil {
		t.Fatal("States returned no error with Redis down")
	}
}

// A state value this package did not write can only come from something else
// with keyspace access. Denying and repairing is the only safe reading.
func TestUninterpretableStateDeniesAndRepairs(t *testing.T) {
	h := newHarness(t, nil)
	h.mr.HSet(h.b.stateKey(testIssuer), fieldState, "MOSTLY_FINE")

	h.requireState(testIssuer, domain.BreakerOpen, "stored state is uninterpretable")
	if h.allow(testIssuer) {
		t.Fatal("Allow = true on an uninterpretable state")
	}
	if stored := h.mr.HGet(h.b.stateKey(testIssuer), fieldState); stored != string(domain.BreakerOpen) {
		t.Fatalf("stored state = %q after repair, want OPEN", stored)
	}

	repairs := 0
	for _, tr := range h.log.all() {
		if tr.Reason == ReasonStateRepaired {
			repairs++
		}
	}
	if repairs != 1 {
		t.Fatalf("got %d repair transitions, want 1: %+v", repairs, h.log.all())
	}

	// The repair starts a fresh cooldown rather than leaving the breaker open
	// on a timestamp that was never written.
	h.clock.Advance(h.cfg.Cooldown)
	h.requireState(testIssuer, domain.BreakerHalfOpen, "one cooldown after the repair")
}

func TestReportRepairsUninterpretableState(t *testing.T) {
	h := newHarness(t, nil)
	h.mr.HSet(h.b.stateKey(testIssuer), fieldState, "MOSTLY_FINE")

	h.report(testIssuer, true)

	if stored := h.mr.HGet(h.b.stateKey(testIssuer), fieldState); stored != string(domain.BreakerOpen) {
		t.Fatalf("stored state = %q after repair, want OPEN", stored)
	}
	h.requireState(testIssuer, domain.BreakerOpen, "a success must not close an uninterpretable breaker")
}

// ---------------------------------------------------------------------------
// Callback isolation
// ---------------------------------------------------------------------------

func TestPanickingCallbackDoesNotBreakTheBreaker(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(c *Config) {
		c.OnTransition = func(context.Context, Transition) {
			calls.Add(1)
			panic("audit ledger unavailable")
		}
	})

	h.reportN(testIssuer, false, h.cfg.MinSamples)

	if calls.Load() != 1 {
		t.Fatalf("callback called %d times, want 1", calls.Load())
	}
	h.requireState(testIssuer, domain.BreakerOpen, "a panicking callback must not undo the trip")
	if h.allow(testIssuer) {
		t.Fatal("Allow = true after a panicking callback")
	}
}

func TestNilCallbackIsFine(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OnTransition = nil })
	h.reportN(testIssuer, false, h.cfg.MinSamples)
	h.requireState(testIssuer, domain.BreakerOpen, "trip with no callback configured")
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentReportsAgreeOnOneTrip(t *testing.T) {
	h := newHarness(t, nil)

	const (
		goroutines = 25
		each       = 20
	)
	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
		errs  atomic.Int64
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < each; j++ {
				if err := h.b.Report(context.Background(), testIssuer, false); err != nil {
					errs.Add(1)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if n := errs.Load(); n != 0 {
		t.Fatalf("%d concurrent Report calls failed", n)
	}
	h.requireState(testIssuer, domain.BreakerOpen, "after 500 concurrent failures")

	// Once open, outcomes are ignored, so the trip can only be observed once
	// no matter how many goroutines were mid-flight.
	if n := h.log.count(domain.BreakerClosed, domain.BreakerOpen); n != 1 {
		t.Fatalf("got %d CLOSED -> OPEN transitions from %d goroutines, want 1", n, goroutines)
	}
}

func TestIssuersAreIndependent(t *testing.T) {
	h := newHarness(t, nil)
	const other = "netbanking:ICIC"

	h.trip(testIssuer)

	h.requireState(other, domain.BreakerClosed, "an untouched issuer")
	if !h.allow(other) {
		t.Fatal("Allow = false for an unrelated issuer")
	}
	h.reportN(other, true, 20)
	h.requireState(other, domain.BreakerClosed, "a healthy issuer beside a tripped one")
	h.requireState(testIssuer, domain.BreakerOpen, "the tripped issuer is unaffected by its neighbour")
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestZeroConfigUsesThePlanDefaults(t *testing.T) {
	got := Config{}.withDefaults()
	want := DefaultConfig()
	if got.TripRate != want.TripRate || got.MinSamples != want.MinSamples ||
		got.Cooldown != want.Cooldown || got.HalfOpenProbes != want.HalfOpenProbes ||
		got.WindowSize != want.WindowSize {
		t.Fatalf("zero Config resolved to %+v, want %+v", got, want)
	}
	if got.Namespace != defaultNamespace {
		t.Fatalf("namespace = %q, want %q", got.Namespace, defaultNamespace)
	}
}

func TestConfigClamping(t *testing.T) {
	cases := []struct {
		name  string
		in    Config
		check func(*testing.T, Config)
	}{
		{
			name: "a zero trip rate is unset, not never-trip",
			in:   Config{TripRate: 0},
			check: func(t *testing.T, c Config) {
				if c.TripRate != DefaultConfig().TripRate {
					t.Fatalf("TripRate = %v, want the default", c.TripRate)
				}
			},
		},
		{
			name: "an out-of-range trip rate falls back",
			in:   Config{TripRate: 4.2},
			check: func(t *testing.T, c Config) {
				if c.TripRate != DefaultConfig().TripRate {
					t.Fatalf("TripRate = %v, want the default", c.TripRate)
				}
			},
		},
		{
			name: "a floor above the window would never be reached",
			in:   Config{MinSamples: 500, WindowSize: 20},
			check: func(t *testing.T, c Config) {
				if c.MinSamples != 20 {
					t.Fatalf("MinSamples = %d, want it clamped to the window size 20", c.MinSamples)
				}
			},
		},
		{
			name: "negative values fall back",
			in:   Config{MinSamples: -1, WindowSize: -1, Cooldown: -time.Second, HalfOpenProbes: -3},
			check: func(t *testing.T, c Config) {
				d := DefaultConfig()
				if c.MinSamples != d.MinSamples || c.WindowSize != d.WindowSize ||
					c.Cooldown != d.Cooldown || c.HalfOpenProbes != d.HalfOpenProbes {
					t.Fatalf("negative Config resolved to %+v, want the defaults", c)
				}
			},
		},
		{
			name: "ceilings hold",
			in:   Config{WindowSize: maxWindowSize * 10, HalfOpenProbes: maxHalfOpenProbes * 10, Cooldown: 100 * 24 * time.Hour},
			check: func(t *testing.T, c Config) {
				if c.WindowSize != maxWindowSize || c.HalfOpenProbes != maxHalfOpenProbes || c.Cooldown != maxCooldown {
					t.Fatalf("oversized Config resolved to %+v, want the ceilings", c)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, tc.in.withDefaults())
		})
	}
}

// A NaN trip rate defeats every ordered comparison, so a breaker configured
// with one would never trip and nothing would say why.
func TestNaNTripRateFallsBackAndStillTrips(t *testing.T) {
	nan := math.NaN()
	h := newHarness(t, func(c *Config) { c.TripRate = nan })
	if h.cfg.TripRate != DefaultConfig().TripRate {
		t.Fatalf("TripRate = %v, want the default", h.cfg.TripRate)
	}
	h.reportN(testIssuer, false, h.cfg.MinSamples)
	h.requireState(testIssuer, domain.BreakerOpen, "a NaN trip rate must not disable the breaker")
}

func TestKeyTTLExceedsTheCooldown(t *testing.T) {
	// An open breaker whose key expires mid-cooldown is a closed breaker, so
	// the TTL must outlast the window it is protecting by a wide margin. The
	// extremes matter most: this is the assertion that catches a ceiling
	// lowered later without noticing what depends on it.
	for _, cooldown := range []time.Duration{time.Second, 60 * time.Second, time.Hour, maxCooldown, 100 * maxCooldown} {
		b := New(nil, newTestClock(), Config{Cooldown: cooldown})
		if b.ttlMS < 2*b.cooldownMS {
			t.Fatalf("cooldown %s: ttl %d ms does not comfortably exceed cooldown %d ms", cooldown, b.ttlMS, b.cooldownMS)
		}
		if b.ttlMS < minKeyTTL.Milliseconds() {
			t.Fatalf("cooldown %s: ttl %d ms is below the floor", cooldown, b.ttlMS)
		}
		if b.ttlMS > maxKeyTTL.Milliseconds() {
			t.Fatalf("cooldown %s: ttl %d ms is above the ceiling", cooldown, b.ttlMS)
		}
	}
}

func TestNamespacesIsolateBreakers(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("closing redis client: %v", err)
		}
	})
	clock := newTestClock()
	a := New(rdb, clock, Config{Namespace: "tenant:a"})
	b := New(rdb, clock, Config{Namespace: "tenant:b"})

	ctx := context.Background()
	for i := 0; i < DefaultConfig().MinSamples; i++ {
		if err := a.Report(ctx, testIssuer, false); err != nil {
			t.Fatalf("Report: %v", err)
		}
	}
	st, err := a.State(ctx, testIssuer)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st != domain.BreakerOpen {
		t.Fatalf("tenant a state = %s, want OPEN", st)
	}
	st, err = b.State(ctx, testIssuer)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st != domain.BreakerClosed {
		t.Fatalf("tenant b state = %s, want CLOSED", st)
	}
	states, err := b.States(ctx)
	if err != nil {
		t.Fatalf("States: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("tenant b sees %v, want nothing", states)
	}
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

func TestScriptValueDecoding(t *testing.T) {
	t.Run("integers", func(t *testing.T) {
		for _, v := range []any{int64(7), 7, 7.9, "7", []byte("7")} {
			got, err := asInt(v)
			if err != nil {
				t.Fatalf("asInt(%#v): %v", v, err)
			}
			if got != 7 {
				t.Fatalf("asInt(%#v) = %d, want 7", v, got)
			}
		}
		for _, v := range []any{nil, "seven", struct{}{}} {
			if _, err := asInt(v); err == nil {
				t.Fatalf("asInt(%#v) accepted a non-integer", v)
			}
		}
	})

	t.Run("strings", func(t *testing.T) {
		for _, v := range []any{"OPEN", []byte("OPEN")} {
			got, err := asString(v)
			if err != nil {
				t.Fatalf("asString(%#v): %v", v, err)
			}
			if got != "OPEN" {
				t.Fatalf("asString(%#v) = %q, want OPEN", v, got)
			}
		}
		for _, v := range []any{nil, struct{}{}} {
			if _, err := asString(v); err == nil {
				t.Fatalf("asString(%#v) accepted a non-string", v)
			}
		}
	})
}

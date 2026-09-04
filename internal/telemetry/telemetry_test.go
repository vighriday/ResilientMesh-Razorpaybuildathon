package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// fakeClock is mutex-guarded because the concurrency test shares one Recorder,
// and therefore one clock, across goroutines under -race.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harness struct {
	rec *Recorder
	mr  *miniredis.Miniredis
	clk *fakeClock
	rdb *redis.Client
}

func newHarness(t *testing.T, window time.Duration) harness {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	clk := &fakeClock{now: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)}
	return harness{rec: New(rdb, clk, window), mr: mr, clk: clk, rdb: rdb}
}

func (h harness) record(t *testing.T, issuer, code string, success bool, latency time.Duration) {
	t.Helper()
	if err := h.rec.RecordOutcome(context.Background(), issuer, code, success, latency); err != nil {
		t.Fatalf("RecordOutcome(%q): %v", issuer, err)
	}
}

func (h harness) snapshot(t *testing.T, issuer string) domain.TelemetrySnapshot {
	t.Helper()
	snap, err := h.rec.Snapshot(context.Background(), issuer)
	if err != nil {
		t.Fatalf("Snapshot(%q): %v", issuer, err)
	}
	return snap
}

func (h harness) zcard(t *testing.T, key string) int64 {
	t.Helper()
	n, err := h.rdb.ZCard(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("ZCARD %s: %v", key, err)
	}
	return n
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

// ---------------------------------------------------------------------------
// Rate math
// ---------------------------------------------------------------------------

func TestSnapshotRateMath(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 0; i < 7; i++ {
		h.record(t, "card:HDFC", "", true, 20*time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		h.record(t, "card:HDFC", "bank_technical_error", false, 900*time.Millisecond)
	}

	snap := h.snapshot(t, "card:HDFC")
	if snap.IssuerKey != "card:HDFC" {
		t.Errorf("IssuerKey = %q, want card:HDFC", snap.IssuerKey)
	}
	if snap.Attempts != 10 || snap.Successes != 7 || snap.Failures != 3 {
		t.Errorf("attempts/successes/failures = %d/%d/%d, want 10/7/3",
			snap.Attempts, snap.Successes, snap.Failures)
	}
	if !approx(snap.SuccessRate, 0.7) {
		t.Errorf("SuccessRate = %v, want 0.7", snap.SuccessRate)
	}
	if snap.WindowSeconds != 60 {
		t.Errorf("WindowSeconds = %d, want 60", snap.WindowSeconds)
	}
	if !snap.SampledAt.Equal(h.clk.Now()) {
		t.Errorf("SampledAt = %v, want %v", snap.SampledAt, h.clk.Now())
	}
	// The breaker owns this field; telemetry must not invent one.
	if snap.BreakerState != "" {
		t.Errorf("BreakerState = %q, want empty", snap.BreakerState)
	}
}

func TestSnapshotOfUnknownIssuerIsEmptyNotAnError(t *testing.T) {
	h := newHarness(t, time.Minute)
	snap := h.snapshot(t, "netbanking:SBIN")
	if snap.Attempts != 0 || snap.SuccessRate != 0 || snap.BaselineRate != 0 {
		t.Fatalf("unexpected non-empty snapshot: %+v", snap)
	}
	if snap.Degraded() {
		t.Error("an issuer with no samples must not be reported degraded")
	}
	if snap.WindowSeconds != 60 {
		t.Errorf("WindowSeconds = %d, want 60", snap.WindowSeconds)
	}
}

// ---------------------------------------------------------------------------
// Member uniqueness: the ZADD overwrite bug
// ---------------------------------------------------------------------------

// TestIdenticalOutcomesInSameMillisecondAllCount is the regression test for the
// member-collision bug. Every field except the uniqueness suffix is identical
// across these five events, so an encoding without the suffix would ZADD the
// same member five times and leave a set of cardinality one.
func TestIdenticalOutcomesInSameMillisecondAllCount(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 0; i < 5; i++ {
		h.record(t, "card:HDFC", "bank_technical_error", false, 250*time.Millisecond)
	}

	if got := h.zcard(t, "tel:z:card:HDFC"); got != 5 {
		t.Fatalf("issuer set cardinality = %d, want 5 (members collided on ZADD)", got)
	}
	if got := h.zcard(t, "tel:m:card"); got != 5 {
		t.Fatalf("method set cardinality = %d, want 5", got)
	}

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != 5 || snap.Failures != 5 {
		t.Fatalf("attempts/failures = %d/%d, want 5/5", snap.Attempts, snap.Failures)
	}
	// Under-counting here would hold Attempts below the evidence floor and keep
	// the breaker closed through the outage.
	if snap.Attempts < domain.DegradedMinSamples-3 {
		t.Fatalf("sample count too low to be useful: %d", snap.Attempts)
	}
}

func TestTwoRecordersDoNotCollideOnMembers(t *testing.T) {
	h := newHarness(t, time.Minute)
	second := New(h.rdb, h.clk, time.Minute)

	h.record(t, "card:HDFC", "server_error", false, 100*time.Millisecond)
	if err := second.RecordOutcome(context.Background(), "card:HDFC", "server_error", false, 100*time.Millisecond); err != nil {
		t.Fatalf("second recorder RecordOutcome: %v", err)
	}

	if got := h.zcard(t, "tel:z:card:HDFC"); got != 2 {
		t.Fatalf("cardinality = %d, want 2: per-process nonce failed to disambiguate", got)
	}
}

// ---------------------------------------------------------------------------
// Window trimming
// ---------------------------------------------------------------------------

func TestWindowTrimDropsAgedEventsFromReadAndStorage(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 0; i < 3; i++ {
		h.record(t, "card:HDFC", "payment_timed_out", false, 500*time.Millisecond)
	}
	if got := h.snapshot(t, "card:HDFC").Attempts; got != 3 {
		t.Fatalf("attempts before advance = %d, want 3", got)
	}

	h.clk.Advance(61 * time.Second)

	// The read excludes them immediately, before any write has trimmed.
	if got := h.snapshot(t, "card:HDFC").Attempts; got != 0 {
		t.Fatalf("attempts after advance = %d, want 0", got)
	}
	if got := h.zcard(t, "tel:z:card:HDFC"); got != 3 {
		t.Fatalf("storage should still hold %d aged members until the next write, got %d", 3, got)
	}

	// The next write trims, so the set stays bounded rather than growing for
	// the lifetime of a busy issuer.
	h.record(t, "card:HDFC", "", true, 10*time.Millisecond)

	if got := h.zcard(t, "tel:z:card:HDFC"); got != 1 {
		t.Fatalf("issuer set cardinality after trim = %d, want 1", got)
	}
	if got := h.zcard(t, "tel:m:card"); got != 1 {
		t.Fatalf("method set cardinality after trim = %d, want 1", got)
	}

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != 1 || snap.Successes != 1 {
		t.Fatalf("attempts/successes = %d/%d, want 1/1", snap.Attempts, snap.Successes)
	}
	if !approx(snap.SuccessRate, 1.0) {
		t.Errorf("SuccessRate = %v, want 1.0", snap.SuccessRate)
	}
}

func TestEventExactlyOnWindowBoundaryIsRetained(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "card:HDFC", "server_error", false, 0)

	// Advancing by exactly the window puts the event on the cutoff. Read and
	// trim must agree that it is still inside.
	h.clk.Advance(time.Minute)
	if got := h.snapshot(t, "card:HDFC").Attempts; got != 1 {
		t.Fatalf("attempts at boundary = %d, want 1", got)
	}

	h.record(t, "card:HDFC", "server_error", false, 0)
	if got := h.zcard(t, "tel:z:card:HDFC"); got != 2 {
		t.Fatalf("boundary member was trimmed: cardinality = %d, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// Portfolio baseline
// ---------------------------------------------------------------------------

func TestBaselineIsThePerMethodPortfolioRate(t *testing.T) {
	h := newHarness(t, time.Minute)

	for i := 0; i < 8; i++ {
		h.record(t, "card:HDFC", "", true, 30*time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		h.record(t, "card:HDFC", "server_error", false, 30*time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		h.record(t, "card:ICICI", "issuer_down", false, 3*time.Second)
	}
	// A different method must not move the card baseline.
	for i := 0; i < 10; i++ {
		h.record(t, "upi:okaxis", "", true, 15*time.Millisecond)
	}

	hdfc := h.snapshot(t, "card:HDFC")
	if !approx(hdfc.SuccessRate, 0.8) {
		t.Errorf("HDFC SuccessRate = %v, want 0.8", hdfc.SuccessRate)
	}
	if !approx(hdfc.BaselineRate, 0.4) {
		t.Errorf("HDFC BaselineRate = %v, want 0.4 (8 of 20 card attempts)", hdfc.BaselineRate)
	}

	icici := h.snapshot(t, "card:ICICI")
	if !approx(icici.SuccessRate, 0.0) {
		t.Errorf("ICICI SuccessRate = %v, want 0", icici.SuccessRate)
	}
	if !approx(icici.BaselineRate, 0.4) {
		t.Errorf("ICICI BaselineRate = %v, want 0.4", icici.BaselineRate)
	}
	if !icici.Degraded() {
		t.Error("a wholly failing issuer with 10 samples must read as degraded")
	}

	upi := h.snapshot(t, "upi:okaxis")
	if !approx(upi.SuccessRate, 1.0) || !approx(upi.BaselineRate, 1.0) {
		t.Errorf("upi rate/baseline = %v/%v, want 1.0/1.0", upi.SuccessRate, upi.BaselineRate)
	}
}

func TestBaselineWindowTracksTheSameCutoffAsTheIssuerWindow(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 0; i < 10; i++ {
		h.record(t, "card:ICICI", "", true, time.Millisecond)
	}
	h.clk.Advance(61 * time.Second)
	for i := 0; i < 4; i++ {
		h.record(t, "card:HDFC", "issuer_down", false, time.Second)
	}

	snap := h.snapshot(t, "card:HDFC")
	if !approx(snap.BaselineRate, 0.0) {
		t.Fatalf("BaselineRate = %v, want 0: aged peer successes must not prop up the baseline", snap.BaselineRate)
	}
}

// ---------------------------------------------------------------------------
// P95
// ---------------------------------------------------------------------------

func TestPercentile95NearestRank(t *testing.T) {
	cases := []struct {
		name string
		in   []int64
		want int64
	}{
		{"empty", nil, 0},
		{"single", []int64{42}, 42},
		{"two", []int64{5, 900}, 900},
		{"twenty", seqMS(20), 19},
		{"hundred", seqMS(100), 95},
		{"unsorted input", []int64{9, 1, 5, 3, 7}, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := percentile95(tc.in); got != tc.want {
				t.Fatalf("percentile95(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestP95ThroughRedisWindow(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 1; i <= 100; i++ {
		h.record(t, "card:HDFC", "server_error", false, time.Duration(i)*time.Millisecond)
	}
	if got := h.snapshot(t, "card:HDFC").P95LatencyMS; got != 95 {
		t.Fatalf("P95LatencyMS = %d, want 95", got)
	}
}

func TestLatencyIsClamped(t *testing.T) {
	h := newHarness(t, time.Minute)

	// A negative sample means the caller measured across a clock adjustment.
	h.record(t, "card:HDFC", "server_error", false, -5*time.Second)
	if got := h.snapshot(t, "card:HDFC").P95LatencyMS; got != 0 {
		t.Fatalf("negative latency recorded as %d, want 0", got)
	}

	h2 := newHarness(t, time.Minute)
	h2.record(t, "card:HDFC", "server_error", false, 5*time.Hour)
	if got := h2.snapshot(t, "card:HDFC").P95LatencyMS; got != maxLatencyMS {
		t.Fatalf("oversized latency recorded as %d, want %d", got, maxLatencyMS)
	}
}

func seqMS(n int) []int64 {
	out := make([]int64, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, int64(i))
	}
	return out
}

// ---------------------------------------------------------------------------
// Error code histogram
// ---------------------------------------------------------------------------

func TestTopErrorCodesOrderingIsStableAndCapped(t *testing.T) {
	h := newHarness(t, time.Minute)
	counts := map[string]int{
		"e1": 5, "e2": 4, "e3": 3, "e4": 2, "e5": 2, "e6": 1, "e7": 1,
	}
	// Iterate a sorted key list so the write order itself is deterministic;
	// what is under test is the read ordering, not the writes.
	for _, code := range []string{"e1", "e2", "e3", "e4", "e5", "e6", "e7"} {
		for i := 0; i < counts[code]; i++ {
			h.record(t, "card:HDFC", code, false, time.Millisecond)
		}
	}

	want := []domain.CodeCount{
		{Code: "e1", Count: 5},
		{Code: "e2", Count: 4},
		{Code: "e3", Count: 3},
		{Code: "e4", Count: 2},
		{Code: "e5", Count: 2},
	}

	// Repeat: Go randomises map iteration per range, so a single pass would
	// pass by luck even if the ordering were unstable.
	for round := 0; round < 25; round++ {
		got := h.snapshot(t, "card:HDFC").TopErrorCodes
		if len(got) != len(want) {
			t.Fatalf("round %d: got %d codes, want %d (%+v)", round, len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("round %d: position %d = %+v, want %+v", round, i, got[i], want[i])
			}
		}
	}
}

func TestSuccessCarriesNoErrorCode(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "card:HDFC", "should_not_appear", true, time.Millisecond)
	if got := h.snapshot(t, "card:HDFC").TopErrorCodes; len(got) != 0 {
		t.Fatalf("TopErrorCodes = %+v, want none on a successful attempt", got)
	}
}

func TestErrorCodeWithDelimiterAndControlBytesRoundTrips(t *testing.T) {
	h := newHarness(t, time.Minute)
	// A pipe would split the member, a percent would be read as an escape, and
	// a NUL is the classic delimiter-injection byte.
	raw := "WE|IRD\x00CODE%41"
	h.record(t, "card:HDFC", raw, false, time.Millisecond)

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != 1 || snap.Failures != 1 {
		t.Fatalf("attempts/failures = %d/%d, want 1/1: member encoding was corrupted",
			snap.Attempts, snap.Failures)
	}
	if len(snap.TopErrorCodes) != 1 {
		t.Fatalf("TopErrorCodes = %+v, want one entry", snap.TopErrorCodes)
	}
	if want := strings.ToLower(raw); snap.TopErrorCodes[0].Code != want {
		t.Fatalf("code = %q, want %q", snap.TopErrorCodes[0].Code, want)
	}
}

func TestOversizedErrorCodeIsTruncatedNotRejected(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "card:HDFC", strings.Repeat("z", 4096), false, time.Millisecond)

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1: an oversized label must not drop the sample", snap.Attempts)
	}
	if got := len(snap.TopErrorCodes[0].Code); got != maxErrorCodeLen {
		t.Fatalf("stored code length = %d, want %d", got, maxErrorCodeLen)
	}
}

func TestUndecodableMembersAreExcludedFromCounters(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "card:HDFC", "", true, time.Millisecond)
	h.record(t, "card:HDFC", "server_error", false, time.Millisecond)

	// A member from an encoding this build does not understand, e.g. mid-deploy.
	score := float64(h.clk.Now().UnixMilli())
	for _, junk := range []string{"9|1|1|0|x|y", "not-a-member", "1|abc|1|0||z"} {
		if err := h.rdb.ZAdd(context.Background(), "tel:z:card:HDFC",
			redis.Z{Score: score, Member: junk}).Err(); err != nil {
			t.Fatalf("seed junk member: %v", err)
		}
	}

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != 2 || snap.Successes != 1 || snap.Failures != 1 {
		t.Fatalf("attempts/successes/failures = %d/%d/%d, want 2/1/1: undecodable members must not be charged to either column",
			snap.Attempts, snap.Successes, snap.Failures)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentRecordOutcomeLosesNothing(t *testing.T) {
	h := newHarness(t, time.Minute)

	const (
		workers = 8
		perWork = 64
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWork)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWork; i++ {
				success := i%2 == 0
				code := ""
				if !success {
					code = "bank_technical_error"
				}
				// The clock never advances, so every one of these 512 events
				// carries the same timestamp and one of only two payloads:
				// the strongest possible test of member uniqueness.
				if err := h.rec.RecordOutcome(context.Background(), "card:HDFC", code, success, 10*time.Millisecond); err != nil {
					errs <- fmt.Errorf("worker %d: %w", w, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent RecordOutcome: %v", err)
	}

	snap := h.snapshot(t, "card:HDFC")
	if snap.Attempts != workers*perWork {
		t.Fatalf("Attempts = %d, want %d", snap.Attempts, workers*perWork)
	}
	if snap.Successes != workers*perWork/2 || snap.Failures != workers*perWork/2 {
		t.Fatalf("successes/failures = %d/%d, want %d/%d",
			snap.Successes, snap.Failures, workers*perWork/2, workers*perWork/2)
	}
	if !approx(snap.SuccessRate, 0.5) {
		t.Fatalf("SuccessRate = %v, want 0.5", snap.SuccessRate)
	}
}

func TestConcurrentSnapshotAndRecordAreRaceFree(t *testing.T) {
	h := newHarness(t, time.Minute)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := h.rec.RecordOutcome(ctx, "upi:okhdfcbank", "upi_psp_error", i%3 == 0, 5*time.Millisecond); err != nil {
				t.Errorf("RecordOutcome: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := h.rec.SnapshotAll(ctx); err != nil {
				t.Errorf("SnapshotAll: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TTL
// ---------------------------------------------------------------------------

func TestTTLIsSetOnEveryKeyAndIdleTelemetryExpires(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "card:HDFC", "server_error", false, time.Millisecond)

	wantTTL := time.Minute * ttlMultiplier
	for _, key := range []string{"tel:z:card:HDFC", "tel:m:card"} {
		if got := h.mr.TTL(key); got != wantTTL {
			t.Fatalf("TTL(%s) = %v, want %v", key, got, wantTTL)
		}
	}

	// An issuer that goes quiet must cost nothing: no sweeper runs in this
	// system, so the TTL is the only thing bounding Redis memory.
	h.mr.FastForward(wantTTL + time.Second)
	for _, key := range []string{"tel:z:card:HDFC", "tel:m:card"} {
		if h.mr.Exists(key) {
			t.Fatalf("key %s survived its TTL", key)
		}
	}

	all, err := h.rec.SnapshotAll(context.Background())
	if err != nil {
		t.Fatalf("SnapshotAll after expiry: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("SnapshotAll = %+v, want empty after expiry", all)
	}
}

func TestTTLIsRefreshedByEveryWrite(t *testing.T) {
	h := newHarness(t, time.Minute)
	wantTTL := time.Minute * ttlMultiplier

	h.record(t, "card:HDFC", "server_error", false, time.Millisecond)
	h.mr.FastForward(2 * time.Minute)
	if !h.mr.Exists("tel:z:card:HDFC") {
		t.Fatal("key expired early")
	}

	h.clk.Advance(2 * time.Minute)
	h.record(t, "card:HDFC", "server_error", false, time.Millisecond)
	if got := h.mr.TTL("tel:z:card:HDFC"); got != wantTTL {
		t.Fatalf("TTL after second write = %v, want %v (a busy issuer must never expire)", got, wantTTL)
	}
}

// ---------------------------------------------------------------------------
// SnapshotAll
// ---------------------------------------------------------------------------

func TestSnapshotAllIsSortedAndIgnoresForeignKeys(t *testing.T) {
	h := newHarness(t, time.Minute)

	for i := 0; i < 4; i++ {
		h.record(t, "upi:okaxis", "upi_psp_error", false, 2*time.Second)
	}
	for i := 0; i < 6; i++ {
		h.record(t, "card:HDFC", "", true, 20*time.Millisecond)
	}
	for i := 0; i < 4; i++ {
		h.record(t, "card:ICICI", "issuer_down", false, 3*time.Second)
	}

	// A key under our prefix whose identity we cannot decode, and a key that
	// must not match the SCAN pattern at all.
	if err := h.mr.Set("tel:z:bad%ZZ", "x"); err != nil {
		t.Fatalf("seed undecodable key: %v", err)
	}
	if err := h.mr.Set("unrelated:key", "x"); err != nil {
		t.Fatalf("seed unrelated key: %v", err)
	}

	all, err := h.rec.SnapshotAll(context.Background())
	if err != nil {
		t.Fatalf("SnapshotAll: %v", err)
	}
	gotKeys := make([]string, 0, len(all))
	for _, s := range all {
		gotKeys = append(gotKeys, s.IssuerKey)
	}
	want := []string{"card:HDFC", "card:ICICI", "upi:okaxis"}
	if len(gotKeys) != len(want) {
		t.Fatalf("SnapshotAll keys = %v, want %v", gotKeys, want)
	}
	for i := range want {
		if gotKeys[i] != want[i] {
			t.Fatalf("SnapshotAll keys = %v, want %v (sorted)", gotKeys, want)
		}
	}

	byKey := map[string]domain.TelemetrySnapshot{}
	for _, s := range all {
		byKey[s.IssuerKey] = s
	}
	// card portfolio: 6 successes out of 10 attempts.
	if !approx(byKey["card:HDFC"].BaselineRate, 0.6) || !approx(byKey["card:ICICI"].BaselineRate, 0.6) {
		t.Fatalf("card baselines = %v / %v, want 0.6 each",
			byKey["card:HDFC"].BaselineRate, byKey["card:ICICI"].BaselineRate)
	}
	if !approx(byKey["upi:okaxis"].BaselineRate, 0.0) {
		t.Fatalf("upi baseline = %v, want 0", byKey["upi:okaxis"].BaselineRate)
	}
	if !approx(byKey["card:HDFC"].SuccessRate, 1.0) {
		t.Fatalf("HDFC SuccessRate = %v, want 1.0", byKey["card:HDFC"].SuccessRate)
	}
}

func TestSnapshotAllAgreesWithSnapshot(t *testing.T) {
	h := newHarness(t, time.Minute)
	for i := 0; i < 9; i++ {
		h.record(t, "netbanking:SBIN", "gateway_error", i%3 == 0, time.Duration(i)*time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		h.record(t, "netbanking:UTIB", "", true, time.Millisecond)
	}

	all, err := h.rec.SnapshotAll(context.Background())
	if err != nil {
		t.Fatalf("SnapshotAll: %v", err)
	}
	for _, batched := range all {
		single := h.snapshot(t, batched.IssuerKey)
		if single.Attempts != batched.Attempts ||
			!approx(single.SuccessRate, batched.SuccessRate) ||
			!approx(single.BaselineRate, batched.BaselineRate) ||
			single.P95LatencyMS != batched.P95LatencyMS {
			t.Fatalf("SnapshotAll and Snapshot disagree for %s:\n batched=%+v\n single =%+v",
				batched.IssuerKey, batched, single)
		}
	}
}

func TestSnapshotAllOnEmptyKeyspace(t *testing.T) {
	h := newHarness(t, time.Minute)
	all, err := h.rec.SnapshotAll(context.Background())
	if err != nil {
		t.Fatalf("SnapshotAll: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("SnapshotAll = %+v, want empty", all)
	}
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

func TestIssuerKeysWithGlobMetacharactersStayIsolated(t *testing.T) {
	h := newHarness(t, time.Minute)

	// A merchant controls the bank field, so it can carry a SCAN pattern.
	h.record(t, "card:HD*", "server_error", false, time.Millisecond)
	for i := 0; i < 3; i++ {
		h.record(t, "card:HDX", "", true, time.Millisecond)
	}

	star := h.snapshot(t, "card:HD*")
	if star.Attempts != 1 {
		t.Fatalf("card:HD* attempts = %d, want 1: escaping collapsed two issuers", star.Attempts)
	}
	plain := h.snapshot(t, "card:HDX")
	if plain.Attempts != 3 {
		t.Fatalf("card:HDX attempts = %d, want 3", plain.Attempts)
	}

	all, err := h.rec.SnapshotAll(context.Background())
	if err != nil {
		t.Fatalf("SnapshotAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("SnapshotAll returned %d issuers, want 2", len(all))
	}
	// The key must round-trip exactly, or the breaker and the console would key
	// off different strings for the same issuer.
	if all[0].IssuerKey != "card:HD*" || all[1].IssuerKey != "card:HDX" {
		t.Fatalf("issuer keys = %q, %q; want card:HD*, card:HDX", all[0].IssuerKey, all[1].IssuerKey)
	}
}

func TestEscapeRoundTrip(t *testing.T) {
	cases := []string{
		"card:HDFC",
		"upi:okhdfcbank",
		"wallet:paytm",
		"card:HD*",
		"a%b",
		"has space",
		"tab\there",
		"nul\x00byte",
		"unicode-\u20b9",
		"",
	}
	for _, in := range cases {
		enc := escapeSegment(in)
		for _, meta := range []string{"*", "?", "[", "]", "|"} {
			if strings.Contains(enc, meta) {
				t.Fatalf("escapeSegment(%q) = %q, still contains %q", in, enc, meta)
			}
		}
		out, err := unescapeSegment(enc)
		if err != nil {
			t.Fatalf("unescapeSegment(%q): %v", enc, err)
		}
		if out != in {
			t.Fatalf("round trip of %q gave %q", in, out)
		}
	}
}

func TestUnescapeRejectsMalformedInput(t *testing.T) {
	for _, in := range []string{"%", "%4", "%ZZ", "abc%G1", "%4%41"} {
		if _, err := unescapeSegment(in); !errors.Is(err, errMalformedEscape) {
			t.Fatalf("unescapeSegment(%q) error = %v, want errMalformedEscape", in, err)
		}
	}
}

func TestIssuerKeyValidation(t *testing.T) {
	h := newHarness(t, time.Minute)
	ctx := context.Background()

	cases := []struct {
		name string
		key  string
		want error
	}{
		{"empty", "", ErrEmptyIssuerKey},
		{"whitespace only", "   \t ", ErrEmptyIssuerKey},
		{"too long", strings.Repeat("k", maxIssuerKeyLen+1), ErrIssuerKeyTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.rec.RecordOutcome(ctx, tc.key, "x", false, 0); !errors.Is(err, tc.want) {
				t.Errorf("RecordOutcome error = %v, want %v", err, tc.want)
			}
			if _, err := h.rec.Snapshot(ctx, tc.key); !errors.Is(err, tc.want) {
				t.Errorf("Snapshot error = %v, want %v", err, tc.want)
			}
		})
	}

	// A rejected key must leave nothing behind.
	if keys := h.mr.Keys(); len(keys) != 0 {
		t.Fatalf("rejected keys wrote to redis: %v", keys)
	}
}

func TestIssuerKeyIsTrimmedConsistently(t *testing.T) {
	h := newHarness(t, time.Minute)
	h.record(t, "  card:HDFC  ", "server_error", false, time.Millisecond)
	if got := h.snapshot(t, "card:HDFC").Attempts; got != 1 {
		t.Fatalf("attempts = %d, want 1: write and read normalised the key differently", got)
	}
}

func TestMethodOf(t *testing.T) {
	cases := map[string]string{
		"card:HDFC":       "card",
		"UPI:okaxis":      "upi",
		"wallet:paytm":    "wallet",
		"netbanking:SBIN": "netbanking",
		"nocolon":         "unknown",
		":leading":        "unknown",
	}
	for in, want := range cases {
		if got := methodOf(in); got != want {
			t.Errorf("methodOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Construction and failure propagation
// ---------------------------------------------------------------------------

func TestNewNormalisesUnusableWindow(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})

	// A sub-second window cannot be represented in WindowSeconds.
	for _, w := range []time.Duration{0, -time.Minute, 999 * time.Millisecond} {
		if got := New(rdb, nil, w).Window(); got != DefaultWindow {
			t.Errorf("New(window=%v).Window() = %v, want %v", w, got, DefaultWindow)
		}
	}
	if got := New(rdb, nil, 90*time.Second).Window(); got != 90*time.Second {
		t.Errorf("Window() = %v, want 90s", got)
	}

	// A nil clock must still produce a usable recorder rather than panicking on
	// first use.
	rec := New(rdb, nil, time.Minute)
	if err := rec.RecordOutcome(context.Background(), "card:HDFC", "server_error", false, time.Millisecond); err != nil {
		t.Fatalf("RecordOutcome with default clock: %v", err)
	}
	snap, err := rec.Snapshot(context.Background(), "card:HDFC")
	if err != nil {
		t.Fatalf("Snapshot with default clock: %v", err)
	}
	if snap.Attempts != 1 {
		t.Fatalf("Attempts = %d, want 1", snap.Attempts)
	}
	if snap.SampledAt.IsZero() {
		t.Fatal("SampledAt is zero with the default clock")
	}
}

func TestRedisFailuresPropagateWrapped(t *testing.T) {
	h := newHarness(t, time.Minute)
	ctx := context.Background()

	h.mr.SetError("BOOM simulated redis failure")
	t.Cleanup(func() { h.mr.SetError("") })

	if err := h.rec.RecordOutcome(ctx, "card:HDFC", "server_error", false, 0); err == nil {
		t.Error("RecordOutcome swallowed a redis failure")
	} else if !strings.Contains(err.Error(), "telemetry: record outcome") {
		t.Errorf("RecordOutcome error not wrapped with context: %v", err)
	}
	if _, err := h.rec.Snapshot(ctx, "card:HDFC"); err == nil {
		t.Error("Snapshot swallowed a redis failure")
	} else if !strings.Contains(err.Error(), "telemetry: snapshot") {
		t.Errorf("Snapshot error not wrapped with context: %v", err)
	}
	if _, err := h.rec.SnapshotAll(ctx); err == nil {
		t.Error("SnapshotAll swallowed a redis failure")
	} else if !strings.Contains(err.Error(), "telemetry: scan issuer keys") {
		t.Errorf("SnapshotAll error not wrapped with context: %v", err)
	}
}

func TestRecorderSatisfiesDomainPort(t *testing.T) {
	h := newHarness(t, time.Minute)
	var port domain.TelemetryRecorder = h.rec
	if err := port.RecordOutcome(context.Background(), "card:HDFC", "server_error", false, time.Millisecond); err != nil {
		t.Fatalf("through port: %v", err)
	}
	if _, err := port.SnapshotAll(context.Background()); err != nil {
		t.Fatalf("through port: %v", err)
	}
}

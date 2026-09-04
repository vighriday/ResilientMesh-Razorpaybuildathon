package obs

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

const epsilon = 1e-9

func nearly(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > epsilon {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

// TestHistogramPercentilesAgainstKnownDistribution pins the interpolation
// against a distribution whose true percentiles are known exactly: the integers
// 1..100, one observation each. Every bucket edge coincides with a rank here,
// so a correct linear interpolation reproduces the exact percentile and any
// off-by-one in the cumulative count shows up immediately.
func TestHistogramPercentilesAgainstKnownDistribution(t *testing.T) {
	h := NewRegistry().Histogram("mesh_gate_latency_ms")
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}

	if got := h.Count(); got != 100 {
		t.Fatalf("Count = %d, want 100", got)
	}
	nearly(t, "Sum", h.Sum(), 5050)
	nearly(t, "P50", h.P50(), 50)
	nearly(t, "P95", h.P95(), 95)
	nearly(t, "P99", h.P99(), 99)

	snap := h.Snapshot()
	nearly(t, "Max", snap.Max, 100)
	want := map[string]uint64{"1": 1, "2": 2, "5": 5, "10": 10, "25": 25, "50": 50, "100": 100, "+Inf": 100}
	for _, b := range snap.Buckets {
		if w, ok := want[b.LE]; ok && b.Count != w {
			t.Errorf("cumulative bucket le=%s = %d, want %d", b.LE, b.Count, w)
		}
	}
}

func TestHistogramEmptyAndSingleSample(t *testing.T) {
	r := NewRegistry()
	empty := r.Histogram("empty")
	if empty.Count() != 0 || empty.Sum() != 0 || empty.P99() != 0 {
		t.Fatalf("empty histogram is not zero-valued: %+v", empty.Snapshot())
	}

	one := r.Histogram("one")
	one.Observe(7)
	// The sample lands in the (5,10] bucket, so the median estimate is the
	// midpoint of that bucket; only Max can report the exact value.
	nearly(t, "P50", one.P50(), 7.5)
	nearly(t, "Max", one.Snapshot().Max, 7)
}

// TestHistogramOverflowReportsObservedMax proves a p99 above the top bound is
// not silently saturated at 5000 ms, which is precisely when an operator needs
// the number.
func TestHistogramOverflowReportsObservedMax(t *testing.T) {
	h := NewRegistry().Histogram("mesh_llm_latency_ms")
	for i := 0; i < 90; i++ {
		h.Observe(10)
	}
	for i := 0; i < 10; i++ {
		h.Observe(31000)
	}

	nearly(t, "P99", h.P99(), 31000)
	snap := h.Snapshot()
	nearly(t, "Max", snap.Max, 31000)

	last := snap.Buckets[len(snap.Buckets)-1]
	if last.LE != "+Inf" || last.Count != 100 {
		t.Fatalf("overflow bucket wrong: %+v", last)
	}
	for _, b := range snap.Buckets {
		if b.LE == "5000" && b.Count != 90 {
			t.Fatalf("cumulative count at le=5000 = %d, want 90", b.Count)
		}
	}
}

// TestHistogramRejectsPoisonSamples matters because a single NaN would make
// encoding/json fail for the entire /metrics response, not just one series.
func TestHistogramRejectsPoisonSamples(t *testing.T) {
	h := NewRegistry().Histogram("poison")
	h.Observe(math.NaN())
	h.Observe(math.Inf(1))
	h.Observe(math.Inf(-1))
	h.Observe(-5)
	if h.Count() != 0 {
		t.Fatalf("invalid samples were recorded: %+v", h.Snapshot())
	}
	h.Observe(3)
	if h.Count() != 1 {
		t.Fatalf("valid sample after invalid ones was lost")
	}
	nearly(t, "Sum", h.Sum(), 3)
}

func TestObserveDurationUsesMilliseconds(t *testing.T) {
	h := NewRegistry().Histogram("mesh_ingest_latency_ms")
	h.ObserveDuration(250 * time.Millisecond)
	h.ObserveDuration(1500 * time.Microsecond)
	nearly(t, "Sum", h.Sum(), 251.5)
	if h.Count() != 2 {
		t.Fatalf("Count = %d, want 2", h.Count())
	}
}

func TestGauge(t *testing.T) {
	g := NewRegistry().Gauge("mesh_sessions_open")
	g.Set(5)
	nearly(t, "Value", g.Value(), 5)
	g.Add(-2)
	nearly(t, "Value", g.Value(), 3)
	g.Set(math.NaN())
	g.Add(math.Inf(1))
	nearly(t, "Value", g.Value(), 3)
}

func TestRegistryReturnsStableInstruments(t *testing.T) {
	r := NewRegistry()
	if r.Counter("a") != r.Counter("a") {
		t.Error("Counter returned different instruments for the same name")
	}
	if r.Gauge("a") != r.Gauge("a") {
		t.Error("Gauge returned different instruments for the same name")
	}
	if r.Histogram("a") != r.Histogram("a") {
		t.Error("Histogram returned different instruments for the same name")
	}
	// Names are normalised, so equivalent spellings must not fork the series.
	r.Counter("mesh webhook/total").Inc()
	if got := r.Counter("mesh_webhook_total").Value(); got != 1 {
		t.Errorf("normalised name did not resolve to the same counter: %d", got)
	}
}

// TestConcurrentWriters is the -race workhorse: creation, mutation, and
// snapshotting all happen simultaneously, which is exactly how the relay,
// worker pool, and /metrics handler use the registry in production.
func TestConcurrentWriters(t *testing.T) {
	const writers, iters = 32, 500
	r := NewRegistry()

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c := r.Counter("mesh_webhooks_total")
			h := r.Histogram("mesh_ingest_latency_ms")
			g := r.Gauge("mesh_sessions_open")
			own := r.Counter(fmt.Sprintf("worker_%d_events", id))
			for j := 0; j < iters; j++ {
				c.Inc()
				own.Add(2)
				h.Observe(float64(j % 120))
				g.Add(1)
				g.Add(-1)
			}
		}(i)
	}
	// Readers run against the same instruments the writers are mutating.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := json.Marshal(r.Snapshot()); err != nil {
					t.Errorf("snapshot is not JSON-encodable: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := r.Counter("mesh_webhooks_total").Value(); got != writers*iters {
		t.Fatalf("counter lost increments: got %d, want %d", got, writers*iters)
	}
	if got := r.Histogram("mesh_ingest_latency_ms").Count(); got != writers*iters {
		t.Fatalf("histogram lost observations: got %d, want %d", got, writers*iters)
	}
	nearly(t, "gauge", r.Gauge("mesh_sessions_open").Value(), 0)
	if got := r.Counter("worker_0_events").Value(); got != 2*iters {
		t.Fatalf("per-goroutine counter = %d, want %d", got, 2*iters)
	}
}

func TestSnapshotShapeIsJSONEncodable(t *testing.T) {
	r := NewRegistry()
	r.Counter("mesh_hmac_failures_total").Add(3)
	r.Gauge("mesh_outbox_pending").Set(17)
	r.Histogram("mesh_ingest_latency_ms").Observe(42)

	blob, err := json.Marshal(r.Snapshot())
	if err != nil {
		t.Fatalf("Snapshot is not JSON-encodable: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(blob, &round); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	counters, ok := round["counters"].(map[string]any)
	if !ok || counters["mesh_hmac_failures_total"] != float64(3) {
		t.Fatalf("counters section wrong: %v", round["counters"])
	}
	gauges := round["gauges"].(map[string]any)
	if gauges["mesh_outbox_pending"] != float64(17) {
		t.Fatalf("gauges section wrong: %v", gauges)
	}
	hist := round["histograms"].(map[string]any)["mesh_ingest_latency_ms"].(map[string]any)
	if hist["count"] != float64(1) {
		t.Fatalf("histogram section wrong: %v", hist)
	}
	if round["dropped_series"] != float64(0) {
		t.Fatalf("dropped_series should be zero: %v", round["dropped_series"])
	}
}

// TestCardinalityCap covers the failure mode where a metric name is derived
// from webhook-controlled data: the map must stop growing, writes must keep
// working, and the degradation must be visible instead of silent.
func TestCardinalityCap(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < maxSeries+50; i++ {
		c := r.Counter(fmt.Sprintf("issuer_%d_failures", i))
		if c == nil {
			t.Fatalf("Counter returned nil at series %d", i)
		}
		c.Inc()
	}
	snap := r.Snapshot()
	counters := snap["counters"].(map[string]uint64)
	if len(counters) > maxSeries {
		t.Fatalf("registry grew past the cap: %d series", len(counters))
	}
	if snap["dropped_series"].(uint64) == 0 {
		t.Fatal("overflow was not reported in the snapshot")
	}
	if counters[overflowSeriesName] == 0 {
		t.Fatal("writes past the cap were dropped instead of folded into the overflow series")
	}
}

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		"mesh_ingest_latency_ms": "mesh_ingest_latency_ms",
		"  spaced  name  ":       "spaced__name",
		"upi:okhdfcbank":         "upi:okhdfcbank",
		"inject\"key\nmore":      "inject_key_more",
		"":                       "unnamed",
		"   ":                    "unnamed",
	}
	for in, want := range cases {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := normalizeName(strings.Repeat("n", maxMetricNameLen*2))
	if len(long) != maxMetricNameLen {
		t.Errorf("long name not capped: %d bytes", len(long))
	}
	// A multi-byte rune cut in half by the length cap must not leave invalid
	// UTF-8 in a JSON object key.
	if got := normalizeName(strings.Repeat("世", 60)); !json.Valid([]byte(fmt.Sprintf("%q", got))) {
		t.Errorf("normalised name is not JSON-safe: %q", got)
	}
}

func TestDefaultRegistryIsShared(t *testing.T) {
	if Default() != Default() {
		t.Fatal("Default returned different registries")
	}
	Default().Counter("obs_default_registry_probe").Inc()
	if Default().Counter("obs_default_registry_probe").Value() == 0 {
		t.Fatal("default registry did not retain the increment")
	}
}

func TestLatencyBucketsCannotBeMutatedByCallers(t *testing.T) {
	got := LatencyBuckets()
	if len(got) != len(latencyBucketsMS) {
		t.Fatalf("LatencyBuckets returned %d bounds, want %d", len(got), len(latencyBucketsMS))
	}
	got[0] = 9999
	if latencyBucketsMS[0] != 1 {
		t.Fatal("LatencyBuckets aliased the package bounds")
	}
}

package obs

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// latencyBucketsMS are the histogram bounds, in milliseconds. They are fixed
// rather than configurable so that a Snapshot from one process is directly
// comparable with a Snapshot from another: bucket boundaries chosen per
// deployment make aggregated percentiles meaningless. The spread covers the
// range that matters here, from an in-memory gate decision to a timed-out
// issuer call.
var latencyBucketsMS = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// LatencyBuckets returns a copy of the bucket bounds, for a console that wants
// to draw the same axis the histograms use. It copies because an exported slice
// is writable by any caller, and a mutated bound would misfile every subsequent
// observation — or, if the length changed, panic inside Observe.
func LatencyBuckets() []float64 {
	out := make([]float64, len(latencyBucketsMS))
	copy(out, latencyBucketsMS)
	return out
}

const (
	// maxMetricNameLen bounds a series name. Names are sometimes derived from
	// issuer keys, which originate in a webhook payload.
	maxMetricNameLen = 128

	// maxSeries caps registry cardinality. A metric map keyed by anything an
	// attacker can vary is an unbounded allocation, i.e. a memory-exhaustion
	// vector dressed up as observability. Past the cap the registry hands back
	// a shared overflow instrument instead of growing.
	maxSeries = 1024

	// overflowSeriesName is where writes land once the cap is hit, so the data
	// is degraded rather than lost and the condition is visible in Snapshot.
	overflowSeriesName = "metrics_overflow"
)

// Registry is a concurrency-safe set of in-process metrics with a JSON-shaped
// Snapshot, which is all /metrics needs and is one fewer dependency than a
// Prometheus client. Instruments are looked up by name and created on demand;
// the returned pointers are stable, so a hot path can resolve once at wiring
// time and then record without touching the registry lock at all.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram

	dropped atomic.Uint64

	overflowCounter   *Counter
	overflowGauge     *Gauge
	overflowHistogram *Histogram
}

var defaultRegistry = NewRegistry()

// Default is the process-wide registry, for wiring in main where threading a
// registry through every constructor buys nothing. Libraries should still take
// a *Registry so their tests can assert on an isolated one.
func Default() *Registry { return defaultRegistry }

// NewRegistry returns an empty registry with its overflow instruments already
// registered, so that the cardinality cap can never make a lookup return nil
// and turn a metrics problem into a nil-pointer panic on a payment path.
func NewRegistry() *Registry {
	r := &Registry{
		counters:          make(map[string]*Counter),
		gauges:            make(map[string]*Gauge),
		histograms:        make(map[string]*Histogram),
		overflowCounter:   &Counter{},
		overflowGauge:     &Gauge{},
		overflowHistogram: newHistogram(),
	}
	r.counters[overflowSeriesName] = r.overflowCounter
	r.gauges[overflowSeriesName] = r.overflowGauge
	r.histograms[overflowSeriesName] = r.overflowHistogram
	return r
}

// Counter returns the monotonic counter called name, creating it if needed.
func (r *Registry) Counter(name string) *Counter {
	return getOrCreate(r, r.counters, normalizeName(name), func() *Counter { return &Counter{} }, r.overflowCounter)
}

// Gauge returns the point-in-time gauge called name, creating it if needed.
func (r *Registry) Gauge(name string) *Gauge {
	return getOrCreate(r, r.gauges, normalizeName(name), func() *Gauge { return &Gauge{} }, r.overflowGauge)
}

// Histogram returns the latency histogram called name, creating it if needed.
// All histograms share the bounds from LatencyBuckets; observations are
// milliseconds.
func (r *Registry) Histogram(name string) *Histogram {
	return getOrCreate(r, r.histograms, normalizeName(name), newHistogram, r.overflowHistogram)
}

// getOrCreate is the read-mostly lookup shared by all three instrument kinds:
// an RLock fast path for the steady state, then a double-checked write lock for
// first use, so two goroutines racing on a new name still share one instrument.
func getOrCreate[T any](r *Registry, m map[string]*T, name string, mk func() *T, overflow *T) *T {
	r.mu.RLock()
	v, ok := m[name]
	r.mu.RUnlock()
	if ok {
		return v
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := m[name]; ok {
		return v
	}
	if r.seriesLocked() >= maxSeries {
		r.dropped.Add(1)
		return overflow
	}
	v = mk()
	m[name] = v
	return v
}

func (r *Registry) seriesLocked() int {
	return len(r.counters) + len(r.gauges) + len(r.histograms)
}

// Snapshot renders every instrument as JSON-encodable values for the /metrics
// endpoint. Every float that reaches it is finite by construction — Observe and
// Set reject NaN and infinity — because encoding/json fails on those, and a
// single poisoned sample would take the whole endpoint down.
func (r *Registry) Snapshot() map[string]any {
	r.mu.RLock()
	counters := make(map[string]uint64, len(r.counters))
	for name, c := range r.counters {
		counters[name] = c.Value()
	}
	gauges := make(map[string]float64, len(r.gauges))
	for name, g := range r.gauges {
		gauges[name] = g.Value()
	}
	histograms := make(map[string]HistogramSnapshot, len(r.histograms))
	for name, h := range r.histograms {
		histograms[name] = h.Snapshot()
	}
	r.mu.RUnlock()

	return map[string]any{
		"counters":       counters,
		"gauges":         gauges,
		"histograms":     histograms,
		"dropped_series": r.dropped.Load(),
	}
}

// normalizeName forces a series name into a bounded, printable identifier.
// Names can be built from issuer keys and other webhook-derived text, and they
// become JSON object keys in Snapshot, so they are filtered rather than
// trusted. Truncation is by bytes and any resulting partial rune is replaced,
// which keeps the output valid UTF-8.
func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > maxMetricNameLen {
		name = name[:maxMetricNameLen]
	}
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == ':', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

// Counter is a monotonic event count. It is unsigned so that "decrement" is not
// expressible: a counter that can go down cannot be differentiated correctly by
// any downstream aggregator.
type Counter struct {
	v atomic.Uint64
}

func (c *Counter) Inc() { c.v.Add(1) }

// Add increases the counter by n, which is the batch form of Inc (one claimed
// outbox batch, n rows dispatched).
func (c *Counter) Add(n uint64) { c.v.Add(n) }

func (c *Counter) Value() uint64 { return c.v.Load() }

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

// Gauge is a point-in-time value such as queue depth or open session count.
// The float64 is stored as its bit pattern in an atomic word so that reads and
// writes stay lock-free on the hot path.
type Gauge struct {
	bits atomic.Uint64
}

// Set replaces the value. Non-finite input is dropped rather than stored: NaN
// and infinity cannot be JSON-encoded, so accepting one here would break the
// /metrics endpoint for every other series in the registry.
func (g *Gauge) Set(v float64) {
	if !finite(v) {
		return
	}
	g.bits.Store(math.Float64bits(v))
}

// Add applies a delta with a compare-and-swap loop, for gauges that are
// incremented and decremented by concurrent owners (open sessions, in-flight
// requests) rather than recomputed from scratch.
func (g *Gauge) Add(delta float64) {
	if !finite(delta) {
		return
	}
	for {
		old := g.bits.Load()
		next := math.Float64frombits(old) + delta
		if !finite(next) {
			return
		}
		if g.bits.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

// Histogram is a fixed-bucket latency distribution in milliseconds.
//
// It is guarded by a mutex rather than per-bucket atomics because Snapshot must
// be internally coherent: a percentile computed from bucket counts that do not
// sum to the recorded total is not merely imprecise, it can fall outside the
// observed range entirely. The critical section is a compare and two adds.
type Histogram struct {
	mu     sync.Mutex
	counts []uint64 // len(latencyBucketsMS)+1; the last slot is the overflow bucket
	count  uint64
	sum    float64
	max    float64
}

func newHistogram() *Histogram {
	return &Histogram{counts: make([]uint64, len(latencyBucketsMS)+1)}
}

// Observe records one measurement in milliseconds. Non-finite and negative
// values are discarded: a negative latency means the caller subtracted a
// wall-clock time across an NTP step, and folding that into sum would corrupt
// every derived statistic for the life of the process.
func (h *Histogram) Observe(ms float64) {
	if !finite(ms) || ms < 0 {
		return
	}
	i := sort.SearchFloat64s(latencyBucketsMS, ms)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts[i]++
	h.count++
	h.sum += ms
	if ms > h.max {
		h.max = ms
	}
}

// ObserveDuration is the form callers actually want, so that no call site has
// to remember which unit the buckets are in.
func (h *Histogram) ObserveDuration(d time.Duration) {
	h.Observe(float64(d) / float64(time.Millisecond))
}

func (h *Histogram) Count() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

func (h *Histogram) Sum() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

func (h *Histogram) P50() float64 { return h.percentile(0.50) }

func (h *Histogram) P95() float64 { return h.percentile(0.95) }

func (h *Histogram) P99() float64 { return h.percentile(0.99) }

func (h *Histogram) percentile(q float64) float64 {
	counts, total, _, max := h.read()
	return quantile(counts, total, max, q)
}

// read copies the whole state under one lock. Every derived statistic is built
// from a single copy so that no two numbers in the same answer come from
// different instants.
func (h *Histogram) read() (counts []uint64, total uint64, sum, max float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	counts = make([]uint64, len(h.counts))
	copy(counts, h.counts)
	return counts, h.count, h.sum, h.max
}

// Bucket is one cumulative bucket: Count observations were at most LE
// milliseconds. LE is a string so the overflow bucket can be "+Inf", which has
// no JSON number representation.
type Bucket struct {
	LE    string `json:"le"`
	Count uint64 `json:"count"`
}

// HistogramSnapshot is a coherent read of one histogram.
type HistogramSnapshot struct {
	Count   uint64   `json:"count"`
	Sum     float64  `json:"sum"`
	Max     float64  `json:"max"`
	P50     float64  `json:"p50"`
	P95     float64  `json:"p95"`
	P99     float64  `json:"p99"`
	Buckets []Bucket `json:"buckets"`
}

// Snapshot copies the state under the lock and derives everything afterwards,
// so percentile arithmetic never runs inside the critical section that
// Observe contends on.
func (h *Histogram) Snapshot() HistogramSnapshot {
	counts, total, sum, max := h.read()

	buckets := make([]Bucket, 0, len(counts))
	var cum uint64
	for i, b := range latencyBucketsMS {
		cum += counts[i]
		buckets = append(buckets, Bucket{LE: strconv.FormatFloat(b, 'f', -1, 64), Count: cum})
	}
	buckets = append(buckets, Bucket{LE: "+Inf", Count: total})

	return HistogramSnapshot{
		Count:   total,
		Sum:     sum,
		Max:     max,
		P50:     quantile(counts, total, max, 0.50),
		P95:     quantile(counts, total, max, 0.95),
		P99:     quantile(counts, total, max, 0.99),
		Buckets: buckets,
	}
}

// quantile interpolates linearly inside the bucket the rank falls in, which is
// the standard histogram estimate: exact when the samples are uniform across
// the bucket, and bounded by the bucket edges otherwise. A rank landing in the
// overflow bucket reports the observed maximum rather than the top bound,
// because saturating a p99 at 5000 ms during an issuer outage hides exactly the
// number an operator is looking for.
func quantile(counts []uint64, total uint64, max, q float64) float64 {
	if total == 0 {
		return 0
	}
	rank := q * float64(total)
	var cum uint64
	lower := 0.0
	for i, upper := range latencyBucketsMS {
		cum += counts[i]
		if float64(cum) >= rank {
			if counts[i] == 0 {
				return lower
			}
			frac := (rank - float64(cum-counts[i])) / float64(counts[i])
			if frac < 0 {
				frac = 0
			}
			if frac > 1 {
				frac = 1
			}
			return lower + (upper-lower)*frac
		}
		lower = upper
	}
	if max > lower {
		return max
	}
	return lower
}

package ratelimit

import (
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is mutex-guarded because the concurrency test reads it from every
// goroutine that calls Allow.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestAllowConsumesBurstThenDenies(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 3, 16, clock)

	for i := 0; i < 3; i++ {
		if !l.Allow("client") {
			t.Fatalf("request %d within burst was denied", i+1)
		}
	}
	if l.Allow("client") {
		t.Fatal("request beyond burst was allowed")
	}
	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
}

func TestTokensRefillAsTheClockAdvances(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 1, 16, clock)

	if !l.Allow("client") {
		t.Fatal("first request denied")
	}
	if l.Allow("client") {
		t.Fatal("second request in the same instant was allowed")
	}
	clock.Advance(time.Second)
	if !l.Allow("client") {
		t.Fatal("request after a full refill interval was denied")
	}
}

func TestBucketsAreIndependentPerKey(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 1, 16, clock)

	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("key a did not exhaust its own bucket")
	}
	if !l.Allow("b") {
		t.Fatal("key b was charged for key a's traffic")
	}
}

// The cap is the whole reason this package exists: a client that mints keys
// must not be able to mint heap.
func TestCapacityIsAHardBound(t *testing.T) {
	clock := newFakeClock()
	l := New(100, 100, 4, clock)

	for i := 0; i < 5000; i++ {
		l.Allow("key-" + strconv.Itoa(i))
	}
	if got := l.Len(); got != 4 {
		t.Fatalf("Len = %d, want the configured capacity 4", got)
	}
	if s := l.Stats(); s.Evictions == 0 {
		t.Fatal("no evictions recorded while the capacity was exceeded")
	}
}

func TestEvictionTakesTheLeastRecentlyUsedKey(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 1, 2, clock)

	l.Allow("a") // a exhausted
	l.Allow("b") // b exhausted, order: b, a
	l.Allow("a") // denied, but touching a makes b the oldest

	l.Allow("c") // evicts b

	if l.Allow("a") {
		t.Fatal("key a was evicted; it should still hold an exhausted bucket")
	}
	if !l.Allow("b") {
		t.Fatal("key b should have been evicted and returned as a fresh bucket")
	}
	if got := l.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
}

func TestIdleBucketsAreReclaimed(t *testing.T) {
	clock := newFakeClock()
	l := NewWithIdleTTL(10, 10, 1000, time.Minute, clock)

	for _, k := range []string{"a", "b", "c"} {
		l.Allow(k)
	}
	if got := l.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3", got)
	}

	clock.Advance(2 * time.Minute)
	l.Allow("d")

	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d after the idle window elapsed, want only the live key", got)
	}
}

// A misconfigured rate must never produce a limiter that silently allows
// everything: rate.Limit(+Inf) is the library's "no limit" sentinel, and 0 or a
// negative value is a typo that would otherwise be honoured.
func TestHostileConstructorArgumentsStillLimit(t *testing.T) {
	for _, rps := range []float64{0, -1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		clock := newFakeClock()
		l := New(rps, 1, 8, clock)
		if !l.Allow("client") {
			t.Fatalf("rps=%v: first request denied", rps)
		}
		if l.Allow("client") {
			t.Fatalf("rps=%v: limiter accepted an unlimited second request", rps)
		}
	}
}

func TestOversizedKeysAreHashedNotTruncated(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 1, 8, clock)

	prefix := strings.Repeat("x", 4*maxKeyLen)
	if !l.Allow(prefix + "-alpha") {
		t.Fatal("first oversized key denied")
	}
	if !l.Allow(prefix + "-beta") {
		t.Fatal("a distinct oversized key shared a bucket with the first, so truncation collided them")
	}
	if l.Allow(prefix + "-alpha") {
		t.Fatal("the first oversized key did not keep its own exhausted bucket")
	}
}

func TestUnattributableTrafficSharesOneBucket(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 1, 8, clock)

	if !l.Allow("") {
		t.Fatal("first unattributable request denied")
	}
	if l.Allow("   ") {
		t.Fatal("blank keys were given separate buckets")
	}
	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d, want a single shared bucket", got)
	}
}

func TestRetryAfterIsBounded(t *testing.T) {
	clock := newFakeClock()
	if got := New(1000, 10, 8, clock).RetryAfter(); got != minRetryAfter {
		t.Fatalf("RetryAfter = %v for a fast limiter, want the %v floor", got, minRetryAfter)
	}
	if got := New(0.001, 10, 8, clock).RetryAfter(); got != maxRetryAfter {
		t.Fatalf("RetryAfter = %v for a slow limiter, want the %v ceiling", got, maxRetryAfter)
	}
}

func TestStatsCountAllowedAndDenied(t *testing.T) {
	clock := newFakeClock()
	l := New(1, 2, 8, clock)

	l.Allow("k")
	l.Allow("k")
	l.Allow("k")

	s := l.Stats()
	if s.Allowed != 2 || s.Denied != 1 || s.Tracked != 1 {
		t.Fatalf("Stats = %+v, want 2 allowed, 1 denied, 1 tracked", s)
	}
}

func TestConcurrentAllowAcrossManyKeys(t *testing.T) {
	clock := newFakeClock()
	const capacity = 32
	l := NewWithIdleTTL(50, 10, capacity, time.Second, clock)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// Far more keys than capacity, so every goroutine races on
				// eviction as well as on lookup.
				l.Allow("key-" + strconv.Itoa((g*7+i)%500))
				if i%50 == 0 {
					clock.Advance(100 * time.Millisecond)
					l.Len()
					l.Stats()
				}
			}
		}(g)
	}
	wg.Wait()

	if got := l.Len(); got > capacity {
		t.Fatalf("Len = %d, exceeded capacity %d", got, capacity)
	}
}

// ---------------------------------------------------------------------------
// Client identification
// ---------------------------------------------------------------------------

func request(remoteAddr string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/razorpay", nil)
	r.RemoteAddr = remoteAddr
	for _, f := range forwarded {
		r.Header.Add(forwardedHeader, f)
	}
	return r
}

func TestClientKeyIgnoresForwardedHeaderByDefault(t *testing.T) {
	r := request("203.0.113.9:51000", "198.51.100.7, 10.0.0.1")
	if got, want := ClientKey(r), "ip:203.0.113.9"; got != want {
		t.Fatalf("ClientKey = %q, want %q: a forgeable header must not decide the bucket", got, want)
	}
}

func TestClientKeyGroupsIPv6ByRoutingPrefix(t *testing.T) {
	a := ClientKey(request("[2001:db8:1:2::1]:443"))
	b := ClientKey(request("[2001:db8:1:2:ffff::99]:443"))
	c := ClientKey(request("[2001:db8:1:3::1]:443"))

	if a != b {
		t.Fatalf("addresses in one /64 produced %q and %q; a client could mint buckets by rotating within its allocation", a, b)
	}
	if a == c {
		t.Fatalf("distinct /64s collapsed onto %q", a)
	}
	if !strings.HasSuffix(a, "/64") {
		t.Fatalf("ClientKey = %q, want a /64 prefix key", a)
	}
}

func TestClientKeyCollapsesMappedIPv4(t *testing.T) {
	if got, want := ClientKey(request("[::ffff:203.0.113.9]:443")), "ip:203.0.113.9"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
}

func TestClientKeyFallsBackWhenPeerIsUnparseable(t *testing.T) {
	if got := ClientKey(request("pipe")); got != unknownKey {
		t.Fatalf("ClientKey = %q, want %q", got, unknownKey)
	}
	if got := ClientKey(nil); got != unknownKey {
		t.Fatalf("ClientKey(nil) = %q, want %q", got, unknownKey)
	}
}

func TestTrustedProxyTakesTheHopTheProxyObserved(t *testing.T) {
	k := KeyExtractor{TrustProxy: true}
	// The client forged "9.9.9.9"; the proxy appended what it actually saw.
	r := request("10.0.0.5:9000", "9.9.9.9, 203.0.113.5")
	if got, want := k.ClientKey(r), "ip:203.0.113.5"; got != want {
		t.Fatalf("ClientKey = %q, want %q: the forged leftmost entry won", got, want)
	}
}

func TestTrustedProxySkipsOurOwnHops(t *testing.T) {
	k := KeyExtractor{
		TrustProxy:     true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	r := request("10.0.0.5:9000", "9.9.9.9, 203.0.113.5, 10.0.0.7, 10.0.0.8")
	if got, want := k.ClientKey(r), "ip:203.0.113.5"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
}

// A client that forges an entry inside our trusted range must not be able to
// hide behind it: the proxy's own appended entry still sits to the right.
func TestForgedTrustedHopDoesNotHideTheClient(t *testing.T) {
	k := KeyExtractor{
		TrustProxy:     true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	r := request("10.0.0.5:9000", "9.9.9.9, 10.0.0.99, 203.0.113.5")
	if got, want := k.ClientKey(r), "ip:203.0.113.5"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
}

func TestForwardedHeaderIgnoredFromAnUntrustedPeer(t *testing.T) {
	k := KeyExtractor{
		TrustProxy:     true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	r := request("203.0.113.9:51000", "198.51.100.7")
	if got, want := k.ClientKey(r), "ip:203.0.113.9"; got != want {
		t.Fatalf("ClientKey = %q, want %q: a direct connection claimed a proxy's authority", got, want)
	}
}

func TestMalformedForwardedChainFallsBackToPeer(t *testing.T) {
	k := KeyExtractor{TrustProxy: true}
	cases := []string{
		"not-an-ip",
		"203.0.113.5, ",
		strings.Repeat("a", maxForwardedEntryLen+1),
		"203.0.113.5, <script>alert(1)</script>",
	}
	for _, xff := range cases {
		r := request("10.0.0.5:9000", xff)
		if got, want := k.ClientKey(r), "ip:10.0.0.5"; got != want {
			t.Fatalf("ClientKey(%q) = %q, want the peer %q", xff, got, want)
		}
	}
}

// A chain long enough to be expensive to walk is abandoned rather than
// followed to its end; the sender does not get to choose how much parsing this
// process does per request.
func TestOverlongTrustedChainFallsBackToPeer(t *testing.T) {
	k := KeyExtractor{
		TrustProxy: true,
		TrustedProxies: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("198.51.100.0/24"),
		},
	}
	hops := []string{"203.0.113.5"}
	for i := 0; i < maxForwardedHops*4; i++ {
		hops = append(hops, "198.51.100."+strconv.Itoa(i%250+1))
	}
	r := request("10.0.0.5:9000", strings.Join(hops, ", "))
	if got, want := k.ClientKey(r), "ip:10.0.0.5"; got != want {
		t.Fatalf("ClientKey = %q, want the peer %q", got, want)
	}
}

func TestAllHopsTrustedFallsBackToPeer(t *testing.T) {
	k := KeyExtractor{
		TrustProxy:     true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	r := request("10.0.0.5:9000", "10.0.0.7, 10.0.0.8")
	if got, want := k.ClientKey(r), "ip:10.0.0.5"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
}

func TestForwardedHeaderSplitAcrossValues(t *testing.T) {
	k := KeyExtractor{
		TrustProxy:     true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	// Some proxies append a second header line rather than extending the first.
	r := request("10.0.0.5:9000", "9.9.9.9, 203.0.113.5", "10.0.0.7")
	if got, want := k.ClientKey(r), "ip:203.0.113.5"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
}

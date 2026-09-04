// Package ratelimit provides the per-client token buckets that guard the
// ResilientMesh HTTP edge.
//
// The token bucket itself is golang.org/x/time/rate. What this package adds is
// the container around it, and that is the part that matters: a fixed-capacity
// LRU with idle eviction. The obvious implementation — map[string]*rate.Limiter
// keyed by client IP — is itself the vulnerability it was written to prevent,
// because the key is chosen by the traffic. Anyone who can vary a source
// address (a botnet, a forged X-Forwarded-For, or one client walking its own
// IPv6 /64) makes that map grow without bound until the process is
// OOM-killed. A rate limiter that the traffic it limits can turn into a
// memory-exhaustion DoS is worse than no rate limiter, because it also carries
// the reassurance that the edge is protected.
//
// Everything here is therefore bounded: the number of buckets, the length of a
// key, the number of forwarding hops parsed, and the eviction work any single
// request can be made to pay for.
package ratelimit

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Defaults for a single-instance payment edge. Capacity is the security-
// relevant one: 10,000 buckets is roughly 2 MB of live heap, which bounds the
// worst case at a number an operator can reason about, while still covering
// far more distinct clients than a demo or a single merchant integration ever
// presents.
const (
	DefaultCapacity = 10_000
	DefaultRPS      = 20
	DefaultBurst    = 40

	// DefaultIdleTTL drops a bucket that has not been used in this long. It is
	// what keeps steady-state memory proportional to *active* clients rather
	// than to every client seen since boot; the LRU cap is only the backstop
	// for a burst that arrives faster than idle keys age out.
	DefaultIdleTTL = 10 * time.Minute
)

const (
	// maxKeyLen bounds a stored key. Over-long keys are hashed rather than
	// truncated: truncation would merge two distinct clients that share a
	// prefix into one bucket, which lets an attacker deliberately collide with
	// a victim's key and exhaust the victim's tokens.
	maxKeyLen = 128

	// unknownKey is the single shared bucket for traffic whose origin cannot
	// be determined. Sharing one bucket is the fail-closed choice: the
	// alternative — a fresh bucket per unattributable request — is unlimited
	// capacity for exactly the requests we understand least.
	unknownKey = "unknown"

	// maxSweepPerCall bounds the idle-eviction work a single Allow performs.
	// Without it the one unlucky request that arrives after a quiet period
	// pays to free the entire map while holding the lock.
	maxSweepPerCall = 64

	// minRetryAfter / maxRetryAfter bound the advice handed to a rejected
	// client. Retry-After: 0 invites an immediate retry storm, and anything
	// beyond a minute is indistinguishable from a hang.
	minRetryAfter = time.Second
	maxRetryAfter = time.Minute
)

// Limiter is a bounded set of per-key token buckets.
//
// One mutex guards both the map and the recency list. rate.Limiter is itself
// concurrency-safe, but the lookup, the LRU reorder, and the eviction are not
// individually atomic, and splitting them across finer locks would buy nothing
// measurable at edge request rates while making the eviction invariant much
// harder to keep true.
type Limiter struct {
	limit    rate.Limit
	burst    int
	capacity int
	idleTTL  time.Duration
	clock    domain.Clock

	mu    sync.Mutex
	order *list.List // most recently used at the front
	index map[string]*list.Element
	stats Stats
}

// bucket is one client's tokens plus the recency stamp the sweep reads.
type bucket struct {
	key  string
	lim  *rate.Limiter
	seen time.Time
}

// Stats is a point-in-time read of limiter behaviour.
//
// Evictions is the interesting number: a rising eviction rate on a
// low-cardinality service means keys are being manufactured, which is the
// signature of a distributed source or a spoofed forwarding header, and it is
// visible here before it is visible anywhere else.
type Stats struct {
	Tracked   int    `json:"tracked"`
	Evictions uint64 `json:"evictions"`
	Allowed   uint64 `json:"allowed"`
	Denied    uint64 `json:"denied"`
}

// New builds a limiter admitting rps requests per second per key, tolerating
// bursts of burst, over at most capacity distinct keys.
//
// Non-positive, NaN, and infinite arguments fall back to the package defaults
// rather than being honoured. rate.Limit(+Inf) in particular is the library's
// "allow everything" sentinel, so accepting it would silently turn a
// misconfigured deployment into an unprotected one — a no-op limiter that
// still looks installed in the middleware chain is the failure mode worth
// engineering against.
func New(rps float64, burst int, capacity int, clock domain.Clock) *Limiter {
	return NewWithIdleTTL(rps, burst, capacity, DefaultIdleTTL, clock)
}

// NewWithIdleTTL is New with an explicit idle window, which tests need in
// order to observe eviction without waiting ten minutes.
func NewWithIdleTTL(rps float64, burst, capacity int, idleTTL time.Duration, clock domain.Clock) *Limiter {
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps <= 0 {
		rps = DefaultRPS
	}
	if burst <= 0 {
		burst = DefaultBurst
	}
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if idleTTL <= 0 {
		idleTTL = DefaultIdleTTL
	}
	if clock == nil {
		clock = systemClock{}
	}
	return &Limiter{
		limit:    rate.Limit(rps),
		burst:    burst,
		capacity: capacity,
		idleTTL:  idleTTL,
		clock:    clock,
		order:    list.New(),
		index:    make(map[string]*list.Element),
	}
}

// Allow consumes one token for key and reports whether the request may
// proceed. A key seen for the first time starts with a full burst, so an
// eviction can only ever be generous to the evicted client, never punitive to
// an innocent one.
func (l *Limiter) Allow(key string) bool {
	key = normalizeKey(key)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()
	l.sweepLocked(now)

	var b *bucket
	if el, ok := l.index[key]; ok {
		b, _ = el.Value.(*bucket)
		b.seen = now
		l.order.MoveToFront(el)
	} else {
		for l.order.Len() >= l.capacity {
			l.evictOldestLocked()
		}
		b = &bucket{key: key, lim: rate.NewLimiter(l.limit, l.burst), seen: now}
		l.index[key] = l.order.PushFront(b)
	}

	ok := b.lim.AllowN(now, 1)
	if ok {
		l.stats.Allowed++
	} else {
		l.stats.Denied++
	}
	return ok
}

// Len reports how many keys are currently tracked. It is a plain read: idle
// buckets are reclaimed by Allow, so a quiescent limiter keeps its last
// working set until traffic resumes.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// Stats returns a coherent copy of the counters for the ops console.
func (l *Limiter) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Tracked = l.order.Len()
	return s
}

// RetryAfter is how long a rejected client should wait for one token, bounded
// into a range that is honest to advertise. The limiter owns this answer
// because only it knows the refill rate; a middleware guessing a constant
// would drift from the configuration the moment either changed.
func (l *Limiter) RetryAfter() time.Duration {
	d := time.Duration(float64(time.Second) / float64(l.limit))
	if d < minRetryAfter {
		return minRetryAfter
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// sweepLocked drops buckets idle for longer than idleTTL, oldest first, and
// stops at the first live one because the list is ordered by last use.
//
// A wall clock that steps backwards simply defers eviction to a later call;
// that is deliberately preferred to reacting to the jump, since a backwards
// step must never be able to evict the buckets that are currently absorbing an
// attack.
func (l *Limiter) sweepLocked(now time.Time) {
	for i := 0; i < maxSweepPerCall; i++ {
		el := l.order.Back()
		if el == nil {
			return
		}
		b, ok := el.Value.(*bucket)
		if !ok || now.Sub(b.seen) < l.idleTTL {
			return
		}
		l.removeLocked(el, b)
	}
}

func (l *Limiter) evictOldestLocked() {
	el := l.order.Back()
	if el == nil {
		return
	}
	b, ok := el.Value.(*bucket)
	if !ok {
		l.order.Remove(el)
		return
	}
	l.removeLocked(el, b)
}

func (l *Limiter) removeLocked(el *list.Element, b *bucket) {
	l.order.Remove(el)
	delete(l.index, b.key)
	l.stats.Evictions++
}

// normalizeKey bounds an arbitrary caller-supplied key. Empty keys collapse
// onto the shared unattributable bucket; over-long keys are replaced by a
// digest so that distinct keys stay distinct however they were constructed.
func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return unknownKey
	}
	if len(key) > maxKeyLen {
		sum := sha256.Sum256([]byte(key))
		return "h:" + hex.EncodeToString(sum[:16])
	}
	return key
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// Client identification
// ---------------------------------------------------------------------------

const (
	// forwardedHeader is the only forwarding header consulted. RFC 7239's
	// Forwarded header is deliberately not parsed: supporting two spellings of
	// the same claim doubles the parser surface and creates a second, less
	// tested path to the same trust decision.
	forwardedHeader = "X-Forwarded-For"

	// maxForwardedHops bounds how many entries are examined, counting from the
	// right. The header is attacker-controlled and can carry thousands of
	// comma-separated entries; parsing all of them is free CPU for the sender.
	maxForwardedHops = 16

	// maxForwardedEntryLen is generous for an IPv6 literal with a port and a
	// zone, and rejects anything longer without parsing it.
	maxForwardedEntryLen = 64

	// ipv6GroupBits groups IPv6 clients by their routing prefix. A single
	// residential or cloud customer routinely holds an entire /64, so keying on
	// the full address lets one client mint 2^64 buckets: that both evades the
	// limit and evicts every other client's bucket from the LRU, which is the
	// more damaging half.
	ipv6GroupBits = 64
)

// KeyExtractor turns a request into a rate-limit key under an explicit trust
// policy.
//
// Blindly honouring X-Forwarded-For is the classic way to make a rate limiter
// decorative: the header is a claim made by the client, so any caller can send
// a fresh value per request, appear as a new client every time, never exhaust a
// bucket, and — worse — pin the limit on a spoofed victim address. The header
// is therefore read only when TrustProxy says a proxy we operate terminates the
// connection, and even then only the portion of the chain that our own
// infrastructure appended is believed.
type KeyExtractor struct {
	// TrustProxy enables reading X-Forwarded-For at all. It must be false
	// whenever the process is reachable directly, which includes the default
	// managed-mode demo.
	TrustProxy bool

	// TrustedProxies are the networks our own reverse proxies occupy. Entries
	// matching these are skipped while walking the chain right to left, so the
	// key becomes the leftmost address that no trusted hop could have forged.
	// Leaving it empty trusts exactly one hop — the address the terminating
	// proxy observed and appended — which is the only claim that is
	// unforgeable without knowing the proxy's own topology.
	TrustedProxies []netip.Prefix
}

// ClientKey derives a bucket key from the transport peer alone, ignoring every
// forwarding header. This is the safe default for a process that is exposed
// directly, and is what the middleware uses unless a deployment explicitly
// configures a proxy it trusts.
func ClientKey(r *http.Request) string {
	return KeyExtractor{}.ClientKey(r)
}

// ClientKey resolves the request to a stable, bounded key under k's policy.
func (k KeyExtractor) ClientKey(r *http.Request) string {
	if r == nil {
		return unknownKey
	}
	peer, ok := parseAddr(hostOnly(r.RemoteAddr))
	if !ok {
		// A RemoteAddr this process cannot parse means the transport is not
		// what we think it is; attributing the request to the shared bucket is
		// the only honest answer.
		return unknownKey
	}
	if !k.TrustProxy {
		return bucketKey(peer)
	}
	if len(k.TrustedProxies) > 0 && !k.trusted(peer) {
		// The connection did not arrive from one of our proxies, so anything
		// it claims about earlier hops is unverifiable. Fall back to the peer,
		// which at least cost the sender a TCP handshake.
		return bucketKey(peer)
	}
	if client, ok := k.forwardedClient(r.Header.Values(forwardedHeader)); ok {
		return bucketKey(client)
	}
	return bucketKey(peer)
}

// forwardedClient walks the forwarding chain from right to left — newest hop
// first — skipping addresses belonging to proxies we operate, and returns the
// first address that is left. Everything to the left of that point was
// appended by, or supplied to, a party we do not control, so it is a claim
// rather than an observation.
// The chain is consumed from the end of the string inward rather than by
// splitting it: an attacker may send a header holding many thousands of
// entries, and splitting materialises all of them before the first one is even
// looked at.
func (k KeyExtractor) forwardedClient(values []string) (netip.Addr, bool) {
	hops := 0
	for vi := len(values) - 1; vi >= 0; vi-- {
		v := values[vi]
		for len(v) > 0 {
			if hops >= maxForwardedHops {
				return netip.Addr{}, false
			}
			hops++

			var raw string
			if c := strings.LastIndexByte(v, ','); c >= 0 {
				raw, v = v[c+1:], v[:c]
			} else {
				raw, v = v, ""
			}
			raw = strings.TrimSpace(raw)
			if raw == "" || len(raw) > maxForwardedEntryLen {
				return netip.Addr{}, false
			}
			addr, ok := parseAddr(hostOnly(raw))
			if !ok {
				// A hop we cannot parse breaks the chain of custody for
				// everything to its left, so stop rather than guess.
				return netip.Addr{}, false
			}
			if k.trusted(addr) {
				continue
			}
			return addr, true
		}
	}
	// Every hop was one of ours, which means no client address was ever
	// recorded. The caller falls back to the peer.
	return netip.Addr{}, false
}

func (k KeyExtractor) trusted(addr netip.Addr) bool {
	for _, p := range k.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// bucketKey renders an address as a key, collapsing IPv6 onto its routing
// prefix and 4-in-6 forms onto plain IPv4 so that one client cannot occupy two
// buckets by changing address family mid-session.
func bucketKey(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return "ip:" + addr.String()
	}
	prefix, err := addr.Prefix(ipv6GroupBits)
	if err != nil {
		return "ip6:" + addr.String()
	}
	return "ip6:" + prefix.String()
}

// hostOnly strips a port from an address literal, tolerating the bracketed
// IPv6 form and bare addresses that carry no port at all.
func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}

func parseAddr(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

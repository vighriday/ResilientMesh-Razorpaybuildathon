// Package httpx is the middleware stack every ResilientMesh HTTP surface is
// mounted behind.
//
// The webhook edge is unauthenticated and internet-facing, the ops API guards
// the audit trail, and the console is a browser page rendering operator data,
// so the three defaults this package enforces are: nothing about an internal
// failure reaches a client, nothing attacker-controlled reaches a log line
// unbounded or unvalidated, and every control fails closed. A middleware that
// degrades to "allow" when it is misconfigured has removed itself from the
// chain while still appearing in it, which is the failure mode worth
// engineering against.
package httpx

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/ratelimit"
)

// Middleware is the standard decorator shape. Everything here is plain
// net/http so that a handler can be tested with httptest and nothing else.
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares outermost-first: Chain(a, b)(h) runs a, then b,
// then h. Nil entries are skipped so that an optional middleware — CORS on a
// deployment with no browser origin — can be threaded through without the call
// site branching.
func Chain(mw ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			if mw[i] != nil {
				next = mw[i](next)
			}
		}
		return next
	}
}

// Base is the ordering every ResilientMesh server mounts, offered as one value
// so the order cannot be got wrong at a call site.
//
// The order is load-bearing. RequestID is outermost so the id exists before
// anything can log or panic. SecurityHeaders runs before any handler can write,
// since headers set after WriteHeader are silently dropped. AccessLog sits
// outside Recover so that a panicking request is logged with the 500 it
// actually returned rather than with a status of zero. Recover is innermost of
// the four so it covers every middleware and handler below it.
func Base(log *slog.Logger, reg *obs.Registry) Middleware {
	return Chain(RequestID(), SecurityHeaders(), AccessLog(log, reg), Recover(log))
}

// ---------------------------------------------------------------------------
// Recover
// ---------------------------------------------------------------------------

// Recover converts a panic into an opaque 500.
//
// The panic value and stack go to the log, never to the response: a panic
// message in this system routinely contains a payment id, a struct dump, or a
// SQL fragment, and a client that can trigger a panic must not be able to read
// the result. The response is byte-identical to any other internal error, so a
// prober cannot use it to tell a crash apart from a rejection.
func Recover(log *slog.Logger) Middleware {
	logger := orDefault(log)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := wrapWriter(w)
			defer func() {
				rv := recover()
				if rv == nil {
					return
				}
				// http.ErrAbortHandler is net/http's documented way for a
				// handler to drop a connection without noise — most often a
				// hijacked or streaming response giving up. Swallowing it would
				// turn a deliberate abort into a bogus 500 and a false alarm.
				if rv == http.ErrAbortHandler {
					panic(rv)
				}
				obs.LoggerFrom(r.Context(), logger).Error("httpx: handler panic",
					slog.String("method", r.Method),
					slog.String("route", routePattern(r)),
					// The redacting handler bounds both of these at 512 bytes,
					// which is enough stack to name the panicking frame.
					slog.String("panic", fmt.Sprint(rv)),
					slog.String("stack", string(debug.Stack())),
				)
				if !rec.wrote {
					Error(rec, http.StatusInternalServerError, CodeInternal)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

// contentSecurityPolicy is written for the embedded console and checkout pages,
// which ship from this binary's embed.FS with no CDN and no external origin.
//
// script-src is 'self' with no 'unsafe-inline': the console renders operator
// data, including issuer keys and audit detail that originate in webhook
// payloads, so an inline-script allowance would hand any stored-XSS bug the
// whole page. That obliges the console to serve its JavaScript as a separate
// same-origin file rather than as an inline <script> block.
//
// style-src keeps 'unsafe-inline' because the pages carry inline CSS by design
// (no build step, works offline). The exposure is style injection — defacement
// and, at the margin, CSS-based exfiltration of DOM structure — which is a far
// smaller surface than script execution, and it is the only allowance made.
//
// base-uri and form-action are stated explicitly because neither falls back to
// default-src: without them an injected <base> or form can retarget the page's
// relative URLs and posts to an attacker's origin.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// permissionsPolicy denies every powerful browser feature. The checkout demo
// needs none of them, including payment=(): it is a simulated checkout, not a
// Payment Request API integration, so denying it costs nothing and removes a
// feature an injected script could otherwise reach.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), " +
	"display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
	"gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), " +
	"publickey-credentials-get=(), screen-wake-lock=(), usb=(), " +
	"xr-spatial-tracking=()"

// APIPathPrefix is the prefix under which every JSON endpoint is mounted, and
// therefore the prefix whose responses must never be cached.
const APIPathPrefix = "/api/"

// SecurityHeaders sets the response headers that constrain a browser.
//
// Strict-Transport-Security is deliberately absent: the demo and the local
// stack are served over http://localhost, and an HSTS header there poisons the
// browser's cache for every other localhost service on the developer's machine.
// TLS termination is a deployment concern, and the header belongs at the
// terminator that actually knows the scheme.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", permissionsPolicy)
			h.Set("Content-Security-Policy", contentSecurityPolicy)

			// API responses carry incident state, telemetry, and audit
			// entries. A shared cache holding any of that — or a browser
			// replaying it from disk after an operator logs out — is a
			// disclosure, so the whole prefix is no-store.
			if strings.HasPrefix(r.URL.Path, APIPathPrefix) {
				h.Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Request id
// ---------------------------------------------------------------------------

// RequestIDHeader is the correlation header, read on the way in and echoed on
// the way out.
const RequestIDHeader = "X-Request-Id"

// maxInboundRequestIDLen matches obs.MaxIDLen so that an id accepted here is
// never silently reshaped downstream.
const maxInboundRequestIDLen = obs.MaxIDLen

var requestIDFallback atomic.Uint64

// RequestID establishes the correlation id for the request.
//
// An inbound X-Request-Id is honoured only when it is short and drawn from the
// identifier alphabet, and is otherwise replaced rather than repaired. An
// unvalidated inbound id is a log-injection primitive: it is stamped on every
// line this request produces, so a value carrying a newline and a fabricated
// JSON object forges log entries, and an unbounded one inflates every line by
// its length. Replacing instead of filtering also avoids the subtler harm of
// two distinct hostile ids sanitising to the same string and merging two
// requests in the trace.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := acceptInboundID(r.Header.Get(RequestIDHeader))
			if id == "" {
				id = newRequestID()
			}
			w.Header().Set(RequestIDHeader, id)
			next.ServeHTTP(w, r.WithContext(obs.WithRequestID(r.Context(), id)))
		})
	}
}

// acceptInboundID returns the header value if it is usable as-is, and ""
// otherwise. The alphabet is what UUIDs, ULIDs, and W3C trace ids are built
// from; anything else is a caller trying something.
func acceptInboundID(v string) string {
	if v == "" || len(v) > maxInboundRequestIDLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return ""
		}
	}
	return v
}

// newRequestID prefers a random UUID and falls back to a process-local counter
// when the entropy source is unavailable. Correlation needs uniqueness within
// this process, not unpredictability, so a degraded entropy source must never
// be a reason to fail a payment request.
func newRequestID() string {
	if id, err := uuid.NewRandom(); err == nil {
		return id.String()
	}
	return "req-" + strconv.FormatUint(requestIDFallback.Add(1), 36)
}

// ---------------------------------------------------------------------------
// Access log
// ---------------------------------------------------------------------------

// maxRouteLen bounds the logged route. Patterns come from this repository's own
// mux, but the bound costs nothing and keeps the field width predictable.
const maxRouteLen = 128

// AccessLog records one line per request and feeds the RED metrics.
//
// The route pattern is logged, never the raw path: raw paths embed payment ids
// and session ids, which makes log cardinality unbounded and turns the log
// index into a searchable list of identifiers. Query strings and bodies are
// never logged at all — the session stream carries its bearer token in the
// query string for EventSource, and one line here would persist it.
//
// A nil registry disables metrics, which is what tests want; a nil logger falls
// back to the process default rather than silently discarding the access log.
func AccessLog(log *slog.Logger, reg *obs.Registry) Middleware {
	logger := orDefault(log)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// time.Since reads the monotonic clock. A domain.Clock is the wall
			// clock and exists for scheduling decisions; measuring elapsed time
			// with one would report negative latencies across an NTP step and
			// poison every histogram it feeds.
			start := time.Now()
			rec := wrapWriter(w)
			method := r.Method

			next.ServeHTTP(rec, r)

			elapsed := time.Since(start)
			// The mux stamps the matched pattern onto the request it was
			// handed, so it is only readable once the handler has returned.
			route := routePattern(r)
			status := rec.statusOrDefault()

			level := slog.LevelInfo
			if status >= http.StatusInternalServerError {
				level = slog.LevelError
			}
			obs.LoggerFrom(r.Context(), logger).LogAttrs(r.Context(), level, "httpx: request",
				slog.String("method", method),
				slog.String("route", route),
				slog.Int("status", status),
				slog.Int64("bytes", rec.bytes),
				slog.Int64("duration_ms", elapsed.Milliseconds()),
			)

			if reg == nil {
				return
			}
			reg.Counter("http_requests_total").Inc()
			reg.Counter("http_responses_" + statusClass(status)).Inc()
			reg.Histogram("http_request_duration_ms").ObserveDuration(elapsed)
			if route != "" {
				// Series cardinality is bounded by the route table, which is
				// compiled in. Deriving it from r.URL.Path instead would let a
				// caller mint metric series, which is the same unbounded-map
				// problem the rate limiter exists to avoid.
				reg.Histogram("http_route_duration_ms." + route).ObserveDuration(elapsed)
			}
		})
	}
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// routePattern returns the mux pattern that matched, or "" when nothing did —
// a 404, or a handler mounted without a mux. It never falls back to the raw
// path, since that is the cardinality hazard this exists to avoid.
func routePattern(r *http.Request) string {
	p := r.Pattern
	if len(p) > maxRouteLen {
		p = p[:maxRouteLen]
	}
	return p
}

// ---------------------------------------------------------------------------
// Body limit
// ---------------------------------------------------------------------------

// DefaultBodyLimit is the webhook cap from the plan: Razorpay payloads are a
// few kilobytes, so a megabyte is generous by three orders of magnitude and
// still bounds what one unauthenticated request can make this process allocate.
const DefaultBodyLimit int64 = 1 << 20

// BodyLimit caps the request body at n bytes.
//
// It does two things, because one is not enough. A declared Content-Length over
// the cap is rejected before the body is read, so an attacker cannot make the
// server stream a gigabyte to discover it was too big. MaxBytesReader then
// covers the chunked and lying-Content-Length cases, where the only way to know
// the size is to count it.
func BodyLimit(n int64) Middleware {
	if n <= 0 {
		n = DefaultBodyLimit
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				Error(w, http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
				return
			}
			if r.Body != nil {
				// Mutating the request rather than cloning it keeps the
				// pointer identity the mux needs to stamp r.Pattern onto.
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

// Limiter is the behaviour RateLimit needs. RetryAfter belongs to the limiter
// because only it knows the refill rate; a middleware advertising a constant
// would drift from the configuration the first time either changed.
type Limiter interface {
	Allow(key string) bool
	RetryAfter() time.Duration
}

// KeyFunc buckets a request. It is injectable so the same middleware serves
// both the per-client limiter and the global one, whose key is a constant.
type KeyFunc func(*http.Request) string

var _ Limiter = (*ratelimit.Limiter)(nil)

// FixedKey buckets every request together, which is how the global admission
// limiter is expressed: one bucket, one capacity, no per-client fan-out.
func FixedKey(key string) KeyFunc {
	return func(*http.Request) string { return key }
}

// RateLimit rejects a request whose bucket is empty with 429 and a Retry-After.
//
// A nil limiter panics at construction rather than at request time. It is a
// wiring mistake, and the two runtime alternatives are both worse: allowing
// everything silently uninstalls the control, and denying everything turns a
// typo into an outage. Failing while the server is still starting is the only
// option an operator can act on.
//
// A nil key function defaults to ratelimit.ClientKey, which reads the transport
// peer and ignores forwarding headers.
func RateLimit(l Limiter, key KeyFunc) Middleware {
	if l == nil {
		panic("httpx: RateLimit requires a limiter")
	}
	if key == nil {
		key = ratelimit.ClientKey
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l.Allow(key(r)) {
				next.ServeHTTP(w, r)
				return
			}
			seconds := int(l.RetryAfter() / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			Error(w, http.StatusTooManyRequests, CodeRateLimited)
		})
	}
}

// ---------------------------------------------------------------------------
// Ops authentication
// ---------------------------------------------------------------------------

// maxAuthHeaderLen bounds what is hashed for comparison. net/http already caps
// total header bytes, but there is no reason to run SHA-256 over a megabyte
// supplied by an unauthenticated caller.
const maxAuthHeaderLen = 512

const opsRealm = `Bearer realm="mesh-ops"`

// RequireOpsToken guards the operator API, which exposes incident state,
// telemetry, and the audit ledger.
//
// An unset token denies every request. That is the whole point: the natural
// implementation — skip the check when no token is configured — means a
// deployment that forgot MESH_OPS_TOKEN publishes its audit trail to the
// internet, and it does so silently, because everything appears to work. Fail
// closed makes the misconfiguration impossible to miss and impossible to
// exploit.
//
// The comparison runs over SHA-256 digests with subtle.ConstantTimeCompare, so
// neither the token's content nor its length is observable through timing. The
// token is accepted only from the Authorization header: a ?token= query
// parameter would be written to every access log and proxy log between the
// operator and this process.
func RequireOpsToken(token string) Middleware {
	want, configured := digestToken(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !configured {
				denyOps(w)
				return
			}
			presented, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				denyOps(w)
				return
			}
			got, _ := digestToken(presented)
			if !constantTimeEqual(got, want) {
				denyOps(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func denyOps(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", opsRealm)
	// Independently of path-based caching rules: an authentication failure is
	// never a cacheable answer, because the next request may carry a valid
	// credential.
	w.Header().Set("Cache-Control", "no-store")
	Error(w, http.StatusUnauthorized, CodeUnauthorized)
}

// digestToken hashes a credential to a fixed width so the comparison below
// leaks neither content nor length. The second result distinguishes "no token
// configured" from "a token that happens to hash to zero".
func digestToken(tok string) ([32]byte, bool) {
	if tok == "" {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(tok)), true
}

func constantTimeEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// bearerToken extracts the credential from an Authorization header, tolerating
// the case-insensitive scheme the RFC mandates and nothing else.
func bearerToken(h string) (string, bool) {
	if h == "" || len(h) > maxAuthHeaderLen {
		return "", false
	}
	const scheme = "bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(scheme):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

const (
	corsMethods  = "GET, POST, OPTIONS"
	corsHeaders  = "Authorization, Content-Type, X-Request-Id"
	corsMaxAge   = "600"
	maxOriginLen = 256
)

// CORS permits exactly one origin and never reflects what it was sent.
//
// Reflecting the Origin header is the standard way this control is neutralised:
// a reflected origin means every page on the internet is same-origin with this
// API as far as the browser is concerned. Access-Control-Allow-Credentials is
// never emitted, so no browser will attach cookies to a cross-origin call here;
// the session stream authenticates with a bearer token, which is ambient to no
// one, and combining credentials with a wildcard is forbidden precisely because
// it recreates CSRF.
//
// An empty or "*" allowedOrigin disables cross-origin access entirely rather
// than opening it up, which keeps the misconfiguration on the safe side.
func CORS(allowedOrigin string) Middleware {
	origin := strings.TrimSpace(allowedOrigin)
	enabled := origin != "" && origin != "*" && len(origin) <= maxOriginLen

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Vary is set unconditionally: the response body may legitimately
			// be cacheable, but its CORS headers depend on Origin, and a cache
			// that ignores that serves one origin's grant to another.
			w.Header().Add("Vary", "Origin")

			got := r.Header.Get("Origin")
			allowed := enabled && len(got) <= maxOriginLen && strings.EqualFold(got, origin)
			preflight := r.Method == http.MethodOptions &&
				r.Header.Get("Access-Control-Request-Method") != ""

			if allowed {
				// The configured value is echoed, never the received bytes, so
				// no attacker-controlled string can reach this header even if
				// the comparison above were ever loosened.
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				if preflight {
					h.Set("Access-Control-Allow-Methods", corsMethods)
					h.Set("Access-Control-Allow-Headers", corsHeaders)
					h.Set("Access-Control-Max-Age", corsMaxAge)
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if preflight {
				// A preflight from an origin we do not allow gets an explicit
				// refusal instead of a 204 with no grant, so the rejection is
				// visible in the access log rather than only in a browser
				// console.
				Error(w, http.StatusForbidden, CodeForbidden)
				return
			}

			// A simple cross-origin request from a foreign origin still reaches
			// the handler — CORS governs whether the browser hands back the
			// response, not whether it sends the request. That is safe here
			// only because no endpoint authenticates by cookie: every mutating
			// route requires a bearer token or an HMAC signature, so there is
			// no ambient authority for a foreign page to borrow.
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Response recorder
// ---------------------------------------------------------------------------

// responseRecorder observes the status and byte count for the access log while
// staying transparent to the handler beneath it.
//
// Flush is forwarded and Unwrap is implemented because the SSE hub streams
// through this wrapper: a wrapper that hides http.Flusher converts a live event
// stream into a response that is delivered when the handler returns, which for
// a stream is never.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

// wrapWriter avoids stacking recorders: Recover and AccessLog both need one,
// and two layers would double-count nothing but would make the "already
// written" flag ambiguous between them.
func wrapWriter(w http.ResponseWriter) *responseRecorder {
	if rec, ok := w.(*responseRecorder); ok {
		return rec
	}
	return &responseRecorder{ResponseWriter: w}
}

func (rr *responseRecorder) WriteHeader(status int) {
	if rr.wrote {
		// net/http logs a "superfluous WriteHeader" line for a second call.
		// Swallowing it here keeps the recorded status equal to the one the
		// client actually received.
		return
	}
	rr.wrote = true
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if !rr.wrote {
		rr.WriteHeader(http.StatusOK)
	}
	n, err := rr.ResponseWriter.Write(b)
	rr.bytes += int64(n)
	// The error is returned unwrapped: callers such as io.Copy and
	// http.ServeContent compare it against sentinels, and a wrapped value
	// changes behaviour in code this package does not own.
	return n, err
}

func (rr *responseRecorder) Flush() {
	if !rr.wrote {
		rr.wrote = true
		rr.status = http.StatusOK
	}
	if f, ok := rr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController, which is how
// a handler reaches Hijack and the read/write deadlines through a wrapper.
func (rr *responseRecorder) Unwrap() http.ResponseWriter { return rr.ResponseWriter }

// statusOrDefault reports what the client saw. A handler that returns without
// writing anything still produced a 200, because net/http writes one.
func (rr *responseRecorder) statusOrDefault() int {
	if !rr.wrote {
		return http.StatusOK
	}
	return rr.status
}

func orDefault(log *slog.Logger) *slog.Logger {
	if log == nil {
		return slog.Default()
	}
	return log
}

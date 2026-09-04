package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/ratelimit"
)

// syncBuffer collects log output from tests that run requests concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func newFixedClock() fixedClock {
	return fixedClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body %q is not the fixed error shape: %v", rr.Body.String(), err)
	}
	return body
}

// ---------------------------------------------------------------------------
// Recover
// ---------------------------------------------------------------------------

func TestRecoverReturnsOpaqueInternalError(t *testing.T) {
	var logs syncBuffer
	const leak = "mandate rzp_live_5xKz for pay_JQ8s3nAcme"

	h := Recover(obs.NewLogger("debug", &logs))(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic(leak) }))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/ops/incidents", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	body := rr.Body.String()
	for _, forbidden := range []string{"rzp_live", "pay_JQ8s3nAcme", "goroutine", "panic", ".go:"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	if got := decodeBody(t, rr); got.Code != CodeInternal || got.Message != messages[CodeInternal] {
		t.Fatalf("body = %+v, want the fixed internal error", got)
	}
	if !strings.Contains(logs.String(), "handler panic") {
		t.Fatalf("panic was not logged: %s", logs.String())
	}
}

func TestRecoverKeepsAnAlreadyWrittenResponse(t *testing.T) {
	var logs syncBuffer
	h := Recover(obs.NewLogger("debug", &logs))(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
				t.Errorf("write: %v", err)
			}
			panic("after the response was committed")
		}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", nil))

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want the already-written 202", rr.Code)
	}
	if got := rr.Body.String(); got != `{"status":"queued"}` {
		t.Fatalf("body = %q, want the handler's own body", got)
	}
}

// net/http uses ErrAbortHandler to drop a connection deliberately; converting
// it into a 500 would fabricate an error where the handler chose to stop.
func TestRecoverRepanicsAbortHandler(t *testing.T) {
	var logs syncBuffer
	h := Recover(obs.NewLogger("debug", &logs))(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))

	defer func() {
		if rv := recover(); rv != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want ErrAbortHandler to propagate", rv)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Fatal("ErrAbortHandler did not propagate")
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

func TestSecurityHeadersArePresent(t *testing.T) {
	h := SecurityHeaders()(http.HandlerFunc(ok))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/console.html", nil))

	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if rr.Header().Get("Permissions-Policy") == "" {
		t.Error("Permissions-Policy is absent")
	}

	csp := rr.Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'self'", "script-src 'self'", "object-src 'none'",
		"base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q is missing %q", csp, directive)
		}
	}
	// No external origin may appear: the console is entirely self-hosted, and a
	// single CDN entry would undo the policy.
	for _, external := range []string{"http://", "https://", "*"} {
		if strings.Contains(csp, external) {
			t.Errorf("CSP %q permits an external origin via %q", csp, external)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP %q allows inline script", csp)
	}
}

func TestNoStoreIsSetOnAPIPathsOnly(t *testing.T) {
	h := SecurityHeaders()(http.HandlerFunc(ok))

	api := httptest.NewRecorder()
	h.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil))
	if got := api.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control on an API path = %q, want no-store", got)
	}

	static := httptest.NewRecorder()
	h.ServeHTTP(static, httptest.NewRequest(http.MethodGet, "/checkout.html", nil))
	if got := static.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control on a static path = %q, want the handler to decide", got)
	}
}

// ---------------------------------------------------------------------------
// Request id
// ---------------------------------------------------------------------------

func TestRequestIDRejectsHostileInboundValues(t *testing.T) {
	hostile := map[string]string{
		"newline":        "abc\ndef",
		"crlf injection": "abc\r\n{\"level\":\"ERROR\",\"msg\":\"forged\"}",
		"too long":       strings.Repeat("a", 200),
		"space":          "abc def",
		"json":           `{"a":1}`,
		"path":           "../../etc/passwd",
		"html":           "<script>alert(1)</script>",
		"tab":            "abc\tdef",
	}

	for name, value := range hostile {
		t.Run(name, func(t *testing.T) {
			var seen string
			h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = obs.RequestID(r.Context())
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/incidents", nil)
			req.Header.Set(RequestIDHeader, value)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			echoed := rr.Header().Get(RequestIDHeader)
			if echoed == value {
				t.Fatalf("hostile id %q was echoed back", value)
			}
			if echoed != seen {
				t.Fatalf("echoed %q but stored %q", echoed, seen)
			}
			if acceptInboundID(echoed) == "" {
				t.Fatalf("generated id %q is not itself acceptable", echoed)
			}
		})
	}
}

func TestRequestIDHonoursASafeInboundValue(t *testing.T) {
	const id = "01JBK7Z5Q0-trace_9"
	var seen string
	h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = obs.RequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/incidents", nil)
	req.Header.Set(RequestIDHeader, id)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get(RequestIDHeader); got != id {
		t.Fatalf("echoed %q, want the caller's id %q", got, id)
	}
	if seen != id {
		t.Fatalf("context carried %q, want %q", seen, id)
	}
}

func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	seen := make(map[string]bool)
	h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[obs.RequestID(r.Context())] = true
	}))
	for i := 0; i < 8; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if len(seen) != 8 {
		t.Fatalf("generated %d distinct ids over 8 requests", len(seen))
	}
	if seen[""] {
		t.Fatal("a request ran without a correlation id")
	}
}

// ---------------------------------------------------------------------------
// Access log
// ---------------------------------------------------------------------------

func TestAccessLogRecordsRouteNotRawPath(t *testing.T) {
	var logs syncBuffer
	reg := obs.NewRegistry()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ops/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := AccessLog(obs.NewLogger("info", &logs), reg)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/incidents/pay_JQ8s3nAcme?token=sup3rsecret", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	line := logs.String()
	if !strings.Contains(line, `"route":"GET /api/v1/ops/incidents/{id}"`) {
		t.Fatalf("route pattern missing from log line: %s", line)
	}
	// The raw path carries a payment id and the query string carries a bearer
	// token; neither may ever be written to disk.
	for _, forbidden := range []string{"pay_JQ8s3nAcme", "sup3rsecret", "token="} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("access log leaked %q: %s", forbidden, line)
		}
	}
	if !strings.Contains(line, `"status":204`) {
		t.Fatalf("status missing from log line: %s", line)
	}

	counters, _ := reg.Snapshot()["counters"].(map[string]uint64)
	if counters["http_requests_total"] != 1 || counters["http_responses_2xx"] != 1 {
		t.Fatalf("RED counters not recorded: %+v", counters)
	}
}

func TestAccessLogRecordsUnroutedRequestsWithoutAPath(t *testing.T) {
	var logs syncBuffer
	mux := http.NewServeMux()
	h := AccessLog(obs.NewLogger("info", &logs), nil)(mux)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/no/such/route/pay_JQ8s3n", nil))

	line := logs.String()
	if !strings.Contains(line, `"route":""`) {
		t.Fatalf("unrouted request should log an empty route: %s", line)
	}
	if strings.Contains(line, "pay_JQ8s3n") {
		t.Fatalf("access log fell back to the raw path: %s", line)
	}
}

// ---------------------------------------------------------------------------
// Body limit
// ---------------------------------------------------------------------------

func TestBodyLimitRejectsDeclaredOversizeBeforeReading(t *testing.T) {
	var read int64
	h := BodyLimit(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		read = n
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(strings.Repeat("a", 4096)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if got := decodeBody(t, rr); got.Code != CodePayloadTooLarge {
		t.Fatalf("code = %q, want %q", got.Code, CodePayloadTooLarge)
	}
	if read != 0 {
		t.Fatalf("read %d bytes of an over-declared body; it should be rejected unread", read)
	}
}

func TestBodyLimitCapsAnUndeclaredStream(t *testing.T) {
	var readErr error
	h := BodyLimit(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.Copy(io.Discard, r.Body)
		if readErr != nil {
			Error(w, http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// A body with no declared length, as a chunked upload arrives.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay",
		io.NopCloser(strings.NewReader(strings.Repeat("a", 4096))))
	req.ContentLength = -1
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("read error = %v, want *http.MaxBytesError", readErr)
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

func TestRateLimitRejectsAfterBurstWithRetryAfter(t *testing.T) {
	l := ratelimit.New(1, 2, 16, newFixedClock())
	h := RateLimit(l, nil)(http.HandlerFunc(ok))

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", nil)
		req.RemoteAddr = "203.0.113.7:44321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	for i := 0; i < 2; i++ {
		if got := call().Code; got != http.StatusOK {
			t.Fatalf("request %d within burst = %d, want 200", i+1, got)
		}
	}

	rr := call()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
	if got := decodeBody(t, rr); got.Code != CodeRateLimited {
		t.Fatalf("code = %q, want %q", got.Code, CodeRateLimited)
	}
}

func TestRateLimitIsPerClient(t *testing.T) {
	l := ratelimit.New(1, 1, 16, newFixedClock())
	h := RateLimit(l, nil)(http.HandlerFunc(ok))

	call := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", nil)
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := call("203.0.113.7:1000"); got != http.StatusOK {
		t.Fatalf("first client = %d, want 200", got)
	}
	if got := call("203.0.113.7:1001"); got != http.StatusTooManyRequests {
		t.Fatalf("same client on a new port = %d, want 429 (the port is not part of identity)", got)
	}
	if got := call("198.51.100.4:1000"); got != http.StatusOK {
		t.Fatalf("second client = %d, want 200", got)
	}
}

func TestRateLimitWithAFixedKeyIsGlobal(t *testing.T) {
	l := ratelimit.New(1, 1, 4, newFixedClock())
	h := RateLimit(l, FixedKey("global"))(http.HandlerFunc(ok))

	call := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", nil)
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := call("203.0.113.7:1000"); got != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got)
	}
	if got := call("198.51.100.4:1000"); got != http.StatusTooManyRequests {
		t.Fatalf("a different client = %d, want 429 from the shared bucket", got)
	}
}

func TestRateLimitPanicsWithoutALimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a nil limiter was accepted; it would silently uninstall the control")
		}
	}()
	RateLimit(nil, nil)
}

// ---------------------------------------------------------------------------
// Ops token
// ---------------------------------------------------------------------------

func TestRequireOpsTokenFailsClosedWhenUnconfigured(t *testing.T) {
	var reached bool
	h := RequireOpsToken("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, auth := range []string{"", "Bearer anything", "Bearer "} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: status = %d, want 401 when no token is configured", auth, rr.Code)
		}
		if reached {
			t.Fatalf("auth %q: the ops handler ran with no token configured", auth)
		}
		if got := rr.Header().Get("WWW-Authenticate"); got == "" {
			t.Fatalf("auth %q: WWW-Authenticate is absent", auth)
		}
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("auth %q: Cache-Control = %q, want no-store", auth, got)
		}
	}
}

func TestRequireOpsTokenRejectsBadCredentials(t *testing.T) {
	const token = "s3cr3t-ops-token-value"
	cases := map[string]string{
		"absent":       "",
		"wrong":        "Bearer not-the-token",
		"prefix":       "Bearer s3cr3t-ops-token-valu",
		"extended":     "Bearer s3cr3t-ops-token-values",
		"empty bearer": "Bearer ",
		"basic":        "Basic czNjcjN0",
		"raw token":    token,
		"oversized":    "Bearer " + strings.Repeat("a", maxAuthHeaderLen),
	}

	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			var reached bool
			h := RequireOpsToken(token)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			if reached {
				t.Fatal("the ops handler ran without a valid credential")
			}
			if strings.Contains(rr.Body.String(), token) {
				t.Fatalf("the response echoed the configured token: %s", rr.Body.String())
			}
		})
	}
}

func TestRequireOpsTokenAcceptsTheConfiguredCredential(t *testing.T) {
	const token = "s3cr3t-ops-token-value"
	for _, scheme := range []string{"Bearer ", "bearer ", "BEARER "} {
		var reached bool
		h := RequireOpsToken(token)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
		req.Header.Set("Authorization", scheme+token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK || !reached {
			t.Fatalf("scheme %q: status = %d, reached = %v; want the request to pass", scheme, rr.Code, reached)
		}
	}
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

const demoOrigin = "http://localhost:8080"

func TestCORSNeverReflectsAForeignOrigin(t *testing.T) {
	var reached bool
	h := CORS(demoOrigin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
	req.Header.Set("Origin", "https://attacker.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want no grant for a foreign origin", got)
	}
	if !strings.Contains(rr.Header().Get("Vary"), "Origin") {
		t.Fatal("Vary: Origin is absent, so a cache could serve one origin's grant to another")
	}
	if !reached {
		t.Fatal("a simple cross-origin request should still reach the handler; CORS governs the response, not the request")
	}
}

func TestCORSGrantsTheConfiguredOriginOnly(t *testing.T) {
	h := CORS(demoOrigin)(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/session/stream/s_1", nil)
	req.Header.Set("Origin", demoOrigin)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != demoOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, demoOrigin)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want it never to be sent", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	var reached bool
	h := CORS(demoOrigin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	allowed := httptest.NewRequest(http.MethodOptions, "/api/v1/session", nil)
	allowed.Header.Set("Origin", demoOrigin)
	allowed.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, allowed)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight = %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != corsMethods {
		t.Fatalf("Access-Control-Allow-Methods = %q, want %q", got, corsMethods)
	}
	if reached {
		t.Fatal("a preflight must not reach the handler")
	}

	foreign := httptest.NewRequest(http.MethodOptions, "/api/v1/session", nil)
	foreign.Header.Set("Origin", "https://attacker.example")
	foreign.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, foreign)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("foreign preflight = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("foreign preflight granted %q", got)
	}
}

func TestCORSWildcardConfigurationDisablesSharing(t *testing.T) {
	for _, configured := range []string{"", "*", "   "} {
		h := CORS(configured)(http.HandlerFunc(ok))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
		req.Header.Set("Origin", "https://attacker.example")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("configured %q granted %q; a wildcard must disable sharing, not open it", configured, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

func TestErrorBodyIsFixedAndCodeSanitized(t *testing.T) {
	cases := map[string]struct {
		status   int
		code     string
		wantCode string
		wantMsg  string
	}{
		"known code": {http.StatusNotFound, CodeNotFound, CodeNotFound, messages[CodeNotFound]},
		// An internal error string passed as a code must not survive in any
		// form: it collapses onto the code implied by the status.
		"injected": {http.StatusBadRequest, "pgx: duplicate key\n<script>",
			CodeBadRequest, messages[CodeBadRequest]},
		"empty falls back to status": {http.StatusUnauthorized, "", CodeUnauthorized, messages[CodeUnauthorized]},
		"invalid status":             {999, CodeInternal, CodeInternal, messages[CodeInternal]},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			Error(rr, tc.status, tc.code)

			body := decodeBody(t, rr)
			if body.Code != tc.wantCode || body.Message != tc.wantMsg {
				t.Fatalf("body = %+v, want code %q message %q", body, tc.wantCode, tc.wantMsg)
			}
			if got := rr.Header().Get("Content-Type"); got != jsonContentType {
				t.Fatalf("Content-Type = %q, want %q", got, jsonContentType)
			}
			if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

func TestJSONWritesTheValue(t *testing.T) {
	rr := httptest.NewRecorder()
	JSON(rr, http.StatusOK, map[string]any{"status": "duplicate_ignored"})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["status"] != "duplicate_ignored" {
		t.Fatalf("body = %v", got)
	}
	if want := strconv.Itoa(rr.Body.Len()); rr.Header().Get("Content-Length") != want {
		t.Fatalf("Content-Length = %q, want %s", rr.Header().Get("Content-Length"), want)
	}
}

func TestJSONDegradesToTheInternalErrorOnAnUnmarshalableValue(t *testing.T) {
	rr := httptest.NewRecorder()
	JSON(rr, http.StatusOK, map[string]any{"ch": make(chan int)})

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if got := decodeBody(t, rr); got.Code != CodeInternal {
		t.Fatalf("code = %q, want %q", got.Code, CodeInternal)
	}
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

func TestChainRunsOutermostFirst(t *testing.T) {
	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	h := Chain(mark("a"), nil, mark("b"))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if strings.Join(order, ",") != "a,b,handler" {
		t.Fatalf("order = %v, want a,b,handler", order)
	}
}

// The SSE hub streams through this stack; a wrapper that hides http.Flusher
// would turn every event stream into a response delivered at handler exit.
func TestResponseWrapperKeepsFlusherAndUnwrap(t *testing.T) {
	var flushable, unwrappable bool
	h := Base(obs.NewLogger("error", io.Discard), nil)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, flushable = w.(http.Flusher)
			if u, okAssert := w.(interface{ Unwrap() http.ResponseWriter }); okAssert {
				unwrappable = u.Unwrap() != nil
			}
			w.WriteHeader(http.StatusOK)
			http.NewResponseController(w).Flush()
		}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/session/stream/s_1", nil))

	if !flushable || !unwrappable {
		t.Fatalf("flusher = %v, unwrap = %v; both are required for SSE", flushable, unwrappable)
	}
}

func TestBaseChainHandlesAPanickingHandler(t *testing.T) {
	var logs syncBuffer
	reg := obs.NewRegistry()
	h := Base(obs.NewLogger("debug", &logs), reg)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic("boom pay_JQ8s3n") }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/audit", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if rr.Header().Get(RequestIDHeader) == "" {
		t.Fatal("no request id was echoed")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("security headers were lost on the panic path")
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store on an API path", got)
	}
	if strings.Contains(rr.Body.String(), "pay_JQ8s3n") {
		t.Fatalf("the panic value reached the client: %s", rr.Body.String())
	}
	if !strings.Contains(logs.String(), `"status":500`) {
		t.Fatalf("the access log did not record the 500 the client received: %s", logs.String())
	}
	counters, _ := reg.Snapshot()["counters"].(map[string]uint64)
	if counters["http_responses_5xx"] != 1 {
		t.Fatalf("5xx counter = %d, want 1", counters["http_responses_5xx"])
	}
}

func TestFullStackUnderConcurrentLoad(t *testing.T) {
	var logs syncBuffer
	reg := obs.NewRegistry()
	limiter := ratelimit.New(1000, 1000, 64, newFixedClock())

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/webhooks/razorpay", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			Error(w, http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
			return
		}
		JSON(w, http.StatusOK, map[string]string{"status": "accepted"})
	})

	h := Chain(
		Base(obs.NewLogger("info", &logs), reg),
		CORS(demoOrigin),
		RateLimit(limiter, nil),
		BodyLimit(1024),
	)(mux)

	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay",
					strings.NewReader(`{"event":"payment.failed"}`))
				req.RemoteAddr = "203.0.113." + strconv.Itoa(g%10+1) + ":4000"
				req.Header.Set("Origin", demoOrigin)
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rr.Code)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	counters, _ := reg.Snapshot()["counters"].(map[string]uint64)
	if counters["http_requests_total"] != 24*20 {
		t.Fatalf("http_requests_total = %d, want %d", counters["http_requests_total"], 24*20)
	}
}

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/httpx"
	"github.com/hriday/razorpay-resilient-mesh/internal/ratelimit"
	"github.com/hriday/razorpay-resilient-mesh/internal/sse"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

const (
	// webhookBodyLimit matches the ingest handler's own cap. Enforcing it at the
	// middleware too means an oversized body is refused before any handler
	// allocates for it.
	webhookBodyLimit = 1 << 20

	// jsonBodyLimit bounds the small JSON bodies the checkout posts. It is
	// deliberately far below the webhook limit: nothing on this path is large,
	// and a limit sized for the largest endpoint is no limit at all for the
	// smallest.
	jsonBodyLimit = 16 << 10

	// opsListDefault and opsListMax bound the ops listing endpoints. A caller
	// that asks for everything gets the ceiling rather than an error, because
	// an operator hunting an incident should not have to learn the API's
	// pagination rules first.
	opsListDefault = 40
	opsListMax     = 500

	// sessionTokenBytes is the entropy in a checkout stream credential. The
	// token authorises reading one customer's recovery progress, and it travels
	// in a query parameter because EventSource cannot set headers, so it is
	// sized to be unguessable rather than merely unique.
	sessionTokenBytes = 32

	// webRateLimit and opsRateLimit are per-client ceilings. The public
	// endpoints are the ones an anonymous caller can reach, so they are the
	// ones that need a limiter; the ops endpoints are already behind a bearer
	// token and are limited only to bound a leaked-token blast radius.
	webRatePerSecond, webBurst = 20, 40
	opsRatePerSecond, opsBurst = 10, 20
	limiterCapacity            = 8192

	// maxCheckoutPaisa bounds the only amount that enters this system from an
	// untrusted client. Rs 10,00,000 is far above any demo order and far below
	// the overflow-adjacent values a fuzzer reaches for; every downstream
	// invariant assumes a chargeable value, so the assumption is enforced at
	// the one place it can be violated.
	maxCheckoutPaisa = 10_00_000_00
)

// buildMux assembles the API. Route patterns use Go 1.22 method-and-path
// matching so the mux enforces the method and the segment shape; hand-rolled
// prefix matching plus manual parsing is how a path like /a/b reaches a handler
// expecting a single segment.
func (a *App) buildMux() http.Handler {
	mux := http.NewServeMux()

	// ---- Public: the webhook trust boundary --------------------------------
	//
	// The ingest handler performs its own signature verification, so the only
	// thing added here is the body cap. It is intentionally not rate limited by
	// client address: Razorpay retries from its own infrastructure, and a
	// limiter that sheds a legitimate retry converts a transient error into a
	// lost payment.
	mux.Handle("POST /webhooks/razorpay",
		httpx.BodyLimit(webhookBodyLimit)(a.webhook))

	// ---- Public: the checkout session and its event stream -----------------
	webLimiter := ratelimit.New(webRatePerSecond, webBurst, limiterCapacity, a.clock)
	public := httpx.Chain(
		httpx.BodyLimit(jsonBodyLimit),
		httpx.RateLimit(webLimiter, clientKey),
	)
	mux.Handle("POST /api/v1/session", public(http.HandlerFunc(a.createSession)))

	// The stream handler owns its own route pattern, including the session id
	// segment, so it is mounted rather than re-declared. Re-declaring it here
	// would put the authorisation-critical path shape in two places.
	mux.Handle(sse.DefaultRoute+"/", http.NotFoundHandler()) // reject sub-paths explicitly
	mux.Handle(sse.DefaultRoute, sse.HandlerWithOptions(a.hub, a.lookupSession, a.log, sse.Options{
		MaxSessions: a.cfg.MaxSessions,
		Clock:       a.clock,
	}))

	// ---- Operator: everything behind the ops token -------------------------
	opsLimiter := ratelimit.New(opsRatePerSecond, opsBurst, limiterCapacity, a.clock)
	ops := httpx.Chain(
		httpx.RequireOpsToken(a.cfg.OpsToken),
		httpx.RateLimit(opsLimiter, clientKey),
	)
	mux.Handle("GET /api/v1/ops/metrics", ops(http.HandlerFunc(a.opsMetrics)))
	mux.Handle("GET /api/v1/ops/telemetry", ops(http.HandlerFunc(a.opsTelemetry)))
	mux.Handle("GET /api/v1/ops/incidents", ops(http.HandlerFunc(a.opsIncidents)))
	mux.Handle("GET /api/v1/ops/incidents/{id}", ops(http.HandlerFunc(a.opsIncidentDetail)))
	mux.Handle("GET /api/v1/ops/audit", ops(http.HandlerFunc(a.opsAudit)))
	mux.Handle("GET /api/v1/ops/audit/verify", ops(http.HandlerFunc(a.opsAuditVerify)))
	mux.Handle("GET /api/v1/ops/downtime", ops(http.HandlerFunc(a.opsDowntime)))
	mux.Handle("GET /api/v1/ops/dlq", ops(http.HandlerFunc(a.opsDeadLetters)))
	// Prometheus scraping sits behind the same token. An unauthenticated
	// /metrics leaks issuer names, volumes and failure rates, which is
	// commercially sensitive even though none of it is a credential.
	mux.Handle("GET /metrics", ops(http.HandlerFunc(a.promMetrics)))

	// ---- Unauthenticated liveness and readiness ----------------------------
	//
	// These stay open because a probe that needs a credential is a probe that
	// fails during exactly the credential outage it should be reporting.
	mux.Handle("GET /healthz", http.HandlerFunc(a.healthz))
	mux.Handle("GET /readyz", http.HandlerFunc(a.readyz))

	// ---- Static console and checkout ---------------------------------------
	mux.Handle("GET /", a.staticHandler())

	base := httpx.Chain(
		httpx.Recover(a.log),
		httpx.RequestID(),
		httpx.SecurityHeaders(),
		httpx.AccessLog(a.log, a.metr),
	)
	return base(mux)
}

// clientKey buckets a rate limiter by remote address.
//
// X-Forwarded-For is deliberately ignored. This process is reached directly in
// every supported deployment, so trusting a header any client can set would let
// one caller occupy every bucket by varying it.
func clientKey(r *http.Request) string {
	host, _, err := splitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return addr, "", errors.New("no port")
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr[:i], "["), "]"), addr[i+1:], nil
}

// staticHandler serves web/ with the strict CSP the pages already declare.
//
// http.FileServer's directory listing is disabled by serving through a wrapper:
// a listing exposes filenames that are not linked from anywhere, and there is
// no reason for this deployment to offer one.
func (a *App) staticHandler() http.Handler {
	root := http.Dir(filepath.Join("web"))
	fs := http.FileServer(noDirListing{root})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/checkout.html", http.StatusFound)
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// noDirListing turns a directory open into a not-found, which is what removes
// the listing without also removing index files.
type noDirListing struct{ fs http.FileSystem }

func (n noDirListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, errors.New("directory listing is not served")
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Checkout session
// ---------------------------------------------------------------------------

type createSessionRequest struct {
	AmountPaisa int64  `json:"amount_paisa"`
	Currency    string `json:"currency"`
	Rail        string `json:"rail"`
}

type createSessionResponse struct {
	SessionID   string      `json:"session_id"`
	Token       string      `json:"token"`
	OrderID     string      `json:"order_id"`
	CurrentRail domain.Rail `json:"current_rail"`
	AmountPaisa int64       `json:"amount_paisa"`
	Currency    string      `json:"currency"`
	ExpiresAt   time.Time   `json:"expires_at"`
}

// createSession opens a checkout session and mints its stream credential.
//
// The session id is opaque and the token is returned exactly once, in this
// response. Only its hash is stored, so a database read — by an operator, a
// backup, or an attacker — cannot reconstruct a credential that would let
// someone watch a stranger's checkout. See ADR-011.
func (a *App) createSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.Error(w, http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, httpx.CodeBadRequest)
		return
	}
	// The amount is validated here rather than trusted, even though this is a
	// demo endpoint: it is the only place in the system where an amount enters
	// from an untrusted client, and every downstream invariant assumes a
	// chargeable value.
	if req.AmountPaisa <= 0 || req.AmountPaisa > maxCheckoutPaisa {
		httpx.Error(w, http.StatusBadRequest, httpx.CodeBadRequest)
		return
	}
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	if currency == "" {
		currency = "INR"
	}
	if currency != "INR" {
		httpx.Error(w, http.StatusBadRequest, httpx.CodeBadRequest)
		return
	}
	rail := domain.Rail(strings.ToLower(strings.TrimSpace(req.Rail)))
	if !rail.Valid() || rail == domain.RailNone {
		rail = domain.RailNetbanking
	}

	token, err := newToken()
	if err != nil {
		a.log.Error("could not generate a session token", "error", err)
		httpx.Error(w, http.StatusInternalServerError, httpx.CodeInternal)
		return
	}
	sum := sha256.Sum256([]byte(token))
	now := a.clock.Now()
	rec := domain.SessionRecord{
		ID:          "sess_" + mustRandomHex(12),
		OrderID:     "order_" + mustRandomHex(12),
		TokenHash:   hex.EncodeToString(sum[:]),
		CurrentRail: rail,
		AmountPaisa: req.AmountPaisa,
		Currency:    currency,
		Active:      true,
		CreatedAt:   now,
		ExpiresAt:   now.Add(a.cfg.SessionTTL),
	}
	if err := a.pg.CreateSession(r.Context(), rec); err != nil {
		a.log.Error("could not create a checkout session", "error", err)
		httpx.Error(w, http.StatusInternalServerError, httpx.CodeInternal)
		return
	}

	httpx.JSON(w, http.StatusCreated, createSessionResponse{
		SessionID:   rec.ID,
		Token:       token,
		OrderID:     rec.OrderID,
		CurrentRail: rec.CurrentRail,
		AmountPaisa: rec.AmountPaisa,
		Currency:    rec.Currency,
		ExpiresAt:   rec.ExpiresAt,
	})
}

// lookupSession is the single query the stream edge needs. Passing a function
// rather than the whole store is what keeps the SSE package from being able to
// write anything.
func (a *App) lookupSession(ctx context.Context, sessionID string) (domain.SessionRecord, error) {
	return a.pg.GetSession(ctx, sessionID)
}

func newToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// mustRandomHex generates an identifier. A failure of the system CSPRNG is not
// a recoverable condition for a process that mints session identifiers, so it
// is surfaced as a panic caught by the recovery middleware rather than as an
// identifier with less entropy than it claims.
func mustRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("app: the system random source failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// healthz is liveness only: the process is running and can serve a request.
// Deliberately dependency-free, because a liveness probe that fails when the
// database is down asks the supervisor to restart a process that would come
// back to the same database.
func (a *App) healthz(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type readiness struct {
	Ready     bool              `json:"ready"`
	Checks    map[string]string `json:"checks"`
	CheckedAt time.Time         `json:"checked_at"`
}

// readyz reports whether this process can actually do its job.
//
// Every check probes the real dependency. A readiness endpoint that returns a
// constant 200 is worse than none: it converts a broken deployment into a
// silently broken one, and the load balancer keeps sending traffic to it.
func (a *App) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	checks := map[string]string{}
	ready := true
	record := func(name string, err error) {
		if err != nil {
			// The error text is recorded for the operator reading this
			// endpoint, not echoed from an untrusted source: every producer
			// here is one of our own dependencies.
			checks[name] = "failed: " + err.Error()
			ready = false
			return
		}
		checks[name] = "ok"
	}

	record("postgres", a.pg.Ping(ctx))
	record("redis", a.q.Ping(ctx))

	lastPolled, active, err := a.downtime.Health()
	switch {
	case err != nil:
		record("downtime", err)
	case lastPolled.IsZero():
		record("downtime", errors.New("no successful poll yet"))
	case a.clock.Now().Sub(lastPolled) > downtimeStaleAfter:
		record("downtime", errors.New("view is stale"))
	default:
		checks["downtime"] = "ok (" + strconv.Itoa(active) + " active)"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	httpx.JSON(w, status, readiness{Ready: ready, Checks: checks, CheckedAt: a.clock.Now()})
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// clampLimit reads a caller-supplied limit and bounds it. An unparseable or
// absent value takes the default rather than an error: the console is the main
// caller and a 400 there would blank the whole page over one bad query string.
func clampLimit(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return opsListDefault
	}
	if n > opsListMax {
		return opsListMax
	}
	return n
}

// notFoundOr maps a store error onto a status. It exists so that "no such
// incident" and "the database is down" cannot collapse into the same response,
// which is how an outage gets diagnosed as a missing record.
func notFoundOr(w http.ResponseWriter, err error, log func(error)) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, httpx.CodeNotFound)
	case errors.Is(err, store.ErrInvalidInput):
		httpx.Error(w, http.StatusBadRequest, httpx.CodeBadRequest)
	default:
		log(err)
		httpx.Error(w, http.StatusInternalServerError, httpx.CodeInternal)
	}
}

// Command razorpay-sim is a faithful local stand-in for the Razorpay surfaces
// ResilientMesh depends on: the downtime API, a payment retry and capture
// endpoint, and signed webhook delivery.
//
// It exists for three reasons. First, the mesh must be demonstrable and
// benchmarkable with no payment account, no network egress, and no Docker.
// Second, the client code that talks to this server has to be the same client
// code that would talk to production — same Basic auth, same schemas, same
// HMAC — or the integration is untested where it matters. Third, and most
// importantly, a run has to be reproducible: every arrival time, every
// instrument, every amount, and every issuer verdict is a pure function of
// --seed, so a reviewer re-running the demo sees the same incidents in the same
// order, and a benchmark difference between two policies is attributable to the
// policies rather than to the weather.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

const (
	// envSimulatorTarget is the webhook destination. It is read directly rather
	// than through internal/config because the config contract has no field for
	// it; see the note in the build report.
	envSimulatorTarget = "MESH_SIMULATOR_TARGET"

	// targetDisabled turns webhook emission off while leaving the read APIs
	// serving, which is what cmd/mesh wants before the API is listening and
	// what a schema-only test wants always.
	targetDisabled = "none"

	// defaultWebhookPath is where the mesh's ingest edge listens.
	defaultWebhookPath = "/api/v1/webhooks/razorpay"

	// maxConcurrentDeliveries bounds in-flight webhook posts. Unbounded
	// dispatch would let a slow receiver convert an outage burst into unbounded
	// goroutine and memory growth here.
	maxConcurrentDeliveries = 16

	// maxEnvValueLen bounds any environment value read outside config.
	maxEnvValueLen = 2048

	// shutdownGrace bounds the drain on SIGINT.
	shutdownGrace = 5 * time.Second

	// maxIdentifierLen bounds a path identifier before it is used as a map key.
	maxIdentifierLen = 64
)

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "razorpay-sim: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "razorpay-sim: %v\n", err)
		return 1
	}
	return 0
}

// options is the fully resolved run configuration: flags layered over the
// environment, validated once so nothing downstream re-checks a bound.
type options struct {
	Seed              int64
	Addr              string
	Target            string
	Scenario          string
	Rate              float64
	Duration          time.Duration
	DuplicatePerMille int

	KeyID     string
	KeySecret string
	Secret    string
	LogLevel  string
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	cfg, err := config.Load()
	if err != nil {
		return options{}, fmt.Errorf("load configuration: %w", err)
	}

	fs := flag.NewFlagSet("razorpay-sim", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		seed      = fs.Int64("seed", cfg.Seed, "deterministic run seed; identical seeds produce identical event sequences")
		addr      = fs.String("addr", cfg.SimulatorAddr, "listen address for the Razorpay-shaped API")
		target    = fs.String("target", "", "webhook destination URL, or \"none\" to serve the APIs without emitting")
		scenario  = fs.String("scenario", ScenarioIssuerOutage, "outage scenario: "+strings.Join(Scenarios(), " | "))
		rate      = fs.Float64("rate", 4, "simulated payment attempts per second; only failures produce a webhook")
		duration  = fs.Duration("duration", 5*time.Minute, "length of the scripted timeline")
		duplicate = fs.Float64("duplicate-rate", 0.05, "fraction of deliveries repeated verbatim, to exercise idempotency")
	)

	fs.Usage = func() {
		fmt.Fprintf(stderr, "razorpay-sim — a deterministic local Razorpay for ResilientMesh\n\nUsage:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nEnvironment: %s (webhook destination), %s, %s, %s, %s\n",
			envSimulatorTarget, "MESH_SIMULATOR_ADDR", "MESH_WEBHOOK_SECRET",
			"MESH_RAZORPAY_KEY_ID", "MESH_RAZORPAY_KEY_SECRET")
	}
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	if *duplicate < 0 || *duplicate > 1 {
		return options{}, fmt.Errorf("--duplicate-rate %v out of range [0, 1]", *duplicate)
	}

	opts := options{
		Seed:      *seed,
		Addr:      strings.TrimSpace(*addr),
		Target:    resolveTarget(*target, cfg.HTTPAddr),
		Scenario:  strings.ToLower(strings.TrimSpace(*scenario)),
		Rate:      *rate,
		Duration:  *duration,
		KeyID:     cfg.RazorpayKeyID,
		KeySecret: cfg.RazorpayKeySecret,
		Secret:    cfg.WebhookSecret,
		LogLevel:  cfg.LogLevel,
		// Rounded once, here, so the per-mille integer the generator uses is
		// derived from the operator's fraction exactly once and never re-derived
		// differently somewhere else.
		DuplicatePerMille: int(math.Round(*duplicate * perMille)),
	}
	if opts.Addr == "" {
		return options{}, errors.New("--addr must not be empty")
	}
	return opts, nil
}

// resolveTarget layers the flag over the environment over a value derived from
// the mesh's own listen address, which is right almost always and wrong
// visibly rather than silently.
func resolveTarget(flagValue, meshAddr string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(envSimulatorTarget)); v != "" {
		if len(v) > maxEnvValueLen {
			return v[:maxEnvValueLen]
		}
		return v
	}
	return targetFromAddr(meshAddr)
}

// targetFromAddr turns a listen address into a reachable URL. A wildcard bind
// is rewritten to loopback: "http://:8080/..." is not a URL anything can dial.
func targetFromAddr(addr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + defaultWebhookPath
}

// serve wires the process together and blocks until the context is cancelled.
func serve(ctx context.Context, opts options, stdout, stderr io.Writer) error {
	log := obs.NewLogger(opts.LogLevel, stderr)
	metrics := obs.NewRegistry()
	clock := systemClock{}

	timeline, err := NewTimeline(opts.Scenario, opts.Seed, clock.Now(), opts.Duration)
	if err != nil {
		return err
	}
	script, err := timeline.Script(opts.Rate, opts.DuplicatePerMille)
	if err != nil {
		return err
	}

	srv, err := newServer(serverConfig{
		Timeline:     timeline,
		Clock:        clock,
		Log:          log,
		Metrics:      metrics,
		KeyID:        opts.KeyID,
		KeySecret:    opts.KeySecret,
		PaymentLimit: len(script) + maxTrackedPayments,
	})
	if err != nil {
		return err
	}
	// Every payment the run will emit is registered up front, so a retry that
	// arrives before its webhook has been delivered — which happens whenever
	// the mesh is faster than the network — still finds the real entity rather
	// than a synthesised one.
	for _, ev := range script {
		srv.payments.put(ev.Payment)
	}

	var em *emitter
	if opts.Target != targetDisabled {
		em, err = newEmitter(emitterConfig{
			Target:    opts.Target,
			Secret:    opts.Secret,
			AccountID: timeline.AccountID(),
			Seed:      opts.Seed,
			Clock:     clock,
			Log:       log,
			Metrics:   metrics,
		})
		if err != nil {
			return err
		}
	}

	httpSrv := &http.Server{
		Addr:    opts.Addr,
		Handler: srv,
		// Slowloris and body-stall protection. A simulator on a laptop is not a
		// target, but shipping a server without these teaches the wrong thing.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.Addr, err)
	}

	printSummary(stdout, opts, timeline, script, listener.Addr().String())
	log.Info("razorpay-sim listening",
		"addr", listener.Addr().String(),
		"scenario", timeline.Scenario(),
		"seed", opts.Seed,
		"events", len(script),
		"webhook_secret_fingerprint", SecretFingerprint(opts.Secret))

	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	var scriptDone sync.WaitGroup
	if em != nil {
		scriptDone.Add(1)
		go func() {
			defer scriptDone.Done()
			dispatch(ctx, em, script, timeline.Start(), clock, log)
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			runErr = fmt.Errorf("http server: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown did not complete cleanly", "cause", err.Error())
	}
	scriptDone.Wait()

	snapshot, err := json.Marshal(metrics.Snapshot())
	if err != nil {
		log.Warn("could not render final metrics", "cause", err.Error())
	} else {
		log.Info("razorpay-sim stopped", "metrics", string(snapshot))
	}
	return runErr
}

// dispatch walks the script in order, delivering each event when its virtual
// offset arrives. Deliveries run concurrently under a semaphore because a
// receiver that pauses must not push every later event behind it — that would
// turn one slow response into a reordered, compressed burst, which is not what
// the script says should happen.
func dispatch(ctx context.Context, em *emitter, script []ScheduledEvent, start time.Time,
	clock domain.Clock, log *slog.Logger) {

	sem := make(chan struct{}, maxConcurrentDeliveries)
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, ev := range script {
		due := start.Add(time.Duration(ev.OffsetMS) * time.Millisecond)
		if wait := due.Sub(clock.Now()); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(ev ScheduledEvent) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := em.Emit(ctx, ev); err != nil && ctx.Err() == nil {
				log.Warn("webhook emission failed",
					"event_id", ev.EventID, "payment_id", ev.Payment.ID, "cause", err.Error())
			}
		}(ev)
	}
	log.Info("scripted timeline complete", "events", len(script))
}

// printSummary is the operator's first screen: what will happen, when, and what
// to point a client at.
func printSummary(w io.Writer, opts options, t *Timeline, script []ScheduledEvent, addr string) {
	duplicates := 0
	for _, ev := range script {
		if ev.Duplicate {
			duplicates++
		}
	}
	target := opts.Target
	if target == targetDisabled || target == "" {
		target = "(emission disabled)"
	}

	line := strings.Repeat("─", 74)
	fmt.Fprintf(w, "┌%s┐\n", line)
	fmt.Fprintf(w, "│ razorpay-sim — deterministic Razorpay for ResilientMesh%s│\n", strings.Repeat(" ", 19))
	fmt.Fprintf(w, "├%s┤\n", line)
	fmt.Fprintf(w, "│ scenario   %-61s │\n", t.Scenario())
	fmt.Fprintf(w, "│ seed       %-61d │\n", opts.Seed)
	fmt.Fprintf(w, "│ listening  %-61s │\n", "http://"+addr)
	fmt.Fprintf(w, "│ webhooks   %-61s │\n", truncateForBox(target, 61))
	fmt.Fprintf(w, "│ timeline   %-61s │\n",
		fmt.Sprintf("%s at %.2f attempts/s", opts.Duration, opts.Rate))
	fmt.Fprintf(w, "│ events     %-61s │\n",
		fmt.Sprintf("%d webhooks, %d duplicated (%.1f%%)", len(script), duplicates,
			percent(duplicates, len(script))))
	fmt.Fprintf(w, "├%s┤\n", line)
	for _, win := range t.Windows() {
		fmt.Fprintf(w, "│ outage     %-61s │\n",
			fmt.Sprintf("%-22s %-6s %s → %s", win.TelemetryKey(), win.Severity,
				win.Begin.Format("15:04:05"), win.End.Format("15:04:05")))
	}
	fmt.Fprintf(w, "└%s┘\n", line)
}

func percent(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}

func truncateForBox(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

type serverConfig struct {
	Timeline  *Timeline
	Clock     domain.Clock
	Log       *slog.Logger
	Metrics   *obs.Registry
	KeyID     string
	KeySecret string

	// PaymentLimit sizes the payment registry. serve sets it above the script
	// length so a scripted payment can never be evicted by the synthesised
	// entries a stray retry creates — evicting one would mean a payment the
	// mesh is actively recovering changes identity underneath it.
	PaymentLimit int
}

// server holds everything the handlers need. The timeline is immutable after
// construction, so the only shared mutable state is the payment registry, which
// carries its own mutex.
type server struct {
	timeline   *Timeline
	clock      domain.Clock
	log        *slog.Logger
	metrics    *obs.Registry
	payments   *paymentRegistry
	keyIDHash  [sha256.Size]byte
	keySecHash [sha256.Size]byte
	mux        *http.ServeMux
}

// newServer refuses to start without credentials.
//
// An empty expected key would make the constant-time comparison below succeed
// against an empty presented key, which is an authentication bypass that reads
// as a working server. Managed-mode config always mints these, so an empty pair
// here means a wiring mistake, and failing loudly is the only safe response.
func newServer(cfg serverConfig) (*server, error) {
	if cfg.Timeline == nil {
		return nil, errors.New("simulator: server requires a timeline")
	}
	if strings.TrimSpace(cfg.KeyID) == "" || strings.TrimSpace(cfg.KeySecret) == "" {
		return nil, errors.New("simulator: API key id and secret are required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = obs.NewRegistry()
	}

	s := &server{
		timeline:   cfg.Timeline,
		clock:      clock,
		log:        log,
		metrics:    metrics,
		payments:   newPaymentRegistry(cfg.PaymentLimit),
		keyIDHash:  sha256.Sum256([]byte(cfg.KeyID)),
		keySecHash: sha256.Sum256([]byte(cfg.KeySecret)),
		mux:        http.NewServeMux(),
	}

	s.mux.HandleFunc("GET /healthz", s.open(s.handleHealth))
	s.mux.HandleFunc("GET /v1/downtimes", s.secured(s.handleDowntimeList))
	s.mux.HandleFunc("GET /v1/downtimes/{id}", s.secured(s.handleDowntimeGet))
	s.mux.HandleFunc("GET /v1/payments/{id}", s.secured(s.handlePaymentFetch))
	s.mux.HandleFunc("POST /v1/payments/{id}/retry", s.secured(s.handlePaymentRetry))
	s.mux.HandleFunc("POST /v1/payments/{id}/capture", s.secured(s.handlePaymentCapture))
	s.mux.HandleFunc("GET /sim/metrics", s.secured(s.handleMetrics))
	s.mux.HandleFunc("/", s.open(s.handleNotFound))

	return s, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// open applies the response hygiene every route needs and bounds the request
// body. It does not authenticate.
func (s *server) open(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	}
}

// secured is open plus Basic auth.
func (s *server) secured(h http.HandlerFunc) http.HandlerFunc {
	return s.open(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			s.metrics.Counter("sim_auth_rejected").Inc()
			// No detail about which half was wrong, and no echo of what was
			// presented: an authentication error that explains itself is an
			// oracle for guessing the other half.
			w.Header().Set("WWW-Authenticate", `Basic realm="Razorpay"`)
			s.writeError(w, http.StatusUnauthorized, "BAD_REQUEST_ERROR",
				"Authentication failed", "NA", "NA", "input_validation_failed", nil)
			return
		}
		h(w, r)
	})
}

// authorized compares the presented credentials against the configured pair in
// constant time.
//
// Both halves are compared over their SHA-256 digests rather than their raw
// bytes, so the comparison is fixed-length and cannot leak the secret's length
// through timing. Neither result short-circuits the other: a bitwise AND keeps
// the work identical whichever half is wrong.
func (s *server) authorized(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	gotID := sha256.Sum256([]byte(user))
	gotSecret := sha256.Sum256([]byte(pass))
	idOK := hmacEqual(gotID[:], s.keyIDHash[:])
	secretOK := hmacEqual(gotSecret[:], s.keySecHash[:])
	return idOK && secretOK
}

func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"scenario": s.timeline.Scenario(),
		"seed":     s.timeline.Seed(),
		"payments": s.payments.size(),
	})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.metrics.Snapshot())
}

func (s *server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, http.StatusNotFound, "BAD_REQUEST_ERROR",
		"The requested URL was not found on the server", "NA", "NA", "input_validation_failed", nil)
}

// ---------------------------------------------------------------------------
// Razorpay response shapes
// ---------------------------------------------------------------------------

// errorEnvelope is Razorpay's error body, field for field.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code        string            `json:"code"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Step        string            `json:"step"`
	Reason      string            `json:"reason"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// writeJSON marshals before touching the response, so a marshalling failure
// produces a clean 500 rather than a half-written body with a 200 status
// already committed.
func (s *server) writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		s.log.Error("could not marshal response", "cause", err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"SERVER_ERROR","description":"The server encountered an error","source":"NA","step":"NA","reason":"server_error"}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		// A client that hung up mid-response is normal, not an incident.
		s.log.Debug("response write interrupted", "cause", err.Error())
	}
}

// writeError emits the error envelope. Every description passed here is a fixed
// string from this package: no request content is ever reflected into a
// response, so the endpoint cannot be used to echo an attacker's payload back
// through a log or a console.
func (s *server) writeError(w http.ResponseWriter, status int, code, description,
	source, step, reason string, metadata map[string]string) {
	s.writeJSON(w, status, errorEnvelope{Error: errorBody{
		Code:        code,
		Description: description,
		Source:      source,
		Step:        step,
		Reason:      reason,
		Metadata:    metadata,
	}})
}

// ---------------------------------------------------------------------------
// Determinism helpers
// ---------------------------------------------------------------------------

// draw returns a per-mille value derived from the run seed and the caller's
// discriminators.
//
// A keyed hash rather than a shared generator, because HTTP handlers run
// concurrently: a shared *rand.Rand would hand out draws in whatever order the
// scheduler happened to run the goroutines, so two identical runs could reach
// different verdicts. Keying on (scope, payment id, attempt) makes every
// verdict a pure function of what it is about, which also means a retry of the
// same attempt returns the same answer — the correct behaviour for an
// idempotent request.
func (s *server) draw(scope, id string, attempt int) int {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], uint64(s.timeline.Seed()))
	mac := hmac.New(sha256.New, key[:])
	absorbString(mac, scope)
	absorbString(mac, id)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(attempt))
	absorbString(mac, string(n[:]))
	return int(binary.BigEndian.Uint64(mac.Sum(nil)[:8]) % perMille)
}

// validRazorID bounds and shape-checks a path identifier before it is used as a
// map key or echoed into a response. Length first: an identifier is attacker
// controlled, and an unbounded one is an unbounded allocation.
func validRazorID(prefix, id string) bool {
	if len(id) > maxIdentifierLen {
		return false
	}
	rest, ok := strings.CutPrefix(id, prefix+"_")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		default:
			return false
		}
	}
	return true
}

// systemClock is the production Clock. Every component here takes a
// domain.Clock rather than calling time.Now, so a test can place the run
// anywhere on the timeline without waiting for it.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

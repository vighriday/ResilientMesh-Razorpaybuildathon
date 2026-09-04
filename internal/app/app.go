// Package app is the composition root: it turns a config.Config into a wired,
// runnable system.
//
// There is exactly one of these because there are three binaries. cmd/api,
// cmd/worker and cmd/mesh differ only in which roles they enable, so wiring
// them separately would guarantee that they drift — a middleware added to the
// API and forgotten in the all-in-one demo is the kind of difference nobody
// notices until a judge runs the demo instead of the server.
//
// Construction is fail-fast and ordered. Anything that can fail — reaching the
// database, applying migrations, reading the cost model, creating the consumer
// group — fails in New, where an operator sees it at startup, rather than on
// first use, where it becomes a 500 at three in the morning.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/agent"
	"github.com/hriday/razorpay-resilient-mesh/internal/audit"
	"github.com/hriday/razorpay-resilient-mesh/internal/breaker"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/downtime"
	"github.com/hriday/razorpay-resilient-mesh/internal/executor"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/infra"
	"github.com/hriday/razorpay-resilient-mesh/internal/ingest"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/outbox"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
	"github.com/hriday/razorpay-resilient-mesh/internal/queue"
	"github.com/hriday/razorpay-resilient-mesh/internal/sse"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
	"github.com/hriday/razorpay-resilient-mesh/internal/telemetry"
	"github.com/hriday/razorpay-resilient-mesh/internal/worker"
)

// Role selects which halves of the system a process runs.
//
// Splitting the API from the worker is what lets the edge scale on request
// volume while recovery scales on incident volume, and those two numbers are
// unrelated: a merchant with one very large outage has few requests and many
// incidents.
type Role string

const (
	// RoleAPI serves the webhook edge, the checkout stream, the ops API and the
	// static console.
	RoleAPI Role = "api"
	// RoleWorker runs the recovery pipeline, the outbox relay and the downtime
	// poller.
	RoleWorker Role = "worker"
)

const (
	// shutdownGrace bounds the drain of in-flight HTTP requests. A recovery
	// decision that is dropped mid-flight is a payment nobody retries, so the
	// window is generous relative to the p99 request.
	shutdownGrace = 15 * time.Second

	// redisDialTimeout keeps a wrong RedisAddr from looking like a hang.
	redisDialTimeout = 5 * time.Second

	// readinessTimeout bounds each dependency probe on /readyz. A readiness
	// check that can block forever turns a degraded dependency into a hung
	// load balancer.
	readinessTimeout = 2 * time.Second

	// downtimeStaleAfter is how long the downtime view may go unrefreshed
	// before readiness reports the process as not ready. Recovery decisions are
	// made against this cache, so a stale view is silently wrong rather than
	// loudly broken, which is exactly the failure a readiness probe exists for.
	downtimeStaleAfter = 2 * time.Minute
)

// App is a fully wired system. Every field is written once during New and only
// read afterwards, so an App may be shared across goroutines without
// synchronisation; Close carries its own.
type App struct {
	cfg   config.Config
	log   *slog.Logger
	clock domain.Clock
	metr  *obs.Registry
	roles map[Role]bool

	// Owned resources, in construction order. Close releases them in reverse.
	managed *infra.Runtime
	pg      *store.Postgres
	rdb     *redis.Client
	q       *queue.Redis

	ledger    *audit.Ledger
	telemetry *telemetry.Recorder
	breaker   *breaker.Breaker
	downtime  *downtime.Poller
	diagnoser *agent.Stack
	policy    *policy.Engine
	gate      *gatekeeper.Gatekeeper
	exec      *executor.Gateway
	hub       *sse.Hub
	relay     *outbox.Relay
	pool      *worker.Pool
	webhook   *ingest.Handler

	// Handler is the API mux. It is nil when RoleAPI is not enabled, which is
	// what makes a worker process incapable of serving a request by accident.
	Handler http.Handler

	// listener is bound during New rather than during Run so that a port
	// conflict is reported at startup, and so cmd/mesh can print the address it
	// actually got instead of the one it hoped for.
	listener net.Listener

	closeOnce sync.Once
	closeErr  error
}

// Options are the knobs a caller supplies that do not belong in the
// environment: the clock (so a test can freeze time) and the logger.
type Options struct {
	// Roles selects the halves to run. Empty enables both, which is the
	// single-process demo.
	Roles []Role
	// Clock is injected so a test can make startup deterministic. Nil is the
	// wall clock.
	Clock domain.Clock
	// Logger receives structured records. Nil builds one from cfg.LogLevel.
	Logger *slog.Logger
	// SkipManagedInfra suppresses starting embedded Postgres and miniredis even
	// in managed mode, for a caller that has already started them and wants a
	// second App against the same backing services.
	SkipManagedInfra bool
}

// New builds the system. On any failure it releases whatever it had already
// built and returns a nil App, so a caller cannot leak a half-constructed
// process by forgetting to check the error.
func New(ctx context.Context, cfg config.Config, opts Options) (a *App, err error) {
	logger := opts.Logger
	if logger == nil {
		logger = obs.NewLogger(cfg.LogLevel, nil)
	}
	clock := opts.Clock
	if clock == nil {
		clock = systemClock{}
	}

	roles := map[Role]bool{}
	for _, r := range opts.Roles {
		switch r {
		case RoleAPI, RoleWorker:
			roles[r] = true
		default:
			return nil, fmt.Errorf("app: unknown role %q", r)
		}
	}
	if len(roles) == 0 {
		roles[RoleAPI], roles[RoleWorker] = true, true
	}

	app := &App{
		cfg:   cfg,
		log:   logger,
		clock: clock,
		metr:  obs.NewRegistry(),
		roles: roles,
	}
	// Every early return past this point must release what has been built.
	// Deferring the teardown is the only version of this that stays correct as
	// steps are added between here and the end of the function.
	defer func() {
		if err != nil {
			_ = app.Close()
		}
	}()

	if cfg.InfraMode == config.InfraManaged && !opts.SkipManagedInfra {
		rt, startErr := infra.StartManaged(ctx, infra.Options{
			Logger: logger,
			Clock:  clock,
		})
		if startErr != nil {
			return nil, fmt.Errorf("app: starting managed infrastructure: %w", startErr)
		}
		app.managed = rt
		// The managed runtime owns the credentials, so the resolved endpoints
		// replace whatever the environment said. Downstream code therefore has
		// no reason to branch on InfraMode.
		app.cfg.PGDSN = rt.PGDSN
		app.cfg.RedisAddr = rt.RedisAddr
		logger.Info("managed infrastructure ready",
			"pg_port", rt.PGPort, "redis_port", rt.RedisPort,
			"cold_start", rt.ColdStart, "startup", rt.StartupDuration)
	}

	if app.cfg.PGDSN == "" {
		return nil, errors.New("app: no PostgreSQL DSN; set MESH_PG_DSN or use managed infrastructure")
	}
	pg, err := store.New(ctx, app.cfg.PGDSN, logger)
	if err != nil {
		return nil, fmt.Errorf("app: opening the store: %w", err)
	}
	app.pg = pg

	app.rdb = redis.NewClient(&redis.Options{
		Addr:         app.cfg.RedisAddr,
		DialTimeout:  redisDialTimeout,
		ReadTimeout:  0, // blocking reads on the stream set their own deadline
		WriteTimeout: redisDialTimeout,
	})
	if err = app.rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("app: reaching Redis at %s: %w", app.cfg.RedisAddr, err)
	}

	app.q = queue.New(app.rdb, queue.DefaultConfig(), logger)
	// The group is created explicitly at startup rather than lazily on the
	// first read, so a permissions or connectivity problem surfaces here.
	if err = app.q.EnsureGroup(ctx, queue.GroupWorkers); err != nil {
		return nil, fmt.Errorf("app: creating the consumer group: %w", err)
	}

	app.ledger = audit.New(pg, clock, auditActor(roles))
	app.telemetry = telemetry.New(app.rdb, clock, app.cfg.TelemetryWindow)

	app.breaker = breaker.New(app.rdb, clock, breaker.Config{
		TripRate:   app.cfg.BreakerTripRate,
		MinSamples: app.cfg.BreakerMinSamples,
		Cooldown:   app.cfg.BreakerCooldown,
		Logger:     logger,
	})

	app.policy = policy.New(clock, rand.New(rand.NewSource(app.cfg.Seed)))
	app.gate = gatekeeper.New(clock, app.policy, gatekeeper.Config{
		MaxAttempts: app.cfg.MaxAttempts,
	})

	app.diagnoser, err = agent.New(agent.Config{
		BaseURL:     app.cfg.LLMBaseURL,
		APIKey:      app.cfg.LLMAPIKey,
		Model:       app.cfg.LLMModel,
		Timeout:     app.cfg.LLMTimeout,
		CassetteDir: app.cfg.CassetteDir,
	}, logger, clock)
	if err != nil {
		return nil, fmt.Errorf("app: building the inference stack: %w", err)
	}

	app.hub = sse.NewHub(sse.HubConfig{
		Clock:                clock,
		MaxRetainedSequences: app.cfg.MaxSessions,
	})

	app.exec, err = executor.New(executor.Config{
		BaseURL:   app.cfg.RazorpayBaseURL,
		KeyID:     app.cfg.RazorpayKeyID,
		KeySecret: app.cfg.RazorpayKeySecret,
		CostModel: app.cfg.CostModel,
	}, app.hub, pg, clock, logger, app.metr)
	if err != nil {
		return nil, fmt.Errorf("app: building the gateway executor: %w", err)
	}

	// The poller is constructed for both roles because the ops console reads
	// the downtime view, but only the worker registers a resolution callback:
	// releasing parked retries from two processes would release them twice.
	var onResolved downtime.ResolutionFunc
	if roles[RoleWorker] {
		onResolved = app.releaseParkedRetries
	}
	app.downtime = downtime.New(downtime.Config{
		BaseURL:   app.cfg.RazorpayBaseURL,
		KeyID:     app.cfg.RazorpayKeyID,
		KeySecret: app.cfg.RazorpayKeySecret,
	}, clock, logger, app.metr, onResolved)

	if roles[RoleWorker] {
		app.relay = outbox.New(outbox.DefaultConfig(), pg, app.q, app.ledger, logger, app.metr,
			rand.New(rand.NewSource(app.cfg.Seed^relaySeedSalt)))

		app.pool, err = worker.New(worker.Config{
			Concurrency:   app.cfg.WorkerConcurrency,
			SessionTTL:    app.cfg.SessionTTL,
			DemoTimeScale: app.cfg.DemoTimeScale,
		}, worker.Deps{
			Store:           pg,
			Queue:           app.q,
			DeadLetter:      app.q,
			Diagnoser:       app.diagnoser,
			Gatekeeper:      app.gate,
			Policy:          app.policy,
			Telemetry:       app.telemetry,
			Breaker:         app.breaker,
			Downtime:        app.downtime,
			Executor:        app.exec,
			Ledger:          app.ledger,
			Hub:             app.hub,
			Clock:           clock,
			Log:             logger,
			Metrics:         app.metr,
			AvailableRails:  merchantRails,
			DowntimeSignals: app.downtime.Signals,
		})
		if err != nil {
			return nil, fmt.Errorf("app: building the worker pool: %w", err)
		}
	}

	if roles[RoleAPI] {
		app.webhook, err = ingest.New(ingest.Config{
			Secret:  []byte(app.cfg.WebhookSecret),
			MaxSkew: app.cfg.WebhookMaxSkew,
		}, pg, app.ledger, clock, logger, app.metr)
		if err != nil {
			return nil, fmt.Errorf("app: building the webhook edge: %w", err)
		}
		app.Handler = app.buildMux()

		app.listener, err = net.Listen("tcp", app.cfg.HTTPAddr)
		if err != nil {
			// Deliberately not falling back to another port. Printing a URL
			// that is not the one an operator configured is worse than
			// refusing to start.
			return nil, fmt.Errorf("app: binding %s: %w", app.cfg.HTTPAddr, err)
		}
	}

	return app, nil
}

// merchantRails is the rail set this deployment's merchant has enabled.
//
// The gatekeeper will not permit a morph onto anything outside it, so this is a
// security boundary rather than a preference: a model that proposes a rail the
// merchant never enabled is proposing a payment the merchant cannot settle.
// RailNone is deliberately absent — it is the sentinel for "no rail", not a
// destination.
var merchantRails = []domain.Rail{
	domain.RailUPIIntent,
	domain.RailUPICollect,
	domain.RailCard,
	domain.RailNetbanking,
	domain.RailWallet,
}

// relaySeedSalt keeps the outbox relay's jitter from replaying the same
// sequence as the policy engine's backoff. Two components seeded identically
// produce correlated delays, which is the opposite of what jitter is for.
const relaySeedSalt = 0x5f3759df

// auditActor names the process in every ledger entry it writes, so a chain read
// months later still says which half of the system took the action.
func auditActor(roles map[Role]bool) string {
	switch {
	case roles[RoleAPI] && roles[RoleWorker]:
		return "mesh"
	case roles[RoleWorker]:
		return "worker"
	default:
		return "api"
	}
}

// Addr reports the address the API is actually listening on, which is not
// necessarily the configured one: ":0" resolves to a kernel-assigned port, and
// a caller printing a URL must print the resolved value.
func (a *App) Addr() string {
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

// Metrics exposes the registry so an embedding process can record its own
// series into the same output.
func (a *App) Metrics() *obs.Registry { return a.metr }

// Config returns the resolved configuration, including any endpoints the
// managed runtime overwrote.
func (a *App) Config() config.Config { return a.cfg }

// Store exposes the durable store for tooling that has to query what the system
// actually recorded — the end-to-end self-test reads its results from here
// rather than from in-process counters, so the numbers it reports are the ones
// a reviewer would find by querying the database themselves.
func (a *App) Store() *store.Postgres { return a.pg }

// Run starts every enabled role and returns when all of them have stopped.
//
// The first error wins and cancels the rest: a worker pool that keeps running
// after the API has failed to bind is a process that looks healthy to its
// supervisor while serving nothing.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	fail := func(name string, err error) {
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
			return
		}
		mu.Lock()
		if first == nil {
			first = fmt.Errorf("%s: %w", name, err)
		}
		mu.Unlock()
		cancel()
	}
	spawn := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fail(name, fn(ctx))
		}()
	}

	// The downtime poller runs in both roles: the worker needs it to release
	// parked retries, and the API serves its view to the console.
	spawn("downtime", a.downtime.Run)

	if a.roles[RoleWorker] {
		spawn("outbox", a.relay.Run)
		spawn("worker", a.pool.Run)
	}

	if a.roles[RoleAPI] {
		srv := &http.Server{
			Handler: a.Handler,
			// A server with no header timeout is a slowloris target: a client
			// that dribbles one header byte per minute holds a connection open
			// indefinitely and costs the attacker nothing.
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			// WriteTimeout is deliberately unset. The event stream is a long
			// -lived response and a write deadline would cut it; sse.Handler
			// sets its own per-frame deadline instead, which bounds a stalled
			// peer without bounding a healthy stream.
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 16,
			ErrorLog:       nil,
		}
		spawn("http", func(ctx context.Context) error {
			// Shutdown is driven from here rather than from a separate
			// goroutine so the drain cannot outlive the server's own lifetime.
			done := make(chan error, 1)
			go func() { done <- srv.Serve(a.listener) }()
			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				grace, stop := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
				defer stop()
				if err := srv.Shutdown(grace); err != nil {
					// A drain that times out is reported rather than
					// swallowed: it means a request was cut off, and someone
					// should know which deploy did that.
					a.log.Warn("http drain did not complete within the grace period", "error", err)
					_ = srv.Close()
				}
				return nil
			}
		})
		a.log.Info("api listening", "addr", a.Addr())
	}

	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return first
}

// Close releases every owned resource in reverse construction order. It is
// idempotent, because a failed New calls it and a caller's defer calls it
// again.
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		var errs []error
		add := func(what string, err error) {
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", what, err))
			}
		}
		if a.listener != nil {
			// Already closed by http.Server.Serve in the normal path; closing
			// twice returns an error that carries no information.
			_ = a.listener.Close()
		}
		if a.q != nil {
			add("queue", a.q.Close())
		}
		if a.rdb != nil {
			add("redis", a.rdb.Close())
		}
		if a.pg != nil {
			add("store", a.pg.Close())
		}
		if a.managed != nil {
			// Last, and unconditionally: embedded PostgreSQL leaves an orphaned
			// postmaster behind if Stop is not called, and an orphan holds the
			// data directory lock against the next run.
			add("managed infrastructure", a.managed.Stop())
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}

// releaseParkedRetries is the downtime resolution callback.
//
// This is the behaviour the whole system is organised around: incumbents
// estimate when an issuer will recover because their processors do not tell
// them, while Razorpay publishes the resolution. Waiting out a computed backoff
// for an event that is being broadcast is strictly worse than subscribing to
// the broadcast, so the backoff becomes an upper bound and the notice is the
// mechanism.
func (a *App) releaseParkedRetries(ctx context.Context, issuerKey string, ent domain.DowntimeEntity) {
	a.metr.Counter("downtime.release_requested").Inc()
	if _, err := a.ledger.Append(ctx, domain.AuditDowntimeRelease, "", auditActor(a.roles), map[string]any{
		"issuer_key":  issuerKey,
		"downtime_id": ent.ID,
		"method":      ent.Method,
		"severity":    ent.Severity,
	}); err != nil {
		a.log.Warn("could not record a downtime release in the ledger",
			"issuer_key", issuerKey, "error", err)
	}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

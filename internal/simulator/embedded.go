package simulator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// EmbeddedConfig configures an in-process simulator.
//
// This exists so cmd/mesh can bring up the whole demo in one process. Shelling
// out to a second binary would add a failure mode — a child that starts slowly,
// binds a different port, or outlives its parent — that has nothing to do with
// the system being demonstrated, and a judge hitting that failure would be
// diagnosing the harness rather than the work.
type EmbeddedConfig struct {
	// Addr is the listen address. ":0" takes a kernel-assigned port, which the
	// caller then reads back from Embedded.Addr.
	Addr string

	// Target is where webhooks are delivered. Empty disables delivery, which is
	// what a caller wants when it will drive the script itself.
	Target string

	// Secret signs outgoing webhooks. It must match the mesh's
	// MESH_WEBHOOK_SECRET or every delivery is correctly rejected.
	Secret string

	// KeyID and KeySecret authenticate inbound API calls, matching what the
	// executor is configured with.
	KeyID, KeySecret string

	Scenario          string
	Seed              int64
	Rate              float64
	Duration          time.Duration
	DuplicatePerMille int

	Clock   domain.Clock
	Log     *slog.Logger
	Metrics *obs.Registry
}

// Embedded is a running in-process simulator.
type Embedded struct {
	listener net.Listener
	http     *http.Server
	srv      *server
	timeline *Timeline
	script   []ScheduledEvent
	emitter  *emitter
	clock    domain.Clock
	log      *slog.Logger

	stopOnce sync.Once
}

// NewEmbedded builds and binds the simulator without starting it.
//
// Binding here rather than in Run is what lets the caller print the real
// address before any traffic flows, and what makes a port conflict a startup
// error instead of a message that arrives after the URLs have been shown.
func NewEmbedded(cfg EmbeddedConfig) (*Embedded, error) {
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = obs.NewRegistry()
	}
	if cfg.Scenario == "" {
		cfg.Scenario = ScenarioIssuerOutage
	}
	if cfg.Duration <= 0 {
		cfg.Duration = time.Hour
	}
	// A modest default rate: the demo is about what happens to each incident,
	// not about throughput, and a flood makes the console unreadable.
	if cfg.Rate <= 0 {
		cfg.Rate = 4
	}

	timeline, err := NewTimeline(cfg.Scenario, cfg.Seed, cfg.Clock.Now(), cfg.Duration)
	if err != nil {
		return nil, err
	}
	script, err := timeline.Script(cfg.Rate, cfg.DuplicatePerMille)
	if err != nil {
		return nil, err
	}

	srv, err := newServer(serverConfig{
		Timeline:     timeline,
		Clock:        cfg.Clock,
		Log:          cfg.Log,
		Metrics:      cfg.Metrics,
		KeyID:        cfg.KeyID,
		KeySecret:    cfg.KeySecret,
		PaymentLimit: len(script) + maxTrackedPayments,
	})
	if err != nil {
		return nil, err
	}
	// Registering every scripted payment up front is what lets a retry that
	// overtakes its own webhook still find the real entity. The mesh is
	// routinely faster than the delivery.
	for _, ev := range script {
		srv.payments.put(ev.Payment)
	}

	var em *emitter
	if cfg.Target != "" && cfg.Target != targetDisabled {
		em, err = newEmitter(emitterConfig{
			Target:    cfg.Target,
			Secret:    cfg.Secret,
			AccountID: timeline.AccountID(),
			Seed:      cfg.Seed,
			Clock:     cfg.Clock,
			Log:       cfg.Log,
			Metrics:   cfg.Metrics,
		})
		if err != nil {
			return nil, err
		}
	}

	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("simulator: listen on %s: %w", addr, err)
	}

	return &Embedded{
		listener: listener,
		http: &http.Server{
			Handler:           srv,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 16,
			ErrorLog:          slog.NewLogLogger(cfg.Log.Handler(), slog.LevelWarn),
		},
		srv:      srv,
		timeline: timeline,
		script:   script,
		emitter:  em,
		clock:    cfg.Clock,
		log:      cfg.Log,
	}, nil
}

// Addr is the bound address, which is not necessarily the requested one when
// the caller asked for port zero.
func (e *Embedded) Addr() string { return e.listener.Addr().String() }

// BaseURL is the address in the form the executor and the downtime poller take.
func (e *Embedded) BaseURL() string { return "http://" + e.Addr() }

// Events is how many webhook deliveries the script will make.
func (e *Embedded) Events() int { return len(e.script) }

// Scenario names the outage being replayed.
func (e *Embedded) Scenario() string { return e.timeline.Scenario() }

// Run serves until ctx is cancelled, dispatching the script if a target was
// configured. It returns only after the HTTP drain and the script have both
// finished, so a caller that returns from Run knows nothing is still emitting.
func (e *Embedded) Run(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		err := e.http.Serve(e.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	var script sync.WaitGroup
	if e.emitter != nil {
		script.Add(1)
		go func() {
			defer script.Done()
			dispatch(ctx, e.emitter, e.script, e.timeline.Start(), e.clock, e.log)
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			runErr = fmt.Errorf("simulator: http server: %w", err)
		}
	}

	e.Stop()
	script.Wait()
	return runErr
}

// Stop drains the HTTP server. It is idempotent so a caller may both defer it
// and let Run call it.
func (e *Embedded) Stop() {
	e.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := e.http.Shutdown(ctx); err != nil {
			e.log.Warn("simulator shutdown did not complete cleanly", "cause", err.Error())
			_ = e.http.Close()
		}
	})
}

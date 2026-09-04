// Package outbox drains durably-recorded events into the work queue.
//
// It exists because a database write and a queue publish cannot be made atomic
// across two systems. The edge commits the incident and the outbox row in one
// transaction; this relay moves rows onto the queue afterwards, at-least-once.
// The consequence worth stating plainly: when the queue is unavailable the
// relay stalls and rows accumulate, and that is the designed behaviour. The
// outbox is the buffer, and nothing is lost while it fills.
package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// Config tunes the relay loop.
type Config struct {
	// BatchSize bounds how many rows one iteration claims. Larger batches
	// amortise round trips; smaller batches shorten the window in which a
	// crash leaves rows claimed-but-undispatched and awaiting redelivery.
	BatchSize int
	// PollInterval is the idle sleep when there was nothing to do.
	PollInterval time.Duration
	// MinBackoff and MaxBackoff bound the retry delay when the queue is
	// unhealthy. Backoff is jittered because a fleet of relays that all retry
	// on the same schedule reconverges into a thundering herd the moment the
	// queue recovers, which is when it can least absorb one.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// MaxPublishAttempts is how many times a single row may fail to publish
	// before it is parked as failed. Without a ceiling one malformed row spins
	// forever and starves every healthy row behind it.
	MaxPublishAttempts int
	// DrainTimeout bounds the shutdown drain.
	DrainTimeout time.Duration
}

const (
	// probeTimeout bounds the queue health check taken after a publish failure.
	// It is short because the answer is only used to classify a failure that
	// has already happened, and a slow probe would hold the batch open.
	probeTimeout = 2 * time.Second

	// releaseTimeout bounds handing leased rows back. Short for the same
	// reason: failing to release is recoverable, because the lease expires.
	releaseTimeout = 3 * time.Second
)

// DefaultConfig returns settings sized for the demo and for CI.
func DefaultConfig() Config {
	return Config{
		BatchSize:          128,
		PollInterval:       200 * time.Millisecond,
		MinBackoff:         250 * time.Millisecond,
		MaxBackoff:         15 * time.Second,
		MaxPublishAttempts: 8,
		DrainTimeout:       10 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.BatchSize <= 0 {
		c.BatchSize = d.BatchSize
	}
	if c.PollInterval <= 0 {
		c.PollInterval = d.PollInterval
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = d.MinBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = d.MaxBackoff
	}
	if c.MaxPublishAttempts <= 0 {
		c.MaxPublishAttempts = d.MaxPublishAttempts
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = d.DrainTimeout
	}
	return c
}

// Relay moves pending outbox rows onto the queue.
type Relay struct {
	cfg     Config
	store   domain.Store
	queue   domain.Queue
	ledger  domain.AuditLedger
	log     *slog.Logger
	metrics *obs.Registry

	rngMu sync.Mutex
	rng   *rand.Rand

	// consecutiveFailures drives the backoff curve and is only touched by the
	// single relay goroutine.
	consecutiveFailures int
}

// New builds a relay. rng is injected so backoff jitter is reproducible under
// test; production passes a time-seeded source.
func New(cfg Config, st domain.Store, q domain.Queue, ledger domain.AuditLedger, log *slog.Logger, m *obs.Registry, rng *rand.Rand) *Relay {
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return &Relay{
		cfg: cfg.withDefaults(), store: st, queue: q,
		ledger: ledger, log: log, metrics: m, rng: rng,
	}
}

// Run drives the relay until ctx is cancelled, then drains once more.
//
// The final drain matters: without it a graceful shutdown leaves every row
// claimed in the last iteration sitting pending until another instance picks
// them up, which on a single-instance deploy means until restart.
func (r *Relay) Run(ctx context.Context) error {
	r.log.Info("outbox relay started",
		"batch_size", r.cfg.BatchSize, "poll_interval", r.cfg.PollInterval)

	for {
		select {
		case <-ctx.Done():
			r.drain()
			r.log.Info("outbox relay stopped")
			return nil
		default:
		}

		dispatched, err := r.Once(ctx)
		switch {
		case err != nil:
			r.consecutiveFailures++
			delay := r.backoff()
			r.log.Warn("outbox iteration failed; backing off",
				"error", err, "consecutive_failures", r.consecutiveFailures, "backoff", delay)
			r.count("outbox.iteration_failed")
			if !sleepCtx(ctx, delay) {
				r.drain()
				return nil
			}
		case dispatched == 0:
			r.consecutiveFailures = 0
			if !sleepCtx(ctx, r.cfg.PollInterval) {
				r.drain()
				return nil
			}
		default:
			// Work was found, so loop straight back without sleeping: a
			// backlog should drain at the speed of the queue, not at the speed
			// of the poll timer.
			r.consecutiveFailures = 0
		}
	}
}

// drain performs one final best-effort iteration on shutdown, on its own
// timeout because the parent context is already cancelled.
func (r *Relay) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.DrainTimeout)
	defer cancel()
	n, err := r.Once(ctx)
	if err != nil {
		r.log.Warn("final outbox drain did not complete; rows remain pending for the next start", "error", err)
		return
	}
	if n > 0 {
		r.log.Info("final outbox drain dispatched remaining rows", "count", n)
	}
}

// Once claims a batch and publishes it. It is exported so tests and the
// end-to-end harness can step the relay deterministically instead of racing a
// background loop.
func (r *Relay) Once(ctx context.Context) (int, error) {
	batch, err := r.store.ClaimOutboxBatch(ctx, r.cfg.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("claiming outbox batch: %w", err)
	}
	if len(batch) == 0 {
		return 0, nil
	}

	dispatched := make([]int64, 0, len(batch))
	var firstErr error

	// unpublished tracks the tail of the batch abandoned after a failure, so
	// those rows can be handed back explicitly rather than left leased until
	// their lease expires.
	var unpublished []int64
	failedAt := -1

	for i, ev := range batch {
		if ctx.Err() != nil {
			unpublished = append(unpublished, idsFrom(batch[i:])...)
			break
		}
		err := r.queue.Publish(ctx, ev.Topic, ev)
		if err == nil {
			dispatched = append(dispatched, ev.ID)
			continue
		}

		if firstErr == nil {
			firstErr = err
		}
		failedAt = i
		// Abandoning the rest of the batch avoids hammering a dead queue once
		// per row. Those rows are handed back below.
		unpublished = append(unpublished, idsFrom(batch[i+1:])...)
		break
	}

	if failedAt >= 0 {
		r.handlePublishFailure(ctx, batch[failedAt], firstErr, unpublished)
	} else if len(unpublished) > 0 {
		r.release(ctx, unpublished)
	}

	if len(dispatched) > 0 {
		if err := r.store.MarkOutboxDispatched(ctx, dispatched); err != nil {
			// The rows are on the queue but not marked. At-least-once delivery
			// makes that safe: they will be published again and the consumer's
			// idempotency absorbs the duplicate. Losing them would not be safe,
			// so this is the correct direction to fail in.
			r.count("outbox.mark_failed")
			return len(dispatched), fmt.Errorf("marking %d dispatched row(s): %w", len(dispatched), err)
		}
		r.count("outbox.dispatched")
		r.add("outbox.dispatched_total", uint64(len(dispatched)))
	}

	if firstErr != nil {
		return len(dispatched), fmt.Errorf("publishing outbox batch: %w", firstErr)
	}
	return len(dispatched), nil
}

// idsFrom projects a batch onto its row ids.
func idsFrom(batch []domain.OutboxEvent) []int64 {
	out := make([]int64, 0, len(batch))
	for _, ev := range batch {
		out = append(out, ev.ID)
	}
	return out
}

// release hands leased rows back without charging them.
func (r *Relay) release(ctx context.Context, ids []int64) {
	if len(ids) == 0 {
		return
	}
	// Released with a context that survives the caller's cancellation. A
	// shutdown that left rows leased would stall the next process for the
	// length of the lease, which is the worst moment to add latency.
	rel, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	if err := r.store.ReleaseOutboxClaim(rel, ids); err != nil {
		// Not fatal: the lease expires on its own. Logged because a persistent
		// failure here shows up as unexplained dispatch latency.
		r.log.Warn("could not release an outbox claim; the lease will expire instead",
			"rows", len(ids), "error", err)
	}
}

// handlePublishFailure decides whether the failure was the row's fault.
//
// This is the distinction that matters. A broker outage makes every publish
// fail for reasons that have nothing to do with any particular row, so charging
// a retry budget for it destroys work that was never poison — and because the
// budget is small and an outage is long, it destroys all of it. The queue is
// therefore probed: if it answers, this row failed on its own merits and the
// attempt is charged; if it does not, every row in the batch is handed back
// untouched and the relay's jittered backoff rides the outage out.
func (r *Relay) handlePublishFailure(ctx context.Context, ev domain.OutboxEvent, cause error, tail []int64) {
	probe, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
	defer cancel()
	if err := r.queue.Ping(probe); err != nil {
		// Transport failure. Nothing here is attributable to a row.
		r.count("outbox.transport_failure")
		r.release(ctx, append([]int64{ev.ID}, tail...))
		return
	}

	// The queue is reachable and this row still would not publish, so the row
	// is the problem. The rest of the batch is still innocent.
	r.release(ctx, tail)

	attempts := ev.Attempts + 1
	if attempts < r.cfg.MaxPublishAttempts {
		if err := r.store.RecordOutboxFailure(ctx, ev.ID, cause.Error()); err != nil {
			r.log.Error("could not record an outbox publish failure",
				"outbox_id", ev.ID, "incident_id", ev.IncidentID, "error", err)
		}
		return
	}

	// Exhausted, and exhausted against a reachable queue every time. Park it and
	// make the decision visible: a row that stops being retried without a trace
	// is an event silently dropped.
	r.count("outbox.poisoned")
	r.log.Error("outbox row exhausted its publish attempts and was parked",
		"outbox_id", ev.ID, "incident_id", ev.IncidentID,
		"attempts", attempts, "error", cause)

	if err := r.store.MarkOutboxFailed(ctx, ev.ID, fmt.Sprintf("exhausted after %d attempts: %v", attempts, cause)); err != nil {
		r.log.Error("could not park an exhausted outbox row",
			"outbox_id", ev.ID, "error", err)
	}
	if r.ledger != nil {
		if _, err := r.ledger.Append(ctx, domain.AuditDeadLettered, ev.IncidentID, "outbox-relay", map[string]any{
			"outbox_id": ev.ID,
			"topic":     ev.Topic,
			"attempts":  attempts,
			"cause":     truncate(cause.Error(), 512),
		}); err != nil {
			r.log.Error("could not audit a parked outbox row", "outbox_id", ev.ID, "error", err)
		}
	}
}

// backoff returns a jittered delay that grows with consecutive failures.
//
// Full jitter is used rather than exponential-with-small-jitter because the
// failure mode being defended against is correlated: every relay in a fleet
// sees the queue fail at the same instant, so their retry schedules must be
// decorrelated, not merely spread.
func (r *Relay) backoff() time.Duration {
	shift := r.consecutiveFailures - 1
	if shift < 0 {
		shift = 0
	}
	if shift > 20 { // guard the shift itself against overflow
		shift = 20
	}
	ceiling := r.cfg.MinBackoff << uint(shift)
	if ceiling > r.cfg.MaxBackoff || ceiling <= 0 {
		ceiling = r.cfg.MaxBackoff
	}

	r.rngMu.Lock()
	d := time.Duration(r.rng.Int63n(int64(ceiling)))
	r.rngMu.Unlock()

	if d < r.cfg.MinBackoff {
		d = r.cfg.MinBackoff
	}
	return d
}

// Depth reports pending and failed row counts for the health endpoint.
func (r *Relay) Depth(ctx context.Context) (pending, failed int, err error) {
	pending, failed, err = r.store.OutboxDepth(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("reading outbox depth: %w", err)
	}
	r.gauge("outbox.pending", float64(pending))
	r.gauge("outbox.failed", float64(failed))
	return pending, failed, nil
}

// sleepCtx waits for d or until ctx is done. It reports false if the context
// ended, so callers can distinguish a completed wait from a cancellation
// without inspecting the context again.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

func (r *Relay) count(name string) {
	if r.metrics != nil {
		r.metrics.Counter(name).Inc()
	}
}

func (r *Relay) add(name string, n uint64) {
	if r.metrics != nil {
		r.metrics.Counter(name).Add(n)
	}
}

func (r *Relay) gauge(name string, v float64) {
	if r.metrics != nil {
		r.metrics.Gauge(name).Set(v)
	}
}

// ErrStopped is returned by helpers that observe a cancelled relay.
var ErrStopped = errors.New("outbox: relay stopped")

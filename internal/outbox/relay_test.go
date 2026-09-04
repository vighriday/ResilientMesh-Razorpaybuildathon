package outbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// ---------------------------------------------------------------------------
// Fakes
//
// The relay's contract is about claim/publish/mark ordering and failure
// behaviour, so the store and queue are faked. The real SKIP LOCKED semantics
// are covered by the store's suite against PostgreSQL.
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu sync.Mutex

	pending    []domain.OutboxEvent
	dispatched []int64
	failed     map[int64]string
	attempts   map[int64]int

	claimErr    error
	markErr     error
	claimCalls  int
	claimedOnce map[int64]bool
}

func newStore(n int) *fakeStore {
	s := &fakeStore{
		failed:      map[int64]string{},
		attempts:    map[int64]int{},
		claimedOnce: map[int64]bool{},
	}
	for i := 1; i <= n; i++ {
		s.pending = append(s.pending, domain.OutboxEvent{
			ID:         int64(i),
			IncidentID: fmt.Sprintf("inc_%03d", i),
			Topic:      "incident.failed",
			Payload:    domain.RawJSON(fmt.Sprintf(`{"incident_id":"inc_%03d"}`, i)),
			State:      domain.OutboxPending,
		})
	}
	return s
}

func (s *fakeStore) ClaimOutboxBatch(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimCalls++
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	if len(s.pending) == 0 {
		return nil, nil
	}
	if limit > len(s.pending) {
		limit = len(s.pending)
	}
	out := make([]domain.OutboxEvent, limit)
	copy(out, s.pending[:limit])
	for i := range out {
		out[i].Attempts = s.attempts[out[i].ID]
	}
	return out, nil
}

func (s *fakeStore) MarkOutboxDispatched(_ context.Context, ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markErr != nil {
		return s.markErr
	}
	for _, id := range ids {
		s.dispatched = append(s.dispatched, id)
		for i, ev := range s.pending {
			if ev.ID == id {
				s.pending = append(s.pending[:i], s.pending[i+1:]...)
				break
			}
		}
	}
	return nil
}

func (s *fakeStore) MarkOutboxFailed(_ context.Context, id int64, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[id]++
	s.failed[id] = cause
	return nil
}

func (s *fakeStore) OutboxDepth(context.Context) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending), len(s.failed), nil
}

func (s *fakeStore) snapshot() (pending int, dispatched []int64, failed map[int64]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := append([]int64{}, s.dispatched...)
	f := map[int64]string{}
	for k, v := range s.failed {
		f[k] = v
	}
	return len(s.pending), d, f
}

// Unused port methods panic so an accidental dependency fails loudly.
func (s *fakeStore) WithTx(context.Context, func(context.Context, domain.Tx) error) error {
	panic("not used by the relay")
}
func (s *fakeStore) GetIncident(context.Context, string) (domain.Incident, error) {
	panic("not used by the relay")
}
func (s *fakeStore) GetIncidentByEventID(context.Context, string) (domain.Incident, error) {
	panic("not used by the relay")
}

// The scheduling surface is unused by this package's tests, but domain.Store is
// one contract: a fake that implements only the convenient half would compile
// today and fail to notice the day this package starts deferring work.
func (s *fakeStore) ScheduleIncident(context.Context, string, time.Time) error {
	return errors.New("fakeStore: ScheduleIncident is not exercised by these tests")
}

func (s *fakeStore) ClaimDueIncidents(context.Context, time.Time, int) ([]domain.Incident, error) {
	return nil, nil
}

func (s *fakeStore) DueIncidentCount(context.Context, time.Time) (int, error) { return 0, nil }

func (s *fakeStore) UpdateIncidentState(context.Context, string, domain.IncidentState) error {
	panic("not used by the relay")
}
func (s *fakeStore) IncrementIncidentAttempts(context.Context, string) (int, error) {
	panic("not used by the relay")
}
func (s *fakeStore) ListIncidents(context.Context, int) ([]domain.Incident, error) {
	panic("not used by the relay")
}
func (s *fakeStore) GetMandate(context.Context, string) (domain.MandateRecord, error) {
	panic("not used by the relay")
}
func (s *fakeStore) SaveMandate(context.Context, domain.MandateRecord) error {
	panic("not used by the relay")
}
func (s *fakeStore) RecordAttempt(context.Context, domain.AttemptRecord) error {
	panic("not used by the relay")
}
func (s *fakeStore) ListAttempts(context.Context, string) ([]domain.AttemptRecord, error) {
	panic("not used by the relay")
}
func (s *fakeStore) CreateSession(context.Context, domain.SessionRecord) error {
	panic("not used by the relay")
}
func (s *fakeStore) GetSession(context.Context, string) (domain.SessionRecord, error) {
	panic("not used by the relay")
}
func (s *fakeStore) GetSessionByOrder(context.Context, string) (domain.SessionRecord, error) {
	panic("not used by the relay")
}
func (s *fakeStore) UpdateSession(context.Context, domain.SessionRecord) error {
	panic("not used by the relay")
}
func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) Close() error               { return nil }

type fakeQueue struct {
	mu        sync.Mutex
	published []string
	err       error
	failFirst int
	calls     int
}

func (q *fakeQueue) Publish(_ context.Context, _ string, ev domain.OutboxEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls++
	if q.err != nil {
		return q.err
	}
	if q.failFirst > 0 {
		q.failFirst--
		return errors.New("queue unavailable")
	}
	q.published = append(q.published, ev.IncidentID)
	return nil
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.published)
}

func (q *fakeQueue) Consume(context.Context, string, string, int, time.Duration) ([]domain.QueueMessage, error) {
	panic("not used by the relay")
}
func (q *fakeQueue) Ack(context.Context, string, ...string) error { panic("not used by the relay") }
func (q *fakeQueue) Reclaim(context.Context, string, string, time.Duration, int) ([]domain.QueueMessage, error) {
	panic("not used by the relay")
}
func (q *fakeQueue) Depth(context.Context) (int64, error) { return 0, nil }
func (q *fakeQueue) Ping(context.Context) error           { return nil }
func (q *fakeQueue) Close() error                         { return nil }

type fakeLedger struct {
	mu      sync.Mutex
	entries []domain.AuditKind
}

func (l *fakeLedger) Append(_ context.Context, k domain.AuditKind, _, _ string, _ any) (domain.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, k)
	return domain.AuditEntry{}, nil
}
func (l *fakeLedger) kinds() []domain.AuditKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]domain.AuditKind{}, l.entries...)
}
func (l *fakeLedger) List(context.Context, string) ([]domain.AuditEntry, error) { return nil, nil }
func (l *fakeLedger) Verify(context.Context) (domain.VerifyReport, error) {
	return domain.VerifyReport{Valid: true}, nil
}
func (l *fakeLedger) Head(context.Context) (domain.AuditEntry, error) {
	return domain.AuditEntry{}, nil
}

func newRelay(t *testing.T, st *fakeStore, q *fakeQueue, l *fakeLedger, mutate ...func(*Config)) *Relay {
	t.Helper()
	cfg := Config{BatchSize: 16, PollInterval: time.Millisecond, MaxPublishAttempts: 3}
	for _, m := range mutate {
		m(&cfg)
	}
	return New(cfg, st, q, l,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		obs.NewRegistry(),
		rand.New(rand.NewSource(1)))
}

// ---------------------------------------------------------------------------

func TestOnceDispatchesAndMarksTheBatch(t *testing.T) {
	st := newStore(5)
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{})

	n, err := r.Once(context.Background())
	if err != nil {
		t.Fatalf("Once: %v", err)
	}
	if n != 5 {
		t.Fatalf("dispatched %d, want 5", n)
	}
	if q.count() != 5 {
		t.Fatalf("published %d, want 5", q.count())
	}
	pending, dispatched, _ := st.snapshot()
	if pending != 0 || len(dispatched) != 5 {
		t.Fatalf("pending %d, marked %d; want 0 and 5", pending, len(dispatched))
	}
}

func TestOnceOnAnEmptyOutboxIsANoOp(t *testing.T) {
	st := newStore(0)
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{})

	n, err := r.Once(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("Once on an empty outbox = %d, %v", n, err)
	}
	if q.calls != 0 {
		t.Fatalf("the queue was called %d times with nothing to publish", q.calls)
	}
}

// The defining behaviour of the outbox pattern: when the queue is down, rows
// accumulate rather than being lost, and the edge keeps accepting.
func TestQueueOutageLeavesRowsPendingAndLosesNothing(t *testing.T) {
	st := newStore(10)
	q := &fakeQueue{err: errors.New("connection refused")}
	r := newRelay(t, st, q, &fakeLedger{})

	if _, err := r.Once(context.Background()); err == nil {
		t.Fatal("expected an error while the queue is unavailable")
	}
	pending, dispatched, _ := st.snapshot()
	if pending != 10 {
		t.Fatalf("pending = %d, want all 10 rows retained", pending)
	}
	if len(dispatched) != 0 {
		t.Fatalf("%d rows were marked dispatched despite the queue being down", len(dispatched))
	}

	// Recovery drains everything with no intervention.
	q.err = nil
	if _, err := r.Once(context.Background()); err != nil {
		t.Fatalf("Once after recovery: %v", err)
	}
	pending, dispatched, _ = st.snapshot()
	if pending != 0 || len(dispatched) != 10 {
		t.Fatalf("after recovery: pending %d, dispatched %d; want 0 and 10", pending, len(dispatched))
	}
}

// A dead queue must not be hammered once per row. The batch is abandoned on the
// first failure and retried whole.
func TestBatchIsAbandonedOnTheFirstPublishFailure(t *testing.T) {
	st := newStore(50)
	q := &fakeQueue{err: errors.New("connection refused")}
	r := newRelay(t, st, q, &fakeLedger{})

	_, _ = r.Once(context.Background())
	if q.calls != 1 {
		t.Fatalf("queue was called %d times for a dead queue; want 1", q.calls)
	}
}

func TestPartialBatchMarksOnlyWhatWasPublished(t *testing.T) {
	st := newStore(6)
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{})

	// One row per iteration, so the queue can be broken at a known point.
	r.cfg.BatchSize = 1
	published := 0
	for i := 0; i < 3; i++ {
		n, err := r.Once(context.Background())
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		published += n
	}
	if published != 3 {
		t.Fatalf("published %d before the outage, want 3", published)
	}
	q.mu.Lock()
	q.err = errors.New("queue died")
	q.mu.Unlock()
	if _, err := r.Once(context.Background()); err == nil {
		t.Fatal("expected the failure once the queue died")
	}

	pending, dispatched, _ := st.snapshot()
	if len(dispatched) != 3 {
		t.Fatalf("marked %d dispatched, want exactly the 3 that were published", len(dispatched))
	}
	if pending != 3 {
		t.Fatalf("pending = %d, want the 3 unpublished rows retained", pending)
	}
}

// Rows that keep failing must eventually stop being retried, and the decision
// must be recorded. A row that silently stops retrying is a dropped payment.
func TestExhaustedRowIsParkedAndAudited(t *testing.T) {
	st := newStore(1)
	q := &fakeQueue{err: errors.New("payload rejected")}
	l := &fakeLedger{}
	r := newRelay(t, st, q, l, func(c *Config) { c.MaxPublishAttempts = 3 })

	for i := 0; i < 3; i++ {
		_, _ = r.Once(context.Background())
	}

	_, _, failed := st.snapshot()
	if len(failed) != 1 {
		t.Fatalf("failed rows = %d, want 1", len(failed))
	}
	kinds := l.kinds()
	found := false
	for _, k := range kinds {
		if k == domain.AuditDeadLettered {
			found = true
		}
	}
	if !found {
		t.Fatalf("parking a row was not audited; kinds seen: %v", kinds)
	}
}

func TestRowsBelowTheAttemptCeilingAreNotParked(t *testing.T) {
	st := newStore(1)
	q := &fakeQueue{err: errors.New("transient")}
	l := &fakeLedger{}
	r := newRelay(t, st, q, l, func(c *Config) { c.MaxPublishAttempts = 5 })

	_, _ = r.Once(context.Background())

	for _, k := range l.kinds() {
		if k == domain.AuditDeadLettered {
			t.Fatal("a row was parked on its first failure")
		}
	}
}

// Marking failure after a successful publish would lose the rows. At-least-once
// makes redelivery safe, so failing in that direction is correct.
func TestMarkFailureIsReportedButPublishedRowsAreNotLost(t *testing.T) {
	st := newStore(3)
	st.markErr = errors.New("database unavailable")
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{})

	n, err := r.Once(context.Background())
	if err == nil {
		t.Fatal("expected the mark failure to surface")
	}
	if n != 3 {
		t.Fatalf("reported %d dispatched, want 3: they did reach the queue", n)
	}
	if q.count() != 3 {
		t.Fatalf("published %d, want 3", q.count())
	}
	// Rows remain pending, so the next iteration republishes them and the
	// consumer's idempotency absorbs the duplicate.
	pending, _, _ := st.snapshot()
	if pending != 3 {
		t.Fatalf("pending = %d, want the rows retained for redelivery", pending)
	}
}

func TestClaimFailureSurfaces(t *testing.T) {
	st := newStore(3)
	st.claimErr = errors.New("database unavailable")
	r := newRelay(t, st, &fakeQueue{}, &fakeLedger{})

	if _, err := r.Once(context.Background()); err == nil {
		t.Fatal("expected a claim failure to surface")
	}
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

func TestBackoffStaysWithinBoundsAndGrows(t *testing.T) {
	r := newRelay(t, newStore(0), &fakeQueue{}, &fakeLedger{}, func(c *Config) {
		c.MinBackoff = 10 * time.Millisecond
		c.MaxBackoff = time.Second
	})

	var lastCeiling time.Duration
	for failures := 1; failures <= 12; failures++ {
		r.consecutiveFailures = failures
		var maxSeen time.Duration
		for i := 0; i < 500; i++ {
			d := r.backoff()
			if d < r.cfg.MinBackoff {
				t.Fatalf("backoff %v below the floor %v", d, r.cfg.MinBackoff)
			}
			if d > r.cfg.MaxBackoff {
				t.Fatalf("backoff %v above the ceiling %v", d, r.cfg.MaxBackoff)
			}
			if d > maxSeen {
				maxSeen = d
			}
		}
		if maxSeen < lastCeiling {
			// Sampled maxima should trend upward until the ceiling saturates.
			t.Logf("failures=%d maxSeen=%v lastCeiling=%v", failures, maxSeen, lastCeiling)
		}
		lastCeiling = maxSeen
	}
}

// Full jitter exists to decorrelate a fleet. Identical delays every time would
// reconverge every relay onto the same retry instant.
func TestBackoffIsJitteredNotFixed(t *testing.T) {
	r := newRelay(t, newStore(0), &fakeQueue{}, &fakeLedger{}, func(c *Config) {
		c.MinBackoff = time.Millisecond
		c.MaxBackoff = time.Second
	})
	r.consecutiveFailures = 8

	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[r.backoff()] = true
	}
	if len(seen) < 50 {
		t.Fatalf("only %d distinct delays in 200 draws; the jitter is not spreading", len(seen))
	}
}

func TestBackoffDoesNotOverflowAtExtremeFailureCounts(t *testing.T) {
	r := newRelay(t, newStore(0), &fakeQueue{}, &fakeLedger{}, func(c *Config) {
		c.MinBackoff = time.Second
		c.MaxBackoff = 30 * time.Second
	})
	r.consecutiveFailures = 1 << 20
	d := r.backoff()
	if d <= 0 || d > r.cfg.MaxBackoff {
		t.Fatalf("backoff = %v at an extreme failure count; a shift overflowed", d)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestRunDrainsTheBacklogThenStops(t *testing.T) {
	st := newStore(40)
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{}, func(c *Config) { c.BatchSize = 7 })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if q.count() == 40 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d of 40 rows drained", q.count())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// Cancelling mid-flight must still flush what was claimed, or a graceful
// shutdown strands rows until the next start.
func TestShutdownPerformsAFinalDrain(t *testing.T) {
	st := newStore(3)
	q := &fakeQueue{}
	r := newRelay(t, st, q, &fakeLedger{}, func(c *Config) {
		c.PollInterval = time.Hour // guarantee the loop is parked when cancelled
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
	}
	if q.count() != 3 {
		t.Fatalf("published %d of 3 rows; the final drain did not run", q.count())
	}
}

func TestDepthReportsPendingAndFailed(t *testing.T) {
	st := newStore(4)
	st.failed[99] = "parked"
	r := newRelay(t, st, &fakeQueue{}, &fakeLedger{})

	pending, failed, err := r.Depth(context.Background())
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if pending != 4 || failed != 1 {
		t.Fatalf("depth = (%d pending, %d failed), want (4, 1)", pending, failed)
	}
}

func TestTruncateKeepsValidUTF8(t *testing.T) {
	s := ""
	for len(s) < 800 {
		s += "₹ rupee "
	}
	got := truncate(s, 512)
	if len(got) > 520 {
		t.Fatalf("truncated to %d bytes", len(got))
	}
	for _, r := range got {
		if r == '�' {
			t.Fatal("truncation split a rune")
		}
	}
}

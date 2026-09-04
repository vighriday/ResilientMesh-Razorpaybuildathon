package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// Test doubles for the recovery pipeline.
//
// The pool is exercised against hand-written fakes rather than Redis and
// PostgreSQL because what is under test here is ordering, idempotency and
// failure isolation, not storage. Every fake is deterministic and every one of
// them can be told to fail on demand, because most of the properties worth
// proving about this package are properties of its failure paths.
//
// internal/simulation carries richer versions of the same shapes, but all of
// them are unexported members of that package and so are unreachable from here.

// origin is the instant every test starts from. A fixed value rather than
// time.Now keeps scheduled_for assertions exact.
var origin = time.Date(2026, time.March, 1, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

// fakeClock is mutable and mutex-guarded: the pool reads it from several
// goroutines at once, so an unguarded field would be a data race in the fake
// rather than in the code under test.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: origin} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

// fakeStore models the durable state the pipeline depends on, including the
// claim semantics the port documents: ClaimDueIncidents clears the due time in
// the same critical section that reads it, which is what FOR UPDATE SKIP LOCKED
// buys in PostgreSQL and what makes two concurrent sweepers safe.
type fakeStore struct {
	mu        sync.Mutex
	incidents map[string]domain.Incident
	due       map[string]time.Time
	attempts  []domain.AttemptRecord
	mandates  map[string]domain.MandateRecord
	sessions  map[string]domain.SessionRecord // keyed by order id
	states    []stateChange

	incrCalls  int
	claimCalls int

	getErr      error
	incrErr     error
	updateErr   error
	scheduleErr error
	claimErr    error
	attemptErr  error
	sessionErr  error

	// beforeGet runs before GetIncident takes the lock. Tests use it as a
	// rendezvous point between two concurrent handlers; running it outside the
	// lock is what keeps the rendezvous from deadlocking on the fake itself.
	beforeGet func(id string)
	// panicOnGet models a collaborator that blows up mid-pipeline.
	panicOnGet bool

	// scheduledC and attemptC let a test wait for durable progress instead of
	// polling for it. Waiting on a signal keeps the pool tests free of both
	// sleeps and busy loops, either of which would make them flaky under -race.
	scheduledC chan struct{}
	attemptC   chan struct{}
}

type stateChange struct {
	id    string
	state domain.IncidentState
}

func newStore() *fakeStore {
	return &fakeStore{
		incidents:  map[string]domain.Incident{},
		due:        map[string]time.Time{},
		mandates:   map[string]domain.MandateRecord{},
		sessions:   map[string]domain.SessionRecord{},
		scheduledC: make(chan struct{}, 4096),
		attemptC:   make(chan struct{}, 4096),
	}
}

// signal is a non-blocking notification: a test that is not listening must
// never be able to stall the pool.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *fakeStore) put(in domain.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[in.ID] = in
}

func (s *fakeStore) snapshotIncident(id string) (domain.Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.incidents[id]
	return in, ok
}

func (s *fakeStore) dueTime(id string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.due[id]
	return t, ok
}

func (s *fakeStore) recordedAttempts() []domain.AttemptRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.AttemptRecord, len(s.attempts))
	copy(out, s.attempts)
	return out
}

func (s *fakeStore) transitions() []stateChange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stateChange, len(s.states))
	copy(out, s.states)
	return out
}

func (s *fakeStore) GetIncident(_ context.Context, id string) (domain.Incident, error) {
	if s.beforeGet != nil {
		s.beforeGet(id)
	}
	if s.panicOnGet {
		panic("fakeStore: GetIncident exploded")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return domain.Incident{}, s.getErr
	}
	in, ok := s.incidents[id]
	if !ok {
		return domain.Incident{}, fmt.Errorf("fakeStore: %w", store.ErrNotFound)
	}
	return in, nil
}

func (s *fakeStore) UpdateIncidentState(_ context.Context, id string, st domain.IncidentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateErr != nil {
		return s.updateErr
	}
	in, ok := s.incidents[id]
	if !ok {
		return fmt.Errorf("fakeStore: update state: %w", store.ErrNotFound)
	}
	in.State = st
	s.incidents[id] = in
	s.states = append(s.states, stateChange{id: id, state: st})
	return nil
}

func (s *fakeStore) IncrementIncidentAttempts(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incrCalls++
	if s.incrErr != nil {
		return 0, s.incrErr
	}
	in, ok := s.incidents[id]
	if !ok {
		return 0, fmt.Errorf("fakeStore: increment attempts: %w", store.ErrNotFound)
	}
	in.AttemptCount++
	s.incidents[id] = in
	return in.AttemptCount, nil
}

// ScheduleIncident mirrors the SQL: state and due time move together, so an
// incident can never be SCHEDULED with no schedule.
func (s *fakeStore) ScheduleIncident(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scheduleErr != nil {
		return s.scheduleErr
	}
	in, ok := s.incidents[id]
	if !ok {
		return fmt.Errorf("fakeStore: schedule: %w", store.ErrNotFound)
	}
	in.State = domain.IncidentScheduled
	s.incidents[id] = in
	s.due[id] = at
	signal(s.scheduledC)
	return nil
}

// ClaimDueIncidents takes ownership under one lock and clears the due time in
// the same critical section, which is this fake's stand-in for FOR UPDATE SKIP
// LOCKED. Without that atomicity two sweepers would both see the same row and
// the concurrency test would be proving a property of the fake, not the pool.
func (s *fakeStore) ClaimDueIncidents(_ context.Context, now time.Time, limit int) ([]domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimCalls++
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	ids := make([]string, 0, len(s.due))
	for id, at := range s.due {
		if !at.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]domain.Incident, 0, len(ids))
	for _, id := range ids {
		delete(s.due, id)
		out = append(out, s.incidents[id])
	}
	return out, nil
}

func (s *fakeStore) DueIncidentCount(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, at := range s.due {
		if !at.After(now) {
			n++
		}
	}
	return n, nil
}

func (s *fakeStore) GetMandate(_ context.Context, subscriptionID string) (domain.MandateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mandates[subscriptionID]
	if !ok {
		return domain.MandateRecord{}, fmt.Errorf("fakeStore: %w", store.ErrNotFound)
	}
	return m, nil
}

func (s *fakeStore) SaveMandate(_ context.Context, m domain.MandateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mandates[m.SubscriptionID] = m
	return nil
}

func (s *fakeStore) RecordAttempt(_ context.Context, a domain.AttemptRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attemptErr != nil {
		return s.attemptErr
	}
	a.ID = int64(len(s.attempts) + 1)
	s.attempts = append(s.attempts, a)
	signal(s.attemptC)
	return nil
}

func (s *fakeStore) ListAttempts(_ context.Context, incidentID string) ([]domain.AttemptRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []domain.AttemptRecord{}
	for _, a := range s.attempts {
		if a.IncidentID == incidentID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *fakeStore) GetSessionByOrder(_ context.Context, orderID string) (domain.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionErr != nil {
		return domain.SessionRecord{}, s.sessionErr
	}
	sess, ok := s.sessions[orderID]
	if !ok {
		return domain.SessionRecord{}, fmt.Errorf("fakeStore: %w", store.ErrNotFound)
	}
	return sess, nil
}

// The remainder of domain.Store is not on the worker's path. They panic rather
// than returning zero values so a test that starts depending on one fails
// loudly instead of quietly asserting against a fake's default. They still
// exist because domain.Store is one contract: a fake implementing only the
// convenient half would compile today and hide the day this package grows into
// the other half.
func (s *fakeStore) WithTx(context.Context, func(context.Context, domain.Tx) error) error {
	panic("worker: the pipeline does not open transactions")
}

func (s *fakeStore) GetIncidentByEventID(context.Context, string) (domain.Incident, error) {
	panic("worker: event-id lookup belongs to the ingest edge")
}

func (s *fakeStore) ListIncidents(context.Context, int) ([]domain.Incident, error) {
	panic("worker: listing incidents belongs to the console")
}

func (s *fakeStore) ClaimOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error) {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) MarkOutboxDispatched(context.Context, []int64) error {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) MarkOutboxFailed(context.Context, int64, string) error {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) RecordOutboxFailure(context.Context, int64, string) error {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) ReleaseOutboxClaim(context.Context, []int64) error {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) OutboxDepth(context.Context) (int, int, error) {
	panic("worker: the outbox belongs to the relay")
}

func (s *fakeStore) CreateSession(context.Context, domain.SessionRecord) error {
	panic("worker: sessions are created at the edge")
}

func (s *fakeStore) GetSession(context.Context, string) (domain.SessionRecord, error) {
	panic("worker: the pipeline resolves sessions by order id")
}

func (s *fakeStore) UpdateSession(context.Context, domain.SessionRecord) error {
	panic("worker: sessions are updated by the SSE hub")
}

func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) Close() error               { return nil }

var _ domain.Store = (*fakeStore)(nil)

// ---------------------------------------------------------------------------
// queue
// ---------------------------------------------------------------------------

// fakeQueue delivers over a channel rather than a polled slice so a consumer
// with nothing to do parks on the context instead of spinning. A spinning
// consumer would turn every pool test into a race-detector hot loop and would
// burn CPU proportional to test duration rather than to work done.
type fakeQueue struct {
	mu        sync.Mutex
	acked     []string
	published []domain.OutboxEvent
	reclaims  [][]domain.QueueMessage

	publishErr  error
	ackErr      error
	reclaimErr  error
	consumeErrs []error

	// loopback feeds published events straight back to the consumers, which is
	// what lets one test drive the whole defer -> sweep -> execute loop.
	loopback bool
	nextID   int

	deliver  chan domain.QueueMessage
	swept    chan struct{}
	reclaimC chan struct{}
	ackC     chan struct{}
}

func newQueue() *fakeQueue {
	return &fakeQueue{
		deliver:  make(chan domain.QueueMessage, 4096),
		swept:    make(chan struct{}, 4096),
		reclaimC: make(chan struct{}, 4096),
		ackC:     make(chan struct{}, 4096),
	}
}

func (q *fakeQueue) seed(msgs ...domain.QueueMessage) {
	for _, m := range msgs {
		q.deliver <- m
	}
}

func (q *fakeQueue) Publish(_ context.Context, topic string, ev domain.OutboxEvent) error {
	q.mu.Lock()
	if q.publishErr != nil {
		err := q.publishErr
		q.mu.Unlock()
		return err
	}
	ev.Topic = topic
	q.published = append(q.published, ev)
	q.nextID++
	id := fmt.Sprintf("republished-%d", q.nextID)
	loop := q.loopback
	q.mu.Unlock()

	if loop {
		q.deliver <- domain.QueueMessage{
			ID: id, IncidentID: ev.IncidentID, Topic: topic, Payload: ev.Payload, Deliveries: 1,
		}
	}
	select {
	case q.swept <- struct{}{}:
	default:
	}
	return nil
}

func (q *fakeQueue) Consume(ctx context.Context, _, _ string, count int, _ time.Duration) ([]domain.QueueMessage, error) {
	q.mu.Lock()
	if len(q.consumeErrs) > 0 {
		err := q.consumeErrs[0]
		q.consumeErrs = q.consumeErrs[1:]
		q.mu.Unlock()
		return nil, err
	}
	q.mu.Unlock()

	var out []domain.QueueMessage
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m := <-q.deliver:
		out = append(out, m)
	}
	for len(out) < count {
		select {
		case m := <-q.deliver:
			out = append(out, m)
		default:
			return out, nil
		}
	}
	return out, nil
}

func (q *fakeQueue) Ack(_ context.Context, _ string, ids ...string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ackErr != nil {
		return q.ackErr
	}
	q.acked = append(q.acked, ids...)
	for range ids {
		signal(q.ackC)
	}
	return nil
}

func (q *fakeQueue) Reclaim(_ context.Context, _, _ string, _ time.Duration, _ int) ([]domain.QueueMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	select {
	case q.reclaimC <- struct{}{}:
	default:
	}
	if q.reclaimErr != nil {
		return nil, q.reclaimErr
	}
	if len(q.reclaims) == 0 {
		return nil, nil
	}
	batch := q.reclaims[0]
	q.reclaims = q.reclaims[1:]
	return batch, nil
}

func (q *fakeQueue) Depth(context.Context) (int64, error) { return 0, nil }
func (q *fakeQueue) Ping(context.Context) error           { return nil }
func (q *fakeQueue) Close() error                         { return nil }

func (q *fakeQueue) ackedIDs() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, len(q.acked))
	copy(out, q.acked)
	return out
}

func (q *fakeQueue) publishedEvents() []domain.OutboxEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]domain.OutboxEvent, len(q.published))
	copy(out, q.published)
	return out
}

var _ domain.Queue = (*fakeQueue)(nil)

// ---------------------------------------------------------------------------
// dead letter
// ---------------------------------------------------------------------------

type parked struct {
	msg   domain.QueueMessage
	cause string
}

type fakeDeadLetter struct {
	mu     sync.Mutex
	parked []parked
	err    error
	// panics models a dead-letter path that is itself broken.
	panics bool
}

func (d *fakeDeadLetter) DeadLetter(_ context.Context, _ string, msg domain.QueueMessage, cause string) error {
	if d.panics {
		panic("fakeDeadLetter: the dead-letter stream exploded")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.parked = append(d.parked, parked{msg: msg, cause: cause})
	return nil
}

func (d *fakeDeadLetter) all() []parked {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]parked, len(d.parked))
	copy(out, d.parked)
	return out
}

var _ DeadLetterer = (*fakeDeadLetter)(nil)

// ---------------------------------------------------------------------------
// audit ledger
// ---------------------------------------------------------------------------

type auditEntry struct {
	kind       domain.AuditKind
	incidentID string
	actor      string
	detail     map[string]any
}

// fakeLedger round-trips the detail through JSON exactly as the real ledger
// does, so an assertion here fails for the same reasons a real append would: a
// detail that cannot be marshalled is a broken audit record, not a passing test.
type fakeLedger struct {
	mu      sync.Mutex
	entries []auditEntry
	err     error
	seq     int64
}

func (l *fakeLedger) Append(_ context.Context, kind domain.AuditKind, incidentID, actor string, detail any) (domain.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return domain.AuditEntry{}, l.err
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("fakeLedger: marshalling detail: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return domain.AuditEntry{}, fmt.Errorf("fakeLedger: detail is not an object: %w", err)
	}
	l.seq++
	l.entries = append(l.entries, auditEntry{kind: kind, incidentID: incidentID, actor: actor, detail: m})
	return domain.AuditEntry{Seq: l.seq, Kind: kind, IncidentID: incidentID, Actor: actor}, nil
}

func (l *fakeLedger) List(context.Context, string) ([]domain.AuditEntry, error) {
	panic("worker: the pipeline never reads the ledger back")
}

func (l *fakeLedger) Verify(context.Context) (domain.VerifyReport, error) {
	panic("worker: chain verification belongs to meshctl")
}

func (l *fakeLedger) Head(context.Context) (domain.AuditEntry, error) {
	panic("worker: the pipeline never reads the ledger head")
}

func (l *fakeLedger) all() []auditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]auditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *fakeLedger) kinds() []domain.AuditKind {
	out := []domain.AuditKind{}
	for _, e := range l.all() {
		out = append(out, e.kind)
	}
	return out
}

func (l *fakeLedger) find(kind domain.AuditKind) (auditEntry, bool) {
	for _, e := range l.all() {
		if e.kind == kind {
			return e, true
		}
	}
	return auditEntry{}, false
}

func (l *fakeLedger) count(kind domain.AuditKind) int {
	n := 0
	for _, e := range l.all() {
		if e.kind == kind {
			n++
		}
	}
	return n
}

var _ domain.AuditLedger = (*fakeLedger)(nil)

// ---------------------------------------------------------------------------
// diagnoser
// ---------------------------------------------------------------------------

type fakeDiagnoser struct {
	mu    sync.Mutex
	calls []domain.DiagnosticContext
	fn    func(dc domain.DiagnosticContext) (domain.DiagnosticProposal, error)
}

func (d *fakeDiagnoser) Diagnose(ctx context.Context, dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dc)
	fn := d.fn
	d.mu.Unlock()
	if fn != nil {
		return fn(dc)
	}
	return domain.DiagnosticProposal{
		IncidentID:            dc.IncidentID,
		InferredRootCause:     "issuer authorisation host intermittently unavailable",
		FailureClassification: domain.ClassTransientDegradation,
		ConfidenceScore:       0.81,
		RecommendedAction:     domain.ActionAsyncRetry,
		SuggestedFallbackRail: domain.RailNone,
		Mode:                  domain.ModeLive,
		Model:                 "fake-model",
		LatencyMS:             42,
	}, ctx.Err()
}

func (d *fakeDiagnoser) Describe() string { return "fake-diagnoser" }

func (d *fakeDiagnoser) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *fakeDiagnoser) lastContext() (domain.DiagnosticContext, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return domain.DiagnosticContext{}, false
	}
	return d.calls[len(d.calls)-1], true
}

var _ domain.Diagnoser = (*fakeDiagnoser)(nil)

// ---------------------------------------------------------------------------
// gatekeeper
// ---------------------------------------------------------------------------

// fakeGate stands in for the real gatekeeper so each worker test can pin the
// exact command shape it is about. The gate's own semantics are covered by
// internal/gatekeeper; what matters here is that the worker treats whatever the
// gate returns as authoritative and never second-guesses it.
type fakeGate struct {
	mu     sync.Mutex
	inputs []domain.GateInput
	fn     func(in domain.GateInput) (domain.SanitizedCommand, error)
	panics bool
}

func (g *fakeGate) Decide(_ context.Context, in domain.GateInput) (domain.SanitizedCommand, error) {
	if g.panics {
		panic("fakeGate: the gatekeeper exploded")
	}
	g.mu.Lock()
	g.inputs = append(g.inputs, in)
	fn := g.fn
	g.mu.Unlock()
	if fn != nil {
		return fn(in)
	}
	return executableCommand(in), nil
}

func (g *fakeGate) seen() []domain.GateInput {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]domain.GateInput, len(g.inputs))
	copy(out, g.inputs)
	return out
}

// executableCommand is the ordinary outcome: an immediate async retry on the
// payment's own rail. The delay is zero so the command executes rather than
// deferring, which keeps the deferral path opt-in per test.
func executableCommand(in domain.GateInput) domain.SanitizedCommand {
	return domain.SanitizedCommand{
		IncidentID:           in.IncidentID,
		PaymentID:            in.Payment.ID,
		OrderID:              in.Payment.OrderID,
		ImmutableAmountPaisa: in.Payment.Amount,
		Currency:             in.Payment.Currency,
		Action:               domain.ActionAsyncRetry,
		TargetRail:           domain.RailFromMethod(in.Payment.Method),
		AttemptNumber:        in.AttemptNumber,
		MaxAttempts:          3,
		Presentation:         domain.PresentationUnchanged,
		AppliedInvariants:    []string{"AMOUNT_PINNED", "DELAY_BOUNDS"},
		ProposalMode:         in.Proposal.Mode,
		ProposalConfidence:   in.Proposal.ConfidenceScore,
		ProposalAction:       in.Proposal.RecommendedAction,
	}
}

var _ domain.Gatekeeper = (*fakeGate)(nil)

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type fakeExecutor struct {
	mu      sync.Mutex
	retries []domain.SanitizedCommand
	morphs  []domain.SanitizedCommand
	notices []domain.SanitizedCommand

	succeed   bool
	retryErr  error
	notifyErr error
	panics    bool

	// entered and release let a test hold the executor inside a call, which is
	// how "cancel the context mid-execution" is made deterministic without a
	// sleep.
	entered chan struct{}
	release chan struct{}
}

func newExecutor() *fakeExecutor { return &fakeExecutor{succeed: true} }

func (e *fakeExecutor) run(cmd domain.SanitizedCommand, action domain.Action) (domain.AttemptRecord, error) {
	if e.panics {
		panic("fakeExecutor: the gateway call exploded")
	}
	if e.entered != nil {
		e.entered <- struct{}{}
		<-e.release
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rec := domain.AttemptRecord{
		AttemptNumber:   cmd.AttemptNumber,
		Action:          action,
		Rail:            cmd.TargetRail,
		Presentation:    cmd.Presentation,
		AmountPaisa:     cmd.ImmutableAmountPaisa,
		Succeeded:       e.succeed && e.retryErr == nil,
		GatewayFeePaisa: 250,
	}
	if !rec.Succeeded {
		rec.ErrorCode = "bank_technical_error"
	}
	return rec, e.retryErr
}

func (e *fakeExecutor) Retry(_ context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	e.mu.Lock()
	e.retries = append(e.retries, cmd)
	e.mu.Unlock()
	return e.run(cmd, domain.ActionAsyncRetry)
}

func (e *fakeExecutor) MorphRail(_ context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	e.mu.Lock()
	e.morphs = append(e.morphs, cmd)
	e.mu.Unlock()
	return e.run(cmd, domain.ActionRailMorph)
}

func (e *fakeExecutor) NotifyPreDebit(_ context.Context, cmd domain.SanitizedCommand) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.notifyErr != nil {
		return e.notifyErr
	}
	e.notices = append(e.notices, cmd)
	return nil
}

func (e *fakeExecutor) counts() (retries, morphs, notices int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.retries), len(e.morphs), len(e.notices)
}

var _ domain.Executor = (*fakeExecutor)(nil)

// ---------------------------------------------------------------------------
// telemetry, breaker, hub
// ---------------------------------------------------------------------------

type outcome struct {
	issuerKey string
	errorCode string
	success   bool
	latency   time.Duration
}

type fakeTelemetry struct {
	mu       sync.Mutex
	outcomes []outcome
	snap     domain.TelemetrySnapshot
	snapErr  error
	writeErr error
}

func (t *fakeTelemetry) RecordOutcome(_ context.Context, issuerKey, errorCode string, success bool, latency time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outcomes = append(t.outcomes, outcome{issuerKey, errorCode, success, latency})
	return t.writeErr
}

func (t *fakeTelemetry) Snapshot(_ context.Context, issuerKey string) (domain.TelemetrySnapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.snapErr != nil {
		return domain.TelemetrySnapshot{}, t.snapErr
	}
	s := t.snap
	s.IssuerKey = issuerKey
	return s, nil
}

func (t *fakeTelemetry) SnapshotAll(context.Context) ([]domain.TelemetrySnapshot, error) {
	panic("worker: the pipeline reads one issuer at a time")
}

func (t *fakeTelemetry) recorded() []outcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]outcome, len(t.outcomes))
	copy(out, t.outcomes)
	return out
}

var _ domain.TelemetryRecorder = (*fakeTelemetry)(nil)

type fakeBreaker struct {
	mu        sync.Mutex
	allow     bool
	allowErr  error
	state     domain.BreakerState
	stateErr  error
	reports   []bool
	reportErr error
}

func newBreaker() *fakeBreaker {
	return &fakeBreaker{allow: true, state: domain.BreakerClosed}
}

func (b *fakeBreaker) State(context.Context, string) (domain.BreakerState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state, b.stateErr
}

func (b *fakeBreaker) Allow(context.Context, string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allow, b.allowErr
}

func (b *fakeBreaker) Report(_ context.Context, _ string, success bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reports = append(b.reports, success)
	return b.reportErr
}

func (b *fakeBreaker) States(context.Context) (map[string]domain.BreakerState, error) {
	panic("worker: the pipeline reads one breaker at a time")
}

func (b *fakeBreaker) reported() []bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]bool, len(b.reports))
	copy(out, b.reports)
	return out
}

var _ domain.Breaker = (*fakeBreaker)(nil)

type fakeHub struct {
	mu     sync.Mutex
	active map[string]bool
}

func newHub() *fakeHub { return &fakeHub{active: map[string]bool{}} }

func (h *fakeHub) Subscribe(context.Context, string) (<-chan domain.SessionEvent, func(), error) {
	panic("worker: the pipeline never subscribes")
}

func (h *fakeHub) Publish(context.Context, string, domain.SessionEvent) error {
	panic("worker: the executor publishes morphs, not the pool")
}

func (h *fakeHub) Active(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active[sessionID]
}

func (h *fakeHub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.active)
}

var _ domain.SessionHub = (*fakeHub)(nil)

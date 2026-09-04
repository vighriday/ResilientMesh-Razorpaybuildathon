package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ErrNotFound mirrors store.ErrNotFound without importing internal/store.
//
// The simulation deliberately does not link the PostgreSQL package: pulling a
// driver in would make a pure in-memory harness depend on a module whose
// behaviour it is not modelling, and the only thing the sim needs from that
// package is the shape of its absent-row sentinel.
var ErrNotFound = errors.New("simulation: not found")

// ErrConflict mirrors store.ErrConflict: a uniqueness invariant rejected the
// write. The webhook replay guard depends on telling this apart from a generic
// failure, so it is a distinct sentinel here too.
var ErrConflict = errors.New("simulation: conflict")

const (
	// claimLease is how long a relay owns a claimed outbox row. It models the
	// lifetime of the FOR UPDATE SKIP LOCKED transaction: if the relay dies
	// mid-batch the lock dies with the transaction and another relay may take
	// the row. Without a lease, a crashed relay would strand rows forever and
	// the simulation would mistake that for a lost event.
	claimLease = 30 * time.Second

	// maxOutboxPublishAttempts is the poison-message threshold. Past it the row
	// is FAILED and dead-lettered rather than retried forever, because a row
	// that cannot be published is not made publishable by trying harder.
	maxOutboxPublishAttempts = 5

	// telemetryWindow matches the production rolling window.
	telemetryWindow = 5 * time.Minute

	// subscriberBuffer matches internal/sse: a bounded per-subscriber buffer
	// whose overflow costs the subscriber frames and never blocks the publisher.
	subscriberBuffer = 16

	maxTextField = 256
)

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

// outboxRow is one durable outbox entry plus the two columns the port does not
// expose.
//
// availableAt is a real column in any production outbox that supports delayed
// dispatch, and it is how a retry scheduled 24 hours out survives a process
// restart. domain.Tx.InsertOutboxEvent has no field for it, so the writer
// carries it in the payload envelope and the store lifts it out at insert time.
// That is a modelling compromise forced by the port shape and is reported as a
// contract gap rather than worked around silently.
type outboxRow struct {
	ev           domain.OutboxEvent
	availableAt  int64 // virtual nanos; zero means immediately claimable
	claimedUntil int64
	issuerKey    string
}

type memStore struct {
	// The scheduler runs everything on one goroutine, so this mutex is never
	// contended. It is here because domain.Store is a concurrency-safe contract
	// in production and a fake that quietly is not would let a future
	// multi-goroutine harness pass -race by accident.
	mu sync.Mutex

	clock  domain.Clock
	faults *Injector
	ledger *memLedger

	incidents map[string]*domain.Incident
	byEvent   map[string]string
	// dueAt holds the absolute due time of every deferred incident. It lives
	// beside the incidents map rather than inside the record so that clearing a
	// claim is one delete rather than a mutation a caller could forget.
	dueAt map[string]time.Time

	outbox       []*outboxRow
	nextOutboxID int64

	// Outbox state counters and the orphan set are maintained on every write so
	// the invariant monitor can assert conservation in constant time after each
	// of tens of thousands of steps. Recomputing them per step would make the
	// monitor the run's bottleneck and would push verification towards being
	// sampled instead of continuous.
	pendingCount      int
	dispatchedCount   int
	failedCount       int
	nonTerminal       int
	outboxPerIncident map[string]int
	orphans           map[string]struct{}

	mandates map[string]domain.MandateRecord

	attempts      []domain.AttemptRecord
	nextAttemptID int64

	sessions     map[string]domain.SessionRecord
	sessionOrder map[string]string

	closed bool

	commits, rollbacks, injected int64
}

var _ domain.Store = (*memStore)(nil)

func newMemStore(clock domain.Clock, faults *Injector, ledger *memLedger) *memStore {
	return &memStore{
		clock:        clock,
		faults:       faults,
		ledger:       ledger,
		incidents:    make(map[string]*domain.Incident),
		byEvent:      make(map[string]string),
		mandates:     make(map[string]domain.MandateRecord),
		sessions:     make(map[string]domain.SessionRecord),
		sessionOrder: make(map[string]string),

		outboxPerIncident: make(map[string]int),
		orphans:           make(map[string]struct{}),
	}
}

// guard applies the two conditions every store call must respect before it
// touches state: the caller's context, and the injected database fault. Both
// fail closed — nothing is written.
func (s *memStore) guard(ctx context.Context, op string) error {
	if s.closed {
		return fmt.Errorf("%s: %w", op, ErrStoreClosed)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if s.faults.StoreFailed() {
		s.injected++
		return fmt.Errorf("%s: %w", op, ErrStoreUnavailable)
	}
	return nil
}

// memTx buffers every write and applies them in one shot at commit, so a
// failure anywhere in fn — or an injected fault at commit — leaves no partial
// state. That is the property the transactional outbox depends on: the incident
// row and the outbox row either both exist or neither does.
type memTx struct {
	store     *memStore
	incidents []domain.Incident
	outbox    []domain.OutboxEvent
	mandates  []domain.MandateRecord
	audits    []domain.AuditEntry
	done      bool
}

var _ domain.Tx = (*memTx)(nil)

func (t *memTx) InsertIncident(ctx context.Context, in domain.Incident) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	if t.done {
		return errors.New("simulation: transaction already finished")
	}
	if in.ID == "" || in.EventID == "" {
		return fmt.Errorf("insert incident: %w: missing identifiers", ErrInvalidInput)
	}
	// The UNIQUE index on incidents(event_id) is the webhook replay guard, so
	// the fake enforces it against both committed rows and this transaction's
	// own buffer. Checking only committed rows would let one batch insert the
	// same event twice.
	if _, dup := t.store.byEvent[in.EventID]; dup {
		return fmt.Errorf("insert incident: %w: event_id already recorded", ErrConflict)
	}
	for _, buffered := range t.incidents {
		if buffered.EventID == in.EventID {
			return fmt.Errorf("insert incident: %w: event_id already recorded in this transaction", ErrConflict)
		}
	}
	t.incidents = append(t.incidents, in)
	return nil
}

func (t *memTx) InsertOutboxEvent(ctx context.Context, ev domain.OutboxEvent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	if t.done {
		return errors.New("simulation: transaction already finished")
	}
	if ev.IncidentID == "" || ev.Topic == "" {
		return fmt.Errorf("insert outbox event: %w: missing incident or topic", ErrInvalidInput)
	}
	t.outbox = append(t.outbox, ev)
	return nil
}

func (t *memTx) UpsertMandate(ctx context.Context, m domain.MandateRecord) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("upsert mandate: %w", err)
	}
	if t.done {
		return errors.New("simulation: transaction already finished")
	}
	if m.SubscriptionID == "" {
		return fmt.Errorf("upsert mandate: %w: missing subscription id", ErrInvalidInput)
	}
	t.mandates = append(t.mandates, m)
	return nil
}

func (t *memTx) AppendAudit(ctx context.Context, e domain.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	if t.done {
		return errors.New("simulation: transaction already finished")
	}
	t.audits = append(t.audits, e)
	return nil
}

// ErrInvalidInput mirrors store.ErrInvalidInput: the value was rejected before
// it could be stored. The fake fails closed on anything it cannot represent
// exactly, for the same reason the real store does.
var ErrInvalidInput = errors.New("simulation: invalid input")

func (s *memStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx domain.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guard(ctx, "begin transaction"); err != nil {
		s.rollbacks++
		return err
	}
	tx := &memTx{store: s}
	if err := fn(ctx, tx); err != nil {
		tx.done = true
		s.rollbacks++
		return err
	}
	// The commit-time fault is the interesting one: it lands after the caller
	// believed every write succeeded, which is precisely the window a naive
	// implementation would leak partial state through.
	if s.faults.StoreFailed() {
		tx.done = true
		s.rollbacks++
		s.injected++
		return fmt.Errorf("commit transaction: %w", ErrStoreUnavailable)
	}
	if err := s.apply(tx); err != nil {
		tx.done = true
		s.rollbacks++
		return err
	}
	tx.done = true
	s.commits++
	return nil
}

func (s *memStore) apply(tx *memTx) error {
	now := s.clock.Now()
	for _, in := range tx.incidents {
		rec := in
		if rec.ReceivedAt.IsZero() {
			rec.ReceivedAt = now
		}
		rec.UpdatedAt = now
		s.incidents[rec.ID] = &rec
		s.byEvent[rec.EventID] = rec.ID
		if !rec.State.Terminal() {
			s.nonTerminal++
		}
	}
	defer func() {
		// Checked after the outbox writes in this same transaction land, since
		// the ingest path writes both together and an incident is only an orphan
		// once the whole transaction has committed without one.
		for _, in := range tx.incidents {
			if s.outboxPerIncident[in.ID] == 0 {
				s.orphans[in.ID] = struct{}{}
			}
		}
	}()
	for _, ev := range tx.outbox {
		s.insertOutboxLocked(ev, now)
	}
	for _, m := range tx.mandates {
		rec := m
		rec.UpdatedAt = now
		s.mandates[rec.SubscriptionID] = rec
	}
	for _, e := range tx.audits {
		if _, err := s.ledger.appendEntry(e); err != nil {
			return fmt.Errorf("commit transaction: %w", err)
		}
	}
	return nil
}

// dispatchEnvelope is the sliver of the outbox payload the store itself reads.
// See outboxRow.availableAt for why a store parses its own payload here.
type dispatchEnvelope struct {
	AvailableAtNS int64  `json:"available_at_ns"`
	IssuerKey     string `json:"issuer_key"`
}

func (s *memStore) insertOutboxLocked(ev domain.OutboxEvent, now time.Time) {
	s.nextOutboxID++
	row := &outboxRow{ev: ev}
	row.ev.ID = s.nextOutboxID
	row.ev.State = domain.OutboxPending
	row.ev.Attempts = 0
	row.ev.LastError = ""
	row.ev.DispatchedAt = nil
	if row.ev.CreatedAt.IsZero() {
		row.ev.CreatedAt = now
	}
	var env dispatchEnvelope
	if len(ev.Payload) > 0 && json.Unmarshal(ev.Payload, &env) == nil {
		row.availableAt = env.AvailableAtNS
		row.issuerKey = truncateField(env.IssuerKey)
	}
	s.outbox = append(s.outbox, row)
	s.pendingCount++
	s.outboxPerIncident[ev.IncidentID]++
	delete(s.orphans, ev.IncidentID)
}

func (s *memStore) GetIncident(ctx context.Context, id string) (domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "get incident"); err != nil {
		return domain.Incident{}, err
	}
	in, ok := s.incidents[id]
	if !ok {
		return domain.Incident{}, fmt.Errorf("get incident: %w", ErrNotFound)
	}
	return *in, nil
}

func (s *memStore) GetIncidentByEventID(ctx context.Context, eventID string) (domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "get incident by event id"); err != nil {
		return domain.Incident{}, err
	}
	id, ok := s.byEvent[eventID]
	if !ok {
		return domain.Incident{}, fmt.Errorf("get incident by event id: %w", ErrNotFound)
	}
	return *s.incidents[id], nil
}

// ScheduleIncident defers an incident. The simulated store keeps the due time
// beside the incident rather than in a parallel map, so the two cannot be
// cleaned up out of step — the same property the real schema gets from putting
// the column on the row.
func (s *memStore) ScheduleIncident(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "schedule incident"); err != nil {
		return err
	}
	in, ok := s.incidents[id]
	if !ok {
		return fmt.Errorf("schedule incident: %w", ErrNotFound)
	}
	if in.State.Terminal() {
		return nil
	}
	in.State = domain.IncidentScheduled
	if s.dueAt == nil {
		s.dueAt = map[string]time.Time{}
	}
	s.dueAt[id] = at
	return nil
}

// ClaimDueIncidents takes every incident whose schedule has arrived, clearing
// the due time as part of the claim so a second sweeper cannot take it. The
// result is ordered by due time so a simulation replay is deterministic; map
// iteration order here would make every trace irreproducible.
func (s *memStore) ClaimDueIncidents(ctx context.Context, now time.Time, limit int) ([]domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "claim due incidents"); err != nil {
		return nil, err
	}
	type due struct {
		id string
		at time.Time
	}
	var ready []due
	for id, at := range s.dueAt {
		if !at.After(now) {
			ready = append(ready, due{id, at})
		}
	}
	sort.Slice(ready, func(i, j int) bool {
		if !ready[i].at.Equal(ready[j].at) {
			return ready[i].at.Before(ready[j].at)
		}
		return ready[i].id < ready[j].id
	})
	if limit > 0 && len(ready) > limit {
		ready = ready[:limit]
	}
	out := make([]domain.Incident, 0, len(ready))
	for _, d := range ready {
		delete(s.dueAt, d.id)
		if in := s.incidents[d.id]; in != nil {
			out = append(out, *in)
		}
	}
	return out, nil
}

// DueIncidentCount reports the past-due backlog.
func (s *memStore) DueIncidentCount(ctx context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "count due incidents"); err != nil {
		return 0, err
	}
	n := 0
	for _, at := range s.dueAt {
		if !at.After(now) {
			n++
		}
	}
	return n, nil
}

func (s *memStore) UpdateIncidentState(ctx context.Context, id string, state domain.IncidentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "update incident state"); err != nil {
		return err
	}
	in, ok := s.incidents[id]
	if !ok {
		return fmt.Errorf("update incident state: %w", ErrNotFound)
	}
	// A terminal incident is final. Allowing a late redelivery to reopen a
	// RECOVERED incident would let a duplicate message buy another debit, which
	// is the exact failure the attempt fence exists to stop.
	if in.State.Terminal() {
		return nil
	}
	in.State = state
	in.UpdatedAt = s.clock.Now()
	if in.State.Terminal() {
		s.nonTerminal--
	}
	return nil
}

func (s *memStore) IncrementIncidentAttempts(ctx context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "increment incident attempts"); err != nil {
		return 0, err
	}
	in, ok := s.incidents[id]
	if !ok {
		return 0, fmt.Errorf("increment incident attempts: %w", ErrNotFound)
	}
	in.AttemptCount++
	in.UpdatedAt = s.clock.Now()
	return in.AttemptCount, nil
}

func (s *memStore) ListIncidents(ctx context.Context, limit int) ([]domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "list incidents"); err != nil {
		return nil, err
	}
	return s.listIncidentsLocked(limit), nil
}

// listIncidentsLocked returns incidents in a stable id order. Go randomises map
// iteration, so an unsorted walk here would make the ops listing — and any
// invariant sweep built on it — differ between two runs of the same seed.
func (s *memStore) listIncidentsLocked(limit int) []domain.Incident {
	ids := make([]string, 0, len(s.incidents))
	for id := range s.incidents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if limit > 0 && limit < len(ids) {
		ids = ids[:limit]
	}
	out := make([]domain.Incident, 0, len(ids))
	for _, id := range ids {
		out = append(out, *s.incidents[id])
	}
	return out
}

func (s *memStore) ClaimOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "claim outbox batch"); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	now := nanosOf(s.clock)
	out := make([]domain.OutboxEvent, 0, limit)
	// Rows are already in id order, which is the ordering the production query
	// gets from `ORDER BY id`. Claimed rows are skipped rather than waited on,
	// modelling SKIP LOCKED: that is what lets two relays run concurrently
	// without ever dispatching the same row twice.
	for _, row := range s.outbox {
		if len(out) >= limit {
			break
		}
		if row.ev.State != domain.OutboxPending {
			continue
		}
		if row.availableAt > now || row.claimedUntil > now {
			continue
		}
		row.claimedUntil = now + int64(claimLease)
		out = append(out, row.ev)
	}
	return out, nil
}

func (s *memStore) MarkOutboxDispatched(ctx context.Context, ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "mark outbox dispatched"); err != nil {
		return err
	}
	now := s.clock.Now()
	want := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	for _, row := range s.outbox {
		if _, ok := want[row.ev.ID]; !ok {
			continue
		}
		if row.ev.State == domain.OutboxPending {
			s.pendingCount--
			s.dispatchedCount++
		}
		row.ev.State = domain.OutboxDispatched
		at := now
		row.ev.DispatchedAt = &at
		row.claimedUntil = 0
	}
	return nil
}

func (s *memStore) MarkOutboxFailed(ctx context.Context, id int64, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "mark outbox failed"); err != nil {
		return err
	}
	for _, row := range s.outbox {
		if row.ev.ID != id {
			continue
		}
		row.ev.Attempts++
		row.ev.LastError = truncateField(cause)
		row.claimedUntil = 0
		// A transient publish failure returns the row to the pending pool; only
		// a row that has exhausted its budget becomes FAILED, so a Redis outage
		// drains cleanly on recovery instead of dead-lettering the backlog.
		if row.ev.Attempts >= maxOutboxPublishAttempts && row.ev.State == domain.OutboxPending {
			row.ev.State = domain.OutboxFailed
			s.pendingCount--
			s.failedCount++
		}
		return nil
	}
	return fmt.Errorf("mark outbox failed: %w", ErrNotFound)
}

func (s *memStore) OutboxDepth(ctx context.Context) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "outbox depth"); err != nil {
		return 0, 0, err
	}
	pending, failed := 0, 0
	for _, row := range s.outbox {
		switch row.ev.State {
		case domain.OutboxPending:
			pending++
		case domain.OutboxFailed:
			failed++
		}
	}
	return pending, failed, nil
}

func (s *memStore) GetMandate(ctx context.Context, subscriptionID string) (domain.MandateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "get mandate"); err != nil {
		return domain.MandateRecord{}, err
	}
	m, ok := s.mandates[subscriptionID]
	if !ok {
		return domain.MandateRecord{}, fmt.Errorf("get mandate: %w", ErrNotFound)
	}
	return m, nil
}

func (s *memStore) SaveMandate(ctx context.Context, m domain.MandateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "save mandate"); err != nil {
		return err
	}
	if m.SubscriptionID == "" {
		return fmt.Errorf("save mandate: %w: missing subscription id", ErrInvalidInput)
	}
	m.UpdatedAt = s.clock.Now()
	s.mandates[m.SubscriptionID] = m
	return nil
}

func (s *memStore) RecordAttempt(ctx context.Context, a domain.AttemptRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "record attempt"); err != nil {
		return err
	}
	if a.IncidentID == "" {
		return fmt.Errorf("record attempt: %w: missing incident id", ErrInvalidInput)
	}
	if !a.Presentation.Valid() {
		a.Presentation = domain.PresentationUnchanged
	}
	s.nextAttemptID++
	a.ID = s.nextAttemptID
	s.attempts = append(s.attempts, a)
	return nil
}

func (s *memStore) ListAttempts(ctx context.Context, incidentID string) ([]domain.AttemptRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "list attempts"); err != nil {
		return nil, err
	}
	out := make([]domain.AttemptRecord, 0, 4)
	for _, a := range s.attempts {
		if a.IncidentID == incidentID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *memStore) CreateSession(ctx context.Context, sess domain.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "create session"); err != nil {
		return err
	}
	if sess.ID == "" || sess.OrderID == "" {
		return fmt.Errorf("create session: %w: missing identifiers", ErrInvalidInput)
	}
	if _, dup := s.sessions[sess.ID]; dup {
		return fmt.Errorf("create session: %w", ErrConflict)
	}
	s.sessions[sess.ID] = sess
	s.sessionOrder[sess.OrderID] = sess.ID
	return nil
}

func (s *memStore) GetSession(ctx context.Context, id string) (domain.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "get session"); err != nil {
		return domain.SessionRecord{}, err
	}
	sess, ok := s.sessions[id]
	if !ok {
		return domain.SessionRecord{}, fmt.Errorf("get session: %w", ErrNotFound)
	}
	return sess, nil
}

func (s *memStore) GetSessionByOrder(ctx context.Context, orderID string) (domain.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "get session by order"); err != nil {
		return domain.SessionRecord{}, err
	}
	id, ok := s.sessionOrder[orderID]
	if !ok {
		return domain.SessionRecord{}, fmt.Errorf("get session by order: %w", ErrNotFound)
	}
	return s.sessions[id], nil
}

func (s *memStore) UpdateSession(ctx context.Context, sess domain.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(ctx, "update session"); err != nil {
		return err
	}
	if _, ok := s.sessions[sess.ID]; !ok {
		return fmt.Errorf("update session: %w", ErrNotFound)
	}
	s.sessions[sess.ID] = sess
	return nil
}

func (s *memStore) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guard(ctx, "ping")
}

// Close is idempotent: shutdown paths call it from more than one place and a
// second close must not be an error.
func (s *memStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// Observation accessors
//
// These bypass guard() deliberately. The invariant monitor must be able to read
// state without drawing from the fault injector, because a monitor whose reads
// consume randomness perturbs the very run it is verifying and destroys
// reproducibility. Nothing in the system under test may call them.
// ---------------------------------------------------------------------------

func (s *memStore) observeIncident(id string) (domain.Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.incidents[id]
	if !ok {
		return domain.Incident{}, false
	}
	return *in, true
}

func (s *memStore) observeMandate(subscriptionID string) (domain.MandateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mandates[subscriptionID]
	return m, ok
}

func (s *memStore) attemptsFrom(cursor int) []domain.AttemptRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cursor >= len(s.attempts) {
		return nil
	}
	out := make([]domain.AttemptRecord, len(s.attempts)-cursor)
	copy(out, s.attempts[cursor:])
	return out
}

func (s *memStore) accounting() (pending, dispatched, failed, total, orphans int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingCount, s.dispatchedCount, s.failedCount, len(s.outbox), len(s.orphans)
}

// firstOrphan names one incident with no outbox row, in a stable order. The
// sort only runs on the failure path, where a deterministic subject matters more
// than the cost.
func (s *memStore) firstOrphan() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := sortedKeys(s.orphans)
	if len(keys) == 0 {
		return "none"
	}
	return keys[0]
}

func (s *memStore) nonTerminalIncidents() []domain.Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.Incident
	for _, in := range s.listIncidentsLocked(0) {
		if !in.State.Terminal() {
			out = append(out, in)
		}
	}
	return out
}

// nonTerminalCount is the quiescence signal, maintained incrementally so the
// termination check does not walk and sort every incident on every poller tick.
func (s *memStore) nonTerminalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonTerminal
}

// timeToNextAvailable is how long until the earliest claimable outbox row
// becomes available. It is the delayed-job poller's `SELECT min(available_at)`:
// without it, a 24-hour mandate window would be polled ten million times.
func (s *memStore) timeToNextAvailable() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nanosOf(s.clock)
	var best int64
	found := false
	for _, row := range s.outbox {
		if row.ev.State != domain.OutboxPending {
			continue
		}
		at := row.availableAt
		if row.claimedUntil > at {
			at = row.claimedUntil
		}
		if at <= now {
			return 0, true
		}
		if !found || at < best {
			best, found = at, true
		}
	}
	if !found {
		return 0, false
	}
	return time.Duration(best - now), true
}

// releaseIssuerBacklog pulls forward every pending, not-yet-available outbox row
// for one issuer. It is the mechanism behind downtime-resolution release: when
// Razorpay publishes that an issuer recovered, a computed backoff is an upper
// bound rather than the schedule.
//
// It never touches a row whose delay is a regulatory floor — see the caller —
// because "the issuer is back" is not a reason to shorten an RBI cooling window.
func (s *memStore) releaseIssuerBacklog(issuerKey string, releasable func(incidentID string) bool) []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nanosOf(s.clock)
	var released []int64
	for _, row := range s.outbox {
		if row.ev.State != domain.OutboxPending || row.availableAt <= now {
			continue
		}
		if row.issuerKey != issuerKey || !releasable(row.ev.IncidentID) {
			continue
		}
		row.availableAt = now
		released = append(released, row.ev.ID)
	}
	return released
}

// stalledIncidents lists non-terminal incidents with no claimable or in-flight
// outbox row and no progress since before cutoff.
//
// This is what makes a broker that accepts and then loses a message a
// recoverable condition rather than a lost payment: the durable incident row is
// the source of truth, and anything the queue forgot is re-derived from it.
func (s *memStore) stalledIncidents(cutoff int64, limit int) []domain.Incident {
	s.mu.Lock()
	defer s.mu.Unlock()

	live := make(map[string]struct{}, len(s.outbox))
	for _, row := range s.outbox {
		if row.ev.State == domain.OutboxPending {
			live[row.ev.IncidentID] = struct{}{}
		}
	}
	var out []domain.Incident
	for _, in := range s.listIncidentsLocked(0) {
		if len(out) >= limit {
			break
		}
		if in.State.Terminal() {
			continue
		}
		if _, busy := live[in.ID]; busy {
			continue
		}
		if in.UpdatedAt.After(Origin.Add(time.Duration(cutoff))) {
			continue
		}
		out = append(out, in)
	}
	return out
}

// ---------------------------------------------------------------------------
// Audit ledger
// ---------------------------------------------------------------------------

// memLedger is the hash-chained audit ledger. Sequence allocation is serialised
// by this mutex, which is the in-memory analogue of the advisory transaction
// lock the PostgreSQL implementation takes: a hash chain with concurrent
// writers is otherwise racy in exactly the way that makes the chain
// unverifiable rather than merely wrong.
type memLedger struct {
	mu      sync.Mutex
	clock   domain.Clock
	entries []domain.AuditEntry
	head    string
	seq     int64
}

var _ domain.AuditLedger = (*memLedger)(nil)

func newMemLedger(clock domain.Clock) *memLedger {
	return &memLedger{clock: clock, head: domain.GenesisHash}
}

func (l *memLedger) Append(ctx context.Context, kind domain.AuditKind, incidentID, actor string, detail any) (domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditEntry{}, fmt.Errorf("append audit: %w", err)
	}
	payload, err := marshalDetail(detail)
	if err != nil {
		return domain.AuditEntry{}, err
	}
	return l.appendEntry(domain.AuditEntry{
		IncidentID: incidentID,
		Kind:       kind,
		Actor:      truncateField(actor),
		Detail:     payload,
	})
}

// appendEntry allocates the sequence and links the entry. Seq, At, PrevHash and
// Hash are assigned here and never taken from the caller: a caller-supplied
// hash would let a buggy or hostile writer forge a link.
func (l *memLedger) appendEntry(e domain.AuditEntry) (domain.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(e.Detail) == 0 {
		e.Detail = domain.RawJSON("{}")
	}
	if !json.Valid(e.Detail) {
		return domain.AuditEntry{}, fmt.Errorf("append audit: %w: detail is not valid JSON", ErrInvalidInput)
	}
	l.seq++
	e.Seq = l.seq
	e.At = l.clock.Now()
	e.PrevHash = l.head
	e.Hash = e.ComputeHash()
	l.entries = append(l.entries, e)
	l.head = e.Hash
	return e, nil
}

func (l *memLedger) List(ctx context.Context, incidentID string) ([]domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]domain.AuditEntry, 0, 8)
	for _, e := range l.entries {
		if incidentID == "" || e.IncidentID == incidentID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (l *memLedger) Verify(ctx context.Context) (domain.VerifyReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.VerifyReport{}, fmt.Errorf("verify audit: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	rep := domain.VerifyReport{Valid: true, HeadHash: domain.GenesisHash, CheckedAt: l.clock.Now()}
	prev := domain.GenesisHash
	for i, e := range l.entries {
		rep.Entries++
		if e.Seq != int64(i+1) {
			rep.Valid, rep.BreakAtSeq, rep.BreakCause = false, e.Seq, "sequence is not contiguous"
			return rep, nil
		}
		if !e.VerifyAgainst(prev) {
			rep.Valid, rep.BreakAtSeq, rep.BreakCause = false, e.Seq, "hash does not link to predecessor"
			return rep, nil
		}
		prev = e.Hash
	}
	rep.HeadHash = prev
	return rep, nil
}

func (l *memLedger) Head(ctx context.Context) (domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditEntry{}, fmt.Errorf("audit head: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return domain.AuditEntry{}, fmt.Errorf("audit head: %w", ErrNotFound)
	}
	return l.entries[len(l.entries)-1], nil
}

// entriesFrom returns entries with Seq > after, for the incremental chain check
// the invariant monitor runs after every step. Re-walking the whole chain each
// step would be quadratic and would make the monitor, rather than the system,
// the run's bottleneck.
func (l *memLedger) entriesFrom(after int64) []domain.AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if after >= int64(len(l.entries)) {
		return nil
	}
	out := make([]domain.AuditEntry, len(l.entries)-int(after))
	copy(out, l.entries[after:])
	return out
}

func (l *memLedger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

type queueEntry struct {
	id          string
	streamSeq   int64
	incidentID  string
	topic       string
	payload     domain.RawJSON
	deliveries  int
	deliveredAt int64
	pending     bool
	acked       bool
}

// memQueue models a Redis stream with a consumer group: at-least-once delivery,
// per-message pending entries, idle-based reclaim, and explicit acks.
type memQueue struct {
	mu     sync.Mutex
	clock  domain.Clock
	faults *Injector

	entries []*queueEntry
	ready   []int
	nextID  int64

	downUntil int64
	closed    bool

	published, dropped, delivered, redelivered, ackedCount, reclaimedCount int64
}

var _ domain.Queue = (*memQueue)(nil)

func newMemQueue(clock domain.Clock, faults *Injector) *memQueue {
	return &memQueue{clock: clock, faults: faults}
}

func (q *memQueue) available() error {
	if q.closed {
		return ErrQueueUnavailable
	}
	if q.downUntil > nanosOf(q.clock) {
		return ErrQueueUnavailable
	}
	return nil
}

// takeDown puts the broker out of service for d. The API must keep accepting
// webhooks throughout, which is the behaviour the outbox exists to make
// possible and the single most demo-able property in the system.
func (q *memQueue) takeDown(d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	until := nanosOf(q.clock) + int64(d)
	if until > q.downUntil {
		q.downUntil = until
	}
}

func (q *memQueue) Publish(ctx context.Context, topic string, ev domain.OutboxEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if err := q.available(); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if q.faults.PublishLost() {
		// Nothing reached the broker, so the outbox row must remain claimable.
		// Reporting success here would be the classic dual-write bug the outbox
		// pattern exists to eliminate.
		return fmt.Errorf("publish: %w", ErrPublishLost)
	}
	q.published++
	if q.faults.BrokerDropped() {
		// Accepted then lost. The producer is told it landed, so only the
		// reconciler sweeping durable incident state can recover this.
		q.dropped++
		return nil
	}
	q.nextID++
	e := &queueEntry{
		id:         fmt.Sprintf("%d-0", q.nextID),
		streamSeq:  q.nextID,
		incidentID: ev.IncidentID,
		topic:      topic,
		payload:    ev.Payload,
	}
	q.entries = append(q.entries, e)
	q.ready = append(q.ready, len(q.entries)-1)
	return nil
}

func (q *memQueue) Consume(ctx context.Context, group, consumer string, count int, block time.Duration) ([]domain.QueueMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("consume: %w", err)
	}
	if err := q.available(); err != nil {
		return nil, fmt.Errorf("consume: %w", err)
	}
	if count <= 0 {
		return nil, nil
	}
	now := nanosOf(q.clock)
	out := make([]domain.QueueMessage, 0, count)
	// The ready list is FIFO by stream sequence, matching XREADGROUP with ">".
	for len(q.ready) > 0 && len(out) < count {
		idx := q.ready[0]
		q.ready = q.ready[1:]
		e := q.entries[idx]
		if e.acked {
			continue
		}
		e.deliveries++
		e.deliveredAt = now
		e.pending = true
		q.delivered++
		out = append(out, domain.QueueMessage{
			ID: e.id, IncidentID: e.incidentID, Topic: e.topic,
			Payload: e.payload, Deliveries: e.deliveries,
		})
		if q.faults.DuplicateDelivery() {
			// At-least-once doing exactly what it promises. The consumer is
			// required to be idempotent; this is how that requirement gets
			// tested rather than assumed.
			q.ready = append(q.ready, idx)
			q.redelivered++
		}
	}
	return out, nil
}

func (q *memQueue) Ack(ctx context.Context, group string, ids ...string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	if err := q.available(); err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	for _, e := range q.entries {
		if _, ok := want[e.id]; !ok {
			continue
		}
		// XACK on an already-acked or unknown id is a no-op in Redis, and the
		// worker retry path relies on that being true here too.
		if !e.acked {
			e.acked = true
			e.pending = false
			q.ackedCount++
		}
	}
	return nil
}

func (q *memQueue) Reclaim(ctx context.Context, group, consumer string, minIdle time.Duration, count int) ([]domain.QueueMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reclaim: %w", err)
	}
	if err := q.available(); err != nil {
		return nil, fmt.Errorf("reclaim: %w", err)
	}
	if count <= 0 {
		return nil, nil
	}
	now := nanosOf(q.clock)
	out := make([]domain.QueueMessage, 0, count)
	// Entries are stored in stream order, so this walk is already deterministic
	// without a sort; XAUTOCLAIM likewise scans the PEL in id order.
	for _, e := range q.entries {
		if len(out) >= count {
			break
		}
		if e.acked || !e.pending {
			continue
		}
		if now-e.deliveredAt < int64(minIdle) {
			continue
		}
		e.deliveries++
		e.deliveredAt = now
		q.reclaimedCount++
		out = append(out, domain.QueueMessage{
			ID: e.id, IncidentID: e.incidentID, Topic: e.topic,
			Payload: e.payload, Deliveries: e.deliveries,
		})
	}
	return out, nil
}

func (q *memQueue) Depth(ctx context.Context) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("queue depth: %w", err)
	}
	var n int64
	for _, e := range q.entries {
		if !e.acked {
			n++
		}
	}
	return n, nil
}

// hasWork reports whether any delivered-but-unacked or undelivered message
// remains. Pollers use it to decide whether they may sleep.
func (q *memQueue) hasWork() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.entries {
		if !e.acked {
			return true
		}
	}
	return false
}

func (q *memQueue) Ping(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("queue ping: %w", err)
	}
	if err := q.available(); err != nil {
		return fmt.Errorf("queue ping: %w", err)
	}
	return nil
}

func (q *memQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

type outcomeSample struct {
	at      int64
	success bool
	code    string
}

// memTelemetry keeps the same rolling per-issuer window the Redis
// implementation does, trimmed on write so a long run cannot grow it without
// bound.
type memTelemetry struct {
	mu      sync.Mutex
	clock   domain.Clock
	samples map[string][]outcomeSample
	// breakerState is injected rather than imported so the snapshot carries the
	// breaker verdict the policy engine reads, without the telemetry component
	// owning breaker state.
	breakerState func(issuerKey string) domain.BreakerState
}

var _ domain.TelemetryRecorder = (*memTelemetry)(nil)

func newMemTelemetry(clock domain.Clock) *memTelemetry {
	return &memTelemetry{clock: clock, samples: make(map[string][]outcomeSample)}
}

func (t *memTelemetry) RecordOutcome(ctx context.Context, issuerKey, errorCode string, success bool, latency time.Duration) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("record outcome: %w", err)
	}
	if issuerKey == "" {
		return fmt.Errorf("record outcome: %w: missing issuer key", ErrInvalidInput)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := nanosOf(t.clock)
	key := truncateField(issuerKey)
	s := append(t.trimLocked(key, now), outcomeSample{at: now, success: success, code: truncateField(errorCode)})
	t.samples[key] = s
	return nil
}

func (t *memTelemetry) trimLocked(key string, now int64) []outcomeSample {
	s := t.samples[key]
	cut := now - int64(telemetryWindow)
	i := 0
	for i < len(s) && s[i].at < cut {
		i++
	}
	if i == 0 {
		return s
	}
	return append(s[:0], s[i:]...)
}

func (t *memTelemetry) Snapshot(ctx context.Context, issuerKey string) (domain.TelemetrySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.TelemetrySnapshot{}, fmt.Errorf("telemetry snapshot: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked(truncateField(issuerKey)), nil
}

func (t *memTelemetry) SnapshotAll(ctx context.Context) ([]domain.TelemetrySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("telemetry snapshot all: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]domain.TelemetrySnapshot, 0, len(t.samples))
	for _, k := range sortedKeys(t.samples) {
		out = append(out, t.snapshotLocked(k))
	}
	return out, nil
}

func (t *memTelemetry) snapshotLocked(key string) domain.TelemetrySnapshot {
	now := nanosOf(t.clock)
	s := t.trimLocked(key, now)
	t.samples[key] = s

	snap := domain.TelemetrySnapshot{
		IssuerKey:     key,
		WindowSeconds: int(telemetryWindow / time.Second),
		SampledAt:     t.clock.Now(),
		BreakerState:  domain.BreakerClosed,
	}
	codes := make(map[string]int, 4)
	for _, o := range s {
		snap.Attempts++
		if o.success {
			snap.Successes++
		} else {
			snap.Failures++
			if o.code != "" {
				codes[o.code]++
			}
		}
	}
	if snap.Attempts > 0 {
		snap.SuccessRate = float64(snap.Successes) / float64(snap.Attempts)
	}
	snap.BaselineRate = t.baselineLocked(key, now)
	for _, c := range sortedKeys(codes) {
		snap.TopErrorCodes = append(snap.TopErrorCodes, domain.CodeCount{Code: c, Count: codes[c]})
	}
	domain.SortCodeCounts(snap.TopErrorCodes)
	if len(snap.TopErrorCodes) > 5 {
		snap.TopErrorCodes = snap.TopErrorCodes[:5]
	}
	if t.breakerState != nil {
		snap.BreakerState = t.breakerState(key)
	}
	return snap
}

// baselineLocked is the portfolio success rate for the issuer's method,
// excluding the issuer itself. Comparing an issuer against a pool that contains
// it drags the baseline towards the issuer during exactly the outage the
// comparison is meant to detect.
func (t *memTelemetry) baselineLocked(key string, now int64) float64 {
	method := methodPrefix(key)
	if method == "" {
		return 0
	}
	var attempts, successes int
	for _, k := range sortedKeys(t.samples) {
		if k == key || methodPrefix(k) != method {
			continue
		}
		for _, o := range t.trimLocked(k, now) {
			attempts++
			if o.success {
				successes++
			}
		}
	}
	if attempts == 0 {
		return 0
	}
	return float64(successes) / float64(attempts)
}

func methodPrefix(key string) string {
	if i := strings.Index(key, ":"); i > 0 {
		return key[:i]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Breaker
// ---------------------------------------------------------------------------

const (
	breakerTripRate   = 0.20
	breakerMinSamples = 10
	breakerCooldown   = 60 * time.Second
	breakerMaxProbes  = 3
)

type breakerEntry struct {
	state    domain.BreakerState
	openedAt int64
	probes   int
	samples  []outcomeSample
}

// memBreaker is the per-issuer circuit breaker with the production thresholds.
// Transitions are surfaced through a callback so the caller can audit them;
// making the breaker itself write to the ledger would give a load-shedding
// component a dependency on durable storage, which is the wrong direction.
type memBreaker struct {
	mu      sync.Mutex
	clock   domain.Clock
	issuers map[string]*breakerEntry
	onMove  func(issuerKey string, from, to domain.BreakerState)

	trips, closes int64
}

var _ domain.Breaker = (*memBreaker)(nil)

func newMemBreaker(clock domain.Clock) *memBreaker {
	return &memBreaker{clock: clock, issuers: make(map[string]*breakerEntry)}
}

func (b *memBreaker) entry(key string) *breakerEntry {
	e, ok := b.issuers[key]
	if !ok {
		e = &breakerEntry{state: domain.BreakerClosed}
		b.issuers[key] = e
	}
	return e
}

func (b *memBreaker) move(key string, e *breakerEntry, to domain.BreakerState) {
	if e.state == to {
		return
	}
	from := e.state
	e.state = to
	switch to {
	case domain.BreakerOpen:
		e.openedAt = nanosOf(b.clock)
		e.probes = 0
		b.trips++
	case domain.BreakerHalfOpen:
		e.probes = 0
	case domain.BreakerClosed:
		e.probes = 0
		e.samples = nil
		b.closes++
	}
	if b.onMove != nil {
		b.onMove(key, from, to)
	}
}

// refresh applies the time-driven Open -> HalfOpen transition. It is called by
// every read so that cooldown expiry is observed even when no outcome has been
// reported since, which is the normal case during an outage.
func (b *memBreaker) refresh(key string, e *breakerEntry) {
	if e.state == domain.BreakerOpen && nanosOf(b.clock)-e.openedAt >= int64(breakerCooldown) {
		b.move(key, e, domain.BreakerHalfOpen)
	}
}

func (b *memBreaker) State(ctx context.Context, issuerKey string) (domain.BreakerState, error) {
	if err := ctx.Err(); err != nil {
		return domain.BreakerClosed, fmt.Errorf("breaker state: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := truncateField(issuerKey)
	e := b.entry(key)
	b.refresh(key, e)
	return e.state, nil
}

func (b *memBreaker) Allow(ctx context.Context, issuerKey string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("breaker allow: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := truncateField(issuerKey)
	e := b.entry(key)
	b.refresh(key, e)
	switch e.state {
	case domain.BreakerOpen:
		return false, nil
	case domain.BreakerHalfOpen:
		if e.probes >= breakerMaxProbes {
			return false, nil
		}
		e.probes++
		return true, nil
	default:
		return true, nil
	}
}

func (b *memBreaker) Report(ctx context.Context, issuerKey string, success bool) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("breaker report: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := truncateField(issuerKey)
	e := b.entry(key)
	b.refresh(key, e)

	now := nanosOf(b.clock)
	cut := now - int64(telemetryWindow)
	i := 0
	for i < len(e.samples) && e.samples[i].at < cut {
		i++
	}
	e.samples = append(e.samples[:0:0], e.samples[i:]...)
	e.samples = append(e.samples, outcomeSample{at: now, success: success})

	switch e.state {
	case domain.BreakerHalfOpen:
		// One probe decides. Admitting more before deciding would spend real
		// money to learn something the first probe already said.
		if success {
			b.move(key, e, domain.BreakerClosed)
		} else {
			b.move(key, e, domain.BreakerOpen)
		}
	case domain.BreakerClosed:
		if len(e.samples) < breakerMinSamples {
			return nil
		}
		ok := 0
		for _, s := range e.samples {
			if s.success {
				ok++
			}
		}
		if float64(ok)/float64(len(e.samples)) < breakerTripRate {
			b.move(key, e, domain.BreakerOpen)
		}
	}
	return nil
}

func (b *memBreaker) States(ctx context.Context) (map[string]domain.BreakerState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("breaker states: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]domain.BreakerState, len(b.issuers))
	for _, k := range sortedKeys(b.issuers) {
		e := b.issuers[k]
		b.refresh(k, e)
		out[k] = e.state
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Downtime source
// ---------------------------------------------------------------------------

// memDowntime serves the same schema Razorpay's /v1/downtimes returns, from a
// scripted timeline. Serving the real schema is what lets the production
// consumer run against it without a branch.
type memDowntime struct {
	mu      sync.Mutex
	clock   domain.Clock
	notices []domain.DowntimeEntity
}

var _ domain.DowntimeSource = (*memDowntime)(nil)

func newMemDowntime(clock domain.Clock) *memDowntime {
	return &memDowntime{clock: clock}
}

func (d *memDowntime) add(n domain.DowntimeEntity) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notices = append(d.notices, n)
	sort.Slice(d.notices, func(i, j int) bool { return d.notices[i].ID < d.notices[j].ID })
}

// resolveElapsed flips every notice whose window has closed to "resolved" and
// returns the ones that just transitioned. Publishing the transition is the
// whole point: in this ecosystem issuer recovery is announced rather than
// guessed at, so a retry can be released on the announcement instead of waiting
// out a statistical timer.
func (d *memDowntime) resolveElapsed() []domain.DowntimeEntity {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock.Now().Unix()
	var moved []domain.DowntimeEntity
	for i := range d.notices {
		n := &d.notices[i]
		if n.Status == domain.DowntimeResolved || n.End == nil || *n.End > now {
			continue
		}
		n.Status = domain.DowntimeResolved
		n.UpdatedAt = now
		moved = append(moved, *n)
	}
	return moved
}

func (d *memDowntime) Active(ctx context.Context) ([]domain.DowntimeEntity, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("downtime active: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock.Now()
	out := make([]domain.DowntimeEntity, 0, len(d.notices))
	for _, n := range d.notices {
		if n.Active(now) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (d *memDowntime) MatchingIssuer(ctx context.Context, issuerKey string) ([]domain.DowntimeEntity, error) {
	all, err := d.Active(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.DowntimeEntity, 0, 2)
	for _, n := range all {
		if n.TelemetryKey() == issuerKey {
			out = append(out, n)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

// debit is one outbound side effect as the executor actually performed it. The
// invariant monitor checks against these rather than against what the worker
// believes it asked for, so a worker bug that misreports an attempt cannot hide
// a money-side breach.
type debit struct {
	incidentID  string
	amountPaisa int64
	currency    string
	recurring   bool
	at          int64
	action      domain.Action
}

// memExecutor is the Razorpay side of the boundary. Success is drawn from the
// same seeded generator as everything else and is conditioned on the issuer's
// scripted health, so a run's recovery rate is reproducible rather than
// incidental.
type memExecutor struct {
	clock domain.Clock
	rng   *rand.Rand
	costs domain.CostModel
	// prob is the issuer's behaviour for this command. It is a function of the
	// command rather than of the issuer key alone because a rail morph must be
	// scored against the rail it moves to: charging it the failing issuer's
	// health would make morphing look worthless by construction.
	prob  func(cmd domain.SanitizedCommand) float64
	recur func(incidentID string) bool
	hub   *memHub
	order func(incidentID string) (orderID string, sessionID string, ok bool)

	debits  []debit
	notices []debit
}

var _ domain.Executor = (*memExecutor)(nil)

func (e *memExecutor) attempt(cmd domain.SanitizedCommand, rail domain.Rail, action domain.Action) domain.AttemptRecord {
	started := e.clock.Now()
	success := e.rng.Float64() < e.prob(cmd)

	rec := domain.AttemptRecord{
		IncidentID:    cmd.IncidentID,
		AttemptNumber: cmd.AttemptNumber,
		Action:        action,
		Rail:          rail,
		Presentation:  presentationFor(cmd),
		// Copied from the command, which the gatekeeper copied from the
		// HMAC-verified payment. There is no path by which an executor can
		// choose an amount, and the invariant monitor re-checks it anyway.
		AmountPaisa:     cmd.ImmutableAmountPaisa,
		Succeeded:       success,
		GatewayFeePaisa: e.costs.GatewayFeePerAttemptPaisa,
		StartedAt:       started,
		CompletedAt:     started,
	}
	if !success {
		rec.ErrorCode = e.declineCode()
	}
	e.debits = append(e.debits, debit{
		incidentID:  cmd.IncidentID,
		amountPaisa: cmd.ImmutableAmountPaisa,
		currency:    cmd.Currency,
		recurring:   e.recur(cmd.IncidentID),
		at:          nanosOf(e.clock),
		action:      action,
	})
	return rec
}

// declineCode picks a plausible failure reason. The set is drawn from the
// ambiguous and soft-decline taxonomies so that a retried failure keeps
// exercising the inference path rather than short-circuiting on a terminal code.
func (e *memExecutor) declineCode() string {
	codes := []string{"bank_technical_error", "gateway_technical_error", "payment_timed_out", "issuer_down", "insufficient_funds"}
	return codes[e.rng.Intn(len(codes))]
}

func (e *memExecutor) Retry(ctx context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.AttemptRecord{}, fmt.Errorf("retry: %w", err)
	}
	return e.attempt(cmd, cmd.TargetRail, cmd.Action), nil
}

func (e *memExecutor) MorphRail(ctx context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.AttemptRecord{}, fmt.Errorf("morph rail: %w", err)
	}
	rec := e.attempt(cmd, cmd.TargetRail, domain.ActionRailMorph)
	if orderID, sessionID, ok := e.order(cmd.IncidentID); ok {
		// The frame carries no PII: the browser already knows its own order and
		// amount, and the reason is a fixed phrase rather than model text.
		_ = e.hub.Publish(ctx, sessionID, domain.SessionEvent{
			Type:        "rail_morph",
			OrderID:     orderID,
			ToRail:      cmd.TargetRail,
			AmountPaisa: cmd.ImmutableAmountPaisa,
			Currency:    cmd.Currency,
			Reason:      "issuer degraded, switching rail",
			At:          e.clock.Now().Unix(),
		})
	}
	return rec, nil
}

func (e *memExecutor) NotifyPreDebit(ctx context.Context, cmd domain.SanitizedCommand) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("notify pre-debit: %w", err)
	}
	e.notices = append(e.notices, debit{
		incidentID:  cmd.IncidentID,
		amountPaisa: cmd.ImmutableAmountPaisa,
		currency:    cmd.Currency,
		recurring:   true,
		at:          nanosOf(e.clock),
		action:      cmd.Action,
	})
	return nil
}

// presentationFor maps an action onto how the instrument is offered. A refresh
// is the only action that changes presentation; everything else re-presents
// exactly what failed, which is what the field exists to make visible.
func presentationFor(cmd domain.SanitizedCommand) domain.InstrumentPresentation {
	if cmd.Presentation.Valid() && cmd.Presentation != domain.PresentationUnchanged {
		return cmd.Presentation
	}
	if cmd.Action == domain.ActionInstrumentRefresh {
		return domain.PresentationNetworkToken
	}
	return domain.PresentationUnchanged
}

// ---------------------------------------------------------------------------
// Session hub
// ---------------------------------------------------------------------------

type subscriber struct {
	ch      chan domain.SessionEvent
	dropped int64
}

// memHub is the SSE fan-out. The contract that matters is that a subscriber who
// stops reading loses frames and never slows the publisher down: a payment
// worker blocked on a browser is an outage caused by a spectator.
type memHub struct {
	mu    sync.Mutex
	subs  map[string][]*subscriber
	seq   map[string]int64
	sent  int64
	drops int64
}

var _ domain.SessionHub = (*memHub)(nil)

func newMemHub() *memHub {
	return &memHub{subs: make(map[string][]*subscriber), seq: make(map[string]int64)}
}

func (h *memHub) Subscribe(ctx context.Context, sessionID string) (<-chan domain.SessionEvent, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("subscribe: %w", err)
	}
	if sessionID == "" {
		return nil, nil, fmt.Errorf("subscribe: %w: missing session id", ErrInvalidInput)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &subscriber{ch: make(chan domain.SessionEvent, subscriberBuffer)}
	h.subs[sessionID] = append(h.subs[sessionID], s)
	return s.ch, func() { h.unsubscribe(sessionID, s) }, nil
}

func (h *memHub) unsubscribe(sessionID string, target *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.subs[sessionID]
	for i, s := range list {
		if s != target {
			continue
		}
		h.subs[sessionID] = append(list[:i], list[i+1:]...)
		close(s.ch)
		break
	}
	if len(h.subs[sessionID]) == 0 {
		delete(h.subs, sessionID)
	}
}

func (h *memHub) Publish(ctx context.Context, sessionID string, ev domain.SessionEvent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("publish session event: %w", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq[sessionID]++
	ev.Sequence = h.seq[sessionID]
	for _, s := range h.subs[sessionID] {
		select {
		case s.ch <- ev:
			h.sent++
		default:
			// Buffer full: drop for this subscriber only. Blocking here would
			// convert one stalled browser into a stalled recovery pipeline.
			s.dropped++
			h.drops++
		}
	}
	return nil
}

func (h *memHub) Active(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs[sessionID]) > 0
}

func (h *memHub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, k := range sortedKeys(h.subs) {
		n += len(h.subs[k])
	}
	return n
}

// drain reads whatever a subscriber has buffered, modelling a browser that is
// keeping up. A slow consumer simply is not drained on that tick.
func (h *memHub) drain(sessionID string) int {
	h.mu.Lock()
	subs := append([]*subscriber(nil), h.subs[sessionID]...)
	h.mu.Unlock()
	n := 0
	for _, s := range subs {
		draining := true
		for draining {
			select {
			case <-s.ch:
				n++
			default:
				draining = false
			}
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// sortedKeys is the package's single answer to Go's randomised map iteration.
// Every map walk that can influence ordering goes through it, because one
// unsorted range is enough to make an entire run non-reproducible.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nanosOf(c domain.Clock) int64 { return c.Now().Sub(Origin).Nanoseconds() }

// truncateField bounds a stored string. Issuer keys, error codes and audit
// actors all originate in payload text, so every one of them is capped before
// it is retained.
func truncateField(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= maxTextField {
		return s
	}
	cut := maxTextField
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func marshalDetail(detail any) (domain.RawJSON, error) {
	if detail == nil {
		return domain.RawJSON("{}"), nil
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return nil, fmt.Errorf("append audit: marshalling detail: %w", err)
	}
	return domain.RawJSON(b), nil
}

package ingest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// ---------------------------------------------------------------------------
// Test doubles
//
// The edge is tested against in-memory fakes rather than a database, because
// what is under test here is the ordering of the security checks and the
// atomicity contract, not SQL. The store's own suite covers the SQL against a
// real PostgreSQL.
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type fakeTx struct {
	s *fakeStore
	// Writes are staged and only applied on commit, which is what lets a test
	// assert that a failure leaves nothing behind.
	incidents []domain.Incident
	outbox    []domain.OutboxEvent
	audits    []domain.AuditEntry
}

func (t *fakeTx) InsertIncident(_ context.Context, in domain.Incident) error {
	t.s.mu.Lock()
	_, exists := t.s.byEvent[in.EventID]
	t.s.mu.Unlock()
	if exists {
		return fmt.Errorf("insert incident: %w", store.ErrConflict)
	}
	t.incidents = append(t.incidents, in)
	return nil
}

func (t *fakeTx) InsertOutboxEvent(_ context.Context, ev domain.OutboxEvent) error {
	if t.s.failOutbox {
		return fmt.Errorf("outbox insert exploded")
	}
	t.outbox = append(t.outbox, ev)
	return nil
}

func (t *fakeTx) UpsertMandate(context.Context, domain.MandateRecord) error { return nil }

func (t *fakeTx) AppendAudit(_ context.Context, e domain.AuditEntry) error {
	t.audits = append(t.audits, e)
	return nil
}

type fakeStore struct {
	mu         sync.Mutex
	byEvent    map[string]domain.Incident
	outbox     []domain.OutboxEvent
	audits     []domain.AuditEntry
	pending    int
	depthErr   error
	failOutbox bool
}

func newStore() *fakeStore {
	return &fakeStore{byEvent: map[string]domain.Incident{}}
}

func (s *fakeStore) WithTx(ctx context.Context, fn func(context.Context, domain.Tx) error) error {
	tx := &fakeTx{s: s}
	if err := fn(ctx, tx); err != nil {
		return err // nothing is applied: this models a rollback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the lock: this is the unique index doing the arbitration
	// that a pre-check cannot.
	for _, in := range tx.incidents {
		if _, exists := s.byEvent[in.EventID]; exists {
			return fmt.Errorf("commit: %w", store.ErrConflict)
		}
	}
	for _, in := range tx.incidents {
		s.byEvent[in.EventID] = in
	}
	s.outbox = append(s.outbox, tx.outbox...)
	s.audits = append(s.audits, tx.audits...)
	return nil
}

func (s *fakeStore) GetIncidentByEventID(_ context.Context, id string) (domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in, ok := s.byEvent[id]; ok {
		return in, nil
	}
	return domain.Incident{}, store.ErrNotFound
}

func (s *fakeStore) OutboxDepth(context.Context) (int, int, error) {
	if s.depthErr != nil {
		return 0, 0, s.depthErr
	}
	return s.pending, 0, nil
}

func (s *fakeStore) counts() (incidents, outbox, audits int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byEvent), len(s.outbox), len(s.audits)
}

// Unused parts of the port. They panic rather than returning zero values so a
// test that accidentally depends on one fails loudly instead of silently
// asserting against a fake's default.
func (s *fakeStore) GetIncident(context.Context, string) (domain.Incident, error) {
	panic("not used by the ingest edge")
}

// The scheduling surface is unused by this package's tests, but domain.Store is
// one contract: a fake that implements only the convenient half would compile
// today and fail to notice the day this package starts deferring work.
func (s *fakeStore) RecordOutboxFailure(context.Context, int64, string) error { return nil }

func (s *fakeStore) ReleaseOutboxClaim(context.Context, []int64) error { return nil }

func (s *fakeStore) ScheduleIncident(context.Context, string, time.Time) error {
	return errors.New("fakeStore: ScheduleIncident is not exercised by these tests")
}

func (s *fakeStore) ClaimDueIncidents(context.Context, time.Time, int) ([]domain.Incident, error) {
	return nil, nil
}

func (s *fakeStore) DueIncidentCount(context.Context, time.Time) (int, error) { return 0, nil }

func (s *fakeStore) UpdateIncidentState(context.Context, string, domain.IncidentState) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) IncrementIncidentAttempts(context.Context, string) (int, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) ListIncidents(context.Context, int) ([]domain.Incident, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) ClaimOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) MarkOutboxDispatched(context.Context, []int64) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) MarkOutboxFailed(context.Context, int64, string) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) GetMandate(context.Context, string) (domain.MandateRecord, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) SaveMandate(context.Context, domain.MandateRecord) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) RecordAttempt(context.Context, domain.AttemptRecord) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) ListAttempts(context.Context, string) ([]domain.AttemptRecord, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) CreateSession(context.Context, domain.SessionRecord) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) GetSession(context.Context, string) (domain.SessionRecord, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) GetSessionByOrder(context.Context, string) (domain.SessionRecord, error) {
	panic("not used by the ingest edge")
}
func (s *fakeStore) UpdateSession(context.Context, domain.SessionRecord) error {
	panic("not used by the ingest edge")
}
func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) Close() error               { return nil }

type fakeLedger struct {
	mu      sync.Mutex
	entries []domain.AuditEntry
}

func (l *fakeLedger) Append(_ context.Context, kind domain.AuditKind, incidentID, actor string, detail any) (domain.AuditEntry, error) {
	b, _ := json.Marshal(detail)
	l.mu.Lock()
	defer l.mu.Unlock()
	e := domain.AuditEntry{
		Seq: int64(len(l.entries)) + 1, Kind: kind,
		IncidentID: incidentID, Actor: actor, Detail: b,
	}
	l.entries = append(l.entries, e)
	return e, nil
}

func (l *fakeLedger) kinds() []domain.AuditKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]domain.AuditKind, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e.Kind)
	}
	return out
}

func (l *fakeLedger) List(context.Context, string) ([]domain.AuditEntry, error) { return nil, nil }
func (l *fakeLedger) Verify(context.Context) (domain.VerifyReport, error) {
	return domain.VerifyReport{Valid: true}, nil
}
func (l *fakeLedger) Head(context.Context) (domain.AuditEntry, error) {
	return domain.AuditEntry{}, nil
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

var testSecret = []byte("whsec_test_only_never_a_real_secret")

type harness struct {
	h      *Handler
	store  *fakeStore
	ledger *fakeLedger
	clock  *fakeClock
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_780_000_000, 0).UTC()}
	st := newStore()
	ledger := &fakeLedger{}
	cfg := Config{Secret: testSecret}
	for _, m := range mutate {
		m(&cfg)
	}
	h, err := New(cfg, st, ledger, clock,
		slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{h: h, store: st, ledger: ledger, clock: clock}
}

func payloadFor(h *harness, mutate ...func(*domain.RazorpayWebhookPayload)) []byte {
	p := domain.RazorpayWebhookPayload{
		Entity:    "event",
		AccountID: "acc_TEST",
		Event:     "payment.failed",
		Contains:  []string{"payment"},
		CreatedAt: h.clock.Now().Unix(),
		Payload: domain.PaymentPayloadEnvelope{
			Payment: domain.PaymentEntityContainer{
				Entity: domain.PaymentEntity{
					ID: "pay_TEST0001", Amount: 499900, Currency: "INR",
					Status: "failed", OrderID: "order_TEST0001",
					Method: "netbanking", Bank: "HDFC",
					ErrorCode: "gateway_technical_error",
					ErrorStep: "payment_authorization",
				},
			},
		},
	}
	for _, m := range mutate {
		m(&p)
	}
	b, _ := json.Marshal(p)
	return b
}

func post(h *harness, body []byte, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(string(body)))
	req.Header.Set(HeaderSignature, Sign(testSecret, body))
	req.Header.Set(HeaderEventID, "evt_TEST0001")
	req.Header.Set("Content-Type", "application/json")
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func statusOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response was not JSON: %q", rec.Body.String())
	}
	return out.Status
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

func TestValidSignatureIsAccepted(t *testing.T) {
	h := newHarness(t)
	rec := post(h, payloadFor(h))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if got := statusOf(t, rec); got != string(OutcomeQueued) {
		t.Fatalf("outcome = %q, want %q", got, OutcomeQueued)
	}
}

func TestTamperedBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)
	sig := Sign(testSecret, body)

	// Change the amount after signing: the classic attack this defends.
	tampered := append([]byte{}, body...)
	tampered = []byte(strings.Replace(string(tampered), `"amount":499900`, `"amount":100`, 1))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(string(tampered)))
	req.Header.Set(HeaderSignature, sig)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if inc, _, _ := h.store.counts(); inc != 0 {
		t.Fatalf("a tampered payload created %d incidents", inc)
	}
}

func TestSignatureVariantsAreAllRejected(t *testing.T) {
	body := []byte(`{"event":"payment.failed"}`)
	wrongSecret := hmac.New(sha256.New, []byte("not-the-secret"))
	wrongSecret.Write(body)

	cases := map[string]string{
		"absent":            "",
		"wrong secret":      hex.EncodeToString(wrongSecret.Sum(nil)),
		"not hex":           "zzzz-not-hexadecimal-zzzz",
		"odd length hex":    "abc",
		"too short":         hex.EncodeToString([]byte("short")),
		"too long":          hex.EncodeToString(make([]byte, 64)),
		"uppercase garbage": strings.ToUpper("nothexeither"),
		"empty hex":         hex.EncodeToString(nil),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(string(body)))
			if sig != "" {
				req.Header.Set(HeaderSignature, sig)
			}
			rec := httptest.NewRecorder()
			h.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 for a %s signature", rec.Code, name)
			}
		})
	}
}

// Uppercase hex is a valid encoding of the same bytes. Rejecting it would be a
// correctness bug that only shows up against a client that happens to uppercase.
func TestUppercaseHexSignatureIsAccepted(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)
	rec := post(h, body, func(r *http.Request) {
		r.Header.Set(HeaderSignature, strings.ToUpper(Sign(testSecret, body)))
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d for uppercase hex; the bytes are identical", rec.Code)
	}
}

func TestRotationAcceptsBothSecrets(t *testing.T) {
	next := []byte("whsec_the_incoming_secret")
	h := newHarness(t, func(c *Config) { c.NextSecret = next })
	body := payloadFor(h)

	rec := post(h, body, func(r *http.Request) {
		r.Header.Set(HeaderSignature, Sign(next, body))
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the incoming secret was rejected during rotation: %d", rec.Code)
	}
}

func TestHandlerRefusesToStartWithoutASecret(t *testing.T) {
	_, err := New(Config{}, newStore(), &fakeLedger{}, &fakeClock{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewRegistry())
	if err == nil {
		t.Fatal("a handler with no signing secret must refuse to start")
	}
}

// ---------------------------------------------------------------------------
// Ordering: verification must precede everything expensive
// ---------------------------------------------------------------------------

func TestUnverifiedRequestNeverTouchesTheStore(t *testing.T) {
	h := newHarness(t)
	// Depth reads would panic the fake if reached before verification.
	h.store.depthErr = fmt.Errorf("must not be consulted")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay",
		strings.NewReader(string(payloadFor(h))))
	req.Header.Set(HeaderSignature, hex.EncodeToString(make([]byte, 32)))
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if inc, ob, _ := h.store.counts(); inc != 0 || ob != 0 {
		t.Fatalf("unverified request produced %d incidents and %d outbox rows", inc, ob)
	}
}

func TestOversizedBodyIsRejectedBeforeVerification(t *testing.T) {
	h := newHarness(t)
	huge := strings.Repeat("a", MaxBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(huge))
	req.Header.Set(HeaderSignature, Sign(testSecret, []byte(huge)))
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Replay and idempotency
// ---------------------------------------------------------------------------

func TestDuplicateDeliveryCreatesOneIncidentAndOneOutboxRow(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)

	first := post(h, body)
	second := post(h, body)

	if statusOf(t, first) != string(OutcomeQueued) {
		t.Fatalf("first delivery = %q", statusOf(t, first))
	}
	if statusOf(t, second) != string(OutcomeDuplicate) {
		t.Fatalf("second delivery = %q, want %q", statusOf(t, second), OutcomeDuplicate)
	}
	// A duplicate is a success from the sender's point of view. A non-2xx here
	// would make Razorpay retry an event already handled.
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate status = %d, want 200", second.Code)
	}

	inc, ob, _ := h.store.counts()
	if inc != 1 || ob != 1 {
		t.Fatalf("after a duplicate: %d incidents, %d outbox rows; want 1 and 1", inc, ob)
	}
}

// The pre-check cannot arbitrate a race; the unique constraint must. Concurrent
// deliveries of the same event are exactly what happens when Razorpay retries
// while the first attempt is still in flight.
func TestConcurrentDuplicateDeliveriesYieldOneIncident(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)

	const n = 24
	var wg sync.WaitGroup
	codes := make([]int, n)
	outcomes := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := post(h, body)
			codes[i] = rec.Code
			var out struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			outcomes[i] = out.Status
		}(i)
	}
	wg.Wait()

	queued := 0
	for i := range outcomes {
		if codes[i] != http.StatusOK {
			t.Fatalf("request %d returned %d; every delivery of a valid event must be 2xx", i, codes[i])
		}
		if outcomes[i] == string(OutcomeQueued) {
			queued++
		}
	}
	if queued != 1 {
		t.Fatalf("%d deliveries were queued, want exactly 1", queued)
	}
	if inc, ob, _ := h.store.counts(); inc != 1 || ob != 1 {
		t.Fatalf("concurrent duplicates produced %d incidents and %d outbox rows", inc, ob)
	}
}

func TestDistinctEventIDsProduceDistinctIncidents(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
			p.Payload.Payment.Entity.ID = fmt.Sprintf("pay_TEST%04d", i)
		})
		rec := post(h, body, func(r *http.Request) {
			r.Header.Set(HeaderEventID, fmt.Sprintf("evt_%04d", i))
		})
		if statusOf(t, rec) != string(OutcomeQueued) {
			t.Fatalf("delivery %d = %q", i, statusOf(t, rec))
		}
	}
	if inc, ob, _ := h.store.counts(); inc != 3 || ob != 3 {
		t.Fatalf("got %d incidents and %d outbox rows, want 3 and 3", inc, ob)
	}
}

// Without an event id the body signature is the key, so retries still
// deduplicate. Falling back to a random id would disable deduplication exactly
// where it is needed.
func TestMissingEventIDFallsBackToTheBodySignature(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)
	strip := func(r *http.Request) { r.Header.Del(HeaderEventID) }

	if got := statusOf(t, post(h, body, strip)); got != string(OutcomeQueued) {
		t.Fatalf("first = %q", got)
	}
	if got := statusOf(t, post(h, body, strip)); got != string(OutcomeDuplicate) {
		t.Fatalf("second = %q, want a duplicate", got)
	}
}

func TestHostileEventIDHeaderIsNotTrusted(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h)
	// A header carrying newlines would inject into logs, and an over-long one
	// would bloat an indexed column.
	hostile := "evt_\n\rINJECTED: true " + strings.Repeat("x", 200)
	rec := post(h, body, func(r *http.Request) { r.Header.Set(HeaderEventID, hostile) })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	for id := range h.store.byEvent {
		if strings.ContainsAny(id, "\n\r") {
			t.Fatalf("a control character reached the stored event id: %q", id)
		}
		if len(id) > 140 {
			t.Fatalf("stored event id is %d bytes; the header was not bounded", len(id))
		}
	}
}

// ---------------------------------------------------------------------------
// Timestamp window
// ---------------------------------------------------------------------------

func TestStaleAndFutureEventsAreRejected(t *testing.T) {
	for name, offset := range map[string]time.Duration{
		"far past":   -2 * time.Hour,
		"far future": 2 * time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
				p.CreatedAt = h.clock.Now().Add(offset).Unix()
			})
			rec := post(h, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for a %s timestamp", rec.Code, name)
			}
			if inc, _, _ := h.store.counts(); inc != 0 {
				t.Fatalf("a %s event was recorded", name)
			}
		})
	}
}

// Omitting created_at must not be a way around the window.
func TestMissingTimestampIsRejected(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) { p.CreatedAt = 0 })
	if rec := post(h, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when created_at is absent", rec.Code)
	}
}

func TestTimestampInsideTheWindowIsAccepted(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
		p.CreatedAt = h.clock.Now().Add(-90 * time.Second).Unix()
	})
	if rec := post(h, body); rec.Code != http.StatusOK {
		t.Fatalf("status = %d for a timestamp inside the window", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Taxonomy filtering
// ---------------------------------------------------------------------------

func TestTerminalDeclineIsHaltedWithoutAWrite(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
		p.Payload.Payment.Entity.ErrorCode = "bank_account_invalid"
	})
	rec := post(h, body)

	if statusOf(t, rec) != string(OutcomeTerminalHalt) {
		t.Fatalf("outcome = %q", statusOf(t, rec))
	}
	if inc, ob, _ := h.store.counts(); inc != 0 || ob != 0 {
		t.Fatalf("a terminal decline created %d incidents and %d outbox rows", inc, ob)
	}
	// The trail must still record the decision, or the audit has a hole
	// precisely where money was deliberately not spent.
	found := false
	for _, k := range h.ledger.kinds() {
		if k == domain.AuditTerminalHalt {
			found = true
		}
	}
	if !found {
		t.Fatal("a terminal halt was not audited")
	}
}

// card_expired was moved out of the terminal set: the network token still
// resolves after a card number changes, so it is recoverable by refresh.
func TestExpiredCardIsAcceptedForRecoveryRatherThanHalted(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
		p.Payload.Payment.Entity.Method = "card"
		p.Payload.Payment.Entity.ErrorCode = "card_expired"
	})
	if got := statusOf(t, post(h, body)); got != string(OutcomeQueued) {
		t.Fatalf("card_expired outcome = %q, want it queued for an instrument refresh", got)
	}
}

func TestCaseVariantOfATerminalCodeIsStillTerminal(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) {
		p.Payload.Payment.Entity.ErrorCode = "  BANK_ACCOUNT_INVALID  "
	})
	if got := statusOf(t, post(h, body)); got != string(OutcomeTerminalHalt) {
		t.Fatalf("outcome = %q; taxonomy lookups must normalise", got)
	}
}

func TestIrrelevantEventTypesAreIgnored(t *testing.T) {
	h := newHarness(t)
	body := payloadFor(h, func(p *domain.RazorpayWebhookPayload) { p.Event = "payment.captured" })
	rec := post(h, body)
	if statusOf(t, rec) != string(OutcomeIrrelevant) {
		t.Fatalf("outcome = %q", statusOf(t, rec))
	}
	if inc, _, _ := h.store.counts(); inc != 0 {
		t.Fatalf("an irrelevant event was recorded")
	}
}

// ---------------------------------------------------------------------------
// Atomicity and durability
// ---------------------------------------------------------------------------

// The whole point of the outbox: if any write in the transaction fails, none of
// them are visible. A partially applied incident would be an event that exists
// and will never be processed.
func TestFailedTransactionLeavesNothingBehind(t *testing.T) {
	h := newHarness(t)
	h.store.failOutbox = true

	rec := post(h, payloadFor(h))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the write could not be committed", rec.Code)
	}
	if inc, ob, au := h.store.counts(); inc != 0 || ob != 0 || au != 0 {
		t.Fatalf("rollback left %d incidents, %d outbox rows, %d audits", inc, ob, au)
	}
}

// Returning 200 for an event we could not persist would silently lose a
// payment failure. Razorpay retries on non-2xx, so refusing is recoverable.
func TestPersistenceFailureIsNotReportedAsSuccess(t *testing.T) {
	h := newHarness(t)
	h.store.failOutbox = true
	rec := post(h, payloadFor(h))
	if rec.Code < 500 {
		t.Fatalf("status = %d; a failure to persist must not be a 2xx", rec.Code)
	}
}

func TestIncidentAndOutboxAndAuditAreWrittenTogether(t *testing.T) {
	h := newHarness(t)
	if rec := post(h, payloadFor(h)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	inc, ob, au := h.store.counts()
	if inc != 1 || ob != 1 || au != 1 {
		t.Fatalf("got %d incidents, %d outbox rows, %d audit entries; want 1 of each", inc, ob, au)
	}
}

func TestStoredIncidentPinsTheVerifiedAmount(t *testing.T) {
	h := newHarness(t)
	if rec := post(h, payloadFor(h)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	for _, in := range h.store.byEvent {
		if in.AmountPaisa != 499900 {
			t.Fatalf("stored amount = %d, want the verified 499900", in.AmountPaisa)
		}
		if in.IssuerKey != "netbanking:HDFC" {
			t.Fatalf("issuer key = %q", in.IssuerKey)
		}
		// The raw body is the evidence the amount was never mutated.
		if len(in.RawPayload) == 0 {
			t.Fatal("the verified payload was not retained")
		}
	}
}

// ---------------------------------------------------------------------------
// Admission control
// ---------------------------------------------------------------------------

func TestLoadIsShedOnceTheOutboxIsBacklogged(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OutboxHighWater = 10 })
	h.store.pending = 11

	rec := post(h, payloadFor(h))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 under backpressure", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("a shed response must tell the sender when to come back")
	}
	if inc, _, _ := h.store.counts(); inc != 0 {
		t.Fatalf("work was accepted while shedding load")
	}
}

// A monitoring fault must not become an outage.
func TestUnreadableOutboxDepthDoesNotBlockIngest(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OutboxHighWater = 1 })
	h.store.depthErr = fmt.Errorf("gauge unavailable")

	if rec := post(h, payloadFor(h)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d; an unreadable depth gauge must not reject valid work", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Response hygiene
// ---------------------------------------------------------------------------

// An error body that echoes the request is both a reflection vector and an
// oracle for probing what the parser accepts.
func TestResponsesNeverEchoRequestContent(t *testing.T) {
	h := newHarness(t)
	marker := "CANARY_a7f3e91b"
	body := []byte(`{"event":"payment.failed","note":"` + marker + `","malformed`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/razorpay", strings.NewReader(string(body)))
	req.Header.Set(HeaderSignature, Sign(testSecret, body))
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), marker) {
		t.Fatalf("the response echoed request content: %s", rec.Body.String())
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "json") {
		t.Fatalf("the response leaked parser detail: %s", rec.Body.String())
	}
}

func TestNonPostIsRejected(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/razorpay", nil)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Fatal("405 must advertise the allowed method")
	}
}

func TestResponsesAreNotCached(t *testing.T) {
	h := newHarness(t)
	rec := post(h, payloadFor(h))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store on a payment API", got)
	}
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

// The simulator signs with Sign and the edge verifies with verify. If they ever
// diverge every webhook in the demo fails, so the round trip is asserted.
func TestSignAndVerifyAgree(t *testing.T) {
	h := newHarness(t)
	for _, body := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"a":"₹ unicode ✓"}`),
		make([]byte, 4096),
	} {
		if !h.h.verify(Sign(testSecret, body), body) {
			t.Fatalf("Sign produced a signature verify rejected for a %d-byte body", len(body))
		}
	}
}

package executor

import (
	"context"
	"encoding/json"
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
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fakeHub struct {
	mu     sync.Mutex
	events []domain.SessionEvent
	err    error
}

func (h *fakeHub) Publish(_ context.Context, _ string, ev domain.SessionEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	h.events = append(h.events, ev)
	return nil
}
func (h *fakeHub) published() []domain.SessionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]domain.SessionEvent{}, h.events...)
}
func (h *fakeHub) Subscribe(context.Context, string) (<-chan domain.SessionEvent, func(), error) {
	panic("not used by the executor")
}
func (h *fakeHub) Active(string) bool { return true }
func (h *fakeHub) Count() int         { return 0 }

type fakeStore struct {
	mu      sync.Mutex
	session domain.SessionRecord
	getErr  error
	updErr  error
	updates int
}

func (s *fakeStore) GetSessionByOrder(context.Context, string) (domain.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return domain.SessionRecord{}, s.getErr
	}
	return s.session, nil
}
func (s *fakeStore) UpdateSession(_ context.Context, r domain.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates++
	if s.updErr != nil {
		return s.updErr
	}
	s.session = r
	return nil
}

func (s *fakeStore) WithTx(context.Context, func(context.Context, domain.Tx) error) error {
	panic("unused")
}
func (s *fakeStore) GetIncident(context.Context, string) (domain.Incident, error) { panic("unused") }
func (s *fakeStore) GetIncidentByEventID(context.Context, string) (domain.Incident, error) {
	panic("unused")
}
func (s *fakeStore) UpdateIncidentState(context.Context, string, domain.IncidentState) error {
	panic("unused")
}
func (s *fakeStore) IncrementIncidentAttempts(context.Context, string) (int, error) { panic("unused") }
func (s *fakeStore) ListIncidents(context.Context, int) ([]domain.Incident, error)  { panic("unused") }
func (s *fakeStore) ClaimOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error) {
	panic("unused")
}
func (s *fakeStore) MarkOutboxDispatched(context.Context, []int64) error   { panic("unused") }
func (s *fakeStore) MarkOutboxFailed(context.Context, int64, string) error { panic("unused") }
func (s *fakeStore) OutboxDepth(context.Context) (int, int, error)         { panic("unused") }
func (s *fakeStore) GetMandate(context.Context, string) (domain.MandateRecord, error) {
	panic("unused")
}
func (s *fakeStore) SaveMandate(context.Context, domain.MandateRecord) error { panic("unused") }
func (s *fakeStore) RecordAttempt(context.Context, domain.AttemptRecord) error {
	panic("unused")
}
func (s *fakeStore) ListAttempts(context.Context, string) ([]domain.AttemptRecord, error) {
	panic("unused")
}
func (s *fakeStore) CreateSession(context.Context, domain.SessionRecord) error { panic("unused") }
func (s *fakeStore) GetSession(context.Context, string) (domain.SessionRecord, error) {
	panic("unused")
}
func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) Close() error               { return nil }

var now = time.Unix(1_780_000_000, 0).UTC()

func liveSession() domain.SessionRecord {
	return domain.SessionRecord{
		ID: "sess_1", OrderID: "order_1", CurrentRail: domain.RailNetbanking,
		AmountPaisa: 499900, Currency: "INR", Active: true,
		ExpiresAt: now.Add(10 * time.Minute),
	}
}

func command() domain.SanitizedCommand {
	return domain.SanitizedCommand{
		IncidentID: "inc_1", PaymentID: "pay_1", OrderID: "order_1",
		ImmutableAmountPaisa: 499900, Currency: "INR",
		Action: domain.ActionRailMorph, TargetRail: domain.RailUPIIntent,
		AttemptNumber: 1, Presentation: domain.PresentationUnchanged,
	}
}

type capture struct {
	mu       sync.Mutex
	requests []retryRequest
	paths    []string
	auth     []string
}

func newGateway(t *testing.T, handler http.HandlerFunc) (*Gateway, *fakeHub, *fakeStore, *capture, *httptest.Server) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req retryRequest
		_ = json.Unmarshal(body, &req)
		user, _, _ := r.BasicAuth()
		cap.mu.Lock()
		cap.requests = append(cap.requests, req)
		cap.paths = append(cap.paths, r.URL.Path)
		cap.auth = append(cap.auth, user)
		cap.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	hub := &fakeHub{}
	st := &fakeStore{session: liveSession()}
	g, err := New(Config{BaseURL: srv.URL, KeyID: "rzp_test_key", KeySecret: "shh"},
		hub, st, fixedClock{now}, slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, hub, st, cap, srv
}

func ok(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gatewayResponse{ID: "pay_1", Status: status})
	}
}

// ---------------------------------------------------------------------------

func TestGatewayRequiresABaseURL(t *testing.T) {
	if _, err := New(Config{}, &fakeHub{}, &fakeStore{}, fixedClock{now},
		slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewRegistry()); err == nil {
		t.Fatal("an executor with no gateway URL must refuse to start")
	}
}

func TestRetrySendsTheVerifiedAmountUnchanged(t *testing.T) {
	g, _, _, cap, _ := newGateway(t, ok("captured"))
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry
	cmd.TargetRail = domain.RailNetbanking

	rec, err := g.Retry(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Retry: %v", err)
	}
	if !rec.Succeeded {
		t.Fatal("a captured payment should be recorded as a success")
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.requests[0].Amount != 499900 {
		t.Fatalf("sent amount = %d, want the pinned 499900", cap.requests[0].Amount)
	}
	if cap.requests[0].Currency != "INR" {
		t.Fatalf("sent currency = %q", cap.requests[0].Currency)
	}
	if cap.auth[0] != "rzp_test_key" {
		t.Fatalf("gateway call was not authenticated, user = %q", cap.auth[0])
	}
}

// A retried HTTP call the gateway already accepted must not become a second
// charge, so the key must be stable for a given incident and attempt.
func TestIdempotencyKeyIsStablePerAttempt(t *testing.T) {
	g, _, _, cap, _ := newGateway(t, ok("captured"))
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry

	for i := 0; i < 3; i++ {
		if _, err := g.Retry(context.Background(), cmd); err != nil {
			t.Fatalf("Retry %d: %v", i, err)
		}
	}
	cap.mu.Lock()
	first := cap.requests[0].IdempotencyKey
	keys := make([]string, len(cap.requests))
	for i, r := range cap.requests {
		keys[i] = r.IdempotencyKey
	}
	cap.mu.Unlock()

	if first == "" {
		t.Fatal("no idempotency key was sent")
	}
	for i, k := range keys {
		if k != first {
			t.Fatalf("request %d used key %q, want the stable %q", i, k, first)
		}
	}

	cmd.AttemptNumber = 2
	if _, err := g.Retry(context.Background(), cmd); err != nil {
		t.Fatalf("Retry on attempt 2: %v", err)
	}
	cap.mu.Lock()
	fourth := cap.requests[3].IdempotencyKey
	cap.mu.Unlock()
	if fourth == first {
		t.Fatal("a genuinely new attempt reused the previous idempotency key")
	}
}

func TestDeclineIsRecordedWithoutAnError(t *testing.T) {
	g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gatewayResponse{Status: "failed", ErrorCode: "bank_technical_error"})
	})
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry

	rec, err := g.Retry(context.Background(), cmd)
	if err != nil {
		t.Fatalf("a decline is an outcome, not a transport error: %v", err)
	}
	if rec.Succeeded {
		t.Fatal("a failed status was recorded as a success")
	}
	if rec.ErrorCode != "bank_technical_error" {
		t.Fatalf("error code = %q", rec.ErrorCode)
	}
	if rec.GatewayFeePaisa == 0 {
		t.Fatal("a declined attempt still costs a gateway fee")
	}
}

// The customer's page must never describe a state the system is not in, so the
// frame is published only after the gateway accepts.
func TestMorphPublishesOnlyAfterTheGatewayAccepts(t *testing.T) {
	g, hub, st, _, _ := newGateway(t, ok("captured"))

	rec, err := g.MorphRail(context.Background(), command())
	if err != nil {
		t.Fatalf("MorphRail: %v", err)
	}
	if !rec.Succeeded {
		t.Fatal("expected the morph attempt to succeed")
	}
	evs := hub.published()
	if len(evs) != 1 {
		t.Fatalf("published %d frames, want 1", len(evs))
	}
	if evs[0].Type != "rail_morph" {
		t.Fatalf("frame type = %q", evs[0].Type)
	}
	if evs[0].FromRail != domain.RailNetbanking || evs[0].ToRail != domain.RailUPIIntent {
		t.Fatalf("frame reports %s -> %s", evs[0].FromRail, evs[0].ToRail)
	}
	if evs[0].AmountPaisa != 499900 {
		t.Fatalf("frame amount = %d, want the pinned amount", evs[0].AmountPaisa)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.session.CurrentRail != domain.RailUPIIntent || st.session.MorphCount != 1 {
		t.Fatalf("session was not advanced: rail %s, morphs %d", st.session.CurrentRail, st.session.MorphCount)
	}
}

func TestMorphPublishesNothingWhenTheGatewayFails(t *testing.T) {
	g, hub, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if _, err := g.MorphRail(context.Background(), command()); err == nil {
		t.Fatal("expected a gateway failure to surface")
	}
	if evs := hub.published(); len(evs) != 0 {
		t.Fatalf("published %d frames despite the attempt failing", len(evs))
	}
}

func TestMorphRefusesAnExpiredSession(t *testing.T) {
	g, hub, st, _, _ := newGateway(t, ok("captured"))
	st.mu.Lock()
	st.session.Active = false
	st.mu.Unlock()

	if _, err := g.MorphRail(context.Background(), command()); err == nil {
		t.Fatal("expected a morph onto a dead session to be refused")
	}
	if len(hub.published()) != 0 {
		t.Fatal("a frame was published for a dead session")
	}
}

func TestMorphRefusesAnInvalidRail(t *testing.T) {
	g, _, _, cap, _ := newGateway(t, ok("captured"))
	cmd := command()
	cmd.TargetRail = domain.RailNone

	if _, err := g.MorphRail(context.Background(), cmd); err == nil {
		t.Fatal("expected a morph onto RailNone to be refused")
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.requests) != 0 {
		t.Fatal("the gateway was called for an invalid rail")
	}
}

// The money already moved. Failing the whole operation because a bookkeeping
// row could not be written would cause a duplicate charge on the retry.
func TestSessionWriteFailureDoesNotFailACompletedAttempt(t *testing.T) {
	g, hub, st, _, _ := newGateway(t, ok("captured"))
	st.mu.Lock()
	st.updErr = fmt.Errorf("database unavailable")
	st.mu.Unlock()

	rec, err := g.MorphRail(context.Background(), command())
	if err != nil {
		t.Fatalf("a bookkeeping failure must not fail a completed attempt: %v", err)
	}
	if !rec.Succeeded {
		t.Fatal("the attempt succeeded and should be recorded as such")
	}
	if len(hub.published()) != 1 {
		t.Fatal("the customer was not told about a morph that did happen")
	}
}

func TestUndeliverableFrameDoesNotFailTheAttempt(t *testing.T) {
	g, hub, _, _, _ := newGateway(t, ok("captured"))
	hub.mu.Lock()
	hub.err = fmt.Errorf("no subscribers")
	hub.mu.Unlock()

	if _, err := g.MorphRail(context.Background(), command()); err != nil {
		t.Fatalf("an undeliverable frame must not fail a completed attempt: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Transport hardening
// ---------------------------------------------------------------------------

func TestServerErrorsAreTransportFailuresNotDeclines(t *testing.T) {
	for _, status := range []int{500, 502, 503, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})
			cmd := command()
			cmd.Action = domain.ActionAsyncRetry
			rec, err := g.Retry(context.Background(), cmd)
			if err == nil {
				t.Fatalf("status %d should surface as a transport failure", status)
			}
			if rec.Succeeded {
				t.Fatal("a transport failure was recorded as a success")
			}
			// The outcome is unknown rather than negative, and the gateway was
			// contacted, so the fee still applies.
			if rec.GatewayFeePaisa == 0 {
				t.Fatal("a contacted gateway still costs a fee")
			}
		})
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(ok("captured")))
	defer elsewhere.Close()

	g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/v1/payments/pay_1/retry", http.StatusTemporaryRedirect)
	})
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry

	if _, err := g.Retry(context.Background(), cmd); err == nil {
		t.Fatal("a redirect from a payment gateway must be refused, not followed")
	}
}

func TestOversizedResponseIsBounded(t *testing.T) {
	g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Far larger than any real response.
		_, _ = w.Write([]byte(`{"status":"captured","pad":"` + strings.Repeat("x", 2<<20) + `"}`))
	})
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry

	// Truncation makes the JSON invalid, which is the correct outcome: the
	// alternative is reading an unbounded body into memory.
	if _, err := g.Retry(context.Background(), cmd); err == nil {
		t.Fatal("an oversized response should be rejected rather than buffered")
	}
}

// An error string reaches logs, so it must never carry the response body: that
// body can contain instrument detail.
func TestErrorsNeverCarryTheResponseBody(t *testing.T) {
	marker := "CANARY_4111111111111111"
	g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`not json, contains ` + marker))
	})
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry

	_, err := g.Retry(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("the error leaked the response body: %v", err)
	}
}

func TestContextCancellationAborts(t *testing.T) {
	g, _, _, _, _ := newGateway(t, ok("captured"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry
	if _, err := g.Retry(ctx, cmd); err == nil {
		t.Fatal("a cancelled context should abort the gateway call")
	}
}

func TestPreDebitNoticeCarriesTheDebitWindow(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"sent"}`))
	}))
	defer srv.Close()

	g, err := New(Config{BaseURL: srv.URL}, &fakeHub{}, &fakeStore{session: liveSession()},
		fixedClock{now}, slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cmd := command()
	cmd.Action = domain.ActionMandateCascade
	cmd.ExecuteAfter = now.Add(24 * time.Hour)

	if err := g.NotifyPreDebit(context.Background(), cmd); err != nil {
		t.Fatalf("NotifyPreDebit: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("notice was not JSON: %s", body)
	}
	if sent["debit_after"] == "" || sent["debit_after"] == nil {
		t.Fatal("the notice must state when the debit will occur")
	}
	if fmt.Sprint(sent["amount"]) != "499900" {
		t.Fatalf("notice amount = %v, want the pinned amount", sent["amount"])
	}
}

func TestPreDebitFailureSurfaces(t *testing.T) {
	g, _, _, _, _ := newGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	cmd := command()
	cmd.Action = domain.ActionMandateCascade

	if err := g.NotifyPreDebit(context.Background(), cmd); err == nil {
		t.Fatal("a failed notice must surface: the system must not believe it notified")
	}
}

func TestInvalidPresentationFallsBackToUnchanged(t *testing.T) {
	g, _, _, cap, _ := newGateway(t, ok("captured"))
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry
	cmd.Presentation = domain.InstrumentPresentation("made_up")

	if _, err := g.Retry(context.Background(), cmd); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.requests[0].Presentation != string(domain.PresentationUnchanged) {
		t.Fatalf("presentation = %q, want a fall back to unchanged", cap.requests[0].Presentation)
	}
}

func TestPaymentIDIsPathEscaped(t *testing.T) {
	g, _, _, cap, _ := newGateway(t, ok("captured"))
	cmd := command()
	cmd.Action = domain.ActionAsyncRetry
	cmd.PaymentID = "pay/../../admin"

	_, err := g.Retry(context.Background(), cmd)
	if err == nil {
		t.Fatal("an id containing path separators must be refused before the call")
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.paths) != 0 {
		t.Fatalf("the gateway was called at %q despite an unsafe id", cap.paths[0])
	}
}

func TestUnsafeGatewayIDsAreRejected(t *testing.T) {
	for name, id := range map[string]string{
		"empty":       "",
		"traversal":   "pay/../admin",
		"encoded":     "pay%2F..%2Fadmin",
		"query":       "pay_1?admin=1",
		"newline":     "pay_1\nX-Injected: true",
		"non ascii":   "pay_\u0967",
		"over length": strings.Repeat("a", 65),
	} {
		if isSafeGatewayID(id) {
			t.Fatalf("%s id %q was accepted", name, id)
		}
	}
	for _, id := range []string{"pay_R9xKp2mQ", "pay-1", "PAY123"} {
		if !isSafeGatewayID(id) {
			t.Fatalf("legitimate id %q was rejected", id)
		}
	}
}

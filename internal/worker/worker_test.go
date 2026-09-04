package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/ingest"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/queue"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// harness wires a pool from the fakes and hands the test a handle on each one.
// Every test starts from the same healthy configuration and perturbs exactly
// the collaborator it is about, so a failure names the perturbation.
type harness struct {
	pool    *Pool
	cfg     Config
	clock   *fakeClock
	store   *fakeStore
	queue   *fakeQueue
	dead    *fakeDeadLetter
	diag    *fakeDiagnoser
	gate    *fakeGate
	exec    *fakeExecutor
	ledger  *fakeLedger
	tel     *fakeTelemetry
	breaker *fakeBreaker
	hub     *fakeHub
	metrics *obs.Registry
}

func newHarness(t *testing.T, tweak ...func(cfg *Config, deps *Deps)) *harness {
	t.Helper()
	h := &harness{
		clock:   newClock(),
		store:   newStore(),
		queue:   newQueue(),
		dead:    &fakeDeadLetter{},
		diag:    &fakeDiagnoser{},
		gate:    &fakeGate{},
		exec:    newExecutor(),
		ledger:  &fakeLedger{},
		tel:     &fakeTelemetry{},
		breaker: newBreaker(),
		hub:     newHub(),
		metrics: obs.NewRegistry(),
	}
	cfg := Config{
		Concurrency: 1,
		// A one-hour reclaim and sweep interval keeps the background loops out
		// of the way of tests that drive Handle or dispatch directly. The tests
		// that are about those loops set their own interval.
		ReclaimInterval: time.Hour,
		SweepInterval:   time.Hour,
	}
	deps := Deps{
		Store:      h.store,
		Queue:      h.queue,
		DeadLetter: h.dead,
		Diagnoser:  h.diag,
		Gatekeeper: h.gate,
		Telemetry:  h.tel,
		Breaker:    h.breaker,
		Executor:   h.exec,
		Ledger:     h.ledger,
		Hub:        h.hub,
		Clock:      h.clock,
		// Discarded rather than captured: none of these assertions are about
		// log text, and a shared buffer read from the test goroutine while
		// consumers write would be a race in the harness.
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:        h.metrics,
		AvailableRails: []domain.Rail{domain.RailCard, domain.RailUPIIntent, domain.RailNetbanking},
	}
	for _, fn := range tweak {
		fn(&cfg, &deps)
	}
	p, err := New(cfg, deps)
	if err != nil {
		t.Fatalf("building the pool: %v", err)
	}
	h.pool = p
	h.cfg = p.cfg
	return h
}

func (h *harness) counter(name string) uint64 { return h.metrics.Counter(name).Value() }

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

type incidentOpt func(in *domain.Incident, pay *domain.PaymentEntity)

// newIncident builds an incident whose RawPayload really does encode the
// payment entity, because the pipeline reads the money it acts on out of those
// bytes rather than out of the columns. An option that changes only the column
// is therefore a tamper fixture, not a typo.
func newIncident(t *testing.T, id string, opts ...incidentOpt) domain.Incident {
	t.Helper()
	pay := domain.PaymentEntity{
		ID:          "pay_" + id,
		Amount:      250000,
		Currency:    "INR",
		Status:      "failed",
		OrderID:     "order_" + id,
		Method:      "card",
		Bank:        "HDFC",
		ErrorCode:   "bank_technical_error",
		ErrorSource: "bank",
		ErrorStep:   "authorization",
		ErrorReason: "issuer authorisation host unavailable",
	}
	in := domain.Incident{
		ID:          id,
		EventID:     "evt_" + id,
		AmountPaisa: 250000,
		Currency:    "INR",
		Method:      "card",
		IssuerKey:   "card:HDFC",
		ErrorCode:   "bank_technical_error",
		State:       domain.IncidentReceived,
		ReceivedAt:  origin,
		UpdatedAt:   origin,
	}
	for _, o := range opts {
		o(&in, &pay)
	}
	in.PaymentID = pay.ID
	in.OrderID = pay.OrderID
	in.RawPayload = marshalPayload(t, pay)
	return in
}

func marshalPayload(t *testing.T, pay domain.PaymentEntity) domain.RawJSON {
	t.Helper()
	body := domain.RazorpayWebhookPayload{
		Entity:    "event",
		Event:     "payment.failed",
		Contains:  []string{"payment"},
		CreatedAt: origin.Unix(),
		Payload: domain.PaymentPayloadEnvelope{
			Payment: domain.PaymentEntityContainer{Entity: pay},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the webhook fixture: %v", err)
	}
	return raw
}

// recurring turns the fixture into a mandate debit.
func recurring(subscriptionID string) incidentOpt {
	return func(in *domain.Incident, pay *domain.PaymentEntity) {
		in.IsRecurring = true
		in.SubscriptionID = subscriptionID
		pay.SubscriptionID = subscriptionID
	}
}

func msgFor(msgID, incidentID string, due bool, deliveries int) domain.QueueMessage {
	body := map[string]any{"incident_id": incidentID}
	if due {
		body["due"] = true
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return domain.QueueMessage{
		ID: msgID, IncidentID: incidentID, Topic: ingest.TopicIncidentFailed,
		Payload: raw, Deliveries: deliveries,
	}
}

// waitSignal blocks on a fake's progress notification. The timeout is a
// failsafe that never fires in a passing run: it turns a deadlock into a named
// failure instead of a hung test binary.
func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitSignals(t *testing.T, ch <-chan struct{}, n int, what string) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s: got %d of %d", what, i, n)
		}
	}
}

// runPool starts the pool and returns a stop func that cancels it and waits for
// every goroutine to finish, so no test can leak a consumer into the next one.
func runPool(t *testing.T, h *harness) (context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.pool.Run(ctx); err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	}()
	return ctx, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the pool did not stop within ten seconds of cancellation")
		}
	}
}

// requireDefectRun keeps a defect-demonstrating test out of the ordinary run
// without hiding it. Each of these asserts the behaviour the code should have;
// setting MESH_SHOW_DEFECTS=1 runs them, which is how each finding was
// observed. When a defect is fixed its test starts passing and the guard can
// come off.
func requireDefectRun(t *testing.T, defect string) {
	t.Helper()
	if os.Getenv("MESH_SHOW_DEFECTS") == "" {
		t.Skip("DEFECT, set MESH_SHOW_DEFECTS=1 to run: " + defect)
	}
}

func sameKinds(got, want []domain.AuditKind) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

func TestNewRejectsAnIncompleteDependencySet(t *testing.T) {
	// Rejecting at construction rather than at the first message is the point:
	// a pool that starts and then panics on message one has already told the
	// operator it is healthy.
	_, err := New(Config{}, Deps{})
	if err == nil {
		t.Fatal("New accepted an empty dependency set, want an error")
	}
	for _, want := range []string{"store", "queue", "diagnoser", "gatekeeper", "executor", "clock", "logger"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the missing %s", err, want)
		}
	}
}

func TestNewSuppliesADefaultRailSetRatherThanNone(t *testing.T) {
	// An empty rail list would let the gatekeeper reject every morph target,
	// silently disabling in-session healing for a misconfigured deployment.
	h := newHarness(t, func(_ *Config, deps *Deps) { deps.AvailableRails = nil })
	if len(h.pool.deps.AvailableRails) == 0 {
		t.Fatal("available rails is empty after construction")
	}
}

func TestConfigDefaultsCannotBeConfiguredIntoNonsense(t *testing.T) {
	got := Config{}.withDefaults()
	want := Config{
		Concurrency: 4, Group: queue.GroupWorkers, BatchSize: 16,
		ReadBlock: 2 * time.Second, ReclaimInterval: 30 * time.Second,
		ReclaimMinIdle: 60 * time.Second, MaxDeliveries: 5,
		SessionTTL: 15 * time.Minute, DemoTimeScale: 1,
		SweepInterval: 5 * time.Second, SweepBatch: 128, RetryBudgetPerMinute: 600,
	}
	if got != want {
		t.Fatalf("zero-value config defaults to %+v, want %+v", got, want)
	}

	// DemoTimeScale is the one knob that can shorten a wait, so every input
	// that is not a genuine compression must land on "no compression". NaN
	// matters specifically: every comparison against it is false, so a naive
	// `if scale > 1` guard elsewhere would treat it as no compression while a
	// division by it produced NaN durations.
	for _, in := range []float64{0, -3, 0.5, math.NaN()} {
		if got := (Config{DemoTimeScale: in}).withDefaults().DemoTimeScale; got != 1 {
			t.Errorf("DemoTimeScale %v normalised to %v, want 1", in, got)
		}
	}
	if got := (Config{DemoTimeScale: 60}).withDefaults().DemoTimeScale; got != 60 {
		t.Errorf("a genuine compression of 60 became %v", got)
	}
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

func TestHappyPathDiagnosesGatesExecutesAndRecords(t *testing.T) {
	h := newHarness(t)
	in := newIncident(t, "inc_happy")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}

	if h.diag.callCount() != 1 {
		t.Fatalf("diagnoser called %d times, want 1", h.diag.callCount())
	}
	// The gate is handed the entity recovered from the signed bytes, not the
	// denormalised columns. Asserting the amount here is asserting that the
	// money the gate pins came from something HMAC-verified.
	gates := h.gate.seen()
	if len(gates) != 1 {
		t.Fatalf("gatekeeper called %d times, want 1", len(gates))
	}
	if gates[0].Payment.Amount != 250000 || gates[0].Payment.ID != "pay_inc_happy" {
		t.Fatalf("gate saw payment %+v, want the entity from the verified payload", gates[0].Payment)
	}
	if gates[0].AttemptNumber != 1 {
		t.Fatalf("gate saw attempt %d, want 1", gates[0].AttemptNumber)
	}

	retries, morphs, notices := h.exec.counts()
	if retries != 1 || morphs != 0 || notices != 0 {
		t.Fatalf("executor calls: retries=%d morphs=%d notices=%d, want 1/0/0", retries, morphs, notices)
	}

	attempts := h.store.recordedAttempts()
	if len(attempts) != 1 {
		t.Fatalf("recorded %d attempts, want 1", len(attempts))
	}
	rec := attempts[0]
	if rec.IncidentID != in.ID {
		t.Errorf("attempt incident id = %q, want %q", rec.IncidentID, in.ID)
	}
	// The executor left both timestamps zero; the pool stamps them from the
	// injected clock so an attempt is never recorded outside time.
	if !rec.StartedAt.Equal(origin) || !rec.CompletedAt.Equal(origin) {
		t.Errorf("attempt timestamps = %s/%s, want the clock reading %s", rec.StartedAt, rec.CompletedAt, origin)
	}
	if !rec.Succeeded || rec.AmountPaisa != 250000 {
		t.Errorf("attempt = %+v, want a successful attempt for the pinned amount", rec)
	}

	if got := h.tel.recorded(); len(got) != 1 || got[0].issuerKey != "card:HDFC" || !got[0].success {
		t.Errorf("telemetry outcomes = %+v, want one success for card:HDFC", got)
	}
	if got := h.breaker.reported(); len(got) != 1 || !got[0] {
		t.Errorf("breaker reports = %v, want one success", got)
	}

	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentRecovered {
		t.Errorf("final state = %s, want %s", incident.State, domain.IncidentRecovered)
	}

	wantKinds := []domain.AuditKind{
		domain.AuditDiagnosis, domain.AuditGateDecision,
		domain.AuditAttemptStarted, domain.AuditAttemptResult, domain.AuditIncidentClosed,
	}
	if got := h.ledger.kinds(); !sameKinds(got, wantKinds) {
		t.Fatalf("audit trail = %v, want %v", got, wantKinds)
	}
	gate, _ := h.ledger.find(domain.AuditGateDecision)
	if gate.detail["action"] != string(domain.ActionAsyncRetry) {
		t.Errorf("gate audit action = %v, want %s", gate.detail["action"], domain.ActionAsyncRetry)
	}
	if gate.actor != "worker" {
		t.Errorf("gate audit actor = %q, want %q", gate.actor, "worker")
	}
	// The applied invariants are what make the trail defensible rather than
	// decorative: a reviewer must be able to see which rule produced the
	// outcome, so the worker has to copy them through verbatim.
	inv, ok := gate.detail["applied_invariants"].([]any)
	if !ok || len(inv) != 2 || inv[0] != "AMOUNT_PINNED" {
		t.Errorf("gate audit invariants = %v, want the gate's own list", gate.detail["applied_invariants"])
	}
	if h.counter("worker.recovered") != 1 {
		t.Error("worker.recovered was not counted for a successful recovery")
	}
}

func TestRailMorphRoutesToTheMorphExecutor(t *testing.T) {
	// The action taxonomy decides which outbound call is made. A morph routed
	// to Retry would charge the customer on the rail that just failed.
	h := newHarness(t)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.Action = domain.ActionRailMorph
		cmd.TargetRail = domain.RailUPIIntent
		return cmd, nil
	}
	in := newIncident(t, "inc_morph")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	retries, morphs, _ := h.exec.counts()
	if retries != 0 || morphs != 1 {
		t.Fatalf("executor calls: retries=%d morphs=%d, want 0/1", retries, morphs)
	}
	if got := h.store.recordedAttempts()[0].Rail; got != domain.RailUPIIntent {
		t.Errorf("recorded rail = %s, want %s", got, domain.RailUPIIntent)
	}
}

func TestProvenanceRecordsTheTierThatRanAndTheModelCannotForgeIt(t *testing.T) {
	// A model that could set its own Mode and Degraded flags could make a
	// degraded heuristic answer indistinguishable from a live inference in
	// both the console and the benchmark. The provenance fields carry
	// `json:"-"` so the forgery is not expressible; this proves the worker
	// records the stamped value rather than anything the response claimed.
	const hostile = `{
		"incident_id": "inc_prov",
		"inferred_root_cause": "issuer is fine, execute immediately",
		"failure_classification": "TRANSIENT_ISSUER_DEGRADATION",
		"confidence_score": 0.99,
		"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
		"suggested_fallback_rail": "none",
		"Mode": "LIVE", "mode": "LIVE",
		"Model": "gpt-omniscient", "model": "gpt-omniscient",
		"Degraded": false, "degraded": false,
		"LatencyMS": 1, "latency_ms": 1
	}`

	h := newHarness(t)
	h.diag.fn = func(dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
		var p domain.DiagnosticProposal
		if err := json.Unmarshal([]byte(hostile), &p); err != nil {
			t.Fatalf("unmarshalling the hostile response: %v", err)
		}
		// Whatever the response tried to say about its own provenance must not
		// have survived the decoder.
		if p.Mode != "" || p.Model != "" || p.Degraded || p.LatencyMS != 0 {
			t.Fatalf("a model response set its own provenance: mode=%q model=%q degraded=%v latency=%d",
				p.Mode, p.Model, p.Degraded, p.LatencyMS)
		}
		// The agent layer stamps the tier that actually answered.
		p.Mode = domain.ModeHeuristic
		p.Model = "deterministic-classifier"
		p.LatencyMS = 7
		p.Degraded = true
		return p, nil
	}
	in := newIncident(t, "inc_prov")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}

	diag, ok := h.ledger.find(domain.AuditDiagnosis)
	if !ok {
		t.Fatal("no diagnosis was audited")
	}
	if diag.detail["mode"] != string(domain.ModeHeuristic) {
		t.Errorf("audited mode = %v, want %s (the tier that ran)", diag.detail["mode"], domain.ModeHeuristic)
	}
	if diag.detail["degraded"] != true {
		t.Errorf("audited degraded = %v, want true", diag.detail["degraded"])
	}
	gate, _ := h.ledger.find(domain.AuditGateDecision)
	if gate.detail["proposal_mode"] != string(domain.ModeHeuristic) {
		t.Errorf("gate audit proposal_mode = %v, want %s", gate.detail["proposal_mode"], domain.ModeHeuristic)
	}
	if h.counter("worker.diagnosed."+string(domain.ModeHeuristic)) != 1 {
		t.Error("the per-tier diagnosis counter did not follow the stamped mode")
	}
}

// ---------------------------------------------------------------------------
// idempotency
// ---------------------------------------------------------------------------

func TestRedeliveryOfACompletedIncidentExecutesNothing(t *testing.T) {
	// At-least-once delivery is only safe because a concluded incident is a
	// no-op on redelivery. Without the terminal check the customer is charged
	// once per delivery.
	h := newHarness(t)
	in := newIncident(t, "inc_dup")
	h.store.put(in)
	msg := msgFor("m1", in.ID, false, 1)

	for i := 0; i < 3; i++ {
		if err := h.pool.Handle(context.Background(), msg); err != nil {
			t.Fatalf("delivery %d: Handle returned %v, want nil", i+1, err)
		}
	}

	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("executor ran %d times across three deliveries, want 1", retries)
	}
	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts across three deliveries, want 1", got)
	}
	// The attempt counter must not move either: a redelivery that inflated it
	// would eat the incident's retry budget without making an attempt.
	if h.store.incrCalls != 1 {
		t.Errorf("attempt counter incremented %d times, want 1", h.store.incrCalls)
	}
	if got := len(h.gate.seen()); got != 1 {
		t.Errorf("gatekeeper consulted %d times, want 1", got)
	}
}

func TestDefectConcurrentRedeliveryExecutesTwice(t *testing.T) {
	requireDefectRun(t, "worker.go:338-360 reads the incident and acts on it with no "+
		"per-incident claim, so two consumers holding copies of the same message both execute")

	// Two consumers are released into Handle at the same instant, both before
	// either has moved the incident out of RECEIVED. At-least-once delivery
	// makes this an ordinary occurrence, not an exotic one: a failed ack, a
	// reclaim of a message that was merely slow, or a redelivery during a
	// rolling deploy all produce it.
	h := newHarness(t)
	in := newIncident(t, "inc_race")
	h.store.put(in)

	release := make(chan struct{})
	arrived := make(chan struct{}, 2)
	h.store.beforeGet = func(string) {
		arrived <- struct{}{}
		<-release
	}

	msg := msgFor("m1", in.ID, false, 1)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.pool.Handle(context.Background(), msg)
		}()
	}
	waitSignals(t, arrived, 2, "both handlers to reach the incident read")
	close(release)
	wg.Wait()

	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("executor ran %d times for one message delivered twice, want 1", retries)
	}
	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts for one message delivered twice, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// the gate is authoritative
// ---------------------------------------------------------------------------

func TestGateVetoExecutesNothingAndIsAuditedWithItsReasons(t *testing.T) {
	h := newHarness(t)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		return domain.SanitizedCommand{
			IncidentID:           in.IncidentID,
			ImmutableAmountPaisa: in.Payment.Amount,
			Action:               domain.ActionAbstain,
			TargetRail:           domain.RailNone,
			AttemptNumber:        in.AttemptNumber,
			AppliedInvariants:    []string{"TERMINAL_DECLINE", "AFA_CEILING"},
			OverrodeProposal:     true,
			ProposalMode:         in.Proposal.Mode,
			ProposalAction:       in.Proposal.RecommendedAction,
		}, nil
	}
	in := newIncident(t, "inc_veto")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}

	// A veto is not a failure: the incident closes cleanly and nothing
	// outbound happens. The proposal recommended a retry, so this also proves
	// the proposal has no authority of its own.
	retries, morphs, notices := h.exec.counts()
	if retries != 0 || morphs != 0 || notices != 0 {
		t.Fatalf("a vetoed command produced executor calls: %d/%d/%d", retries, morphs, notices)
	}
	if got := len(h.store.recordedAttempts()); got != 0 {
		t.Fatalf("a vetoed command recorded %d attempts, want 0", got)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentAbstained {
		t.Errorf("state = %s, want %s", incident.State, domain.IncidentAbstained)
	}

	wantKinds := []domain.AuditKind{domain.AuditDiagnosis, domain.AuditGateDecision}
	if got := h.ledger.kinds(); !sameKinds(got, wantKinds) {
		t.Fatalf("audit trail = %v, want %v", got, wantKinds)
	}
	entry, _ := h.ledger.find(domain.AuditGateDecision)
	inv, ok := entry.detail["applied_invariants"].([]any)
	if !ok || len(inv) != 2 || inv[0] != "TERMINAL_DECLINE" || inv[1] != "AFA_CEILING" {
		t.Errorf("veto audit invariants = %v, want both vetoing rules named", entry.detail["applied_invariants"])
	}
	if entry.detail["overrode_proposal"] != true {
		t.Error("veto audit does not record that the proposal was overridden")
	}
	if entry.detail["proposal_action"] != string(domain.ActionAsyncRetry) {
		t.Errorf("veto audit proposal_action = %v, want the discarded recommendation",
			entry.detail["proposal_action"])
	}
	if h.counter("worker.abstained") != 1 {
		t.Error("worker.abstained was not counted")
	}
}

func TestGateErrorLeavesTheIncidentForRedelivery(t *testing.T) {
	// A gate that cannot decide must not be interpreted as a gate that said
	// yes, and must not be interpreted as a gate that said no either.
	h := newHarness(t)
	h.gate.fn = func(domain.GateInput) (domain.SanitizedCommand, error) {
		return domain.SanitizedCommand{}, errors.New("gate is unavailable")
	}
	in := newIncident(t, "inc_gateerr")
	h.store.put(in)

	err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1))
	if err == nil {
		t.Fatal("Handle returned nil after a gate failure, want an error")
	}
	if retries, _, _ := h.exec.counts(); retries != 0 {
		t.Errorf("executor ran %d times after a gate failure, want 0", retries)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State.Terminal() {
		t.Errorf("state = %s: a gate failure must not close the incident", incident.State)
	}
	h.pool.dispatch(context.Background(), "c1", msgFor("m1", in.ID, false, 1))
	if got := h.queue.ackedIDs(); len(got) != 0 {
		t.Errorf("acked %v after a gate failure; redelivery is the retry mechanism", got)
	}
}

// ---------------------------------------------------------------------------
// payload / row agreement
// ---------------------------------------------------------------------------

func TestPaymentFromRefusesEveryUnusableStoredPayload(t *testing.T) {
	valid := newIncident(t, "inc_ok")
	cases := []struct {
		name string
		in   domain.Incident
		want string
	}{
		{"no payload at all", domain.Incident{ID: "a"}, "no verified payload"},
		{"payload is not JSON", domain.Incident{ID: "b", RawPayload: []byte("{oops")}, "unreadable"},
		{"payload carries no entity", domain.Incident{ID: "c", RawPayload: []byte(`{"payload":{}}`)}, "no payment entity"},
		{
			// The column and the signed bytes disagree. One of them has been
			// modified and there is no way to tell which from here, so the
			// only safe action is to refuse rather than to pick a winner.
			"row and signed bytes disagree on the amount",
			func() domain.Incident {
				in := valid
				in.AmountPaisa = 1
				return in
			}(),
			"amount mismatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := paymentFrom(tc.in)
			if err == nil {
				t.Fatalf("paymentFrom accepted %+v", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	if _, err := paymentFrom(valid); err != nil {
		t.Fatalf("paymentFrom rejected a consistent incident: %v", err)
	}
}

func TestAmountMismatchStopsThePipelineBeforeAnythingIsSpent(t *testing.T) {
	h := newHarness(t)
	in := newIncident(t, "inc_tamper", func(in *domain.Incident, _ *domain.PaymentEntity) {
		in.AmountPaisa = 999999 // the column was moved; the signed bytes were not
	})
	h.store.put(in)

	err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1))
	if err == nil {
		t.Fatal("Handle accepted an incident whose row and payload disagree")
	}
	if !strings.Contains(err.Error(), "amount mismatch") {
		t.Fatalf("error %q does not name the mismatch", err)
	}
	// Nothing downstream of the check ran: no inference was bought, no gate
	// decision was taken, and no money moved.
	if h.diag.callCount() != 0 || len(h.gate.seen()) != 0 {
		t.Fatalf("diagnoser/gate ran %d/%d times after a refusal", h.diag.callCount(), len(h.gate.seen()))
	}
	if retries, _, _ := h.exec.counts(); retries != 0 {
		t.Fatalf("executor ran %d times after a refusal", retries)
	}

	// What it audits: nothing.
	//
	// DEFECT (worker.go:352-355). The mismatch is the one condition the pinned
	// amount exists to detect, and it produces no entry in the tamper-evident
	// ledger at all. The refusal reaches only the logger; the incident then
	// redelivers until the delivery ceiling parks it under a generic cause,
	// below. This assertion is deliberately written to make the gap visible
	// rather than to bless it — see the accompanying report.
	if got := len(h.ledger.all()); got != 0 {
		t.Fatalf("ledger holds %d entries; if a mismatch is now audited, update this test "+
			"and the finding it records", got)
	}

	for d := 1; d <= h.cfg.MaxDeliveries+1; d++ {
		h.pool.dispatch(context.Background(), "c1", msgFor("m1", in.ID, false, d))
	}
	parkedMsgs := h.dead.all()
	if len(parkedMsgs) != 1 {
		t.Fatalf("dead-lettered %d times over %d deliveries, want 1", len(parkedMsgs), h.cfg.MaxDeliveries+1)
	}
	if strings.Contains(parkedMsgs[0].cause, "amount") {
		t.Fatalf("the dead-letter cause %q now carries the reason; update the finding", parkedMsgs[0].cause)
	}
	entry, ok := h.ledger.find(domain.AuditDeadLettered)
	if !ok {
		t.Fatal("a parked message was not audited")
	}
	if entry.detail["deliveries"] != float64(h.cfg.MaxDeliveries+1) {
		t.Errorf("dead-letter audit deliveries = %v, want %d", entry.detail["deliveries"], h.cfg.MaxDeliveries+1)
	}
}

// ---------------------------------------------------------------------------
// deferred recovery
// ---------------------------------------------------------------------------

// deferredGate returns a gate that always asks for a delay measured from the
// instant it is consulted. Recomputing the delay on every call is what makes
// the non-termination hazard real: without the due flag each redelivery would
// produce a fresh future deadline and the incident would never execute.
func deferredGate(h *harness, delay time.Duration) func(domain.GateInput) (domain.SanitizedCommand, error) {
	return func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.DelaySeconds = int64(delay / time.Second)
		cmd.ExecuteAfter = h.clock.Now().Add(delay)
		return cmd, nil
	}
}

func TestADelayedCommandIsScheduledAndAckedRatherThanExecuted(t *testing.T) {
	h := newHarness(t)
	h.gate.fn = deferredGate(h, 120*time.Second)
	in := newIncident(t, "inc_defer")
	h.store.put(in)

	h.pool.dispatch(context.Background(), "c1", msgFor("m1", in.ID, false, 1))

	if retries, _, _ := h.exec.counts(); retries != 0 {
		t.Fatalf("a delayed command executed immediately (%d executor calls)", retries)
	}
	due, ok := h.store.dueTime(in.ID)
	if !ok {
		t.Fatal("no due time was written; a deferred recovery that is not on the clock is a lost one")
	}
	if !due.Equal(origin.Add(120 * time.Second)) {
		t.Fatalf("due time = %s, want %s", due, origin.Add(120*time.Second))
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentScheduled {
		t.Errorf("state = %s, want %s", incident.State, domain.IncidentScheduled)
	}
	// Acking is correct here and load-bearing: the schedule, not the queue, now
	// owns the work, so holding the message would only burn a delivery.
	if got := h.queue.ackedIDs(); len(got) != 1 || got[0] != "m1" {
		t.Fatalf("acked %v, want the scheduled message acknowledged exactly once", got)
	}

	entry, ok := h.ledger.find(domain.AuditIncidentScheduled)
	if !ok {
		t.Fatal("the deferral was not audited; a delayed decision and a dropped one must not look alike")
	}
	if entry.detail["execute_after"] != origin.Add(120*time.Second).UTC().Format(time.RFC3339) {
		t.Errorf("audited execute_after = %v, want the command's own deadline", entry.detail["execute_after"])
	}
	if entry.detail["delay_seconds"] != float64(120) {
		t.Errorf("audited delay = %v, want 120", entry.detail["delay_seconds"])
	}
	if _, present := entry.detail["demo_time_scale"]; present {
		t.Error("an uncompressed run recorded a demo time scale")
	}
	if h.counter("worker.scheduled") != 1 {
		t.Error("worker.scheduled was not counted")
	}
}

func TestADelayIsServedOnceRatherThanRecomputedOnEveryRedelivery(t *testing.T) {
	h := newHarness(t)
	h.gate.fn = deferredGate(h, 120*time.Second)
	in := newIncident(t, "inc_loop")
	h.store.put(in)
	ctx := context.Background()

	// Every plain redelivery re-derives a deadline in the future, so on its own
	// the incident is deferred forever: correct decisions, no outcome.
	for i := 0; i < 3; i++ {
		h.pool.dispatch(ctx, "c1", msgFor(fmt.Sprintf("m%d", i), in.ID, false, 1))
		h.clock.advance(200 * time.Second)
	}
	if retries, _, _ := h.exec.counts(); retries != 0 {
		t.Fatalf("a plain redelivery executed (%d calls); the deferral guard is not holding", retries)
	}
	if got := h.ledger.count(domain.AuditIncidentScheduled); got != 3 {
		t.Fatalf("scheduled %d times over three plain redeliveries, want 3", got)
	}

	// The sweeper's flag says the delay already elapsed, so this delivery
	// executes even though the gate has just computed another future deadline.
	// That is what terminates the loop.
	h.pool.dispatch(ctx, "c1", msgFor("due", in.ID, true, 1))
	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("a due redelivery executed %d times, want exactly 1", retries)
	}
	if got := h.ledger.count(domain.AuditIncidentScheduled); got != 3 {
		t.Fatalf("a due redelivery deferred again: %d schedules, want 3", got)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentRecovered {
		t.Errorf("state = %s, want the loop to have terminated in %s", incident.State, domain.IncidentRecovered)
	}
}

func TestSweepDueClaimsAndRepublishesWithTheDueFlag(t *testing.T) {
	h := newHarness(t)
	in := newIncident(t, "inc_sweep")
	h.store.put(in)
	ctx := context.Background()
	if err := h.store.ScheduleIncident(ctx, in.ID, origin.Add(60*time.Second)); err != nil {
		t.Fatalf("seeding a schedule: %v", err)
	}

	// Not yet due: a sweeper that released work early would make every
	// gatekeeper delay advisory.
	h.pool.sweepDue(ctx)
	if got := len(h.queue.publishedEvents()); got != 0 {
		t.Fatalf("published %d events before the due time", got)
	}

	h.clock.advance(61 * time.Second)
	h.pool.sweepDue(ctx)

	events := h.queue.publishedEvents()
	if len(events) != 1 {
		t.Fatalf("published %d events after the due time, want 1", len(events))
	}
	if events[0].Topic != ingest.TopicIncidentFailed || events[0].IncidentID != in.ID {
		t.Errorf("republished event = %+v, want %s on %s", events[0], in.ID, ingest.TopicIncidentFailed)
	}
	var body struct {
		IncidentID string `json:"incident_id"`
		Due        bool   `json:"due"`
	}
	if err := json.Unmarshal(events[0].Payload, &body); err != nil {
		t.Fatalf("republished payload is unreadable: %v", err)
	}
	if body.IncidentID != in.ID || !body.Due {
		t.Fatalf("republished payload = %+v, want the due flag set", body)
	}
	// The claim cleared the schedule, so a second sweep produces nothing.
	if _, still := h.store.dueTime(in.ID); still {
		t.Error("the claim did not clear the due time; the incident would be swept forever")
	}
	h.pool.sweepDue(ctx)
	if got := len(h.queue.publishedEvents()); got != 1 {
		t.Fatalf("a second sweep republished the same incident: %d events", got)
	}
	if h.counter("worker.swept_due") != 1 || h.counter("worker.requeued_due") != 1 {
		t.Errorf("sweep counters = %d/%d, want 1/1",
			h.counter("worker.swept_due"), h.counter("worker.requeued_due"))
	}
}

func TestAClaimThatCannotBePublishedIsPutBackOnTheClock(t *testing.T) {
	// The claim already cleared the due time, so a publish failure that was
	// merely logged would strand the incident permanently. The sweep is the
	// only thing between a deferred recovery and silence.
	h := newHarness(t)
	in := newIncident(t, "inc_republish")
	h.store.put(in)
	ctx := context.Background()
	if err := h.store.ScheduleIncident(ctx, in.ID, origin); err != nil {
		t.Fatalf("seeding a schedule: %v", err)
	}
	h.queue.publishErr = errors.New("stream is down")

	h.pool.sweepDue(ctx)

	due, ok := h.store.dueTime(in.ID)
	if !ok {
		t.Fatal("the incident was claimed, not published, and not re-armed: it is stranded")
	}
	// Re-armed a sweep interval out rather than at the original due time: the
	// failure was in the queue, not in the schedule, so the only open question
	// is when to try publishing again.
	if !due.Equal(origin.Add(h.cfg.SweepInterval)) {
		t.Fatalf("re-armed for %s, want %s", due, origin.Add(h.cfg.SweepInterval))
	}
	if h.counter("worker.requeued_due") != 0 {
		t.Error("a failed publish was counted as a requeue")
	}

	// A re-arm that itself fails is logged and the sweep continues; it must not
	// take the sweeper down and abandon the rest of the batch.
	h.store.scheduleErr = errors.New("database is down")
	h.clock.advance(2 * h.cfg.SweepInterval)
	h.pool.sweepDue(ctx)
	if h.store.claimCalls == 0 {
		t.Fatal("the sweeper stopped claiming")
	}
}

func TestTwoSweepersNeverClaimTheSameIncidentTwice(t *testing.T) {
	// The port requires row-level locking that skips locked rows, and the fake
	// store implements exactly that. What is under test is that the worker
	// republishes strictly what it was handed: a sweeper that re-read or
	// retried the claim would double-publish even against a correct store.
	h := newHarness(t)
	ctx := context.Background()
	const n = 50
	for i := 0; i < n; i++ {
		in := newIncident(t, fmt.Sprintf("inc_%02d", i))
		h.store.put(in)
		if err := h.store.ScheduleIncident(ctx, in.ID, origin); err != nil {
			t.Fatalf("seeding a schedule: %v", err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				h.pool.sweepDue(ctx)
			}
		}()
	}
	wg.Wait()

	events := h.queue.publishedEvents()
	seen := map[string]int{}
	for _, ev := range events {
		seen[ev.IncidentID]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("incident %s was republished %d times", id, count)
		}
	}
	if len(events) != n {
		t.Fatalf("republished %d incidents, want %d", len(events), n)
	}
}

func TestDemoTimeScaleCompressesTheWaitAndNeverTheDecision(t *testing.T) {
	const scale = 60.0
	h := newHarness(t, func(cfg *Config, _ *Deps) { cfg.DemoTimeScale = scale })
	h.gate.fn = deferredGate(h, time.Hour)
	in := newIncident(t, "inc_demo")
	h.store.put(in)

	h.pool.dispatch(context.Background(), "c1", msgFor("m1", in.ID, false, 1))

	// The wait is compressed...
	due, ok := h.store.dueTime(in.ID)
	if !ok {
		t.Fatal("no due time was written")
	}
	if !due.Equal(origin.Add(time.Minute)) {
		t.Fatalf("due time = %s, want the hour compressed to %s", due, origin.Add(time.Minute))
	}
	// ...and the decision is not. A ledger showing only the compressed time
	// would misrepresent what the system decided; one showing only the real
	// time would misrepresent what it did, so both are written.
	entry, _ := h.ledger.find(domain.AuditIncidentScheduled)
	if entry.detail["execute_after"] != origin.Add(time.Hour).UTC().Format(time.RFC3339) {
		t.Errorf("audited execute_after = %v, want the real decision %s",
			entry.detail["execute_after"], origin.Add(time.Hour).UTC().Format(time.RFC3339))
	}
	if entry.detail["delay_seconds"] != float64(3600) {
		t.Errorf("audited delay = %v, want the real 3600", entry.detail["delay_seconds"])
	}
	if entry.detail["demo_time_scale"] != scale {
		t.Errorf("audited scale = %v, want %v so a compressed run is never mistaken for a real one",
			entry.detail["demo_time_scale"], scale)
	}
	if entry.detail["demo_execute_after"] != origin.Add(time.Minute).UTC().Format(time.RFC3339) {
		t.Errorf("audited demo_execute_after = %v, want %s",
			entry.detail["demo_execute_after"], origin.Add(time.Minute).UTC().Format(time.RFC3339))
	}
	// The command the gate produced is untouched: compression happens at the
	// point of waiting, never in the decision.
	if got := h.gate.seen(); len(got) != 1 {
		t.Fatalf("gate consulted %d times", len(got))
	}
}

func TestDueAtNeverCollapsesAScheduleIntoNow(t *testing.T) {
	cases := []struct {
		name  string
		scale float64
		after time.Time
		want  time.Time
	}{
		{"no compression returns the command's own deadline", 1, origin.Add(time.Hour), origin.Add(time.Hour)},
		{"a deadline already past is returned unchanged", 60, origin.Add(-time.Minute), origin.Add(-time.Minute)},
		{"ordinary compression", 60, origin.Add(time.Hour), origin.Add(time.Minute)},
		{
			// A floor keeps an aggressive scale from turning a deferred retry
			// into an immediate one, which would stop demonstrating the very
			// thing the deferral exists to demonstrate.
			"an extreme scale is floored at one second", 1e9, origin.Add(time.Hour), origin.Add(time.Second),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config, _ *Deps) { cfg.DemoTimeScale = tc.scale })
			got := h.pool.dueAt(domain.SanitizedCommand{ExecuteAfter: tc.after})
			if !got.Equal(tc.want) {
				t.Fatalf("dueAt = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDefectDemoTimeScaleShortensTheCoolingWindowInWallClock(t *testing.T) {
	requireDefectRun(t, "worker.go:511 executes on the due flag alone and never re-checks "+
		"the ExecuteAfter the gate has just recomputed, so a compressed schedule brings a "+
		"recurring debit back inside its own cooling window; Config.DemoTimeScale's doc at "+
		"worker.go:53-62 states the regulatory floor cannot be configured under")

	// Gatekeeper rule 8 floors a recurring debit's delay at the cooling window
	// measured from the instant of the decision, and it does so on every
	// decision. The stand-in below reproduces exactly that.
	const scale = 3600.0
	const coolingSeconds = 86400
	h := newHarness(t, func(cfg *Config, _ *Deps) { cfg.DemoTimeScale = scale })
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.Action = domain.ActionMandateCascade
		cmd.DelaySeconds = coolingSeconds
		cmd.ExecuteAfter = h.clock.Now().Add(coolingSeconds * time.Second)
		return cmd, nil
	}
	in := newIncident(t, "inc_cooling", recurring("sub_cooling"))
	h.store.put(in)
	ctx := context.Background()

	h.pool.dispatch(ctx, "c1", msgFor("m1", in.ID, false, 1))
	due, ok := h.store.dueTime(in.ID)
	if !ok {
		t.Fatal("the recurring debit was not deferred at all")
	}
	// The compressed schedule falls due twenty-four seconds after the decision.
	h.clock.advance(due.Sub(origin))
	h.pool.sweepDue(ctx)
	h.pool.dispatch(ctx, "c1", msgFor("m2", in.ID, true, 1))

	if retries, _, _ := h.exec.counts(); retries != 0 {
		t.Fatalf("a recurring debit executed %s after the decision, inside the %ds window the "+
			"gate had just recomputed; compression reached the regulatory floor, not only the wait",
			h.clock.Now().Sub(origin), coolingSeconds)
	}
}

func TestDeferSweepExecuteLoopTerminatesUnderTheRunningPool(t *testing.T) {
	// The three moving parts wired together: a delayed decision, the sweeper
	// that brings it back, and the due redelivery that finally executes it.
	h := newHarness(t, func(cfg *Config, _ *Deps) {
		cfg.SweepInterval = 2 * time.Millisecond
		cfg.ReclaimInterval = time.Hour
	})
	h.queue.loopback = true
	h.gate.fn = deferredGate(h, 120*time.Second)
	in := newIncident(t, "inc_e2e")
	h.store.put(in)

	_, stop := runPool(t, h)
	h.queue.seed(msgFor("m1", in.ID, false, 1))
	waitSignal(t, h.store.scheduledC, "the deferral to be written")
	h.clock.advance(121 * time.Second)
	waitSignal(t, h.store.attemptC, "the swept incident to execute")
	stop()

	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts, want exactly 1", got)
	}
	if got := h.ledger.count(domain.AuditIncidentScheduled); got != 1 {
		t.Fatalf("deferred %d times, want 1: the delay must be served once, not recomputed", got)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentRecovered {
		t.Fatalf("state = %s, want %s", incident.State, domain.IncidentRecovered)
	}
	if got := len(h.queue.ackedIDs()); got != 2 {
		t.Errorf("acked %d messages, want the original and the republished one", got)
	}
}

// ---------------------------------------------------------------------------
// degradation
// ---------------------------------------------------------------------------

func TestBreakerOpenSkipsInferenceAndStillTerminates(t *testing.T) {
	// During a confirmed outage the cause is already known, so diagnosing
	// thousands of identical failures individually spends latency and money to
	// rediscover one fact. Skipping must not turn into dropping.
	h := newHarness(t)
	h.breaker.allow = false
	h.breaker.state = domain.BreakerOpen
	in := newIncident(t, "inc_breaker")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	if h.diag.callCount() != 0 {
		t.Fatalf("inference ran %d times with the breaker open", h.diag.callCount())
	}
	if h.counter("worker.inference_skipped") != 1 {
		t.Error("worker.inference_skipped was not counted")
	}
	gates := h.gate.seen()
	if len(gates) != 1 {
		t.Fatalf("gate consulted %d times, want 1: skipping inference must not skip the gate", len(gates))
	}
	prop := gates[0].Proposal
	if prop.Mode != domain.ModeSkipped {
		t.Errorf("proposal mode = %s, want %s", prop.Mode, domain.ModeSkipped)
	}
	if prop.FailureClassification != domain.ClassIssuerOutage || prop.RecommendedAction != domain.ActionAsyncRetry {
		t.Errorf("skipped proposal = %+v, want an issuer-outage async retry", prop)
	}
	// Not degraded: the taxonomy resolved this without inference, so flagging
	// it degraded would misreport a confident answer as a fallback.
	if prop.Degraded {
		t.Error("a skipped proposal was flagged degraded")
	}
	// The breaker snapshot travels to the gate, which is what lets the gate
	// reason about the outage it is deciding inside.
	if gates[0].Telemetry.BreakerState != domain.BreakerOpen {
		t.Errorf("gate saw breaker state %s, want %s", gates[0].Telemetry.BreakerState, domain.BreakerOpen)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); !incident.State.Terminal() {
		t.Errorf("state = %s: the incident must still reach a conclusion", incident.State)
	}
}

func TestAnUnreadableBreakerDoesNotSuppressInference(t *testing.T) {
	// Failing towards more inference is the safe direction here: the cost is
	// money, and the alternative is skipping diagnosis on evidence we do not
	// actually have.
	h := newHarness(t)
	h.breaker.allowErr = errors.New("breaker store unreachable")
	h.breaker.stateErr = errors.New("breaker store unreachable")
	in := newIncident(t, "inc_brkerr")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	if h.diag.callCount() != 1 {
		t.Fatalf("inference ran %d times, want 1", h.diag.callCount())
	}
	// An unreadable breaker still yields a usable snapshot rather than an empty
	// state string, so no downstream rule has to special-case "".
	if got := h.gate.seen()[0].Telemetry.BreakerState; got != domain.BreakerClosed {
		t.Errorf("breaker state = %q, want %s when it cannot be read", got, domain.BreakerClosed)
	}
}

func TestDiagnosisFailureDegradesRatherThanDroppingTheIncident(t *testing.T) {
	cases := []struct {
		name string
		fn   func(dc domain.DiagnosticContext) (domain.DiagnosticProposal, error)
	}{
		{
			"the diagnoser errors",
			func(domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
				return domain.DiagnosticProposal{}, errors.New("inference backend refused the request")
			},
		},
		{
			"the diagnoser times out",
			func(domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
				return domain.DiagnosticProposal{}, context.DeadlineExceeded
			},
		},
		{
			// A partially filled proposal returned alongside an error must not
			// be half-used: the abstain default replaces it wholesale.
			"the diagnoser errors but returns a confident-looking proposal",
			func(dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
				return domain.DiagnosticProposal{
					IncidentID:        dc.IncidentID,
					ConfidenceScore:   1,
					RecommendedAction: domain.ActionRailMorph,
					Mode:              domain.ModeLive,
				}, errors.New("truncated response")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.diag.fn = tc.fn
			in := newIncident(t, "inc_degrade")
			h.store.put(in)

			if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
				t.Fatalf("Handle returned %v, want nil: a failed diagnosis must not drop the incident", err)
			}
			gates := h.gate.seen()
			if len(gates) != 1 {
				t.Fatalf("gate consulted %d times, want 1", len(gates))
			}
			prop := gates[0].Proposal
			if prop.RecommendedAction != domain.ActionAbstain || prop.ConfidenceScore != 0 {
				t.Fatalf("degraded proposal = %+v, want a zero-confidence abstention", prop)
			}
			if prop.Mode != domain.ModeHeuristic || !prop.Degraded {
				t.Fatalf("degraded proposal provenance = mode %s degraded %v, want HEURISTIC/true",
					prop.Mode, prop.Degraded)
			}
			if h.counter("worker.diagnose_failed") != 1 {
				t.Error("worker.diagnose_failed was not counted")
			}
			// No diagnosis entry is written for a failure, so the ledger's
			// first word on this incident is the gate's.
			if _, ok := h.ledger.find(domain.AuditDiagnosis); ok {
				t.Error("a failed diagnosis was audited as a diagnosis")
			}
			if _, ok := h.ledger.find(domain.AuditGateDecision); !ok {
				t.Error("the incident never reached the gate")
			}
			if incident, _ := h.store.snapshotIncident(in.ID); !incident.State.Terminal() {
				t.Errorf("state = %s, want the incident concluded rather than abandoned", incident.State)
			}
		})
	}
}

func TestAMalformedProposalStillReachesTheGate(t *testing.T) {
	// The proposal is advisory, so a malformed one is not an error condition
	// for this package: it must still be carried to the gate, which is the
	// component with the authority to discard it.
	h := newHarness(t)
	h.diag.fn = func(dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
		return domain.DiagnosticProposal{
			IncidentID:            dc.IncidentID,
			FailureClassification: domain.FailureClass("SOLAR_FLARE"),
			RecommendedAction:     domain.Action("TRANSFER_TO_MY_ACCOUNT"),
			SuggestedFallbackRail: domain.Rail("wire"),
			ConfidenceScore:       0.99,
			RecommendedDelaySec:   -5,
			Mode:                  domain.ModeLive,
		}, nil
	}
	in := newIncident(t, "inc_malformed")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	gates := h.gate.seen()
	if len(gates) != 1 {
		t.Fatalf("gate consulted %d times, want 1", len(gates))
	}
	if got := gates[0].Proposal.RecommendedAction; got != domain.Action("TRANSFER_TO_MY_ACCOUNT") {
		t.Fatalf("the worker rewrote the proposal to %q; sanitising is the gate's job, not this package's", got)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); !incident.State.Terminal() {
		t.Errorf("state = %s, want the incident concluded", incident.State)
	}
}

func TestAnExhaustedRetryBudgetStopsExecutionObservably(t *testing.T) {
	// Per-incident stop rules bound one lifecycle. Only a global budget bounds
	// aggregate load during a mass outage, which is exactly when every incident
	// wants to retry at once.
	h := newHarness(t, func(cfg *Config, _ *Deps) { cfg.RetryBudgetPerMinute = 1 })
	first := newIncident(t, "inc_budget_a")
	second := newIncident(t, "inc_budget_b")
	h.store.put(first)
	h.store.put(second)
	ctx := context.Background()

	if err := h.pool.Handle(ctx, msgFor("m1", first.ID, false, 1)); err != nil {
		t.Fatalf("the first incident inside budget returned %v", err)
	}
	err := h.pool.Handle(ctx, msgFor("m2", second.ID, false, 1))
	if err == nil {
		t.Fatal("the second incident executed with the budget exhausted")
	}
	if !strings.Contains(err.Error(), "retry budget exhausted") {
		t.Fatalf("error %q does not name the budget", err)
	}
	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("executor ran %d times against a budget of 1", retries)
	}
	if h.counter("worker.budget_exhausted") != 1 {
		t.Error("worker.budget_exhausted was not counted")
	}
	// The budget check precedes the attempt-started entry, so the ledger never
	// claims an attempt that was not made.
	if got := h.ledger.count(domain.AuditAttemptStarted); got != 1 {
		t.Errorf("%d attempts were audited as started, want 1", got)
	}
	// Deferred rather than dropped: the message is left unacked so redelivery
	// brings the work back once the window rolls.
	h.pool.dispatch(ctx, "c1", msgFor("m2", second.ID, false, 1))
	if got := h.queue.ackedIDs(); len(got) != 0 {
		t.Errorf("acked %v; a budget-blocked incident must stay on the queue", got)
	}

	h.clock.advance(time.Minute)
	if err := h.pool.Handle(ctx, msgFor("m2", second.ID, false, 1)); err != nil {
		t.Fatalf("the incident did not resume in the next window: %v", err)
	}
	if retries, _, _ := h.exec.counts(); retries != 2 {
		t.Fatalf("executor ran %d times after the window rolled, want 2", retries)
	}
}

func TestALostAttemptRecordDoesNotUndoACompletedAttempt(t *testing.T) {
	// The money has already moved. Failing the incident because the bookkeeping
	// write failed would send it round again and spend it twice.
	h := newHarness(t)
	h.store.attemptErr = errors.New("attempts table is unavailable")
	h.tel.writeErr = errors.New("telemetry is unavailable")
	h.breaker.reportErr = errors.New("breaker is unavailable")
	in := newIncident(t, "inc_lostrec")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v after an observation failure, want nil", err)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentRecovered {
		t.Errorf("state = %s, want the completed attempt to stand", incident.State)
	}
	if _, ok := h.ledger.find(domain.AuditAttemptResult); !ok {
		t.Error("the attempt result was not audited")
	}
}

func TestATransportFailureRecordsTheAttemptAndLeavesTheIncidentOpen(t *testing.T) {
	// An attempt that was made but not recorded is money the benchmark cannot
	// see, so the record is written even when the call itself failed.
	h := newHarness(t)
	h.exec.retryErr = errors.New("gateway connection reset")
	in := newIncident(t, "inc_transport")
	h.store.put(in)

	err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1))
	if err == nil {
		t.Fatal("Handle returned nil after a transport failure")
	}
	attempts := h.store.recordedAttempts()
	if len(attempts) != 1 || attempts[0].Succeeded {
		t.Fatalf("recorded attempts = %+v, want one failed attempt", attempts)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State.Terminal() {
		t.Errorf("state = %s: a transport failure must leave the incident open", incident.State)
	}
	if got := h.breaker.reported(); len(got) != 1 || got[0] {
		t.Errorf("breaker reports = %v, want one failure", got)
	}
}

func TestDefectAFailedAttemptWithBudgetRemainingIsRearmed(t *testing.T) {
	requireDefectRun(t, "worker.go:592-598 marks the incident SCHEDULED without writing a "+
		"due time and then acks the message, so nothing ever brings the next attempt back")

	// The gate declares three attempts. The first fails cleanly, which is the
	// ordinary case, and the incident is left non-terminal on the promise that
	// another attempt is coming. ClaimDueIncidents only sees rows with a due
	// time, so unless one is written here the promise is never kept: the
	// incident sits SCHEDULED with no schedule and no queue message, which is
	// exactly the failure store/schedule.go:88-92 warns about.
	h := newHarness(t)
	h.exec.succeed = false
	in := newIncident(t, "inc_rearm")
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	incident, _ := h.store.snapshotIncident(in.ID)
	if incident.State != domain.IncidentScheduled {
		t.Fatalf("state = %s, want %s", incident.State, domain.IncidentScheduled)
	}
	if _, ok := h.store.dueTime(in.ID); !ok {
		t.Fatal("the incident is SCHEDULED with no due time: no sweeper will ever claim it")
	}
}

// ---------------------------------------------------------------------------
// pre-debit notice
// ---------------------------------------------------------------------------

func TestAPreDebitNoticeFailureAbortsTheDebit(t *testing.T) {
	// Believing we notified when we did not is the precise condition the rule
	// exists to prevent, so the notice is sent first and its failure is fatal
	// to the attempt.
	h := newHarness(t)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.Action = domain.ActionMandateCascade
		cmd.PreDebitNotificationNeeded = true
		return cmd, nil
	}
	h.exec.notifyErr = errors.New("comms provider rejected the message")
	in := newIncident(t, "inc_notice", recurring("sub_1"))
	h.store.put(in)

	err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1))
	if err == nil {
		t.Fatal("the debit proceeded after the notice failed")
	}
	if retries, morphs, _ := h.exec.counts(); retries != 0 || morphs != 0 {
		t.Fatalf("executor ran (%d/%d) after a failed pre-debit notice", retries, morphs)
	}
	if got := len(h.store.recordedAttempts()); got != 0 {
		t.Fatalf("recorded %d attempts after a failed notice", got)
	}
	if _, ok := h.ledger.find(domain.AuditPreDebitNotice); ok {
		t.Error("a notice that was not delivered was audited as delivered")
	}
}

func TestAPreDebitNoticeIsAuditedWithTheDebitDeadline(t *testing.T) {
	h := newHarness(t)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.Action = domain.ActionMandateCascade
		cmd.PreDebitNotificationNeeded = true
		cmd.ExecuteAfter = origin.Add(24 * time.Hour)
		return cmd, nil
	}
	in := newIncident(t, "inc_notice_ok", recurring("sub_2"))
	h.store.mandates["sub_2"] = domain.MandateRecord{SubscriptionID: "sub_2", Category: domain.CategoryGeneral}
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	if _, _, notices := h.exec.counts(); notices != 1 {
		t.Fatalf("sent %d notices, want 1", notices)
	}
	entry, ok := h.ledger.find(domain.AuditPreDebitNotice)
	if !ok {
		t.Fatal("the notice was not audited")
	}
	if entry.detail["debit_after"] != origin.Add(24*time.Hour).UTC().Format(time.RFC3339) {
		t.Errorf("audited debit_after = %v, want the command's own deadline", entry.detail["debit_after"])
	}
	// The mandate row really was read and handed to the gate: the compliance
	// rules are evaluated against durable state, not an in-memory counter.
	if got := h.gate.seen()[0].Mandate; got == nil || got.SubscriptionID != "sub_2" {
		t.Fatalf("gate saw mandate %+v, want the stored record", got)
	}
}

func TestDefectAPreDebitNoticeIsNotRecordedSoItIsSentAgain(t *testing.T) {
	requireDefectRun(t, "worker.go:494-501 delivers the notice but never persists "+
		"PreDebitNotifiedAt, so gatekeeper.go:632-643 can never see one on record")

	// A recurring incident is deferred behind the cooling window, and the
	// notice is delivered at that moment. When the sweeper brings it back the
	// notice obligation is asserted again and a second message goes to the
	// customer for one debit. The simulator persists the notice
	// (simulation/sim.go:1218-1240); the production worker does not, so the
	// mandate's AttemptsInCycle and NextEligibleAt never advance either and
	// the cycle cap can never fire through this path.
	h := newHarness(t)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		cmd := executableCommand(in)
		cmd.Action = domain.ActionMandateCascade
		cmd.PreDebitNotificationNeeded = in.Mandate == nil || in.Mandate.PreDebitNotifiedAt == nil
		cmd.DelaySeconds = 86400
		cmd.ExecuteAfter = h.clock.Now().Add(24 * time.Hour)
		return cmd, nil
	}
	in := newIncident(t, "inc_notice_dup", recurring("sub_3"))
	h.store.mandates["sub_3"] = domain.MandateRecord{SubscriptionID: "sub_3", Category: domain.CategoryGeneral}
	h.store.put(in)
	ctx := context.Background()

	h.pool.dispatch(ctx, "c1", msgFor("m1", in.ID, false, 1))
	h.clock.advance(24 * time.Hour)
	h.pool.dispatch(ctx, "c1", msgFor("m2", in.ID, true, 1))

	if _, _, notices := h.exec.counts(); notices != 1 {
		t.Fatalf("the customer received %d pre-debit notices for one debit, want 1", notices)
	}
}

// ---------------------------------------------------------------------------
// failure isolation
// ---------------------------------------------------------------------------

func TestAPanicInAnyCollaboratorIsContainedAndParked(t *testing.T) {
	cases := []struct {
		name string
		bomb func(h *harness)
	}{
		{"the store panics", func(h *harness) { h.store.panicOnGet = true }},
		{"the gatekeeper panics", func(h *harness) { h.gate.panics = true }},
		{"the executor panics", func(h *harness) { h.exec.panics = true }},
		{"the diagnoser panics", func(h *harness) {
			h.diag.fn = func(domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
				panic("fakeDiagnoser: the inference client exploded")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			in := newIncident(t, "inc_panic")
			h.store.put(in)
			tc.bomb(h)

			h.pool.dispatch(context.Background(), "c1", msgFor("boom", in.ID, false, 1))

			parkedMsgs := h.dead.all()
			if len(parkedMsgs) != 1 {
				t.Fatalf("dead-lettered %d messages, want 1", len(parkedMsgs))
			}
			if !strings.HasPrefix(parkedMsgs[0].cause, "panic:") {
				t.Errorf("cause = %q, want it to name the panic so the crash becomes a bug report",
					parkedMsgs[0].cause)
			}
			if parkedMsgs[0].msg.ID != "boom" {
				t.Errorf("parked message id = %q, want the failing message", parkedMsgs[0].msg.ID)
			}
			if _, ok := h.ledger.find(domain.AuditDeadLettered); !ok {
				t.Error("the parked message was not audited")
			}
			if h.counter("worker.panic") != 1 {
				t.Error("worker.panic was not counted")
			}
			// A poisoned message must not be acked: parking it is what removes
			// it from circulation, and acking as well would hide a bug in the
			// dead-letter path.
			if got := h.queue.ackedIDs(); len(got) != 0 {
				t.Errorf("acked %v after a panic", got)
			}

			// The pool keeps working: one malformed payload must not stop
			// every other recovery in flight.
			h2 := newHarness(t)
			healthy := newIncident(t, "inc_healthy")
			h2.store.put(healthy)
			h2.pool.dispatch(context.Background(), "c2", msgFor("ok", healthy.ID, false, 1))
			if retries, _, _ := h2.exec.counts(); retries != 1 {
				t.Errorf("a healthy message after a panic executed %d times, want 1", retries)
			}
		})
	}
}

func TestTheConsumerKeepsProcessingAfterAPanic(t *testing.T) {
	// The panic is recovered inside dispatch, so the consumer goroutine that
	// called it survives and takes the next message off the same queue.
	h := newHarness(t)
	poison := newIncident(t, "inc_poison")
	healthy := newIncident(t, "inc_after")
	h.store.put(poison)
	h.store.put(healthy)
	h.gate.fn = func(in domain.GateInput) (domain.SanitizedCommand, error) {
		if in.IncidentID == poison.ID {
			panic("fakeGate: exploded on one incident only")
		}
		return executableCommand(in), nil
	}

	_, stop := runPool(t, h)
	h.queue.seed(msgFor("boom", poison.ID, false, 1), msgFor("ok", healthy.ID, false, 1))
	waitSignal(t, h.store.attemptC, "the message after the poison one to execute")
	stop()

	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts, want 1 from the healthy message", got)
	}
	if got := len(h.dead.all()); got != 1 {
		t.Fatalf("dead-lettered %d messages, want 1", got)
	}
}

func TestADeadLetterFailureDoesNotStopThePool(t *testing.T) {
	// The dead-letter stream is itself a dependency and can be down. Losing the
	// parked copy is bad; losing the consumer that would have parked the next
	// hundred messages is worse.
	h := newHarness(t)
	h.dead.err = errors.New("dead-letter stream is unavailable")
	h.gate.panics = true
	in := newIncident(t, "inc_dlq_down")
	h.store.put(in)

	h.pool.dispatch(context.Background(), "c1", msgFor("boom", in.ID, false, 1))

	if got := len(h.dead.all()); got != 0 {
		t.Fatalf("parked %d messages with the stream down", got)
	}
	if _, ok := h.ledger.find(domain.AuditDeadLettered); ok {
		t.Error("a message that was not parked was audited as parked")
	}
	// The pool is intact: the next message runs the whole pipeline.
	h.gate.panics = false
	next := newIncident(t, "inc_after_dlq")
	h.store.put(next)
	h.pool.dispatch(context.Background(), "c1", msgFor("ok", next.ID, false, 1))
	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("the next message executed %d times, want 1", retries)
	}
}

func TestAnAbsentDeadLetterStreamIsNotAnError(t *testing.T) {
	// DeadLetter is optional in Deps, so a deployment without one must degrade
	// to "drop the poison message" rather than to a nil dereference.
	h := newHarness(t, func(_ *Config, deps *Deps) { deps.DeadLetter = nil })
	h.gate.panics = true
	in := newIncident(t, "inc_no_dlq")
	h.store.put(in)
	h.pool.dispatch(context.Background(), "c1", msgFor("boom", in.ID, false, 1))
	if _, ok := h.ledger.find(domain.AuditDeadLettered); ok {
		t.Error("a message was audited as parked with no dead-letter stream configured")
	}
}

func TestDefectAPanickingDeadLetterPathEscapesTheConsumer(t *testing.T) {
	requireDefectRun(t, "worker.go:270 calls park inside the deferred recover, so a panic "+
		"raised by the DeadLetterer is no longer covered by any recover and unwinds the "+
		"consumer goroutine, taking the process with it")

	// An error from the dead-letter path is handled (see the test above); a
	// panic from it is not. The two failure modes are equally plausible for a
	// network client and the pool survives only one of them.
	h := newHarness(t)
	h.dead.panics = true
	h.gate.panics = true
	in := newIncident(t, "inc_dlq_panic")
	h.store.put(in)

	escaped := func() (rec any) {
		defer func() { rec = recover() }()
		h.pool.dispatch(context.Background(), "c1", msgFor("boom", in.ID, false, 1))
		return nil
	}()
	if escaped != nil {
		t.Fatalf("a panic escaped dispatch: %v", escaped)
	}
}

func TestPoisonMessagesAreParkedWithoutRunningThePipeline(t *testing.T) {
	// Past the delivery ceiling the message is poison. Running the pipeline
	// once more would spend another inference call and another gateway fee to
	// reach the same failure.
	h := newHarness(t)
	in := newIncident(t, "inc_poison_ceiling")
	h.store.put(in)

	h.pool.dispatch(context.Background(), "c1", msgFor("m1", in.ID, false, h.cfg.MaxDeliveries+1))

	if h.diag.callCount() != 0 || len(h.gate.seen()) != 0 {
		t.Fatalf("the pipeline ran for a poison message: %d diagnoses, %d gate calls",
			h.diag.callCount(), len(h.gate.seen()))
	}
	parkedMsgs := h.dead.all()
	if len(parkedMsgs) != 1 {
		t.Fatalf("parked %d messages, want 1", len(parkedMsgs))
	}
	if !strings.Contains(parkedMsgs[0].cause, fmt.Sprintf("exceeded %d deliveries", h.cfg.MaxDeliveries)) {
		t.Errorf("cause = %q, want it to name the delivery ceiling", parkedMsgs[0].cause)
	}
	if h.counter("worker.poison") != 1 {
		t.Error("worker.poison was not counted")
	}

	// One delivery below the ceiling is still ordinary work.
	h2 := newHarness(t)
	ok := newIncident(t, "inc_at_ceiling")
	h2.store.put(ok)
	h2.pool.dispatch(context.Background(), "c1", msgFor("m1", ok.ID, false, h2.cfg.MaxDeliveries))
	if retries, _, _ := h2.exec.counts(); retries != 1 {
		t.Fatalf("a message at the ceiling executed %d times, want 1", retries)
	}
}

func TestAnUnreadableQueuePayloadIsAPermanentFailure(t *testing.T) {
	// A payload this process wrote and cannot now read is poison, not a
	// transient fault, so it must not be acked into silence.
	h := newHarness(t)
	msg := domain.QueueMessage{ID: "m1", IncidentID: "inc_x", Payload: []byte("{not json")}
	err := h.pool.Handle(context.Background(), msg)
	if err == nil {
		t.Fatal("Handle accepted an unreadable payload")
	}
	if !strings.Contains(err.Error(), "unreadable queue payload") {
		t.Fatalf("error %q does not name the payload", err)
	}
	h.pool.dispatch(context.Background(), "c1", msg)
	if got := h.queue.ackedIDs(); len(got) != 0 {
		t.Errorf("acked %v; an unreadable payload must reach the dead-letter path instead", got)
	}
	if h.counter("worker.handle_failed") != 1 {
		t.Error("worker.handle_failed was not counted")
	}
}

func TestAMessageWithNoPayloadIncidentIDFallsBackToTheEnvelope(t *testing.T) {
	// Two producers write this stream and only one of them fills the body, so
	// the envelope is the fallback rather than a reason to fail.
	h := newHarness(t)
	in := newIncident(t, "inc_envelope")
	h.store.put(in)
	msg := domain.QueueMessage{ID: "m1", IncidentID: in.ID, Payload: []byte(`{}`)}
	if err := h.pool.Handle(context.Background(), msg); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("executor ran %d times, want 1", retries)
	}
}

func TestAVanishedIncidentIsAckedRatherThanRetriedForever(t *testing.T) {
	h := newHarness(t)
	msg := msgFor("m1", "inc_gone", false, 1)
	if err := h.pool.Handle(context.Background(), msg); err != nil {
		t.Fatalf("Handle returned %v, want nil: there is nothing to recover", err)
	}
	h.pool.dispatch(context.Background(), "c1", msg)
	if got := h.queue.ackedIDs(); len(got) != 1 {
		t.Fatalf("acked %v, want the message removed from circulation", got)
	}
}

func TestAStoreFailureIsTransientAndKeepsTheMessage(t *testing.T) {
	// Not-found is a conclusion; anything else is an outage, and an outage must
	// not be mistaken for a conclusion.
	h := newHarness(t)
	h.store.getErr = errors.New("connection pool exhausted")
	msg := msgFor("m1", "inc_any", false, 1)
	if err := h.pool.Handle(context.Background(), msg); err == nil {
		t.Fatal("a store outage was treated as a missing incident")
	}
	h.pool.dispatch(context.Background(), "c1", msg)
	if got := h.queue.ackedIDs(); len(got) != 0 {
		t.Errorf("acked %v during a store outage", got)
	}
}

// ---------------------------------------------------------------------------
// session liveness
// ---------------------------------------------------------------------------

func TestSessionLivenessFailsClosed(t *testing.T) {
	// The worst case of a false negative is an unnecessary async retry. The
	// worst case of a false positive is a morph published into a session
	// nobody is watching, which is a customer who sees nothing happen.
	live := domain.SessionRecord{
		ID: "sess_1", OrderID: "order_inc_sess", Active: true,
		ExpiresAt: origin.Add(10 * time.Minute), CurrentRail: domain.RailCard,
	}
	cases := []struct {
		name  string
		setup func(h *harness)
		want  bool
	}{
		{"an attached live session", func(h *harness) {
			h.store.sessions["order_inc_sess"] = live
			h.hub.active["sess_1"] = true
		}, true},
		{"no session row at all", func(*harness) {}, false},
		{
			// Liveness that cannot be determined is liveness we do not have.
			// The cost of being wrong the other way is a morph published into
			// a session nobody is watching.
			"the session lookup fails", func(h *harness) {
				h.store.sessions["order_inc_sess"] = live
				h.hub.active["sess_1"] = true
				h.store.sessionErr = errors.New("sessions table is unavailable")
			}, false,
		},
		{"an expired session", func(h *harness) {
			expired := live
			expired.ExpiresAt = origin.Add(-time.Second)
			h.store.sessions["order_inc_sess"] = expired
			h.hub.active["sess_1"] = true
		}, false},
		{"a closed session", func(h *harness) {
			closed := live
			closed.Active = false
			h.store.sessions["order_inc_sess"] = closed
			h.hub.active["sess_1"] = true
		}, false},
		{"the row says live but the customer closed the tab", func(h *harness) {
			h.store.sessions["order_inc_sess"] = live
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			in := newIncident(t, "inc_sess")
			h.store.put(in)
			tc.setup(h)

			if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
				t.Fatalf("Handle returned %v, want nil", err)
			}
			if got := h.gate.seen()[0].SessionActive; got != tc.want {
				t.Fatalf("gate saw SessionActive = %v, want %v", got, tc.want)
			}
			dc, ok := h.diag.lastContext()
			if !ok {
				t.Fatal("the diagnoser was never called")
			}
			if dc.SessionActive != tc.want {
				t.Fatalf("the diagnostic context said SessionActive = %v, want %v", dc.SessionActive, tc.want)
			}
		})
	}
}

func TestAnIncidentWithNoOrderIsNeverTreatedAsInSession(t *testing.T) {
	h := newHarness(t)
	in := newIncident(t, "inc_noorder", func(_ *domain.Incident, pay *domain.PaymentEntity) {
		pay.OrderID = ""
	})
	h.store.put(in)
	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	if h.gate.seen()[0].SessionActive {
		t.Fatal("an incident with no order was reported as in-session")
	}
}

// ---------------------------------------------------------------------------
// diagnostic context
// ---------------------------------------------------------------------------

func TestTheDiagnosticContextCarriesOnlySanitisedEvidence(t *testing.T) {
	// The context struct is the allowlist that keeps cardholder data out of a
	// prompt. What this package owns is filling it correctly: bucketed amount,
	// the verified error fields, the ambient signals and nothing else.
	h := newHarness(t, func(_ *Config, deps *Deps) {
		deps.DowntimeSignals = func(issuerKey string) []domain.DowntimeSignal {
			return []domain.DowntimeSignal{{TelemetryKey: issuerKey, MatchesIssuer: true, Severity: domain.SeverityHigh}}
		}
	})
	h.tel.snap = domain.TelemetrySnapshot{Attempts: 40, Successes: 8, SuccessRate: 0.2, BaselineRate: 0.9}
	in := newIncident(t, "inc_ctx", func(_ *domain.Incident, pay *domain.PaymentEntity) {
		pay.VPA = "customer@okhdfcbank" // present in the payload, absent from the context
	})
	h.store.put(in)

	if err := h.pool.Handle(context.Background(), msgFor("m1", in.ID, false, 1)); err != nil {
		t.Fatalf("Handle returned %v, want nil", err)
	}
	dc, ok := h.diag.lastContext()
	if !ok {
		t.Fatal("the diagnoser was never called")
	}
	if dc.AmountBand != domain.AmountBand(250000) || dc.AmountBand == "" {
		t.Errorf("amount band = %q, want the bucketed form rather than a value", dc.AmountBand)
	}
	if dc.ErrorCode != "bank_technical_error" || dc.ErrorSource != "bank" || dc.ErrorStep != "authorization" {
		t.Errorf("failure signal = %+v, want the fields from the verified payload", dc)
	}
	if dc.IssuerKey != "card:HDFC" || dc.Method != "card" {
		t.Errorf("instrument shape = %s/%s, want card:HDFC/card", dc.IssuerKey, dc.Method)
	}
	if len(dc.Downtimes) != 1 || !dc.Downtimes[0].MatchesIssuer {
		t.Errorf("downtime signals = %+v, want the matching notice", dc.Downtimes)
	}
	if dc.Telemetry.SuccessRate != 0.2 || dc.Telemetry.BreakerState != domain.BreakerClosed {
		t.Errorf("telemetry = %+v, want the snapshot with its breaker state filled in", dc.Telemetry)
	}
	if !dc.ObservedAt.Equal(origin) {
		t.Errorf("observed at = %s, want the injected clock reading", dc.ObservedAt)
	}
	if len(dc.AvailableRails) != 3 {
		t.Errorf("available rails = %v, want the merchant's configured set", dc.AvailableRails)
	}
	// The struct has no field that could carry it, and that is the point: the
	// check documents the property rather than defending it.
	raw, err := json.Marshal(dc)
	if err != nil {
		t.Fatalf("marshalling the context: %v", err)
	}
	if strings.Contains(string(raw), "okhdfcbank") {
		t.Fatal("the diagnostic context carried the VPA from the payload")
	}
}

// ---------------------------------------------------------------------------
// shutdown and reclaim
// ---------------------------------------------------------------------------

func TestCancellationDoesNotAbandonAnInFlightMessage(t *testing.T) {
	// The context is cancelled while the executor is mid-call. The pool must
	// finish the message it already took rather than dropping it, because the
	// outbound call has already happened and the record of it has not.
	h := newHarness(t)
	h.exec.entered = make(chan struct{})
	h.exec.release = make(chan struct{})
	in := newIncident(t, "inc_shutdown")
	h.store.put(in)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.pool.Run(ctx); err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	}()
	h.queue.seed(msgFor("m1", in.ID, false, 1))
	waitSignal(t, h.exec.entered, "the executor to be entered")

	cancel()
	close(h.exec.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the pool did not stop after cancellation")
	}

	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts, want the in-flight one completed", got)
	}
	if incident, _ := h.store.snapshotIncident(in.ID); incident.State != domain.IncidentRecovered {
		t.Fatalf("state = %s, want the in-flight message concluded", incident.State)
	}
	if got := h.queue.ackedIDs(); len(got) != 1 {
		t.Errorf("acked %v, want the completed message acknowledged", got)
	}
	if _, ok := h.ledger.find(domain.AuditAttemptResult); !ok {
		t.Error("the completed attempt was not audited")
	}
}

func TestAConsumeFailureIsRetriedRatherThanFatal(t *testing.T) {
	// A queue that blips must not silently retire a consumer: the pool would
	// keep reporting healthy on a shrinking number of workers.
	h := newHarness(t)
	h.queue.consumeErrs = []error{errors.New("stream read failed")}
	in := newIncident(t, "inc_consume_err")
	h.store.put(in)

	_, stop := runPool(t, h)
	h.queue.seed(msgFor("m1", in.ID, false, 1))
	waitSignal(t, h.store.attemptC, "the consumer to recover and take the message")
	stop()

	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts, want 1", got)
	}
}

func TestTheReclaimLoopHandlesAStalledMessageExactlyOnce(t *testing.T) {
	h := newHarness(t, func(cfg *Config, _ *Deps) {
		cfg.ReclaimInterval = time.Millisecond
		cfg.SweepInterval = time.Hour
	})
	in := newIncident(t, "inc_stalled")
	h.store.put(in)
	h.queue.reclaims = [][]domain.QueueMessage{{msgFor("stalled", in.ID, false, 2)}}

	_, stop := runPool(t, h)
	waitSignal(t, h.store.attemptC, "the reclaimed message to be handled")
	stop()

	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts for one reclaimed message, want 1", got)
	}
	if got := h.queue.ackedIDs(); len(got) != 1 || got[0] != "stalled" {
		t.Fatalf("acked %v, want the reclaimed message acknowledged once", got)
	}
	if h.counter("worker.reclaimed") != 1 {
		t.Error("worker.reclaimed was not counted")
	}
}

func TestAReclaimOfAMessageAlreadyHandledDoesNotExecuteAgain(t *testing.T) {
	// A message is reclaimed when it looks stalled, which includes the case
	// where the original consumer finished the work and died before acking.
	h := newHarness(t)
	in := newIncident(t, "inc_reclaim_dup")
	h.store.put(in)
	ctx := context.Background()

	h.pool.dispatch(ctx, "worker-0", msgFor("m1", in.ID, false, 1))
	h.pool.dispatch(ctx, "reclaimer", msgFor("m1", in.ID, false, 2))

	if retries, _, _ := h.exec.counts(); retries != 1 {
		t.Fatalf("executor ran %d times across a handle and a reclaim, want 1", retries)
	}
	if got := len(h.store.recordedAttempts()); got != 1 {
		t.Fatalf("recorded %d attempts, want 1", got)
	}
}

func TestAReclaimFailureDoesNotStopTheLoop(t *testing.T) {
	h := newHarness(t, func(cfg *Config, _ *Deps) {
		cfg.ReclaimInterval = time.Millisecond
		cfg.SweepInterval = time.Hour
	})
	h.queue.reclaimErr = errors.New("reclaim failed")
	_, stop := runPool(t, h)
	// Two ticks observed through the fake is proof the loop survived the first
	// failure rather than returning.
	waitSignals(t, h.queue.reclaimC, 2, "two reclaim attempts")
	stop()
}

func TestASweepFailureDoesNotStopTheLoop(t *testing.T) {
	h := newHarness(t, func(cfg *Config, _ *Deps) {
		cfg.SweepInterval = time.Millisecond
		cfg.ReclaimInterval = time.Hour
	})
	h.store.claimErr = errors.New("claim failed")
	_, stop := runPool(t, h)
	deadline := time.After(10 * time.Second)
	for {
		h.store.mu.Lock()
		calls := h.store.claimCalls
		h.store.mu.Unlock()
		if calls >= 2 {
			break
		}
		select {
		case <-deadline:
			stop()
			t.Fatal("the sweep loop stopped after its first failure")
		default:
			runtime.Gosched()
		}
	}
	stop()
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

func TestAPoolOfConsumersAbsorbsABurstAndItsRedeliveries(t *testing.T) {
	// The burst is delivered once per incident, then delivered again after the
	// first pass has concluded. That second pass is what at-least-once delivery
	// looks like in production, and every one of those messages must be a
	// no-op.
	const n = 60
	h := newHarness(t, func(cfg *Config, _ *Deps) {
		cfg.Concurrency = 8
		cfg.BatchSize = 4
		cfg.SweepInterval = time.Hour
		cfg.ReclaimInterval = time.Hour
	})
	msgs := make([]domain.QueueMessage, 0, n)
	for i := 0; i < n; i++ {
		in := newIncident(t, fmt.Sprintf("inc_burst_%02d", i))
		h.store.put(in)
		msgs = append(msgs, msgFor(fmt.Sprintf("m%02d", i), in.ID, false, 1))
	}

	_, stop := runPool(t, h)
	h.queue.seed(msgs...)
	waitSignals(t, h.store.attemptC, n, "every incident in the burst to execute")
	waitSignals(t, h.queue.ackC, n, "every message in the burst to be acked")

	h.queue.seed(msgs...)
	waitSignals(t, h.queue.ackC, n, "every redelivery to be acked")
	stop()

	attempts := h.store.recordedAttempts()
	if len(attempts) != n {
		t.Fatalf("recorded %d attempts for %d incidents delivered twice each, want %d",
			len(attempts), n, n)
	}
	seen := map[string]int{}
	for _, a := range attempts {
		seen[a.IncidentID]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("incident %s was executed %d times", id, count)
		}
	}
	if len(seen) != n {
		t.Fatalf("%d distinct incidents were executed, want %d", len(seen), n)
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("inc_burst_%02d", i)
		incident, ok := h.store.snapshotIncident(id)
		if !ok || incident.State != domain.IncidentRecovered {
			t.Fatalf("incident %s finished in state %s, want %s", id, incident.State, domain.IncidentRecovered)
		}
	}
	if h.counter("worker.recovered") != n {
		t.Errorf("worker.recovered = %d, want %d", h.counter("worker.recovered"), n)
	}
}

func TestConcurrentSweepAndConsumeShareTheRetryBudgetSafely(t *testing.T) {
	// The budget is the one piece of mutable state the pool shares across
	// consumers, so it is worth its own concurrent exercise: an unlocked
	// window roll would let the whole pool overspend at the top of a minute.
	h := newHarness(t, func(cfg *Config, _ *Deps) { cfg.RetryBudgetPerMinute = 25 })
	var wg sync.WaitGroup
	granted := make(chan bool, 200)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				granted <- h.pool.spendRetryBudget()
			}
		}()
	}
	wg.Wait()
	close(granted)
	allowed := 0
	for ok := range granted {
		if ok {
			allowed++
		}
	}
	if allowed != 25 {
		t.Fatalf("the budget granted %d of 200 requests, want exactly 25", allowed)
	}
	h.clock.advance(time.Minute)
	if !h.pool.spendRetryBudget() {
		t.Fatal("the budget did not reset when the window rolled")
	}
}

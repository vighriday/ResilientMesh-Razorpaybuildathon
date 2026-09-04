// Package worker runs the recovery pipeline: consume, diagnose, gate, execute,
// record.
//
// The ordering encodes the trust boundary. Diagnosis is advisory and may be
// skipped entirely; the gatekeeper is authoritative and never is. Nothing
// between the queue and the executor is permitted to change an amount or a
// compliance verdict.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/queue"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// Config tunes the pool.
type Config struct {
	// Concurrency is the number of consumers. Each gets its own consumer name
	// so the group can partition work and so a stalled consumer's pending
	// entries are attributable.
	Concurrency int
	// Group is the consumer group name.
	Group string
	// BatchSize bounds one read.
	BatchSize int
	// ReadBlock is how long a consumer parks waiting for work.
	ReadBlock time.Duration
	// ReclaimInterval is how often stranded messages are swept up.
	ReclaimInterval time.Duration
	// ReclaimMinIdle is how long a message must be unacknowledged before
	// another consumer may take it.
	ReclaimMinIdle time.Duration
	// MaxDeliveries is the redelivery ceiling. Past it a message is poison and
	// goes to the dead-letter stream rather than cycling forever and starving
	// healthy work.
	MaxDeliveries int
	// SessionTTL bounds how long a session is considered live for in-session
	// healing.
	SessionTTL time.Duration
	// RetryBudgetPerMinute caps total outbound attempts across all incidents.
	// Per-incident stop rules bound one lifecycle; only a global budget bounds
	// aggregate load during a mass outage, which is exactly when every incident
	// wants to retry at once.
	RetryBudgetPerMinute int
}

func (c Config) withDefaults() Config {
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.Group == "" {
		c.Group = queue.GroupWorkers
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 16
	}
	if c.ReadBlock <= 0 {
		c.ReadBlock = 2 * time.Second
	}
	if c.ReclaimInterval <= 0 {
		c.ReclaimInterval = 30 * time.Second
	}
	if c.ReclaimMinIdle <= 0 {
		c.ReclaimMinIdle = 60 * time.Second
	}
	if c.MaxDeliveries <= 0 {
		c.MaxDeliveries = 5
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 15 * time.Minute
	}
	if c.RetryBudgetPerMinute <= 0 {
		c.RetryBudgetPerMinute = 600
	}
	return c
}

// DeadLetterer is the subset of the queue used to park poison messages. It is
// separate from domain.Queue because dead-lettering is an implementation
// concern of the Redis queue rather than part of the port every consumer needs.
type DeadLetterer interface {
	DeadLetter(ctx context.Context, group string, msg domain.QueueMessage, cause string) error
}

// Deps are the collaborators the pipeline needs.
type Deps struct {
	Store      domain.Store
	Queue      domain.Queue
	DeadLetter DeadLetterer
	Diagnoser  domain.Diagnoser
	Gatekeeper domain.Gatekeeper
	Policy     domain.PolicyEngine
	Telemetry  domain.TelemetryRecorder
	Breaker    domain.Breaker
	Downtime   domain.DowntimeSource
	Executor   domain.Executor
	Ledger     domain.AuditLedger
	Hub        domain.SessionHub
	Clock      domain.Clock
	Log        *slog.Logger
	Metrics    *obs.Registry
	// AvailableRails is the merchant's enabled rail set. The gatekeeper will
	// not permit a morph onto anything outside it.
	AvailableRails []domain.Rail
	// DowntimeSignals renders the flattened downtime view for a given issuer.
	// It is a function rather than a method so the simulator can substitute a
	// deterministic view without implementing the whole poller.
	DowntimeSignals func(issuerKey string) []domain.DowntimeSignal
}

// Pool consumes incidents and drives them through recovery.
type Pool struct {
	cfg  Config
	deps Deps

	budgetMu     sync.Mutex
	budgetWindow time.Time
	budgetSpent  int
}

// New builds a pool, rejecting an incomplete dependency set at construction
// rather than panicking on the first message.
func New(cfg Config, deps Deps) (*Pool, error) {
	cfg = cfg.withDefaults()
	missing := []string{}
	if deps.Store == nil {
		missing = append(missing, "store")
	}
	if deps.Queue == nil {
		missing = append(missing, "queue")
	}
	if deps.Diagnoser == nil {
		missing = append(missing, "diagnoser")
	}
	if deps.Gatekeeper == nil {
		missing = append(missing, "gatekeeper")
	}
	if deps.Executor == nil {
		missing = append(missing, "executor")
	}
	if deps.Clock == nil {
		missing = append(missing, "clock")
	}
	if deps.Log == nil {
		missing = append(missing, "logger")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("worker: missing dependencies: %v", missing)
	}
	if len(deps.AvailableRails) == 0 {
		deps.AvailableRails = []domain.Rail{
			domain.RailUPIIntent, domain.RailCard, domain.RailNetbanking,
		}
	}
	return &Pool{cfg: cfg, deps: deps}, nil
}

// Run starts the consumers and the reclaim sweeper, returning when ctx is done
// and every consumer has finished its in-flight message.
func (p *Pool) Run(ctx context.Context) error {
	p.deps.Log.Info("worker pool started",
		"concurrency", p.cfg.Concurrency, "group", p.cfg.Group)

	var wg sync.WaitGroup
	for i := 0; i < p.cfg.Concurrency; i++ {
		wg.Add(1)
		name := fmt.Sprintf("worker-%d", i)
		go func() {
			defer wg.Done()
			p.consume(ctx, name)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.reclaimLoop(ctx)
	}()

	wg.Wait()
	p.deps.Log.Info("worker pool stopped")
	return nil
}

func (p *Pool) consume(ctx context.Context, name string) {
	for {
		if ctx.Err() != nil {
			return
		}
		msgs, err := p.deps.Queue.Consume(ctx, p.cfg.Group, name, p.cfg.BatchSize, p.cfg.ReadBlock)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.deps.Log.Warn("consume failed", "consumer", name, "error", err)
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		for _, m := range msgs {
			p.dispatch(ctx, name, m)
		}
	}
}

// dispatch handles one message, isolating any panic.
//
// A panic inside handling must not take down the pool: one malformed payload
// would otherwise stop every other recovery in flight. The message is parked
// with its failure history instead, which turns a crash into a bug report.
func (p *Pool) dispatch(ctx context.Context, consumer string, msg domain.QueueMessage) {
	defer func() {
		if rec := recover(); rec != nil {
			p.count("worker.panic")
			p.deps.Log.Error("recovered a panic while handling a message",
				"consumer", consumer, "incident_id", msg.IncidentID,
				"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
			p.park(ctx, msg, fmt.Sprintf("panic: %v", rec))
		}
	}()

	if msg.Deliveries > p.cfg.MaxDeliveries {
		p.count("worker.poison")
		p.park(ctx, msg, fmt.Sprintf("exceeded %d deliveries", p.cfg.MaxDeliveries))
		return
	}

	start := p.deps.Clock.Now()
	err := p.Handle(ctx, msg)
	p.observe("worker.handle_ms", float64(p.deps.Clock.Now().Sub(start).Milliseconds()))

	if err != nil {
		p.count("worker.handle_failed")
		p.deps.Log.Error("incident handling failed; leaving it for redelivery",
			"consumer", consumer, "incident_id", msg.IncidentID, "error", err)
		// Deliberately not acked: redelivery is the retry mechanism, and the
		// delivery counter is what eventually parks a genuinely poison message.
		return
	}

	if err := p.deps.Queue.Ack(ctx, p.cfg.Group, msg.ID); err != nil {
		// The work is done; a failed ack causes one redelivery, which
		// idempotency absorbs.
		p.deps.Log.Warn("could not acknowledge a handled message",
			"incident_id", msg.IncidentID, "error", err)
	}
}

func (p *Pool) park(ctx context.Context, msg domain.QueueMessage, cause string) {
	if p.deps.DeadLetter == nil {
		return
	}
	if err := p.deps.DeadLetter.DeadLetter(ctx, p.cfg.Group, msg, cause); err != nil {
		p.deps.Log.Error("could not dead-letter a message",
			"incident_id", msg.IncidentID, "error", err)
		return
	}
	p.audit(ctx, domain.AuditDeadLettered, msg.IncidentID, map[string]any{
		"deliveries": msg.Deliveries,
		"cause":      cause,
	})
}

// Handle runs the full pipeline for one message. It is exported so tests and
// the deterministic simulator can drive a single incident without a pool.
func (p *Pool) Handle(ctx context.Context, msg domain.QueueMessage) error {
	var queued struct {
		IncidentID string `json:"incident_id"`
	}
	if err := json.Unmarshal(msg.Payload, &queued); err != nil {
		// A payload this process wrote and cannot now read is poison, not a
		// transient fault, so it is surfaced as a permanent failure.
		return fmt.Errorf("worker: unreadable queue payload for %s: %w", msg.IncidentID, err)
	}
	incidentID := queued.IncidentID
	if incidentID == "" {
		incidentID = msg.IncidentID
	}

	incident, err := p.deps.Store.GetIncident(ctx, incidentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The incident is gone. Nothing to recover; acking is correct.
			p.deps.Log.Warn("queued incident no longer exists", "incident_id", incidentID)
			return nil
		}
		return fmt.Errorf("worker: loading incident %s: %w", incidentID, err)
	}
	if incident.State.Terminal() {
		// Redelivery of an incident already concluded. Idempotency in action.
		return nil
	}

	payment, err := paymentFrom(incident)
	if err != nil {
		return fmt.Errorf("worker: incident %s: %w", incidentID, err)
	}

	attempt, err := p.deps.Store.IncrementIncidentAttempts(ctx, incidentID)
	if err != nil {
		return fmt.Errorf("worker: counting attempts for %s: %w", incidentID, err)
	}

	snapshot := p.snapshot(ctx, incident.IssuerKey)
	sessionLive := p.sessionLive(ctx, incident.OrderID)

	proposal := p.diagnose(ctx, incident, payment, snapshot, sessionLive, attempt)

	var mandate *domain.MandateRecord
	if incident.IsRecurring && incident.SubscriptionID != "" {
		if m, err := p.deps.Store.GetMandate(ctx, incident.SubscriptionID); err == nil {
			mandate = &m
		} else if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("worker: loading mandate %s: %w", incident.SubscriptionID, err)
		}
	}

	cmd, err := p.deps.Gatekeeper.Decide(ctx, domain.GateInput{
		IncidentID:     incidentID,
		Payment:        payment,
		Proposal:       proposal,
		Telemetry:      snapshot,
		SessionActive:  sessionLive,
		AttemptNumber:  attempt,
		Mandate:        mandate,
		AvailableRails: p.deps.AvailableRails,
	})
	if err != nil {
		return fmt.Errorf("worker: gating incident %s: %w", incidentID, err)
	}

	p.audit(ctx, domain.AuditGateDecision, incidentID, map[string]any{
		"action":             string(cmd.Action),
		"target_rail":        string(cmd.TargetRail),
		"delay_seconds":      cmd.DelaySeconds,
		"applied_invariants": cmd.AppliedInvariants,
		"overrode_proposal":  cmd.OverrodeProposal,
		"proposal_mode":      string(cmd.ProposalMode),
		"proposal_action":    string(cmd.ProposalAction),
		"attempt":            cmd.AttemptNumber,
	})

	if !cmd.Executable() {
		p.count("worker.abstained")
		if err := p.deps.Store.UpdateIncidentState(ctx, incidentID, domain.IncidentAbstained); err != nil {
			return fmt.Errorf("worker: closing incident %s: %w", incidentID, err)
		}
		return nil
	}

	return p.execute(ctx, incident, cmd, snapshot)
}

// diagnose produces an advisory proposal, skipping inference entirely when the
// issuer is in a confirmed outage.
//
// During an outage the cause is already known, so diagnosing thousands of
// identical failures individually spends latency and money to rediscover one
// fact. Skipping is both cheaper and more accurate.
func (p *Pool) diagnose(
	ctx context.Context,
	incident domain.Incident,
	payment domain.PaymentEntity,
	snapshot domain.TelemetrySnapshot,
	sessionLive bool,
	attempt int,
) domain.DiagnosticProposal {
	if p.deps.Breaker != nil {
		if allowed, err := p.deps.Breaker.Allow(ctx, incident.IssuerKey); err == nil && !allowed {
			p.count("worker.inference_skipped")
			prop := domain.AbstainProposal(incident.ID,
				"issuer breaker open; recovery deferred without inference", domain.ModeSkipped)
			prop.FailureClassification = domain.ClassIssuerOutage
			prop.RecommendedAction = domain.ActionAsyncRetry
			prop.ConfidenceScore = 0.9
			prop.Degraded = false
			return prop
		}
	}

	var signals []domain.DowntimeSignal
	if p.deps.DowntimeSignals != nil {
		signals = p.deps.DowntimeSignals(incident.IssuerKey)
	}

	dc := domain.DiagnosticContext{
		IncidentID:     incident.ID,
		ErrorCode:      payment.ErrorCode,
		ErrorSource:    payment.ErrorSource,
		ErrorStep:      payment.ErrorStep,
		ErrorReason:    payment.ErrorReason,
		Method:         payment.Method,
		IssuerKey:      incident.IssuerKey,
		AmountBand:     domain.AmountBand(incident.AmountPaisa),
		IsRecurring:    incident.IsRecurring,
		SessionActive:  sessionLive,
		AttemptNumber:  attempt,
		Telemetry:      snapshot,
		Downtimes:      signals,
		AvailableRails: p.deps.AvailableRails,
		ObservedAt:     p.deps.Clock.Now(),
	}

	proposal, err := p.deps.Diagnoser.Diagnose(ctx, dc)
	if err != nil {
		p.count("worker.diagnose_failed")
		p.deps.Log.Warn("diagnosis failed; abstaining",
			"incident_id", incident.ID, "error", err)
		return domain.AbstainProposal(incident.ID, "diagnosis unavailable", domain.ModeHeuristic)
	}

	p.count("worker.diagnosed." + string(proposal.Mode))
	p.audit(ctx, domain.AuditDiagnosis, incident.ID, map[string]any{
		"mode":           string(proposal.Mode),
		"classification": string(proposal.FailureClassification),
		"confidence":     proposal.ConfidenceScore,
		"action":         string(proposal.RecommendedAction),
		"rail":           string(proposal.SuggestedFallbackRail),
		"degraded":       proposal.Degraded,
		"root_cause":     proposal.InferredRootCause,
	})
	return proposal
}

// execute performs the command's side effect and records the outcome.
func (p *Pool) execute(ctx context.Context, incident domain.Incident, cmd domain.SanitizedCommand, snap domain.TelemetrySnapshot) error {
	// A recurring debit may not proceed without its notice. The notice is sent
	// first and its failure aborts the debit, because believing we notified
	// when we did not is the precise condition the rule exists to prevent.
	if cmd.PreDebitNotificationNeeded {
		if err := p.deps.Executor.NotifyPreDebit(ctx, cmd); err != nil {
			return fmt.Errorf("worker: pre-debit notice for %s: %w", incident.ID, err)
		}
		p.audit(ctx, domain.AuditPreDebitNotice, incident.ID, map[string]any{
			"debit_after": cmd.ExecuteAfter.UTC().Format(time.RFC3339),
		})
	}

	// A scheduled command is not executed now. Marking it scheduled and acking
	// is correct: the delay is absolute, so it cannot drift, and the scheduler
	// picks it up when due.
	if cmd.DelaySeconds > 0 && cmd.ExecuteAfter.After(p.deps.Clock.Now()) {
		p.count("worker.scheduled")
		if err := p.deps.Store.UpdateIncidentState(ctx, incident.ID, domain.IncidentScheduled); err != nil {
			return fmt.Errorf("worker: scheduling incident %s: %w", incident.ID, err)
		}
		return nil
	}

	if !p.spendRetryBudget() {
		// The global budget is exhausted. Leaving the message unacked defers
		// the work rather than dropping it, which is what keeps a mass outage
		// from becoming a retry storm.
		p.count("worker.budget_exhausted")
		return fmt.Errorf("worker: retry budget exhausted; deferring incident %s", incident.ID)
	}

	p.audit(ctx, domain.AuditAttemptStarted, incident.ID, map[string]any{
		"action": string(cmd.Action), "rail": string(cmd.TargetRail), "attempt": cmd.AttemptNumber,
	})

	var (
		rec domain.AttemptRecord
		err error
	)
	switch cmd.Action {
	case domain.ActionRailMorph:
		rec, err = p.deps.Executor.MorphRail(ctx, cmd)
	default:
		rec, err = p.deps.Executor.Retry(ctx, cmd)
	}

	// The attempt is recorded whether or not it succeeded, and whether or not
	// the transport failed: an attempt that was made but not recorded is money
	// spent that the benchmark cannot see.
	rec.IncidentID = incident.ID
	if rec.StartedAt.IsZero() {
		rec.StartedAt = p.deps.Clock.Now()
	}
	if rec.CompletedAt.IsZero() {
		rec.CompletedAt = p.deps.Clock.Now()
	}
	if saveErr := p.deps.Store.RecordAttempt(ctx, rec); saveErr != nil {
		p.deps.Log.Error("could not record an attempt",
			"incident_id", incident.ID, "error", saveErr)
	}

	p.recordOutcome(ctx, incident.IssuerKey, rec)

	p.audit(ctx, domain.AuditAttemptResult, incident.ID, map[string]any{
		"succeeded":  rec.Succeeded,
		"error_code": rec.ErrorCode,
		"rail":       string(rec.Rail),
		"attempt":    rec.AttemptNumber,
		"fee_paisa":  rec.GatewayFeePaisa,
	})

	if err != nil {
		// A transport failure leaves the incident open for redelivery.
		return fmt.Errorf("worker: executing incident %s: %w", incident.ID, err)
	}

	next := domain.IncidentAbandoned
	if rec.Succeeded {
		next = domain.IncidentRecovered
		p.count("worker.recovered")
	}
	if !rec.Succeeded && cmd.AttemptNumber < cmd.MaxAttempts {
		// More attempts remain; the incident stays open for the next one.
		next = domain.IncidentScheduled
	}
	if err := p.deps.Store.UpdateIncidentState(ctx, incident.ID, next); err != nil {
		return fmt.Errorf("worker: updating incident %s: %w", incident.ID, err)
	}
	if next.Terminal() {
		p.audit(ctx, domain.AuditIncidentClosed, incident.ID, map[string]any{"state": string(next)})
	}
	return nil
}

// recordOutcome feeds telemetry and the breaker. Failures here are logged, not
// returned: losing an observation must never undo a completed attempt.
func (p *Pool) recordOutcome(ctx context.Context, issuerKey string, rec domain.AttemptRecord) {
	latency := rec.CompletedAt.Sub(rec.StartedAt)
	if latency < 0 {
		latency = 0
	}
	if p.deps.Telemetry != nil {
		if err := p.deps.Telemetry.RecordOutcome(ctx, issuerKey, rec.ErrorCode, rec.Succeeded, latency); err != nil {
			p.deps.Log.Warn("telemetry write failed", "issuer_key", issuerKey, "error", err)
		}
	}
	if p.deps.Breaker != nil {
		if err := p.deps.Breaker.Report(ctx, issuerKey, rec.Succeeded); err != nil {
			p.deps.Log.Warn("breaker report failed", "issuer_key", issuerKey, "error", err)
		}
	}
}

// spendRetryBudget consumes one unit of the global per-minute allowance.
func (p *Pool) spendRetryBudget() bool {
	now := p.deps.Clock.Now().Truncate(time.Minute)
	p.budgetMu.Lock()
	defer p.budgetMu.Unlock()
	if !now.Equal(p.budgetWindow) {
		p.budgetWindow = now
		p.budgetSpent = 0
	}
	if p.budgetSpent >= p.cfg.RetryBudgetPerMinute {
		return false
	}
	p.budgetSpent++
	return true
}

func (p *Pool) snapshot(ctx context.Context, issuerKey string) domain.TelemetrySnapshot {
	snap := domain.TelemetrySnapshot{IssuerKey: issuerKey, SampledAt: p.deps.Clock.Now()}
	if p.deps.Telemetry != nil {
		if s, err := p.deps.Telemetry.Snapshot(ctx, issuerKey); err == nil {
			snap = s
		} else {
			p.deps.Log.Debug("telemetry snapshot unavailable", "issuer_key", issuerKey, "error", err)
		}
	}
	if p.deps.Breaker != nil {
		if st, err := p.deps.Breaker.State(ctx, issuerKey); err == nil {
			snap.BreakerState = st
		}
	}
	if snap.BreakerState == "" {
		snap.BreakerState = domain.BreakerClosed
	}
	return snap
}

// sessionLive reports whether an in-session morph is even available. It fails
// closed: if liveness cannot be determined, the session is treated as gone, so
// the worst case is an unnecessary async retry rather than a morph published
// into a session nobody is watching.
func (p *Pool) sessionLive(ctx context.Context, orderID string) bool {
	if orderID == "" {
		return false
	}
	sess, err := p.deps.Store.GetSessionByOrder(ctx, orderID)
	if err != nil {
		return false
	}
	if sess.Expired(p.deps.Clock.Now()) {
		return false
	}
	if p.deps.Hub != nil && !p.deps.Hub.Active(sess.ID) {
		// The row says live but nobody is attached: the customer closed the tab.
		return false
	}
	return true
}

// reclaimLoop sweeps up messages stranded by a consumer that stopped
// acknowledging, which is what a crashed worker leaves behind.
func (p *Pool) reclaimLoop(ctx context.Context) {
	t := time.NewTicker(p.cfg.ReclaimInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			msgs, err := p.deps.Queue.Reclaim(ctx, p.cfg.Group, "reclaimer",
				p.cfg.ReclaimMinIdle, p.cfg.BatchSize)
			if err != nil {
				p.deps.Log.Warn("reclaim failed", "error", err)
				continue
			}
			if len(msgs) == 0 {
				continue
			}
			p.add("worker.reclaimed", uint64(len(msgs)))
			p.deps.Log.Info("reclaimed stranded messages", "count", len(msgs))
			for _, m := range msgs {
				p.dispatch(ctx, "reclaimer", m)
			}
		}
	}
}

// paymentFrom recovers the verified entity from the stored raw payload.
//
// The amount is read from the bytes that passed HMAC verification, not from the
// denormalised columns, so the money acted on traces to a signature even if a
// column were later modified.
func paymentFrom(in domain.Incident) (domain.PaymentEntity, error) {
	if len(in.RawPayload) == 0 {
		return domain.PaymentEntity{}, errors.New("stored incident has no verified payload")
	}
	var payload domain.RazorpayWebhookPayload
	if err := json.Unmarshal(in.RawPayload, &payload); err != nil {
		return domain.PaymentEntity{}, fmt.Errorf("stored payload is unreadable: %w", err)
	}
	p := payload.Payload.Payment.Entity
	if p.ID == "" {
		return domain.PaymentEntity{}, errors.New("stored payload carries no payment entity")
	}
	if p.Amount != in.AmountPaisa {
		// The column and the signed bytes disagree. Refusing is the only safe
		// action: one of them has been tampered with and there is no way to
		// tell which from here.
		return domain.PaymentEntity{}, fmt.Errorf(
			"amount mismatch between the verified payload and the incident row for %s", in.ID)
	}
	return p, nil
}

func (p *Pool) audit(ctx context.Context, kind domain.AuditKind, incidentID string, detail any) {
	if p.deps.Ledger == nil {
		return
	}
	if _, err := p.deps.Ledger.Append(ctx, kind, incidentID, "worker", detail); err != nil {
		p.deps.Log.Error("audit append failed",
			"kind", string(kind), "incident_id", incidentID, "error", err)
	}
}

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

func (p *Pool) count(name string) {
	if p.deps.Metrics != nil {
		p.deps.Metrics.Counter(name).Inc()
	}
}

func (p *Pool) add(name string, n uint64) {
	if p.deps.Metrics != nil {
		p.deps.Metrics.Counter(name).Add(n)
	}
}

func (p *Pool) observe(name string, v float64) {
	if p.deps.Metrics != nil {
		p.deps.Metrics.Histogram(name).Observe(v)
	}
}

// Package ingest is the webhook edge: the only place untrusted bytes enter the
// system.
//
// The ordering of the checks in Handle is the security design, not a style
// choice. Signature verification happens before parsing, parsing before the
// replay check, and the replay check before any write. Every step that could
// consume resources or mutate state is behind a step that proves the request
// came from Razorpay.
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
	"time"

	"github.com/google/uuid"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// Razorpay's webhook headers.
const (
	HeaderSignature = "X-Razorpay-Signature"
	HeaderEventID   = "X-Razorpay-Event-Id"
)

// MaxBodyBytes caps the request body. Razorpay payloads are a few kilobytes;
// a megabyte is generous. The cap is applied before the body is read, so an
// attacker cannot force an unbounded allocation by streaming forever.
const MaxBodyBytes = 1 << 20

// TopicIncidentFailed is the outbox topic for a failed payment.
const TopicIncidentFailed = "incident.failed"

// Config holds the edge's tunables.
type Config struct {
	// Secret is the current webhook signing secret.
	Secret []byte
	// NextSecret, when set, is also accepted. Razorpay signs with one secret at
	// a time, so rotation needs a window where both verify; without it a
	// rotation drops every webhook sent between the dashboard change and the
	// deploy.
	NextSecret []byte
	// MaxSkew rejects events whose creation time is too far from now in either
	// direction. It bounds replay of a captured webhook after an issuer has
	// recovered, when acting on it would be wrong.
	MaxSkew time.Duration
	// OutboxHighWater sheds load once the outbox has more undispatched rows
	// than this. Accepting work that cannot be drained turns an incident into
	// an outage; Razorpay retries, so shed load is deferred rather than lost.
	OutboxHighWater int
}

func (c Config) withDefaults() Config {
	if c.MaxSkew <= 0 {
		c.MaxSkew = 5 * time.Minute
	}
	if c.OutboxHighWater <= 0 {
		c.OutboxHighWater = 50_000
	}
	return c
}

// Handler verifies, deduplicates and durably records incoming webhooks.
type Handler struct {
	cfg     Config
	store   domain.Store
	ledger  domain.AuditLedger
	clock   domain.Clock
	log     *slog.Logger
	metrics *obs.Registry
}

// New builds the edge handler.
func New(cfg Config, st domain.Store, ledger domain.AuditLedger, clock domain.Clock, log *slog.Logger, m *obs.Registry) (*Handler, error) {
	cfg = cfg.withDefaults()
	if len(cfg.Secret) == 0 {
		// Refusing to start without a secret is deliberate. A handler that
		// accepts unsigned webhooks is worse than one that does not run: it
		// looks healthy while letting anyone forge a payment failure.
		return nil, errors.New("ingest: refusing to start without a webhook signing secret")
	}
	return &Handler{cfg: cfg, store: st, ledger: ledger, clock: clock, log: log, metrics: m}, nil
}

// Outcome names what the edge did with a request, for metrics and tests.
type Outcome string

const (
	OutcomeQueued          Outcome = "queued_for_healing"
	OutcomeDuplicate       Outcome = "duplicate_ignored"
	OutcomeTerminalHalt    Outcome = "terminal_decline_halted"
	OutcomeIrrelevant      Outcome = "event_ignored"
	OutcomeRejectedSig     Outcome = "invalid_signature"
	OutcomeRejectedSkew    Outcome = "timestamp_out_of_range"
	OutcomeRejectedFormat  Outcome = "malformed_payload"
	OutcomeRejectedTooBig  Outcome = "payload_too_large"
	OutcomeShedLoad        Outcome = "backpressure"
	OutcomeInternalFailure Outcome = "internal_error"
)

// ServeHTTP implements the webhook endpoint.
//
// Response bodies are fixed strings chosen from the Outcome set. Nothing about
// the request is echoed: an error message that repeats attacker input is both
// a reflection vector and a probing oracle.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.clock.Now()
	ctx := r.Context()

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.respond(w, http.StatusMethodNotAllowed, OutcomeRejectedFormat)
		return
	}

	// 1. Bound the body before reading a single byte of it.
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.count("ingest.rejected.too_large")
			h.respond(w, http.StatusRequestEntityTooLarge, OutcomeRejectedTooBig)
			return
		}
		h.count("ingest.rejected.read")
		h.respond(w, http.StatusBadRequest, OutcomeRejectedFormat)
		return
	}

	// 2. Verify before parsing. Parsing attacker-controlled JSON is work, and
	//    work performed for an unauthenticated caller is a denial-of-service
	//    surface.
	if !h.verify(r.Header.Get(HeaderSignature), body) {
		h.count("ingest.rejected.signature")
		h.log.Warn("webhook signature verification failed",
			"request_id", obs.RequestID(ctx), "bytes", len(body))
		h.audit(ctx, domain.AuditWebhookRejected, "", map[string]any{
			"reason": "signature_mismatch",
			"bytes":  len(body),
		})
		h.respond(w, http.StatusUnauthorized, OutcomeRejectedSig)
		return
	}

	var payload domain.RazorpayWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.count("ingest.rejected.malformed")
		h.respond(w, http.StatusBadRequest, OutcomeRejectedFormat)
		return
	}

	// 3. Bound replay in time. A signature stays valid forever, so a captured
	//    webhook replayed a week later would still verify.
	if skew := h.skew(payload.CreatedAt); skew > h.cfg.MaxSkew {
		h.count("ingest.rejected.skew")
		h.audit(ctx, domain.AuditWebhookRejected, "", map[string]any{
			"reason":     "timestamp_out_of_range",
			"skew_secs":  int64(skew.Seconds()),
			"event_type": payload.Event,
		})
		h.respond(w, http.StatusBadRequest, OutcomeRejectedSkew)
		return
	}

	payment := payload.Payload.Payment.Entity
	if !isRecoverableEvent(payload.Event) || payment.ID == "" {
		h.count("ingest.ignored")
		h.respond(w, http.StatusOK, OutcomeIrrelevant)
		return
	}

	// 4. Terminal declines never reach the database or the model. Retrying them
	//    burns gateway fees and, on recurring rails, can trip issuer abuse
	//    heuristics. The audit entry is still written so the trail is complete.
	if domain.IsTerminalDecline(payment.ErrorCode) {
		h.count("ingest.terminal_halt")
		h.audit(ctx, domain.AuditTerminalHalt, "", map[string]any{
			"payment_id": payment.ID,
			"error_code": payment.ErrorCode,
			"reason":     domain.TerminalDeclineCodes[payment.ErrorCode],
		})
		h.respond(w, http.StatusOK, OutcomeTerminalHalt)
		return
	}

	// 5. Admission control. Checked after verification so an unauthenticated
	//    caller cannot probe queue depth.
	if h.overHighWater(ctx) {
		h.count("ingest.shed")
		w.Header().Set("Retry-After", "30")
		h.respond(w, http.StatusServiceUnavailable, OutcomeShedLoad)
		return
	}

	eventID := h.eventID(r, body)

	outcome, err := h.record(ctx, eventID, payload, payment, body)
	if err != nil {
		h.count("ingest.error")
		h.log.Error("failed to durably record webhook",
			"request_id", obs.RequestID(ctx), "payment_id", payment.ID, "error", err)
		// Refusing is correct: returning 200 for an event we could not persist
		// would silently lose a payment failure. Razorpay retries on non-2xx.
		h.respond(w, http.StatusServiceUnavailable, OutcomeInternalFailure)
		return
	}

	h.count("ingest." + string(outcome))
	h.observe("ingest.latency_ms", float64(h.clock.Now().Sub(start).Milliseconds()))
	h.respond(w, http.StatusOK, outcome)
}

// verify performs a constant-time comparison against every accepted secret.
//
// The hex is decoded first and the decode failure is a rejection in its own
// right: comparing hex strings would silently accept a differently-cased or
// malformed signature as merely "not equal", hiding a malformed-input case that
// deserves to be visible.
func (h *Handler) verify(header string, body []byte) bool {
	if header == "" {
		return false
	}
	got, err := hex.DecodeString(header)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	// Both secrets are always checked, with no early return, so the work done
	// does not reveal which secret matched.
	ok := hmacMatches(h.cfg.Secret, body, got)
	if len(h.cfg.NextSecret) > 0 && hmacMatches(h.cfg.NextSecret, body, got) {
		ok = true
	}
	return ok
}

func hmacMatches(secret, body, want []byte) bool {
	if len(secret) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

func (h *Handler) skew(createdAt int64) time.Duration {
	if createdAt == 0 {
		// Razorpay always sets created_at. Treating a missing value as zero
		// skew would let an attacker bypass the window by omitting the field.
		return h.cfg.MaxSkew + time.Second
	}
	d := h.clock.Now().Sub(time.Unix(createdAt, 0))
	if d < 0 {
		d = -d
	}
	return d
}

// eventID returns the idempotency key.
//
// Razorpay sends X-Razorpay-Event-Id. When it is absent the signature itself is
// a sound substitute: it is a deterministic function of the exact body, so two
// deliveries of the same event share a key while two genuinely different events
// cannot collide. Falling back to a random id would silently disable
// deduplication for the requests that need it most.
func (h *Handler) eventID(r *http.Request, body []byte) string {
	if id := r.Header.Get(HeaderEventID); id != "" && len(id) <= 128 && isSafeIdentifier(id) {
		return id
	}
	sum := sha256.Sum256(body)
	return "sig:" + hex.EncodeToString(sum[:])
}

// isSafeIdentifier keeps header-supplied values inside a character set that is
// safe to store, index and render. An unvalidated header echoed into a log is a
// log-injection vector.
func isSafeIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return s != ""
}

func (h *Handler) overHighWater(ctx context.Context) bool {
	pending, _, err := h.store.OutboxDepth(ctx)
	if err != nil {
		// If depth cannot be read the safe assumption is that the system is
		// healthy enough to accept: refusing on a failed gauge would turn a
		// monitoring fault into an outage.
		h.log.Debug("outbox depth unavailable; admission control skipped", "error", err)
		return false
	}
	h.gauge("outbox.pending", float64(pending))
	return pending > h.cfg.OutboxHighWater
}

// record writes the incident, the outbox event and the audit entry in one
// transaction. Either all three land or none do, which is what removes the
// dual-write window entirely.
func (h *Handler) record(
	ctx context.Context,
	eventID string,
	payload domain.RazorpayWebhookPayload,
	payment domain.PaymentEntity,
	body []byte,
) (Outcome, error) {
	// A pre-check is an optimisation, not the guarantee. Two concurrent
	// deliveries can both pass it; the unique constraint below is what actually
	// arbitrates.
	if _, err := h.store.GetIncidentByEventID(ctx, eventID); err == nil {
		return OutcomeDuplicate, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("looking up event %s: %w", eventID, err)
	}

	now := h.clock.Now()
	incident := domain.Incident{
		ID:             uuid.NewString(),
		PaymentID:      payment.ID,
		OrderID:        payment.OrderID,
		SubscriptionID: payment.SubscriptionID,
		EventID:        eventID,
		AmountPaisa:    payment.Amount,
		Currency:       payment.Currency,
		Method:         payment.Method,
		IssuerKey:      payment.Issuer(),
		ErrorCode:      payment.ErrorCode,
		State:          domain.IncidentReceived,
		IsRecurring:    payment.IsRecurring(),
		RawPayload:     domain.RawJSON(body),
		ReceivedAt:     now,
		UpdatedAt:      now,
	}

	// The queue payload carries the incident id and the verified entity, never
	// the raw body: workers must read money from the stored, verified record
	// rather than re-parsing bytes that travelled through a cache.
	queued, err := json.Marshal(queuedIncident{
		IncidentID: incident.ID,
		PaymentID:  payment.ID,
		EventID:    eventID,
		Event:      payload.Event,
		ReceivedAt: now.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encoding queue payload for %s: %w", incident.ID, err)
	}

	err = h.store.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		if err := tx.InsertIncident(ctx, incident); err != nil {
			return err
		}
		if err := tx.InsertOutboxEvent(ctx, domain.OutboxEvent{
			IncidentID: incident.ID,
			Topic:      TopicIncidentFailed,
			Payload:    domain.RawJSON(queued),
			State:      domain.OutboxPending,
			CreatedAt:  now,
		}); err != nil {
			return err
		}
		entry := domain.AuditEntry{
			IncidentID: incident.ID,
			Kind:       domain.AuditWebhookAccepted,
			Actor:      "ingest",
			At:         now,
			Detail: mustJSON(map[string]any{
				"payment_id": payment.ID,
				"issuer_key": incident.IssuerKey,
				"error_code": payment.ErrorCode,
				"amount":     payment.Amount,
				"recurring":  incident.IsRecurring,
				"event":      payload.Event,
			}),
		}
		return tx.AppendAudit(ctx, entry)
	})

	if err != nil {
		// The unique index on event_id is the real deduplication point, so a
		// conflict here means a concurrent delivery won the race. That is a
		// success from the sender's perspective, not an error.
		if errors.Is(err, store.ErrConflict) {
			return OutcomeDuplicate, nil
		}
		return "", fmt.Errorf("recording incident for payment %s: %w", payment.ID, err)
	}

	h.log.Info("webhook accepted",
		"request_id", obs.RequestID(ctx),
		"incident_id", incident.ID,
		"payment_id", payment.ID,
		"issuer_key", incident.IssuerKey,
		"error_code", payment.ErrorCode)

	return OutcomeQueued, nil
}

// queuedIncident is the message the relay publishes. It is deliberately a
// reference plus provenance, not a copy of the payload.
type queuedIncident struct {
	IncidentID string `json:"incident_id"`
	PaymentID  string `json:"payment_id"`
	EventID    string `json:"event_id"`
	Event      string `json:"event"`
	ReceivedAt int64  `json:"received_at"`
}

// isRecoverableEvent filters to the events this system acts on. Razorpay sends
// many event types; processing ones we have no recovery path for would fill the
// queue with work that always ends in an abstain.
func isRecoverableEvent(event string) bool {
	switch event {
	case "payment.failed",
		"subscription.charged.failed",
		"subscription.pending",
		"invoice.payment_failed",
		"order.payment_failed":
		return true
	default:
		return false
	}
}

func (h *Handler) respond(w http.ResponseWriter, status int, outcome Outcome) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// Fixed body, built from a closed set of outcomes. Nothing from the request
	// is reflected.
	_, _ = fmt.Fprintf(w, `{"status":%q}`, string(outcome))
}

func (h *Handler) audit(ctx context.Context, kind domain.AuditKind, incidentID string, detail any) {
	if h.ledger == nil {
		return
	}
	if _, err := h.ledger.Append(ctx, kind, incidentID, "ingest", detail); err != nil {
		// A failed audit write must not fail the request that was otherwise
		// handled correctly, but it must be loud: a gap in the chain is a
		// verification failure later.
		h.log.Error("audit append failed", "kind", string(kind), "error", err)
	}
}

func (h *Handler) count(name string) {
	if h.metrics != nil {
		h.metrics.Counter(name).Inc()
	}
}

func (h *Handler) observe(name string, v float64) {
	if h.metrics != nil {
		h.metrics.Histogram(name).Observe(v)
	}
}

func (h *Handler) gauge(name string, v float64) {
	if h.metrics != nil {
		h.metrics.Gauge(name).Set(v)
	}
}

func mustJSON(v any) domain.RawJSON {
	b, err := json.Marshal(v)
	if err != nil {
		// The inputs are all plain maps of scalars built in this package, so a
		// failure here is a programming error rather than a runtime condition.
		return domain.RawJSON(`{"encoding_error":true}`)
	}
	return domain.RawJSON(b)
}

// Sign produces the signature Razorpay would send for a body. It exists so the
// simulator and the tests sign exactly the way the verifier checks, rather than
// reimplementing the scheme and drifting from it.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Package executor performs the outbound side effects a sanitised command
// calls for: retrying a payment, morphing a live session onto another rail, and
// sending a pre-debit notification.
//
// This is the only package that spends money, so it is deliberately dull. It
// makes no decisions: every field it acts on was fixed by the gatekeeper, and
// anything it cannot execute exactly as specified is an error rather than an
// approximation.
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// maxResponseBytes bounds what is read from the gateway. A compromised or
// misbehaving upstream must not be able to exhaust memory through a response
// body, and no legitimate payment response is anywhere near this size.
const maxResponseBytes = 256 << 10

// Config describes how to reach the payment gateway.
type Config struct {
	// BaseURL points at Razorpay or at the local simulator. Both speak the same
	// schemas, which is what lets the benchmark run without an account and the
	// production path run without a code change.
	BaseURL   string
	KeyID     string
	KeySecret string
	// Timeout bounds a single gateway call. A worker holds a queue message for
	// the duration, so a generous timeout converts a slow gateway into queue
	// lag rather than into resilience.
	Timeout time.Duration
	// CostModel prices each attempt. It is the same model the benchmark uses,
	// read from one shared file, so the economics the system optimises and the
	// economics it is measured by cannot diverge.
	CostModel domain.CostModel
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = 8 * time.Second
	}
	if c.CostModel == (domain.CostModel{}) {
		c.CostModel = domain.DefaultCostModel()
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	return c
}

// Gateway performs recovery actions against a Razorpay-compatible API.
type Gateway struct {
	cfg     Config
	client  *http.Client
	hub     domain.SessionHub
	store   domain.Store
	clock   domain.Clock
	log     *slog.Logger
	metrics *obs.Registry
}

// New builds a gateway executor.
func New(cfg Config, hub domain.SessionHub, st domain.Store, clock domain.Clock, log *slog.Logger, m *obs.Registry) (*Gateway, error) {
	cfg = cfg.withDefaults()
	if cfg.BaseURL == "" {
		return nil, errors.New("executor: a gateway base URL is required")
	}
	if _, err := url.Parse(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("executor: gateway base URL is not a URL: %w", err)
	}
	return &Gateway{
		cfg:     cfg,
		clock:   clock,
		hub:     hub,
		store:   st,
		log:     log,
		metrics: m,
		client: &http.Client{
			Timeout: cfg.Timeout,
			// Redirects are refused: a payment API that redirects is either
			// misconfigured or being intercepted, and following one would send
			// credentials to an unintended host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("executor: refusing to follow a redirect from the payment gateway")
			},
		},
	}, nil
}

// Retry re-presents a payment on its original rail.
func (g *Gateway) Retry(ctx context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	return g.attempt(ctx, cmd, cmd.TargetRail)
}

// MorphRail moves a live checkout session onto a different rail and re-presents
// the payment there.
//
// The session frame is published only after the gateway has accepted the new
// attempt. Telling the customer their method changed and then failing to move
// it would leave the page describing a state the system is not in.
func (g *Gateway) MorphRail(ctx context.Context, cmd domain.SanitizedCommand) (domain.AttemptRecord, error) {
	if cmd.TargetRail == domain.RailNone || !cmd.TargetRail.Valid() {
		return domain.AttemptRecord{}, fmt.Errorf("executor: refusing to morph incident %s onto an invalid rail %q", cmd.IncidentID, cmd.TargetRail)
	}

	session, err := g.store.GetSessionByOrder(ctx, cmd.OrderID)
	if err != nil {
		return domain.AttemptRecord{}, fmt.Errorf("executor: loading session for order %s: %w", cmd.OrderID, err)
	}
	if session.Expired(g.clock.Now()) {
		return domain.AttemptRecord{}, fmt.Errorf("executor: session for order %s is no longer live", cmd.OrderID)
	}

	from := session.CurrentRail
	rec, err := g.attempt(ctx, cmd, cmd.TargetRail)
	if err != nil {
		return rec, err
	}

	session.CurrentRail = cmd.TargetRail
	session.MorphCount++
	if err := g.store.UpdateSession(ctx, session); err != nil {
		// The attempt already happened; failing here would double-charge on a
		// retry. Record it and continue: the session row is bookkeeping, the
		// attempt is the money.
		g.log.Error("could not persist a rail morph",
			"incident_id", cmd.IncidentID, "order_id", cmd.OrderID, "error", err)
	}

	// The reason is drawn from a fixed vocabulary. Model text never reaches a
	// customer's screen.
	ev := domain.SessionEvent{
		Type:        "rail_morph",
		OrderID:     cmd.OrderID,
		FromRail:    from,
		ToRail:      cmd.TargetRail,
		AmountPaisa: cmd.ImmutableAmountPaisa,
		Currency:    cmd.Currency,
		Reason:      "issuer_unavailable",
		At:          g.clock.Now().Unix(),
	}
	if err := g.hub.Publish(ctx, session.ID, ev); err != nil {
		g.log.Warn("rail morph completed but the session frame could not be delivered",
			"incident_id", cmd.IncidentID, "session_id", session.ID, "error", err)
	}

	g.count("executor.rail_morph")
	rec.FrictionPaisa = g.cfg.CostModel.SessionFrictionPaisa
	return rec, nil
}

// NotifyPreDebit records the RBI-mandated notification before a recurring debit.
//
// The notification is the compliance artefact, so the mandate row is updated
// only after the send succeeds. Marking first would let a failed send leave the
// system believing it had notified, which is the precise condition the rule
// exists to prevent.
func (g *Gateway) NotifyPreDebit(ctx context.Context, cmd domain.SanitizedCommand) error {
	if cmd.PaymentID == "" {
		return errors.New("executor: cannot notify without a payment reference")
	}

	body, err := json.Marshal(map[string]any{
		"payment_id":  cmd.PaymentID,
		"amount":      cmd.ImmutableAmountPaisa,
		"currency":    cmd.Currency,
		"debit_after": cmd.ExecuteAfter.UTC().Format(time.RFC3339),
		"notice_type": "pre_debit",
	})
	if err != nil {
		return fmt.Errorf("executor: encoding pre-debit notice for %s: %w", cmd.PaymentID, err)
	}

	if _, err := g.call(ctx, http.MethodPost, "/v1/notifications/pre-debit", body); err != nil {
		return fmt.Errorf("executor: sending pre-debit notice for %s: %w", cmd.PaymentID, err)
	}
	g.count("executor.pre_debit_notified")
	return nil
}

// attempt performs one gateway call and returns the outcome as a record.
func (g *Gateway) attempt(ctx context.Context, cmd domain.SanitizedCommand, rail domain.Rail) (domain.AttemptRecord, error) {
	started := g.clock.Now()

	presentation := cmd.Presentation
	if presentation == "" || !presentation.Valid() {
		presentation = domain.PresentationUnchanged
	}

	// Amount and currency are copied from the command, which copied them from
	// the HMAC-verified payload. Nothing between the webhook and this request
	// is permitted to change them.
	body, err := json.Marshal(retryRequest{
		PaymentID:    cmd.PaymentID,
		OrderID:      cmd.OrderID,
		Amount:       cmd.ImmutableAmountPaisa,
		Currency:     cmd.Currency,
		Rail:         string(rail),
		Presentation: string(presentation),
		AttemptNo:    cmd.AttemptNumber,
		// The incident id is the idempotency key. A retried HTTP call that the
		// gateway already accepted must not become a second charge.
		IdempotencyKey: fmt.Sprintf("%s:%d", cmd.IncidentID, cmd.AttemptNumber),
	})
	if err != nil {
		return domain.AttemptRecord{}, fmt.Errorf("executor: encoding retry for %s: %w", cmd.PaymentID, err)
	}

	rec := domain.AttemptRecord{
		IncidentID:      cmd.IncidentID,
		AttemptNumber:   cmd.AttemptNumber,
		Action:          cmd.Action,
		Rail:            rail,
		Presentation:    presentation,
		AmountPaisa:     cmd.ImmutableAmountPaisa,
		GatewayFeePaisa: g.cfg.CostModel.GatewayFeePerAttemptPaisa,
		StartedAt:       started,
	}

	if !isSafeGatewayID(cmd.PaymentID) {
		return rec, fmt.Errorf("executor: refusing to call the gateway with an unsafe payment id for incident %s", cmd.IncidentID)
	}
	resp, err := g.call(ctx, http.MethodPost, "/v1/payments/"+url.PathEscape(cmd.PaymentID)+"/retry", body)
	rec.CompletedAt = g.clock.Now()
	g.observe("executor.gateway_latency_ms", float64(rec.CompletedAt.Sub(started).Milliseconds()))

	if err != nil {
		// A transport failure is not a decline. The fee is still charged
		// because the gateway was contacted, and the outcome is unknown rather
		// than negative; the idempotency key makes the next attempt safe.
		rec.Succeeded = false
		rec.ErrorCode = "gateway_unreachable"
		g.count("executor.transport_error")
		return rec, fmt.Errorf("executor: retrying payment %s: %w", cmd.PaymentID, err)
	}

	rec.Succeeded = resp.Status == "captured" || resp.Status == "authorized"
	rec.ErrorCode = resp.ErrorCode
	if rec.Succeeded {
		g.count("executor.retry_succeeded")
	} else {
		g.count("executor.retry_failed")
	}
	return rec, nil
}

// isSafeGatewayID bounds an identifier before it is interpolated into a URL.
//
// Escaping is not sufficient on its own: the client re-parses the URL it is
// given, and traversal segments survive that round trip, so a malformed id can
// still change which endpoint is called. Razorpay identifiers are a narrow
// alphanumeric shape, so validating against that shape is both simpler and
// stronger than trying to encode an arbitrary string into safety.
func isSafeGatewayID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

type retryRequest struct {
	PaymentID      string `json:"payment_id"`
	OrderID        string `json:"order_id"`
	Amount         int64  `json:"amount"`
	Currency       string `json:"currency"`
	Rail           string `json:"rail"`
	Presentation   string `json:"presentation"`
	AttemptNo      int    `json:"attempt_number"`
	IdempotencyKey string `json:"idempotency_key"`
}

type gatewayResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	ErrorDesc string `json:"error_description,omitempty"`
}

// call performs one authenticated request and decodes the response.
func (g *Gateway) call(ctx context.Context, method, path string, body []byte) (gatewayResponse, error) {
	var out gatewayResponse

	req, err := http.NewRequestWithContext(ctx, method, g.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return out, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if g.cfg.KeyID != "" {
		req.SetBasicAuth(g.cfg.KeyID, g.cfg.KeySecret)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return out, err
	}
	defer func() {
		// Draining before closing lets the connection return to the pool
		// instead of being torn down, which matters when every recovery
		// attempt opens one.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return out, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 500 {
		return out, fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return out, fmt.Errorf("gateway rate limited the request")
	}

	if err := json.Unmarshal(raw, &out); err != nil {
		// The body is deliberately not included in the error: it can contain
		// instrument detail, and this error string reaches logs.
		return out, fmt.Errorf("gateway response was not valid JSON (status %d, %d bytes)", resp.StatusCode, len(raw))
	}
	if resp.StatusCode >= 400 && out.ErrorCode == "" {
		return out, fmt.Errorf("gateway returned %d with no error code", resp.StatusCode)
	}
	return out, nil
}

func (g *Gateway) count(name string) {
	if g.metrics != nil {
		g.metrics.Counter(name).Inc()
	}
}

func (g *Gateway) observe(name string, v float64) {
	if g.metrics != nil {
		g.metrics.Histogram(name).Observe(v)
	}
}

// Compile-time proof that the concrete type satisfies the port.
var _ domain.Executor = (*Gateway)(nil)

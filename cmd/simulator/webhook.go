package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

const (
	// maxDeliveryAttempts bounds redelivery of a single event. Razorpay retries
	// a failing webhook for hours; a demo that did the same would spend the run
	// hammering a target that is not coming back.
	maxDeliveryAttempts = 5

	// deliveryBaseBackoff and deliveryMaxBackoff bracket the retry schedule.
	deliveryBaseBackoff = 250 * time.Millisecond
	deliveryMaxBackoff  = 8 * time.Second

	// maxRetryAfter caps how long a target can push us out with a Retry-After
	// header. Honouring an unbounded value would hand a misbehaving receiver
	// control of this process's schedule.
	maxRetryAfter = 30 * time.Second

	// maxResponseDrain is how much of a response body is read before closing.
	// Draining lets the connection be reused; bounding the drain means a target
	// that streams forever cannot pin this goroutine or its memory.
	maxResponseDrain = 4 << 10

	// maxTargetURLLen bounds the operator-supplied target.
	maxTargetURLLen = 2048

	// deliveryTimeout is the per-attempt HTTP deadline.
	deliveryTimeout = 10 * time.Second
)

// errPermanentDelivery marks a rejection that redelivery cannot fix — a bad
// signature, an unknown route, a malformed body. Retrying those is how a
// misconfigured secret turns into a self-inflicted denial of service.
var errPermanentDelivery = errors.New("simulator: webhook rejected permanently")

// SignPayload computes the X-Razorpay-Signature value: lowercase hex
// HMAC-SHA256 over the exact bytes on the wire.
//
// Over the exact bytes matters. Signing a re-marshalled copy of the payload
// would produce a signature that verifies against a body the receiver never
// saw, and would hide the one bug — sign-then-mutate — that makes an HMAC
// check worthless in practice.
func SignPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	// hash.Hash documents that Write never returns an error.
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SecretFingerprint is a short, non-reversible label for a shared secret.
//
// Two processes must agree on the webhook secret or nothing verifies, and the
// only safe way to help an operator confirm that is to print something derived
// from it. A truncated SHA-256 of a domain-separated input is that: it compares
// equal exactly when the secrets do, and reveals nothing that shortens a search
// for the secret itself.
func SecretFingerprint(secret string) string {
	if secret == "" {
		return "unset"
	}
	sum := sha256.Sum256([]byte("razorpay-sim/webhook-secret\x00" + secret))
	return hex.EncodeToString(sum[:4])
}

// emitterConfig is the emitter's dependency set, gathered into a struct so the
// constructor's signature does not become a positional puzzle.
type emitterConfig struct {
	Target    string
	Secret    string
	AccountID string
	Seed      int64
	Client    *http.Client
	Clock     domain.Clock
	Log       *slog.Logger
	Metrics   *obs.Registry

	// After is the delay primitive. It is injected so tests exercise the real
	// backoff logic without spending real seconds in it.
	After func(time.Duration) <-chan time.Time
}

// emitter signs and delivers webhooks to the mesh.
type emitter struct {
	target    string
	secret    string
	accountID string
	client    *http.Client
	clock     domain.Clock
	log       *slog.Logger
	metrics   *obs.Registry
	after     func(time.Duration) <-chan time.Time

	// mu guards jitter only. The generator is shared by concurrent deliveries
	// and math/rand.Rand is not safe for concurrent use; seeding it from the
	// run seed keeps a single-threaded run reproducible.
	mu     sync.Mutex
	jitter *rand.Rand
}

// newEmitter validates the destination before anything is signed for it.
//
// An empty secret is refused outright. Emitting unsigned or zero-key-signed
// webhooks would make every downstream HMAC check pass for an attacker who
// guessed the empty string, which is the fail-open case this whole system is
// built to avoid.
func newEmitter(cfg emitterConfig) (*emitter, error) {
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("simulator: webhook target is required")
	}
	if len(target) > maxTargetURLLen {
		return nil, fmt.Errorf("simulator: webhook target exceeds %d bytes", maxTargetURLLen)
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("simulator: parse webhook target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("simulator: webhook target scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("simulator: webhook target has no host")
	}
	if u.User != nil {
		return nil, errors.New("simulator: webhook target must not embed credentials")
	}
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("simulator: webhook secret is required to sign deliveries")
	}

	client := cfg.Client
	if client == nil {
		// Not http.DefaultClient: this process must not mutate a client other
		// packages share.
		client = &http.Client{Timeout: deliveryTimeout}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = obs.NewRegistry()
	}
	after := cfg.After
	if after == nil {
		after = time.After
	}

	return &emitter{
		target:    u.String(),
		secret:    cfg.Secret,
		accountID: cfg.AccountID,
		client:    client,
		clock:     clock,
		log:       log,
		metrics:   metrics,
		after:     after,
		jitter:    rand.New(rand.NewSource(scriptSeed(cfg.Seed, "webhook-jitter"))),
	}, nil
}

// BuildPayload renders a scheduled event as the webhook envelope Razorpay
// delivers.
func BuildPayload(ev ScheduledEvent, accountID string, at time.Time) domain.RazorpayWebhookPayload {
	contains := []string{"payment"}
	envelope := domain.PaymentPayloadEnvelope{
		Payment: domain.PaymentEntityContainer{Entity: ev.Payment},
	}
	if ev.Subscription != nil {
		contains = append(contains, "subscription")
		envelope.Subscription = &domain.SubscriptionEntityContainer{Entity: *ev.Subscription}
	}
	return domain.RazorpayWebhookPayload{
		Entity:    "event",
		AccountID: accountID,
		Event:     ev.Event,
		Contains:  contains,
		Payload:   envelope,
		CreatedAt: at.Unix(),
	}
}

// Emit delivers one scheduled event, and delivers it a second time when the
// script marked it a duplicate.
//
// The duplicate is byte-identical and carries the same event id, because that
// is what a real duplicate delivery looks like: a receiver that deduplicates on
// anything other than the event id would pass a test built from re-generated
// payloads and fail in production.
func (e *emitter) Emit(ctx context.Context, ev ScheduledEvent) error {
	payload := BuildPayload(ev, e.accountID, e.clock.Now())
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("simulator: marshal webhook payload for %s: %w", ev.EventID, err)
	}

	if err := e.deliver(ctx, body, ev.EventID, false); err != nil {
		return err
	}
	if !ev.Duplicate {
		return nil
	}
	if err := e.deliver(ctx, body, ev.EventID, true); err != nil {
		return err
	}
	return nil
}

// deliver posts one body, retrying transient rejections with exponential
// backoff and full jitter.
func (e *emitter) deliver(ctx context.Context, body []byte, eventID string, duplicate bool) error {
	signature := SignPayload(e.secret, body)
	var lastErr error

	for attempt := 1; attempt <= maxDeliveryAttempts; attempt++ {
		started := e.clock.Now()
		retryAfter, err := e.post(ctx, body, signature, eventID)
		e.metrics.Histogram("sim_webhook_latency_ms").ObserveDuration(e.clock.Now().Sub(started))

		switch {
		case err == nil:
			e.metrics.Counter("sim_webhook_delivered").Inc()
			if duplicate {
				e.metrics.Counter("sim_webhook_duplicates").Inc()
			}
			e.log.Debug("webhook delivered",
				"event_id", eventID, "attempt", attempt, "duplicate", duplicate)
			return nil

		case errors.Is(err, errPermanentDelivery):
			e.metrics.Counter("sim_webhook_rejected").Inc()
			// Logged at warn, not error: a rejected delivery is usually a
			// mismatched secret between this process and the mesh, and that is
			// an operator problem worth surfacing loudly but not a crash.
			e.log.Warn("webhook rejected permanently, not retrying",
				"event_id", eventID, "attempt", attempt, "cause", err.Error())
			return err

		case ctx.Err() != nil:
			return fmt.Errorf("simulator: webhook delivery cancelled for %s: %w", eventID, ctx.Err())
		}

		lastErr = err
		e.metrics.Counter("sim_webhook_retries").Inc()
		if attempt == maxDeliveryAttempts {
			break
		}
		if werr := e.wait(ctx, e.backoff(attempt, retryAfter)); werr != nil {
			return werr
		}
	}

	e.metrics.Counter("sim_webhook_failed").Inc()
	return fmt.Errorf("simulator: webhook %s undelivered after %d attempts: %w",
		eventID, maxDeliveryAttempts, lastErr)
}

// post performs a single delivery and reports any Retry-After the target asked
// for. A returned error wrapping errPermanentDelivery means stop.
func (e *emitter) post(ctx context.Context, body []byte, signature, eventID string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("simulator: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", signature)
	req.Header.Set("X-Razorpay-Event-Id", eventID)
	req.Header.Set("User-Agent", "Razorpay-Webhook/1.0 (razorpay-sim)")
	req.ContentLength = int64(len(body))

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("simulator: post webhook: %w", err)
	}
	defer func() {
		_, _ = io.CopyN(io.Discard, resp.Body, maxResponseDrain)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return 0, nil
	}
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	if retryable(resp.StatusCode) {
		return retryAfter, fmt.Errorf("simulator: webhook target returned HTTP %d", resp.StatusCode)
	}
	return retryAfter, fmt.Errorf("%w: HTTP %d", errPermanentDelivery, resp.StatusCode)
}

// retryable splits statuses worth another attempt from statuses that only
// change if the operator changes something. Every 4xx except 408 and 429 says
// "this request is wrong", and repeating a wrong request is a retry storm.
func retryable(status int) bool {
	switch {
	case status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
		return true
	case status >= 500:
		return true
	default:
		return false
	}
}

// parseRetryAfter reads the delta-seconds form of the header, clamped. The HTTP
// date form is deliberately unsupported: it is vanishingly rare on an API
// backpressure path and parsing it would add a clock-skew dependency for no
// gain.
func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// backoff is exponential with full jitter, floored by any Retry-After the
// target asked for. Full jitter rather than a fixed schedule because every
// in-flight delivery retries against the same target at the same moment
// otherwise, which is how a recovering receiver gets knocked over again.
func (e *emitter) backoff(attempt int, retryAfter time.Duration) time.Duration {
	d := deliveryBaseBackoff << (attempt - 1)
	if d > deliveryMaxBackoff || d <= 0 {
		d = deliveryMaxBackoff
	}
	e.mu.Lock()
	jittered := time.Duration(e.jitter.Int63n(int64(d) + 1))
	e.mu.Unlock()

	if jittered < retryAfter {
		return retryAfter
	}
	return jittered
}

func (e *emitter) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("simulator: backoff interrupted: %w", ctx.Err())
	case <-e.after(d):
		return nil
	}
}

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// fixedClock is the injected Clock. Nothing in this package reads the wall
// clock during a test, so a failure is never a timing artefact.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFixedClock(t time.Time) *fixedClock { return &fixedClock{t: t} }

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// TestSignatureMatchesAKnownVector pins the signature to a value computed
// outside this package. Asserting against a locally recomputed HMAC would pass
// even if both sides were wrong in the same way; a fixed vector cannot.
func TestSignatureMatchesAKnownVector(t *testing.T) {
	t.Parallel()

	const (
		secret = "razorpay_webhook_secret_v1"
		body   = `{"entity":"event","event":"payment.failed"}`
		want   = "dc4db0d1fe5a63cae1b2d6379b379ea61408052fc54f53acd653b6eed2da169d"
	)
	if got := SignPayload(secret, []byte(body)); got != want {
		t.Fatalf("SignPayload = %s, want %s", got, want)
	}
}

// TestSignatureVerifiesTheWayIngestWill reproduces the receiver's exact
// procedure — hex-decode the header, then constant-time compare against a MAC
// over the raw bytes — because that is the only check that matters. A signature
// that is merely "an HMAC of something" is not a signature.
func TestSignatureVerifiesTheWayIngestWill(t *testing.T) {
	t.Parallel()

	const secret = "shared-webhook-secret"
	body := []byte(`{"entity":"event","event":"payment.failed","created_at":1773000000}`)

	verify := func(secret string, body []byte, header string) bool {
		raw, err := hex.DecodeString(header)
		if err != nil || len(raw) != sha256.Size {
			return false
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		return hmac.Equal(raw, mac.Sum(nil))
	}

	sig := SignPayload(secret, body)
	if !verify(secret, body, sig) {
		t.Fatal("a freshly signed body does not verify against the same secret")
	}
	if strings.ToLower(sig) != sig || len(sig) != hex.EncodedLen(sha256.Size) {
		t.Fatalf("signature %q is not %d lowercase hex characters", sig, hex.EncodedLen(sha256.Size))
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-2] = '1'
	if verify(secret, tampered, sig) {
		t.Fatal("a tampered body verified against the original signature")
	}
	if verify("a-different-secret", body, sig) {
		t.Fatal("the signature verified under the wrong secret")
	}
	if verify(secret, body, "not-hex") {
		t.Fatal("a malformed hex header verified")
	}
	if verify(secret, body, sig[:len(sig)-2]) {
		t.Fatal("a truncated signature verified")
	}
}

func TestSecretFingerprintIdentifiesWithoutRevealing(t *testing.T) {
	t.Parallel()

	const secret = "correct horse battery staple"
	fp := SecretFingerprint(secret)
	if fp != SecretFingerprint(secret) {
		t.Fatal("fingerprint is not stable")
	}
	if fp == SecretFingerprint(secret+"!") {
		t.Fatal("two different secrets share a fingerprint")
	}
	if strings.Contains(fp, secret) || len(fp) != 8 {
		t.Fatalf("fingerprint %q leaks or is the wrong length", fp)
	}
	if SecretFingerprint("") != "unset" {
		t.Fatal("an unset secret must be labelled, not fingerprinted")
	}
}

// capture is a recording webhook target.
type capture struct {
	mu       sync.Mutex
	bodies   [][]byte
	headers  []http.Header
	statuses []int
	respond  func(n int) (status int, retryAfter string)
}

func (c *capture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		c.mu.Lock()
		n := len(c.bodies)
		c.bodies = append(c.bodies, body)
		c.headers = append(c.headers, r.Header.Clone())
		c.mu.Unlock()

		status, retryAfter := http.StatusOK, ""
		if c.respond != nil {
			status, retryAfter = c.respond(n)
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		c.mu.Lock()
		c.statuses = append(c.statuses, status)
		c.mu.Unlock()
		w.WriteHeader(status)
	}
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func newTestEmitter(t *testing.T, target, secret string, after func(time.Duration) <-chan time.Time) *emitter {
	t.Helper()
	em, err := newEmitter(emitterConfig{
		Target:    target,
		Secret:    secret,
		AccountID: "acc_TestAccount01",
		Seed:      7,
		Clock:     newFixedClock(fixedStart),
		After:     after,
	})
	if err != nil {
		t.Fatalf("newEmitter: %v", err)
	}
	return em
}

func sampleEvent(t *testing.T, duplicate bool) ScheduledEvent {
	t.Helper()
	tl := newTestTimeline(t, ScenarioIssuerOutage, 42, 10*time.Minute)
	script, err := tl.Script(20, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if len(script) == 0 {
		t.Fatal("no events generated")
	}
	ev := script[0]
	ev.Duplicate = duplicate
	return ev
}

// TestEmitSignsTheExactBytesOnTheWire is the end-to-end version of the
// signature test: the target verifies what it actually received, not what the
// sender believes it sent.
func TestEmitSignsTheExactBytesOnTheWire(t *testing.T) {
	t.Parallel()

	const secret = "end-to-end-secret"
	cap := &capture{}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	em := newTestEmitter(t, ts.URL, secret, nil)
	ev := sampleEvent(t, false)
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if cap.count() != 1 {
		t.Fatalf("expected exactly one delivery, got %d", cap.count())
	}

	body, header := cap.bodies[0], cap.headers[0]
	if got := SignPayload(secret, body); got != header.Get("X-Razorpay-Signature") {
		t.Fatalf("signature over the received body is %s, header carried %s",
			got, header.Get("X-Razorpay-Signature"))
	}
	if got := header.Get("X-Razorpay-Event-Id"); got != ev.EventID {
		t.Fatalf("event id header is %q, want %q", got, ev.EventID)
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type is %q", got)
	}

	var payload domain.RazorpayWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("the delivered body is not a valid webhook payload: %v", err)
	}
	if payload.Entity != "event" || payload.Event != "payment.failed" {
		t.Fatalf("envelope is %+v", payload)
	}
	if payload.Payload.Payment.Entity.ID != ev.Payment.ID {
		t.Fatalf("payment id is %q, want %q", payload.Payload.Payment.Entity.ID, ev.Payment.ID)
	}
	if payload.Payload.Payment.Entity.Amount != ev.Payment.Amount {
		t.Fatalf("amount changed in transit: %d != %d",
			payload.Payload.Payment.Entity.Amount, ev.Payment.Amount)
	}
	if payload.CreatedAt != fixedStart.Unix() {
		t.Fatalf("created_at is %d, want %d", payload.CreatedAt, fixedStart.Unix())
	}
}

// TestDuplicateDeliveryIsByteIdentical asserts that a duplicate is a real
// duplicate. A receiver deduplicating on a body hash rather than the event id
// would pass a test built from re-generated payloads and fail against a real
// redelivery, so this pins both the bytes and the id.
func TestDuplicateDeliveryIsByteIdentical(t *testing.T) {
	t.Parallel()

	cap := &capture{}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	em := newTestEmitter(t, ts.URL, "dup-secret", nil)
	if err := em.Emit(context.Background(), sampleEvent(t, true)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if cap.count() != 2 {
		t.Fatalf("a duplicated event produced %d deliveries, want 2", cap.count())
	}
	if string(cap.bodies[0]) != string(cap.bodies[1]) {
		t.Fatal("the duplicate carried a different body")
	}
	if cap.headers[0].Get("X-Razorpay-Event-Id") != cap.headers[1].Get("X-Razorpay-Event-Id") {
		t.Fatal("the duplicate carried a different event id")
	}
	if cap.headers[0].Get("X-Razorpay-Signature") != cap.headers[1].Get("X-Razorpay-Signature") {
		t.Fatal("the duplicate carried a different signature")
	}
}

func TestEmitRetriesTransientRejections(t *testing.T) {
	t.Parallel()

	cap := &capture{respond: func(n int) (int, string) {
		if n < 2 {
			return http.StatusInternalServerError, ""
		}
		return http.StatusOK, ""
	}}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	var delays []time.Duration
	var mu sync.Mutex
	after := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}

	em := newTestEmitter(t, ts.URL, "retry-secret", after)
	if err := em.Emit(context.Background(), sampleEvent(t, false)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if cap.count() != 3 {
		t.Fatalf("expected 3 attempts, got %d", cap.count())
	}
	if len(delays) != 2 {
		t.Fatalf("expected 2 backoffs, got %d", len(delays))
	}
	for i, d := range delays {
		ceiling := deliveryBaseBackoff << i
		if ceiling > deliveryMaxBackoff {
			ceiling = deliveryMaxBackoff
		}
		if d < 0 || d > ceiling {
			t.Fatalf("backoff %d is %s, outside [0, %s]", i, d, ceiling)
		}
	}
	if string(cap.bodies[0]) != string(cap.bodies[2]) {
		t.Fatal("a retry re-marshalled the payload instead of resending the signed bytes")
	}
}

// TestEmitDoesNotRetryPermanentRejections is the anti-storm assertion. A
// mismatched webhook secret makes every delivery a 400; retrying those would
// turn a configuration mistake into a self-inflicted flood.
func TestEmitDoesNotRetryPermanentRejections(t *testing.T) {
	t.Parallel()

	cap := &capture{respond: func(int) (int, string) { return http.StatusBadRequest, "" }}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	em := newTestEmitter(t, ts.URL, "bad-secret", nil)
	err := em.Emit(context.Background(), sampleEvent(t, false))
	if err == nil {
		t.Fatal("expected an error for a permanently rejected delivery")
	}
	if cap.count() != 1 {
		t.Fatalf("a 400 was retried: %d attempts", cap.count())
	}
}

func TestEmitGivesUpAfterTheAttemptCeiling(t *testing.T) {
	t.Parallel()

	cap := &capture{respond: func(int) (int, string) { return http.StatusBadGateway, "" }}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	after := func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	em := newTestEmitter(t, ts.URL, "give-up-secret", after)
	if err := em.Emit(context.Background(), sampleEvent(t, false)); err == nil {
		t.Fatal("expected an error after the attempt ceiling")
	}
	if cap.count() != maxDeliveryAttempts {
		t.Fatalf("made %d attempts, want %d", cap.count(), maxDeliveryAttempts)
	}
}

// TestEmitHonoursRetryAfter proves the emitter respects the edge's admission
// control instead of ignoring it and re-flooding a shedding receiver.
func TestEmitHonoursRetryAfter(t *testing.T) {
	t.Parallel()

	cap := &capture{respond: func(n int) (int, string) {
		if n == 0 {
			return http.StatusServiceUnavailable, "3"
		}
		return http.StatusOK, ""
	}}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	var delays []time.Duration
	var mu sync.Mutex
	after := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	em := newTestEmitter(t, ts.URL, "shed-secret", after)
	if err := em.Emit(context.Background(), sampleEvent(t, false)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(delays) != 1 {
		t.Fatalf("expected one backoff, got %d", len(delays))
	}
	if delays[0] < 3*time.Second {
		t.Fatalf("backoff %s ignored a Retry-After of 3s", delays[0])
	}
}

func TestParseRetryAfterIsBounded(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"abc", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0},
		{"2", 2 * time.Second},
		{"100000", maxRetryAfter},
	} {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestEmitStopsOnContextCancellation(t *testing.T) {
	t.Parallel()

	cap := &capture{respond: func(int) (int, string) { return http.StatusBadGateway, "" }}
	ts := httptest.NewServer(cap.handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	em := newTestEmitter(t, ts.URL, "cancel-secret", func(time.Duration) <-chan time.Time {
		cancel()
		return make(chan time.Time)
	})
	if err := em.Emit(ctx, sampleEvent(t, false)); err == nil {
		t.Fatal("expected an error when the context is cancelled mid-backoff")
	}
}

// TestNewEmitterFailsClosed covers every way a misconfiguration could produce a
// sender that emits unsigned or misdirected traffic.
func TestNewEmitterFailsClosed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		target string
		secret string
	}{
		{"empty target", "", "s"},
		{"no scheme", "127.0.0.1:8080/hook", "s"},
		{"unsupported scheme", "ftp://example.test/hook", "s"},
		{"no host", "http:///hook", "s"},
		{"credentials in url", "http://user:pass@example.test/hook", "s"},
		{"empty secret", "http://example.test/hook", ""},
		{"blank secret", "http://example.test/hook", "   "},
		{"oversized target", "http://example.test/" + strings.Repeat("a", maxTargetURLLen), "s"},
	} {
		if _, err := newEmitter(emitterConfig{Target: tc.target, Secret: tc.secret}); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

func TestBuildPayloadCarriesSubscriptionWhenPresent(t *testing.T) {
	t.Parallel()

	tl := newTestTimeline(t, ScenarioMandateBatch, 31, 20*time.Minute)
	script, err := tl.Script(25, 0)
	if err != nil {
		t.Fatalf("script: %v", err)
	}

	var recurring, plain *ScheduledEvent
	for i := range script {
		ev := &script[i]
		if ev.Subscription != nil && recurring == nil {
			recurring = ev
		}
		if ev.Subscription == nil && plain == nil {
			plain = ev
		}
	}
	if recurring == nil || plain == nil {
		t.Skip("scenario did not produce both recurring and one-off events at this seed")
	}

	got := BuildPayload(*recurring, "acc_X", fixedStart)
	if len(got.Contains) != 2 || got.Contains[1] != "subscription" {
		t.Fatalf("recurring envelope contains %v", got.Contains)
	}
	if got.Payload.Subscription == nil || got.Payload.Subscription.Entity.ID != recurring.Subscription.ID {
		t.Fatal("recurring envelope lost its subscription entity")
	}

	one := BuildPayload(*plain, "acc_X", fixedStart)
	if len(one.Contains) != 1 || one.Contains[0] != "payment" {
		t.Fatalf("one-off envelope contains %v", one.Contains)
	}
	if one.Payload.Subscription != nil {
		t.Fatal("a one-off payment carried a subscription container")
	}
}

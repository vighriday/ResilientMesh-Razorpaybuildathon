package simulator

import (
	"encoding/json"
	"fmt"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

const testKeySecret = "3v3ry0n3Kn0wsTh1sIsATest"

// testKeyID is composed rather than written out: a sandbox-shaped key
// literal is indistinguishable from a real one to a secret scanner.
var testKeyID = testsecret.TestKeyID("A1b2C3d4E5f6")

func newTestServer(t *testing.T, scenario string, clock *fixedClock) *server {
	t.Helper()
	tl, err := NewTimeline(scenario, 42, fixedStart, time.Hour)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}
	srv, err := newServer(serverConfig{
		Timeline:  tl,
		Clock:     clock,
		KeyID:     testKeyID,
		KeySecret: testKeySecret,
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return srv
}

type requestOpts struct {
	method      string
	path        string
	body        string
	contentType string
	keyID       string
	keySecret   string
	noAuth      bool
}

func do(t *testing.T, srv *server, o requestOpts) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if o.body == "" {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(o.body)
	}
	req := httptest.NewRequest(o.method, o.path, body)
	if o.contentType != "" {
		req.Header.Set("Content-Type", o.contentType)
	} else if o.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if !o.noAuth {
		id, secret := o.keyID, o.keySecret
		if id == "" && secret == "" {
			id, secret = testKeyID, testKeySecret
		}
		req.SetBasicAuth(id, secret)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not an error envelope (%d): %s", rec.Code, rec.Body.String())
	}
	return env.Error
}

// TestAuthRejectsBadCredentials sweeps every way a caller can present the wrong
// thing. Each must be a 401 with the same opaque body: a response that
// distinguishes "unknown key" from "wrong secret" is a guessing oracle.
func TestAuthRejectsBadCredentials(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	protected := []string{
		"/v1/downtimes",
		"/v1/downtimes/down_anything00",
		"/v1/payments/pay_abcdefghij1234",
		"/sim/metrics",
	}

	cases := []struct {
		name   string
		opts   requestOpts
		expect int
	}{
		{"no credentials", requestOpts{noAuth: true}, http.StatusUnauthorized},
		{"empty pair", requestOpts{keyID: " ", keySecret: " "}, http.StatusUnauthorized},
		{"wrong key id", requestOpts{keyID: testsecret.TestKeyID("wrong000000"), keySecret: testKeySecret}, http.StatusUnauthorized},
		{"wrong secret", requestOpts{keyID: testKeyID, keySecret: "wrong"}, http.StatusUnauthorized},
		{"both wrong", requestOpts{keyID: "x", keySecret: "y"}, http.StatusUnauthorized},
		{"swapped pair", requestOpts{keyID: testKeySecret, keySecret: testKeyID}, http.StatusUnauthorized},
		{"secret as prefix", requestOpts{keyID: testKeyID, keySecret: testKeySecret[:len(testKeySecret)-1]}, http.StatusUnauthorized},
		{"secret with suffix", requestOpts{keyID: testKeyID, keySecret: testKeySecret + "!"}, http.StatusUnauthorized},
		{"correct pair", requestOpts{}, http.StatusOK},
	}

	for _, path := range protected {
		for _, tc := range cases {
			opts := tc.opts
			opts.method = http.MethodGet
			opts.path = path
			rec := do(t, srv, opts)

			want := tc.expect
			// An authenticated request for a downtime that does not exist is a
			// 404; the point of the sweep is that it is not a 401.
			if want == http.StatusOK && strings.HasPrefix(path, "/v1/downtimes/down_") {
				want = http.StatusNotFound
			}
			if rec.Code != want {
				t.Errorf("%s %s: status %d, want %d", tc.name, path, rec.Code, want)
				continue
			}
			if rec.Code != http.StatusUnauthorized {
				continue
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
				t.Errorf("%s %s: WWW-Authenticate is %q", tc.name, path, got)
			}
			body := decodeError(t, rec)
			if body.Description != "Authentication failed" {
				t.Errorf("%s %s: description %q leaks which half failed", tc.name, path, body.Description)
			}
		}
	}
}

func TestBearerTokenIsNotAcceptedAsBasicAuth(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	req := httptest.NewRequest(http.MethodGet, "/v1/downtimes", nil)
	req.Header.Set("Authorization", "Bearer "+testKeySecret)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a bearer token was accepted: %d", rec.Code)
	}
}

func TestHealthzNeedsNoCredentials(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/healthz", noAuth: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz returned %d", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("security headers missing: %q", got)
	}
}

// TestNewServerRefusesEmptyCredentials guards the bypass that an empty expected
// secret would create: a constant-time comparison against "" succeeds for a
// caller who presents "".
func TestNewServerRefusesEmptyCredentials(t *testing.T) {
	t.Parallel()

	tl, err := NewTimeline(ScenarioIssuerOutage, 1, fixedStart, time.Hour)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}
	for _, tc := range []struct{ id, secret string }{
		{"", ""},
		{testKeyID, ""},
		{"", testKeySecret},
		{"  ", "  "},
	} {
		if _, err := newServer(serverConfig{Timeline: tl, KeyID: tc.id, KeySecret: tc.secret}); err == nil {
			t.Errorf("newServer accepted id=%q secret=%q", tc.id, tc.secret)
		}
	}
	if _, err := newServer(serverConfig{KeyID: testKeyID, KeySecret: testKeySecret}); err == nil {
		t.Error("newServer accepted a nil timeline")
	}
}

func TestDowntimeListEndpointServesTheDomainSchema(t *testing.T) {
	t.Parallel()

	clock := newFixedClock(fixedStart.Add(30 * time.Minute)) // inside the HDFC window
	srv := newTestServer(t, ScenarioIssuerOutage, clock)

	rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/downtimes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type is %q", ct)
	}

	var list domain.DowntimeList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("body does not decode as domain.DowntimeList: %v", err)
	}
	if list.Entity != "collection" || list.Count != len(list.Items) || list.Count == 0 {
		t.Fatalf("envelope is %+v", list)
	}
	item := list.Items[0]
	if item.Status != domain.DowntimeStarted || item.End != nil {
		t.Fatalf("mid-window item is %+v", item)
	}
	if item.TelemetryKey() != "netbanking:HDFC" {
		t.Fatalf("telemetry key is %q, want netbanking:HDFC", item.TelemetryKey())
	}

	// The same endpoint after resolution must report the transition.
	clock.Set(fixedStart.Add(50 * time.Minute))
	rec = do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/downtimes"})
	var resolved domain.DowntimeList
	if err := json.Unmarshal(rec.Body.Bytes(), &resolved); err != nil {
		t.Fatalf("second body does not decode: %v", err)
	}
	if len(resolved.Items) != 1 || resolved.Items[0].Status != domain.DowntimeResolved {
		t.Fatalf("expected one resolved item, got %+v", resolved.Items)
	}
	if resolved.Items[0].ID != item.ID {
		t.Fatal("the resolved notice carries a different id than the started one")
	}
}

func TestDowntimeGetByID(t *testing.T) {
	t.Parallel()

	clock := newFixedClock(fixedStart.Add(30 * time.Minute))
	srv := newTestServer(t, ScenarioIssuerOutage, clock)
	id := srv.timeline.Windows()[0].ID

	rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/downtimes/" + id})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var entity domain.DowntimeEntity
	if err := json.Unmarshal(rec.Body.Bytes(), &entity); err != nil {
		t.Fatalf("body does not decode as domain.DowntimeEntity: %v", err)
	}
	if entity.ID != id || entity.Entity != "payment.downtime" {
		t.Fatalf("entity is %+v", entity)
	}

	rec = do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/downtimes/down_doesNotExist"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id returned %d, want 404", rec.Code)
	}
	rec = do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/downtimes/pay_wrongPrefix1"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed id returned %d, want 400", rec.Code)
	}
	rec = do(t, srv, requestOpts{method: http.MethodGet,
		path: "/v1/downtimes/down_" + strings.Repeat("a", maxIdentifierLen)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized id returned %d, want 400", rec.Code)
	}
}

// seedPayment registers a payment with a chosen failure so a test can drive one
// branch of the outcome model without hunting for a matching generated event.
func seedPayment(srv *server, id, method, bank, code string, amount int64) domain.PaymentEntity {
	fc := failureCatalog[code]
	p := domain.PaymentEntity{
		ID:          id,
		Amount:      amount,
		Currency:    "INR",
		Status:      "failed",
		OrderID:     "order_" + strings.Repeat("z", idBodyLen),
		Method:      method,
		Bank:        bank,
		ErrorCode:   code,
		ErrorReason: code,
		ErrorStep:   fc.Step,
		ErrorSource: fc.Source,
		ErrorDesc:   fc.Description,
	}
	srv.payments.put(p)
	return p
}

func payID(n int) string { return razorID("pay", 42, "server-test", fmt.Sprintf("%d", n)) }

// TestRetryRefusesToRestateTheAmount is the simulator's half of amount pinning.
// A gateway that accepted a different amount on a retry would let the mesh's
// most important invariant break without any test failing.
func TestRetryRefusesToRestateTheAmount(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	p := seedPayment(srv, payID(1), "netbanking", "HDFC", "bank_technical_error", 149900)

	rec := do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + p.ID + "/retry",
		body: `{"amount":999900}`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a mutated amount returned %d, want 400", rec.Code)
	}
	if got := decodeError(t, rec).Reason; got != "input_validation_failed" {
		t.Fatalf("reason is %q, want input_validation_failed", got)
	}

	// The matching amount must reach the outcome model rather than the
	// validator, whichever way the issuer then decides.
	rec = do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + p.ID + "/retry",
		body: `{"amount":149900}`})
	if rec.Code == http.StatusBadRequest && decodeError(t, rec).Reason == "input_validation_failed" {
		t.Fatal("a matching amount was rejected as invalid")
	}
}

func TestCaptureEnforcesTheAuthorizedAmount(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	p := seedPayment(srv, payID(2), "card", "HDFC", "payment_timed_out", 250000)
	path := "/v1/payments/" + p.ID + "/capture"

	for _, tc := range []struct{ name, body, contentType string }{
		{"missing amount", `{}`, "application/json"},
		{"mismatched amount", `{"amount":250001}`, "application/json"},
		{"fractional amount", `{"amount":2500.5}`, "application/json"},
		{"amount as string", `{"amount":"2500.00"}`, "application/json"},
		{"wrong currency", `{"amount":250000,"currency":"USD"}`, "application/json"},
		{"form mismatch", "amount=1&currency=INR", "application/x-www-form-urlencoded"},
	} {
		rec := do(t, srv, requestOpts{method: http.MethodPost, path: path, body: tc.body, contentType: tc.contentType})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tc.name, rec.Code)
			continue
		}
		if got := decodeError(t, rec).Reason; got != "input_validation_failed" {
			t.Errorf("%s: reason %q, want input_validation_failed", tc.name, got)
		}
	}

	// The form encoding the official SDKs send must work when it is correct.
	rec := do(t, srv, requestOpts{method: http.MethodPost, path: path,
		body: "amount=250000&currency=INR", contentType: "application/x-www-form-urlencoded"})
	if rec.Code == http.StatusBadRequest && decodeError(t, rec).Reason == "input_validation_failed" {
		t.Fatalf("a correct form-encoded capture was rejected: %s", rec.Body.String())
	}
}

// TestTerminalDeclineNeverRecovers is the taxonomy's most important behaviour.
// If the simulator ever let a blocked instrument succeed, a blind-retry policy
// would score points it has no right to and the benchmark would understate the
// value of abstaining.
func TestTerminalDeclineNeverRecovers(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	for code := range domain.TerminalDeclineCodes {
		if _, ok := failureCatalog[code]; !ok {
			continue
		}
		p := seedPayment(srv, payID(len(code)+100), "card", "HDFC", code, 99900)
		for attempt := 1; attempt <= 25; attempt++ {
			rec := do(t, srv, requestOpts{method: http.MethodPost,
				path: fmt.Sprintf("/v1/payments/%s/retry", p.ID),
				body: fmt.Sprintf(`{"attempt":%d}`, attempt)})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: attempt %d returned %d, want a decline", code, attempt, rec.Code)
			}
			if got := decodeError(t, rec).Reason; got != code {
				t.Fatalf("%s: attempt %d declined with %q instead", code, attempt, got)
			}
		}
	}
}

// TestRefreshRecoversOnlyWhenThePresentationChanges is the behaviour that makes
// the instrument-refresh action worth having: an expired card retried unchanged
// can never work, and the same card re-presented as a network token usually
// does.
func TestRefreshRecoversOnlyWhenThePresentationChanges(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	const trials = 300

	for code := range domain.RefreshableDeclineCodes {
		unchangedSuccess, tokenSuccess := 0, 0
		for i := 0; i < trials; i++ {
			id := razorID("pay", 42, "refresh", code, fmt.Sprintf("%d", i))
			seedPayment(srv, id, "card", "HDFC", code, 199900)

			if do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + id + "/retry",
				body: `{"attempt":1}`}).Code == http.StatusOK {
				unchangedSuccess++
			}
			if do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + id + "/retry",
				body: `{"attempt":1,"presentation":"network_token"}`}).Code == http.StatusOK {
				tokenSuccess++
			}
		}
		if unchangedSuccess != 0 {
			t.Errorf("%s: %d of %d unchanged retries succeeded; a stale credential cannot recover unchanged",
				code, unchangedSuccess, trials)
		}
		rate := float64(tokenSuccess) / float64(trials)
		if rate < 0.60 || rate > 0.80 {
			t.Errorf("%s: network-token refresh succeeded %.2f of the time, want near %.2f",
				code, rate, float64(refreshSuccessPerMille)/perMille)
		}
	}
}

// TestRetryOutcomeIsIdempotentPerAttempt matters because the mesh may resend a
// retry it never saw the response to. A gateway that re-rolled the dice would
// make a timeout indistinguishable from a decline.
func TestRetryOutcomeIsIdempotentPerAttempt(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	p := seedPayment(srv, payID(3), "netbanking", "ICIC", "payment_timed_out", 349900)

	var first int
	for i := 0; i < 12; i++ {
		rec := do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + p.ID + "/retry",
			body: `{"attempt":2}`})
		if i == 0 {
			first = rec.Code
			continue
		}
		if rec.Code != first {
			t.Fatalf("repeat %d of the same attempt returned %d, first returned %d", i, rec.Code, first)
		}
	}
}

// TestRetrySucceedsOnceTheDowntimeResolves is the offline proof of the
// downtime-resolution retry release: the identical request that fails during
// the outage succeeds after the resolution notice, which is what makes the
// release mechanism worth building.
func TestRetrySucceedsOnceTheDowntimeResolves(t *testing.T) {
	t.Parallel()

	clock := newFixedClock(fixedStart.Add(30 * time.Minute)) // inside the HDFC window
	srv := newTestServer(t, ScenarioIssuerOutage, clock)

	const trials = 200
	ids := make([]string, trials)
	for i := range ids {
		ids[i] = razorID("pay", 42, "release", fmt.Sprintf("%d", i))
		seedPayment(srv, ids[i], "netbanking", "HDFC", "bank_technical_error", 129900)
	}

	countSuccess := func(attempt int) int {
		n := 0
		for _, id := range ids {
			rec := do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + id + "/retry",
				body: fmt.Sprintf(`{"attempt":%d}`, attempt)})
			if rec.Code == http.StatusOK {
				n++
			}
		}
		return n
	}

	during := float64(countSuccess(1)) / trials
	if during > 0.20 {
		t.Fatalf("%.2f of retries succeeded during a 94%% outage", during)
	}

	// Re-seed: a captured payment is no longer failed, and the point of the
	// second half is the issuer's health, not the payment's state machine.
	for _, id := range ids {
		seedPayment(srv, id, "netbanking", "HDFC", "bank_technical_error", 129900)
	}
	clock.Set(fixedStart.Add(50 * time.Minute)) // after resolution
	after := float64(countSuccess(2)) / trials
	if after < 0.80 {
		t.Fatalf("only %.2f of retries succeeded after the outage resolved", after)
	}
	if after <= during {
		t.Fatalf("resolution did not improve the success rate: %.2f before, %.2f after", during, after)
	}
}

// TestUnknownPaymentIsSynthesisedDeterministically covers the restart case: a
// payment the mesh is still recovering must resolve to the same entity after
// this process is restarted, or a recovery in flight becomes unrecoverable.
func TestUnknownPaymentIsSynthesisedDeterministically(t *testing.T) {
	t.Parallel()

	id := razorID("pay", 42, "unknown-to-the-process")
	clock := newFixedClock(fixedStart)

	fetch := func() domain.PaymentEntity {
		srv := newTestServer(t, ScenarioIssuerOutage, clock)
		rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/payments/" + id})
		if rec.Code != http.StatusOK {
			t.Fatalf("fetch of an unknown payment returned %d: %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Entity string `json:"entity"`
			domain.PaymentEntity
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if env.Entity != "payment" {
			t.Fatalf("entity is %q", env.Entity)
		}
		return env.PaymentEntity
	}

	first, second := fetch(), fetch()
	if first != second {
		t.Fatalf("two processes synthesised different payments for %s:\n%+v\n%+v", id, first, second)
	}
	if first.Amount <= 0 || first.Amount%100 != 0 {
		t.Fatalf("synthesised amount %d is not a positive whole rupee", first.Amount)
	}
	if first.Currency != "INR" || first.Status != "failed" || first.ErrorCode == "" {
		t.Fatalf("synthesised payment is not a plausible failure: %+v", first)
	}
	if !knownToTaxonomy(first.ErrorCode) {
		t.Fatalf("synthesised error code %q is outside the taxonomy", first.ErrorCode)
	}
}

func TestMalformedPaymentIdentifiersAreRejected(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	for _, id := range []string{
		"pay_",
		"order_abcdefghij1234",
		"pay_with-a-dash",
		"pay_" + strings.Repeat("a", maxIdentifierLen),
		"pay_%2e%2e",
	} {
		rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/payments/" + id})
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("identifier %q returned %d, want a rejection", id, rec.Code)
		}
	}
}

func TestValidRazorIDBoundsItsInput(t *testing.T) {
	t.Parallel()

	if validRazorID("pay", "pay_"+strings.Repeat("a", maxIdentifierLen)) {
		t.Fatal("an over-long identifier was accepted")
	}
	if validRazorID("pay", "pay_") {
		t.Fatal("an empty body was accepted")
	}
	if validRazorID("pay", "PAY_abcdef") {
		t.Fatal("the prefix comparison is case-insensitive")
	}
	if !validRazorID("pay", "pay_aZ09") {
		t.Fatal("a well-formed identifier was rejected")
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	p := seedPayment(srv, payID(4), "upi", "", "upi_psp_error", 50000)
	huge := `{"amount":50000,"pad":"` + strings.Repeat("A", maxRequestBody+1024) + `"}`

	rec := do(t, srv, requestOpts{method: http.MethodPost, path: "/v1/payments/" + p.ID + "/capture", body: huge})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body returned %d, want 400", rec.Code)
	}
}

func TestUnknownRouteReturnsTheRazorpayErrorShape(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ScenarioIssuerOutage, newFixedClock(fixedStart))
	rec := do(t, srv, requestOpts{method: http.MethodGet, path: "/v1/orders", noAuth: true})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if got := decodeError(t, rec).Code; got != "BAD_REQUEST_ERROR" {
		t.Fatalf("error code is %q", got)
	}
}

func TestCapturedPaymentCarriesIntegerFees(t *testing.T) {
	t.Parallel()

	env := envelopeFor(domain.PaymentEntity{ID: "pay_x", Amount: 1_000_00, Currency: "INR", Status: "captured"})
	if !env.Captured {
		t.Fatal("a captured payment is not flagged captured")
	}
	// 2.36% of Rs 1,000 is Rs 23.60; the GST share of that is Rs 3.60.
	if env.Fee != 2360 {
		t.Fatalf("fee is %d paisa, want 2360", env.Fee)
	}
	if env.Tax != 360 {
		t.Fatalf("tax is %d paisa, want 360", env.Tax)
	}

	failed := envelopeFor(domain.PaymentEntity{ID: "pay_y", Amount: 1_000_00, Status: "failed"})
	if failed.Captured || failed.Fee != 0 || failed.Tax != 0 {
		t.Fatalf("a failed payment carries fees: %+v", failed)
	}
}

func TestPaymentRegistryEvictsOldestFirst(t *testing.T) {
	t.Parallel()

	r := newPaymentRegistry(3)
	for i := 0; i < 5; i++ {
		r.put(domain.PaymentEntity{ID: fmt.Sprintf("pay_%d", i)})
	}
	if r.size() != 3 {
		t.Fatalf("registry holds %d entries, want 3", r.size())
	}
	if _, ok := r.get("pay_0"); ok {
		t.Fatal("the oldest entry survived eviction")
	}
	if _, ok := r.get("pay_4"); !ok {
		t.Fatal("the newest entry was evicted")
	}

	// Re-putting an existing id must not consume a second slot.
	r.put(domain.PaymentEntity{ID: "pay_4", Amount: 1})
	if r.size() != 3 {
		t.Fatalf("an update grew the registry to %d", r.size())
	}
	if got, _ := r.get("pay_4"); got.Amount != 1 {
		t.Fatal("an update did not replace the stored entity")
	}
}

// Not parallel: it manipulates the process environment.
func TestTargetResolution(t *testing.T) {
	t.Setenv(envSimulatorTarget, "")
	if got := resolveTarget("http://explicit.test/hook", ":8080"); got != "http://explicit.test/hook" {
		t.Fatalf("the flag did not win: %q", got)
	}
	if got := resolveTarget("", ":8080"); got != "http://127.0.0.1:8080"+defaultWebhookPath {
		t.Fatalf("wildcard address derived %q", got)
	}
	if got := resolveTarget("", "0.0.0.0:9000"); got != "http://127.0.0.1:9000"+defaultWebhookPath {
		t.Fatalf("0.0.0.0 derived %q", got)
	}
	if got := resolveTarget("", "10.0.0.4:8080"); got != "http://10.0.0.4:8080"+defaultWebhookPath {
		t.Fatalf("explicit host derived %q", got)
	}
	if got := resolveTarget("", "not-an-address"); got != "" {
		t.Fatalf("an unparseable address derived %q", got)
	}

	t.Setenv(envSimulatorTarget, "http://from-env.test/hook")
	if got := resolveTarget("", ":8080"); got != "http://from-env.test/hook" {
		t.Fatalf("the environment did not win over the derived default: %q", got)
	}
	if got := resolveTarget("http://flag.test/hook", ":8080"); got != "http://flag.test/hook" {
		t.Fatalf("the environment beat the flag: %q", got)
	}

	t.Setenv(envSimulatorTarget, "http://x.test/"+strings.Repeat("a", maxEnvValueLen*2))
	if got := resolveTarget("", ":8080"); len(got) != maxEnvValueLen {
		t.Fatalf("an oversized environment value was not bounded: %d bytes", len(got))
	}
}

// TestCapturedPaymentIsIdempotentOnRetry covers the lost-response case: the
// mesh re-presents a payment whose success it never saw. Anything other than a
// repeated success here makes a dropped response look like a decline, which is
// the shape of a double-charge bug.
func TestCapturedPaymentIsIdempotentOnRetry(t *testing.T) {
	t.Parallel()

	clock := newFixedClock(fixedStart.Add(50 * time.Minute)) // after the outage resolves
	srv := newTestServer(t, ScenarioIssuerOutage, clock)

	var id string
	for i := 0; i < 60 && id == ""; i++ {
		candidate := razorID("pay", 42, "idempotent-capture", fmt.Sprintf("%d", i))
		seedPayment(srv, candidate, "netbanking", "HDFC", "bank_technical_error", 99900)
		if do(t, srv, requestOpts{method: http.MethodPost,
			path: "/v1/payments/" + candidate + "/retry", body: `{"attempt":1}`}).Code == http.StatusOK {
			id = candidate
		}
	}
	if id == "" {
		t.Fatal("no retry succeeded against a healthy issuer in 60 tries")
	}

	for attempt := 2; attempt <= 5; attempt++ {
		rec := do(t, srv, requestOpts{method: http.MethodPost,
			path: "/v1/payments/" + id + "/retry", body: fmt.Sprintf(`{"attempt":%d}`, attempt)})
		if rec.Code != http.StatusOK {
			t.Fatalf("re-presenting a captured payment on attempt %d returned %d: %s",
				attempt, rec.Code, rec.Body.String())
		}
		var env paymentEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if env.Status != "captured" || !env.Captured {
			t.Fatalf("attempt %d returned a non-captured entity: %+v", attempt, env)
		}
		if env.Amount != 99900 {
			t.Fatalf("attempt %d changed the amount to %d", attempt, env.Amount)
		}
		if env.ErrorCode != "" {
			t.Fatalf("attempt %d resurrected an error code: %q", attempt, env.ErrorCode)
		}
	}
}

func TestPaymentRegistryDefaultsItsLimit(t *testing.T) {
	t.Parallel()

	if got := newPaymentRegistry(0).limit; got != maxTrackedPayments {
		t.Fatalf("an unset limit is %d, want %d", got, maxTrackedPayments)
	}
	if got := newPaymentRegistry(-1).limit; got != maxTrackedPayments {
		t.Fatalf("a negative limit is %d, want %d", got, maxTrackedPayments)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ---------------------------------------------------------------------------
// Failure taxonomy
// ---------------------------------------------------------------------------

// failureCode is one entry of the gateway's error vocabulary.
//
// Code is the granular taxonomy value the mesh classifies on. Razorpay reports
// that value in error_reason and puts a coarse class in error_code, while the
// frozen domain contract classifies on PaymentEntity.ErrorCode. Every response
// this file emits therefore carries the granular code in *both* fields, so a
// consumer written against either reading behaves identically. See the report
// note on this divergence.
type failureCode struct {
	Code        string
	Source      string // bank | gateway | customer | issuer
	Step        string // payment_initiation | payment_authentication | payment_authorization
	Description string
}

// failureCatalog is the human-facing text for each code. Descriptions are fixed
// strings rather than generated, so nothing an API client sends can steer what
// this server writes into the mesh's audit trail.
var failureCatalog = map[string]failureCode{
	"bank_technical_error":                  {"bank_technical_error", "bank", "payment_authorization", "Payment failed due to a technical error at the bank"},
	"gateway_technical_error":               {"gateway_technical_error", "gateway", "payment_authorization", "Payment processing failed at the gateway"},
	"payment_timed_out":                     {"payment_timed_out", "gateway", "payment_authentication", "Payment was not completed in time"},
	"issuer_down":                           {"issuer_down", "issuer", "payment_authorization", "The issuing bank is currently unavailable"},
	"upi_psp_error":                         {"upi_psp_error", "bank", "payment_authorization", "The UPI app reported an error while processing the request"},
	"server_error":                          {"server_error", "gateway", "payment_authorization", "The upstream service reported an internal error"},
	"insufficient_funds":                    {"insufficient_funds", "bank", "payment_authorization", "Payment failed because of insufficient funds in the account"},
	"payment_failed":                        {"payment_failed", "bank", "payment_authorization", "Payment was declined by the bank"},
	"invalid_otp":                           {"invalid_otp", "customer", "payment_authentication", "Payment failed because an invalid OTP was entered"},
	"incorrect_otp":                         {"incorrect_otp", "customer", "payment_authentication", "Payment failed because the OTP entered was incorrect"},
	"authentication_failed":                 {"authentication_failed", "customer", "payment_authentication", "Payment failed because authentication could not be completed"},
	"upi_collect_expired":                   {"upi_collect_expired", "customer", "payment_authentication", "The collect request expired before it was approved"},
	"mandate_not_active":                    {"mandate_not_active", "bank", "payment_authorization", "The mandate is not active at the bank"},
	"card_expired":                          {"card_expired", "bank", "payment_authorization", "Payment failed because the card has expired"},
	"card_not_supported":                    {"card_not_supported", "bank", "payment_authorization", "The card is not supported for this transaction"},
	"debit_instrument_blocked":              {"debit_instrument_blocked", "bank", "payment_authorization", "The payment instrument is blocked by the issuer"},
	"bank_account_invalid":                  {"bank_account_invalid", "bank", "payment_authorization", "The bank account details are invalid"},
	"transaction_limit_exceeded":            {"transaction_limit_exceeded", "bank", "payment_authorization", "The transaction exceeds the limit set on the instrument"},
	"invalid_card_number":                   {"invalid_card_number", "customer", "payment_initiation", "The card number entered is invalid"},
	"card_lost_or_stolen":                   {"card_lost_or_stolen", "bank", "payment_authorization", "The card has been reported lost or stolen"},
	"international_transaction_not_allowed": {"international_transaction_not_allowed", "bank", "payment_authorization", "International transactions are not enabled on this instrument"},
	"payment_cancelled_by_user":             {"payment_cancelled_by_user", "customer", "payment_authentication", "Payment was cancelled by the customer"},
	"payment_method_not_enabled":            {"payment_method_not_enabled", "gateway", "payment_initiation", "The payment method is not enabled for this account"},
}

// weightedCode is one row of a per-mille failure distribution.
type weightedCode struct {
	Code   string
	Weight int
}

// Failure distributions. Each table sums to exactly perMille, which a test
// asserts: a table that silently summed to less would make the last code absorb
// the remainder and quietly change the mix.
//
// The outage tables are the point. During a real issuer outage the declines
// stop looking like customer problems and start looking like infrastructure —
// bank_technical_error and payment_timed_out crowd out insufficient_funds. A
// simulator that kept emitting the baseline mix during an outage would let a
// classifier score well without ever learning anything.
var (
	outageNetbanking = []weightedCode{
		{"bank_technical_error", 620}, {"gateway_technical_error", 180},
		{"payment_timed_out", 150}, {"issuer_down", 50},
	}
	outageUPI = []weightedCode{
		{"upi_psp_error", 550}, {"payment_timed_out", 250},
		{"gateway_technical_error", 120}, {"bank_technical_error", 80},
	}
	outageCard = []weightedCode{
		{"bank_technical_error", 500}, {"gateway_technical_error", 250},
		{"payment_timed_out", 200}, {"issuer_down", 50},
	}
	outageWallet = []weightedCode{
		{"gateway_technical_error", 560}, {"payment_timed_out", 340},
		{"server_error", 100},
	}

	baseNetbanking = []weightedCode{
		{"payment_failed", 220}, {"insufficient_funds", 200}, {"bank_technical_error", 150},
		{"payment_timed_out", 140}, {"authentication_failed", 120}, {"gateway_technical_error", 90},
		{"bank_account_invalid", 40}, {"payment_cancelled_by_user", 40},
	}
	baseUPI = []weightedCode{
		{"upi_collect_expired", 200}, {"insufficient_funds", 190}, {"payment_timed_out", 170},
		{"upi_psp_error", 140}, {"payment_cancelled_by_user", 120}, {"payment_failed", 100},
		{"debit_instrument_blocked", 40}, {"bank_technical_error", 40},
	}
	baseCard = []weightedCode{
		{"insufficient_funds", 220}, {"authentication_failed", 170}, {"invalid_otp", 130},
		{"incorrect_otp", 90}, {"card_expired", 90}, {"payment_failed", 90},
		{"gateway_technical_error", 70}, {"transaction_limit_exceeded", 50},
		{"invalid_card_number", 40}, {"international_transaction_not_allowed", 30},
		{"card_not_supported", 10}, {"card_lost_or_stolen", 10},
	}
	baseWallet = []weightedCode{
		{"insufficient_funds", 350}, {"payment_failed", 250},
		{"gateway_technical_error", 200}, {"payment_timed_out", 200},
	}
)

// failureTable selects the distribution for a method and outage state.
func failureTable(method string, outage bool) []weightedCode {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "upi":
		if outage {
			return outageUPI
		}
		return baseUPI
	case "card", "emi":
		if outage {
			return outageCard
		}
		return baseCard
	case "wallet":
		if outage {
			return outageWallet
		}
		return baseWallet
	default:
		if outage {
			return outageNetbanking
		}
		return baseNetbanking
	}
}

// pickFailure resolves a per-mille roll into a concrete failure. The roll is
// supplied by the caller rather than drawn here so the decision stays a pure
// function: the script draws from its seeded generator, the retry endpoint
// derives its roll from the payment id, and neither can perturb the other.
func pickFailure(method string, outage bool, roll int) failureCode {
	table := failureTable(method, outage)
	if roll < 0 {
		roll = 0
	}
	for _, wc := range table {
		if roll < wc.Weight {
			return failureCatalog[wc.Code]
		}
		roll -= wc.Weight
	}
	return failureCatalog[table[len(table)-1].Code]
}

// ---------------------------------------------------------------------------
// Payment registry
// ---------------------------------------------------------------------------

// maxTrackedPayments bounds the in-memory payment map. The map is keyed by an
// identifier a client supplies, so an unbounded one is a memory-exhaustion
// vector wearing a state machine's clothes.
const maxTrackedPayments = 20_000

// paymentRegistry holds the payments this process has minted or been asked
// about, plus their attempt counts. Eviction is oldest-first, which is right for
// a simulator: an incident the mesh is still working on was created recently.
type paymentRegistry struct {
	mu       sync.Mutex
	byID     map[string]domain.PaymentEntity
	attempts map[string]int
	order    []string
	limit    int
}

func newPaymentRegistry(limit int) *paymentRegistry {
	if limit <= 0 {
		limit = maxTrackedPayments
	}
	return &paymentRegistry{
		byID:     make(map[string]domain.PaymentEntity),
		attempts: make(map[string]int),
		order:    make([]string, 0, 64),
		limit:    limit,
	}
}

func (r *paymentRegistry) put(p domain.PaymentEntity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.putLocked(p)
}

func (r *paymentRegistry) putLocked(p domain.PaymentEntity) {
	if _, exists := r.byID[p.ID]; !exists {
		r.order = append(r.order, p.ID)
	}
	r.byID[p.ID] = p
	for len(r.order) > r.limit {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.byID, oldest)
		delete(r.attempts, oldest)
	}
}

func (r *paymentRegistry) get(id string) (domain.PaymentEntity, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.byID[id]
	return p, ok
}

// nextAttempt records and returns the attempt ordinal for a payment. The count
// is authoritative only when the caller does not supply one, which keeps the
// endpoint usable both by the mesh (which knows its own attempt number) and by
// a load generator that does not.
func (r *paymentRegistry) nextAttempt(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[id]++
	return r.attempts[id]
}

func (r *paymentRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// ---------------------------------------------------------------------------
// Request decoding
// ---------------------------------------------------------------------------

// maxRequestBody caps a request body. Razorpay's capture body is a few dozen
// bytes; this is four orders of magnitude of headroom and still bounded.
const maxRequestBody = 64 << 10

// paymentRequest is the union of the retry and capture request shapes. Amount
// is a json.Number so a fractional value is a parse failure rather than a
// silent truncation: money is int64 paisa on every path, including the one that
// only exists to be rejected.
type paymentRequest struct {
	Amount       json.Number `json:"amount"`
	Currency     string      `json:"currency"`
	Attempt      int         `json:"attempt"`
	Presentation string      `json:"presentation"`
}

var errBadRequestBody = errors.New("simulator: malformed request body")

// decodePaymentRequest accepts both wire formats the real API accepts: form
// encoding, which is what the official SDKs send, and JSON, which is what a
// hand-rolled client sends.
func decodePaymentRequest(r *http.Request) (paymentRequest, error) {
	var req paymentRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return req, errBadRequestBody
	}
	if len(body) == 0 {
		return req, nil
	}

	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
		return decodeFormRequest(string(body))
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return paymentRequest{}, errBadRequestBody
	}
	return req, nil
}

func decodeFormRequest(raw string) (paymentRequest, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return paymentRequest{}, errBadRequestBody
	}
	req := paymentRequest{
		Amount:       json.Number(values.Get("amount")),
		Currency:     values.Get("currency"),
		Presentation: values.Get("presentation"),
	}
	if a := values.Get("attempt"); a != "" {
		n, err := strconv.Atoi(a)
		if err != nil {
			return paymentRequest{}, errBadRequestBody
		}
		req.Attempt = n
	}
	return req, nil
}

// amountPaisa parses the requested amount as an exact integer. Absent is
// reported as (0, false) so a caller can distinguish "not supplied" from zero.
func (p paymentRequest) amountPaisa() (int64, bool, error) {
	s := strings.TrimSpace(p.Amount.String())
	if s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false, errBadRequestBody
	}
	return v, true, nil
}

// presentation normalises the requested instrument presentation through the
// domain's closed set, so an unknown value degrades to "unchanged" rather than
// buying the caller a success path that does not exist.
func (p paymentRequest) presentation() domain.InstrumentPresentation {
	v := domain.InstrumentPresentation(strings.ToLower(strings.TrimSpace(p.Presentation)))
	if v.Valid() {
		return v
	}
	return domain.PresentationUnchanged
}

// ---------------------------------------------------------------------------
// Outcome model
// ---------------------------------------------------------------------------

// refreshSuccessPerMille is how often re-presenting an expired or unsupported
// card through a network token succeeds. It is deliberately high: the whole
// reason those codes are not treated as terminal is that the account updater
// resolves most of them, and a simulator that made the refresh path fail as
// often as a blind retry would make the feature look pointless.
const refreshSuccessPerMille = 700

// outcome is what the issuer decided for one attempt.
type outcome struct {
	Success bool
	Failure failureCode
}

// decideOutcome is the issuer-health model applied to a single retry.
//
// The three branches encode the taxonomy's whole point. A terminal decline
// never recovers no matter how many attempts are spent on it. A refreshable
// decline never recovers if the instrument is re-presented unchanged, and
// usually does if it is re-presented as a token. Everything else is a draw
// against the issuer's health at this instant, which is what makes a retry
// after a downtime resolution succeed and the same retry during the outage
// fail.
func (s *server) decideOutcome(p domain.PaymentEntity, attempt int,
	presentation domain.InstrumentPresentation, now time.Time) outcome {

	switch {
	case domain.IsTerminalDecline(p.ErrorCode):
		return outcome{Failure: failureFor(p.ErrorCode, p.Method)}

	case domain.IsRefreshable(p.ErrorCode):
		if presentation == domain.PresentationUnchanged {
			// Re-presenting an expired card unchanged cannot succeed, and
			// pretending otherwise would reward exactly the blind retry this
			// system exists to replace.
			return outcome{Failure: failureFor(p.ErrorCode, p.Method)}
		}
		if s.draw("refresh", p.ID, attempt) < refreshSuccessPerMille {
			return outcome{Success: true}
		}
		return outcome{Failure: failureFor(p.ErrorCode, p.Method)}
	}

	key := p.Issuer()
	if s.draw("retry", p.ID, attempt) >= s.timeline.FailPerMille(key, now) {
		return outcome{Success: true}
	}
	_, outage := s.timeline.ActiveWindow(key, now)
	return outcome{Failure: pickFailure(p.Method, outage, s.draw("code", p.ID, attempt))}
}

// failureFor resolves a code to its catalog entry, falling back to a method
// appropriate generic failure for a code this simulator does not publish.
func failureFor(code, method string) failureCode {
	if fc, ok := failureCatalog[strings.ToLower(strings.TrimSpace(code))]; ok {
		return fc
	}
	return pickFailure(method, false, 0)
}

// ---------------------------------------------------------------------------
// Payment entities on the wire
// ---------------------------------------------------------------------------

// paymentEnvelope is the payment entity as the API returns it. It embeds the
// frozen domain type rather than restating its fields, so the simulator's wire
// format cannot drift from the one the mesh parses; only the attributes the
// domain has no reason to model are added here.
type paymentEnvelope struct {
	Entity string `json:"entity"`
	domain.PaymentEntity
	Captured       bool  `json:"captured"`
	AmountRefunded int64 `json:"amount_refunded"`
	Fee            int64 `json:"fee"`
	Tax            int64 `json:"tax"`
}

// Razorpay's standard pricing on domestic transactions is 2% plus 18% GST on
// the fee, i.e. 2.36% all-in. Both are integer paisa divisions; there is no
// float anywhere on this path.
const (
	feeBasisPoints  = 236   // 2.36% of the captured amount, in hundredths of a percent
	feeBasisDivisor = 10000 //
	gstNumerator    = 18    // GST is 18% of the fee, i.e. 18/118 of the all-in charge
	gstDivisor      = 118
)

func envelopeFor(p domain.PaymentEntity) paymentEnvelope {
	env := paymentEnvelope{Entity: "payment", PaymentEntity: p}
	if p.Status == "captured" {
		env.Captured = true
		env.Fee = p.Amount * feeBasisPoints / feeBasisDivisor
		env.Tax = env.Fee * gstNumerator / gstDivisor
	}
	return env
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handlePaymentFetch mirrors GET /v1/payments/{id}.
func (s *server) handlePaymentFetch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.resolvePayment(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, envelopeFor(p))
}

// handlePaymentRetry re-presents a failed payment to the issuer.
//
// The real API has no generic payment retry — recovery there runs through the
// subscription and invoice endpoints — so this is the one endpoint shaped for
// this system rather than copied from Razorpay. Its request and response bodies
// still follow Razorpay's conventions exactly, so the client code that talks to
// it is the client code that talks to production.
func (s *server) handlePaymentRetry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.resolvePayment(w, r)
	if !ok {
		return
	}
	req, err := decodePaymentRequest(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The request body could not be parsed", "NA", "payment_initiation", "input_validation_failed", nil)
		return
	}

	// A retry may not restate the amount. Accepting a different one would make
	// the simulator complicit in the exact mutation the mesh's amount pinning
	// exists to prevent, and would hide a real bug in a reviewer's run.
	if amount, present, aerr := req.amountPaisa(); aerr != nil || (present && amount != p.Amount) {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The amount must be the same as the amount of the original payment",
			"NA", "payment_initiation", "input_validation_failed",
			map[string]string{"payment_id": p.ID, "order_id": p.OrderID})
		return
	}

	attempt := req.Attempt
	if attempt <= 0 {
		attempt = s.payments.nextAttempt(p.ID)
	}
	s.complete(w, p, attempt, req.presentation(), "retry")
}

// handlePaymentCapture mirrors POST /v1/payments/{id}/capture, including its
// amount check. That check is not decoration: capturing a different amount than
// was authorised is the classic payment-integration defect, and a simulator
// that accepted it would let the bug ship.
func (s *server) handlePaymentCapture(w http.ResponseWriter, r *http.Request) {
	p, ok := s.resolvePayment(w, r)
	if !ok {
		return
	}
	req, err := decodePaymentRequest(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The request body could not be parsed", "NA", "payment_initiation", "input_validation_failed", nil)
		return
	}
	amount, present, aerr := req.amountPaisa()
	if aerr != nil || !present {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The amount field is required and must be an integer in paisa",
			"NA", "payment_initiation", "input_validation_failed",
			map[string]string{"payment_id": p.ID})
		return
	}
	if amount != p.Amount {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The amount must be the same as the amount authorized",
			"NA", "payment_initiation", "input_validation_failed",
			map[string]string{"payment_id": p.ID, "order_id": p.OrderID})
		return
	}
	if cur := strings.TrimSpace(req.Currency); cur != "" && !strings.EqualFold(cur, p.Currency) {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The currency must be the same as the currency of the original payment",
			"NA", "payment_initiation", "input_validation_failed",
			map[string]string{"payment_id": p.ID})
		return
	}

	attempt := req.Attempt
	if attempt <= 0 {
		attempt = s.payments.nextAttempt(p.ID)
	}
	s.complete(w, p, attempt, req.presentation(), "capture")
}

// complete runs the outcome model, persists the new state of the payment, and
// writes the success entity or the decline envelope.
func (s *server) complete(w http.ResponseWriter, p domain.PaymentEntity, attempt int,
	presentation domain.InstrumentPresentation, op string) {

	s.metrics.Counter("sim_payment_attempts").Inc()

	// An already-captured payment reports success rather than being re-run.
	//
	// The real API answers this with a 400. Answering 200 is the deliberate
	// deviation: a recovery system that re-presents a payment whose response it
	// never saw must read "already captured" as recovered, not as a fresh
	// failure to retry. Any other answer makes a lost response indistinguishable
	// from a decline, which is how a retry loop double-charges someone.
	if p.Status == "captured" {
		s.log.Debug("retry of an already captured payment",
			slogPaymentAttrs(p, attempt, op, string(presentation))...)
		s.writeJSON(w, http.StatusOK, envelopeFor(p))
		return
	}

	now := s.clock.Now()
	res := s.decideOutcome(p, attempt, presentation, now)

	if res.Success {
		p.Status = "captured"
		p.ErrorCode, p.ErrorReason, p.ErrorStep, p.ErrorSource, p.ErrorDesc = "", "", "", "", ""
		s.payments.put(p)
		s.metrics.Counter("sim_payment_captured").Inc()
		s.log.Info("simulated payment captured",
			slogPaymentAttrs(p, attempt, op, string(presentation))...)
		s.writeJSON(w, http.StatusOK, envelopeFor(p))
		return
	}

	fc := res.Failure
	p.Status = "failed"
	p.ErrorCode, p.ErrorReason = fc.Code, fc.Code
	p.ErrorStep, p.ErrorSource, p.ErrorDesc = fc.Step, fc.Source, fc.Description
	s.payments.put(p)
	s.metrics.Counter("sim_payment_declined").Inc()
	s.log.Info("simulated payment declined",
		append(slogPaymentAttrs(p, attempt, op, string(presentation)), "error_code", fc.Code)...)

	// A declined attempt is a 400 with the error envelope, exactly as the real
	// API reports one. The granular code travels in reason, which is where a
	// Razorpay client already looks for it.
	s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR", fc.Description,
		fc.Source, fc.Step, fc.Code,
		map[string]string{"payment_id": p.ID, "order_id": p.OrderID})
}

// resolvePayment validates the path identifier and returns the payment it
// names, synthesising one for an identifier this process did not mint.
//
// Synthesising rather than 404ing is a deliberate deviation from the real API.
// A payment recovered across a simulator restart, or driven by the load
// harness, must still be retryable, and the synthesised entity is a pure
// function of the seed and the id — so a restart resumes the same world rather
// than a new one.
func (s *server) resolvePayment(w http.ResponseWriter, r *http.Request) (domain.PaymentEntity, bool) {
	id := r.PathValue("id")
	if !validRazorID("pay", id) {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The id provided is not a valid payment identifier",
			"NA", "payment_initiation", "input_validation_failed", nil)
		return domain.PaymentEntity{}, false
	}
	if p, ok := s.payments.get(id); ok {
		return p, true
	}
	p := s.synthesizePayment(id)
	s.payments.put(p)
	return p, true
}

// synthesizePayment reconstructs a plausible failed payment for an unknown id,
// deterministically from the seed so two processes given the same id agree.
func (s *server) synthesizePayment(id string) domain.PaymentEntity {
	mix := indiaMix()
	total := 0
	for _, p := range mix {
		total += p.Weight
	}
	roll := s.draw("synth_profile", id, 0) * total / perMille
	profile := mix[len(mix)-1]
	for _, p := range mix {
		if roll < p.Weight {
			profile = p
			break
		}
		roll -= p.Weight
	}

	band := amountBands[s.draw("synth_band", id, 0)*len(amountBands)/perMille]
	spread := band.Max - band.Min + 1
	amount := band.Min + int64(s.draw("synth_amount", id, 0))*spread/perMille
	amount = amount / 100 * 100 // whole rupees; integer division only

	now := s.clock.Now()
	_, outage := s.timeline.ActiveWindow(profile.issuerKey(), now)
	fc := pickFailure(profile.Method, outage, s.draw("synth_code", id, 0))

	p := domain.PaymentEntity{
		ID:          id,
		Amount:      amount,
		Currency:    "INR",
		Status:      "failed",
		OrderID:     razorID("order", s.timeline.Seed(), "synth", id),
		Method:      profile.Method,
		Bank:        profile.Bank,
		Wallet:      profile.Wallet,
		ErrorCode:   fc.Code,
		ErrorReason: fc.Code,
		ErrorStep:   fc.Step,
		ErrorSource: fc.Source,
		ErrorDesc:   fc.Description,
		CreatedAt:   now.Unix(),
	}
	if strings.EqualFold(profile.Method, "upi") {
		p.VPA = syntheticVPA(id, profile.VPAHandle)
	}
	return p
}

// slogPaymentAttrs builds the log attributes for one attempt. The VPA and the
// amount are deliberately absent: the redacting handler would mask the former
// anyway, and neither belongs in a line whose purpose is to say what happened.
func slogPaymentAttrs(p domain.PaymentEntity, attempt int, op, presentation string) []any {
	return []any{
		"payment_id", p.ID,
		"issuer_key", p.Issuer(),
		"method", p.Method,
		"attempt", attempt,
		"op", op,
		"presentation", presentation,
	}
}

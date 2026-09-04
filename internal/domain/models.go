// Package domain holds the frozen data contracts of ResilientMesh.
//
// Every type here is either (a) a wire format owned by Razorpay, mirrored
// field-for-field, or (b) an internal value object that crosses a package
// boundary. Nothing in this package performs I/O and nothing here imports
// another internal package, which keeps the contract acyclic and independently
// testable.
package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Razorpay webhook wire format
// ---------------------------------------------------------------------------

// RazorpayWebhookPayload is the envelope delivered to /api/v1/webhooks/razorpay.
// Field names mirror Razorpay's documented webhook schema. Unknown fields are
// tolerated on purpose: Razorpay adds attributes without a version bump, and a
// strict decoder would reject otherwise-valid production traffic. Every field
// the system acts on is declared explicitly, so tolerance costs no safety.
type RazorpayWebhookPayload struct {
	Entity    string                 `json:"entity"`
	AccountID string                 `json:"account_id"`
	Event     string                 `json:"event"`
	Contains  []string               `json:"contains"`
	Payload   PaymentPayloadEnvelope `json:"payload"`
	CreatedAt int64                  `json:"created_at"`
}

type PaymentPayloadEnvelope struct {
	Payment      PaymentEntityContainer       `json:"payment"`
	Subscription *SubscriptionEntityContainer `json:"subscription,omitempty"`
}

type PaymentEntityContainer struct {
	Entity PaymentEntity `json:"entity"`
}

type SubscriptionEntityContainer struct {
	Entity SubscriptionEntity `json:"entity"`
}

// PaymentEntity captures Razorpay's payment entity and its failure taxonomy.
// Amount is always paisa and is treated as immutable downstream: it is the
// single most security-sensitive field in the system, so it is copied from the
// HMAC-verified payload and never sourced from a model response.
type PaymentEntity struct {
	ID             string `json:"id"`
	Amount         int64  `json:"amount"` // paisa; immutable
	Currency       string `json:"currency"`
	Status         string `json:"status"`
	OrderID        string `json:"order_id"`
	Method         string `json:"method"` // card | upi | netbanking | wallet | emi
	Bank           string `json:"bank,omitempty"`
	Wallet         string `json:"wallet,omitempty"`
	VPA            string `json:"vpa,omitempty"`
	International  bool   `json:"international,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	InvoiceID      string `json:"invoice_id,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorReason    string `json:"error_reason,omitempty"`
	ErrorStep      string `json:"error_step,omitempty"`
	ErrorSource    string `json:"error_source,omitempty"`
	ErrorDesc      string `json:"error_description,omitempty"`
	CreatedAt      int64  `json:"created_at,omitempty"`
}

// SubscriptionEntity is the recurring-mandate view Razorpay attaches to
// subscription.* events. Only fields the mandate sentry reasons about are
// declared.
type SubscriptionEntity struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	PlanID         string `json:"plan_id"`
	CustomerID     string `json:"customer_id"`
	CurrentStart   int64  `json:"current_start,omitempty"`
	CurrentEnd     int64  `json:"current_end,omitempty"`
	ChargeAt       int64  `json:"charge_at,omitempty"`
	PaidCount      int    `json:"paid_count,omitempty"`
	RemainingCount int    `json:"remaining_count,omitempty"`
	TotalCount     int    `json:"total_count,omitempty"`
	AuthAttempts   int    `json:"auth_attempts,omitempty"`
}

// IsRecurring reports whether this payment belongs to a mandate lifecycle,
// which activates the RBI e-mandate invariant set inside the gatekeeper.
func (p PaymentEntity) IsRecurring() bool {
	return p.SubscriptionID != "" || p.InvoiceID != ""
}

// Issuer returns the stable telemetry key for the institution that declined.
// Card and netbanking key off the bank code; UPI keys off the VPA handle,
// because UPI outages are PSP-handle scoped rather than bank scoped.
func (p PaymentEntity) Issuer() string {
	switch strings.ToLower(p.Method) {
	case "upi":
		if at := strings.LastIndex(p.VPA, "@"); at >= 0 && at+1 < len(p.VPA) {
			return "upi:" + strings.ToLower(p.VPA[at+1:])
		}
		return "upi:unknown"
	case "wallet":
		if p.Wallet != "" {
			return "wallet:" + strings.ToLower(p.Wallet)
		}
		return "wallet:unknown"
	default:
		if p.Bank != "" {
			return strings.ToLower(p.Method) + ":" + strings.ToUpper(p.Bank)
		}
		return strings.ToLower(p.Method) + ":unknown"
	}
}

// ---------------------------------------------------------------------------
// Razorpay Downtime API
// ---------------------------------------------------------------------------

// DowntimeEntity maps Razorpay's /v1/downtimes response entity.
type DowntimeEntity struct {
	ID         string             `json:"id"`
	Entity     string             `json:"entity"`
	Method     string             `json:"method"`
	Begin      int64              `json:"begin"`
	End        *int64             `json:"end"`
	Status     DowntimeStatus     `json:"status"`
	Scheduled  bool               `json:"scheduled"`
	Severity   DowntimeSeverity   `json:"severity"`
	Instrument DowntimeInstrument `json:"instrument"`
	CreatedAt  int64              `json:"created_at,omitempty"`
	UpdatedAt  int64              `json:"updated_at,omitempty"`
}

type DowntimeInstrument struct {
	Issuer    string `json:"issuer,omitempty"`
	Bank      string `json:"bank,omitempty"`
	CardType  string `json:"card_type,omitempty"`
	Network   string `json:"network,omitempty"`
	PSP       string `json:"psp,omitempty"`
	VPAHandle string `json:"vpa_handle,omitempty"`
}

type DowntimeStatus string

const (
	DowntimeScheduled DowntimeStatus = "scheduled"
	DowntimeStarted   DowntimeStatus = "started"
	DowntimeResolved  DowntimeStatus = "resolved"
	DowntimeUpdated   DowntimeStatus = "updated"
)

type DowntimeSeverity string

const (
	SeverityHigh   DowntimeSeverity = "high"
	SeverityMedium DowntimeSeverity = "medium"
	SeverityLow    DowntimeSeverity = "low"
)

// Active reports whether the downtime window covers instant t.
func (d DowntimeEntity) Active(t time.Time) bool {
	if d.Status == DowntimeResolved {
		return false
	}
	ts := t.Unix()
	if ts < d.Begin {
		return false
	}
	return d.End == nil || ts <= *d.End
}

// TelemetryKey renders the downtime's instrument as the same issuer key space
// PaymentEntity.Issuer uses, so a downtime notice can be joined against live
// failure counters without a lookup table.
func (d DowntimeEntity) TelemetryKey() string {
	method := strings.ToLower(d.Method)
	switch method {
	case "upi":
		if d.Instrument.VPAHandle != "" {
			return "upi:" + strings.ToLower(d.Instrument.VPAHandle)
		}
		if d.Instrument.PSP != "" {
			return "upi:" + strings.ToLower(d.Instrument.PSP)
		}
		return "upi:unknown"
	case "wallet":
		if d.Instrument.Issuer != "" {
			return "wallet:" + strings.ToLower(d.Instrument.Issuer)
		}
		return "wallet:unknown"
	default:
		issuer := d.Instrument.Issuer
		if issuer == "" {
			issuer = d.Instrument.Bank
		}
		if issuer == "" {
			return method + ":unknown"
		}
		return method + ":" + strings.ToUpper(issuer)
	}
}

// DowntimeList is the paginated envelope Razorpay returns for collections.
type DowntimeList struct {
	Entity string           `json:"entity"`
	Count  int              `json:"count"`
	Items  []DowntimeEntity `json:"items"`
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

// TerminalDeclineCodes are issuer responses no amount of retrying can fix.
// Retrying them burns gateway fees, irritates the customer, and on recurring
// rails can trip issuer abuse heuristics. They are rejected before any database
// write or model call.
var TerminalDeclineCodes = map[string]string{
	"debit_instrument_blocked":              "instrument blocked by issuer",
	"bank_account_invalid":                  "account does not exist",
	"transaction_limit_exceeded":            "per-transaction ceiling breached",
	"payment_method_not_enabled":            "method not enabled on issuer",
	"invalid_card_number":                   "malformed instrument",
	"card_lost_or_stolen":                   "instrument reported lost or stolen",
	"international_transaction_not_allowed": "cross-border disabled on instrument",
	"payment_cancelled_by_user":             "explicit user abandonment",
	"mandate_revoked":                       "mandate cancelled by payer",
}

// RefreshableDeclineCodes are declines that a retry cannot fix but an
// instrument refresh can. See IsRefreshable for why these are not terminal.
var RefreshableDeclineCodes = map[string]string{
	"card_expired":       "instrument expired; network token may still resolve",
	"card_not_supported": "presentation unsupported; re-present via network token",
}

// AmbiguousFailureCodes are the codes whose root cause is genuinely
// underdetermined from the code alone. These are the only inputs the causal
// model is permitted to reason about; everything else is decided
// deterministically.
var AmbiguousFailureCodes = map[string]struct{}{
	"bank_technical_error":    {},
	"gateway_technical_error": {},
	"payment_timed_out":       {},
	"server_error":            {},
	"issuer_down":             {},
	"gateway_error":           {},
	"upi_psp_error":           {},
	"payment_pending":         {},
}

// SoftDeclineCodes are recoverable but unambiguous: the cause is known, so the
// policy engine handles them without invoking the model.
var SoftDeclineCodes = map[string]struct{}{
	"insufficient_funds":    {},
	"payment_failed":        {},
	"invalid_otp":           {},
	"incorrect_otp":         {},
	"authentication_failed": {},
	"upi_collect_expired":   {},
	"mandate_not_active":    {},
}

// foldLower and foldUpper case-fold ASCII letters and leave every other byte
// alone. Every parser over a closed set in this package folds through them.
//
// strings.ToLower and strings.ToUpper apply full Unicode case mapping, which
// maps characters outside ASCII *into* ASCII: U+017F LATIN SMALL LETTER LONG S
// uppercases to 'S', and U+212A KELVIN SIGN lowercases to 'k'. Every identifier
// in this package's closed sets is ASCII, so a Unicode fold can never repair a
// member — it can only admit a non-member. That is a fail-open on the boundary
// this package exists to defend: the gatekeeper parses the model's own
// recommended_action, failure_classification and suggested_fallback_rail through
// these functions, so "AſYNC_EXPONENTIAL_RETRY" folding to a valid retry
// instead of degrading to an abstention hands a prompt-injected response the
// authority the closed set was supposed to deny it. Folding must only ever be
// able to add a terminal halt, never a recovery licence, so it stays ASCII.
const asciiCaseDelta = 'a' - 'A'

func foldLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + asciiCaseDelta
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

func foldUpper(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c - asciiCaseDelta
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// normaliseCode folds an error code the same way ParseAction and ParseRail fold
// their inputs. Without it the taxonomy lookups are exact map hits, so
// "CARD_EXPIRED" or a code with a stray space is not recognised as terminal and
// silently buys a retry on a dead instrument. Consistent normalisation across
// every parser is what stops that class of bug.
func normaliseCode(code string) string {
	return foldLower(strings.TrimSpace(code))
}

func IsTerminalDecline(code string) bool {
	_, ok := TerminalDeclineCodes[normaliseCode(code)]
	return ok
}

// IsRefreshable reports whether the decline is recoverable by re-presenting the
// instrument rather than by retrying it unchanged.
//
// These codes look terminal and are widely treated as such, but the card number
// changing does not mean the funding account went away: the network token still
// resolves, and an account-updater refresh recovers a large share of them. RBI
// card-on-file tokenization means recurring card payments in this market
// already run on tokens, so the refresh path exists. Classifying them terminal
// silently discards recoverable revenue.
func IsRefreshable(code string) bool {
	_, ok := RefreshableDeclineCodes[normaliseCode(code)]
	return ok
}

func IsAmbiguous(code string) bool {
	_, ok := AmbiguousFailureCodes[normaliseCode(code)]
	return ok
}

func IsSoftDecline(code string) bool {
	_, ok := SoftDeclineCodes[normaliseCode(code)]
	return ok
}

// ---------------------------------------------------------------------------
// Payment rails
// ---------------------------------------------------------------------------

// Rail is a payment instrument family a live session can be morphed onto.
type Rail string

const (
	RailUPIIntent  Rail = "upi_intent"
	RailUPICollect Rail = "upi_collect"
	RailCard       Rail = "card"
	RailNetbanking Rail = "netbanking"
	RailWallet     Rail = "wallet"
	RailNone       Rail = "none"
)

var allRails = map[Rail]struct{}{
	RailUPIIntent: {}, RailUPICollect: {}, RailCard: {},
	RailNetbanking: {}, RailWallet: {}, RailNone: {},
}

func (r Rail) Valid() bool { _, ok := allRails[r]; return ok }

// ParseRail normalises free-form model output into a known rail, defaulting to
// RailNone. The model is never permitted to invent a rail identifier.
func ParseRail(s string) Rail {
	r := Rail(foldLower(strings.TrimSpace(s)))
	if r.Valid() {
		return r
	}
	return RailNone
}

// RailFromMethod maps a Razorpay payment method onto its rail.
func RailFromMethod(method string) Rail {
	switch strings.ToLower(method) {
	case "upi":
		return RailUPIIntent
	case "card", "emi":
		return RailCard
	case "netbanking":
		return RailNetbanking
	case "wallet":
		return RailWallet
	default:
		return RailNone
	}
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// RawJSON is a []byte that marshals as embedded JSON rather than base64.
type RawJSON []byte

func (r RawJSON) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}
	if !json.Valid(r) {
		return nil, fmt.Errorf("domain: RawJSON holds invalid JSON")
	}
	return r, nil
}

func (r *RawJSON) UnmarshalJSON(b []byte) error {
	*r = append((*r)[:0], b...)
	return nil
}

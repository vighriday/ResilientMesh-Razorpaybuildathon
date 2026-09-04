package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Shippable scenario names.
//
// A scenario is a script, not a random walk: every outage window sits at a
// fixed fraction of the run, so the same demo lands on the same beat every
// time. The seed decides which payments arrive and how they resolve, never
// when the issuer falls over. That split is what makes a recorded demo and a
// live demo tell the same story.
const (
	ScenarioIssuerOutage   = "issuer-outage"
	ScenarioPSPDegradation = "psp-degradation"
	ScenarioMixedTraffic   = "mixed-traffic"
	ScenarioMandateBatch   = "mandate-batch"
)

// Scenarios lists the known scenarios in a stable order, for --help text and
// for tests that sweep all of them.
func Scenarios() []string {
	return []string{
		ScenarioIssuerOutage,
		ScenarioPSPDegradation,
		ScenarioMixedTraffic,
		ScenarioMandateBatch,
	}
}

const (
	// perMille is the fixed-point scale for every probability here.
	//
	// Probabilities are integers on purpose. A severity expressed as a float
	// would make "same seed, same output" depend on floating-point rounding,
	// and reproducibility is the only property this simulator sells.
	perMille = 1000

	// resolvedRetention keeps a finished outage listed with status "resolved"
	// rather than deleting it. A poller that only ever sees entries disappear
	// cannot distinguish a resolution from a dropped response, and the
	// downtime-resolution retry release depends on observing the transition
	// explicitly.
	resolvedRetention = 30 * time.Minute

	// scheduledLead is how far ahead a planned maintenance window is published,
	// mirroring the scheduled notices Razorpay emits before bank maintenance.
	scheduledLead = 10 * time.Minute

	// maxScriptEvents bounds a generated script. --rate and --duration are
	// operator input and their product is an allocation; without a ceiling a
	// fat-fingered flag is an out-of-memory kill rather than an error message.
	maxScriptEvents = 200_000

	// maxRatePerSecond bounds --rate for the same reason.
	maxRatePerSecond = 5000.0

	// minTimelineDuration and maxTimelineDuration bound --duration.
	minTimelineDuration = time.Second
	maxTimelineDuration = 24 * time.Hour
)

// instrumentProfile is one issuer/method combination the simulated traffic can
// select. Bank codes are the real Razorpay netbanking codes rather than
// friendly names, because the mesh keys telemetry off whatever the gateway
// sends and a demo that uses invented codes would not exercise that join.
type instrumentProfile struct {
	Method    string // card | upi | netbanking | wallet
	Bank      string // IFSC-style bank code, as Razorpay reports it
	VPAHandle string // UPI handle without the "@", as the downtime API reports it
	Wallet    string

	Weight           int // relative share of attempted traffic
	BaseFailPerMille int // failure rate outside any outage window
	MandateEligible  bool
}

// issuerKey projects the profile into the mesh's telemetry key space by
// building a payment entity and asking the domain for its issuer. Deriving the
// key rather than formatting it here means the simulator cannot drift from the
// consumer: if domain.PaymentEntity.Issuer changes, this follows.
func (p instrumentProfile) issuerKey() string {
	pe := domain.PaymentEntity{Method: p.Method, Bank: p.Bank, Wallet: p.Wallet}
	if strings.EqualFold(p.Method, "upi") {
		pe.VPA = "sim@" + p.VPAHandle
	}
	return pe.Issuer()
}

// indiaMix is the default issuer and method distribution: the five netbanking
// banks that carry most Indian e-commerce volume, the four UPI handles that
// carry most UPI volume, and a card mix weighted the way an Indian checkout
// actually splits.
//
// Returned fresh on every call so no caller can mutate a shared slice.
func indiaMix() []instrumentProfile {
	return []instrumentProfile{
		// Netbanking. Codes are Razorpay's: HDFC Bank, ICICI, State Bank of
		// India, Axis (UTIB), Kotak Mahindra (KKBK).
		{Method: "netbanking", Bank: "HDFC", Weight: 70, BaseFailPerMille: 70, MandateEligible: true},
		{Method: "netbanking", Bank: "ICIC", Weight: 55, BaseFailPerMille: 62, MandateEligible: true},
		{Method: "netbanking", Bank: "SBIN", Weight: 60, BaseFailPerMille: 115, MandateEligible: true},
		{Method: "netbanking", Bank: "UTIB", Weight: 35, BaseFailPerMille: 68, MandateEligible: true},
		{Method: "netbanking", Bank: "KKBK", Weight: 25, BaseFailPerMille: 58, MandateEligible: true},

		// UPI. The handle is the outage-scoped unit, not the bank behind it.
		{Method: "upi", VPAHandle: "okhdfcbank", Weight: 110, BaseFailPerMille: 55, MandateEligible: true},
		{Method: "upi", VPAHandle: "ybl", Weight: 130, BaseFailPerMille: 60, MandateEligible: true},
		{Method: "upi", VPAHandle: "paytm", Weight: 90, BaseFailPerMille: 72, MandateEligible: true},
		{Method: "upi", VPAHandle: "okaxis", Weight: 75, BaseFailPerMille: 64, MandateEligible: true},
		{Method: "upi", VPAHandle: "oksbi", Weight: 60, BaseFailPerMille: 96, MandateEligible: true},

		// Cards.
		{Method: "card", Bank: "HDFC", Weight: 60, BaseFailPerMille: 88, MandateEligible: true},
		{Method: "card", Bank: "ICIC", Weight: 45, BaseFailPerMille: 92, MandateEligible: true},
		{Method: "card", Bank: "SBIN", Weight: 40, BaseFailPerMille: 104, MandateEligible: true},
		{Method: "card", Bank: "UTIB", Weight: 30, BaseFailPerMille: 90, MandateEligible: true},

		// Wallets. Not mandate eligible: a wallet balance carries no e-mandate
		// registration.
		{Method: "wallet", Wallet: "paytm", Weight: 25, BaseFailPerMille: 78},
		{Method: "wallet", Wallet: "phonepe", Weight: 18, BaseFailPerMille: 74},
	}
}

// OutageWindow is one scripted issuer failure: who, how hard, from when, for
// how long.
type OutageWindow struct {
	ID           string
	Method       string
	Instrument   domain.DowntimeInstrument
	Severity     domain.DowntimeSeverity
	Scheduled    bool
	Begin        time.Time
	End          time.Time
	FailPerMille int
	CreatedAt    time.Time
}

// TelemetryKey routes the window through the same domain projection the mesh
// uses, so a window and the payments it should affect are guaranteed to land on
// one key.
func (w OutageWindow) TelemetryKey() string {
	return domain.DowntimeEntity{Method: w.Method, Instrument: w.Instrument}.TelemetryKey()
}

// EntityAt renders the window as Razorpay would report it at instant now, and
// reports whether it is visible at all.
//
// The status machine is the point of this function: scheduled before it starts,
// started with a null end while it runs, then resolved with a concrete end for
// a retention period afterwards. A consumer polling this endpoint sees a real
// started -> resolved transition, which is the signal a parked retry is
// released on.
func (w OutageWindow) EntityAt(now time.Time) (domain.DowntimeEntity, bool) {
	e := domain.DowntimeEntity{
		ID:         w.ID,
		Entity:     "payment.downtime",
		Method:     w.Method,
		Begin:      w.Begin.Unix(),
		Scheduled:  w.Scheduled,
		Severity:   w.Severity,
		Instrument: w.Instrument,
		CreatedAt:  w.CreatedAt.Unix(),
	}
	end := w.End.Unix()

	switch {
	case now.Before(w.Begin):
		// An unscheduled outage is not knowable before it happens. Publishing
		// one early would let a consumer predict an outage and would make the
		// simulator prove a capability the real API does not offer.
		if !w.Scheduled || now.Before(w.Begin.Add(-scheduledLead)) {
			return domain.DowntimeEntity{}, false
		}
		e.Status = domain.DowntimeScheduled
		e.End = &end
		e.UpdatedAt = w.CreatedAt.Unix()
	case !now.After(w.End):
		e.Status = domain.DowntimeStarted
		e.End = nil // an ongoing outage carries a null end
		e.UpdatedAt = w.Begin.Unix()
	case now.Before(w.End.Add(resolvedRetention)):
		e.Status = domain.DowntimeResolved
		e.End = &end
		e.UpdatedAt = end
	default:
		return domain.DowntimeEntity{}, false
	}
	return e, true
}

// Timeline is a scenario instance: an immutable script plus the traffic mix it
// runs against. Every field is set at construction and never written again, so
// it is safe to share across the HTTP handlers and the emitter without a lock.
type Timeline struct {
	scenario  string
	seed      int64
	start     time.Time
	duration  time.Duration
	accountID string

	windows           []OutageWindow
	mix               []instrumentProfile
	baseline          map[string]int // issuer key -> baseline failure per mille
	totalWeight       int
	recurringPerMille int
}

// NewTimeline builds a scenario. It fails rather than defaulting on unknown
// input: a typo in --scenario that silently ran a different outage would make
// the demo unreproducible in the one way that matters.
func NewTimeline(scenario string, seed int64, start time.Time, duration time.Duration) (*Timeline, error) {
	name := strings.ToLower(strings.TrimSpace(scenario))
	if duration < minTimelineDuration || duration > maxTimelineDuration {
		return nil, fmt.Errorf("simulator: duration %s out of range [%s, %s]",
			duration, minTimelineDuration, maxTimelineDuration)
	}

	t := &Timeline{
		scenario:          name,
		seed:              seed,
		start:             start.UTC(),
		duration:          duration,
		mix:               indiaMix(),
		recurringPerMille: 40,
	}
	t.accountID = razorID("acc", seed, name)

	switch name {
	case ScenarioIssuerOutage:
		// HDFC netbanking collapses a fifth of the way in and recovers with a
		// third of the run left, so the console shows the failure spike, the
		// parked retries, and the release on resolution inside one window.
		t.addWindow("netbanking", domain.DowntimeInstrument{Issuer: "HDFC", Bank: "HDFC"},
			domain.SeverityHigh, false, 20, 66, 940)

	case ScenarioPSPDegradation:
		// Two overlapping UPI handles degrade at different severities. Neither
		// is a hard outage: this is the case where a static "issuer down" rule
		// says nothing useful and the rolling window has to carry the verdict.
		t.addWindow("upi", domain.DowntimeInstrument{PSP: "PhonePe", VPAHandle: "ybl"},
			domain.SeverityMedium, false, 15, 70, 620)
		t.addWindow("upi", domain.DowntimeInstrument{PSP: "Paytm", VPAHandle: "paytm"},
			domain.SeverityLow, false, 40, 82, 350)

	case ScenarioMixedTraffic:
		// Overlapping failures across three rails plus one announced
		// maintenance window, so rail selection has to reason about more than
		// one broken thing at a time.
		t.addWindow("netbanking", domain.DowntimeInstrument{Issuer: "SBIN", Bank: "SBIN"},
			domain.SeverityHigh, false, 10, 42, 900)
		t.addWindow("upi", domain.DowntimeInstrument{PSP: "HDFC", VPAHandle: "okhdfcbank"},
			domain.SeverityMedium, false, 30, 74, 550)
		t.addWindow("card", domain.DowntimeInstrument{Issuer: "ICIC", Bank: "ICIC", Network: "MasterCard", CardType: "credit"},
			domain.SeverityLow, false, 55, 90, 300)
		t.addWindow("netbanking", domain.DowntimeInstrument{Issuer: "UTIB", Bank: "UTIB"},
			domain.SeverityMedium, true, 70, 95, 700)

	case ScenarioMandateBatch:
		// A recurring debit batch against a bank having a bad morning. Most
		// traffic is mandate traffic, so the RBI cooling window, the pre-debit
		// notice, and the AFA ceiling are exercised by volume rather than by a
		// single hand-built case.
		t.recurringPerMille = 850
		t.addWindow("netbanking", domain.DowntimeInstrument{Issuer: "ICIC", Bank: "ICIC"},
			domain.SeverityHigh, false, 25, 62, 880)

	default:
		return nil, fmt.Errorf("simulator: unknown scenario %q (known: %s)",
			scenario, strings.Join(Scenarios(), ", "))
	}

	sort.Slice(t.windows, func(i, j int) bool {
		if !t.windows[i].Begin.Equal(t.windows[j].Begin) {
			return t.windows[i].Begin.Before(t.windows[j].Begin)
		}
		return t.windows[i].ID < t.windows[j].ID
	})

	t.baseline = make(map[string]int, len(t.mix))
	for _, p := range t.mix {
		t.totalWeight += p.Weight
		// Two profiles share an issuer key only if they are the same
		// instrument; keeping the worse baseline is the conservative read.
		if cur, ok := t.baseline[p.issuerKey()]; !ok || p.BaseFailPerMille > cur {
			t.baseline[p.issuerKey()] = p.BaseFailPerMille
		}
	}
	if t.totalWeight <= 0 {
		return nil, fmt.Errorf("simulator: scenario %q has no traffic mix", name)
	}
	return t, nil
}

// addWindow places a window at a fraction of the run. Offsets are integer
// percentages of the duration so one scenario scales to a 30-second smoke test
// and a 30-minute demo without changing shape.
func (t *Timeline) addWindow(method string, inst domain.DowntimeInstrument, sev domain.DowntimeSeverity,
	scheduled bool, beginPct, endPct, failPerMille int) {
	begin := t.at(beginPct)
	w := OutageWindow{
		ID:           razorID("down", t.seed, t.scenario, strconv.Itoa(len(t.windows))),
		Method:       method,
		Instrument:   inst,
		Severity:     sev,
		Scheduled:    scheduled,
		Begin:        begin,
		End:          t.at(endPct),
		FailPerMille: failPerMille,
		CreatedAt:    begin.Add(-scheduledLead),
	}
	t.windows = append(t.windows, w)
}

func (t *Timeline) at(pct int) time.Time {
	return t.start.Add(time.Duration(int64(t.duration) * int64(pct) / 100))
}

// Accessors. Internal slices are copied out so a handler cannot mutate the
// script it is serving.

func (t *Timeline) Scenario() string        { return t.scenario }
func (t *Timeline) Seed() int64             { return t.seed }
func (t *Timeline) Start() time.Time        { return t.start }
func (t *Timeline) Duration() time.Duration { return t.duration }
func (t *Timeline) AccountID() string       { return t.accountID }

func (t *Timeline) Windows() []OutageWindow {
	out := make([]OutageWindow, len(t.windows))
	copy(out, t.windows)
	return out
}

// DowntimesAt renders every visible downtime notice at instant now. The slice
// is always non-nil so the JSON envelope carries [] rather than null, which is
// what the real API does and what a strict client parser expects.
func (t *Timeline) DowntimesAt(now time.Time) []domain.DowntimeEntity {
	out := make([]domain.DowntimeEntity, 0, len(t.windows))
	for _, w := range t.windows {
		if e, ok := w.EntityAt(now); ok {
			out = append(out, e)
		}
	}
	return out
}

// DowntimeByID resolves a single notice, or reports absence so the handler can
// answer 404 rather than an empty entity.
func (t *Timeline) DowntimeByID(id string, now time.Time) (domain.DowntimeEntity, bool) {
	for _, w := range t.windows {
		if w.ID != id {
			continue
		}
		return w.EntityAt(now)
	}
	return domain.DowntimeEntity{}, false
}

// ActiveWindow returns the harshest outage covering an issuer key at now.
// Harshest rather than first: overlapping windows on one key should behave like
// the worst of them, not like whichever was declared first.
func (t *Timeline) ActiveWindow(issuerKey string, now time.Time) (OutageWindow, bool) {
	var worst OutageWindow
	found := false
	for _, w := range t.windows {
		if w.TelemetryKey() != issuerKey {
			continue
		}
		if now.Before(w.Begin) || now.After(w.End) {
			continue
		}
		if !found || w.FailPerMille > worst.FailPerMille {
			worst, found = w, true
		}
	}
	return worst, found
}

// FailPerMille is the issuer health model: a per-issuer baseline, raised to the
// window's failure rate while an outage covers it. An unknown key gets the
// generic baseline rather than zero, because "never fails" is the one answer
// that would make the whole harness useless.
func (t *Timeline) FailPerMille(issuerKey string, now time.Time) int {
	fail, ok := t.baseline[issuerKey]
	if !ok {
		fail = defaultBaseFailPerMille
	}
	if w, active := t.ActiveWindow(issuerKey, now); active && w.FailPerMille > fail {
		fail = w.FailPerMille
	}
	return fail
}

// defaultBaseFailPerMille is the health of an issuer the mix does not describe,
// which happens when a client retries a payment id this process did not mint.
const defaultBaseFailPerMille = 80

// ---------------------------------------------------------------------------
// Event script
// ---------------------------------------------------------------------------

// ScheduledEvent is one webhook the simulator will deliver, fully decided
// before the run starts. Deciding up front rather than at delivery time is what
// makes a run reproducible: network timing, goroutine scheduling, and the
// target's response latency cannot influence the content of a single event.
type ScheduledEvent struct {
	Seq          int                        `json:"seq"`
	OffsetMS     int64                      `json:"offset_ms"`
	EventID      string                     `json:"event_id"`
	Event        string                     `json:"event"`
	IssuerKey    string                     `json:"issuer_key"`
	Duplicate    bool                       `json:"duplicate"`
	Payment      domain.PaymentEntity       `json:"payment"`
	Subscription *domain.SubscriptionEntity `json:"subscription,omitempty"`
}

// Script generates the whole run up front.
//
// rate is attempted payments per second, not webhooks per second: an attempt
// succeeds or fails against the issuer health model and only failures produce a
// webhook. That indirection is what makes an outage look like an outage — the
// incident feed accelerates on its own when the issuer goes down, instead of
// arriving at the constant rate an operator typed.
//
// Every attempt consumes the same number of draws whether it fails or not, so
// changing an outage window changes which payments fail without changing which
// payments exist. Two scenarios at one seed therefore run the same traffic, and
// the difference between them is attributable.
func (t *Timeline) Script(ratePerSecond float64, duplicatePerMille int) ([]ScheduledEvent, error) {
	if !(ratePerSecond > 0) || ratePerSecond > maxRatePerSecond {
		return nil, fmt.Errorf("simulator: rate %.4f out of range (0, %.0f]", ratePerSecond, maxRatePerSecond)
	}
	if duplicatePerMille < 0 || duplicatePerMille > perMille {
		return nil, fmt.Errorf("simulator: duplicate rate %d per mille out of range [0, %d]",
			duplicatePerMille, perMille)
	}

	rng := rand.New(rand.NewSource(scriptSeed(t.seed, t.scenario)))
	out := make([]ScheduledEvent, 0, 256)
	elapsed := time.Duration(0)
	attempt := 0

	for len(out) < maxScriptEvents {
		// Poisson arrivals: exponential gaps. Floored at a millisecond so a
		// pathological draw cannot produce a zero-length gap and spin.
		gap := time.Duration(rng.ExpFloat64() / ratePerSecond * float64(time.Second))
		if gap < time.Millisecond {
			gap = time.Millisecond
		}
		elapsed += gap
		if elapsed >= t.duration {
			break
		}
		attempt++

		profile := t.pickProfile(rng)
		amount := pickAmount(rng)
		recurring := profile.MandateEligible && rng.Intn(perMille) < t.recurringPerMille
		outcomeRoll := rng.Intn(perMille)
		codeRoll := rng.Intn(perMille)
		dupRoll := rng.Intn(perMille)

		at := t.start.Add(elapsed)
		key := profile.issuerKey()
		if outcomeRoll >= t.FailPerMille(key, at) {
			continue // succeeded; a successful payment is not this system's business
		}

		_, outage := t.ActiveWindow(key, at)
		out = append(out, t.buildEvent(attempt, elapsed, at, profile, key, amount, recurring,
			codeRoll, outage, dupRoll < duplicatePerMille))
	}
	return out, nil
}

func (t *Timeline) buildEvent(seq int, offset time.Duration, at time.Time, p instrumentProfile,
	issuerKey string, amount int64, recurring bool, codeRoll int, outage, duplicate bool) ScheduledEvent {

	seqStr := strconv.Itoa(seq)
	payID := razorID("pay", t.seed, t.scenario, seqStr)
	fc := pickFailure(p.Method, outage, codeRoll)

	pe := domain.PaymentEntity{
		ID:          payID,
		Amount:      amount,
		Currency:    "INR",
		Status:      "failed",
		OrderID:     razorID("order", t.seed, t.scenario, seqStr),
		Method:      p.Method,
		Bank:        p.Bank,
		Wallet:      p.Wallet,
		ErrorCode:   fc.Code,
		ErrorReason: fc.Code,
		ErrorStep:   fc.Step,
		ErrorSource: fc.Source,
		ErrorDesc:   fc.Description,
		CreatedAt:   at.Unix(),
	}
	if strings.EqualFold(p.Method, "upi") {
		pe.VPA = syntheticVPA(payID, p.VPAHandle)
	}

	ev := ScheduledEvent{
		Seq:       seq,
		OffsetMS:  offset.Milliseconds(),
		EventID:   razorID("evt", t.seed, t.scenario, seqStr),
		Event:     "payment.failed",
		IssuerKey: issuerKey,
		Duplicate: duplicate,
		Payment:   pe,
	}

	if recurring {
		subID := razorID("sub", t.seed, t.scenario, seqStr)
		ev.Payment.SubscriptionID = subID
		ev.Payment.InvoiceID = razorID("inv", t.seed, t.scenario, seqStr)
		// Cycle counters are derived from the sequence rather than drawn, so a
		// mandate's position in its cycle is a property of the event and not of
		// the generator's state.
		paid := seq % 11
		ev.Subscription = &domain.SubscriptionEntity{
			ID:             subID,
			Status:         "active",
			PlanID:         razorID("plan", t.seed, t.scenario, strconv.Itoa(seq%7)),
			CustomerID:     razorID("cust", t.seed, t.scenario, strconv.Itoa(seq%23)),
			CurrentStart:   at.Add(-30 * 24 * time.Hour).Unix(),
			CurrentEnd:     at.Add(24 * time.Hour).Unix(),
			ChargeAt:       at.Unix(),
			PaidCount:      paid,
			RemainingCount: 12 - paid,
			TotalCount:     12,
			AuthAttempts:   1 + seq%3,
		}
	}
	return ev
}

// pickProfile draws from the traffic mix by weight, walking the slice in its
// declared order. Ranging over a map would be the obvious way to write this and
// would silently destroy reproducibility.
func (t *Timeline) pickProfile(rng *rand.Rand) instrumentProfile {
	roll := rng.Intn(t.totalWeight)
	for _, p := range t.mix {
		if roll < p.Weight {
			return p
		}
		roll -= p.Weight
	}
	return t.mix[len(t.mix)-1]
}

// amountBands is a plausible Indian e-commerce order-value distribution.
//
// Every bound is paisa and every draw is integer arithmetic. There is no
// floating-point operation anywhere on a money path in this program.
var amountBands = []struct {
	Weight int
	Min    int64
	Max    int64
}{
	{18, 9_900, 49_900},        // impulse buys, food delivery
	{30, 50_000, 199_900},      // fashion, groceries
	{24, 200_000, 499_900},     // mid-basket
	{14, 500_000, 1_499_900},   // electronics
	{9, 1_500_000, 4_999_900},  // appliances, travel — above the general AFA ceiling
	{5, 5_000_000, 24_999_900}, // high value
}

func pickAmount(rng *rand.Rand) int64 {
	total := 0
	for _, b := range amountBands {
		total += b.Weight
	}
	roll := rng.Intn(total)
	band := amountBands[len(amountBands)-1]
	for _, b := range amountBands {
		if roll < b.Weight {
			band = b
			break
		}
		roll -= b.Weight
	}

	v := band.Min + rng.Int63n(band.Max-band.Min+1)
	rupees := v / 100
	// Indian list prices cluster hard on a 9 ending; snapping most draws there
	// keeps the amount histogram from looking machine-generated.
	if rng.Intn(perMille) < 600 {
		rupees = rupees - rupees%10 + 9
	}
	amount := rupees * 100
	if amount < band.Min {
		amount = band.Min
	}
	return amount
}

// syntheticVPA builds an obviously fake virtual payment address on a real
// handle. The local part is derived from the payment id so it is stable across
// restarts, and prefixed "sim." so nothing in a log or a screenshot can be
// mistaken for a real customer's address.
func syntheticVPA(paymentID, handle string) string {
	if handle == "" || len(paymentID) < 6 {
		return ""
	}
	return "sim." + strings.ToLower(paymentID[len(paymentID)-6:]) + "@" + handle
}

// ---------------------------------------------------------------------------
// Deterministic identifiers
// ---------------------------------------------------------------------------

// idAlphabet matches the alphanumeric shape of a Razorpay identifier.
const idAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// idBodyLen is the length of the suffix Razorpay uses after the type prefix.
const idBodyLen = 14

// razorID mints a Razorpay-shaped identifier as a pure function of the seed and
// the caller's discriminators, so the same seed yields the same ids across
// processes and across restarts. Parts are absorbed length-prefixed rather than
// concatenated, so ("a","bc") and ("ab","c") cannot collide.
//
// The modulo below is a cosmetic bias on an identifier alphabet, not on key
// material: nothing here is secret and nothing depends on uniformity.
func razorID(prefix string, seed int64, parts ...string) string {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], uint64(seed))
	mac := hmac.New(sha256.New, key[:])
	absorbString(mac, prefix)
	for _, p := range parts {
		absorbString(mac, p)
	}
	sum := mac.Sum(nil)

	var b strings.Builder
	b.Grow(len(prefix) + 1 + idBodyLen)
	b.WriteString(prefix)
	b.WriteByte('_')
	for i := 0; i < idBodyLen; i++ {
		b.WriteByte(idAlphabet[int(sum[i])%len(idAlphabet)])
	}
	return b.String()
}

func absorbString(w interface{ Write([]byte) (int, error) }, s string) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(s)))
	// hash.Hash documents that Write never returns an error.
	_, _ = w.Write(l[:])
	_, _ = w.Write([]byte(s))
}

// scriptSeed folds the scenario name into the seed so --seed 42 does not
// generate identical arrival times for two different scenarios, which would
// make a side-by-side comparison look more coincidental than it is.
func scriptSeed(seed int64, scenario string) int64 {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], uint64(seed))
	mac := hmac.New(sha256.New, key[:])
	absorbString(mac, "script")
	absorbString(mac, scenario)
	return int64(binary.BigEndian.Uint64(mac.Sum(nil)[:8]))
}

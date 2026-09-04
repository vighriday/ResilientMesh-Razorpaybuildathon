package domain

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Issuer keys
// ---------------------------------------------------------------------------

// TestIssuerKeyPerMethod pins the key space. Every rolling failure counter,
// every breaker and every downtime join is addressed by this string, so a
// change to its shape silently splits one issuer's history into two and empties
// both.
func TestIssuerKeyPerMethod(t *testing.T) {
	cases := []struct {
		name string
		p    PaymentEntity
		want string
	}{
		// UPI keys off the PSP handle rather than the bank: UPI outages are
		// handle-scoped, so keying on the bank would average a broken PSP into
		// a healthy issuer's numbers.
		{"upi handle", PaymentEntity{Method: "upi", VPA: "customer@okhdfcbank"}, "upi:okhdfcbank"},
		{"upi handle upper", PaymentEntity{Method: "UPI", VPA: "Customer@OKHDFCBANK"}, "upi:okhdfcbank"},
		{"upi with several at signs", PaymentEntity{Method: "upi", VPA: "a@b@ybl"}, "upi:ybl"},
		{"upi no handle", PaymentEntity{Method: "upi", VPA: "customer"}, "upi:unknown"},
		{"upi trailing at", PaymentEntity{Method: "upi", VPA: "customer@"}, "upi:unknown"},
		{"upi leading at", PaymentEntity{Method: "upi", VPA: "@ybl"}, "upi:ybl"},
		{"upi empty vpa", PaymentEntity{Method: "upi"}, "upi:unknown"},

		{"wallet", PaymentEntity{Method: "wallet", Wallet: "PayTM"}, "wallet:paytm"},
		{"wallet unnamed", PaymentEntity{Method: "wallet"}, "wallet:unknown"},

		{"card", PaymentEntity{Method: "card", Bank: "hdfc"}, "card:HDFC"},
		{"card no bank", PaymentEntity{Method: "card"}, "card:unknown"},
		{"netbanking", PaymentEntity{Method: "NetBanking", Bank: "kkbk"}, "netbanking:KKBK"},
		{"emi keeps its own method", PaymentEntity{Method: "emi", Bank: "icici"}, "emi:ICICI"},
		{"unknown method", PaymentEntity{Method: "crypto", Bank: "x"}, "crypto:X"},
		{"empty method", PaymentEntity{}, ":unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Issuer(); got != tc.want {
				t.Fatalf("Issuer() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIssuerKeyIsStable guards against the key acquiring a dependency on
// anything but its inputs. A key that varied per call would scatter one
// issuer's failures across many counters and make every degradation verdict
// meaningless.
func TestIssuerKeyIsStable(t *testing.T) {
	p := PaymentEntity{Method: "card", Bank: "HDFC", VPA: "a@b", Wallet: "paytm"}
	first := p.Issuer()
	for i := 0; i < 64; i++ {
		if got := p.Issuer(); got != first {
			t.Fatalf("Issuer() returned %q then %q for the same value", first, got)
		}
	}
	// Fields the key must not depend on: changing them must not move the key,
	// or two attempts on one instrument would land in different windows.
	other := p
	other.ID, other.Amount, other.ErrorCode, other.Status = "pay_2", 999, "server_error", "created"
	if other.Issuer() != first {
		t.Fatalf("Issuer() depends on a field outside the instrument: %q vs %q", other.Issuer(), first)
	}
}

// TestIssuerKeyCannotBeForgedByShiftingTheMethodBoundary is the separator's
// reason for existing. Without the ":" the method and the bank would simply be
// concatenated, and a payment with method "cardx" and bank "HDFC" would address
// the same counter as method "card" and bank "XHDFC" — letting one instrument's
// failures be attributed to another issuer, which is how a healthy issuer gets
// routed away from or a broken one gets routed to.
func TestIssuerKeyCannotBeForgedByShiftingTheMethodBoundary(t *testing.T) {
	// Each pair is chosen so the shifted character is case-invariant, because
	// the naive scheme these are compared against also folds case: a letter
	// would differ under the fold and the collision would be an artefact of the
	// casing rather than of the missing separator.
	pairs := []struct {
		a, b  PaymentEntity
		naive string // what both would produce with no separator
	}{
		{
			a:     PaymentEntity{Method: "card", Bank: "1HDFC"},
			b:     PaymentEntity{Method: "card1", Bank: "HDFC"},
			naive: "card1HDFC",
		},
		{
			a:     PaymentEntity{Method: "netbanking", Bank: "0PNB"},
			b:     PaymentEntity{Method: "netbanking0", Bank: "PNB"},
			naive: "netbanking0PNB",
		},
	}
	for _, pair := range pairs {
		// Non-vacuity: without the separator these two instruments really would
		// address one counter, so a broken issuer's failures would be charged to
		// a healthy one and the routing decision built on that counter would be
		// made from another institution's numbers.
		naiveA := foldLower(pair.a.Method) + foldUpper(pair.a.Bank)
		naiveB := foldLower(pair.b.Method) + foldUpper(pair.b.Bank)
		if naiveA != naiveB || naiveA != pair.naive {
			t.Fatalf("the pair does not collide under naive concatenation, so it proves nothing: %q vs %q", naiveA, naiveB)
		}
		if a, b := pair.a.Issuer(), pair.b.Issuer(); a == b {
			t.Errorf("two different instruments share the telemetry key %q", a)
		}
	}
	// The same property across the branches: a UPI handle one character shorter
	// is a different PSP and must not share a counter.
	if x, y := (PaymentEntity{Method: "upi", VPA: "a@yb"}).Issuer(), (PaymentEntity{Method: "upi", VPA: "a@ybl"}).Issuer(); x == y {
		t.Errorf("two UPI handles share the key %q", x)
	}
	// A wallet and a card at the same institution must not collide either: the
	// method prefix is what keeps their failure histories separate.
	if x, y := (PaymentEntity{Method: "wallet", Wallet: "hdfc"}).Issuer(), (PaymentEntity{Method: "card", Bank: "hdfc"}).Issuer(); x == y {
		t.Errorf("a wallet and a card at one institution share the key %q", x)
	}
}

// TestDowntimeKeyJoinsAgainstTheIssuerKeySpace is the whole point of
// TelemetryKey: a downtime notice must address the same counter as the payments
// it explains, without a lookup table between them. If the two key spaces
// drift, a confirmed outage stops matching the incidents it caused and the
// release-on-resolution path never fires.
func TestDowntimeKeyJoinsAgainstTheIssuerKeySpace(t *testing.T) {
	cases := []struct {
		name string
		pay  PaymentEntity
		down DowntimeEntity
	}{
		{
			"upi by handle",
			PaymentEntity{Method: "upi", VPA: "customer@okhdfcbank"},
			DowntimeEntity{Method: "upi", Instrument: DowntimeInstrument{VPAHandle: "okhdfcbank"}},
		},
		{
			"upi falls back to the psp",
			PaymentEntity{Method: "upi", VPA: "customer@ybl"},
			DowntimeEntity{Method: "UPI", Instrument: DowntimeInstrument{PSP: "YBL"}},
		},
		{
			"wallet",
			PaymentEntity{Method: "wallet", Wallet: "phonepe"},
			DowntimeEntity{Method: "wallet", Instrument: DowntimeInstrument{Issuer: "PhonePe"}},
		},
		{
			"card by issuer",
			PaymentEntity{Method: "card", Bank: "HDFC"},
			DowntimeEntity{Method: "card", Instrument: DowntimeInstrument{Issuer: "hdfc"}},
		},
		{
			"card falling back to bank",
			PaymentEntity{Method: "card", Bank: "ICICI"},
			DowntimeEntity{Method: "CARD", Instrument: DowntimeInstrument{Bank: "icici"}},
		},
		{
			"netbanking",
			PaymentEntity{Method: "netbanking", Bank: "PNB"},
			DowntimeEntity{Method: "netbanking", Instrument: DowntimeInstrument{Bank: "pnb"}},
		},
		{
			"unknown on both sides",
			PaymentEntity{Method: "card"},
			DowntimeEntity{Method: "card"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := tc.down.TelemetryKey(), tc.pay.Issuer(); got != want {
				t.Fatalf("TelemetryKey() = %q but Issuer() = %q; the two key spaces have drifted", got, want)
			}
		})
	}
}

func TestTelemetryKeyIsStableAndDistinguishesBoundaryShifts(t *testing.T) {
	d := DowntimeEntity{Method: "card", Instrument: DowntimeInstrument{Issuer: "HDFC"}}
	first := d.TelemetryKey()
	for i := 0; i < 64; i++ {
		if got := d.TelemetryKey(); got != first {
			t.Fatalf("TelemetryKey() returned %q then %q", first, got)
		}
	}
	shifted := DowntimeEntity{Method: "cardh", Instrument: DowntimeInstrument{Issuer: "DFC"}}
	if shifted.TelemetryKey() == first {
		t.Fatalf("a method/issuer boundary shift produced the same key %q", first)
	}
	// The issuer takes precedence over the bank, so a notice carrying both
	// resolves the same way every time rather than depending on which field a
	// producer happened to fill.
	both := DowntimeEntity{Method: "card", Instrument: DowntimeInstrument{Issuer: "HDFC", Bank: "ICICI"}}
	if both.TelemetryKey() != "card:HDFC" {
		t.Fatalf("TelemetryKey() = %q, want the issuer to win over the bank", both.TelemetryKey())
	}
}

// ---------------------------------------------------------------------------
// Downtime windows
// ---------------------------------------------------------------------------

func TestDowntimeActiveCoversTheWindowInclusively(t *testing.T) {
	begin := time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC)
	end := begin.Add(5 * time.Minute)
	endUnix := end.Unix()
	open := DowntimeEntity{Status: DowntimeStarted, Begin: begin.Unix(), End: &endUnix}

	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"one second before the window", begin.Add(-time.Second), false},
		{"exactly at begin", begin, true},
		{"inside", begin.Add(time.Minute), true},
		{"exactly at end", end, true},
		{"one second after end", end.Add(time.Second), false},
		// Sub-second precision is discarded by the Unix() comparison, so the
		// last second of the window is fully covered rather than half of it.
		{"end plus 999ms", end.Add(999 * time.Millisecond), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := open.Active(tc.at); got != tc.want {
				t.Fatalf("Active(%s) = %t, want %t", tc.at, got, tc.want)
			}
		})
	}

	// A resolved notice is never active, whatever its window says. In this
	// ecosystem recovery is published rather than inferred, so the status is the
	// authoritative signal and the timestamps are commentary.
	resolved := open
	resolved.Status = DowntimeResolved
	if resolved.Active(begin.Add(time.Minute)) {
		t.Fatal("a resolved notice reported active inside its window")
	}

	// A notice with no end is open-ended: this is what an ongoing outage looks
	// like, and treating it as finished would release traffic back into it.
	ongoing := DowntimeEntity{Status: DowntimeStarted, Begin: begin.Unix()}
	if !ongoing.Active(begin.Add(30 * 24 * time.Hour)) {
		t.Fatal("an unterminated notice stopped being active")
	}
	if ongoing.Active(begin.Add(-time.Second)) {
		t.Fatal("an unterminated notice was active before it began")
	}

	for _, st := range []DowntimeStatus{DowntimeScheduled, DowntimeStarted, DowntimeUpdated} {
		d := open
		d.Status = st
		if !d.Active(begin.Add(time.Minute)) {
			t.Errorf("status %q is not resolved, so the notice must still be active inside its window", st)
		}
	}
}

// ---------------------------------------------------------------------------
// Recurrence
// ---------------------------------------------------------------------------

func TestIsRecurringActivatesOnEitherMandateIdentifier(t *testing.T) {
	// Either identifier is enough: Razorpay attaches a subscription id to
	// subscription debits and an invoice id to some mandate-backed invoices, and
	// missing either would skip the entire RBI invariant set for that payment.
	cases := []struct {
		p    PaymentEntity
		want bool
	}{
		{PaymentEntity{}, false},
		{PaymentEntity{SubscriptionID: "sub_1"}, true},
		{PaymentEntity{InvoiceID: "inv_1"}, true},
		{PaymentEntity{SubscriptionID: "sub_1", InvoiceID: "inv_1"}, true},
		{PaymentEntity{SubscriptionID: " "}, true},
	}
	for _, tc := range cases {
		if got := tc.p.IsRecurring(); got != tc.want {
			t.Errorf("IsRecurring() = %t for %+v, want %t", got, tc.p, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RawJSON
// ---------------------------------------------------------------------------

// TestRawJSONEmbedsRatherThanEncodes covers the reason the type exists: a plain
// []byte marshals as base64, which would make every stored payload and audit
// detail unreadable and would change the bytes the audit chain commits to.
func TestRawJSONEmbedsRatherThanEncodes(t *testing.T) {
	type wrapper struct {
		Payload RawJSON `json:"payload"`
	}
	in := wrapper{Payload: RawJSON(`{"amount":250000,"currency":"INR"}`)}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"payload":{"amount":250000,"currency":"INR"}}`
	if string(out) != want {
		t.Fatalf("Marshal = %s, want %s", out, want)
	}

	var back wrapper
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(back.Payload) != string(in.Payload) {
		t.Fatalf("round trip changed the bytes: %s vs %s", back.Payload, in.Payload)
	}
}

func TestRawJSONRefusesToEmitInvalidJSON(t *testing.T) {
	// An invalid payload must fail the write rather than produce a document
	// that cannot be read back. The audit ledger hashes these bytes, so a
	// document that silently became unparseable would break verification for
	// every entry after it with no indication of where it started.
	for _, bad := range []string{`{"a":`, `not json`, `{"a":1}{"b":2}`, "\x00"} {
		if _, err := RawJSON(bad).MarshalJSON(); err == nil {
			t.Errorf("RawJSON(%q) marshalled cleanly, want an error", bad)
		}
	}
	// Empty is the one exception: a record with no detail marshals as null
	// rather than failing, because "nothing to say" is a legitimate state.
	for _, empty := range []RawJSON{nil, {}} {
		got, err := empty.MarshalJSON()
		if err != nil {
			t.Fatalf("empty RawJSON: %v", err)
		}
		if string(got) != "null" {
			t.Fatalf("empty RawJSON marshalled as %s, want null", got)
		}
	}
	for _, ok := range []string{`{}`, `[]`, `null`, `1`, `"s"`, `true`, ` {"a": 1} `} {
		if _, err := RawJSON(ok).MarshalJSON(); err != nil {
			t.Errorf("RawJSON(%q) was rejected: %v", ok, err)
		}
	}
}

// TestRawJSONUnmarshalDoesNotAliasItsInput matters because encoding/json reuses
// its scratch buffer: a RawJSON that kept a reference into it would be
// overwritten by the next decode, and the value that reached the ledger would
// not be the value that was verified.
func TestRawJSONUnmarshalDoesNotAliasItsInput(t *testing.T) {
	src := []byte(`{"a":1}`)
	var r RawJSON
	if err := r.UnmarshalJSON(src); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	copy(src, []byte(`{"b":2}`))
	if string(r) != `{"a":1}` {
		t.Fatalf("RawJSON aliases the caller's buffer: %s", r)
	}
	// Reusing the destination must not concatenate: UnmarshalJSON truncates
	// before appending, so a decoder that reuses a struct gets the new document
	// and not both.
	if err := r.UnmarshalJSON([]byte(`{"c":3}`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if string(r) != `{"c":3}` {
		t.Fatalf("a reused RawJSON accumulated documents: %s", r)
	}
}

// ---------------------------------------------------------------------------
// Webhook envelope
// ---------------------------------------------------------------------------

// TestWebhookPayloadToleratesUnknownFields is the decoder policy stated as a
// test. Razorpay adds attributes without a version bump, so a strict decoder
// would reject otherwise-valid production traffic — and a rejected webhook is a
// lost payment failure, because the retry eventually gives up.
func TestWebhookPayloadToleratesUnknownFields(t *testing.T) {
	body := []byte(`{
		"entity": "event",
		"account_id": "acc_1",
		"event": "payment.failed",
		"contains": ["payment"],
		"created_at": 1767225600,
		"brand_new_field": {"nested": [1,2,3]},
		"payload": {
			"payment": {"entity": {
				"id": "pay_1", "amount": 250000, "currency": "INR", "status": "failed",
				"order_id": "order_1", "method": "card", "bank": "HDFC",
				"error_code": "bank_technical_error",
				"error_description": "issuer unavailable",
				"another_new_field": true
			}},
			"subscription": {"entity": {"id": "sub_1", "status": "active", "auth_attempts": 2}}
		}
	}`)
	var p RazorpayWebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	pay := p.Payload.Payment.Entity
	if pay.ID != "pay_1" || pay.Amount != 250000 || pay.Currency != "INR" {
		t.Fatalf("payment entity did not decode: %+v", pay)
	}
	if pay.ErrorDesc != "issuer unavailable" {
		t.Fatalf("error_description mapped to %q; the wire name and the field name differ and the tag is what bridges them", pay.ErrorDesc)
	}
	if p.Payload.Subscription == nil || p.Payload.Subscription.Entity.AuthAttempts != 2 {
		t.Fatalf("subscription entity did not decode: %+v", p.Payload.Subscription)
	}
	// A payload with no subscription leaves the pointer nil rather than
	// materialising an empty mandate, which is what lets IsRecurring stay the
	// single source of that judgement.
	var noSub RazorpayWebhookPayload
	if err := json.Unmarshal([]byte(`{"event":"payment.failed","payload":{"payment":{"entity":{"id":"p"}}}}`), &noSub); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if noSub.Payload.Subscription != nil {
		t.Fatal("an absent subscription decoded as a present one")
	}
}

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RBI additional-factor ceilings
// ---------------------------------------------------------------------------

// TestAFACeilingsMatchTheRegulation pins the two numbers in paisa and restates
// them in rupees in the same expression.
//
// These are not tuning parameters. Above the applicable ceiling a recurring
// debit needs a fresh additional factor and cannot be re-presented, so an
// automatic retry there is a breach rather than a suboptimal choice. A typo that
// widened either constant would be invisible in every test that computes the
// expectation from the constant itself, which is why the expectation is written
// out longhand here.
func TestAFACeilingsMatchTheRegulation(t *testing.T) {
	const paisaPerRupee = 100
	if AFACeilingGeneralPaisa != 15_000*paisaPerRupee {
		t.Errorf("general ceiling = %d paisa (Rs %d), want Rs 15,000",
			AFACeilingGeneralPaisa, AFACeilingGeneralPaisa/paisaPerRupee)
	}
	if AFACeilingElevatedPaisa != 1_00_000*paisaPerRupee {
		t.Errorf("elevated ceiling = %d paisa (Rs %d), want Rs 1,00,000",
			AFACeilingElevatedPaisa, AFACeilingElevatedPaisa/paisaPerRupee)
	}
	if AFACeilingGeneralPaisa >= AFACeilingElevatedPaisa {
		t.Fatal("the general ceiling is not stricter than the elevated one; the default would be the permissive branch")
	}
}

// categoryCeilings states the intended ceiling for every declared category.
var categoryCeilings = map[MandateCategory]int64{
	CategoryGeneral:        AFACeilingGeneralPaisa,
	CategoryInsurance:      AFACeilingElevatedPaisa,
	CategoryMutualFund:     AFACeilingElevatedPaisa,
	CategoryCreditCardBill: AFACeilingElevatedPaisa,
}

func TestAFACeilingPerDeclaredCategory(t *testing.T) {
	for c, want := range categoryCeilings {
		if got := c.AFACeilingPaisa(); got != want {
			t.Errorf("MandateCategory(%q).AFACeilingPaisa() = %d, want %d", c, got, want)
		}
	}
}

// TestUnknownCategoryGetsTheStrictCeiling is the money-side fail-closed check.
// An unrecognised category reaching the elevated ceiling would widen a
// regulatory limit for a value nobody validated — a database column written by
// an older build, a typo in a merchant configuration, or a model-supplied
// string that slipped through.
func TestUnknownCategoryGetsTheStrictCeiling(t *testing.T) {
	unknown := []MandateCategory{
		"", " ", "General", "GENERAL", "insurance ", " insurance",
		"insurance_premium", "mutualfund", "mutual fund", "credit_card",
		"credit_card_bill_v2", "utility", MandateCategory(strings.Repeat("i", 300)),
		"insurance\x00", "insurance\n",
	}
	for _, c := range unknown {
		if got := c.AFACeilingPaisa(); got != AFACeilingGeneralPaisa {
			t.Errorf("MandateCategory(%q).AFACeilingPaisa() = %d, want the strict general ceiling %d",
				c, got, AFACeilingGeneralPaisa)
		}
	}
}

// TestParseMandateCategoryNeverWidensACeiling is the property behind the table
// above: parsing may correct a casing or a stray space, but it must never turn a
// string that is not one of the three elevated categories into one of them.
func TestParseMandateCategoryNeverWidensACeiling(t *testing.T) {
	elevated := []MandateCategory{CategoryInsurance, CategoryMutualFund, CategoryCreditCardBill}
	for _, c := range elevated {
		for name, folded := range safeFolds(string(c)) {
			if got := ParseMandateCategory(folded); got != c {
				t.Errorf("ParseMandateCategory(%s of %q) = %q, want %q", name, c, got, c)
			}
		}
		// A non-ASCII lookalike must not fold into an elevated category: that
		// would raise a debit's ceiling from Rs 15,000 to Rs 1,00,000 on a
		// string the merchant never configured.
		for _, hostile := range []string{
			strings.Replace(string(c), "a", "\u0430", 1),         // cyrillic a
			strings.Replace(string(c), "u", "\u1d1c", 1),         // small capital u
			strings.ToUpper(string(c)) + "\x00",                  // trailing NUL
			string(c[:len(c)/2]) + "\x00" + string(c[len(c)/2:]), // interior NUL
		} {
			if hostile == string(c) {
				continue
			}
			if got := ParseMandateCategory(hostile); got != CategoryGeneral {
				t.Errorf("ParseMandateCategory(%q) = %q; a hostile variant must fall back to the strict category", hostile, got)
			}
		}
	}
	// The exhaustive statement of the same rule, over the ceiling rather than
	// the label: no input may ever produce more than the elevated ceiling, and
	// anything unrecognised produces the general one.
	for _, s := range []string{"", "x", "INSURANCE", " mutual_fund\t", "credit_card_bill", "insurance-premium"} {
		got := ParseMandateCategory(s).AFACeilingPaisa()
		if got > AFACeilingElevatedPaisa {
			t.Errorf("ParseMandateCategory(%q) produced a ceiling above the elevated limit: %d", s, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

var stateTerminality = map[IncidentState]bool{
	IncidentReceived:  false,
	IncidentDiagnosed: false,
	IncidentGated:     false,
	IncidentScheduled: false,
	IncidentExecuting: false,
	IncidentRecovered: true,
	IncidentAbandoned: true,
	IncidentAbstained: true,
}

// TestTerminalIsDecidedForEveryDeclaredState matters because the store refuses
// every mutation of a terminal incident: a state wrongly reported terminal
// freezes a live incident, and one wrongly reported non-terminal lets a late
// redelivery reopen a RECOVERED incident and buy another debit.
func TestTerminalIsDecidedForEveryDeclaredState(t *testing.T) {
	for s, want := range stateTerminality {
		if got := s.Terminal(); got != want {
			t.Errorf("IncidentState(%q).Terminal() = %t, want %t", s, got, want)
		}
	}
	for _, s := range []IncidentState{"", " ", "recovered", "RECOVERED ", "DONE", "RECOVERED\x00"} {
		if s.Terminal() {
			t.Errorf("IncidentState(%q).Terminal() = true; an unrecognised state must not read as final", s)
		}
	}
}

func TestSessionExpiryClosesOnBothConditions(t *testing.T) {
	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		rec     SessionRecord
		expired bool
	}{
		{"active and in date", SessionRecord{Active: true, ExpiresAt: now.Add(time.Minute)}, false},
		{"active, exactly at expiry", SessionRecord{Active: true, ExpiresAt: now}, false},
		{"active, one nanosecond past", SessionRecord{Active: true, ExpiresAt: now.Add(-time.Nanosecond)}, true},
		// Inactive wins regardless of the clock: a closed session must never be
		// morphed, and a future ExpiresAt on a closed session is exactly what a
		// stale read looks like.
		{"inactive but in date", SessionRecord{Active: false, ExpiresAt: now.Add(time.Hour)}, true},
		{"zero value", SessionRecord{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Expired(now); got != tc.expired {
				t.Fatalf("Expired() = %t, want %t", got, tc.expired)
			}
		})
	}
}

func TestSessionTokenIsNeverSerialised(t *testing.T) {
	// Only the hash is stored, and even the hash must not leave the process in
	// a JSON body: a response that echoed it would hand a reader something to
	// replay against the SSE endpoint.
	s := SessionRecord{ID: "sess_1", TokenHash: strings.Repeat("d", 64)}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), s.TokenHash) || strings.Contains(string(b), "token") {
		t.Fatalf("session JSON carries the token hash: %s", b)
	}
}

// ---------------------------------------------------------------------------
// Audit hash chain
// ---------------------------------------------------------------------------

func baseEntry() AuditEntry {
	return AuditEntry{
		Seq:        7,
		IncidentID: "inc_000042",
		Kind:       AuditGateDecision,
		Actor:      "worker/worker-0",
		Detail:     RawJSON(`{"action":"ASYNC_EXPONENTIAL_RETRY"}`),
		At:         time.Date(2026, 1, 1, 0, 0, 3, 250_000_000, time.UTC),
		PrevHash:   strings.Repeat("a", 64),
	}
}

// naiveHash is the implementation ComputeHash deliberately is not: the same
// fields, concatenated without length prefixes. It exists so the collision test
// below proves something rather than asserting two arbitrary hashes differ.
func naiveHash(e AuditEntry) string {
	h := sha256.New()
	_, _ = h.Write([]byte(e.IncidentID))
	_, _ = h.Write([]byte(e.Kind))
	_, _ = h.Write([]byte(e.Actor))
	_, _ = h.Write(e.Detail)
	_, _ = h.Write([]byte(e.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// TestLengthPrefixingDefeatsFieldBoundaryShifts is the reason ComputeHash
// absorbs lengths.
//
// An attacker who controls two adjacent fields — the incident id and the actor
// are both strings that reach the ledger from outside — can otherwise move a
// character across the boundary between them and produce a second entry with
// the same digest as the first. A colliding entry is a forged link: it verifies
// against the same predecessor and the same successor, so it can be substituted
// into the chain without the linear verification pass noticing.
//
// Each pair below is constructed so the naive concatenation is byte-identical.
// The test asserts both halves: that the naive scheme really does collide, and
// that this one does not.
func TestLengthPrefixingDefeatsFieldBoundaryShifts(t *testing.T) {
	pairs := []struct {
		name string
		a, b func(AuditEntry) AuditEntry
	}{
		{
			// IncidentID and Kind are adjacent in the absorption order, and both
			// arrive from outside the ledger.
			name: "character shifted from the incident id into the kind",
			a: func(e AuditEntry) AuditEntry {
				e.IncidentID, e.Kind = "inc_", "1GATE_DECISION"
				return e
			},
			b: func(e AuditEntry) AuditEntry {
				e.IncidentID, e.Kind = "inc_1", "GATE_DECISION"
				return e
			},
		},
		{
			name: "character shifted from the kind into the actor",
			a: func(e AuditEntry) AuditEntry {
				e.Kind, e.Actor = "GATE_DECISIONX", "worker/0"
				return e
			},
			b: func(e AuditEntry) AuditEntry {
				e.Kind, e.Actor = "GATE_DECISION", "Xworker/0"
				return e
			},
		},
		{
			// The actor is the field an operator endpoint fills in, and the
			// detail immediately follows it.
			name: "detail bytes shifted into the actor",
			a: func(e AuditEntry) AuditEntry {
				e.Actor, e.Detail = "worker/0{", RawJSON(`"k":1}`)
				return e
			},
			b: func(e AuditEntry) AuditEntry {
				e.Actor, e.Detail = "worker/0", RawJSON(`{"k":1}`)
				return e
			},
		},
		{
			name: "detail byte shifted into the previous hash",
			a: func(e AuditEntry) AuditEntry {
				e.Detail, e.PrevHash = RawJSON(`{"k":1}a`), strings.Repeat("a", 63)
				return e
			},
			b: func(e AuditEntry) AuditEntry {
				e.Detail, e.PrevHash = RawJSON(`{"k":1}`), strings.Repeat("a", 64)
				return e
			},
		},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			a, b := p.a(baseEntry()), p.b(baseEntry())
			if sameFields(a, b) {
				t.Fatal("the two entries are identical; the test constructs no boundary shift")
			}
			// Non-vacuity: without length prefixes these genuinely collide.
			if naiveHash(a) != naiveHash(b) {
				t.Fatalf("the naive concatenation does not collide for this pair, so the test "+
					"proves nothing about length prefixing: %+v vs %+v", a, b)
			}
			if a.ComputeHash() == b.ComputeHash() {
				t.Fatalf("ComputeHash collides across a field boundary shift: %s", a.ComputeHash())
			}
		})
	}
}

// sameFields compares the fields ComputeHash absorbs. AuditEntry is not
// comparable with == because Detail is a byte slice.
func sameFields(a, b AuditEntry) bool {
	return a.Seq == b.Seq && a.IncidentID == b.IncidentID && a.Kind == b.Kind &&
		a.Actor == b.Actor && string(a.Detail) == string(b.Detail) &&
		a.At.Equal(b.At) && a.PrevHash == b.PrevHash
}

// TestComputeHashIsStableAndTotal covers the other direction: the digest must
// depend on every field and on nothing else, or a mutation somewhere in the
// record would not break the chain.
func TestComputeHashIsStableAndTotal(t *testing.T) {
	base := baseEntry()
	if base.ComputeHash() != base.ComputeHash() {
		t.Fatal("ComputeHash is not deterministic for one value")
	}
	// A copy hashes identically, so two processes replaying the same ledger
	// agree. Hash itself is excluded, which is what lets an entry commit to its
	// own content.
	copyOf := base
	copyOf.Hash = "whatever was stored"
	if copyOf.ComputeHash() != base.ComputeHash() {
		t.Fatal("the recorded Hash field feeds back into ComputeHash")
	}

	mutations := map[string]func(*AuditEntry){
		"seq":         func(e *AuditEntry) { e.Seq++ },
		"incident id": func(e *AuditEntry) { e.IncidentID += "0" },
		"kind":        func(e *AuditEntry) { e.Kind = AuditAttemptResult },
		"actor":       func(e *AuditEntry) { e.Actor = "operator/mallory" },
		"detail":      func(e *AuditEntry) { e.Detail = RawJSON(`{"action":"PERMANENT_ABSTAIN"}`) },
		"prev hash":   func(e *AuditEntry) { e.PrevHash = strings.Repeat("b", 64) },
		// One nanosecond is the finest distinction the timestamp carries. If it
		// were absorbed at second resolution, two entries a moment apart would
		// be interchangeable in the chain.
		"timestamp by one nanosecond": func(e *AuditEntry) { e.At = e.At.Add(time.Nanosecond) },
		"detail whitespace":           func(e *AuditEntry) { e.Detail = RawJSON(` {"action":"ASYNC_EXPONENTIAL_RETRY"}`) },
	}
	for name, mutate := range mutations {
		e := baseEntry()
		mutate(&e)
		if e.ComputeHash() == base.ComputeHash() {
			t.Errorf("mutating the %s did not change the digest; that field is not committed to", name)
		}
	}

	// The timestamp is absorbed as UTC nanoseconds, so the same instant written
	// in another zone hashes identically. Without the UTC conversion an entry
	// would verify on the machine that wrote it and fail everywhere else.
	shifted := baseEntry()
	shifted.At = base.At.In(time.FixedZone("IST", 5*3600+1800))
	if shifted.ComputeHash() != base.ComputeHash() {
		t.Fatal("the same instant in a different time zone produced a different digest")
	}
	// A monotonic reading attached by time.Now must not change the digest
	// either, which is what Round(0) strips.
	withMono := baseEntry()
	withMono.At = base.At.Round(0)
	if withMono.ComputeHash() != base.ComputeHash() {
		t.Fatal("stripping the monotonic reading changed the digest")
	}
}

func TestVerifyAgainstChecksBothTheLinkAndTheContent(t *testing.T) {
	e := baseEntry()
	e.Hash = e.ComputeHash()
	if !e.VerifyAgainst(e.PrevHash) {
		t.Fatal("a correctly built entry does not verify")
	}
	if e.VerifyAgainst(strings.Repeat("c", 64)) {
		t.Fatal("an entry verified against the wrong predecessor")
	}
	if e.VerifyAgainst("") {
		t.Fatal("an entry verified against an empty predecessor")
	}
	// Content tampering: the recorded digest stays put while the content moves,
	// which is exactly what an edited historical row looks like.
	tampered := e
	tampered.Detail = RawJSON(`{"action":"IN_SESSION_RAIL_MORPH"}`)
	if tampered.VerifyAgainst(tampered.PrevHash) {
		t.Fatal("an entry whose content was edited still verified")
	}
	// Digest tampering: content stays, digest is replaced with another valid
	// digest.
	forged := e
	forged.Hash = baseEntry().ComputeHash()
	forged.Detail = RawJSON(`{"action":"IN_SESSION_RAIL_MORPH"}`)
	if forged.VerifyAgainst(forged.PrevHash) {
		t.Fatal("an entry with a substituted digest still verified")
	}
	// The zero value must not verify against the genesis anchor, or an empty
	// row inserted at the head of a ledger would pass.
	var zero AuditEntry
	if zero.VerifyAgainst(GenesisHash) {
		t.Fatal("a zero entry verified against the genesis hash")
	}
}

// TestChainLinksRejectReorderingAndRemoval walks a short chain and then attacks
// it the two ways a linear ledger can be attacked.
func TestChainLinksRejectReorderingAndRemoval(t *testing.T) {
	build := func(n int) []AuditEntry {
		out := make([]AuditEntry, 0, n)
		prev := GenesisHash
		for i := 1; i <= n; i++ {
			e := baseEntry()
			e.Seq = int64(i)
			e.IncidentID = "inc_" + strings.Repeat("0", 3) + string(rune('0'+i))
			e.At = baseEntry().At.Add(time.Duration(i) * time.Second)
			e.PrevHash = prev
			e.Hash = e.ComputeHash()
			prev = e.Hash
			out = append(out, e)
		}
		return out
	}
	verify := func(chain []AuditEntry) bool {
		prev := GenesisHash
		for _, e := range chain {
			if !e.VerifyAgainst(prev) {
				return false
			}
			prev = e.Hash
		}
		return true
	}
	chain := build(5)
	if !verify(chain) {
		t.Fatal("a freshly built chain does not verify")
	}
	swapped := append([]AuditEntry(nil), chain...)
	swapped[2], swapped[3] = swapped[3], swapped[2]
	if verify(swapped) {
		t.Fatal("a reordered chain verified")
	}
	removed := append(append([]AuditEntry(nil), chain[:2]...), chain[3:]...)
	if verify(removed) {
		t.Fatal("a chain with an entry removed verified")
	}
	edited := append([]AuditEntry(nil), chain...)
	edited[1].Actor = "operator/mallory"
	if verify(edited) {
		t.Fatal("a chain with an edited historical entry verified")
	}
}

func TestGenesisHashIsAWellFormedAnchor(t *testing.T) {
	if len(GenesisHash) != sha256.Size*2 {
		t.Fatalf("GenesisHash is %d characters, want %d hex characters", len(GenesisHash), sha256.Size*2)
	}
	if _, err := hex.DecodeString(GenesisHash); err != nil {
		t.Fatalf("GenesisHash is not hex: %v", err)
	}
	if strings.Trim(GenesisHash, "0") != "" {
		t.Fatal("GenesisHash is not all zeroes; the anchor must be unmistakable")
	}
	// No real entry can hash to the anchor, so the head of a ledger is
	// unambiguous.
	if baseEntry().ComputeHash() == GenesisHash {
		t.Fatal("a real entry hashes to the genesis anchor")
	}
}

// ---------------------------------------------------------------------------
// Cost model
// ---------------------------------------------------------------------------

// TestDefaultCostModelMatchesTheDocumentedFigures pins the economics both the
// live policy engine and the offline benchmark read. If these drift, the
// benchmark stops describing the running system and nothing else would say so.
func TestDefaultCostModelMatchesTheDocumentedFigures(t *testing.T) {
	c := DefaultCostModel()
	cases := []struct {
		name       string
		got        int64
		wantRupees float64
	}{
		{"gateway fee per attempt", c.GatewayFeePerAttemptPaisa, 2.50},
		{"comms cost per message", c.CommsCostPerMessagePaisa, 0.60},
		{"compliance penalty", c.CompliancePenaltyPaisa, 500},
		{"session friction", c.SessionFrictionPaisa, 0.60},
	}
	for _, tc := range cases {
		if want := int64(tc.wantRupees * 100); tc.got != want {
			t.Errorf("%s = %d paisa, want %d (Rs %.2f)", tc.name, tc.got, want, tc.wantRupees)
		}
		if tc.got <= 0 {
			t.Errorf("%s is not positive; a zero cost makes every retry look free", tc.name)
		}
	}
	// A compliance breach must dominate any number of gateway fees, or the
	// expected-value arithmetic would happily buy one.
	if c.CompliancePenaltyPaisa <= c.GatewayFeePerAttemptPaisa*100 {
		t.Fatal("the compliance penalty does not dominate the retry fee; the cost model would price a breach as affordable")
	}
}

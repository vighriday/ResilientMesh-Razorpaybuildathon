package domain

import (
	"fmt"
	"strings"
	"testing"
)

// The taxonomy and the parsers are the system's trust boundary: every closed
// set in this package exists so that an unrecognised value from a model, a
// gateway or an operator degrades to the safe answer instead of being executed.
// These tests are written adversarially because the boundary is only worth
// having if hostile input cannot cross it.

// ---------------------------------------------------------------------------
// A total verdict, and what "more permissive" means
// ---------------------------------------------------------------------------

// verdict is the taxonomy's complete answer about one code. Classification is
// tested as a whole rather than one predicate at a time because the safety
// property is a relation between the four answers, not a property of any one.
type verdict struct {
	terminal    bool
	refreshable bool
	ambiguous   bool
	soft        bool
}

func classify(code string) verdict {
	return verdict{
		terminal:    IsTerminalDecline(code),
		refreshable: IsRefreshable(code),
		ambiguous:   IsAmbiguous(code),
		soft:        IsSoftDecline(code),
	}
}

func (v verdict) String() string {
	return fmt.Sprintf("terminal=%t refreshable=%t ambiguous=%t soft=%t",
		v.terminal, v.refreshable, v.ambiguous, v.soft)
}

// recoveryLicensed reports whether this verdict lets the system spend money on
// the incident. Refreshable licenses a re-presentation, ambiguous licenses an
// inference call and whatever it recommends, and soft licenses a policy retry.
// Terminal licenses nothing, which is why losing it is the other way to fail
// open.
func (v verdict) recoveryLicensed() bool { return v.refreshable || v.ambiguous || v.soft }

// grantsMorePermissionThan reports whether v licenses recovery that base does
// not, or drops a terminal halt base carries. Either direction is a fail-open:
// the first invents a recovery budget for a string nobody issued, the second
// spends one on an instrument the issuer has already declared dead.
func (v verdict) grantsMorePermissionThan(base verdict) bool {
	if base.terminal && !v.terminal {
		return true
	}
	return (v.refreshable && !base.refreshable) ||
		(v.ambiguous && !base.ambiguous) ||
		(v.soft && !base.soft)
}

// canonicalCodes is every code the taxonomy recognises, paired with the set it
// belongs to. Built from the exported maps so a code added to any of them is
// covered by every test below without being listed twice.
func canonicalCodes() map[string]string {
	out := make(map[string]string)
	for c := range TerminalDeclineCodes {
		out[c] = "terminal"
	}
	for c := range RefreshableDeclineCodes {
		out[c] = "refreshable"
	}
	for c := range AmbiguousFailureCodes {
		out[c] = "ambiguous"
	}
	for c := range SoftDeclineCodes {
		out[c] = "soft"
	}
	return out
}

// ---------------------------------------------------------------------------
// The sets are disjoint
// ---------------------------------------------------------------------------

// TestTaxonomySetsAreDisjoint is the structural precondition for every other
// claim here. A code that is both terminal and refreshable, or both terminal
// and soft, would make the system's behaviour depend on which predicate a given
// call site happened to ask first — and the two call sites that matter
// (internal/ingest's halt filter and the gatekeeper's terminal veto) ask
// different questions in different orders.
func TestTaxonomySetsAreDisjoint(t *testing.T) {
	membership := map[string][]string{}
	for c := range TerminalDeclineCodes {
		membership[c] = append(membership[c], "terminal")
	}
	for c := range RefreshableDeclineCodes {
		membership[c] = append(membership[c], "refreshable")
	}
	for c := range AmbiguousFailureCodes {
		membership[c] = append(membership[c], "ambiguous")
	}
	for c := range SoftDeclineCodes {
		membership[c] = append(membership[c], "soft")
	}
	for code, sets := range membership {
		if len(sets) > 1 {
			t.Errorf("code %q is in %v; the taxonomy sets must partition, not overlap", code, sets)
		}
	}
}

// TestEveryCanonicalCodeIsInExactlyOneSet checks the same property through the
// public predicates rather than the maps, so a future predicate that consults
// more than its own map is caught too.
func TestEveryCanonicalCodeIsInExactlyOneSet(t *testing.T) {
	for code, want := range canonicalCodes() {
		v := classify(code)
		n := 0
		for _, in := range []bool{v.terminal, v.refreshable, v.ambiguous, v.soft} {
			if in {
				n++
			}
		}
		if n != 1 {
			t.Errorf("code %q (%s) classifies as %s; want exactly one set", code, want, v)
		}
	}
}

// TestTerminalCodesAreNeverRecoverable states the money consequence of
// disjointness directly: nothing the issuer called final may also carry a
// licence to spend another gateway fee on it.
func TestTerminalCodesAreNeverRecoverable(t *testing.T) {
	for code := range TerminalDeclineCodes {
		if v := classify(code); v.recoveryLicensed() {
			t.Errorf("terminal code %q also licenses recovery (%s)", code, v)
		}
	}
}

// ---------------------------------------------------------------------------
// Folding: the variations the contract must absorb
// ---------------------------------------------------------------------------

// safeFolds are the input variations normaliseCode is contractually required to
// absorb. They exist because a gateway that emits "CARD_EXPIRED" or a trailing
// newline must not thereby buy an expired instrument three more retries — the
// exact bug the fold was added to close.
func safeFolds(code string) map[string]string {
	return map[string]string{
		"upper case":           strings.ToUpper(code),
		"title case":           strings.ToUpper(code[:1]) + code[1:],
		"leading space":        " " + code,
		"trailing space":       code + " ",
		"surrounding tabs":     "\t" + code + "\t",
		"surrounding newlines": "\n" + code + "\n",
		"surrounding CRLF":     "\r\n" + code + "\r\n",
		// TrimSpace folds on unicode.IsSpace, which includes U+00A0. A
		// non-breaking space is what a copy-paste out of a console produces, so
		// it is a realistic way for an operator-supplied code to arrive padded.
		"non-breaking space":  "\u00a0" + code + "\u00a0",
		"upper and padded":    "  " + strings.ToUpper(code) + "\n",
		"vertical whitespace": "\v" + code + "\f",
	}
}

func TestFoldingPreservesEveryCanonicalClassification(t *testing.T) {
	for code, set := range canonicalCodes() {
		base := classify(code)
		for name, folded := range safeFolds(code) {
			got := classify(folded)
			if got != base {
				t.Errorf("%s code %q under %s (%q): classified %s, want %s",
					set, code, name, folded, got, base)
			}
		}
	}
}

// TestEmptyAndBlankCodesAreInNoSet pins the degenerate input. An empty code is
// what a payload with no error_code produces, and it must not resolve to any
// set: not terminal (which would halt a recoverable payment) and not
// recoverable (which would licence a retry against no evidence at all).
func TestEmptyAndBlankCodesAreInNoSet(t *testing.T) {
	for _, code := range []string{"", " ", "\t\n", "\u00a0", "\x00"} {
		if v := classify(code); v != (verdict{}) {
			t.Errorf("blank code %q classified %s, want no membership", code, v)
		}
	}
}

// TestOversizedCodeIsInNoSet covers the unbounded-input case. A 300-character
// code is not a Razorpay code; it is either a bug or an attempt to push a
// recognised token past a length check somewhere downstream, and either way it
// must land outside every set.
func TestOversizedCodeIsInNoSet(t *testing.T) {
	long := strings.Repeat("a", 300)
	if v := classify(long); v != (verdict{}) {
		t.Errorf("300-character code classified %s, want no membership", v)
	}
	// A recognised code with 300 characters of padding is the more interesting
	// shape: a prefix match would accept it.
	padded := "bank_technical_error" + strings.Repeat("x", 300)
	if v := classify(padded); v != (verdict{}) {
		t.Errorf("padded code classified %s; the lookup must be exact, not a prefix match", v)
	}
	if v := classify(strings.Repeat("x", 300) + "bank_technical_error"); v != (verdict{}) {
		t.Errorf("suffixed code classified %s; the lookup must be exact, not a suffix match", v)
	}
}

// ---------------------------------------------------------------------------
// The one-way property: normalisation may only move towards abstaining
// ---------------------------------------------------------------------------

// hostileVariants are strings a correct producer never emits. Each is built
// from a canonical code so that a comparison against that code's verdict is
// meaningful.
//
// The contract stated at normaliseCode and restated at gatekeeper.go's terminal
// rule is that folding "can only ever move a decision towards abstaining".
// These are the inputs that test it rather than assume it.
func hostileVariants(code string) map[string]string {
	mid := len(code) / 2
	return map[string]string{
		"embedded NUL":       code[:mid] + "\x00" + code[mid:],
		"trailing NUL":       code + "\x00",
		"embedded newline":   code[:mid] + "\n" + code[mid:],
		"embedded space":     code[:mid] + " " + code[mid:],
		"embedded CR":        code[:mid] + "\r" + code[mid:],
		"cyrillic lookalike": strings.Replace(code, "a", "\u0430", 1),
		"greek lookalike":    strings.Replace(code, "o", "\u03bf", 1),
		"fullwidth":          strings.Replace(code, "e", "\uff45", 1),
		"zero width joiner":  code[:mid] + "\u200d" + code[mid:],
		"300 chars appended": code + strings.Repeat("z", 300),
	}
}

// TestHostileVariantsNeverGainARecoveryLicence is the half of the one-way
// property that protects the money. A string that is not a code the gateway
// issued must not acquire membership in the refreshable, ambiguous or soft
// sets, because each of those is a budget: a gateway fee, an inference call, or
// both.
func TestHostileVariantsNeverGainARecoveryLicence(t *testing.T) {
	for code := range canonicalCodes() {
		base := classify(code)
		for name, hostile := range hostileVariants(code) {
			if hostile == code {
				continue // the substitution found nothing to replace
			}
			got := classify(hostile)
			if got.recoveryLicensed() && !base.recoveryLicensed() {
				t.Errorf("%s of %q (%q) acquired a recovery licence: %s", name, code, hostile, got)
			}
			if got.refreshable && !base.refreshable {
				t.Errorf("%s of %q became refreshable", name, code)
			}
			if got.ambiguous && !base.ambiguous {
				t.Errorf("%s of %q became ambiguous, which admits it to the causal model", name, code)
			}
			if got.soft && !base.soft {
				t.Errorf("%s of %q became a soft decline", name, code)
			}
		}
	}
}

// TestUnicodeCaseFoldingCannotSmuggleAStringIntoAClosedSet is the case the
// generic sweep above cannot express, because the smuggled string is not a
// perturbation of any single code — it is a string outside every set that
// Unicode case mapping folds into one.
//
// Go's strings.ToLower and strings.ToUpper apply full Unicode case mapping,
// which maps characters outside ASCII *into* ASCII:
//
//	U+017F LATIN SMALL LETTER LONG S  uppercases to 'S'
//	U+212A KELVIN SIGN                lowercases to 'k'
//
// Every identifier in this package's closed sets is ASCII, so a Unicode fold
// can only ever admit a non-member. Admitting one is a fail-open in the
// direction that costs money: "banK_technical_error" written with a Kelvin sign
// is not a code Razorpay issues, and admitting it to AmbiguousFailureCodes is
// precisely the licence to call the model and act on what it says.
func TestUnicodeCaseFoldingCannotSmuggleAStringIntoAClosedSet(t *testing.T) {
	const (
		longS  = "\u017f" // LATIN SMALL LETTER LONG S: uppercases to ASCII 'S'
		kelvin = "\u212a" // KELVIN SIGN: lowercases to ASCII 'k'
	)
	cases := []struct {
		name string
		in   string
	}{
		{"kelvin sign in an ambiguous code", "ban" + kelvin + "_technical_error"},
		{"kelvin sign in a soft-adjacent code", "ban" + kelvin + "_technical_error "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v := classify(tc.in); v.recoveryLicensed() {
				t.Fatalf("%q classified %s; a string built from a non-ASCII lookalike must not "+
					"enter a closed set, because case folding may only ever add a terminal halt", tc.in, v)
			}
		})
	}
	// The reverse direction is safe and is asserted so the fix above is not
	// mistaken for "reject anything unusual": a Unicode fold that would have
	// *added* a terminal halt is a loss of safety only if it is relied upon, and
	// nothing relies on it. What matters is that the string is not recoverable.
	if v := classify("ban" + kelvin + "_account_invalid"); v.recoveryLicensed() {
		t.Fatalf("kelvin-sign variant of a terminal code acquired a recovery licence: %s", v)
	}
	if a := ParseAction("A" + longS + "YNC_EXPONENTIAL_RETRY"); a != ActionAbstain {
		t.Fatalf("ParseAction(long-s) = %q, want %q: the action set is closed and an "+
			"unrecognised action from any source must degrade to an abstention", a, ActionAbstain)
	}
}

// TestEmbeddedControlCharacterDropsTheTerminalHalt documents the other half of
// the one-way property and where it stops.
//
// normaliseCode trims surrounding whitespace and folds case; it does not strip
// interior control characters, so "card_lost_or_stolen\x00" is in no set at all
// and the terminal halt is lost. That is recorded rather than asserted away
// because the halt is not the only thing standing between such a code and a
// debit: an unrecognised code produces ClassUnknown from every inference tier,
// ClassUnknown is not Recoverable, and the gatekeeper's UNRECOVERABLE_CLASS rule
// vetoes it. The system still fails closed, by a different rule. If that rule
// ever changes, this test is where the argument is written down.
func TestEmbeddedControlCharacterDropsTheTerminalHalt(t *testing.T) {
	const code = "card_lost_or_stolen"
	if !IsTerminalDecline(code) {
		t.Fatalf("precondition: %q must be terminal", code)
	}
	withNUL := code + "\x00"
	if IsTerminalDecline(withNUL) {
		t.Skip("normaliseCode now strips interior control characters; the compensating " +
			"argument below is no longer load-bearing")
	}
	// The compensating control: no recovery licence either, so the class the
	// inference tiers derive is UNKNOWN, and UNKNOWN is not recoverable.
	if v := classify(withNUL); v.recoveryLicensed() {
		t.Fatalf("control-character variant %q acquired a recovery licence: %s", withNUL, v)
	}
	if ClassUnknown.Recoverable() {
		t.Fatal("ClassUnknown is recoverable; the compensating control for an unrecognised " +
			"code no longer holds and normaliseCode must strip control characters")
	}
}

// ---------------------------------------------------------------------------
// Parsers over closed sets
// ---------------------------------------------------------------------------

func TestParseActionFoldsAndDefaultsToAbstain(t *testing.T) {
	for a := range allActions {
		for name, folded := range safeFolds(string(a)) {
			if got := ParseAction(folded); got != a {
				t.Errorf("ParseAction(%s of %q) = %q, want %q", name, a, got, a)
			}
		}
	}
	unknown := []string{
		"", " ", "\x00", "DROP TABLE incidents",
		"ASYNC_EXPONENTIAL_RETRY_NOW", "ASYNC_EXPONENTIAL_RETR",
		"ASYNC EXPONENTIAL RETRY", "ASYNC\x00_EXPONENTIAL_RETRY",
		strings.Repeat("A", 300),
		// The action name as JSON, which is what a model that ignores the
		// schema and echoes the prompt back tends to emit.
		`"ASYNC_EXPONENTIAL_RETRY"`,
	}
	for _, s := range unknown {
		if got := ParseAction(s); got != ActionAbstain {
			t.Errorf("ParseAction(%q) = %q, want %q: the system fails closed, never open", s, got, ActionAbstain)
		}
	}
}

func TestParseRailFoldsAndDefaultsToNone(t *testing.T) {
	for r := range allRails {
		for name, folded := range safeFolds(string(r)) {
			if got := ParseRail(folded); got != r {
				t.Errorf("ParseRail(%s of %q) = %q, want %q", name, r, got, r)
			}
		}
	}
	for _, s := range []string{"", " ", "upi", "card_v2", "netban\u212aing", "\x00card", strings.Repeat("c", 300)} {
		if got := ParseRail(s); got != RailNone {
			t.Errorf("ParseRail(%q) = %q, want %q: the model may not invent a rail identifier", s, got, RailNone)
		}
	}
}

func TestParseFailureClassFoldsAndDefaultsToUnknown(t *testing.T) {
	for c := range allClasses {
		for name, folded := range safeFolds(string(c)) {
			if got := ParseFailureClass(folded); got != c {
				t.Errorf("ParseFailureClass(%s of %q) = %q, want %q", name, c, got, c)
			}
		}
	}
	for _, s := range []string{"", " ", "TOTALLY_FINE", "I\u017fSUER_OUTAGE", "ISSUER_OUTAGE_2", "\x00ISSUER_OUTAGE"} {
		got := ParseFailureClass(s)
		if got != ClassUnknown {
			t.Errorf("ParseFailureClass(%q) = %q, want %q", s, got, ClassUnknown)
		}
		// The consequence, stated where it can be seen: an unrecognised
		// classification must not buy a retry. This is the fail-open the
		// enumerate-the-recoverable-classes rewrite of Recoverable closed, and
		// a smuggled class would reopen it.
		if got.Recoverable() {
			t.Errorf("ParseFailureClass(%q) produced a recoverable class", s)
		}
	}
}

// TestRailFromMethodCoversEveryRazorpayMethod pins the method-to-rail mapping
// and its default. An unrecognised method mapping to anything but RailNone
// would let an unfamiliar instrument be routed as if it were a known one.
func TestRailFromMethodCoversEveryRazorpayMethod(t *testing.T) {
	cases := map[string]Rail{
		"upi": RailUPIIntent, "UPI": RailUPIIntent,
		"card": RailCard, "Card": RailCard,
		"emi":        RailCard, // EMI settles over the card rails
		"netbanking": RailNetbanking,
		"wallet":     RailWallet,
		"":           RailNone,
		"paylater":   RailNone,
		"cardx":      RailNone,
		"  card  ":   RailNone, // RailFromMethod does not trim; the caller passes a verified field
	}
	for method, want := range cases {
		if got := RailFromMethod(method); got != want {
			t.Errorf("RailFromMethod(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestValidReportsMembershipOfEachClosedSet(t *testing.T) {
	if Action("").Valid() || Action("ASYNC_EXPONENTIAL_RETR").Valid() {
		t.Error("Action.Valid accepted a non-member")
	}
	if Rail("").Valid() || Rail("upi").Valid() {
		t.Error("Rail.Valid accepted a non-member")
	}
	if FailureClass("").Valid() || FailureClass("UNKNOWNN").Valid() {
		t.Error("FailureClass.Valid accepted a non-member")
	}
	if InstrumentPresentation("").Valid() || InstrumentPresentation("token").Valid() {
		t.Error("InstrumentPresentation.Valid accepted a non-member")
	}
	for a := range allActions {
		if !a.Valid() {
			t.Errorf("declared action %q reports itself invalid", a)
		}
	}
	for r := range allRails {
		if !r.Valid() {
			t.Errorf("declared rail %q reports itself invalid", r)
		}
	}
	for c := range allClasses {
		if !c.Valid() {
			t.Errorf("declared class %q reports itself invalid", c)
		}
	}
	for p := range allPresentations {
		if !p.Valid() {
			t.Errorf("declared presentation %q reports itself invalid", p)
		}
	}
}

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// Bounds on the document that becomes a permanent ledger row. Audit details are
// assembled from webhook text, issuer error strings, and model output, none of
// which is trustworthy about its own size or shape, and a ledger row is written
// once and then kept forever.
const (
	// maxDetailBytes leaves generous headroom under the store's 64 KiB column
	// bound. The margin is deliberate: the check here is on Go's encoding, and
	// what the store validates is the same document after PostgreSQL has
	// re-rendered it as jsonb.
	maxDetailBytes = 32 << 10

	// maxKeyBytes bounds an object key. Keys are identifiers, so they are cut
	// rather than annotated: a truncation marker inside a key is itself noise
	// that later readers have to parse around.
	maxKeyBytes = 128

	// maxContainerEntries caps the fan-out of any single object or array. Depth
	// alone is not a sufficient bound — a flat array of a million elements is
	// shallow — and the cap keeps the redacted document within a size the
	// elision fallback rarely has to rescue.
	maxContainerEntries = 256

	// maxDepth stops recursion on adversarial nesting. encoding/json decodes to
	// a bounded depth of its own, so this is the second line rather than the
	// first, and it is set well above anything the mesh's own detail structs
	// reach.
	maxDepth = 24

	elidedEntriesKey = "audit_elided_entries"
	deepPlaceholder  = "[TOO_DEEP]"
)

// RedactDetail renders detail as a JSON document that is safe to hash, store,
// and display forever: no value under a credential- or PII-shaped key survives,
// every string is bounded, and every container is bounded.
//
// The pass runs over decoded JSON rather than over the Go value by reflection,
// because the denylist is keyed on wire names. A struct field called Secret with
// tag `json:"s"` is stored as "s", and only the decoded form tells us that.
//
// It cannot fail. An audit ledger whose Append refuses to record because a
// caller handed it an unencodable value has a hole in it exactly where the
// interesting failures are, so encoding problems are described *in* the returned
// document instead of returned as an error — strictly more visible than an error
// value, since the result is what gets kept.
func RedactDetail(detail any) []byte {
	raw, err := json.Marshal(detail)
	if err != nil {
		// Only the Go type is reported. A json.MarshalerError carries whatever
		// a custom MarshalJSON put in it, which is precisely the unvetted text
		// this function exists to keep out of the ledger.
		return unencodableDoc(detail)
	}

	// UseNumber keeps integers as their exact source text. Decoding into the
	// default any would route every number through float64, which silently
	// rounds paisa amounts above 2^53 — corrupting money values in the one
	// record that is supposed to be evidence.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return unencodableDoc(detail)
	}

	out, err := json.Marshal(redactValue(decoded, 0))
	if err != nil {
		return unencodableDoc(detail)
	}
	if len(out) > maxDetailBytes {
		return oversizeDoc(len(out))
	}
	// A nil or JSON-null detail becomes an empty object so that every row in the
	// table has the same document shape and console readers need no null case.
	if len(out) == 0 || bytes.Equal(out, []byte("null")) {
		return []byte("{}")
	}
	return out
}

func redactValue(v any, depth int) any {
	if depth > maxDepth {
		return deepPlaceholder
	}
	switch t := v.(type) {
	case map[string]any:
		return redactMap(t, depth)
	case []any:
		return redactSlice(t, depth)
	case string:
		return obs.TruncateForLog(sanitizeText(t))
	default:
		// json.Number, bool, and nil carry no free text, and any credential
		// hiding in one of them was already replaced by the key check in
		// redactMap before the value was reached.
		return v
	}
}

// redactMap replaces the whole value under a sensitive key rather than
// descending into it. Sealing the subtree matches how the logger treats a
// sensitive group: "card" names cardholder context regardless of what the leaves
// beneath it happen to be called.
func redactMap(m map[string]any, depth int) map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sorted so that which entries survive the cap is a property of the input,
	// not of Go's randomised map iteration. A hash chain over a
	// non-deterministic rendering would be unverifiable by anyone re-deriving it.
	sort.Strings(keys)

	out := make(map[string]any, len(keys))
	for i, k := range keys {
		if i == maxContainerEntries {
			out[elidedEntriesKey] = json.Number(strconv.Itoa(len(keys) - i))
			break
		}
		// Sensitivity is judged on the key as it arrived: truncating first could
		// cut "..._secret" down to something the denylist no longer matches.
		if obs.IsSensitiveKey(k) {
			out[safeKey(k)] = obs.RedactedPlaceholder
			continue
		}
		out[safeKey(k)] = redactValue(m[k], depth+1)
	}
	return out
}

func redactSlice(s []any, depth int) []any {
	n := len(s)
	if n > maxContainerEntries {
		n = maxContainerEntries
	}
	out := make([]any, 0, n+1)
	for _, e := range s[:n] {
		out = append(out, redactValue(e, depth+1))
	}
	if len(s) > n {
		out = append(out, fmt.Sprintf("[ELIDED %d more]", len(s)-n))
	}
	return out
}

func safeKey(k string) string {
	k = sanitizeText(k)
	if len(k) <= maxKeyBytes {
		return k
	}
	cut := maxKeyBytes
	for cut > 0 && !utf8.RuneStart(k[cut]) {
		cut--
	}
	return k[:cut]
}

// sanitizeText makes a string storable and renderable. Control characters are
// folded to spaces for two independent reasons: PostgreSQL cannot represent
// U+0000 in a jsonb string at all, so one stray NUL would reject the whole
// append and lose the record; and the ops console and log shippers downstream
// treat embedded newlines and escape sequences as structure, which is a
// forgery vector in a document an attacker partially controls.
func sanitizeText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	if strings.IndexFunc(s, unicode.IsControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

type unencodableDetail struct {
	Unencodable bool   `json:"audit_detail_unencodable"`
	GoType      string `json:"go_type"`
}

func unencodableDoc(detail any) []byte {
	b, err := json.Marshal(unencodableDetail{
		Unencodable: true,
		GoType:      safeKey(fmt.Sprintf("%T", detail)),
	})
	if err != nil {
		return []byte(`{"audit_detail_unencodable":true}`)
	}
	return b
}

type oversizeDetail struct {
	Oversize bool `json:"audit_detail_oversize"`
	Bytes    int  `json:"redacted_bytes"`
}

// oversizeDoc replaces a document too large to keep. Dropping the entry instead
// would let a caller silence its own audit record by making the detail big,
// which is a cheaper attack than tampering with the chain afterwards.
func oversizeDoc(n int) []byte {
	b, err := json.Marshal(oversizeDetail{Oversize: true, Bytes: n})
	if err != nil {
		return []byte(`{"audit_detail_oversize":true}`)
	}
	return b
}

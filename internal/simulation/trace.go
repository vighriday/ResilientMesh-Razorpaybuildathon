package simulation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// traceVersion is absorbed as the first line of every trace so that a change to
// the rendering can never make a new run's hash collide with an old run's hash.
// A stored "expected hash" that silently keeps matching after the format
// changed would be worse than no assertion at all.
const traceVersion = "rmesh-sim-trace-v1"

const (
	// maxFieldBytes bounds one rendered field value. Trace fields carry issuer
	// keys, error codes and audit reasons, all of which originate in payload
	// text, so the trace inherits the same unbounded-string hazard as a log
	// line and gets the same ceiling.
	maxFieldBytes = 160

	// maxCaptureBytes bounds the retained trace text. The rolling hash is
	// always computed over every event, so truncating the capture weakens what
	// --trace prints, never what --assert-determinism compares.
	maxCaptureBytes = 32 << 20
)

// Field is one key/value pair on a trace event. Values are strings so that the
// rendering has exactly one code path and cannot vary with a numeric formatting
// change.
type Field struct {
	K string
	V string
}

// F builds a string field.
func F(k, v string) Field { return Field{K: k, V: v} }

// Fi builds an integer field.
func Fi(k string, v int64) Field { return Field{K: k, V: strconv.FormatInt(v, 10)} }

// Fb builds a boolean field.
func Fb(k string, v bool) Field { return Field{K: k, V: strconv.FormatBool(v)} }

// Trace is the canonical, deterministic event log of one run and the hash that
// identifies it.
//
// Equality of two runs is asserted on the hash rather than on the text so the
// assertion costs 32 bytes instead of megabytes, and the text is retained only
// when someone asked to see it. The hash is rolled incrementally, so a run that
// prints nothing still produces a comparable identity.
type Trace struct {
	h         hash.Hash
	buf       bytes.Buffer
	capture   bool
	truncated bool
	count     int
}

// NewTrace builds a trace. capture retains the rendered text for --trace and
// for the byte-identical comparison the determinism test performs; the hash is
// computed either way.
func NewTrace(capture bool) *Trace {
	t := &Trace{h: sha256.New(), capture: capture}
	t.write(traceVersion + "\n")
	return t
}

// Emit appends one event. Fields are sorted by key before rendering: callers
// pass fixed literal slices today, but sorting removes the whole class of bug
// where a future caller builds fields from a map and makes the trace — and
// therefore the determinism assertion — depend on Go's randomised map order.
func (t *Trace) Emit(step int, vt time.Time, kind, key string, fields ...Field) {
	sorted := make([]Field, len(fields))
	copy(sorted, fields)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].K < sorted[j].K })

	var b strings.Builder
	// Virtual time is rendered as whole milliseconds since Origin. An absolute
	// formatted timestamp would be identical too, but an integer offset cannot
	// acquire a locale, a monotonic-clock suffix, or a timezone database
	// dependency between two runs.
	fmt.Fprintf(&b, "%06d %012d %s %s",
		step, vt.Sub(Origin).Milliseconds(), sanitizeTraceValue(kind), sanitizeTraceValue(key))
	for _, f := range sorted {
		b.WriteString(" ")
		b.WriteString(sanitizeTraceValue(f.K))
		b.WriteString("=")
		b.WriteString(sanitizeTraceValue(f.V))
	}
	b.WriteString("\n")

	t.count++
	t.write(b.String())
}

func (t *Trace) write(s string) {
	// The hash always sees every byte. Capture may stop; identity may not.
	_, _ = io.WriteString(t.h, s)
	if !t.capture {
		return
	}
	if t.buf.Len()+len(s) > maxCaptureBytes {
		if !t.truncated {
			t.buf.WriteString("[trace capture truncated]\n")
			t.truncated = true
		}
		return
	}
	t.buf.WriteString(s)
}

// Hash is the trace identity: two runs are the same run if and only if these
// match.
func (t *Trace) Hash() string { return hex.EncodeToString(t.h.Sum(nil)) }

// Count is the number of emitted events.
func (t *Trace) Count() int { return t.count }

// Bytes returns the captured text, empty when capture was disabled.
func (t *Trace) Bytes() []byte { return t.buf.Bytes() }

// WriteTo streams the captured text.
func (t *Trace) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(t.buf.Bytes())
	if err != nil {
		return int64(n), fmt.Errorf("simulation: writing trace: %w", err)
	}
	return int64(n), nil
}

// FirstDifference reports the line number and both lines where two captured
// traces diverge. A determinism failure that only says "hashes differ" tells an
// engineer nothing; this points at the exact event, which is almost always
// enough to name the offending map iteration.
func FirstDifference(a, b []byte) (line int, left, right string, differs bool) {
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		if al[i] != bl[i] {
			return i + 1, al[i], bl[i], true
		}
	}
	if len(al) != len(bl) {
		return n + 1, lineAt(al, n), lineAt(bl, n), true
	}
	return 0, "", "", false
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(end of trace)"
}

// sanitizeTraceValue makes a value safe to place in a whitespace-delimited,
// newline-terminated record. Separator characters are replaced rather than
// escaped so that no value can forge a field boundary or a new event line, and
// the result is length-capped for the same reason a log value is.
func sanitizeTraceValue(s string) string {
	if s == "" {
		return "-"
	}
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ', r == '\n', r == '\r', r == '\t', r == '=':
			b.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > maxFieldBytes {
		cut := maxFieldBytes
		for cut > 0 && out[cut]&0xC0 == 0x80 {
			cut--
		}
		out = out[:cut] + "~"
	}
	if out == "" {
		return "-"
	}
	return out
}

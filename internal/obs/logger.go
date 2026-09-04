// Package obs provides the observability primitives the rest of ResilientMesh
// depends on: a redacting JSON logger, an in-process metric registry, and the
// context plumbing that ties a log line back to a request and an incident.
//
// The package imports only the standard library, deliberately. Observability is
// the one dependency every other package takes, so keeping it dependency-free
// means adding a log line can never drag a third-party module into a package's
// build graph, and can never create an import cycle with the code it observes.
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	// RedactedPlaceholder is what a sensitive value becomes. The key survives
	// redaction on purpose: an operator needs to see that a credential was
	// present in order to debug a flow, and the name alone leaks nothing.
	RedactedPlaceholder = "[REDACTED]"

	// MaxValueBytes bounds a single rendered string. Log values reach this
	// process from webhook bodies, model responses, and issuer error text, all
	// of which are attacker-influenced and unbounded; an unbounded log line is a
	// disk-exhaustion and log-pipeline DoS vector, not merely untidy.
	MaxValueBytes = 512

	truncationSuffix = "...(truncated)"

	// unprintablePlaceholder is used when a value's own String or Error method
	// panics. A logger that panics turns an observability problem into an
	// outage.
	unprintablePlaceholder = "[UNPRINTABLE]"

	// deepPlaceholder stops attribute recursion. A cyclic slog.LogValuer can
	// resolve to a group containing itself, which would otherwise exhaust the
	// stack inside the logging path.
	deepPlaceholder = "[TOO_DEEP]"
	maxAttrDepth    = 8
)

// sensitiveKeyTerms are matched as substrings, case-insensitively, against
// attribute keys. Substring matching is deliberately over-broad: the cost of
// redacting one extra debug field is a minor inconvenience, the cost of missing
// "customer_email" because the denylist only held "email" is a PII incident.
// "authorization" is subsumed by "auth" and kept only because auditors read
// this list and expect to find it.
var sensitiveKeyTerms = []string{
	"secret", "token", "key", "password", "passwd", "signature",
	"authorization", "auth", "vpa", "card", "contact", "email", "phone", "dsn",
}

// sensitiveKeyExceptions are the exact key names the substring rule would
// otherwise destroy. An issuer key is routing metadata such as "netbanking:HDFC"
// with no cardholder data in it, and it is the single most useful dimension in
// an outage investigation. Matching here is exact, never substring, so
// "api_key" cannot slip through by resembling an exception.
var sensitiveKeyExceptions = map[string]struct{}{
	"issuer_key":    {},
	"telemetry_key": {},
	"cycle_key":     {},
}

// IsSensitiveKey reports whether the value carried under key may never be
// rendered. It is exported so that anything else which serialises
// caller-supplied maps — notably the audit ledger detail payload, which is
// hashed and then kept forever — applies exactly the same denylist as the
// logger instead of growing a second copy that drifts from this one.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if _, ok := sensitiveKeyExceptions[k]; ok {
		return false
	}
	for _, term := range sensitiveKeyTerms {
		if strings.Contains(k, term) {
			return true
		}
	}
	return false
}

// TruncateForLog bounds a rendered value at MaxValueBytes, cutting on a rune
// boundary so the result is still valid UTF-8. A cut through a multi-byte rune
// emits bytes that JSON encoders rewrite to U+FFFD and that some log shippers
// reject outright, dropping the whole line rather than one field.
func TruncateForLog(s string) string {
	if len(s) <= MaxValueBytes {
		return s
	}
	cut := MaxValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncationSuffix
}

// ParseLevel maps a configured level name onto a slog level, defaulting to Info
// for anything unrecognised. A typo in MESH_LOG_LEVEL must not silently disable
// logging, so the fallback is the level an operator expects rather than Error.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err", "fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewLogger builds the process logger: JSON to w, filtered at level, with every
// attribute forced through the redacting handler. Construction cannot fail and
// never returns nil, because a caller that has no logger has no way to report
// that it has no logger.
func NewLogger(level string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(NewRedactingHandler(h))
}

// NewRedactingHandler wraps inner so no credential or PII-shaped value can
// reach it, whether the attribute arrives on the record, through WithAttrs, or
// nested inside a group.
//
// Wrapping rather than setting HandlerOptions.ReplaceAttr is what makes this
// enforceable: ReplaceAttr is a struct field a future caller can forget to set,
// while a wrapper owns the only path to the writer.
func NewRedactingHandler(inner slog.Handler) slog.Handler {
	if inner == nil {
		// A nil inner handler is a wiring bug. Discarding is the only response
		// that neither panics on every log call nor invents a destination for
		// records that may contain secrets.
		inner = slog.NewJSONHandler(io.Discard, nil)
	}
	return &redactingHandler{inner: inner}
}

// redactingHandler is immutable after construction, so one instance is safe to
// share across goroutines; WithAttrs and WithGroup return new values instead of
// mutating the receiver.
type redactingHandler struct {
	inner slog.Handler

	// sealed records that an enclosing group is itself sensitive: WithGroup
	// ("card") means everything underneath is cardholder context however the
	// leaf attributes are named. It only ever transitions false to true, so
	// nesting can widen redaction but never narrow it.
	sealed bool
}

func (h *redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, TruncateForLog(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(scrub(a, h.sealed, 0))
		return true
	})
	if err := h.inner.Handle(ctx, out); err != nil {
		return fmt.Errorf("obs: emit log record: %w", err)
	}
	return nil
}

// WithAttrs scrubs before delegating. Pre-bound attributes are the easy leak:
// they are attached once at startup and then copied onto every subsequent line,
// so a credential bound here is printed thousands of times rather than once.
func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	clean := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		clean = append(clean, scrub(a, h.sealed, 0))
	}
	return &redactingHandler{inner: h.inner.WithAttrs(clean), sealed: h.sealed}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &redactingHandler{
		inner:  h.inner.WithGroup(name),
		sealed: h.sealed || IsSensitiveKey(name),
	}
}

// scrub returns a safe copy of a. The value is resolved first: an unresolved
// slog.LogValuer would be inspected as an opaque Any here and then hand its
// secret to the inner handler at format time, after redaction has already run.
func scrub(a slog.Attr, sealed bool, depth int) slog.Attr {
	if depth > maxAttrDepth {
		return slog.String(a.Key, deepPlaceholder)
	}
	v := a.Value.Resolve()
	sensitive := sealed || IsSensitiveKey(a.Key)

	switch v.Kind() {
	case slog.KindGroup:
		members := v.Group()
		clean := make([]slog.Attr, 0, len(members))
		for _, m := range members {
			clean = append(clean, scrub(m, sensitive, depth+1))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(clean...)}

	case slog.KindString:
		if sensitive {
			return slog.String(a.Key, RedactedPlaceholder)
		}
		return slog.String(a.Key, TruncateForLog(v.String()))

	case slog.KindAny:
		return scrubAny(a.Key, v, sensitive)

	default:
		if sensitive {
			return slog.String(a.Key, RedactedPlaceholder)
		}
		return slog.Attr{Key: a.Key, Value: v}
	}
}

// scrubAny handles the values slog would otherwise hand to encoding/json
// verbatim. Rendering them as bounded text is the point: a raw []byte in this
// system is a webhook body, an HMAC, or a key, and json.Marshal would happily
// base64 the whole thing into the log.
func scrubAny(key string, v slog.Value, sensitive bool) slog.Attr {
	if sensitive {
		return slog.String(key, RedactedPlaceholder)
	}
	switch t := v.Any().(type) {
	case nil:
		return slog.Attr{Key: key, Value: v}
	case []byte:
		return slog.String(key, fmt.Sprintf("[%d bytes]", len(t)))
	case error:
		return slog.String(key, TruncateForLog(safeText(t.Error)))
	case fmt.Stringer:
		return slog.String(key, TruncateForLog(safeText(t.String)))
	default:
		return slog.Attr{Key: key, Value: v}
	}
}

func safeText(f func() string) (s string) {
	defer func() {
		if r := recover(); r != nil {
			s = unprintablePlaceholder
		}
	}()
	return f()
}

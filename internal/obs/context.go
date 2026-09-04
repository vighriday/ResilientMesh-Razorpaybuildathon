package obs

import (
	"context"
	"log/slog"
	"strings"
)

// ctxKey is an unexported type so no other package can collide with these keys
// or, worse, overwrite a request id that the audit trail is keyed on.
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota + 1
	ctxKeyIncidentID
)

// MaxIDLen bounds a correlation id. Request ids arrive in an inbound header,
// so they are attacker-controlled text that ends up on every log line for the
// life of the request; 64 bytes fits a UUID or a ULID with room to spare.
const MaxIDLen = 64

// sanitizeID keeps only the characters correlation ids legitimately use and
// drops the rest. Even though the JSON handler escapes control characters, an
// id also reaches operator consoles and grep pipelines, where an embedded
// newline is a log-forging primitive.
func sanitizeID(s string) string {
	if len(s) > MaxIDLen {
		s = s[:MaxIDLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// WithRequestID attaches the correlation id for one inbound HTTP request. An id
// that sanitizes to nothing is not stored at all, so a caller reading it back
// gets an honest empty string rather than a mangled remnant of hostile input.
func WithRequestID(ctx context.Context, id string) context.Context {
	clean := sanitizeID(id)
	if clean == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestID, clean)
}

// RequestID returns the correlation id, or "" when the context never carried
// one — an unset id is a normal state on background workers, not an error.
func RequestID(ctx context.Context) string { return idFrom(ctx, ctxKeyRequestID) }

// WithIncidentID attaches the incident under repair, which is the join key
// between a log line, an audit entry, and a row in the incidents table.
func WithIncidentID(ctx context.Context, id string) context.Context {
	clean := sanitizeID(id)
	if clean == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyIncidentID, clean)
}

// IncidentID returns the incident id, or "" when the context never carried one.
func IncidentID(ctx context.Context) string { return idFrom(ctx, ctxKeyIncidentID) }

func idFrom(ctx context.Context, key ctxKey) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(key).(string)
	return id
}

// LoggerFrom pre-tags base with whichever correlation ids the context carries,
// so call sites log once and correlation is never forgotten at the one call
// site that mattered. When the context carries neither id, base is returned
// unchanged rather than needlessly cloned.
func LoggerFrom(ctx context.Context, base *slog.Logger) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	attrs := make([]any, 0, 2)
	if id := RequestID(ctx); id != "" {
		attrs = append(attrs, slog.String("request_id", id))
	}
	if id := IncidentID(ctx); id != "" {
		attrs = append(attrs, slog.String("incident_id", id))
	}
	if len(attrs) == 0 {
		return base
	}
	return base.With(attrs...)
}

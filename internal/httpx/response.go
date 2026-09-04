package httpx

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Error codes. The set is closed on purpose: every rejection this system emits
// is one of these, so no handler can invent a code that describes internal
// state to a caller. A payment edge is probed constantly, and the difference
// between "malformed signature" and "unknown event id" is exactly the oracle a
// prober is looking for.
const (
	CodeBadRequest       = "bad_request"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeNotFound         = "not_found"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeConflict         = "conflict"
	CodePayloadTooLarge  = "payload_too_large"
	CodeUnsupportedMedia = "unsupported_media_type"
	CodeRateLimited      = "rate_limited"
	CodeInternal         = "internal_error"
	CodeUnavailable      = "service_unavailable"
	CodeTimeout          = "timeout"
)

// messages maps a code to the single sentence a client is allowed to see.
// The message is looked up rather than passed in, which is what makes the
// guarantee structural: a caller cannot leak a driver error, a stack frame, or
// a payload fragment through this path even by accident.
var messages = map[string]string{
	CodeBadRequest:       "request could not be processed",
	CodeUnauthorized:     "authentication required",
	CodeForbidden:        "not permitted",
	CodeNotFound:         "not found",
	CodeMethodNotAllowed: "method not allowed",
	CodeConflict:         "conflicting state",
	CodePayloadTooLarge:  "request body too large",
	CodeUnsupportedMedia: "unsupported media type",
	CodeRateLimited:      "too many requests",
	CodeInternal:         "internal error",
	CodeUnavailable:      "service unavailable",
	CodeTimeout:          "request timed out",
}

const (
	genericMessage  = "request rejected"
	maxCodeLen      = 40
	jsonContentType = "application/json; charset=utf-8"
)

// errorBody is the only error shape this service emits. Keeping it flat and
// identical for every failure means the console and the CLI parse one thing,
// and a caller cannot fingerprint the failing subsystem by the shape of the
// response.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON writes v as the response body.
//
// It returns no error deliberately. The only failure reachable here is a
// transport write to a client that has already disconnected, which no caller
// can act on and which net/http already accounts for; offering an error would
// produce a chorus of ignored returns at every call site, and an ignored
// return is worse than an honest absence of one. A value that cannot be
// marshalled is a programming error, and it degrades to the fixed internal
// error body rather than to a truncated half-response.
func JSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, mustMarshal(errorBody{
			Code:    CodeInternal,
			Message: messages[CodeInternal],
		}))
		return
	}
	writeJSON(w, status, body)
}

// Error writes the fixed body for code. Nothing about the cause reaches the
// client: the reason a request failed lives in the logs and the audit ledger,
// where it is correlated by request id, and nowhere else.
func Error(w http.ResponseWriter, status int, code string) {
	code = sanitizeCode(code, status)
	msg, known := messages[code]
	if !known {
		// A code outside the closed set is discarded rather than echoed in
		// sanitised form. Passing an internal error string here is the mistake
		// this guards: "pgx: duplicate key" would otherwise arrive at the
		// client as "pgxduplicatekey", which still names the driver and the
		// constraint that failed.
		code = codeForStatus(status)
		if msg, known = messages[code]; !known {
			msg = genericMessage
		}
	}
	writeJSON(w, status, mustMarshal(errorBody{Code: code, Message: msg}))
}

// writeJSON commits the response in one pass: content type, then length, then
// status, then bytes. Setting Content-Length before WriteHeader keeps the
// response non-chunked, which matters for the ops CLI and for any proxy that
// buffers by length.
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", jsonContentType)
	// Repeated from SecurityHeaders on purpose: a handler mounted outside the
	// middleware chain still must not have its JSON sniffed as HTML, and this
	// is the only place every JSON response in the system passes through.
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(normalizeStatus(status))
	// The trailing newline keeps curl and the operator CLI readable and is
	// counted in Content-Length above. The write result is dropped because the
	// response is the last thing this process does for the request: a failure
	// means the peer is gone, which net/http observes on the connection anyway.
	_, _ = w.Write(append(body, '\n'))
}

// normalizeStatus keeps an out-of-range code away from WriteHeader, which
// panics on one. A miscomputed status must not be able to take down the
// request through the panic path.
func normalizeStatus(status int) int {
	if status < 100 || status > 599 {
		return http.StatusInternalServerError
	}
	return status
}

// sanitizeCode reduces a code to the lowercase identifier alphabet and falls
// back to the code implied by the status. It exists because the alternative —
// trusting the string a handler passes — is how an error message ends up
// pasted into a code field and reflected back to the caller.
func sanitizeCode(code string, status int) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) > maxCodeLen {
		code = code[:maxCodeLen]
	}
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return codeForStatus(status)
	}
	return b.String()
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusConflict:
		return CodeConflict
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	case http.StatusUnsupportedMediaType:
		return CodeUnsupportedMedia
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	case http.StatusGatewayTimeout:
		return CodeTimeout
	default:
		return CodeInternal
	}
}

// mustMarshal encodes a struct of plain strings, which encoding/json cannot
// fail on. The fallback is still spelled out rather than assumed, because the
// error path of the error path is exactly where a service is least able to
// afford an empty body.
func mustMarshal(b errorBody) []byte {
	out, err := json.Marshal(b)
	if err != nil {
		return []byte(`{"code":"internal_error","message":"internal error"}`)
	}
	return out
}

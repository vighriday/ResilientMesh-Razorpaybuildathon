package sse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ErrSessionNotFound is what a SessionLookup returns for an identifier the store
// does not know. It is a distinct sentinel rather than the store's own so this
// package stays free of a database dependency, and so a lookup failure caused by
// an unreachable database can never be mistaken for a missing session — one is a
// 404, the other is a 503, and conflating them would tell an operator the wrong
// story during an outage.
var ErrSessionNotFound = errors.New("sse: session not found")

// SessionLookup resolves a stream request to the durable session record whose
// TokenHash the credential is checked against. It takes a func rather than
// domain.Store so the edge depends on one query instead of the whole store
// surface.
type SessionLookup func(ctx context.Context, sessionID string) (domain.SessionRecord, error)

const (
	// DefaultRoute is the pattern the returned handler registers. Go 1.22
	// pattern routing is used rather than a prefix match plus manual parsing:
	// the mux enforces the method and the single-segment shape, so a path like
	// /stream/a/b cannot reach the handler with a session id of "a/b".
	DefaultRoute = "GET /api/v1/session/stream/{session_id}"

	// DefaultHeartbeat keeps intermediaries from reaping an idle stream. A
	// checkout can sit silent for minutes while a customer reads the page.
	DefaultHeartbeat = 15 * time.Second

	// DefaultWriteTimeout bounds a single frame write. Without it a client that
	// stops reading pins a goroutine until the TCP stack gives up, which can be
	// many minutes: the request context is not cancelled by a stalled peer, only
	// by a closed one.
	DefaultWriteTimeout = 10 * time.Second

	// DefaultMaxSessions mirrors MESH_MAX_SESSIONS. An unset ceiling resolves to
	// this rather than to "unlimited", because a zero-valued security control
	// must not read as permission.
	DefaultMaxSessions = 50000

	// reconnectDelayMS is advertised to EventSource so every dropped client does
	// not return in the same millisecond after a deploy.
	reconnectDelayMS = 3000

	maxLastEventIDLen = 20
)

// Fixed response bodies. Nothing derived from the request is ever echoed: an
// error body that quotes its input is a reflection primitive, and one that
// quotes an internal error is a reconnaissance aid.
const (
	bodyUnauthorized = `{"error":"unauthorized"}`
	bodyNotFound     = `{"error":"session_not_found"}`
	bodyUnavailable  = `{"error":"unavailable"}`
)

// Options configures the SSE edge. The zero value is valid.
type Options struct {
	// MaxSessions caps concurrently attached streams.
	MaxSessions int
	// Heartbeat is the comment-line keep-alive interval.
	Heartbeat time.Duration
	// WriteTimeout bounds one frame write when the platform supports deadlines.
	WriteTimeout time.Duration
	// Clock decides session expiry, so expiry is testable without waiting.
	Clock domain.Clock
	// Route overrides DefaultRoute for a deployment that mounts elsewhere.
	Route string
}

type server struct {
	hub          *Hub
	lookup       SessionLookup
	log          *slog.Logger
	clock        domain.Clock
	maxSessions  int
	heartbeat    time.Duration
	writeTimeout time.Duration
}

// Handler serves the checkout event stream with the ceiling from
// MESH_MAX_SESSIONS. hub and lookup are required; passing nil for either is a
// wiring bug that would otherwise surface as a nil dereference on the first
// customer request, so it fails at construction instead.
func Handler(hub *Hub, lookup SessionLookup, logger *slog.Logger, maxSessions int) http.Handler {
	return HandlerWithOptions(hub, lookup, logger, Options{MaxSessions: maxSessions})
}

// HandlerWithOptions is Handler with the timing knobs exposed, which is what
// makes the heartbeat and expiry paths testable in milliseconds instead of
// minutes.
func HandlerWithOptions(hub *Hub, lookup SessionLookup, logger *slog.Logger, opts Options) http.Handler {
	if hub == nil {
		panic("sse: Handler requires a non-nil hub")
	}
	if lookup == nil {
		panic("sse: Handler requires a non-nil session lookup")
	}
	s := &server{
		hub:          hub,
		lookup:       lookup,
		log:          logger,
		clock:        opts.Clock,
		maxSessions:  opts.MaxSessions,
		heartbeat:    opts.Heartbeat,
		writeTimeout: opts.WriteTimeout,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.clock == nil {
		s.clock = systemClock{}
	}
	if s.maxSessions <= 0 {
		s.maxSessions = DefaultMaxSessions
	}
	if s.heartbeat <= 0 {
		s.heartbeat = DefaultHeartbeat
	}
	if s.writeTimeout <= 0 {
		s.writeTimeout = DefaultWriteTimeout
	}

	route := opts.Route
	if route == "" {
		route = DefaultRoute
	}
	mux := http.NewServeMux()
	mux.Handle(route, http.HandlerFunc(s.stream))
	return mux
}

func (s *server) stream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionID := r.PathValue("session_id")
	if err := ValidateSessionID(sessionID); err != nil {
		// A malformed identifier is answered exactly like an unknown one, so the
		// shape of a session id cannot be probed from the response code.
		s.fail(w, http.StatusNotFound, bodyNotFound)
		return
	}

	token, ok := credential(r)
	if !ok {
		// Rejected before the lookup: an unauthenticated caller must not be able
		// to spend a database round trip per request.
		s.fail(w, http.StatusUnauthorized, bodyUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Streaming through a writer that cannot flush would buffer the whole
		// response and deliver a rail morph after the customer has given up.
		s.log.ErrorContext(ctx, "sse: response writer does not support flushing")
		s.fail(w, http.StatusServiceUnavailable, bodyUnavailable)
		return
	}

	// Cheap shed before the lookup. The authoritative check happens inside
	// SubscribeBounded, which is the only one that is race-free; this one exists
	// so a connection storm is refused without touching the database.
	if s.hub.Streams() >= int64(s.maxSessions) {
		s.fail(w, http.StatusServiceUnavailable, bodyUnavailable)
		return
	}

	rec, err := s.lookup(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			s.fail(w, http.StatusNotFound, bodyNotFound)
			return
		}
		// The cause is logged, never returned: it names internal infrastructure.
		s.log.ErrorContext(ctx, "sse: session lookup failed",
			slog.String("session_id", sessionID), slog.String("error", err.Error()))
		s.fail(w, http.StatusServiceUnavailable, bodyUnavailable)
		return
	}

	// Credential first, liveness second. Checked the other way round, an expired
	// session would answer 404 to a caller holding no token at all, turning the
	// endpoint into a free oracle for session lifetimes.
	if !VerifyToken(token, rec.TokenHash) {
		s.log.WarnContext(ctx, "sse: stream credential rejected", slog.String("session_id", sessionID))
		s.fail(w, http.StatusUnauthorized, bodyUnauthorized)
		return
	}
	if rec.Expired(s.clock.Now()) {
		s.fail(w, http.StatusNotFound, bodyNotFound)
		return
	}

	if r.Method == http.MethodHead {
		// The mux routes HEAD to a GET pattern. Streaming into a discarded body
		// would hold the connection open forever for no observer.
		s.writeStreamHeaders(w, r)
		flusher.Flush()
		return
	}

	events, unsubscribe, err := s.hub.SubscribeBounded(ctx, sessionID, s.maxSessions)
	if err != nil {
		if errors.Is(err, ErrHubFull) {
			s.fail(w, http.StatusServiceUnavailable, bodyUnavailable)
			return
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		s.log.ErrorContext(ctx, "sse: subscribe failed",
			slog.String("session_id", sessionID), slog.String("error", err.Error()))
		s.fail(w, http.StatusServiceUnavailable, bodyUnavailable)
		return
	}
	defer unsubscribe()

	s.writeStreamHeaders(w, r)
	w.WriteHeader(http.StatusOK)

	st := &stream{
		w:            w,
		flusher:      flusher,
		rc:           http.NewResponseController(w),
		clock:        s.clock,
		writeTimeout: s.writeTimeout,
		log:          s.log,
	}
	// Opening preamble: the reconnect hint plus a comment that forces any
	// buffering intermediary to commit the response headers immediately.
	if err := st.writePreamble(); err != nil {
		s.log.DebugContext(ctx, "sse: stream preamble not delivered", slog.String("error", err.Error()))
		return
	}
	if last, resuming := lastEventID(r); resuming {
		if err := st.writeResumeMarker(s.hub.Sequence(sessionID), last); err != nil {
			s.log.DebugContext(ctx, "sse: resume marker not delivered", slog.String("error", err.Error()))
			return
		}
	}

	s.pump(ctx, st, events)
}

// pump is the per-connection loop. It owns exactly three things — the client
// going away, a frame arriving, and the keep-alive — and returns on any write
// error, because a failed write means the socket is gone and every subsequent
// one would fail identically.
func (s *server) pump(ctx context.Context, st *stream, events <-chan domain.SessionEvent) {
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()

	var lastSeq int64
	for {
		select {
		case <-ctx.Done():
			return

		case ev, open := <-events:
			if !open {
				// The hub detached this stream: shutdown, or eviction after the
				// client stopped reading. Synthesising the frame here rather
				// than publishing it through the hub is what guarantees it is
				// not the frame that gets dropped for a full buffer.
				closing := domain.SessionEvent{
					Type:     "closed",
					Reason:   "stream_closed",
					Sequence: lastSeq,
					At:       st.clock.Now().Unix(),
				}
				if err := st.writeEvent(closing); err != nil {
					st.log.DebugContext(ctx, "sse: closing frame not delivered", slog.String("error", err.Error()))
				}
				return
			}
			lastSeq = ev.Sequence
			if err := st.writeEvent(ev); err != nil {
				st.log.DebugContext(ctx, "sse: stream write failed", slog.String("error", err.Error()))
				return
			}

		case <-ticker.C:
			if err := st.writeComment("heartbeat"); err != nil {
				st.log.DebugContext(ctx, "sse: heartbeat write failed", slog.String("error", err.Error()))
				return
			}
		}
	}
}

func (s *server) writeStreamHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-store, no-transform")
	h.Set("X-Content-Type-Options", "nosniff")
	// nginx and several Indian CDN edges buffer unknown content types by
	// default, which turns a live stream into a batch delivered at close.
	h.Set("X-Accel-Buffering", "no")
	if r.ProtoMajor == 1 {
		// Connection is a hop-by-hop header and is illegal in HTTP/2, where the
		// transport keeps the connection alive on its own terms anyway.
		h.Set("Connection", "keep-alive")
	}
}

func (s *server) fail(w http.ResponseWriter, status int, body string) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	switch status {
	case http.StatusUnauthorized:
		h.Set("WWW-Authenticate", `Bearer realm="checkout-session"`)
	case http.StatusServiceUnavailable:
		h.Set("Retry-After", "5")
	}
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		s.log.Debug("sse: error response not delivered", slog.String("error", err.Error()))
	}
}

// credential extracts the stream token, preferring the Authorization header.
//
// The query fallback exists because EventSource cannot set request headers —
// there is no API for it, in any browser — so a header-only endpoint would
// force the checkout page onto a hand-rolled fetch-and-parse reader and lose
// automatic reconnection. The cost is that the credential lands in access logs
// and Referer headers, which is why this particular token is single-purpose (it
// authorises one read-only stream and nothing else), short-lived (it dies with
// the checkout session), and stored only as a SHA-256 digest, so a log line
// containing it is a bounded incident rather than an account compromise.
//
// An Authorization header of a different scheme is a rejection, not a reason to
// look in the query string: silent precedence between two credential sources is
// how a client ends up authenticating as someone it did not intend to.
func credential(r *http.Request) (string, bool) {
	if raw := r.Header.Get("Authorization"); raw != "" {
		const prefix = "Bearer "
		if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
			return "", false
		}
		return validToken(strings.TrimSpace(raw[len(prefix):]))
	}
	return validToken(r.URL.Query().Get("token"))
}

func validToken(tok string) (string, bool) {
	if tok == "" || len(tok) > MaxSessionTokenLen {
		return "", false
	}
	return tok, true
}

// lastEventID reads the header EventSource replays on reconnect. Anything that
// is not a plain bounded integer is ignored rather than repaired: the value is
// attacker-controlled and its only use is a number.
func lastEventID(r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if raw == "" || len(raw) > maxLastEventIDLen {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// stream owns the byte-level framing for one connection.
type stream struct {
	w            http.ResponseWriter
	flusher      http.Flusher
	rc           *http.ResponseController
	clock        domain.Clock
	writeTimeout time.Duration
	log          *slog.Logger
	buf          bytes.Buffer
	noDeadlines  bool
}

func (st *stream) writePreamble() error {
	st.buf.Reset()
	st.buf.WriteString("retry: ")
	st.buf.WriteString(strconv.Itoa(reconnectDelayMS))
	st.buf.WriteString("\n\n: stream open\n\n")
	return st.emit()
}

// writeResumeMarker tells a reconnecting client the truth: this hub holds no
// history, so the frames it missed are gone.
//
// An in-memory hub cannot replay — buffering every session's history to serve a
// reconnect would trade a bounded, honest gap for an unbounded memory footprint
// on the request path. Sending nothing at all would be worse than either: the
// client would assume it had resumed cleanly and quietly act on a partial view.
// The marker carries the hub's current sequence so the client can compute
// exactly how many frames it lost and re-read authoritative order state if the
// number is not zero.
func (st *stream) writeResumeMarker(current, last int64) error {
	reason := "resumed_without_replay"
	if current > last {
		reason = "resumed_with_gap"
	}
	return st.writeEvent(domain.SessionEvent{
		Type:     "status",
		Reason:   reason,
		Sequence: current,
		At:       st.clock.Now().Unix(),
	})
}

func (st *stream) writeEvent(ev domain.SessionEvent) error {
	// JSON encoding is what keeps the framing safe: encoding/json escapes every
	// control byte, so no field value can emit the newline that would end the
	// data line early and let an attacker forge a frame.
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("sse: encode session event: %w", err)
	}
	st.buf.Reset()
	if ev.Sequence > 0 {
		st.buf.WriteString("id: ")
		st.buf.WriteString(strconv.FormatInt(ev.Sequence, 10))
		st.buf.WriteByte('\n')
	}
	st.buf.WriteString("event: ")
	st.buf.WriteString(eventName(ev.Type))
	st.buf.WriteString("\ndata: ")
	st.buf.Write(data)
	st.buf.WriteString("\n\n")
	return st.emit()
}

func (st *stream) writeComment(text string) error {
	st.buf.Reset()
	st.buf.WriteString(": ")
	st.buf.WriteString(eventName(text))
	st.buf.WriteString("\n\n")
	return st.emit()
}

func (st *stream) emit() error {
	st.setDeadline()
	if _, err := st.w.Write(st.buf.Bytes()); err != nil {
		return fmt.Errorf("sse: write frame: %w", err)
	}
	st.flusher.Flush()
	return nil
}

// setDeadline bounds the next write where the platform allows it.
//
// The deadline is taken from time.Now rather than the injected clock on purpose:
// it is handed to the network stack, which compares it against real wall time.
// The domain clock governs decisions — session expiry, event timestamps — and
// wiring it into a socket deadline would mean any deployment or test running on
// virtual time would kill every connection instantly or never at all.
//
// A writer that does not support deadlines — an httptest recorder, a middleware
// that does not unwrap — is a degradation, not a failure, so it is noted once
// and the stream continues.
func (st *stream) setDeadline() {
	if st.noDeadlines {
		return
	}
	if err := st.rc.SetWriteDeadline(time.Now().Add(st.writeTimeout)); err != nil {
		st.noDeadlines = true
		st.log.Debug("sse: write deadlines unsupported on this writer", slog.String("error", err.Error()))
	}
}

// eventName reduces a type or comment to a token that cannot break framing. The
// event field is raw text in the SSE grammar, so an unfiltered newline there
// forges frames outright; the allowlist removes the possibility rather than
// escaping it. An empty result becomes "message", the SSE default.
func eventName(s string) string {
	const maxLen = 32
	out := make([]byte, 0, maxLen)
	for i := 0; i < len(s) && len(out) < maxLen; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == ' ':
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "message"
	}
	return string(out)
}

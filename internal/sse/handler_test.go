package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type stubSessions struct {
	mu      sync.Mutex
	records map[string]domain.SessionRecord
	err     error
	calls   atomic.Int64
}

func newStubSessions() *stubSessions {
	return &stubSessions{records: make(map[string]domain.SessionRecord)}
}

func (s *stubSessions) lookup(_ context.Context, id string) (domain.SessionRecord, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return domain.SessionRecord{}, s.err
	}
	rec, ok := s.records[id]
	if !ok {
		return domain.SessionRecord{}, ErrSessionNotFound
	}
	return rec, nil
}

func (s *stubSessions) put(rec domain.SessionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.ID] = rec
}

func (s *stubSessions) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

type harness struct {
	hub     *Hub
	store   *stubSessions
	clock   *fakeClock
	server  *httptest.Server
	token   string
	session string
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()
	clock := newFakeClock()
	if opts.Clock == nil {
		opts.Clock = clock
	}
	hub := NewHub(HubConfig{Clock: clock})
	store := newStubSessions()

	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	const sessionID = "sess_9fA2bC7dE1"
	store.put(domain.SessionRecord{
		ID:          sessionID,
		OrderID:     "order_JT4bY2",
		TokenHash:   hash,
		CurrentRail: domain.RailCard,
		AmountPaisa: 249900,
		Currency:    "INR",
		Active:      true,
		CreatedAt:   clock.Now(),
		ExpiresAt:   clock.Now().Add(15 * time.Minute),
	})

	srv := httptest.NewServer(HandlerWithOptions(hub, store.lookup, nil, opts))
	t.Cleanup(srv.Close)
	return &harness{hub: hub, store: store, clock: clock, server: srv, token: token, session: sessionID}
}

func (h *harness) url(sessionID string) string {
	return h.server.URL + "/api/v1/session/stream/" + sessionID
}

// do issues a non-streaming request and returns the response with its body read.
func (h *harness) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close body: %v", err)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// frame is one parsed SSE block, terminated by a blank line.
type frame struct {
	id       string
	event    string
	data     string
	retry    string
	comments []string
}

func readFrame(br *bufio.Reader) (frame, error) {
	var f frame
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return f, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return f, nil
		}
		if strings.HasPrefix(line, ":") {
			f.comments = append(f.comments, strings.TrimSpace(line[1:]))
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return f, errors.New("sse frame line has no field separator: " + line)
		}
		value = strings.TrimPrefix(value, " ")
		switch name {
		case "id":
			f.id = value
		case "event":
			f.event = value
		case "data":
			if f.data != "" {
				f.data += "\n"
			}
			f.data += value
		case "retry":
			f.retry = value
		default:
			return f, errors.New("unknown sse field: " + name)
		}
	}
}

// streamConn reads frames off a live stream in the background so a test can
// assert with a timeout instead of blocking forever on a broken server.
type streamConn struct {
	resp   *http.Response
	frames chan frame
	errs   chan error
	cancel context.CancelFunc
}

func (h *harness) open(t *testing.T, req *http.Request) *streamConn {
	t.Helper()
	ctx, cancel := context.WithCancel(req.Context())
	resp, err := h.server.Client().Do(req.WithContext(ctx))
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	sc := &streamConn{
		resp:   resp,
		frames: make(chan frame, 64),
		errs:   make(chan error, 1),
		cancel: cancel,
	}
	go func() {
		br := bufio.NewReader(resp.Body)
		for {
			f, err := readFrame(br)
			if err != nil {
				sc.errs <- err
				close(sc.frames)
				return
			}
			sc.frames <- f
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := resp.Body.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("close stream body: %v", err)
		}
	})
	return sc
}

// nextWithin returns the next frame or an error, so a caller running on a
// spawned goroutine can report through t.Errorf. t.Fatal off the test
// goroutine only exits that one goroutine, which turns a single cause into a
// pile of identical-looking failures.
func (sc *streamConn) nextWithin(d time.Duration) (frame, error) {
	select {
	case f, ok := <-sc.frames:
		if !ok {
			select {
			case err := <-sc.errs:
				return frame{}, fmt.Errorf("stream ended: %w", err)
			default:
				return frame{}, errors.New("stream ended")
			}
		}
		return f, nil
	case <-time.After(d):
		return frame{}, fmt.Errorf("no SSE frame within %s", d)
	}
}

func (sc *streamConn) next(t *testing.T) frame {
	t.Helper()
	f, err := sc.nextWithin(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// nextEventWithin skips preamble comments and heartbeats until a data frame
// arrives or the deadline passes.
//
// The budget is a deadline rather than a frame count, and that distinction is
// the whole point of this helper. Heartbeats are unbounded in number and
// bounded only in rate, so counting frames is really a bet on how much wall
// clock the test will be given. It lost that bet under the race detector: 64
// concurrent streams on a 30ms heartbeat put more than 32 comments ahead of
// the event, and a perfectly healthy stream was reported as broken.
func (sc *streamConn) nextEventWithin(d time.Duration) (frame, domain.SessionEvent, error) {
	deadline := time.Now().Add(d)
	skipped := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return frame{}, domain.SessionEvent{}, fmt.Errorf(
				"no data frame in %s, after %d non-data frames", d, skipped)
		}
		f, err := sc.nextWithin(remaining)
		if err != nil {
			return frame{}, domain.SessionEvent{}, err
		}
		if f.data == "" {
			skipped++
			continue
		}
		var ev domain.SessionEvent
		if err := json.Unmarshal([]byte(f.data), &ev); err != nil {
			return frame{}, domain.SessionEvent{}, fmt.Errorf(
				"data line is not valid JSON: %w (%q)", err, f.data)
		}
		return f, ev, nil
	}
}

// nextEvent skips preamble comments and heartbeats.
func (sc *streamConn) nextEvent(t *testing.T) (frame, domain.SessionEvent) {
	t.Helper()
	f, ev, err := sc.nextEventWithin(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return f, ev
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) authedRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url(h.session), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	return req
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestHandlerStreamsWellFormedSSE(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	sc := h.open(t, h.authedRequest(t, context.Background()))

	hdr := sc.resp.Header
	for _, want := range [][2]string{
		{"Content-Type", "text/event-stream; charset=utf-8"},
		{"Cache-Control", "no-cache, no-store, no-transform"},
		{"X-Accel-Buffering", "no"},
		{"X-Content-Type-Options", "nosniff"},
	} {
		if got := hdr.Get(want[0]); got != want[1] {
			t.Fatalf("%s = %q, want %q", want[0], got, want[1])
		}
	}

	if f := sc.next(t); f.retry != "3000" {
		t.Fatalf("preamble retry = %q, want 3000", f.retry)
	}
	if f := sc.next(t); len(f.comments) != 1 || f.comments[0] != "stream open" {
		t.Fatalf("preamble comment = %v, want [stream open]", f.comments)
	}

	// The preamble is written after Subscribe returns, so the stream is
	// guaranteed attached by the time the client has read it.
	if err := h.hub.Publish(context.Background(), h.session, morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	f, ev := sc.nextEvent(t)
	if f.id != "1" {
		t.Fatalf("id = %q, want 1", f.id)
	}
	if f.event != "rail_morph" {
		t.Fatalf("event = %q, want rail_morph", f.event)
	}
	if strings.Contains(f.data, "\n") {
		t.Fatal("data must be encoded on a single line")
	}
	if ev.Sequence != 1 || ev.ToRail != domain.RailUPIIntent || ev.AmountPaisa != 249900 {
		t.Fatalf("decoded event = %+v", ev)
	}
	if ev.At == 0 {
		t.Fatal("event timestamp missing")
	}
}

func TestHandlerAcceptsQueryTokenForEventSource(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		h.url(h.session)+"?token="+h.token, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	sc := h.open(t, req)
	if f := sc.next(t); f.retry != "3000" {
		t.Fatalf("preamble retry = %q, want 3000", f.retry)
	}
	waitFor(t, "subscription", func() bool { return h.hub.Count() == 1 })
}

func TestHandlerRejectsWrongToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	other, _, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}

	cases := []struct {
		name string
		set  func(*http.Request)
	}{
		{"another session's token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+other) }},
		{"truncated token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+h.token[:len(h.token)-1]) }},
		{"token as query", func(r *http.Request) { r.URL.RawQuery = "token=" + other }},
		{"basic scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic "+h.token) }},
		{"header present but empty scheme", func(r *http.Request) { r.Header.Set("Authorization", "Bearer") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url(h.session), nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			tc.set(req)
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if body != bodyUnauthorized {
				t.Fatalf("body = %q, want a fixed error string", body)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Fatal("401 without a WWW-Authenticate challenge")
			}
			if strings.Contains(body, h.session) || strings.Contains(body, h.token) {
				t.Fatal("error body echoed request input")
			}
		})
	}
	if h.hub.Count() != 0 {
		t.Fatal("a rejected request must not leave a subscription behind")
	}
}

func TestHandlerRejectsMissingTokenWithoutTouchingTheStore(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url(h.session), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if body != bodyUnauthorized {
		t.Fatalf("body = %q", body)
	}
	if n := h.store.calls.Load(); n != 0 {
		t.Fatalf("store consulted %d times for an unauthenticated request, want 0", n)
	}
}

func TestHandlerUnknownSessionIs404(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url("sess_doesnotexist"), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if body != bodyNotFound {
		t.Fatalf("body = %q", body)
	}
}

func TestHandlerMalformedSessionIDIs404WithoutStoreLookup(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	for _, id := range []string{"sess%20a", "sess%00", strings.Repeat("s", MaxSessionIDLen+1)} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url(id), nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+h.token)
		resp, body := h.do(t, req)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status for %q = %d, want 404", id, resp.StatusCode)
		}
		if body != bodyNotFound {
			t.Fatalf("body = %q", body)
		}
	}
	if n := h.store.calls.Load(); n != 0 {
		t.Fatalf("store consulted %d times for a malformed id, want 0", n)
	}
}

func TestHandlerExpiredSessionIs404(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})

	// Past the expiry instant, with a valid credential: the answer is still 404.
	h.clock.Advance(16 * time.Minute)
	resp, body := h.do(t, h.authedRequest(t, context.Background()))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if body != bodyNotFound {
		t.Fatalf("body = %q", body)
	}
}

func TestHandlerClosedSessionIs404(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	closed := time.Now()
	h.store.put(domain.SessionRecord{
		ID:        h.session,
		TokenHash: HashToken(h.token),
		Active:    false,
		ExpiresAt: h.clock.Now().Add(time.Hour),
		ClosedAt:  &closed,
	})
	resp, _ := h.do(t, h.authedRequest(t, context.Background()))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an inactive session", resp.StatusCode)
	}
}

func TestHandlerSessionWithoutTokenHashIs401(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	h.store.put(domain.SessionRecord{
		ID:        h.session,
		TokenHash: "",
		Active:    true,
		ExpiresAt: h.clock.Now().Add(time.Hour),
	})
	resp, _ := h.do(t, h.authedRequest(t, context.Background()))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: an empty stored hash must never match", resp.StatusCode)
	}
}

func TestHandlerShedsLoadPastTheCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 1})
	sc := h.open(t, h.authedRequest(t, context.Background()))
	if f := sc.next(t); f.retry == "" {
		t.Fatal("expected the preamble on the admitted stream")
	}
	waitFor(t, "first stream attached", func() bool { return h.hub.Streams() == 1 })

	resp, body := h.do(t, h.authedRequest(t, context.Background()))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if body != bodyUnavailable {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After: a shed client has no idea when to return")
	}
}

func TestHandlerLookupFailureIs503AndLeaksNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	h.store.fail(errors.New("dial tcp 10.0.3.14:5432: connection refused"))

	resp, body := h.do(t, h.authedRequest(t, context.Background()))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if body != bodyUnavailable {
		t.Fatalf("body = %q, want a fixed error string", body)
	}
	if strings.Contains(body, "5432") || strings.Contains(body, "connection refused") {
		t.Fatal("internal failure detail reached the client")
	}
}

// nonFlusher is an http.ResponseWriter with no Flush method, which is what a
// buffering middleware looks like from in here.
type nonFlusher struct {
	header http.Header
	status int
	body   strings.Builder
}

func (n *nonFlusher) Header() http.Header { return n.header }
func (n *nonFlusher) Write(b []byte) (int, error) {
	return n.body.Write(b)
}
func (n *nonFlusher) WriteHeader(status int) { n.status = status }

func TestHandlerRefusesToStreamWithoutAFlusher(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	hub := NewHub(HubConfig{Clock: clock})
	store := newStubSessions()
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	store.put(domain.SessionRecord{
		ID: "sess_abc", TokenHash: hash, Active: true, ExpiresAt: clock.Now().Add(time.Hour),
	})
	handler := HandlerWithOptions(hub, store.lookup, nil, Options{MaxSessions: 4, Clock: clock})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/session/stream/sess_abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := &nonFlusher{header: make(http.Header)}
	handler.ServeHTTP(w, req)

	if w.status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.status)
	}
	if w.body.String() != bodyUnavailable {
		t.Fatalf("body = %q", w.body.String())
	}
	if hub.Streams() != 0 {
		t.Fatal("a refused stream must not be registered with the hub")
	}
}

func TestHandlerUnsubscribesOnClientDisconnect(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	ctx, cancel := context.WithCancel(context.Background())
	sc := h.open(t, h.authedRequest(t, ctx))
	if f := sc.next(t); f.retry == "" {
		t.Fatal("expected the preamble")
	}
	waitFor(t, "stream attached", func() bool { return h.hub.Count() == 1 })

	cancel()
	waitFor(t, "stream released", func() bool { return h.hub.Count() == 0 && h.hub.Streams() == 0 })
	if h.hub.Active(h.session) {
		t.Fatal("session still reported active after disconnect")
	}
}

func TestHandlerEmitsHeartbeatComments(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8, Heartbeat: 20 * time.Millisecond})
	sc := h.open(t, h.authedRequest(t, context.Background()))

	seen := 0
	for i := 0; i < 16 && seen < 2; i++ {
		f := sc.next(t)
		for _, c := range f.comments {
			if c == "heartbeat" {
				seen++
			}
		}
	}
	if seen < 2 {
		t.Fatalf("saw %d heartbeat comments, want at least 2", seen)
	}
}

func TestHandlerAnswersLastEventIDWithAnHonestResumeMarker(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})

	// Advance the session's sequence, then disconnect: the counter survives, so
	// the reconnecting client can be told exactly how far behind it is.
	_, unsub := mustSubscribe(t, h.hub, h.session)
	for i := 0; i < 4; i++ {
		if err := h.hub.Publish(context.Background(), h.session, morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	unsub()

	req := h.authedRequest(t, context.Background())
	req.Header.Set("Last-Event-ID", "1")
	sc := h.open(t, req)

	f, ev := sc.nextEvent(t)
	if f.event != "status" {
		t.Fatalf("event = %q, want status", f.event)
	}
	if ev.Reason != "resumed_with_gap" {
		t.Fatalf("reason = %q, want resumed_with_gap", ev.Reason)
	}
	if ev.Sequence != 4 || f.id != "4" {
		t.Fatalf("resume marker sequence = %d id = %q, want 4/4", ev.Sequence, f.id)
	}
}

func TestHandlerIgnoresMalformedLastEventID(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	req := h.authedRequest(t, context.Background())
	req.Header.Set("Last-Event-ID", "not-a-number")
	sc := h.open(t, req)

	if f := sc.next(t); f.retry != "3000" {
		t.Fatalf("preamble retry = %q", f.retry)
	}
	if f := sc.next(t); len(f.comments) == 0 {
		t.Fatalf("expected the open comment, got %+v", f)
	}
	if err := h.hub.Publish(context.Background(), h.session, morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	f, ev := sc.nextEvent(t)
	if f.event != "rail_morph" || ev.Sequence != 1 {
		t.Fatalf("first data frame after a malformed resume header = %q seq %d, want rail_morph/1", f.event, ev.Sequence)
	}
}

func TestHandlerSendsClosedFrameWhenTheHubDetachesTheStream(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	sc := h.open(t, h.authedRequest(t, context.Background()))
	if f := sc.next(t); f.retry == "" {
		t.Fatal("expected the preamble")
	}
	waitFor(t, "stream attached", func() bool { return h.hub.Streams() == 1 })

	if closed := h.hub.Shutdown(); closed != 1 {
		t.Fatalf("Shutdown closed %d streams, want 1", closed)
	}
	f, ev := sc.nextEvent(t)
	if f.event != "closed" || ev.Type != "closed" {
		t.Fatalf("final frame = %q/%q, want closed", f.event, ev.Type)
	}
	if _, ok := <-sc.frames; ok {
		t.Fatal("server kept the connection open after the closed frame")
	}
}

func TestHandlerRejectsNonGETMethods(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req, err := http.NewRequestWithContext(context.Background(), method, h.url(h.session), nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+h.token)
		resp, _ := h.do(t, req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want 405", method, resp.StatusCode)
		}
	}
}

func TestHandlerDoesNotStreamIntoAHEADResponse(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, h.url(h.session), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := h.do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream; charset=utf-8" {
			t.Errorf("Content-Type = %q", ct)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HEAD request did not complete: the handler streamed into a discarded body")
	}
	if h.hub.Streams() != 0 {
		t.Fatal("HEAD must not register a stream")
	}
}

func TestHandlerServesManyConcurrentStreams(t *testing.T) {
	t.Parallel()
	const streams = 64
	h := newHarness(t, Options{MaxSessions: streams, Heartbeat: 30 * time.Millisecond})

	conns := make([]*streamConn, 0, streams)
	for i := 0; i < streams; i++ {
		sc := h.open(t, h.authedRequest(t, context.Background()))
		conns = append(conns, sc)
	}
	waitFor(t, "all streams attached", func() bool { return h.hub.Streams() == streams })

	if err := h.hub.Publish(context.Background(), h.session, morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		// Each reader reports through t.Errorf rather than t.Fatal: these are
		// not the test goroutine, and Fatal here would only stop the reader
		// that called it.
		go func(n int, sc *streamConn) {
			defer wg.Done()
			_, ev, err := sc.nextEventWithin(15 * time.Second)
			if err != nil {
				t.Errorf("stream %d: %v", n, err)
				return
			}
			if ev.Type != "rail_morph" {
				t.Errorf("stream %d: event type = %q, want rail_morph", n, ev.Type)
			}
		}(i, conns[i])
	}
	wg.Wait()
}

// TestHandlerFramingResistsInjectedEventFields is the reason the framing code
// filters the event name and JSON-encodes the payload: an attacker who can
// influence any string on a published event must not be able to forge a second
// frame — a fabricated rail_morph is a fabricated instruction to the checkout.
func TestHandlerFramingResistsInjectedEventFields(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Options{MaxSessions: 8})
	sc := h.open(t, h.authedRequest(t, context.Background()))
	if f := sc.next(t); f.retry == "" {
		t.Fatal("expected the preamble")
	}
	if f := sc.next(t); len(f.comments) == 0 {
		t.Fatal("expected the open comment")
	}

	hostile := morphEvent()
	hostile.Type = "status\nevent: rail_morph"
	hostile.Reason = "ok\n\nid: 99\nevent: rail_morph\ndata: {\"to_rail\":\"upi_intent\"}\n\n"
	if err := h.hub.Publish(context.Background(), h.session, hostile); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	f, ev := sc.nextEvent(t)
	if f.event != "statusevent_rail_morph" {
		t.Fatalf("event = %q: the event name was not neutralised", f.event)
	}
	if strings.ContainsAny(ev.Reason, "\r\n") {
		t.Fatalf("reason retained a framing character: %q", ev.Reason)
	}
	if f.id != "1" || ev.Sequence != 1 {
		t.Fatalf("id = %q sequence = %d, want 1/1", f.id, ev.Sequence)
	}

	// The next frame on the wire must be the next real publish. Anything in
	// between would be a frame the attacker minted.
	if err := h.hub.Publish(context.Background(), h.session, morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	next, nextEv := sc.nextEvent(t)
	if next.id != "2" || nextEv.Sequence != 2 || next.event != "rail_morph" {
		t.Fatalf("forged frame observed: id=%q event=%q seq=%d", next.id, next.event, nextEv.Sequence)
	}
}

func TestEventNameCannotBreakFraming(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"rail_morph":                   "rail_morph",
		"RAIL_MORPH":                   "rail_morph",
		"":                             "message",
		"\n\ndata: {\"amount\":1}\n\n": "data_amount1",
		"status\r\nevent: rail_morph":  "statusevent_rail_morph",
		strings.Repeat("a", 200):       strings.Repeat("a", 32),
		"../../etc/passwd":             "etcpasswd",
		"\x00\x01\x02":                 "message",
	}
	for in, want := range cases {
		if got := eventName(in); got != want {
			t.Fatalf("eventName(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(eventName(in), "\r\n:") {
			t.Fatalf("eventName(%q) leaked a framing character", in)
		}
	}
}

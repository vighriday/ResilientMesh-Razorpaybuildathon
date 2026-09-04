// Package sse implements the live checkout session hub and the Server-Sent
// Events edge that exposes it.
//
// The hub is the mechanism behind in-session healing: when the worker decides a
// failing payment should move to a different rail, the decision has to reach a
// browser that is still open, within the few seconds the customer will wait.
// That makes the hub a latency-critical component sitting directly in the path
// of a worker goroutine, which drives its two defining properties: publishing
// never blocks, and a single misbehaving client can degrade nothing but itself.
package sse

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Errors callers are expected to branch on.
var (
	// ErrHubFull is returned by SubscribeBounded when admitting another stream
	// would breach the configured ceiling. The edge turns it into a 503:
	// refusing a connection is recoverable, running out of file descriptors
	// mid-incident is not.
	ErrHubFull = errors.New("sse: session hub at capacity")

	// ErrInvalidSessionID means the identifier failed the character or length
	// bound. The offending value is never included in the error, because it is
	// attacker-controlled text that would otherwise reach log files.
	ErrInvalidSessionID = errors.New("sse: invalid session id")
)

const (
	// SubscriberBuffer is the per-stream queue depth. Sixteen frames is far
	// more than one checkout ever produces (a morph, a status, a close), so a
	// subscriber that is anywhere near this depth is not slow — it is wedged,
	// and the drop path below is the correct response rather than an
	// unfortunate one.
	SubscriberBuffer = 16

	// MaxSessionIDLen bounds an identifier that arrives in a URL path.
	MaxSessionIDLen = 128

	// MaxReasonLen bounds the operator-facing phrase carried on an event. The
	// vocabulary is fixed in code, so this only ever fires on a programming
	// mistake — but the value is rendered in a browser and stored in logs, and
	// an unbounded string in either place is a hazard.
	MaxReasonLen = 200

	defaultSequenceRetention    = 5 * time.Minute
	defaultMaxRetainedSequences = 8192
	defaultMaxDropsBeforeEvict  = 64
)

// HubConfig tunes a Hub. The zero value is valid and yields production
// defaults, so tests can override one field without restating the rest.
type HubConfig struct {
	// Clock is injected so retention windows are testable without sleeping.
	Clock domain.Clock

	// SequenceRetention is how long a session's sequence counter outlives its
	// last stream. See Hub.Publish for why counters outlive connections.
	SequenceRetention time.Duration

	// MaxRetainedSequences bounds how many disconnected sessions keep their
	// counter. Retention with no ceiling is a memory-exhaustion vector reachable
	// by anyone who can open and close streams.
	MaxRetainedSequences int

	// MaxDropsBeforeEvict is how many consecutive dropped frames a stream may
	// accumulate before the hub detaches it. Zero uses the default; a negative
	// value disables eviction.
	MaxDropsBeforeEvict int
}

// Hub is an in-memory, single-process implementation of domain.SessionHub.
//
// It is deliberately not backed by Redis. A checkout stream is pinned to one
// API process by its TCP connection, so cross-process fan-out would only add a
// network hop and a failure mode to a delivery that is already best-effort:
// the browser reconciles against the order state on load regardless.
type Hub struct {
	clock         domain.Clock
	seqRetention  time.Duration
	maxRetained   int
	maxDrops      int
	evictionOn    bool
	mu            sync.RWMutex
	sessions      map[string]*subscriberSet
	retired       []retiredRef
	activeSession int

	streams   atomic.Int64
	published atomic.Int64
	dropped   atomic.Int64
	evicted   atomic.Int64
}

// subscriberSet is every live stream for one session plus that session's
// sequence counter. Keeping the counter next to the set rather than in a
// parallel map means the two can never be cleaned up out of step.
type subscriberSet struct {
	subs    map[*subscriber]struct{}
	seq     int64
	emptyAt time.Time
	// epoch increments each time the set goes from empty to occupied, which is
	// what lets a stale retirement reference be recognised and discarded.
	epoch uint64
}

type subscriber struct {
	ch chan domain.SessionEvent
	// drops is guarded by Hub.mu, like every other mutation of set membership.
	drops int
}

type retiredRef struct {
	id    string
	epoch uint64
	at    time.Time
}

// Stats is a point-in-time read of hub health for the ops console. Dropped and
// Evicted are the two numbers that matter: a rising drop count means clients
// are not keeping up, which is invisible from the outside because the publisher
// never fails.
type Stats struct {
	Sessions  int   `json:"sessions"`
	Streams   int64 `json:"streams"`
	Published int64 `json:"published"`
	Dropped   int64 `json:"dropped"`
	Evicted   int64 `json:"evicted"`
	Retained  int   `json:"retained_sequences"`
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// NewHub builds a hub from cfg, filling unset fields with production defaults.
func NewHub(cfg HubConfig) *Hub {
	h := &Hub{
		clock:        cfg.Clock,
		seqRetention: cfg.SequenceRetention,
		maxRetained:  cfg.MaxRetainedSequences,
		maxDrops:     cfg.MaxDropsBeforeEvict,
		evictionOn:   cfg.MaxDropsBeforeEvict >= 0,
		sessions:     make(map[string]*subscriberSet),
	}
	if h.clock == nil {
		h.clock = systemClock{}
	}
	if h.seqRetention <= 0 {
		h.seqRetention = defaultSequenceRetention
	}
	if h.maxRetained <= 0 {
		h.maxRetained = defaultMaxRetainedSequences
	}
	if h.maxDrops <= 0 {
		h.maxDrops = defaultMaxDropsBeforeEvict
	}
	return h
}

// Subscribe implements domain.SessionHub. It places no ceiling on stream count;
// the HTTP edge uses SubscribeBounded instead, because admission control belongs
// where the connection is accepted rather than where events are fanned out.
func (h *Hub) Subscribe(ctx context.Context, sessionID string) (<-chan domain.SessionEvent, func(), error) {
	return h.SubscribeBounded(ctx, sessionID, 0)
}

// SubscribeBounded registers a stream only if the hub currently holds fewer than
// maxStreams of them; maxStreams <= 0 means unbounded.
//
// The ceiling is checked and the stream registered under one acquisition of the
// lock. Splitting that into a Count() call followed by a Subscribe() would let a
// burst of simultaneous connections all observe the same under-limit count and
// walk straight through the cap — precisely the traffic shape the cap exists to
// survive.
//
// The returned unsubscribe func is idempotent and closes the event channel, so a
// receiver ranging over it terminates. Callers must use the two-value receive
// form: a closed channel yields zero-valued events forever otherwise.
func (h *Hub) SubscribeBounded(ctx context.Context, sessionID string, maxStreams int) (<-chan domain.SessionEvent, func(), error) {
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("sse: subscribe: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if maxStreams > 0 && h.streams.Load() >= int64(maxStreams) {
		return nil, nil, ErrHubFull
	}
	h.pruneRetiredLocked()

	set := h.sessions[sessionID]
	if set == nil {
		set = &subscriberSet{subs: make(map[*subscriber]struct{}, 1)}
		h.sessions[sessionID] = set
	}
	if len(set.subs) == 0 {
		h.activeSession++
		// Invalidate any retirement reference still queued for this session.
		set.epoch++
	}

	s := &subscriber{ch: make(chan domain.SessionEvent, SubscriberBuffer)}
	set.subs[s] = struct{}{}
	h.streams.Add(1)

	var once sync.Once
	return s.ch, func() {
		once.Do(func() { h.remove(sessionID, s) })
	}, nil
}

// Publish implements domain.SessionHub.
//
// Every send is non-blocking. A subscriber whose buffer is full loses the frame
// and the loss is counted; the publisher is never delayed by it. That asymmetry
// is the whole point: Publish is called from a worker goroutine that owns an
// unacked queue message, so blocking here would stall a worker slot behind a
// browser tab the operating system has stopped reading from. One customer
// missing a live rail morph is a degraded experience; a wedged worker pool
// during an issuer outage is an incident.
//
// The sequence number is assigned here, under the lock, and always overwrites
// whatever the caller supplied. Per-session monotonicity is what lets a client
// detect that it missed a frame, and that guarantee is worthless if any caller
// can mint its own numbers.
//
// Publishing to a session with no live stream is not an error. The browser
// reconnecting between two frames is a normal race, and returning an error
// would push callers toward retry loops for something that is not a failure.
// Use Active to ask the liveness question directly.
func (h *Hub) Publish(ctx context.Context, sessionID string, ev domain.SessionEvent) error {
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("sse: publish: %w", err)
	}
	ev.Reason = sanitizeText(ev.Reason, MaxReasonLen)

	// The write lock covers sequence assignment and fan-out together. That is
	// affordable only because no send below can block: the critical section is a
	// bounded number of non-blocking channel operations with no I/O in it.
	h.mu.Lock()
	defer h.mu.Unlock()

	set, ok := h.sessions[sessionID]
	if !ok || len(set.subs) == 0 {
		return nil
	}

	set.seq++
	ev.Sequence = set.seq
	if ev.At == 0 {
		ev.At = h.clock.Now().Unix()
	}
	h.published.Add(1)

	for s := range set.subs {
		select {
		case s.ch <- ev:
			s.drops = 0
		default:
			s.drops++
			h.dropped.Add(1)
			if h.evictionOn && s.drops >= h.maxDrops {
				// A stream this far behind is not going to catch up: nothing on
				// the other end has read a byte in sixty-four frames. Detaching
				// it reclaims the buffer and lets the handler close the socket.
				if h.removeLocked(sessionID, s) {
					h.evicted.Add(1)
				}
			}
		}
	}
	return nil
}

// Active implements domain.SessionHub: it reports whether at least one stream is
// attached, which is the question the gatekeeper's SESSION_REQUIRED_FOR_MORPH
// invariant actually needs answered.
func (h *Hub) Active(sessionID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	set, ok := h.sessions[sessionID]
	return ok && len(set.subs) > 0
}

// Count implements domain.SessionHub and reports live sessions — those with at
// least one attached stream. Sessions retained only for their sequence counter
// are not live and are not counted.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeSession
}

// Streams reports attached streams, which is the resource admission control has
// to bound: each one costs a goroutine, a socket, and a buffer, whereas a
// session with no stream costs nothing.
func (h *Hub) Streams() int64 { return h.streams.Load() }

// Sequence returns the last sequence number issued for a session, or 0 if none
// is known. The SSE handler uses it to tell a reconnecting client how far the
// stream has advanced past its Last-Event-ID.
func (h *Hub) Sequence(sessionID string) int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if set, ok := h.sessions[sessionID]; ok {
		return set.seq
	}
	return 0
}

// Stats snapshots the hub counters for /api/v1/ops/metrics.
func (h *Hub) Stats() Stats {
	h.mu.RLock()
	sessions, retained := h.activeSession, len(h.retired)
	h.mu.RUnlock()
	return Stats{
		Sessions:  sessions,
		Streams:   h.streams.Load(),
		Published: h.published.Load(),
		Dropped:   h.dropped.Load(),
		Evicted:   h.evicted.Load(),
		Retained:  retained,
	}
}

// Shutdown detaches every stream and reports how many it closed. It sends no
// farewell event: the handler synthesises the closed frame when it observes its
// channel close, so the frame cannot be lost to a full buffer at exactly the
// moment it matters most.
func (h *Hub) Shutdown() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	closed := 0
	for id, set := range h.sessions {
		for s := range set.subs {
			if h.removeLocked(id, s) {
				closed++
			}
		}
	}
	return closed
}

func (h *Hub) remove(sessionID string, s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeLocked(sessionID, s)
}

// removeLocked detaches one stream. It is idempotent by construction: a
// subscriber that is no longer a member of its set is a no-op, so a caller that
// unsubscribes after the hub already evicted the stream cannot double-close the
// channel or double-count the stream gauge.
func (h *Hub) removeLocked(sessionID string, s *subscriber) bool {
	set, ok := h.sessions[sessionID]
	if !ok {
		return false
	}
	if _, member := set.subs[s]; !member {
		return false
	}
	delete(set.subs, s)
	// Safe to close: Publish reaches subscribers only through this set while
	// holding the same lock, so no send can be in flight or begin afterwards.
	close(s.ch)
	h.streams.Add(-1)

	if len(set.subs) == 0 {
		h.activeSession--
		set.emptyAt = h.clock.Now()
		h.retired = append(h.retired, retiredRef{id: sessionID, epoch: set.epoch, at: set.emptyAt})
		h.pruneRetiredLocked()
	}
	return true
}

// pruneRetiredLocked drops sequence counters whose retention window has closed.
//
// Counters outlive their last stream on purpose. EventSource reconnects
// automatically, and if the counter restarted at 1 on every reconnect the
// Last-Event-ID a browser sends back would be meaningless — a resumed stream
// would look like it had gone backwards, and gap detection, the one thing the
// sequence exists for, would silently stop working across the exact event that
// makes it necessary.
//
// The retirement list is FIFO and ordered by time, so the scan stops at the
// first entry still inside the window: pruning is amortised O(1) rather than a
// sweep over every session.
func (h *Hub) pruneRetiredLocked() {
	now := h.clock.Now()
	for len(h.retired) > 0 {
		ref := h.retired[0]
		set, ok := h.sessions[ref.id]
		switch {
		case !ok || set.epoch != ref.epoch || len(set.subs) > 0:
			// Stale reference: the session was resubscribed or already removed.
		case len(h.retired) > h.maxRetained || now.Sub(ref.at) >= h.seqRetention:
			delete(h.sessions, ref.id)
		default:
			return
		}
		h.retired = h.retired[1:]
	}
	h.retired = nil
}

// ValidateSessionID bounds an identifier that arrives from a URL path before it
// is used as a map key or written to a log. The character set is the one session
// identifiers are actually minted from; everything else is rejected rather than
// escaped, because an allowlist cannot be defeated by an encoding trick the way
// a denylist can.
func ValidateSessionID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty", ErrInvalidSessionID)
	}
	if len(id) > MaxSessionIDLen {
		return fmt.Errorf("%w: too long", ErrInvalidSessionID)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':':
		default:
			return fmt.Errorf("%w: illegal character", ErrInvalidSessionID)
		}
	}
	return nil
}

// sanitizeText strips control characters and bounds length. JSON encoding
// already escapes control bytes, so this is not what keeps the SSE framing
// intact; it is what keeps a stray byte out of an operator console and out of a
// log line, where escaping is nobody's guarantee.
func sanitizeText(s string, max int) string {
	if s == "" {
		return s
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
		if len(out) == max {
			break
		}
	}
	return string(out)
}

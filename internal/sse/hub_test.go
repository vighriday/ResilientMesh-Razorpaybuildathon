package sse

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// fakeClock makes retention and expiry windows testable without waiting for
// them. It is mutex-guarded because the handler reads it from its own goroutine.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func morphEvent() domain.SessionEvent {
	return domain.SessionEvent{
		Type:        "rail_morph",
		OrderID:     "order_JT4bY2",
		FromRail:    domain.RailCard,
		ToRail:      domain.RailUPIIntent,
		AmountPaisa: 249900,
		Currency:    "INR",
		Reason:      "issuer_degraded",
	}
}

func mustSubscribe(t *testing.T, h *Hub, sessionID string) (<-chan domain.SessionEvent, func()) {
	t.Helper()
	ch, unsub, err := h.Subscribe(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("Subscribe(%q): %v", sessionID, err)
	}
	return ch, unsub
}

func recvWithin(t *testing.T, ch <-chan domain.SessionEvent, d time.Duration) (domain.SessionEvent, bool) {
	t.Helper()
	select {
	case ev, open := <-ch:
		return ev, open
	case <-time.After(d):
		t.Fatalf("no event within %s", d)
		return domain.SessionEvent{}, false
	}
}

func TestHubDeliversEventsWithMonotonicPerSessionSequence(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ctx := context.Background()

	chA, unsubA := mustSubscribe(t, hub, "sess_a")
	defer unsubA()
	chB, unsubB := mustSubscribe(t, hub, "sess_b")
	defer unsubB()

	for i := 0; i < 3; i++ {
		if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	if err := hub.Publish(ctx, "sess_b", morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for want := int64(1); want <= 3; want++ {
		ev, open := recvWithin(t, chA, time.Second)
		if !open {
			t.Fatal("sess_a channel closed early")
		}
		if ev.Sequence != want {
			t.Fatalf("sess_a sequence = %d, want %d", ev.Sequence, want)
		}
		if ev.At == 0 {
			t.Fatal("event timestamp not stamped by hub")
		}
	}

	ev, open := recvWithin(t, chB, time.Second)
	if !open {
		t.Fatal("sess_b channel closed early")
	}
	if ev.Sequence != 1 {
		t.Fatalf("sess_b sequence = %d, want 1 (sequences are per session)", ev.Sequence)
	}
	if hub.Count() != 2 || hub.Streams() != 2 {
		t.Fatalf("Count=%d Streams=%d, want 2/2", hub.Count(), hub.Streams())
	}
}

func TestHubOverwritesCallerSuppliedSequence(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ch, unsub := mustSubscribe(t, hub, "sess_a")
	defer unsub()

	ev := morphEvent()
	ev.Sequence = 9999
	if err := hub.Publish(context.Background(), "sess_a", ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, open := recvWithin(t, ch, time.Second)
	if !open {
		t.Fatal("channel closed early")
	}
	if got.Sequence != 1 {
		t.Fatalf("sequence = %d, want 1: the hub must not honour a caller-supplied sequence", got.Sequence)
	}
}

func TestHubSlowConsumerNeverBlocksPublisherOrStarvesPeers(t *testing.T) {
	t.Parallel()
	// Eviction disabled so the drop accounting is exact for the whole run.
	hub := NewHub(HubConfig{Clock: newFakeClock(), MaxDropsBeforeEvict: -1})
	ctx := context.Background()

	fast, unsubFast := mustSubscribe(t, hub, "sess_a")
	defer unsubFast()
	slow, unsubSlow := mustSubscribe(t, hub, "sess_a")
	defer unsubSlow()
	_ = slow // deliberately never drained: this is the wedged browser tab

	const publishes = 100
	for i := 1; i <= publishes; i++ {
		done := make(chan error, 1)
		go func() { done <- hub.Publish(ctx, "sess_a", morphEvent()) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Publish %d: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Publish %d blocked behind a slow consumer", i)
		}

		ev, open := recvWithin(t, fast, 2*time.Second)
		if !open {
			t.Fatalf("fast subscriber detached at %d", i)
		}
		if ev.Sequence != int64(i) {
			t.Fatalf("fast subscriber sequence = %d, want %d", ev.Sequence, i)
		}
	}

	stats := hub.Stats()
	wantDropped := int64(publishes - SubscriberBuffer)
	if stats.Dropped != wantDropped {
		t.Fatalf("Dropped = %d, want %d (buffer %d absorbs the first frames)", stats.Dropped, wantDropped, SubscriberBuffer)
	}
	if stats.Published != publishes {
		t.Fatalf("Published = %d, want %d", stats.Published, publishes)
	}
	if stats.Streams != 2 {
		t.Fatalf("Streams = %d, want 2: a slow consumer is not detached while eviction is off", stats.Streams)
	}
}

func TestHubEvictsWedgedSubscriberAfterConsecutiveDrops(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock(), MaxDropsBeforeEvict: 4})
	ctx := context.Background()

	fast, unsubFast := mustSubscribe(t, hub, "sess_a")
	defer unsubFast()
	slow, unsubSlow := mustSubscribe(t, hub, "sess_a")
	defer unsubSlow()

	// 16 frames fill the buffer, the next 4 drop consecutively and evict.
	for i := 0; i < SubscriberBuffer+4; i++ {
		if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if _, open := recvWithin(t, fast, time.Second); !open {
			t.Fatal("fast subscriber must survive its peer's eviction")
		}
	}

	drained := 0
	for {
		_, open := recvWithin(t, slow, time.Second)
		if !open {
			break
		}
		drained++
		if drained > SubscriberBuffer {
			t.Fatal("evicted subscriber yielded more frames than its buffer held")
		}
	}
	if drained != SubscriberBuffer {
		t.Fatalf("buffered frames = %d, want %d", drained, SubscriberBuffer)
	}
	if stats := hub.Stats(); stats.Evicted != 1 || stats.Streams != 1 {
		t.Fatalf("Evicted=%d Streams=%d, want 1/1", stats.Evicted, stats.Streams)
	}
	// The unsubscribe handed to the evicted caller must still be safe to call.
	unsubSlow()
}

func TestHubSuccessfulSendResetsTheDropStreak(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock(), MaxDropsBeforeEvict: 4})
	ctx := context.Background()
	ch, unsub := mustSubscribe(t, hub, "sess_a")
	defer unsub()

	// Fill, drop three, drain one, and repeat: a client that is merely bursty
	// must never be mistaken for one that has stopped reading.
	for i := 0; i < SubscriberBuffer+3; i++ {
		if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	if _, open := recvWithin(t, ch, time.Second); !open {
		t.Fatal("subscriber detached too early")
	}
	for i := 0; i < 4; i++ {
		if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	if stats := hub.Stats(); stats.Evicted != 0 || stats.Streams != 1 {
		t.Fatalf("Evicted=%d Streams=%d, want 0/1", stats.Evicted, stats.Streams)
	}
}

func TestHubUnsubscribeIsIdempotentAndReleasesTheSession(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	hub := NewHub(HubConfig{Clock: clock, SequenceRetention: time.Minute})

	ch, unsub := mustSubscribe(t, hub, "sess_a")
	unsub()
	unsub()
	unsub()

	if _, open := recvWithin(t, ch, time.Second); open {
		t.Fatal("unsubscribe must close the event channel")
	}
	if hub.Active("sess_a") {
		t.Fatal("Active reported a session with no streams")
	}
	if hub.Count() != 0 || hub.Streams() != 0 {
		t.Fatalf("Count=%d Streams=%d, want 0/0", hub.Count(), hub.Streams())
	}

	// The map entry lingers only for the sequence counter, and only until the
	// retention window closes.
	clock.Advance(2 * time.Minute)
	hub.mu.Lock()
	hub.pruneRetiredLocked()
	remaining := len(hub.sessions)
	hub.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("sessions map holds %d entries after retention, want 0", remaining)
	}
}

func TestHubSequenceSurvivesReconnectThenExpires(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	hub := NewHub(HubConfig{Clock: clock, SequenceRetention: time.Minute})
	ctx := context.Background()

	_, unsub := mustSubscribe(t, hub, "sess_a")
	for i := 0; i < 3; i++ {
		if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	unsub()

	if got := hub.Sequence("sess_a"); got != 3 {
		t.Fatalf("Sequence after disconnect = %d, want 3", got)
	}

	ch, unsub2 := mustSubscribe(t, hub, "sess_a")
	if err := hub.Publish(ctx, "sess_a", morphEvent()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	ev, open := recvWithin(t, ch, time.Second)
	if !open {
		t.Fatal("channel closed early")
	}
	if ev.Sequence != 4 {
		t.Fatalf("sequence after reconnect = %d, want 4: Last-Event-ID resume needs continuity", ev.Sequence)
	}
	unsub2()

	clock.Advance(2 * time.Minute)
	_, unsub3 := mustSubscribe(t, hub, "sess_other")
	defer unsub3()
	if got := hub.Sequence("sess_a"); got != 0 {
		t.Fatalf("Sequence after retention = %d, want 0", got)
	}
}

func TestHubRetainedSequencesAreCapped(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock(), MaxRetainedSequences: 4, SequenceRetention: time.Hour})
	for i := 0; i < 200; i++ {
		id := "sess_" + strconv.Itoa(i)
		_, unsub := mustSubscribe(t, hub, id)
		unsub()
	}
	hub.mu.Lock()
	sessions, retired := len(hub.sessions), len(hub.retired)
	hub.mu.Unlock()
	if sessions > 8 || retired > 8 {
		t.Fatalf("sessions=%d retired=%d: retention must be bounded regardless of churn", sessions, retired)
	}
}

func TestHubSubscribeBoundedRefusesPastCeiling(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ctx := context.Background()

	_, unsub, err := hub.SubscribeBounded(ctx, "sess_a", 2)
	if err != nil {
		t.Fatalf("first subscribe: %v", err)
	}
	defer unsub()
	_, unsub2, err := hub.SubscribeBounded(ctx, "sess_b", 2)
	if err != nil {
		t.Fatalf("second subscribe: %v", err)
	}

	if _, _, err := hub.SubscribeBounded(ctx, "sess_c", 2); !errors.Is(err, ErrHubFull) {
		t.Fatalf("third subscribe error = %v, want ErrHubFull", err)
	}
	unsub2()
	if _, unsub3, err := hub.SubscribeBounded(ctx, "sess_c", 2); err != nil {
		t.Fatalf("subscribe after a slot freed: %v", err)
	} else {
		unsub3()
	}
}

func TestHubRejectsMalformedSessionIDs(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ctx := context.Background()

	long := make([]byte, MaxSessionIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	for _, id := range []string{"", "sess a", "sess/../etc", "sess\n", "sess<script>", string(long)} {
		if _, _, err := hub.Subscribe(ctx, id); !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("Subscribe(%q) error = %v, want ErrInvalidSessionID", id, err)
		}
		if err := hub.Publish(ctx, id, morphEvent()); !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("Publish(%q) error = %v, want ErrInvalidSessionID", id, err)
		}
	}
}

func TestHubPublishToSessionWithoutStreamsIsNotAnError(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	if err := hub.Publish(context.Background(), "sess_gone", morphEvent()); err != nil {
		t.Fatalf("Publish to an unwatched session = %v, want nil", err)
	}
	if hub.Stats().Published != 0 {
		t.Fatal("an undelivered publish must not be counted as published")
	}
}

func TestHubHonoursContextCancellation(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := hub.Subscribe(ctx, "sess_a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Subscribe error = %v, want context.Canceled", err)
	}
	if err := hub.Publish(ctx, "sess_a", morphEvent()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish error = %v, want context.Canceled", err)
	}
}

func TestHubSanitisesReasonText(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	ch, unsub := mustSubscribe(t, hub, "sess_a")
	defer unsub()

	ev := morphEvent()
	ev.Reason = "issuer\ndown\r\n\x00" + strings.Repeat("x", MaxReasonLen*2)
	if err := hub.Publish(context.Background(), "sess_a", ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, open := recvWithin(t, ch, time.Second)
	if !open {
		t.Fatal("channel closed early")
	}
	if len(got.Reason) != MaxReasonLen {
		t.Fatalf("reason length = %d, want %d", len(got.Reason), MaxReasonLen)
	}
	if strings.ContainsAny(got.Reason, "\n\r\x00") {
		t.Fatalf("control characters survived sanitisation: %q", got.Reason)
	}
}

func TestHubShutdownDetachesEveryStream(t *testing.T) {
	t.Parallel()
	hub := NewHub(HubConfig{Clock: newFakeClock()})
	chans := make([]<-chan domain.SessionEvent, 0, 6)
	for i := 0; i < 6; i++ {
		ch, unsub := mustSubscribe(t, hub, "sess_"+strconv.Itoa(i%3))
		defer unsub()
		chans = append(chans, ch)
	}
	if closed := hub.Shutdown(); closed != 6 {
		t.Fatalf("Shutdown closed %d streams, want 6", closed)
	}
	for i, ch := range chans {
		if _, open := recvWithin(t, ch, time.Second); open {
			t.Fatalf("stream %d still open after shutdown", i)
		}
	}
	if hub.Count() != 0 || hub.Streams() != 0 {
		t.Fatalf("Count=%d Streams=%d after shutdown, want 0/0", hub.Count(), hub.Streams())
	}
}

// TestHubConcurrentSubscribersUnderRace is the load shape the PLAN names: a
// thousand live checkouts fanned out from concurrent publishers, torn down
// concurrently. Every frame must be either received or accounted as dropped.
func TestHubConcurrentSubscribersUnderRace(t *testing.T) {
	t.Parallel()
	const (
		sessions             = 20
		subscribersPerStream = 50
		eventsPerSession     = 25
	)
	// Eviction off: with it on, a detached stream stops receiving attempts and
	// the received+dropped identity below would no longer be exact.
	hub := NewHub(HubConfig{Clock: newFakeClock(), MaxDropsBeforeEvict: -1})
	ctx := context.Background()

	var (
		received  int64
		receivedM sync.Mutex
		drains    sync.WaitGroup
		unsubs    []func()
	)
	for s := 0; s < sessions; s++ {
		id := "sess_" + strconv.Itoa(s)
		for c := 0; c < subscribersPerStream; c++ {
			ch, unsub := mustSubscribe(t, hub, id)
			unsubs = append(unsubs, unsub)
			drains.Add(1)
			go func(ch <-chan domain.SessionEvent) {
				defer drains.Done()
				n := int64(0)
				for range ch {
					n++
				}
				receivedM.Lock()
				received += n
				receivedM.Unlock()
			}(ch)
		}
	}
	if got := hub.Streams(); got != sessions*subscribersPerStream {
		t.Fatalf("Streams = %d, want %d", got, sessions*subscribersPerStream)
	}

	var publishers sync.WaitGroup
	for s := 0; s < sessions; s++ {
		id := "sess_" + strconv.Itoa(s)
		publishers.Add(1)
		go func() {
			defer publishers.Done()
			for i := 0; i < eventsPerSession; i++ {
				if err := hub.Publish(ctx, id, morphEvent()); err != nil {
					t.Errorf("Publish(%s): %v", id, err)
					return
				}
			}
		}()
	}
	publishers.Wait()

	for _, unsub := range unsubs {
		unsub()
	}
	drains.Wait()

	stats := hub.Stats()
	attempts := int64(sessions * eventsPerSession * subscribersPerStream)
	receivedM.Lock()
	total := received + stats.Dropped
	receivedM.Unlock()
	if total != attempts {
		t.Fatalf("received+dropped = %d, want %d delivery attempts", total, attempts)
	}
	if stats.Published != int64(sessions*eventsPerSession) {
		t.Fatalf("Published = %d, want %d", stats.Published, sessions*eventsPerSession)
	}
	if hub.Count() != 0 || hub.Streams() != 0 {
		t.Fatalf("Count=%d Streams=%d after teardown, want 0/0", hub.Count(), hub.Streams())
	}
}

func TestHubImplementsSessionHub(t *testing.T) {
	t.Parallel()
	var _ domain.SessionHub = NewHub(HubConfig{})
}

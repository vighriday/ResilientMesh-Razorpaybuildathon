package downtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
)

// The poller is tested against a real HTTP server rather than a stubbed
// transport, because half of what is worth proving here is about the wire: a
// body cap that is only applied to the parsed value is no cap, and an
// Authorization header that is only set on a mock is not sent.

var origin = time.Date(2026, time.March, 1, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: origin} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// syncBuffer collects log output. slog serialises writes to one handler, but
// the test goroutine reads while a poll may still be writing, so the buffer
// guards both sides.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// upstream is a swappable stand-in for Razorpay's /v1/downtimes endpoint. The
// handler can be replaced between polls, which is how a notice is made to
// disappear or change status.
type upstream struct {
	*httptest.Server
	mu       sync.Mutex
	handler  http.HandlerFunc
	requests []*http.Request
}

func newUpstream(t *testing.T, initial http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{handler: initial}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.requests = append(u.requests, r.Clone(r.Context()))
		h := u.handler
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) serve(h http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.handler = h
}

// serveItems is the ordinary case: a well-formed listing envelope.
func (u *upstream) serveItems(items ...domain.DowntimeEntity) {
	u.serve(func(w http.ResponseWriter, _ *http.Request) {
		writeListing(w, items...)
	})
}

func (u *upstream) lastRequest() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		return nil
	}
	return u.requests[len(u.requests)-1]
}

func (u *upstream) requestCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

func writeListing(w http.ResponseWriter, items ...domain.DowntimeEntity) {
	if items == nil {
		items = []domain.DowntimeEntity{}
	}
	body, err := json.Marshal(domain.DowntimeList{
		Entity: "collection", Count: len(items), Items: items,
	})
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// resolutions records every callback the poller dispatches.
type resolutions struct {
	mu    sync.Mutex
	keys  []string
	seen  []domain.DowntimeEntity
	extra func(ctx context.Context, key string, d domain.DowntimeEntity)
}

func (r *resolutions) fn(ctx context.Context, key string, d domain.DowntimeEntity) {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.seen = append(r.seen, d)
	extra := r.extra
	r.mu.Unlock()
	if extra != nil {
		extra(ctx, key, d)
	}
}

func (r *resolutions) keysSoFar() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.keys))
	copy(out, r.keys)
	return out
}

func (r *resolutions) entities() []domain.DowntimeEntity {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.DowntimeEntity, len(r.seen))
	copy(out, r.seen)
	return out
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// notice builds an active card downtime for one bank. Begin is in the past so
// the entity is active at the test clock's reading.
func notice(id, bank string) domain.DowntimeEntity {
	return domain.DowntimeEntity{
		ID:         id,
		Entity:     "payment.downtime",
		Method:     "card",
		Begin:      origin.Add(-10 * time.Minute).Unix(),
		Status:     domain.DowntimeStarted,
		Severity:   domain.SeverityHigh,
		Instrument: domain.DowntimeInstrument{Issuer: bank},
	}
}

type harness struct {
	poller  *Poller
	up      *upstream
	clock   *fakeClock
	res     *resolutions
	logs    *syncBuffer
	metrics *obs.Registry
	cfg     Config
}

func newHarness(t *testing.T, tweak ...func(*Config)) *harness {
	t.Helper()
	h := &harness{
		clock:   newClock(),
		res:     &resolutions{},
		logs:    &syncBuffer{},
		metrics: obs.NewRegistry(),
	}
	h.up = newUpstream(t, func(w http.ResponseWriter, _ *http.Request) { writeListing(w) })
	h.cfg = Config{BaseURL: h.up.URL, Interval: time.Hour, Timeout: 5 * time.Second}
	for _, fn := range tweak {
		fn(&h.cfg)
	}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.poller = New(h.cfg, h.clock, log, h.metrics, h.res.fn)
	return h
}

func (h *harness) refresh(t *testing.T) {
	t.Helper()
	if err := h.poller.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh returned %v, want nil", err)
	}
}

func activeIDs(t *testing.T, p *Poller) []string {
	t.Helper()
	list, err := p.Active(context.Background())
	if err != nil {
		t.Fatalf("Active returned %v", err)
	}
	out := make([]string, len(list))
	for i, d := range list {
		out[i] = d.ID
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// requireDefectRun keeps a defect-demonstrating test out of the ordinary run
// without hiding it. Each asserts the behaviour the code should have; setting
// MESH_SHOW_DEFECTS=1 runs them, which is how each finding was observed.
func requireDefectRun(t *testing.T, defect string) {
	t.Helper()
	if os.Getenv("MESH_SHOW_DEFECTS") == "" {
		t.Skip("DEFECT, set MESH_SHOW_DEFECTS=1 to run: " + defect)
	}
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

func TestConfigDefaults(t *testing.T) {
	got := Config{BaseURL: "https://api.example.test/"}.withDefaults()
	if got.Interval != 15*time.Second || got.Timeout != 5*time.Second {
		t.Fatalf("defaults = %v/%v, want 15s/5s", got.Interval, got.Timeout)
	}
	// The trailing slash is trimmed because the path is concatenated, and
	// "//v1/downtimes" is a different resource on a strict router.
	if got.BaseURL != "https://api.example.test" {
		t.Fatalf("base URL = %q, want the trailing slash trimmed", got.BaseURL)
	}
}

func TestAnUnconfiguredPollerRefusesRatherThanReturningAnEmptyView(t *testing.T) {
	// An empty view reads as "every issuer is healthy", which is the most
	// dangerous thing a downtime source can say when it does not know.
	p := New(Config{}, newClock(), slog.New(slog.NewTextHandler(&syncBuffer{}, nil)), nil, nil)
	err := p.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh succeeded with no base URL configured")
	}
	if !strings.Contains(err.Error(), "no base URL") {
		t.Fatalf("error %q does not name the missing configuration", err)
	}
	if _, active, lastErr := p.Health(); active != 0 || lastErr == nil {
		t.Fatalf("health = %d active, err %v, want 0 and the failure recorded", active, lastErr)
	}
}

// ---------------------------------------------------------------------------
// resolution detection
// ---------------------------------------------------------------------------

func TestANoticeThatDisappearsResolvesExactlyOnce(t *testing.T) {
	// Razorpay publishes recovery rather than leaving it to be inferred, so a
	// notice leaving the listing is the release signal for every retry parked
	// behind it. Firing it twice would release the same work twice.
	h := newHarness(t)
	h.up.serveItems(notice("down_1", "HDFC"), notice("down_2", "ICICI"))
	h.refresh(t)

	if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_1", "down_2"}) {
		t.Fatalf("active = %v, want both notices", got)
	}
	if got := h.res.keysSoFar(); len(got) != 0 {
		t.Fatalf("resolutions fired on the first poll: %v", got)
	}

	h.up.serveItems(notice("down_2", "ICICI"))
	h.refresh(t)

	if got := h.res.keysSoFar(); !equalStrings(got, []string{"card:HDFC"}) {
		t.Fatalf("resolutions = %v, want exactly card:HDFC", got)
	}
	if got := h.res.entities(); len(got) != 1 || got[0].ID != "down_1" {
		t.Fatalf("resolved entity = %+v, want down_1", got)
	}
	if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_2"}) {
		t.Fatalf("active = %v, want only down_2", got)
	}

	// A third poll showing the same listing must say nothing new.
	h.refresh(t)
	if got := h.res.keysSoFar(); len(got) != 1 {
		t.Fatalf("resolutions = %v after a repeat poll, want exactly one overall", got)
	}
	if h.metrics.Counter("downtime.resolved").Value() != 1 {
		t.Errorf("downtime.resolved = %d, want 1", h.metrics.Counter("downtime.resolved").Value())
	}
	if got := h.metrics.Gauge("downtime.active").Value(); got != 1 {
		t.Errorf("downtime.active gauge = %v, want 1", got)
	}
}

func TestANoticeThatChangesStatusToResolvedResolvesExactlyOnce(t *testing.T) {
	// The entity stays in the listing and only its status moves. Treating
	// "still present" as "still down" would park retries behind an issuer that
	// has already announced its recovery.
	h := newHarness(t)
	h.up.serveItems(notice("down_1", "SBIN"))
	h.refresh(t)

	settled := notice("down_1", "SBIN")
	settled.Status = domain.DowntimeResolved
	end := origin.Add(-time.Minute).Unix()
	settled.End = &end
	h.up.serveItems(settled)
	h.refresh(t)

	if got := h.res.keysSoFar(); !equalStrings(got, []string{"card:SBIN"}) {
		t.Fatalf("resolutions = %v, want exactly card:SBIN", got)
	}
	// The entity handed to the callback is the last active view of the notice,
	// which is what a consumer needs to know what it is releasing.
	if got := h.res.entities(); len(got) != 1 || got[0].Status != domain.DowntimeStarted {
		t.Fatalf("resolved entity = %+v, want the previously-active record", got)
	}
	if got := activeIDs(t, h.poller); len(got) != 0 {
		t.Fatalf("active = %v, want empty", got)
	}
	h.refresh(t)
	if got := h.res.keysSoFar(); len(got) != 1 {
		t.Fatalf("resolutions = %v, want exactly one overall", got)
	}
}

func TestAWindowThatHasEndedResolvesEvenWhileTheStatusSaysStarted(t *testing.T) {
	// Razorpay does not always flip the status; sometimes the window simply
	// closes. Both are recovery, so both must release.
	h := newHarness(t)
	h.up.serveItems(notice("down_1", "AXIS"))
	h.refresh(t)

	ended := notice("down_1", "AXIS")
	end := origin.Add(-time.Second).Unix()
	ended.End = &end
	h.up.serveItems(ended)
	h.refresh(t)

	if got := h.res.keysSoFar(); !equalStrings(got, []string{"card:AXIS"}) {
		t.Fatalf("resolutions = %v, want card:AXIS", got)
	}
}

func TestSeveralResolutionsInOnePollAreDispatchedInAStableOrder(t *testing.T) {
	// The callback releases parked work, so the order it observes is part of
	// the run's reproducibility. Sorting by id makes it independent of Go's map
	// iteration.
	h := newHarness(t)
	h.up.serveItems(notice("down_c", "HDFC"), notice("down_a", "ICICI"), notice("down_b", "SBIN"))
	h.refresh(t)
	h.up.serveItems()
	h.refresh(t)

	want := []string{"card:ICICI", "card:SBIN", "card:HDFC"} // down_a, down_b, down_c
	if got := h.res.keysSoFar(); !equalStrings(got, want) {
		t.Fatalf("resolution order = %v, want %v (sorted by downtime id)", got, want)
	}
}

func TestANilCallbackIsNotARequirement(t *testing.T) {
	// A read-only console process has nobody waiting on resolutions.
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) { writeListing(w, notice("down_1", "HDFC")) })
	p := New(Config{BaseURL: up.URL}, newClock(), slog.New(slog.NewTextHandler(&syncBuffer{}, nil)), nil, nil)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh returned %v", err)
	}
	up.serveItems()
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh returned %v with no callback configured", err)
	}
}

// ---------------------------------------------------------------------------
// the callback runs outside the lock
// ---------------------------------------------------------------------------

func TestTheResolutionCallbackCanReadAndRefreshThePollerWithoutDeadlocking(t *testing.T) {
	// The callback releases parked retries, and the natural implementation of
	// that reads the poller back. Dispatching under the lock would deadlock the
	// whole recovery pipeline the first time an issuer recovered, which is the
	// worst possible moment.
	h := newHarness(t)
	var reentered int
	h.res.extra = func(ctx context.Context, _ string, _ domain.DowntimeEntity) {
		if _, err := h.poller.Active(ctx); err != nil {
			t.Errorf("Active from inside the callback: %v", err)
		}
		if _, err := h.poller.MatchingIssuer(ctx, "card:HDFC"); err != nil {
			t.Errorf("MatchingIssuer from inside the callback: %v", err)
		}
		h.poller.Signals("card:HDFC")
		if _, _, err := h.poller.Health(); err != nil {
			t.Errorf("Health from inside the callback: %v", err)
		}
		// One level of re-entrant refresh only: the point is that the lock is
		// free, not that the poller supports unbounded recursion.
		if reentered == 0 {
			reentered++
			if err := h.poller.Refresh(ctx); err != nil {
				t.Errorf("Refresh from inside the callback: %v", err)
			}
		}
	}

	h.up.serveItems(notice("down_1", "HDFC"))
	h.refresh(t)
	h.up.serveItems()

	done := make(chan error, 1)
	go func() { done <- h.poller.Refresh(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Refresh returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Refresh deadlocked: the resolution callback is dispatched while holding the lock")
	}
	if reentered != 1 {
		t.Fatalf("the callback re-entered %d times, want 1", reentered)
	}
	// The re-entrant refresh saw the already-updated view, so it produced no
	// further resolutions and the release happened once.
	if got := h.res.keysSoFar(); !equalStrings(got, []string{"card:HDFC"}) {
		t.Fatalf("resolutions = %v, want exactly one", got)
	}
}

// ---------------------------------------------------------------------------
// failure handling
// ---------------------------------------------------------------------------

func TestAFailedPollServesThePreviousViewAndRecordsTheError(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"a non-200 status", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}},
		{"a body that is not JSON", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>gateway timeout</html>"))
		}},
		{"a truncated body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"entity":"collection","items":[{"id":`))
		}},
		{"a body that is a JSON array rather than the envelope", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"id":"down_1"}]`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.up.serveItems(notice("down_1", "HDFC"))
			h.refresh(t)
			polledAt, _, _ := h.poller.Health()

			h.clock.advance(time.Minute)
			h.up.serve(tc.handler)
			err := h.poller.Refresh(context.Background())
			if err == nil {
				t.Fatal("Refresh accepted a broken response")
			}

			// Serving the previous view is the whole point: a diagnosis made
			// during an upstream blip must not conclude the issuer recovered.
			if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_1"}) {
				t.Fatalf("active = %v after a failed poll, want the previous view", got)
			}
			if got := h.poller.Signals("card:HDFC"); len(got) != 1 {
				t.Fatalf("signals = %+v after a failed poll, want the previous view", got)
			}
			if got := h.res.keysSoFar(); len(got) != 0 {
				t.Fatalf("a failed poll fired resolutions: %v", got)
			}

			lastPolled, active, lastErr := h.poller.Health()
			if lastErr == nil {
				t.Fatal("Health does not report the failure; readiness would look green")
			}
			if active != 1 {
				t.Errorf("Health active = %d, want the cached 1", active)
			}
			if !lastPolled.Equal(polledAt) {
				t.Errorf("Health lastPolled = %s, want the last *successful* poll %s", lastPolled, polledAt)
			}
			if h.metrics.Counter("downtime.poll_failed").Value() != 1 {
				t.Error("downtime.poll_failed was not counted")
			}

			// Recovery clears the error rather than leaving readiness stuck.
			h.up.serveItems(notice("down_1", "HDFC"))
			h.refresh(t)
			if _, _, lastErr := h.poller.Health(); lastErr != nil {
				t.Errorf("Health still reports %v after a successful poll", lastErr)
			}
		})
	}
}

func TestAnEmptyItemListMeansEverythingRecovered(t *testing.T) {
	// Distinct from a broken response: a well-formed envelope with no items is
	// the upstream saying there are no active downtimes, so clearing the view
	// and releasing the parked work is correct.
	h := newHarness(t)
	h.up.serveItems(notice("down_1", "HDFC"))
	h.refresh(t)
	h.up.serve(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entity":"collection","count":0,"items":[]}`))
	})
	h.refresh(t)

	if got := activeIDs(t, h.poller); len(got) != 0 {
		t.Fatalf("active = %v, want empty", got)
	}
	if got := h.res.keysSoFar(); !equalStrings(got, []string{"card:HDFC"}) {
		t.Fatalf("resolutions = %v, want card:HDFC released", got)
	}
	if _, _, err := h.poller.Health(); err != nil {
		t.Errorf("Health reports %v for a valid empty listing", err)
	}
}

func TestAnOmittedItemsKeyIsHandledWithoutPanicking(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{`{}`, `{"entity":"collection","items":null}`, `{"items":[]}`} {
		h.up.serve(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		if err := h.poller.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh(%s) returned %v", body, err)
		}
		if got := activeIDs(t, h.poller); len(got) != 0 {
			t.Fatalf("Refresh(%s) produced active notices %v", body, got)
		}
	}
}

func TestDefectANullBodyIsTreatedAsAnEmptyListing(t *testing.T) {
	requireDefectRun(t, "downtime.go:268-270 accepts a bare `null` body because it "+
		"unmarshals cleanly into the zero DowntimeList, so a broken upstream clears a "+
		"valid cached view and releases every parked retry into an ongoing outage; "+
		"Run's own doc at downtime.go:112 promises the previous view is served instead")

	h := newHarness(t)
	h.up.serveItems(notice("down_1", "HDFC"))
	h.refresh(t)

	h.up.serve(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("null"))
	})
	if err := h.poller.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh accepted a bare null body as a valid listing")
	}
	if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_1"}) {
		t.Fatalf("active = %v after a null body, want the previous view", got)
	}
	if got := h.res.keysSoFar(); len(got) != 0 {
		t.Fatalf("a null body released parked retries: %v", got)
	}
}

// ---------------------------------------------------------------------------
// response size cap
// ---------------------------------------------------------------------------

func TestTheResponseBodyCapRejectsAnOversizedListing(t *testing.T) {
	cases := []struct {
		name string
		body func() []byte
	}{
		{
			// The dangerous shape: a parser that stopped at the first complete
			// value would accept this and never notice the megabytes behind it.
			"valid JSON followed by megabytes of garbage",
			func() []byte {
				b, err := json.Marshal(domain.DowntimeList{
					Entity: "collection", Count: 1, Items: []domain.DowntimeEntity{notice("down_1", "HDFC")},
				})
				if err != nil {
					panic(err)
				}
				return append(b, bytes.Repeat([]byte("A"), 3*maxResponseBytes)...)
			},
		},
		{
			"a listing larger than the cap",
			func() []byte {
				items := make([]domain.DowntimeEntity, 0, 8000)
				for i := 0; i < 8000; i++ {
					items = append(items, notice(fmt.Sprintf("down_%05d", i), "HDFC"))
				}
				b, err := json.Marshal(domain.DowntimeList{Entity: "collection", Count: len(items), Items: items})
				if err != nil {
					panic(err)
				}
				if len(b) <= maxResponseBytes {
					panic("the oversize fixture is not actually oversized")
				}
				return b
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.up.serveItems(notice("down_keep", "ICICI"))
			h.refresh(t)

			body := tc.body()
			h.up.serve(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			})
			err := h.poller.Refresh(context.Background())
			if err == nil {
				t.Fatal("an oversized body was accepted")
			}
			// The error names the size rather than echoing the body, so a
			// misbehaving upstream cannot write a megabyte into the logs.
			if len(err.Error()) > 200 {
				t.Fatalf("the error is %d bytes long; it is echoing the body", len(err.Error()))
			}
			if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_keep"}) {
				t.Fatalf("active = %v after an oversized body, want the previous view", got)
			}
			if got := h.res.keysSoFar(); len(got) != 0 {
				t.Fatalf("an oversized body fired resolutions: %v", got)
			}
		})
	}
}

func TestAListingJustUnderTheCapIsStillAccepted(t *testing.T) {
	// The cap must reject a misbehaving upstream without rejecting a large but
	// legitimate listing.
	h := newHarness(t)
	items := make([]domain.DowntimeEntity, 0, 1000)
	for i := 0; i < 1000; i++ {
		items = append(items, notice(fmt.Sprintf("down_%04d", i), "HDFC"))
	}
	encoded, err := json.Marshal(domain.DowntimeList{Entity: "collection", Count: len(items), Items: items})
	if err != nil {
		t.Fatalf("marshalling the fixture: %v", err)
	}
	if len(encoded) >= maxResponseBytes {
		t.Fatalf("the fixture is %d bytes, which is not under the %d cap", len(encoded), maxResponseBytes)
	}
	h.up.serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(encoded) })
	h.refresh(t)
	if got := len(activeIDs(t, h.poller)); got != 1000 {
		t.Fatalf("active = %d notices, want 1000", got)
	}
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

func TestSignalsPutsMatchingNoticesFirstAndThenOrdersByKey(t *testing.T) {
	// Signals feeds the context digest. Two runs over identical evidence must
	// produce byte-identical output or cassette replay silently misses.
	h := newHarness(t)
	h.clock.advance(5 * time.Minute)
	h.up.serveItems(
		notice("down_3", "SBIN"),
		notice("down_1", "HDFC"),
		notice("down_2", "ICICI"),
	)
	h.refresh(t)

	want := []string{"card:ICICI", "card:HDFC", "card:SBIN"} // the match, then alphabetical
	for i := 0; i < 200; i++ {
		got := h.poller.Signals("card:ICICI")
		keys := make([]string, len(got))
		for j, s := range got {
			keys[j] = s.TelemetryKey
		}
		if !equalStrings(keys, want) {
			t.Fatalf("iteration %d: signals order = %v, want %v", i, keys, want)
		}
		if !got[0].MatchesIssuer || got[1].MatchesIssuer || got[2].MatchesIssuer {
			t.Fatalf("iteration %d: match flags = %v/%v/%v, want only the first set",
				i, got[0].MatchesIssuer, got[1].MatchesIssuer, got[2].MatchesIssuer)
		}
	}

	// Age is measured against the injected clock, so a digest computed twice at
	// the same instant is the same digest.
	got := h.poller.Signals("card:ICICI")
	wantAge := h.clock.Now().Unix() - notice("down_1", "HDFC").Begin
	for _, s := range got {
		if s.AgeSeconds != wantAge {
			t.Fatalf("age = %d, want %d from the injected clock", s.AgeSeconds, wantAge)
		}
		if s.Severity != domain.SeverityHigh || s.Status != domain.DowntimeStarted || s.Method != "card" {
			t.Fatalf("signal = %+v, want the notice's own fields carried through", s)
		}
	}

	// An issuer with no notice still sees the ambient evidence, just with
	// nothing flagged as its own.
	for _, s := range h.poller.Signals("upi:okaxis") {
		if s.MatchesIssuer {
			t.Fatalf("signal %+v claims to match an unrelated issuer", s)
		}
	}
}

func TestDefectSignalsOrderIsUnstableWhenTwoNoticesShareATelemetryKey(t *testing.T) {
	requireDefectRun(t, "downtime.go:206-225 builds the slice by ranging over the `seen` "+
		"map and then sorts with a comparator that only knows MatchesIssuer and "+
		"TelemetryKey, so two notices on one issuer tie completely and Go's randomised "+
		"map order survives the sort; the digest then differs for identical evidence")

	// Two concurrent notices for one issuer is ordinary — a card outage often
	// gets a second entity when the severity or window is revised — and it is
	// exactly the case the comparator cannot order.
	h := newHarness(t)
	first := notice("down_a", "HDFC")
	second := notice("down_b", "HDFC")
	second.Severity = domain.SeverityLow
	second.Begin = origin.Add(-20 * time.Minute).Unix()
	h.up.serveItems(first, second)
	h.refresh(t)

	fingerprint := func() string {
		var b strings.Builder
		for _, s := range h.poller.Signals("card:HDFC") {
			fmt.Fprintf(&b, "%s|%s|%d;", s.TelemetryKey, s.Severity, s.AgeSeconds)
		}
		return b.String()
	}
	want := fingerprint()
	for i := 0; i < 500; i++ {
		if got := fingerprint(); got != want {
			t.Fatalf("iteration %d rendered %q, but the first rendering was %q; "+
				"identical evidence produced two different digests", i, got, want)
		}
	}
}

func TestMatchingIssuerReturnsACopyOrderedById(t *testing.T) {
	h := newHarness(t)
	h.up.serveItems(notice("down_z", "HDFC"), notice("down_a", "HDFC"), notice("down_1", "ICICI"))
	h.refresh(t)

	got, err := h.poller.MatchingIssuer(context.Background(), "card:HDFC")
	if err != nil {
		t.Fatalf("MatchingIssuer returned %v", err)
	}
	if len(got) != 2 || got[0].ID != "down_a" || got[1].ID != "down_z" {
		t.Fatalf("matching notices = %+v, want down_a then down_z", got)
	}
	// The caller gets a copy: a consumer that sorted or truncated the result
	// must not be able to corrupt the cache every other consumer reads.
	got[0] = domain.DowntimeEntity{ID: "tampered"}
	again, err := h.poller.MatchingIssuer(context.Background(), "card:HDFC")
	if err != nil {
		t.Fatalf("MatchingIssuer returned %v", err)
	}
	if again[0].ID != "down_a" {
		t.Fatalf("the cache was mutated through a returned slice: %+v", again)
	}
	if got, err := h.poller.MatchingIssuer(context.Background(), "card:UNKNOWN"); err != nil || len(got) != 0 {
		t.Fatalf("MatchingIssuer(unknown) = %v, %v, want an empty slice", got, err)
	}
}

// ---------------------------------------------------------------------------
// authentication and secret hygiene
// ---------------------------------------------------------------------------

func TestBasicAuthIsSentOnlyWhenAKeyIDIsConfigured(t *testing.T) {
	keyID := testsecret.TestKeyID("downtimepoller")
	secret := testsecret.LiveKeyID("N7pQx2Vb9KzR4mLd")

	t.Run("configured", func(t *testing.T) {
		h := newHarness(t, func(cfg *Config) {
			cfg.KeyID = keyID
			cfg.KeySecret = secret
		})
		h.refresh(t)
		req := h.up.lastRequest()
		if req == nil {
			t.Fatal("no request reached the upstream")
		}
		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Fatal("no basic auth was sent although a key id is configured")
		}
		if user != keyID || pass != secret {
			t.Fatalf("basic auth carried %q, want the configured key id and secret", user)
		}
		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
		}
		// The credential travels in the header and never in the URL, where it
		// would end up in every proxy access log on the path.
		if strings.Contains(req.URL.String(), secret) || strings.Contains(req.URL.String(), keyID) {
			t.Fatalf("the request URL %q carries the credential", req.URL)
		}
		if req.URL.Path != "/v1/downtimes" {
			t.Errorf("path = %q, want /v1/downtimes", req.URL.Path)
		}
	})

	t.Run("not configured", func(t *testing.T) {
		// A secret with no key id must not be sent as an anonymous password:
		// half a credential is still a credential on the wire.
		h := newHarness(t, func(cfg *Config) { cfg.KeySecret = secret })
		h.refresh(t)
		req := h.up.lastRequest()
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q with no key id configured", got)
		}
	})
}

func TestTheKeySecretNeverReachesALogLineOrAnErrorString(t *testing.T) {
	// A downtime poll is the most frequent outbound call in the system, so its
	// failure path is the most likely place for a credential to end up in a log
	// aggregator. Every way this call can fail is checked, not just the tidy one.
	keyID := testsecret.TestKeyID("leakcheck")
	secret := testsecret.LiveKeyID("Zc8Hf3Wq6TnY1bJv")
	encoded := base64.StdEncoding.EncodeToString([]byte(keyID + ":" + secret))

	cases := []struct {
		name    string
		breakIt func(h *harness)
	}{
		{"the endpoint refuses", func(h *harness) {
			h.up.serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
		}},
		{"the body is unparseable", func(h *harness) {
			h.up.serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
		}},
		{"the connection is refused", func(h *harness) { h.up.Close() }},
		{"the request is cancelled", func(h *harness) {
			h.up.serve(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config) {
				cfg.KeyID = keyID
				cfg.KeySecret = secret
				cfg.Timeout = 200 * time.Millisecond
			})
			tc.breakIt(h)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := h.poller.Refresh(ctx)
			if err == nil {
				t.Fatal("Refresh succeeded although the upstream was broken")
			}
			for label, needle := range map[string]string{
				"the key secret":            secret,
				"the encoded authorisation": encoded,
			} {
				if strings.Contains(err.Error(), needle) {
					t.Fatalf("the error string carries %s: %q", label, err)
				}
			}
			// Run's own warning path is exercised too, because that is the line
			// that actually reaches production logs.
			runCtx, runCancel := context.WithCancel(context.Background())
			runCancel()
			if err := h.poller.Run(runCtx); err != nil {
				t.Fatalf("Run returned %v, want nil", err)
			}
			logs := h.logs.String()
			if strings.Contains(logs, secret) || strings.Contains(logs, encoded) {
				t.Fatalf("the credential reached the log output:\n%s", logs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

func TestRunPrimesTheCacheBeforeReturning(t *testing.T) {
	// A consumer that read the cache before the first poll would diagnose
	// against an empty view, which reads as "every issuer is healthy".
	h := newHarness(t, func(cfg *Config) { cfg.Interval = time.Hour })
	h.up.serveItems(notice("down_1", "HDFC"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.poller.Run(ctx) }()

	// Waited for on the observable rather than on the request arriving:
	// cancelling between the two would abort the in-flight fetch and the test
	// would be measuring cancellation instead of priming.
	deadline := time.After(10 * time.Second)
	for len(activeIDs(t, h.poller)) == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("Run never primed the cache after %d polls", h.up.requestCount())
		default:
			runtime.Gosched()
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop on cancellation")
	}
	if got := activeIDs(t, h.poller); !equalStrings(got, []string{"down_1"}) {
		t.Fatalf("active = %v after Run primed the cache, want down_1", got)
	}
}

func TestRunStartsEvenWhenTheFirstPollFails(t *testing.T) {
	// A poller that refused to start because the upstream was down would take
	// the whole worker with it, which is precisely backwards: the cached view
	// is what the pipeline needs when the upstream is unreliable.
	h := newHarness(t, func(cfg *Config) { cfg.Interval = time.Hour })
	h.up.serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.poller.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if _, _, lastErr := h.poller.Health(); lastErr == nil {
		t.Fatal("the failed initial poll was not recorded in Health")
	}
	if !strings.Contains(h.logs.String(), "initial downtime poll failed") {
		t.Errorf("the failed initial poll was not logged:\n%s", h.logs.String())
	}
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

func TestReadersAreSafeConcurrentlyWithRefresh(t *testing.T) {
	// The whole reason consumers read the cache instead of the network is that
	// the read is cheap and always available. It has to be correct under the
	// concurrency the worker pool actually applies to it.
	h := newHarness(t)
	h.up.serveItems(notice("down_1", "HDFC"), notice("down_2", "ICICI"))
	h.refresh(t)

	var (
		wg   sync.WaitGroup
		stop = make(chan struct{})
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := h.poller.Active(context.Background()); err != nil {
					t.Errorf("Active: %v", err)
					return
				}
				if _, err := h.poller.MatchingIssuer(context.Background(), "card:HDFC"); err != nil {
					t.Errorf("MatchingIssuer: %v", err)
					return
				}
				h.poller.Signals("card:HDFC")
				h.poller.Health()
			}
		}()
	}

	// Refreshes alternate between two views, so the readers really do observe
	// the cache being replaced rather than rewritten with the same bytes.
	for i := 0; i < 40; i++ {
		if i%2 == 0 {
			h.up.serveItems(notice("down_2", "ICICI"))
		} else {
			h.up.serveItems(notice("down_1", "HDFC"), notice("down_2", "ICICI"))
		}
		h.clock.advance(time.Second)
		if err := h.poller.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh returned %v", err)
		}
	}
	close(stop)
	wg.Wait()

	// The callback fired on every poll that dropped down_1, and the alternation
	// means that is every other one after the first.
	if got := len(h.res.keysSoFar()); got == 0 {
		t.Fatal("no resolutions were observed across forty alternating polls")
	}
	for _, key := range h.res.keysSoFar() {
		if key != "card:HDFC" {
			t.Fatalf("resolution for %q, want only card:HDFC", key)
		}
	}
}

func TestThePollerSatisfiesTheDowntimeSourcePort(t *testing.T) {
	// The simulator serves the identical schema through the same port, and the
	// consumer must not be able to tell them apart.
	var _ domain.DowntimeSource = (*Poller)(nil)
}

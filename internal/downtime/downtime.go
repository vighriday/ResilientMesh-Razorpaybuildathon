// Package downtime tracks Razorpay's published issuer downtime notices.
//
// This is the signal that distinguishes this system from statistical retry
// timing. Incumbent recovery products estimate when an issuer will come back,
// because their processors do not tell them. Razorpay publishes it: a downtime
// entity moves to "resolved" when the issuer recovers. Waiting for a
// statistical estimate of an event that is being broadcast is strictly worse
// than subscribing to the broadcast, so retries parked behind an outage are
// released by the resolution notice and the computed backoff becomes an upper
// bound rather than the mechanism.
package downtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
)

// maxResponseBytes bounds the downtime listing. The real endpoint returns a
// handful of entities; anything larger is a misbehaving upstream, not data.
const maxResponseBytes = 1 << 20

// Config describes where and how often to poll.
type Config struct {
	BaseURL   string
	KeyID     string
	KeySecret string
	// Interval is how often the listing is refreshed. Downtime notices change
	// on the order of minutes, so polling faster buys nothing and costs quota.
	Interval time.Duration
	Timeout  time.Duration
}

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = 15 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	return c
}

// ResolutionFunc is called once per issuer key when an active downtime for that
// key becomes resolved.
type ResolutionFunc func(ctx context.Context, issuerKey string, entity domain.DowntimeEntity)

// Poller keeps a cached view of active downtimes and detects resolutions.
//
// Consumers read from the cache rather than the network. A diagnosis that
// blocked on an upstream HTTP call would make the recovery path slower exactly
// when the upstream is degraded, which is when recovery matters most.
type Poller struct {
	cfg     Config
	client  *http.Client
	clock   domain.Clock
	log     *slog.Logger
	metrics *obs.Registry

	mu sync.RWMutex
	// byKey holds the currently active notices, keyed the same way payments
	// are, so a notice joins against live failure counters with no lookup table.
	byKey map[string][]domain.DowntimeEntity
	// seen remembers ids observed as active, so a disappearance or a status
	// change can be recognised as a resolution rather than merely absent.
	seen       map[string]domain.DowntimeEntity
	lastPolled time.Time
	lastErr    error
	onResolved ResolutionFunc
}

// New builds a poller. onResolved may be nil when no one is waiting on
// resolutions, such as in a read-only console process.
func New(cfg Config, clock domain.Clock, log *slog.Logger, m *obs.Registry, onResolved ResolutionFunc) *Poller {
	cfg = cfg.withDefaults()
	return &Poller{
		cfg: cfg, clock: clock, log: log, metrics: m,
		byKey:      map[string][]domain.DowntimeEntity{},
		seen:       map[string]domain.DowntimeEntity{},
		onResolved: onResolved,
		client:     &http.Client{Timeout: cfg.Timeout},
	}
}

// Run polls until the context is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	// Prime the cache before the first consumer reads it, so an early
	// diagnosis is not made against an empty view that looks like "all healthy".
	if err := p.Refresh(ctx); err != nil {
		p.log.Warn("initial downtime poll failed; starting with an empty view", "error", err)
	}

	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.Refresh(ctx); err != nil {
				p.log.Warn("downtime poll failed; serving the previous view", "error", err)
			}
		}
	}
}

// Refresh fetches the listing and reconciles it against the cached view.
func (p *Poller) Refresh(ctx context.Context) error {
	list, err := p.fetch(ctx)
	if err != nil {
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		p.count("downtime.poll_failed")
		return err
	}

	now := p.clock.Now()
	active := map[string][]domain.DowntimeEntity{}
	present := map[string]domain.DowntimeEntity{}

	for _, d := range list.Items {
		if !d.Active(now) {
			continue
		}
		key := d.TelemetryKey()
		active[key] = append(active[key], d)
		present[d.ID] = d
	}
	// Deterministic ordering: the cache feeds the context digest, and an
	// unstable order would change the digest for identical evidence.
	for k := range active {
		sort.Slice(active[k], func(i, j int) bool { return active[k][i].ID < active[k][j].ID })
	}

	p.mu.Lock()
	resolved := make([]domain.DowntimeEntity, 0, 4)
	for id, prev := range p.seen {
		if _, still := present[id]; !still {
			resolved = append(resolved, prev)
		}
	}
	p.byKey = active
	p.seen = present
	p.lastPolled = now
	p.lastErr = nil
	p.mu.Unlock()

	p.gauge("downtime.active", float64(len(present)))

	// Resolutions are dispatched outside the lock: the callback releases parked
	// retries and must not be able to deadlock the poller by touching it.
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].ID < resolved[j].ID })
	for _, d := range resolved {
		key := d.TelemetryKey()
		p.log.Info("issuer downtime resolved; releasing parked retries",
			"downtime_id", d.ID, "issuer_key", key, "method", d.Method)
		p.count("downtime.resolved")
		if p.onResolved != nil {
			p.onResolved(ctx, key, d)
		}
	}
	return nil
}

// Active returns every currently active notice.
func (p *Poller) Active(_ context.Context) ([]domain.DowntimeEntity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]domain.DowntimeEntity, 0, len(p.seen))
	for _, d := range p.seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// MatchingIssuer returns notices affecting one issuer key.
func (p *Poller) MatchingIssuer(_ context.Context, issuerKey string) ([]domain.DowntimeEntity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	src := p.byKey[issuerKey]
	out := make([]domain.DowntimeEntity, len(src))
	copy(out, src)
	return out, nil
}

// Signals renders the cached view as the flattened form the diagnostic context
// carries, marking which notices match the issuer under diagnosis.
func (p *Poller) Signals(issuerKey string) []domain.DowntimeSignal {
	now := p.clock.Now()
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]domain.DowntimeSignal, 0, len(p.seen))
	for _, d := range p.seen {
		key := d.TelemetryKey()
		out = append(out, domain.DowntimeSignal{
			TelemetryKey:  key,
			Method:        d.Method,
			Severity:      d.Severity,
			Status:        d.Status,
			Scheduled:     d.Scheduled,
			AgeSeconds:    now.Unix() - d.Begin,
			MatchesIssuer: key == issuerKey,
		})
	}
	// Sorted so identical evidence produces an identical digest.
	sort.Slice(out, func(i, j int) bool {
		if out[i].MatchesIssuer != out[j].MatchesIssuer {
			return out[i].MatchesIssuer // matching notices first
		}
		return out[i].TelemetryKey < out[j].TelemetryKey
	})
	return out
}

// Health reports the poller's freshness for the readiness endpoint.
func (p *Poller) Health() (lastPolled time.Time, active int, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastPolled, len(p.seen), p.lastErr
}

func (p *Poller) fetch(ctx context.Context) (domain.DowntimeList, error) {
	var out domain.DowntimeList
	if p.cfg.BaseURL == "" {
		return out, fmt.Errorf("downtime: no base URL configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.BaseURL+"/v1/downtimes", nil)
	if err != nil {
		return out, fmt.Errorf("downtime: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if p.cfg.KeyID != "" {
		req.SetBasicAuth(p.cfg.KeyID, p.cfg.KeySecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return out, fmt.Errorf("downtime: fetching notices: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("downtime: endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return out, fmt.Errorf("downtime: reading response: %w", err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("downtime: response was not a valid listing (%d bytes)", len(body))
	}
	return out, nil
}

func (p *Poller) count(name string) {
	if p.metrics != nil {
		p.metrics.Counter(name).Inc()
	}
}

func (p *Poller) gauge(name string, v float64) {
	if p.metrics != nil {
		p.metrics.Gauge(name).Set(v)
	}
}

var _ domain.DowntimeSource = (*Poller)(nil)

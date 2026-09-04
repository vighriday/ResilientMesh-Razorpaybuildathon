// Package breaker implements domain.Breaker as a per-issuer circuit breaker
// whose entire state lives in Redis.
//
// The state is shared rather than per-process for one reason: a breaker each
// worker learns independently is not a breaker. During an issuer outage every
// worker would have to burn its own MinSamples worth of doomed retries before
// tripping, so the load actually shed scales with fleet size in the wrong
// direction, and the ops console would show a different verdict per worker. One
// shared window means the first N failures observed anywhere trip the issuer
// everywhere.
//
// Sharing state moves the hard part into concurrency. Every read-modify-write
// here runs inside a Lua script, which Redis executes atomically against a
// single-threaded keyspace, so the decision "did this caller get a probe" is
// made once by the server and never by two clients acting on stale reads. That
// is not a micro-optimisation: the half-open probe budget is the exact place a
// GET/compare/SET from the client lets a thundering herd through, because
// during an outage every worker in the fleet crosses the cooldown boundary
// within the same millisecond, reads probes=0, and admits itself. The retry
// storm the breaker exists to prevent would then be triggered by the breaker.
//
// Atomicity has a second payoff: because the transition is decided inside the
// script, exactly one caller in the fleet observes any given transition, so an
// audit trail written from the OnTransition callback has one entry per
// transition rather than one per worker.
//
// This package audits nothing itself. Transitions are handed to an optional
// callback and the caller decides what they mean.
//
// Deployment note: the keys one script touches are per-issuer, but the ops
// index is a single shared key, so the scripts assume one logical Redis (a
// *redis.Client, as the constructor requires) rather than a cluster.
package breaker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

var _ domain.Breaker = (*Breaker)(nil)

// ErrInvalidIssuerKey rejects a key that cannot be trusted to name a Redis key
// or to be echoed into a log line. Issuer keys are derived from webhook payload
// fields (bank code, VPA handle), so they are attacker-influenced input.
var ErrInvalidIssuerKey = errors.New("breaker: invalid issuer key")

// Reason vocabulary carried on a Transition. These strings are produced by the
// Lua scripts at the bottom of this file; the constants exist so an audit
// writer can switch on them instead of matching literals.
const (
	ReasonTripRateBreached  = "trip_rate_breached"
	ReasonCooldownElapsed   = "cooldown_elapsed"
	ReasonProbeSuccess      = "probe_success"
	ReasonProbeFailure      = "probe_failure"
	ReasonProbeLeaseExpired = "probe_lease_expired"
	ReasonStateRepaired     = "corrupt_state_repaired"
)

const (
	// tripScale turns the fractional trip rate into integer arithmetic. The
	// comparison successes/samples < TripRate is evaluated in Lua as
	// successes*tripScale < samples*scaledRate, so the threshold never depends
	// on two runtimes rounding the same decimal literal identically. At the
	// boundary — 2 successes in 10 against a rate of 0.20 — that difference
	// decides whether a healthy issuer gets shut off, so it is worth removing
	// rather than reasoning about.
	tripScale = 1_000_000

	// maxIssuerKeyLen bounds the only externally-influenced component of a
	// Redis key. Unbounded keys are both a memory amplification vector and a
	// way to push structure past a log field.
	maxIssuerKeyLen = 128

	// maxTrackedIssuers caps the ops index. The index is keyed by data derived
	// from webhook payloads, so without a cap a stream of novel issuer keys
	// would grow one Redis key without bound; the cap evicts the least recently
	// seen issuers, which are exactly the ones no operator is looking at.
	maxTrackedIssuers = 4096

	// Configuration ceilings. These bound per-issuer memory (WindowSize), the
	// Lua loop that counts the window, and how long a single mistyped
	// environment variable can wedge an issuer.
	maxWindowSize     = 10_000
	maxHalfOpenProbes = 1_000
	maxCooldown       = 24 * time.Hour

	// Key TTL bounds. The TTL must comfortably exceed Cooldown: an OPEN key
	// that expires mid-cooldown is forgotten, and a forgotten breaker is a
	// closed breaker, which silently re-admits full traffic to an issuer that
	// is still down. The TTL is ten cooldowns, and the ceiling here sits well
	// above ten times maxCooldown's clamp so that even the most extreme
	// configuration keeps a wide margin over the window it protects.
	minKeyTTL = 15 * time.Minute
	maxKeyTTL = 7 * 24 * time.Hour

	defaultNamespace = "mesh:breaker"
)

// Hash field names. These also appear as literals inside the Lua scripts;
// changing one means changing both.
const (
	fieldState    = "state"
	fieldOpenedAt = "opened_at"
)

// Transition is one persisted breaker state change, reported to the caller so
// it can be audited. Samples and Successes describe the window that produced a
// trip and are zero for transitions no window explains.
type Transition struct {
	IssuerKey string
	From      domain.BreakerState
	To        domain.BreakerState
	Reason    string
	Samples   int
	Successes int
	At        time.Time
}

// TransitionFunc receives every persisted transition, exactly once across the
// fleet. It is called synchronously on the goroutine that observed the change,
// before Allow or Report returns, so a slow callback slows a payment worker:
// hand the work off if it is not cheap.
type TransitionFunc func(ctx context.Context, t Transition)

// Config tunes the breaker. Every field has a working default, so the zero
// value is the configuration the plan specifies.
type Config struct {
	// TripRate is the success rate below which a closed breaker opens. Zero is
	// treated as unset rather than as "never trip": the two are
	// indistinguishable in a struct literal, and silently disabling the breaker
	// is the worst of the available outcomes.
	TripRate float64

	// MinSamples is the evidence floor. Below it no outage verdict is reached
	// however bad the rate looks, which stops one failure in a quiet window
	// from shutting off an issuer.
	MinSamples int

	// Cooldown is how long an open breaker sheds load before it will spend a
	// probe. It doubles as the probe lease; see Allow.
	Cooldown time.Duration

	// HalfOpenProbes is how many attempts are admitted per half-open episode.
	HalfOpenProbes int

	// WindowSize is how many recent outcomes the trip decision considers.
	WindowSize int

	// OnTransition, if set, receives every persisted transition. The package
	// deliberately does no auditing of its own: what a transition means is the
	// caller's policy, not the breaker's.
	OnTransition TransitionFunc

	// Logger is used only to report a panicking OnTransition callback. Nil is
	// fine and discards.
	Logger *slog.Logger

	// Namespace prefixes every key, so one Redis can host several meshes and so
	// tests need not share a keyspace.
	Namespace string
}

// DefaultConfig returns the tuning the plan specifies.
func DefaultConfig() Config {
	return Config{
		TripRate:       0.20,
		MinSamples:     10,
		Cooldown:       60 * time.Second,
		HalfOpenProbes: 3,
		WindowSize:     50,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()

	// Written as a positive assertion so that NaN — which fails every ordered
	// comparison, and would otherwise leave the breaker unable to trip — lands
	// in the default branch instead of falling through it.
	if !(c.TripRate > 0 && c.TripRate <= 1) {
		c.TripRate = d.TripRate
	}
	if c.WindowSize < 1 {
		c.WindowSize = d.WindowSize
	}
	if c.WindowSize > maxWindowSize {
		c.WindowSize = maxWindowSize
	}
	if c.MinSamples < 1 {
		c.MinSamples = d.MinSamples
	}
	// A floor above the window can never be reached, so the breaker would never
	// trip and nothing would say why. Clamping keeps a misconfiguration merely
	// twitchy instead of inert.
	if c.MinSamples > c.WindowSize {
		c.MinSamples = c.WindowSize
	}
	if c.Cooldown <= 0 {
		c.Cooldown = d.Cooldown
	}
	if c.Cooldown > maxCooldown {
		c.Cooldown = maxCooldown
	}
	if c.HalfOpenProbes < 1 {
		c.HalfOpenProbes = d.HalfOpenProbes
	}
	if c.HalfOpenProbes > maxHalfOpenProbes {
		c.HalfOpenProbes = maxHalfOpenProbes
	}
	if c.Namespace == "" {
		c.Namespace = defaultNamespace
	}
	return c
}

// Breaker is the Redis-backed implementation of domain.Breaker.
type Breaker struct {
	rdb   *redis.Client
	clock domain.Clock
	cfg   Config
	log   *slog.Logger

	indexKey string

	// Precomputed script arguments. Every value Redis will parse as a number is
	// formatted once here in Go, because a Lua number handed to redis.call is
	// stringified using the Lua runtime's number format, and the two runtimes
	// this code must satisfy — real Redis and the in-process RESP server used
	// in tests and managed mode — do not share one.
	cooldownMS   int64
	probeLeaseMS int64
	ttlMS        int64
	ttlMSArg     string
	tripScaled   string
	minSamples   string
	windowTrim   string
	indexTrim    string
}

// New binds a breaker to a Redis client and a clock.
//
// It cannot fail: an unusable Config is clamped to something safe rather than
// rejected, because the alternative — an error a caller might log and start up
// past — ends with payment workers running with no breaker at all.
func New(rdb *redis.Client, clock domain.Clock, cfg Config) *Breaker {
	cfg = cfg.withDefaults()
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if clock == nil {
		clock = systemClock{}
	}

	ttl := 10 * cfg.Cooldown
	if ttl < minKeyTTL {
		ttl = minKeyTTL
	}
	if ttl > maxKeyTTL {
		ttl = maxKeyTTL
	}

	return &Breaker{
		rdb:          rdb,
		clock:        clock,
		cfg:          cfg,
		log:          log,
		indexKey:     cfg.Namespace + ":idx",
		cooldownMS:   cfg.Cooldown.Milliseconds(),
		probeLeaseMS: cfg.Cooldown.Milliseconds(),
		ttlMS:        ttl.Milliseconds(),
		ttlMSArg:     strconv.FormatInt(ttl.Milliseconds(), 10),
		tripScaled:   strconv.FormatInt(int64(math.Round(cfg.TripRate*tripScale)), 10),
		minSamples:   strconv.Itoa(cfg.MinSamples),
		windowTrim:   strconv.Itoa(cfg.WindowSize - 1),
		indexTrim:    strconv.Itoa(-(maxTrackedIssuers + 1)),
	}
}

// State reports the breaker's state without changing it.
//
// An open breaker whose cooldown has elapsed reads as HALF_OPEN even though the
// stored value still says OPEN: the persisted flip belongs to Allow, which is
// the call that hands out probe budget, so that a console refresh or a
// telemetry snapshot cannot consume an issuer's one chance to recover. Keeping
// the read path free of writes is also what makes it cheap enough to call on
// every incident.
//
// On any Redis failure this returns OPEN together with the error. The error is
// the real answer; OPEN is the answer a caller who ignores it deserves, since
// treating an unverifiable issuer as available is precisely how a breaker fails
// open.
func (b *Breaker) State(ctx context.Context, issuerKey string) (domain.BreakerState, error) {
	if err := validateIssuerKey(issuerKey); err != nil {
		return domain.BreakerOpen, err
	}
	vals, err := b.rdb.HMGet(ctx, b.stateKey(issuerKey), fieldState, fieldOpenedAt).Result()
	if err != nil {
		return domain.BreakerOpen, fmt.Errorf("breaker: reading state for %q: %w", issuerKey, err)
	}
	return b.effective(vals, b.clock.Now()), nil
}

// Allow reports whether an attempt against this issuer may proceed.
//
// Closed admits and writes nothing, keeping the hot path to a single HGET
// inside the script. Open denies until the cooldown elapses. Half-open admits
// while the probe budget lasts and denies afterwards, and that budget is
// decremented by the same script that read it — see the package comment for why
// doing it from the client is a load-shedding bug rather than a style
// preference.
//
// The budget counts probes admitted in the current half-open episode rather
// than probes currently in flight, which is the same thing in practice: the
// first probe to report ends the episode either way. A probe that never reports
// — its worker died mid-attempt — would otherwise hold budget forever and wedge
// the issuer permanently, so an episode older than one cooldown is presumed
// lost and a fresh one begins.
//
// A false return alongside a non-nil error is deliberate: a caller that ignores
// the error still fails closed.
func (b *Breaker) Allow(ctx context.Context, issuerKey string) (bool, error) {
	if err := validateIssuerKey(issuerKey); err != nil {
		return false, err
	}
	now := b.clock.Now()
	nowMS := strconv.FormatInt(now.UnixMilli(), 10)

	raw, err := allowScript.Run(ctx, b.rdb,
		[]string{b.stateKey(issuerKey), b.indexKey},
		nowMS,
		b.cooldownMS,
		b.cfg.HalfOpenProbes,
		b.ttlMSArg,
		b.probeLeaseMS,
		b.indexCutoff(now),
		b.indexTrim,
		issuerKey,
	).Slice()
	if err != nil {
		return false, fmt.Errorf("breaker: evaluating admission for %q: %w", issuerKey, err)
	}
	if len(raw) < 4 {
		return false, fmt.Errorf("breaker: admission script returned %d values, want 4", len(raw))
	}

	allowed, err := asInt(raw[0])
	if err != nil {
		return false, fmt.Errorf("breaker: admission verdict for %q: %w", issuerKey, err)
	}
	b.reportTransition(ctx, issuerKey, now, raw[1], raw[2], raw[3], 0, 0)
	return allowed == 1, nil
}

// Report records one outcome and re-evaluates the breaker.
//
// Outcomes observed while the breaker is open are discarded rather than
// counted. They are not a sample of issuer health: load is being shed, so what
// remains is whatever raced past the trip or ignored Allow, and letting a
// handful of stray successes accumulate would let an issuer close itself
// without ever spending a probe.
func (b *Breaker) Report(ctx context.Context, issuerKey string, success bool) error {
	if err := validateIssuerKey(issuerKey); err != nil {
		return err
	}
	outcome := "0"
	if success {
		outcome = "1"
	}
	now := b.clock.Now()
	nowMS := strconv.FormatInt(now.UnixMilli(), 10)

	raw, err := reportScript.Run(ctx, b.rdb,
		[]string{b.stateKey(issuerKey), b.windowKey(issuerKey), b.indexKey},
		nowMS,
		outcome,
		b.minSamples,
		tripScale,
		b.tripScaled,
		b.ttlMSArg,
		b.windowTrim,
		b.indexCutoff(now),
		b.indexTrim,
		issuerKey,
	).Slice()
	if err != nil {
		return fmt.Errorf("breaker: recording outcome for %q: %w", issuerKey, err)
	}
	if len(raw) < 5 {
		return fmt.Errorf("breaker: outcome script returned %d values, want 5", len(raw))
	}

	samples, err := asInt(raw[3])
	if err != nil {
		return fmt.Errorf("breaker: window size for %q: %w", issuerKey, err)
	}
	successes, err := asInt(raw[4])
	if err != nil {
		return fmt.Errorf("breaker: window successes for %q: %w", issuerKey, err)
	}
	b.reportTransition(ctx, issuerKey, now, raw[0], raw[1], raw[2], int(samples), int(successes))
	return nil
}

// States returns every issuer the breaker has touched recently, for the ops
// console. The listing is bounded by maxTrackedIssuers and by the key TTL, so
// it stays a fixed-cost read no matter how much traffic has passed through.
func (b *Breaker) States(ctx context.Context) (map[string]domain.BreakerState, error) {
	members, err := b.rdb.ZRange(ctx, b.indexKey, 0, maxTrackedIssuers-1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("breaker: listing tracked issuers: %w", err)
	}

	out := make(map[string]domain.BreakerState, len(members))
	if len(members) == 0 {
		return out, nil
	}

	pipe := b.rdb.Pipeline()
	keys := make([]string, 0, len(members))
	cmds := make([]*redis.SliceCmd, 0, len(members))
	for _, m := range members {
		// The index holds data, and data read back out of a shared store is
		// validated on the way in exactly as it was on the way out.
		if validateIssuerKey(m) != nil {
			continue
		}
		keys = append(keys, m)
		cmds = append(cmds, pipe.HMGet(ctx, b.stateKey(m), fieldState, fieldOpenedAt))
	}
	if len(keys) == 0 {
		return out, nil
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("breaker: reading tracked breaker states: %w", err)
	}

	now := b.clock.Now()
	for i, key := range keys {
		vals, err := cmds[i].Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				// The state hash expired between the index read and this one.
				// No stored state is a closed breaker.
				out[key] = domain.BreakerClosed
				continue
			}
			return nil, fmt.Errorf("breaker: reading state for %q: %w", key, err)
		}
		out[key] = b.effective(vals, now)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// Keys carry a hash tag around the issuer so one issuer's state and window
// share a slot; the shared ops index cannot, which is the single-instance
// assumption stated in the package comment.
func (b *Breaker) stateKey(issuerKey string) string {
	return b.cfg.Namespace + ":s:{" + issuerKey + "}"
}

func (b *Breaker) windowKey(issuerKey string) string {
	return b.cfg.Namespace + ":w:{" + issuerKey + "}"
}

// indexCutoff is the score at or below which an index member is stale. It is
// computed here rather than in Lua so Redis is handed a plain integer string.
func (b *Breaker) indexCutoff(now time.Time) string {
	return strconv.FormatInt(now.UnixMilli()-b.ttlMS, 10)
}

// effective folds the stored (state, opened_at) pair into the state a caller
// should act on, promoting an elapsed cooldown to HALF_OPEN.
func (b *Breaker) effective(vals []any, now time.Time) domain.BreakerState {
	var stored string
	if len(vals) > 0 && vals[0] != nil {
		if s, err := asString(vals[0]); err == nil {
			stored = s
		}
	}
	switch domain.BreakerState(stored) {
	case domain.BreakerClosed, "":
		return domain.BreakerClosed
	case domain.BreakerHalfOpen:
		return domain.BreakerHalfOpen
	case domain.BreakerOpen:
		var openedAt int64
		if len(vals) > 1 && vals[1] != nil {
			if n, err := asInt(vals[1]); err == nil {
				openedAt = n
			}
		}
		if now.UnixMilli()-openedAt >= b.cooldownMS {
			return domain.BreakerHalfOpen
		}
		return domain.BreakerOpen
	default:
		// Something wrote a value this package did not. Denying is the only
		// safe reading of state that cannot be interpreted; Allow repairs it.
		return domain.BreakerOpen
	}
}

// reportTransition converts a script result into a Transition and hands it to
// the callback. A state repair is surfaced even though from and to match,
// because a breaker hash holding an unrecognised value is an operator concern
// regardless of what it was rewritten to.
func (b *Breaker) reportTransition(ctx context.Context, issuerKey string, now time.Time, fromRaw, toRaw, reasonRaw any, samples, successes int) {
	if b.cfg.OnTransition == nil {
		return
	}
	from, err := asString(fromRaw)
	if err != nil {
		return
	}
	to, err := asString(toRaw)
	if err != nil {
		return
	}
	reason, err := asString(reasonRaw)
	if err != nil {
		return
	}
	if from == to && reason != ReasonStateRepaired {
		return
	}
	b.emit(ctx, Transition{
		IssuerKey: issuerKey,
		From:      domain.BreakerState(from),
		To:        domain.BreakerState(to),
		Reason:    reason,
		Samples:   samples,
		Successes: successes,
		At:        now,
	})
}

// emit isolates the caller's callback. A panicking audit writer must not take
// down a payment worker, and the transition it describes is already committed
// in Redis, so unwinding here would lose the notification without undoing
// anything. The panic value itself is not logged: it comes from caller code
// that may carry incident detail, and its type plus the issuer is enough to
// find the bug.
func (b *Breaker) emit(ctx context.Context, t Transition) {
	defer func() {
		if r := recover(); r != nil {
			b.log.ErrorContext(ctx, "breaker transition callback panicked",
				slog.String("issuer_key", t.IssuerKey),
				slog.String("from", string(t.From)),
				slog.String("to", string(t.To)),
				slog.String("panic_type", fmt.Sprintf("%T", r)),
			)
		}
	}()
	b.cfg.OnTransition(ctx, t)
}

// validateIssuerKey rejects keys that cannot safely become part of a Redis key
// or of a log line. Redis keys are binary safe, so this is deliberately narrow:
// it bounds length, insists on valid UTF-8, and refuses control characters (log
// and console injection) and braces (which would redefine the hash tag the key
// layout depends on). Anything else an issuer code might legitimately contain
// passes through unchanged, because silently rewriting a key would split one
// issuer's window in two and neither half would ever reach MinSamples.
func validateIssuerKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: empty", ErrInvalidIssuerKey)
	}
	if len(key) > maxIssuerKeyLen {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalidIssuerKey, len(key), maxIssuerKeyLen)
	}
	if !utf8.ValidString(key) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidIssuerKey)
	}
	for _, r := range key {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%w: contains a control character", ErrInvalidIssuerKey)
		case r == '{' || r == '}':
			return fmt.Errorf("%w: contains a brace", ErrInvalidIssuerKey)
		}
	}
	return nil
}

// asInt and asString absorb the difference between how a real Redis and an
// in-process RESP server encode a Lua return value. Tolerating both here is
// cheaper than discovering in production that one of them sends a bulk string
// where the other sends an integer.
func asInt(v any) (int64, error) {
	switch t := v.(type) {
	case int64:
		return t, nil
	case int:
		return int64(t), nil
	case float64:
		return int64(t), nil
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("breaker: %q is not an integer: %w", t, err)
		}
		return n, nil
	case []byte:
		n, err := strconv.ParseInt(string(t), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("breaker: %q is not an integer: %w", string(t), err)
		}
		return n, nil
	case nil:
		return 0, errors.New("breaker: expected an integer, got nil")
	default:
		return 0, fmt.Errorf("breaker: expected an integer, got %T", v)
	}
}

func asString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case []byte:
		return string(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case nil:
		return "", errors.New("breaker: expected a string, got nil")
	default:
		return "", fmt.Errorf("breaker: expected a string, got %T", v)
	}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// Scripts
//
// Both scripts follow two rules. Every value Redis will parse as a number is
// passed in already formatted and used verbatim, never rebuilt from a Lua
// number, because the Lua number-to-string format is a property of the server
// rather than of this code. And every branch that writes also refreshes the
// TTLs, so an issuer under continuous traffic never has its state expire out
// from under an open cooldown.
// ---------------------------------------------------------------------------

// allowScript decides admission and performs the two state changes driven by
// time rather than by an outcome: a cooldown expiring, and a half-open episode
// abandoned by a worker that died holding a probe.
//
// KEYS[1] issuer state hash, KEYS[2] ops index zset.
// ARGV: 1 now(ms) 2 cooldown(ms) 3 max probes 4 key ttl(ms) 5 probe lease(ms)
// 6 index cutoff score 7 index trim rank 8 issuer key.
var allowScript = redis.NewScript(`
local now       = tonumber(ARGV[1])
local cooldown  = tonumber(ARGV[2])
local maxProbes = tonumber(ARGV[3])
local lease     = tonumber(ARGV[5])

local st = redis.call('HGET', KEYS[1], 'state')
if st == false or st == nil or st == '' then st = 'CLOSED' end

local from    = st
local to      = st
local reason  = ''
local allowed = 0
local wrote   = 0

if st == 'CLOSED' then
  allowed = 1
elseif st == 'OPEN' then
  local openedAt = tonumber(redis.call('HGET', KEYS[1], 'opened_at'))
  if openedAt == nil then openedAt = 0 end
  if now - openedAt >= cooldown then
    to      = 'HALF_OPEN'
    reason  = 'cooldown_elapsed'
    allowed = 1
    wrote   = 1
    redis.call('HSET', KEYS[1], 'state', 'HALF_OPEN')
    redis.call('HSET', KEYS[1], 'probes', '1')
    redis.call('HSET', KEYS[1], 'half_open_at', ARGV[1])
  end
elseif st == 'HALF_OPEN' then
  local probes = tonumber(redis.call('HGET', KEYS[1], 'probes'))
  if probes == nil then probes = 0 end
  local since = tonumber(redis.call('HGET', KEYS[1], 'half_open_at'))
  if since == nil then since = now end
  if now - since >= lease then
    probes = 0
    reason = 'probe_lease_expired'
    wrote  = 1
    redis.call('HSET', KEYS[1], 'probes', '0')
    redis.call('HSET', KEYS[1], 'half_open_at', ARGV[1])
  end
  if probes < maxProbes then
    redis.call('HINCRBY', KEYS[1], 'probes', 1)
    allowed = 1
    wrote   = 1
  end
else
  from   = 'OPEN'
  to     = 'OPEN'
  reason = 'corrupt_state_repaired'
  wrote  = 1
  redis.call('HSET', KEYS[1], 'state', 'OPEN')
  redis.call('HSET', KEYS[1], 'opened_at', ARGV[1])
  redis.call('HSET', KEYS[1], 'probes', '0')
  redis.call('HSET', KEYS[1], 'half_open_at', ARGV[1])
end

if wrote == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
  redis.call('ZADD', KEYS[2], ARGV[1], ARGV[8])
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[6])
  redis.call('ZREMRANGEBYRANK', KEYS[2], '0', ARGV[7])
  redis.call('PEXPIRE', KEYS[2], ARGV[4])
end

return {allowed, from, to, reason}
`)

// reportScript records an outcome and applies every outcome-driven transition.
//
// The window is a capped list of one character per outcome rather than a
// success/failure counter pair under a TTL. A counter pair is cheaper but it is
// a tumbling window: it forgets everything at the expiry boundary, so an issuer
// that has been failing for the last 59 seconds reads as pristine at second 61,
// and MinSamples stops meaning "the last N outcomes" and starts meaning
// "however many happened to land in this bucket" — which makes a trip decision
// impossible to reconstruct from the audit trail afterwards. The list is
// exactly the last WindowSize outcomes, bounded in length by the trim and in
// age by the key TTL, so memory stays proportional to issuers times WindowSize
// with no unbounded growth path. Counting it is one pass over at most
// WindowSize characters inside a script that already holds the server.
//
// The window is deleted on every state change. Its samples are evidence for one
// decision; once that decision is taken they describe an issuer under a
// different regime, and keeping them would let the burst that opened the
// breaker immediately re-open it the moment a successful probe closed it.
//
// KEYS[1] issuer state hash, KEYS[2] issuer window list, KEYS[3] ops index.
// ARGV: 1 now(ms) 2 outcome 3 min samples 4 trip scale 5 scaled trip rate
// 6 key ttl(ms) 7 window trim index 8 index cutoff 9 index trim rank
// 10 issuer key.
var reportScript = redis.NewScript(`
local outcome    = ARGV[2]
local minSamples = tonumber(ARGV[3])
local scale      = tonumber(ARGV[4])
local tripScaled = tonumber(ARGV[5])

local st = redis.call('HGET', KEYS[1], 'state')
if st == false or st == nil or st == '' then st = 'CLOSED' end

local from      = st
local to        = st
local reason    = ''
local samples   = 0
local successes = 0

local function openNow(why)
  to     = 'OPEN'
  reason = why
  redis.call('DEL', KEYS[2])
  redis.call('HSET', KEYS[1], 'state', 'OPEN')
  redis.call('HSET', KEYS[1], 'opened_at', ARGV[1])
  redis.call('HSET', KEYS[1], 'probes', '0')
  redis.call('HSET', KEYS[1], 'half_open_at', '0')
end

if st == 'HALF_OPEN' then
  if outcome == '1' then
    to     = 'CLOSED'
    reason = 'probe_success'
    redis.call('DEL', KEYS[2])
    redis.call('HSET', KEYS[1], 'state', 'CLOSED')
    redis.call('HSET', KEYS[1], 'opened_at', '0')
    redis.call('HSET', KEYS[1], 'probes', '0')
    redis.call('HSET', KEYS[1], 'half_open_at', '0')
  else
    openNow('probe_failure')
  end
elseif st == 'OPEN' then
  reason = 'ignored_while_open'
elseif st == 'CLOSED' then
  redis.call('LPUSH', KEYS[2], outcome)
  redis.call('LTRIM', KEYS[2], 0, ARGV[7])
  local items = redis.call('LRANGE', KEYS[2], 0, -1)
  samples = #items
  for i = 1, samples do
    if items[i] == '1' then successes = successes + 1 end
  end
  if samples >= minSamples and successes * scale < samples * tripScaled then
    openNow('trip_rate_breached')
  end
else
  from = 'OPEN'
  openNow('corrupt_state_repaired')
end

redis.call('PEXPIRE', KEYS[1], ARGV[6])
redis.call('PEXPIRE', KEYS[2], ARGV[6])
redis.call('ZADD', KEYS[3], ARGV[1], ARGV[10])
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', ARGV[8])
redis.call('ZREMRANGEBYRANK', KEYS[3], '0', ARGV[9])
redis.call('PEXPIRE', KEYS[3], ARGV[6])

return {from, to, reason, samples, successes}
`)

// Package telemetry maintains the rolling per-issuer outcome window that the
// rest of the system reasons about issuer health with: the breaker trips off
// it, the policy engine ranks rails by it, and the ops console renders it.
//
// The window lives in Redis rather than in process memory because the edge, the
// relay and every worker must agree on one view of issuer health. Workers
// holding private counters would disagree about whether an issuer is down, and
// during an outage — the only moment the number matters — they would disagree
// most, because that is when traffic is least evenly spread across them.
//
// Storage is one sorted set per issuer scored by event time. A list or a stream
// would force a full scan to answer "what happened in the last five minutes";
// a sorted set answers it in O(log n + m). Every write trims the set to the
// window and refreshes a TTL, so an issuer that stops taking traffic costs
// nothing rather than accumulating forever. Bounded memory here is an
// availability control rather than tidiness: the issuer key space is derived
// from merchant-supplied payload fields.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Key namespaces. Issuer sets and method aggregates use distinct prefixes so
// the SCAN in SnapshotAll enumerates issuers without also matching the
// aggregates, which are not issuers and would otherwise show up in the console
// as one.
const (
	issuerKeyPrefix = "tel:z:"
	methodKeyPrefix = "tel:m:"
)

const (
	// DefaultWindow is the rolling window used when the caller supplies one
	// that cannot be represented. Five minutes is short enough that an outage
	// shows up before a retry storm builds, and long enough that a low-traffic
	// issuer still clears domain.DegradedMinSamples.
	DefaultWindow = 5 * time.Minute

	// ttlMultiplier sets each key's TTL to this many windows. One window would
	// be too tight: a key expiring the instant its last event ages out races
	// every reader that is mid-snapshot, and writer clocks are not perfectly
	// aligned. Three windows leaves that headroom while still guaranteeing an
	// idle issuer disappears without a sweeper process.
	ttlMultiplier = 3

	// maxIssuerKeyLen bounds the identity half of the key space. Issuer keys
	// are built by domain.Issuer from webhook fields (bank code, VPA handle)
	// that are merchant-controlled, so an unbounded key is an unbounded Redis
	// allocation driven by external input.
	maxIssuerKeyLen = 128

	// maxErrorCodeLen bounds the label half. Unlike the issuer key this is
	// truncated rather than rejected: a code is descriptive, so a clipped label
	// still carries its signal, whereas a mangled issuer key would silently
	// attribute one institution's failures to another.
	maxErrorCodeLen = 64

	// maxLatencyMS clamps a sample to one hour. Anything larger is a clock or
	// instrumentation bug rather than a measurement, and letting it through
	// would drag the P95 into meaninglessness for the whole window.
	maxLatencyMS = int64(60 * 60 * 1000)

	// maxTopErrorCodes bounds what a snapshot carries into prompts, audit
	// details and the console. The head of the distribution is the diagnostic
	// signal; the tail is noise with a serialisation cost.
	maxTopErrorCodes = 5

	// maxIssuerKeys bounds SnapshotAll. Real issuer cardinality is in the low
	// hundreds; anything approaching this bound means the key space has been
	// inflated by garbage instrument fields, and a partial view of a poisoned
	// key space is more dangerous than a loud failure.
	maxIssuerKeys = 10_000

	// maxScanRounds stops a server returning a non-zero cursor forever from
	// pinning a goroutine when the caller passed a context without a deadline.
	maxScanRounds = 1 << 16

	scanBatch = 512

	// memberVersion prefixes every member so a future encoding can roll out
	// without a flag day: a reader meeting a version it does not know skips the
	// member instead of misreading it.
	memberVersion = "1"

	memberSep = '|'
)

// Errors callers can branch on. An invalid issuer key is a caller bug or a
// hostile payload, never a transient condition, so it stays distinguishable
// from a Redis failure.
var (
	ErrEmptyIssuerKey   = errors.New("telemetry: issuer key is empty")
	ErrIssuerKeyTooLong = errors.New("telemetry: issuer key exceeds maximum length")
	ErrTooManyIssuers   = errors.New("telemetry: issuer cardinality exceeds safe bound")

	errMalformedEscape = errors.New("telemetry: malformed escape sequence")
)

// Recorder is the Redis-backed implementation of domain.TelemetryRecorder.
//
// It is safe for concurrent use: the only mutable state is an atomic counter,
// and every Redis command goes through the client's own connection pool.
type Recorder struct {
	rdb    *redis.Client
	clock  domain.Clock
	window time.Duration
	ttl    time.Duration

	// nonce and seq together make every recorded member unique. See
	// encodeMember for why that is a correctness requirement, not hygiene.
	nonce string
	seq   atomic.Uint64
}

var _ domain.TelemetryRecorder = (*Recorder)(nil)

// New builds a Recorder over an already-connected client.
//
// The clock is injected rather than read from time.Now so window trimming and
// snapshot boundaries are testable, and so a simulation run can drive the
// window from virtual time. A nil clock falls back to the wall clock, and a
// window under one second falls back to DefaultWindow because
// domain.TelemetrySnapshot reports the window in whole seconds and a snapshot
// claiming a zero-second window reads as "no window at all".
func New(rdb *redis.Client, clock domain.Clock, window time.Duration) *Recorder {
	if clock == nil {
		clock = systemClock{}
	}
	if window < time.Second {
		window = DefaultWindow
	}
	return &Recorder{
		rdb:    rdb,
		clock:  clock,
		window: window,
		ttl:    window * ttlMultiplier,
		nonce:  newNonce(clock),
	}
}

// Window reports the rolling window this recorder was built with, so a caller
// reasoning about snapshot freshness does not have to re-derive it from
// configuration and risk disagreeing with the recorder.
func (r *Recorder) Window() time.Duration { return r.window }

// RecordOutcome appends one attempt outcome to the issuer window and to the
// per-method portfolio aggregate.
//
// Both writes, both trims and both TTL refreshes travel as a single pipeline:
// six round trips per payment attempt would put Redis latency on the hot path
// of every recovery, and a partially applied write would leave a set growing
// with no trim behind it.
func (r *Recorder) RecordOutcome(ctx context.Context, issuerKey, errorCode string, success bool, latency time.Duration) error {
	key, err := normaliseIssuerKey(issuerKey)
	if err != nil {
		return err
	}

	now := r.clock.Now()
	tsMS := now.UnixMilli()
	member := r.encodeMember(tsMS, success, errorCode, latency)
	score := float64(tsMS)

	// Trim strictly below the cutoff and read at or above it, so the two
	// operations never disagree about an event sitting exactly on the boundary.
	trimBelow := "(" + strconv.FormatInt(r.cutoffMS(now), 10)

	pipe := r.rdb.Pipeline()
	for _, k := range [2]string{r.issuerSetKey(key), r.methodSetKey(methodOf(key))} {
		pipe.ZAdd(ctx, k, redis.Z{Score: score, Member: member})
		pipe.ZRemRangeByScore(ctx, k, "-inf", trimBelow)
		pipe.PExpire(ctx, k, r.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("telemetry: record outcome: %w", err)
	}
	return nil
}

// Snapshot reads one issuer's window and the portfolio aggregate for its method
// in a single pipeline, so the issuer rate and the baseline it is judged
// against describe the same instant.
//
// BreakerState is deliberately left empty. Reading it here would make this
// package depend on the breaker, and the breaker already depends on telemetry
// to decide when to trip; the worker joins the two. Keeping that cycle broken
// is worth the one assignment it costs the caller.
func (r *Recorder) Snapshot(ctx context.Context, issuerKey string) (domain.TelemetrySnapshot, error) {
	key, err := normaliseIssuerKey(issuerKey)
	if err != nil {
		return domain.TelemetrySnapshot{}, err
	}

	now := r.clock.Now()
	window := r.windowRange(now)

	pipe := r.rdb.Pipeline()
	issuerCmd := pipe.ZRangeByScore(ctx, r.issuerSetKey(key), window)
	methodCmd := pipe.ZRangeByScore(ctx, r.methodSetKey(methodOf(key)), window)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return domain.TelemetrySnapshot{}, fmt.Errorf("telemetry: snapshot: %w", err)
	}

	issuerMembers, err := membersOf(issuerCmd)
	if err != nil {
		return domain.TelemetrySnapshot{}, fmt.Errorf("telemetry: snapshot issuer window: %w", err)
	}
	methodMembers, err := membersOf(methodCmd)
	if err != nil {
		return domain.TelemetrySnapshot{}, fmt.Errorf("telemetry: snapshot method window: %w", err)
	}

	return r.build(key, aggregateMembers(issuerMembers), aggregateMembers(methodMembers), now), nil
}

// SnapshotAll enumerates every issuer with live telemetry and snapshots each.
//
// Enumeration uses SCAN, never KEYS. KEYS walks the whole keyspace inside one
// command and Redis executes commands on a single thread, so on an instance
// holding millions of keys it is a multi-second stall for every other client —
// including the ingest path. SCAN is cursor-based and bounded per call, so an
// operator refreshing the console cannot stall payment recovery.
//
// All reads are issued as one pipeline rather than one round trip per issuer,
// and each method aggregate is fetched once and shared, so the console costs a
// single network exchange regardless of issuer count.
func (r *Recorder) SnapshotAll(ctx context.Context) ([]domain.TelemetrySnapshot, error) {
	issuers, err := r.scanIssuerKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(issuers) == 0 {
		return nil, nil
	}

	methods := make([]string, 0, len(issuers))
	for _, k := range issuers {
		methods = append(methods, methodOf(k))
	}
	slices.Sort(methods)
	methods = slices.Compact(methods)

	now := r.clock.Now()
	window := r.windowRange(now)

	pipe := r.rdb.Pipeline()
	issuerCmds := make([]*redis.StringSliceCmd, len(issuers))
	for i, k := range issuers {
		issuerCmds[i] = pipe.ZRangeByScore(ctx, r.issuerSetKey(k), window)
	}
	methodCmds := make([]*redis.StringSliceCmd, len(methods))
	for i, m := range methods {
		methodCmds[i] = pipe.ZRangeByScore(ctx, r.methodSetKey(m), window)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("telemetry: snapshot all: %w", err)
	}

	portfolio := make(map[string]aggregate, len(methods))
	for i, m := range methods {
		members, err := membersOf(methodCmds[i])
		if err != nil {
			return nil, fmt.Errorf("telemetry: snapshot all method window: %w", err)
		}
		portfolio[m] = aggregateMembers(members)
	}

	out := make([]domain.TelemetrySnapshot, 0, len(issuers))
	for i, k := range issuers {
		members, err := membersOf(issuerCmds[i])
		if err != nil {
			return nil, fmt.Errorf("telemetry: snapshot all issuer window: %w", err)
		}
		out = append(out, r.build(k, aggregateMembers(members), portfolio[methodOf(k)], now))
	}
	return out, nil
}

// scanIssuerKeys returns the decoded issuer keys currently holding telemetry,
// sorted so the console does not reshuffle rows between refreshes.
func (r *Recorder) scanIssuerKeys(ctx context.Context) ([]string, error) {
	var (
		cursor uint64
		out    []string
		seen   = make(map[string]struct{})
	)
	for round := 0; round < maxScanRounds; round++ {
		keys, next, err := r.rdb.Scan(ctx, cursor, issuerKeyPrefix+"*", scanBatch).Result()
		if err != nil {
			return nil, fmt.Errorf("telemetry: scan issuer keys: %w", err)
		}
		for _, k := range keys {
			encoded, ok := strings.CutPrefix(k, issuerKeyPrefix)
			if !ok {
				continue
			}
			// A key under our prefix that does not decode was written by
			// something else, or by an encoding this build does not know.
			// Guessing at its identity would attribute foreign data to a real
			// issuer, so it is skipped rather than repaired.
			issuer, err := unescapeSegment(encoded)
			if err != nil {
				continue
			}
			if _, dup := seen[issuer]; dup {
				// SCAN may return the same key more than once across cursor
				// rounds; that is documented behaviour, not an error.
				continue
			}
			if len(seen) >= maxIssuerKeys {
				return nil, fmt.Errorf("%w: more than %d issuer keys", ErrTooManyIssuers, maxIssuerKeys)
			}
			seen[issuer] = struct{}{}
			out = append(out, issuer)
		}
		cursor = next
		if cursor == 0 {
			slices.Sort(out)
			return out, nil
		}
	}
	return nil, fmt.Errorf("telemetry: scan issuer keys: cursor did not converge after %d rounds", maxScanRounds)
}

func (r *Recorder) build(issuerKey string, issuer, portfolio aggregate, now time.Time) domain.TelemetrySnapshot {
	return domain.TelemetrySnapshot{
		IssuerKey:     issuerKey,
		WindowSeconds: int(r.window / time.Second),
		Attempts:      issuer.attempts,
		Successes:     issuer.successes,
		Failures:      issuer.attempts - issuer.successes,
		SuccessRate:   ratio(issuer.successes, issuer.attempts),
		// The baseline includes this issuer's own events. It is a portfolio
		// rate, and excluding self would give every issuer a different
		// baseline, so two snapshots taken at the same instant could no longer
		// be compared with each other. Self-inclusion does mean a method with a
		// single issuer has BaselineRate == SuccessRate and can never be
		// flagged by the relative test; domain.DegradedAbsoluteRate is the
		// backstop for exactly that case.
		BaselineRate:  ratio(portfolio.successes, portfolio.attempts),
		P95LatencyMS:  percentile95(issuer.latencies),
		TopErrorCodes: topCodes(issuer.codes),
		SampledAt:     now,
	}
}

func (r *Recorder) cutoffMS(now time.Time) int64 {
	return now.UnixMilli() - r.window.Milliseconds()
}

// windowRange builds the inclusive lower bound shared by every read. Scores are
// unix milliseconds, which stay below 2^53 for the next quarter-million years,
// so the float64 score Redis stores is exact and no event is misplaced by
// rounding.
func (r *Recorder) windowRange(now time.Time) *redis.ZRangeBy {
	return &redis.ZRangeBy{
		Min: strconv.FormatInt(r.cutoffMS(now), 10),
		Max: "+inf",
	}
}

func (r *Recorder) issuerSetKey(issuerKey string) string {
	return issuerKeyPrefix + escapeSegment(issuerKey)
}

func (r *Recorder) methodSetKey(method string) string {
	return methodKeyPrefix + escapeSegment(method)
}

// encodeMember renders one outcome as a sorted-set member.
//
// The trailing nonce-counter suffix is load-bearing, not decoration. ZADD keys
// on the member: adding a member that already exists updates its score instead
// of inserting a second element. Without the suffix, two attempts on the same
// issuer landing in the same millisecond with the same outcome, error code and
// rounded latency would encode identically, and the second ZADD would silently
// overwrite the first. That is not a rare shape — it is precisely the shape of
// an issuer outage, where hundreds of identical bank_technical_error failures
// arrive together. The window would then under-count attempts exactly when the
// count matters, holding Attempts below domain.DegradedMinSamples and keeping
// the breaker closed through the outage it exists to shed.
//
// The suffix combines a per-Recorder random nonce with a per-Recorder atomic
// counter because both halves are needed: the counter alone collides across the
// worker pool, and the nonce alone collides within one process.
func (r *Recorder) encodeMember(tsMS int64, success bool, errorCode string, latency time.Duration) string {
	bit := byte('0')
	if success {
		bit = '1'
	}

	lat := latency.Milliseconds()
	if lat < 0 {
		// A negative duration means the caller measured across a clock
		// adjustment. Zero is the only honest reading available.
		lat = 0
	}
	if lat > maxLatencyMS {
		lat = maxLatencyMS
	}

	code := ""
	if !success {
		// A success carries no decline reason. Dropping any code supplied
		// alongside one keeps the error histogram free of entries implying
		// failures that never happened.
		code = sanitiseErrorCode(errorCode)
	}

	var b strings.Builder
	b.Grow(len(code) + len(r.nonce) + 48)
	b.WriteString(memberVersion)
	b.WriteByte(memberSep)
	b.WriteString(strconv.FormatInt(tsMS, 10))
	b.WriteByte(memberSep)
	b.WriteByte(bit)
	b.WriteByte(memberSep)
	b.WriteString(strconv.FormatInt(lat, 10))
	b.WriteByte(memberSep)
	b.WriteString(escapeSegment(code))
	b.WriteByte(memberSep)
	b.WriteString(r.nonce)
	b.WriteByte('-')
	b.WriteString(strconv.FormatUint(r.seq.Add(1), 36))
	return b.String()
}

// event is one decoded member.
type event struct {
	success   bool
	latencyMS int64
	code      string
}

func decodeMember(m string) (event, bool) {
	parts := strings.SplitN(m, string(memberSep), 6)
	if len(parts) != 6 || parts[0] != memberVersion {
		return event{}, false
	}
	// The sorted-set score, not this field, decides window membership, so the
	// embedded timestamp is never read. It is still validated: a member whose
	// timestamp does not parse was not written by this encoding, and accepting
	// the rest of it would mean trusting fields from an unknown writer.
	if _, err := strconv.ParseInt(parts[1], 10, 64); err != nil {
		return event{}, false
	}
	var success bool
	switch parts[2] {
	case "0":
	case "1":
		success = true
	default:
		return event{}, false
	}
	lat, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || lat < 0 {
		return event{}, false
	}
	code, err := unescapeSegment(parts[4])
	if err != nil {
		return event{}, false
	}
	return event{success: success, latencyMS: lat, code: code}, true
}

type aggregate struct {
	attempts  int
	successes int
	latencies []int64
	codes     map[string]int
}

// aggregateMembers folds a window into counters.
//
// A member that fails to decode is excluded from every counter rather than
// charged to either column. It carries no verdict, so counting it as a success
// would fabricate health and counting it as a failure would fabricate an
// outage; excluding it only lowers the sample count, which the
// domain.DegradedMinSamples floor already knows how to handle. This is also
// what lets a newer member encoding roll out mid-deploy without an older build
// reading the newer members as garbage failures.
func aggregateMembers(members []string) aggregate {
	agg := aggregate{}
	if len(members) == 0 {
		return agg
	}
	agg.latencies = make([]int64, 0, len(members))
	for _, m := range members {
		ev, ok := decodeMember(m)
		if !ok {
			continue
		}
		agg.attempts++
		if ev.success {
			agg.successes++
		}
		agg.latencies = append(agg.latencies, ev.latencyMS)
		if ev.code != "" {
			if agg.codes == nil {
				agg.codes = make(map[string]int)
			}
			agg.codes[ev.code]++
		}
	}
	return agg
}

// percentile95 uses the nearest-rank definition over integer milliseconds.
//
// Rank arithmetic is integer throughout: interpolating between samples would
// invent a latency nobody measured, and computing the ceiling without floats
// means the same window yields the same index on every machine.
func percentile95(latencies []int64) int64 {
	n := len(latencies)
	if n == 0 {
		return 0
	}
	sorted := slices.Clone(latencies)
	slices.Sort(sorted)
	idx := (95*n+99)/100 - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// topCodes ranks the window's decline reasons.
//
// domain.SortCodeCounts imposes a total order — count descending, then code
// ascending — so the result does not depend on Go's randomised map iteration.
// That matters beyond tidiness: the snapshot feeds the agent's context digest,
// and a digest that reordered between two identical windows would miss its
// cassette and silently drop the run to a degraded inference tier.
func topCodes(counts map[string]int) []domain.CodeCount {
	if len(counts) == 0 {
		return nil
	}
	cc := make([]domain.CodeCount, 0, len(counts))
	for code, n := range counts {
		cc = append(cc, domain.CodeCount{Code: code, Count: n})
	}
	domain.SortCodeCounts(cc)
	if len(cc) > maxTopErrorCodes {
		cc = cc[:maxTopErrorCodes]
	}
	return cc
}

func ratio(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func membersOf(cmd *redis.StringSliceCmd) ([]string, error) {
	v, err := cmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	return v, nil
}

// normaliseIssuerKey validates the one field that is an identity.
//
// It rejects rather than repairs: silently coercing an empty or over-long key
// into something storable would merge two issuers' windows, and a merged window
// is a wrong health verdict for both of them.
func normaliseIssuerKey(k string) (string, error) {
	k = strings.TrimSpace(k)
	if k == "" {
		return "", ErrEmptyIssuerKey
	}
	if len(k) > maxIssuerKeyLen {
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrIssuerKeyTooLong, len(k), maxIssuerKeyLen)
	}
	return k, nil
}

func sanitiseErrorCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) > maxErrorCodeLen {
		code = code[:maxErrorCodeLen]
	}
	// Truncation can land mid-rune; dropping the remnant keeps the label valid
	// UTF-8 all the way through to the JSON the console renders.
	return strings.ToValidUTF8(code, "")
}

// methodOf derives the portfolio bucket from an issuer key.
//
// domain.Issuer always emits "<method>:<institution>", so the method is
// recoverable from the key alone and RecordOutcome needs no second parameter
// that a caller could pass inconsistently with the key it accompanies.
func methodOf(issuerKey string) string {
	if i := strings.IndexByte(issuerKey, ':'); i > 0 {
		return strings.ToLower(issuerKey[:i])
	}
	return "unknown"
}

const hexDigits = "0123456789ABCDEF"

// escapeSegment percent-encodes every byte outside a conservative allowlist.
//
// Two properties are required and neither is available from plain filtering.
// The encoding must be injective, or two issuers whose keys differ only in a
// stripped character would share one window. And the output must contain no
// glob metacharacter, because SnapshotAll matches keys with SCAN MATCH and a
// key holding "*" would otherwise be a merchant-supplied pattern inside an
// operator's query. Percent-encoding gives both, and is reversible so
// SnapshotAll can report the issuer key the caller originally passed.
func escapeSegment(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if !safeSegmentByte(s[i]) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if safeSegmentByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0F])
	}
	return b.String()
}

func unescapeSegment(s string) (string, error) {
	if !strings.ContainsRune(s, '%') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", errMalformedEscape
		}
		hi, err := hexValue(s[i+1])
		if err != nil {
			return "", err
		}
		lo, err := hexValue(s[i+2])
		if err != nil {
			return "", err
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

// safeSegmentByte allows ':' so the common issuer key shape survives unescaped
// and stays readable in redis-cli during an incident.
func safeSegmentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '@', ':':
		return true
	}
	return false
}

func hexValue(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	}
	return 0, errMalformedEscape
}

// newNonce derives the per-Recorder half of the member uniqueness suffix.
//
// crypto/rand is not expected to fail on any supported platform, but a Recorder
// carrying on with a zero nonce would collide with every other process's
// members and collapse their events into one, so the failure path derives a
// value that is still unique in practice rather than ignoring the error.
func newNonce(clock domain.Clock) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		v := uint64(clock.Now().UnixNano()) ^ (uint64(os.Getpid()) * 0x9E3779B97F4A7C15)
		binary.BigEndian.PutUint64(b[:], v)
	}
	return hex.EncodeToString(b[:])
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

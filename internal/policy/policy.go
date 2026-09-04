// Package policy is the deterministic arithmetic behind a recovery decision:
// which rail to fall back to, how long to wait before the next attempt, and
// what that attempt is worth in paisa.
//
// It is deliberately the dumbest package in the system. Every answer here has
// to be re-derivable from the same inputs years later, because these are the
// numbers a reviewer reconstructs when asking why a particular customer was
// charged a particular way. That rules out four things on purpose: model
// output, un-injected wall-clock reads, map iteration order, and floating-point
// money.
package policy

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Tunables that are part of the package's contract with its callers.
const (
	// MinBackoff keeps a retry from landing on the issuer while the failure
	// that produced it is still propagating through the issuer's own stack.
	MinBackoff = 5 * time.Second

	// MaxBackoff mirrors domain.MaxRecommendedDelay so a delay computed here
	// can never be rejected later by DiagnosticProposal.Validate. Deriving it
	// rather than restating it removes the chance of the two drifting.
	MaxBackoff = time.Duration(domain.MaxRecommendedDelay) * time.Second

	// SnapshotStaleAfter is three telemetry windows. Past it, the counts in a
	// snapshot describe an issuer that may since have recovered or collapsed,
	// so they stop contributing evidence. The breaker and degraded verdicts on
	// a stale snapshot are still honoured: stale good news is worthless, stale
	// bad news is the last thing anyone actually observed.
	SnapshotStaleAfter = 15 * time.Minute
)

// Input bounds. Issuer keys and counters originate in webhook payloads, so
// every one of them is treated as hostile and given a ceiling before it reaches
// arithmetic or a rendered string.
const (
	maxIssuerKeyLen     = 128
	maxRenderedKeyLen   = 48
	maxRailsScanned     = 32
	maxExclusionClauses = 3
	maxReasonLen        = 180
	maxBackoffDoublings = 64

	maxSamples     int64 = 1_000_000_000
	maxAmountPaisa int64 = 100_000_000_000_000 // keeps amount*10000 inside int64
	maxCostPaisa   int64 = 1_000_000_000_000
	maxEVAttempts  int64 = 1_000
)

// Reason vocabulary. The second return value of ChooseRail is rendered in the
// ops console and pushed to the browser inside domain.SessionEvent, so it is
// assembled exclusively from these templates plus integers and identifiers from
// closed sets. No model text and no raw payload text ever reaches it.
const (
	reasonHealthy     = "%s healthy at %d%% over %d samples"
	reasonPrior       = "%s selected on prior, no recent samples"
	reasonBreakerOpen = "%s breaker open"
	reasonDegraded    = "%s degraded to %d%%"
	reasonNoRail      = "no eligible alternate rail"
	reasonCancelled   = "policy evaluation cancelled"
)

// Engine implements domain.PolicyEngine.
type Engine struct {
	clock domain.Clock

	// rand.Rand is not safe for concurrent use and one Engine is shared by
	// every worker goroutine, so the source is owned by this mutex. A pool of
	// per-goroutine generators would be faster but would make the jitter
	// sequence depend on scheduling, destroying the reproducibility the
	// injected seed exists to provide.
	mu  sync.Mutex
	rng *rand.Rand
}

var _ domain.PolicyEngine = (*Engine)(nil)

// New builds an Engine. Both dependencies are injected rather than reached for:
// the clock so staleness decisions are testable without sleeping, and the
// generator so a benchmark run replays the exact same backoff schedule. Passing
// nil for either is legal and yields production defaults.
func New(clock domain.Clock, rng *rand.Rand) *Engine {
	if clock == nil {
		clock = systemClock{}
	}
	if rng == nil {
		// Seeded from the OS rather than from the clock: retry timing an
		// outsider can predict is a timing oracle for when an issuer is about
		// to be probed again.
		rng = rand.New(rand.NewSource(osSeed()))
	}
	return &Engine{clock: clock, rng: rng}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func osSeed() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// An unavailable entropy source must not stop the process from
		// starting; degraded jitter is still jitter, and every other guarantee
		// in this package is unaffected by the seed.
		return time.Now().UnixNano()
	}
	return int64(binary.BigEndian.Uint64(b[:]) &^ (1 << 63))
}

// ---------------------------------------------------------------------------
// Rail selection
// ---------------------------------------------------------------------------

// RailIssuerKeys returns the issuer keys in snapshots that belong to rail,
// sorted.
//
// Telemetry is keyed per issuer ("upi:okhdfcbank", "netbanking:HDFC") but a
// rail morph picks a method, not an institution: the customer's own bank
// decides the issuer afterwards. A rail's health is therefore the aggregate
// over its method's issuers. Sorting is not cosmetic. Go randomises map
// iteration, and an unsorted walk would make the chosen rail and its reason
// string differ between two runs on identical inputs.
func RailIssuerKeys(rail domain.Rail, snapshots map[string]domain.TelemetrySnapshot) []string {
	prefixes := railMethodPrefixes(rail)
	if len(prefixes) == 0 || len(snapshots) == 0 {
		return nil
	}
	out := make([]string, 0, len(snapshots))
	for k := range snapshots {
		if k == "" || len(k) > maxIssuerKeyLen {
			continue
		}
		lk := strings.ToLower(k)
		for _, p := range prefixes {
			if strings.HasPrefix(lk, p) {
				out = append(out, k)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// railMethodPrefixes maps a rail onto the telemetry key prefixes it draws from.
// Both UPI rails share one prefix because domain.PaymentEntity keys UPI
// telemetry by VPA handle: an okhdfcbank outage hits intent and collect alike,
// and pretending otherwise would let a morph "route around" a PSP failure by
// changing nothing that matters. EMI rides the card rails, so it folds in.
func railMethodPrefixes(r domain.Rail) []string {
	switch r {
	case domain.RailUPIIntent, domain.RailUPICollect:
		return []string{"upi:"}
	case domain.RailCard:
		return []string{"card:", "emi:"}
	case domain.RailNetbanking:
		return []string{"netbanking:"}
	case domain.RailWallet:
		return []string{"wallet:"}
	default:
		return nil
	}
}

type railScore struct {
	rail      domain.Rail
	attempts  int64
	successes int64
}

// Exclusion kinds are ordered by severity: it decides which clauses survive
// truncation of the reason string.
const (
	exclOpen = iota
	exclDegraded
)

type exclusion struct {
	key  string // already sanitised for rendering
	kind int
	pct  int64
}

func (x exclusion) text() string {
	if x.kind == exclOpen {
		return fmt.Sprintf(reasonBreakerOpen, x.key)
	}
	return fmt.Sprintf(reasonDegraded, x.key, x.pct)
}

// ChooseRail ranks the merchant's remaining rails by a Laplace-smoothed success
// estimate and returns the winner with an operator-facing justification.
//
// The smoothing is the whole point. A raw success rate makes a rail that has
// seen one successful payment (100%) outrank a rail with four hundred out of
// five hundred (80%), which is exactly how a naive router sends an outage's
// worth of traffic onto an untested rail. (s+1)/(n+2) prices that ignorance in:
// the one-sample rail scores 67% and loses, and it keeps losing until it has
// earned enough evidence to win on merit.
func (e *Engine) ChooseRail(ctx context.Context, current domain.Rail, available []domain.Rail, snapshots map[string]domain.TelemetrySnapshot) (domain.Rail, string) {
	if ctx.Err() != nil {
		// Shutdown or a blown deadline is not a reason to gamble on a rail the
		// engine did not finish evaluating.
		return domain.RailNone, reasonCancelled
	}
	now := e.clock.Now()

	var (
		cands    []railScore
		excluded []exclusion
		seenRail = make(map[domain.Rail]struct{}, len(available))
		seenExcl = make(map[string]struct{})
		scanned  int
	)

	for _, r := range available {
		if scanned >= maxRailsScanned {
			break
		}
		scanned++
		if r == current || r == domain.RailNone || !r.Valid() {
			continue
		}
		if _, dup := seenRail[r]; dup {
			continue
		}
		seenRail[r] = struct{}{}

		keys := RailIssuerKeys(r, snapshots)
		var attempts, successes int64
		var known, blocked int

		for _, k := range keys {
			v := assess(now, snapshots[k])
			known++
			switch {
			case v.open:
				blocked++
				addExclusion(&excluded, seenExcl, exclusion{key: sanitizeIssuerKey(k), kind: exclOpen})
			case v.degraded:
				blocked++
				addExclusion(&excluded, seenExcl, exclusion{
					key:  sanitizeIssuerKey(k),
					kind: exclDegraded,
					pct:  observedPct(v.successes, v.attempts),
				})
			case v.fresh:
				attempts += v.attempts
				successes += v.successes
			}
		}

		// A rail is unusable only when every issuer there is evidence for is
		// unusable. Dropping netbanking entirely because one bank tripped would
		// hand the outage a second victim; dropping it once all of them have
		// tripped is the fail-closed case that actually matters.
		if known > 0 && blocked == known {
			continue
		}

		attempts = clampCount(attempts)
		successes = clampCount(successes)
		if successes > attempts {
			successes = attempts
		}
		cands = append(cands, railScore{rail: r, attempts: attempts, successes: successes})
	}

	if len(cands) == 0 {
		return domain.RailNone, buildReason(reasonNoRail, excluded)
	}

	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		// Cross-multiplied comparison of (s+1)/(n+2). Comparing the two
		// divisions as float64 would let arithmetically equal scores land on
		// either side of the tie-break depending on rounding, and the tie-break
		// is what makes this function reproducible.
		lhs := (a.successes + 1) * (b.attempts + 2)
		rhs := (b.successes + 1) * (a.attempts + 2)
		if lhs != rhs {
			return lhs > rhs
		}
		return a.rail < b.rail
	})

	best := cands[0]
	head := fmt.Sprintf(reasonPrior, best.rail)
	if best.attempts > 0 {
		head = fmt.Sprintf(reasonHealthy, best.rail, smoothedPct(best.successes, best.attempts), best.attempts)
	}
	return best.rail, buildReason(head, excluded)
}

func addExclusion(dst *[]exclusion, seen map[string]struct{}, x exclusion) {
	id := fmt.Sprintf("%d/%s", x.kind, x.key)
	if _, dup := seen[id]; dup {
		return
	}
	seen[id] = struct{}{}
	*dst = append(*dst, x)
}

func buildReason(head string, excluded []exclusion) string {
	sort.Slice(excluded, func(i, j int) bool {
		if excluded[i].kind != excluded[j].kind {
			return excluded[i].kind < excluded[j].kind
		}
		return excluded[i].key < excluded[j].key
	})
	parts := make([]string, 0, 1+maxExclusionClauses)
	parts = append(parts, head)
	for i, x := range excluded {
		if i >= maxExclusionClauses {
			break
		}
		parts = append(parts, x.text())
	}
	s := strings.Join(parts, "; ")
	if len(s) > maxReasonLen {
		// Every byte here is ASCII by construction (fixed templates, decimal
		// integers, sanitised keys), so a byte cut cannot split a rune.
		s = s[:maxReasonLen]
	}
	return s
}

// sanitizeIssuerKey bounds and filters an issuer key before it is embedded in a
// reason string. Issuer keys derive from webhook-supplied bank codes and VPA
// handles, and the reason string ends up in an SSE frame rendered by a browser
// and in the audit ledger. Characters outside the key alphabet are dropped
// rather than escaped: no legitimate issuer key needs them, and dropping cannot
// be undone by a downstream decoder the way an escape can.
func sanitizeIssuerKey(k string) string {
	var b strings.Builder
	for i := 0; i < len(k) && b.Len() < maxRenderedKeyLen; i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == ':', c == '_', c == '-', c == '.':
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// snapshotView is the sanitised, integer reading of one telemetry snapshot.
type snapshotView struct {
	open      bool
	degraded  bool
	fresh     bool
	attempts  int64
	successes int64
}

func assess(now time.Time, snap domain.TelemetrySnapshot) snapshotView {
	attempts := clampCount(int64(snap.Attempts))
	successes := clampCount(int64(snap.Successes))
	if successes > attempts {
		// A snapshot claiming more successes than attempts is corrupt; trusting
		// the smaller number is the only direction that cannot inflate a rail's
		// score.
		successes = attempts
	}
	return snapshotView{
		open:      strings.EqualFold(strings.TrimSpace(string(snap.BreakerState)), string(domain.BreakerOpen)),
		degraded:  snap.Degraded(),
		fresh:     !stale(now, snap.SampledAt),
		attempts:  attempts,
		successes: successes,
	}
}

func stale(now, sampledAt time.Time) bool {
	if sampledAt.IsZero() {
		// The producer did not stamp the read, so there is nothing to age it
		// against. Treating an unstamped snapshot as expired would blind the
		// engine to every caller that assembles snapshots by hand.
		return false
	}
	return now.Sub(sampledAt) > SnapshotStaleAfter
}

// smoothedPct renders the Laplace estimate as a whole percent, rounded half up,
// using integers only so the figure quoted in the audit trail is bit-identical
// on every platform.
func smoothedPct(successes, attempts int64) int64 {
	return ((successes+1)*1000/(attempts+2) + 5) / 10
}

func observedPct(successes, attempts int64) int64 {
	if attempts <= 0 {
		return 0
	}
	return (successes*1000/attempts + 5) / 10
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

// BackoffCeiling is the pre-jitter upper bound that BackoffFor samples under.
//
// It is exported and kept separate from BackoffFor because it is the half that
// is assertable: a jittered draw is a random variable, but the bound it is
// drawn from must be monotone in attempt and must respect the clamp. It is also
// what an operator console means by "next retry within N".
func BackoffCeiling(attempt int, class domain.FailureClass, snap domain.TelemetrySnapshot) time.Duration {
	seconds := baseBackoffSeconds(class)
	if class == domain.ClassIssuerOutage {
		seconds *= outageDepth(snap)
	}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > maxBackoffDoublings {
		attempt = maxBackoffDoublings
	}
	limit := int64(domain.MaxRecommendedDelay)
	// Doubling in a bounded loop instead of shifting by (attempt-1): the shift
	// overflows int64 well before attempt reaches a value a caller could not
	// supply, and an overflowed ceiling silently becomes a five-second retry
	// storm against an issuer that is already down.
	for i := 1; i < attempt && seconds < limit; i++ {
		seconds *= 2
	}
	if seconds > limit {
		seconds = limit
	}
	d := time.Duration(seconds) * time.Second
	if d < MinBackoff {
		d = MinBackoff
	}
	return d
}

// baseBackoffSeconds is the first-attempt delay for each causal class. The
// spread between them is the point: a network timeout is probably already over,
// an issuer outage is measured in hours, and an insufficient-funds decline is a
// bet on payday rather than on infrastructure.
func baseBackoffSeconds(class domain.FailureClass) int64 {
	switch class {
	case domain.ClassNetworkTimeout:
		return 15
	case domain.ClassTransientDegradation:
		return 60
	case domain.ClassPSPDegradation:
		return 300
	case domain.ClassIssuerOutage:
		return 900
	case domain.ClassCustomerAction:
		return 3600
	case domain.ClassInsufficientFunds:
		return 86400
	default:
		// PERMANENT_INSTRUMENT_FAILURE and UNKNOWN are not Recoverable(), so
		// the gatekeeper abstains before one is ever scheduled. If a caller
		// asks anyway, the answer is the longest delay the system can express
		// rather than a prompt retry against an instrument that will never work.
		return int64(domain.MaxRecommendedDelay)
	}
}

// outageDepth scales an issuer-outage backoff by how far gone the issuer looks.
// It reads the raw counters rather than the snapshot's float SuccessRate so the
// multiplier cannot flip on a rounding difference between two producers.
func outageDepth(snap domain.TelemetrySnapshot) int64 {
	if strings.EqualFold(strings.TrimSpace(string(snap.BreakerState)), string(domain.BreakerOpen)) {
		// The breaker has already concluded the issuer is down and is shedding
		// load. Retrying on the normal schedule just refills the queue it is
		// trying to drain.
		return 4
	}
	if !snap.Degraded() {
		return 1
	}
	attempts := clampCount(int64(snap.Attempts))
	successes := clampCount(int64(snap.Successes))
	if successes > attempts {
		successes = attempts
	}
	if attempts > 0 && successes*10000/attempts < 500 {
		return 4 // sub-5% success is an outage, not a wobble
	}
	return 2
}

// BackoffFor draws the next delay uniformly from [MinBackoff, ceiling]: full
// jitter, bounded by the class's exponential schedule.
//
// The floor is applied to the sampling range rather than by clamping the draw
// afterwards. That looks equivalent and is not: clamping collapses every
// sub-floor draw onto the same instant, so on a short-base class roughly a
// third of the retries from one failed batch would fire simultaneously at
// exactly five seconds. That synchronised herd is the precise thing jitter
// exists to break up.
func (e *Engine) BackoffFor(ctx context.Context, attempt int, class domain.FailureClass, snap domain.TelemetrySnapshot) time.Duration {
	ceiling := BackoffCeiling(attempt, class, snap)
	if ctx.Err() != nil {
		// Cancellation means shutdown. Returning the full ceiling makes a
		// restarting fleet spread out instead of converging on the floor.
		return ceiling
	}
	if ceiling <= MinBackoff {
		return MinBackoff
	}
	span := int64(ceiling - MinBackoff)

	e.mu.Lock()
	jitter := e.rng.Int63n(span + 1)
	e.mu.Unlock()

	return MinBackoff + time.Duration(jitter)
}

// ---------------------------------------------------------------------------
// Expected value
// ---------------------------------------------------------------------------

// ExpectedValue prices one recovery attempt in paisa:
//
//	(amount * probBps)/10000 - attempts*gatewayFee - sessionFriction
//
// Floats are banned from this computation, and the ban is not stylistic. Paisa
// are exact integers; float64 cannot represent most decimal fractions of one,
// and float addition is not associative, so the same set of incidents summed in
// a different order yields a different total. A benchmark that reports a
// recovered-value figure has to be reproducible to the paisa or it is not
// evidence, and a ledger whose totals depend on goroutine scheduling is not
// auditable. successProb is the single float input and it is converted to basis
// points once, at the boundary; every operation after that is exact.
//
// Division truncates toward zero, so the gross figure always rounds down. That
// is the conservative direction: the system never overstates what a retry is
// worth and so never talks itself into an attempt on a rounding artefact.
//
// CommsCostPerMessagePaisa and CompliancePenaltyPaisa are deliberately absent.
// Both are conditional on the action finally chosen (an out-of-band message, a
// mandate violation), which this function cannot see. They are charged by the
// executor and the benchmark where they are actually incurred, so guessing at
// them here would double-count.
func (e *Engine) ExpectedValue(ctx context.Context, amountPaisa int64, successProb float64, attempts int, costs domain.CostModel) int64 {
	probBps := probToBasisPoints(successProb)
	if ctx.Err() != nil {
		// Fail closed: with the caller shutting down the attempt is worth
		// nothing and only its costs remain, so no caller can read a positive
		// expected value out of a cancelled evaluation.
		probBps = 0
	}

	amount := clamp64(amountPaisa, 0, maxAmountPaisa)
	fee := clamp64(costs.GatewayFeePerAttemptPaisa, 0, maxCostPaisa)
	friction := clamp64(costs.SessionFrictionPaisa, 0, maxCostPaisa)
	n := clamp64(int64(attempts), 0, maxEVAttempts)

	gross := (amount * probBps) / 10000
	return gross - n*fee - friction
}

// probToBasisPoints converts the one float the engine accepts into an exact
// integer, rounding half up. NaN is rejected explicitly because it satisfies
// neither ordering comparison and its conversion to int64 is undefined.
func probToBasisPoints(p float64) int64 {
	if math.IsNaN(p) || p <= 0 {
		return 0
	}
	if p >= 1 {
		return 10000
	}
	return clamp64(int64(p*10000+0.5), 0, 10000)
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

func clamp64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampCount bounds a counter so the cross-multiplied rank comparison stays
// inside int64 no matter what a compromised or buggy telemetry store reports.
func clampCount(v int64) int64 { return clamp64(v, 0, maxSamples) }

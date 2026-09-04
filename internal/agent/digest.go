package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"sort"
	"strings"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// digestVersion is absorbed first so a future change to the projection yields a
// disjoint key space. Without it an old corpus would keep matching after the
// projection changed, and the replay tier would answer with a cassette that was
// never recorded for the context it is now being asked about.
const digestVersion = "rmesh-ctx-v1"

const (
	maxCodeLen   = 64
	maxIssuerLen = 128

	// Downtime notices and error-code histograms are attacker-adjacent in
	// volume if not in content: an issuer flapping under load can emit dozens.
	// Truncating after a canonical sort keeps the digest cost constant.
	maxDigestDowntimes = 8
	maxDigestCodes     = 5
)

// ContextDigest is the cassette key: SHA-256 over a canonical, bucketed
// projection of the diagnostic context.
//
// Two properties are load-bearing. Free text is excluded outright, so a party
// who controls error_reason can neither steer nor fragment the cassette key
// space, and no attacker-supplied text is ever written into the corpus. And
// every continuous value is bucketed, so a few hundred cassettes cover the
// state space instead of each distinct success rate minting a fresh key.
//
// Every variable-length field is absorbed length-prefixed. Plain concatenation
// would let two different projections hash identically by shifting a delimiter
// (issuer "a:b" + code "c" versus issuer "a" + code "b:c").
func ContextDigest(dc domain.DiagnosticContext) string {
	h := sha256.New()
	absorbStr(h, digestVersion)

	absorbStr(h, normToken(dc.ErrorCode, maxCodeLen))
	absorbStr(h, normToken(dc.Method, maxCodeLen))
	absorbStr(h, normToken(dc.IssuerKey, maxIssuerLen))
	absorbStr(h, normToken(dc.AmountBand, maxCodeLen))
	absorbBool(h, dc.IsRecurring)
	absorbBool(h, dc.SessionActive)
	absorbInt(h, bucketAttempt(dc.AttemptNumber))

	t := dc.Telemetry
	absorbInt(h, bucketRate(t.SuccessRate))
	absorbInt(h, bucketRate(t.BaselineRate))
	absorbInt(h, bucketSamples(t.Attempts))
	absorbBool(h, t.Degraded())
	absorbStr(h, normToken(string(t.BreakerState), maxCodeLen))

	codes := make([]domain.CodeCount, len(t.TopErrorCodes))
	copy(codes, t.TopErrorCodes)
	domain.SortCodeCounts(codes)
	if len(codes) > maxDigestCodes {
		codes = codes[:maxDigestCodes]
	}
	absorbInt(h, len(codes))
	for _, c := range codes {
		absorbStr(h, normToken(c.Code, maxCodeLen))
		absorbInt(h, bucketSamples(c.Count))
	}

	// Downtime notices arrive in poll order, which is not stable across runs.
	// Rendering each to a fixed shape and sorting the renders is what makes the
	// digest order-independent.
	signals := make([]string, 0, len(dc.Downtimes))
	for _, d := range dc.Downtimes {
		signals = append(signals, fmt.Sprintf("%s|%s|%s|%s|%t|%t|%d",
			normToken(d.TelemetryKey, maxIssuerLen),
			normToken(d.Method, maxCodeLen),
			normSeverity(d.Severity),
			normStatus(d.Status),
			d.Scheduled,
			d.MatchesIssuer,
			bucketAge(d.AgeSeconds),
		))
	}
	sort.Strings(signals)
	if len(signals) > maxDigestDowntimes {
		signals = signals[:maxDigestDowntimes]
	}
	absorbInt(h, len(signals))
	for _, s := range signals {
		absorbStr(h, s)
	}

	// The rail set bounds what any tier is allowed to propose, so two contexts
	// offering different rails are genuinely different questions.
	rails := normRails(dc.AvailableRails)
	absorbInt(h, len(rails))
	for _, r := range rails {
		absorbStr(h, string(r))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// bucketRate rounds a rate to the nearest 0.1. A non-finite or out-of-range
// input gets its own bucket rather than collapsing to zero, so a broken
// telemetry read never silently keys to the same cassette as a healthy issuer
// at 0% success.
func bucketRate(r float64) int {
	if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 || r > 1 {
		return -1
	}
	return int(math.Round(r * 10))
}

// bucketSamples splits sample counts at the boundaries that change meaning:
// below the Degraded() sample floor of 8 no rate is trustworthy, and past a
// couple of hundred observations more data does not change the conclusion.
func bucketSamples(n int) int {
	switch {
	case n <= 0:
		return 0
	case n < 8:
		return 1
	case n < 50:
		return 2
	case n < 200:
		return 3
	default:
		return 4
	}
}

// bucketAge collapses downtime age into "just started", "minutes", "under an
// hour", "long running" — the resolution at which the answer actually differs.
func bucketAge(sec int64) int {
	switch {
	case sec <= 60:
		return 0
	case sec <= 300:
		return 1
	case sec <= 1800:
		return 2
	default:
		return 3
	}
}

// bucketAttempt clamps the attempt counter. The gatekeeper stops recovery at
// MESH_MAX_ATTEMPTS (3), so distinguishing attempt 7 from attempt 40 would only
// inflate the corpus.
func bucketAttempt(n int) int {
	switch {
	case n < 0:
		return 0
	case n > 6:
		return 6
	default:
		return n
	}
}

func normSeverity(s domain.DowntimeSeverity) string {
	switch s {
	case domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow:
		return string(s)
	default:
		return "unknown"
	}
}

func normStatus(s domain.DowntimeStatus) string {
	switch s {
	case domain.DowntimeScheduled, domain.DowntimeStarted, domain.DowntimeResolved, domain.DowntimeUpdated:
		return string(s)
	default:
		return "unknown"
	}
}

// normToken folds a low-cardinality identifier to its canonical form: the same
// character allowlist the prompt builder uses, lower-cased so that "card:HDFC"
// and "card:hdfc" address one cassette rather than two.
func normToken(s string, max int) string {
	return strings.ToLower(sanitizeToken(s, max))
}

// normRails deduplicates and sorts the offered rails, mapping anything
// unrecognised to RailNone, so caller-side ordering never affects the key.
func normRails(rails []domain.Rail) []domain.Rail {
	seen := make(map[domain.Rail]struct{}, len(rails))
	out := make([]domain.Rail, 0, len(rails))
	for _, r := range rails {
		p := domain.ParseRail(string(r))
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// hash.Hash is documented never to return an error from Write, which is why
// these helpers can absorb without an error path.
func absorb(h hash.Hash, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

func absorbStr(h hash.Hash, s string) { absorb(h, []byte(s)) }

func absorbInt(h hash.Hash, v int) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(int64(v)))
	absorb(h, b[:])
}

func absorbBool(h hash.Hash, v bool) {
	if v {
		absorb(h, []byte{1})
		return
	}
	absorb(h, []byte{0})
}

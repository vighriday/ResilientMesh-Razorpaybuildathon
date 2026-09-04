package simulation

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"
)

// Injected-fault sentinels. They are ordinary errors returned through the
// ordinary port signatures, because the whole value of injecting them is that
// production code takes its ordinary error path: a fault the system under test
// can recognise as "a test" is not a fault, it is a hint.
var (
	// ErrQueueUnavailable stands in for a Redis outage. The system's required
	// response is to keep accepting webhooks and let the outbox grow, not to
	// fail the edge.
	ErrQueueUnavailable = errors.New("simulation: queue unavailable")

	// ErrPublishLost stands in for a publish that never reached the broker.
	// The outbox row must stay claimable so the relay tries again.
	ErrPublishLost = errors.New("simulation: publish lost in transit")

	// ErrStoreUnavailable stands in for a database error mid-transaction. Every
	// caller must treat it as "nothing was written".
	ErrStoreUnavailable = errors.New("simulation: store unavailable")

	// ErrStoreClosed is returned after Close, so a use-after-close is a visible
	// failure rather than a silently successful no-op.
	ErrStoreClosed = errors.New("simulation: store closed")
)

// ChaosProfile is a named fault intensity. Profiles are fixed rather than
// free-form probabilities so that a reported result — "seed 20260904, profile
// standard, 400 incidents, no violation" — names an exact experiment somebody
// else can rerun.
type ChaosProfile struct {
	Name string

	// PublishLoss is the chance one relay publish never reaches the broker.
	PublishLoss float64
	// BrokerDrop is the chance an accepted message is lost by the broker after
	// the producer was told it landed. This is the at-most-once hazard that
	// motivates the reconciler; without a reconciler it silently strands
	// incidents.
	BrokerDrop float64
	// DuplicateDelivery is the chance a consumed message is redelivered to a
	// second consumer, i.e. at-least-once semantics doing what they promise.
	DuplicateDelivery float64
	// WorkerDeath is the chance a worker dies mid-message after the durable
	// attempt fence and before the ack.
	WorkerDeath float64
	// StoreError is the chance a store transaction or read fails.
	StoreError float64
	// QueueOutage is the chance, per relay tick, that the broker goes down for
	// a bounded window.
	QueueOutage float64
	// SlowConsumer is the chance an SSE subscriber fails to drain its buffer on
	// a tick, which must cost the subscriber frames and never block the
	// publisher.
	SlowConsumer float64
	// ClockSkew is the chance a worker's clock jumps, and the bound on the jump.
	ClockSkew    float64
	MaxClockSkew time.Duration

	// OutageWindow bounds an injected broker outage.
	MinOutage time.Duration
	MaxOutage time.Duration
}

// profiles is the closed set of chaos intensities.
//
// "standard" is the default because a run with no faults proves only that the
// happy path is deterministic, which is the least interesting property the
// harness can establish.
var profiles = map[string]ChaosProfile{
	"none": {Name: "none"},
	"light": {
		Name:              "light",
		PublishLoss:       0.01,
		BrokerDrop:        0.002,
		DuplicateDelivery: 0.01,
		WorkerDeath:       0.005,
		StoreError:        0.005,
		QueueOutage:       0.01,
		SlowConsumer:      0.05,
		ClockSkew:         0.01,
		MaxClockSkew:      2 * time.Second,
		MinOutage:         2 * time.Second,
		MaxOutage:         10 * time.Second,
	},
	"standard": {
		Name:              "standard",
		PublishLoss:       0.05,
		BrokerDrop:        0.01,
		DuplicateDelivery: 0.05,
		WorkerDeath:       0.02,
		StoreError:        0.02,
		QueueOutage:       0.03,
		SlowConsumer:      0.15,
		ClockSkew:         0.05,
		MaxClockSkew:      30 * time.Second,
		MinOutage:         5 * time.Second,
		MaxOutage:         45 * time.Second,
	},
	"storm": {
		Name:              "storm",
		PublishLoss:       0.15,
		BrokerDrop:        0.04,
		DuplicateDelivery: 0.20,
		WorkerDeath:       0.08,
		StoreError:        0.08,
		QueueOutage:       0.10,
		SlowConsumer:      0.40,
		ClockSkew:         0.15,
		MaxClockSkew:      5 * time.Minute,
		MinOutage:         15 * time.Second,
		MaxOutage:         3 * time.Minute,
	},
}

// ProfileNames lists the available chaos profiles in a stable order, for flag
// help and error messages.
func ProfileNames() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Profile resolves a profile by name. An unknown name is an error rather than a
// silent fallback to "none": a typo that quietly disables all fault injection
// would turn a green run into a lie.
func Profile(name string) (ChaosProfile, error) {
	p, ok := profiles[name]
	if !ok {
		return ChaosProfile{}, fmt.Errorf("simulation: unknown chaos profile %q, want one of %v", name, ProfileNames())
	}
	return p, nil
}

// faultKind names an injected fault for the counters and the trace.
type faultKind string

const (
	faultPublishLoss  faultKind = "publish_loss"
	faultBrokerDrop   faultKind = "broker_drop"
	faultDuplicate    faultKind = "duplicate_delivery"
	faultWorkerDeath  faultKind = "worker_death"
	faultStoreError   faultKind = "store_error"
	faultQueueOutage  faultKind = "queue_outage"
	faultSlowConsumer faultKind = "slow_consumer"
	faultClockSkew    faultKind = "clock_skew"
)

var allFaultKinds = []faultKind{
	faultBrokerDrop, faultClockSkew, faultDuplicate, faultPublishLoss,
	faultQueueOutage, faultSlowConsumer, faultStoreError, faultWorkerDeath,
}

// Injector is the single source of injected faults. Every draw comes off one
// generator in the order the single-goroutine scheduler makes the calls, which
// is what makes the fault schedule itself a pure function of the seed.
type Injector struct {
	rng    *rand.Rand
	prof   ChaosProfile
	counts map[faultKind]int64
}

// NewInjector builds an injector over a generator the caller seeded from the
// run's single entropy root.
func NewInjector(rng *rand.Rand, prof ChaosProfile) *Injector {
	return &Injector{rng: rng, prof: prof, counts: make(map[faultKind]int64, len(allFaultKinds))}
}

// Profile returns the active profile, for the run summary.
func (f *Injector) Profile() ChaosProfile { return f.prof }

// hit draws once against p. The draw is taken even when p is zero would make it
// pointless — no: it is deliberately skipped, because taking a draw for a
// disabled fault would make the "none" profile's random stream differ from the
// others' for no benefit, and profiles are compared against each other.
func (f *Injector) hit(kind faultKind, p float64) bool {
	if p <= 0 {
		return false
	}
	if f.rng.Float64() >= p {
		return false
	}
	f.counts[kind]++
	return true
}

// PublishLost reports whether this publish attempt should fail in transit.
func (f *Injector) PublishLost() bool { return f.hit(faultPublishLoss, f.prof.PublishLoss) }

// BrokerDropped reports whether the broker accepted and then lost the message.
func (f *Injector) BrokerDropped() bool { return f.hit(faultBrokerDrop, f.prof.BrokerDrop) }

// DuplicateDelivery reports whether a consumed message is also redelivered.
func (f *Injector) DuplicateDelivery() bool {
	return f.hit(faultDuplicate, f.prof.DuplicateDelivery)
}

// WorkerDied reports whether the worker dies before acking the current message.
func (f *Injector) WorkerDied() bool { return f.hit(faultWorkerDeath, f.prof.WorkerDeath) }

// StoreFailed reports whether this store operation fails.
func (f *Injector) StoreFailed() bool { return f.hit(faultStoreError, f.prof.StoreError) }

// SlowConsumer reports whether a subscriber fails to drain this tick.
func (f *Injector) SlowConsumer() bool { return f.hit(faultSlowConsumer, f.prof.SlowConsumer) }

// QueueOutage returns a broker outage duration, or zero for no outage.
func (f *Injector) QueueOutage() time.Duration {
	if !f.hit(faultQueueOutage, f.prof.QueueOutage) {
		return 0
	}
	return f.durationBetween(f.prof.MinOutage, f.prof.MaxOutage)
}

// ClockSkew returns a signed offset to apply to a component's clock, or zero.
//
// Skew is bounded and symmetric on purpose. Unbounded skew would let the
// simulation "disprove" invariants that no real deployment can violate, which
// produces noise instead of findings; bounded skew reproduces the realistic
// case where two hosts disagree by seconds and a naive absolute-deadline
// scheduler quietly shortens a regulatory window.
func (f *Injector) ClockSkew() time.Duration {
	if !f.hit(faultClockSkew, f.prof.ClockSkew) {
		return 0
	}
	max := f.prof.MaxClockSkew
	if max <= 0 {
		return 0
	}
	d := time.Duration(f.rng.Int63n(int64(max) + 1))
	if f.rng.Intn(2) == 0 {
		return -d
	}
	return d
}

func (f *Injector) durationBetween(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(f.rng.Int63n(int64(hi-lo)+1))
}

// Counts renders the injected-fault tally in a stable order for the run summary
// and the trace. A chaos run whose counts are all zero is a configuration bug,
// and printing them is how that gets noticed.
func (f *Injector) Counts() []Field {
	out := make([]Field, 0, len(allFaultKinds))
	for _, k := range allFaultKinds {
		out = append(out, Fi(string(k), f.counts[k]))
	}
	return out
}

// Total is the number of faults injected across all kinds.
func (f *Injector) Total() int64 {
	var n int64
	for _, k := range allFaultKinds {
		n += f.counts[k]
	}
	return n
}

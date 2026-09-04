package modelcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
)

// timeLayout renders instants in reports. RFC3339 in UTC keeps a witness
// comparable across machines and time zones.
const timeLayout = time.RFC3339

// DefaultMaxStates bounds the exploration. It sits comfortably above the
// abstract product, so the default run is exhaustive rather than truncated; it
// exists so that widening a dimension turns into a reported bound instead of a
// run that never finishes.
const DefaultMaxStates = 4_000_000

// DefaultMaxWitnesses bounds how many concrete counterexamples a report
// carries per invariant. A breached invariant is typically breached in a large
// fraction of the space, and an unbounded witness list would bury the finding
// under its own evidence.
const DefaultMaxWitnesses = 8

// DefaultClockAt anchors the virtual clock. It is a constant rather than
// time.Now() because the whole value of this package is that two runs, on two
// machines, on two days, produce the same numbers.
var DefaultClockAt = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// Config parameterises a model-checking run. The zero value is a complete,
// exhaustive, deterministic run against the real gatekeeper.
type Config struct {
	// ClockAt pins the gate's clock. Zero means DefaultClockAt.
	ClockAt time.Time

	// MaxStates bounds the number of distinct states admitted to the frontier.
	// Zero means DefaultMaxStates. Reaching it does not silently truncate: the
	// report is marked bounded and says where it stopped.
	MaxStates int

	// MaxWitnesses bounds recorded counterexamples per invariant. Zero means
	// DefaultMaxWitnesses; negative means none.
	MaxWitnesses int

	// GateConfig is handed to the real gatekeeper when Gate is nil.
	GateConfig gatekeeper.Config

	// Gate builds the decision component under test. Nil means the real
	// internal/gatekeeper with a nil policy engine, whose documented
	// jitter-free fallback backoff is what makes the exploration reproducible.
	//
	// It is a seam for one purpose: a checker that has never seen a violation
	// is indistinguishable from a checker that cannot see one, so the test
	// suite substitutes a deliberately broken gate and requires the invariants
	// to catch it.
	Gate func(clock domain.Clock) domain.Gatekeeper
}

func (c Config) withDefaults() Config {
	if c.ClockAt.IsZero() {
		c.ClockAt = DefaultClockAt
	}
	if c.MaxStates <= 0 {
		c.MaxStates = DefaultMaxStates
	}
	if c.MaxWitnesses == 0 {
		c.MaxWitnesses = DefaultMaxWitnesses
	}
	if c.MaxWitnesses < 0 {
		c.MaxWitnesses = 0
	}
	if c.Gate == nil {
		gcfg := c.GateConfig
		c.Gate = func(clock domain.Clock) domain.Gatekeeper {
			return gatekeeper.New(clock, nil, gcfg)
		}
	}
	return c
}

// InvariantReport is the per-property outcome of a run.
type InvariantReport struct {
	Name       string `json:"name"`
	Why        string `json:"why"`
	Checked    int64  `json:"states_checked"`
	Violations int64  `json:"violations"`
}

// Violation is one concrete counterexample: the abstract state, the command the
// real gatekeeper produced for it, and why that command breaks the property.
type Violation struct {
	Invariant string      `json:"invariant"`
	Detail    string      `json:"detail"`
	State     StateView   `json:"state"`
	Command   CommandView `json:"command"`
}

// Reachability summarises the shape of the reachable set rather than its size.
// A bare state count is not checkable — any number looks plausible — whereas
// these aggregates state facts about what the system's dynamics can and cannot
// produce, and each of them is a safety property in its own right.
type Reachability struct {
	// AttemptHistogram counts reachable states by attempts-in-cycle. Its
	// entries past the mandate cycle cap must be zero: the only transition that
	// increments the counter is an executable command, and the gate refuses to
	// emit one at the cap.
	AttemptHistogram []int64 `json:"attempts_in_cycle_histogram"`
	// HaltedStates is how many reachable states carry a halted mandate.
	HaltedStates int64 `json:"halted_states"`
	// HaltedBelowCycleCap must be zero: a mandate is halted by the cycle-cap
	// verdict and never un-halted, so a halted state below the cap would mean
	// something else halted it.
	HaltedBelowCycleCap int64 `json:"halted_states_below_cycle_cap"`
	// PostAttemptClockSkew must be zero: an attempt resets the clock to the
	// present, so no state that has attempted anything can still be observing a
	// future-dated mandate row.
	PostAttemptClockSkew int64 `json:"post_attempt_clock_skew_states"`
}

// Report is the result of a run. Every count in it is a function of the code
// under test alone, so two runs of the same binary must produce the same
// Digest; ElapsedMS is the sole exception and is excluded from the digest for
// exactly that reason.
type Report struct {
	ClockAt         time.Time         `json:"clock_at"`
	ElapsedMS       int64             `json:"elapsed_ms"`
	AbstractStates  int64             `json:"abstract_states"`
	InitialStates   int64             `json:"initial_states"`
	ReachableStates int64             `json:"reachable_states"`
	UnreachedStates int64             `json:"unreached_abstract_states"`
	Transitions     int64             `json:"transitions"`
	Decisions       int64             `json:"gate_decisions"`
	MaxAttempts     int               `json:"gate_max_attempts"`
	MaxStates       int               `json:"max_states"`
	Bounded         bool              `json:"bounded"`
	BoundNote       string            `json:"bound_note,omitempty"`
	TotalViolations int64             `json:"total_violations"`
	Reachability    Reachability      `json:"reachability"`
	Invariants      []InvariantReport `json:"invariants"`
	Violations      []Violation       `json:"violations"`
	Digest          string            `json:"digest"`
}

// Passed reports whether every asserted property held at every state the run
// visited. It is deliberately not the same question as Complete: a bounded run
// with no violations has checked what it checked and proved nothing beyond it.
func (r Report) Passed() bool { return r.TotalViolations == 0 }

// Complete reports whether the exploration ran to fixpoint rather than stopping
// at the state bound.
func (r Report) Complete() bool { return !r.Bounded }

// Run explores the reachable abstract state space, driving the real gatekeeper
// at every state, and reports the invariants that held and the ones that did
// not. It is the entry point cmd/meshctl's verify-model subcommand should call.
func Run(cfg Config) (Report, error) { return RunContext(context.Background(), cfg) }

// RunContext is Run with cancellation, for a CLI or CI job that must be able to
// give up on a widened state space without being killed.
func RunContext(ctx context.Context, cfg Config) (Report, error) {
	cfg = cfg.withDefaults()
	started := time.Now()

	clock := fixedClock{at: cfg.ClockAt}
	gate := cfg.Gate(clock)
	if gate == nil {
		return Report{}, fmt.Errorf("modelcheck: Config.Gate returned no gatekeeper")
	}

	ex := &explorer{
		cfg:     cfg,
		gate:    gate,
		now:     cfg.ClockAt,
		visited: make(map[uint32]struct{}, 1<<20),
		counts:  make([]int64, len(invariants)+1),
		checked: make([]int64, len(invariants)+1),
	}

	frontier := seed()
	report := Report{
		ClockAt:        cfg.ClockAt,
		AbstractStates: AbstractStateCount(),
		InitialStates:  int64(len(frontier)),
		MaxStates:      cfg.MaxStates,
	}
	if len(frontier) > cfg.MaxStates {
		// The bound has to be enforced on the seed set too. Seeding past it and
		// only checking on discovery would let a small bound quietly explore
		// more states than the operator asked for.
		frontier = frontier[:cfg.MaxStates]
		report.Bounded = true
	}
	for _, k := range frontier {
		ex.visited[k] = struct{}{}
	}

	// A slice used as a FIFO. States are appended in sorted successor order and
	// consumed in order, so the traversal is a function of the transition
	// relation alone: no map iteration, no goroutine scheduling, no wall clock.
	var (
		succ    = make([]uint32, 0, 32)
		visits  int64
		lastErr error
	)
	for head := 0; head < len(frontier); head++ {
		if visits&0xFFF == 0 {
			if err := ctx.Err(); err != nil {
				return Report{}, fmt.Errorf("modelcheck: exploration cancelled after %d states: %w", visits, err)
			}
		}
		visits++

		key := frontier[head]
		state := StateFromKey(key)
		in := state.GateInput(ex.now)

		// Every decision call is one evaluation of the gate-error property, and
		// the calls that return a command are its passing checks. Counting only
		// the failures made a clean run report the property as checked at zero
		// states, which reads as "never evaluated" rather than "never violated".
		ex.checked[len(invariants)]++

		cmd, err := gate.Decide(ctx, in)
		if err != nil {
			// A gate that cannot decide a well-formed input has not abstained,
			// it has failed. Recording it as a violation and treating the state
			// as terminal keeps the run going without pretending the state was
			// checked.
			lastErr = err
			ex.recordGateError(state, err)
			continue
		}
		ex.assert(state, in, cmd)

		succ = ex.successors(state, cmd, succ[:0])
		report.Transitions += int64(len(succ))
		for _, k := range succ {
			if _, seen := ex.visited[k]; seen {
				continue
			}
			if len(ex.visited) >= cfg.MaxStates {
				report.Bounded = true
				continue
			}
			ex.visited[k] = struct{}{}
			frontier = append(frontier, k)
		}
	}

	report.ReachableStates = int64(len(ex.visited))
	report.UnreachedStates = report.AbstractStates - report.ReachableStates
	report.Decisions = visits
	report.MaxAttempts = ex.maxAttempts
	report.Reachability = summariseReachability(ex.visited, cfg.GateConfig.MandateCycleCap)
	if report.Bounded {
		report.BoundNote = fmt.Sprintf(
			"exploration stopped admitting new states at the %d-state bound; %d of %d abstract states were visited, "+
				"so the properties below are proved only over the visited subset",
			cfg.MaxStates, report.ReachableStates, report.AbstractStates)
	}

	report.Invariants = make([]InvariantReport, 0, len(invariants)+1)
	for i, inv := range invariants {
		report.Invariants = append(report.Invariants, InvariantReport{
			Name:       inv.name,
			Why:        inv.why,
			Checked:    ex.checked[i],
			Violations: ex.counts[i],
		})
		report.TotalViolations += ex.counts[i]
	}
	gateErrIdx := len(invariants)
	report.Invariants = append(report.Invariants, InvariantReport{
		Name:       InvGateError,
		Why:        "a decision call that errors on a well-formed input has produced no command to check",
		Checked:    ex.checked[gateErrIdx],
		Violations: ex.counts[gateErrIdx],
	})
	report.TotalViolations += ex.counts[gateErrIdx]

	report.Violations = ex.witnesses
	if report.Violations == nil {
		// An empty list rather than a JSON null: a consumer that ranges over
		// the field should not have to special-case a clean run.
		report.Violations = []Violation{}
	}
	report.Digest = digestOf(report)
	report.ElapsedMS = time.Since(started).Milliseconds()

	if lastErr != nil && report.TotalViolations == 0 {
		// Unreachable given recordGateError, and kept so that a future edit
		// which stops counting decision failures cannot make them disappear.
		return report, fmt.Errorf("modelcheck: gate decision failed without being recorded: %w", lastErr)
	}
	return report, nil
}

// explorer holds the mutable state of one run. It is confined to a single
// goroutine: parallelising the sweep would trade a reproducible traversal for
// wall-clock time this exploration does not need.
type explorer struct {
	cfg  Config
	gate domain.Gatekeeper
	now  time.Time

	visited map[uint32]struct{}

	// counts and checked are indexed by invariant position, with one extra slot
	// at the end for decision failures.
	counts  []int64
	checked []int64

	witnesses   []Violation
	witnessSeen map[string]int

	maxAttempts int
}

// seed builds the initial states: a fresh mandate — nothing attempted, nothing
// notified, not halted — observed under every combination of the inputs the
// environment controls at the moment the incident arrives.
//
// Starting from a fresh mandate rather than from the whole abstract product is
// what makes the reachable count a result instead of a restatement of the
// dimension sizes. States the system's own dynamics cannot produce stay out of
// the reachable set, and the report names how many those are.
func seed() []uint32 {
	seeds := make([]uint32, 0, 1<<16)
	for _, recurring := range []bool{false, true} {
		for category := range categories {
			for amount := range amountsPaisa {
				for hours := range hourBuckets {
					for breaker := range breakerStates {
						for _, session := range []bool{false, true} {
							for proposal := range proposals {
								for delay := range proposalDelaysSec {
									seeds = append(seeds, State{
										Recurring:   recurring,
										Category:    uint8(category),
										Amount:      uint8(amount),
										Attempts:    0,
										Hours:       uint8(hours),
										Notified:    false,
										Halted:      false,
										Breaker:     uint8(breaker),
										SessionLive: session,
										Proposal:    uint8(proposal),
										Delay:       uint8(delay),
									}.Key())
								}
							}
						}
					}
				}
			}
		}
	}
	slices.Sort(seeds)
	return slices.Compact(seeds)
}

// successors is the transition relation. Every edge models something the real
// system does: the recovery loop acting on the command just decided, or the
// environment moving underneath it between decisions.
//
// Successors are emitted in whatever order is convenient and then sorted and
// deduplicated, so the BFS order depends on the packed key ordering alone. That
// sort is the difference between a reproducible run and one whose counts drift
// with map layout.
func (ex *explorer) successors(s State, cmd domain.SanitizedCommand, buf []uint32) []uint32 {
	out := buf

	// The system's own step: execute the command that was just decided.
	next := s
	if cmd.Executable() {
		if next.Attempts < maxCycleAttempts {
			next.Attempts++
		}
		next.Hours = hourZeroIndex
		if cmd.PreDebitNotificationNeeded {
			// The executor delivers the notice before the debit, so a command
			// carrying the obligation leaves a notice on record.
			next.Notified = true
		}
	}
	// The cycle-cap verdict obliges the caller to halt the mandate whether or
	// not the command was executable.
	if gatekeeper.RequiresMandateHalt(cmd) {
		next.Halted = true
	}
	out = appendState(out, s, next)

	// Time passes between decisions. It only moves forward, and only until the
	// next attempt resets the clock, so the negative buckets are observations
	// rather than destinations.
	for h := int(s.Hours) + 1; h < len(hourBuckets); h++ {
		n := s
		n.Hours = uint8(h)
		out = appendState(out, s, n)
	}

	// The issuer breaker moves under its own FSM.
	for _, b := range breakerSuccessors[s.Breaker] {
		n := s
		n.Breaker = b
		out = appendState(out, s, n)
	}

	// The checkout session closes, or the customer opens a new one.
	{
		n := s
		n.SessionLive = !s.SessionLive
		out = appendState(out, s, n)
	}

	// The next diagnosis may recommend anything in — or outside — the action
	// vocabulary, and may ask for any of the delays.
	for p := range proposals {
		n := s
		n.Proposal = uint8(p)
		out = appendState(out, s, n)
	}
	for d := range proposalDelaysSec {
		n := s
		n.Delay = uint8(d)
		out = appendState(out, s, n)
	}

	// The notifier delivers a pre-debit notice out of band, independently of
	// any command.
	if !s.Notified {
		n := s
		n.Notified = true
		out = appendState(out, s, n)
	}

	// A new billing cycle starts: the per-cycle counter and the notice both
	// reset. A halted mandate has no next cycle.
	if s.Recurring && !s.Halted && (s.Attempts != 0 || s.Notified || s.Hours != hourZeroIndex) {
		n := s
		n.Attempts = 0
		n.Notified = false
		n.Hours = hourZeroIndex
		out = appendState(out, s, n)
	}

	slices.Sort(out)
	return slices.Compact(out)
}

// appendState drops self-loops: an edge from a state to itself is not a
// transition anyone can observe, and counting it would inflate the reported
// edge count without describing any behaviour.
func appendState(out []uint32, from, to State) []uint32 {
	if to == from {
		return out
	}
	return append(out, to.Key())
}

// assert evaluates every invariant at one state.
func (ex *explorer) assert(s State, in domain.GateInput, cmd domain.SanitizedCommand) {
	if ex.maxAttempts == 0 && cmd.MaxAttempts > 0 {
		ex.maxAttempts = cmd.MaxAttempts
	}
	c := checkInput{state: s, in: in, cmd: cmd, maxAttempts: ex.maxAttempts}
	for i, inv := range invariants {
		ex.checked[i]++
		if detail := inv.check(c); detail != "" {
			ex.counts[i]++
			ex.recordWitness(inv.name, detail, s, commandView(cmd))
		}
	}
}

func (ex *explorer) recordGateError(s State, err error) {
	ex.counts[len(invariants)]++
	ex.recordWitness(InvGateError, err.Error(), s, CommandView{})
}

// recordWitness keeps a bounded, deterministic sample of counterexamples per
// invariant. BFS order is deterministic, so "the first MaxWitnesses" is a
// stable selection rather than an arbitrary one.
func (ex *explorer) recordWitness(name, detail string, s State, cmd CommandView) {
	if ex.cfg.MaxWitnesses <= 0 {
		return
	}
	if ex.witnessSeen == nil {
		ex.witnessSeen = make(map[string]int, len(invariants)+1)
	}
	if ex.witnessSeen[name] >= ex.cfg.MaxWitnesses {
		return
	}
	ex.witnessSeen[name]++
	ex.witnesses = append(ex.witnesses, Violation{
		Invariant: name,
		Detail:    detail,
		State:     s.View(),
		Command:   cmd,
	})
}

// summariseReachability aggregates the visited set. Iterating a map is
// order-dependent, so every aggregate here is a sum or a max — nothing whose
// value could depend on the order the keys came out.
func summariseReachability(visited map[uint32]struct{}, cycleCap int) Reachability {
	if cycleCap <= 0 {
		cycleCap = gatekeeper.DefaultMandateCycleCap
	}
	r := Reachability{AttemptHistogram: make([]int64, maxCycleAttempts+1)}
	for k := range visited {
		s := StateFromKey(k)
		r.AttemptHistogram[s.Attempts]++
		if s.Halted {
			r.HaltedStates++
			if int(s.Attempts) < cycleCap {
				r.HaltedBelowCycleCap++
			}
		}
		if s.Attempts > 0 && s.Hours < hourZeroIndex {
			r.PostAttemptClockSkew++
		}
	}
	return r
}

// digestOf commits to everything about a run that the code under test
// determines. Two runs whose digests differ have explored different graphs,
// which is the fastest way to notice that a change made the exploration itself
// nondeterministic rather than merely changing an outcome.
func digestOf(r Report) string {
	var b strings.Builder
	b.WriteString("modelcheck/v1\n")
	b.WriteString("clock=" + r.ClockAt.UTC().Format(timeLayout) + "\n")
	b.WriteString("abstract=" + strconv.FormatInt(r.AbstractStates, 10) + "\n")
	b.WriteString("initial=" + strconv.FormatInt(r.InitialStates, 10) + "\n")
	b.WriteString("reachable=" + strconv.FormatInt(r.ReachableStates, 10) + "\n")
	b.WriteString("transitions=" + strconv.FormatInt(r.Transitions, 10) + "\n")
	b.WriteString("decisions=" + strconv.FormatInt(r.Decisions, 10) + "\n")
	b.WriteString("bounded=" + strconv.FormatBool(r.Bounded) + "\n")
	for i, n := range r.Reachability.AttemptHistogram {
		b.WriteString("attempts" + strconv.Itoa(i) + "=" + strconv.FormatInt(n, 10) + "\n")
	}
	b.WriteString("halted=" + strconv.FormatInt(r.Reachability.HaltedStates, 10) + "\n")
	b.WriteString("halted_below_cap=" + strconv.FormatInt(r.Reachability.HaltedBelowCycleCap, 10) + "\n")
	b.WriteString("post_attempt_skew=" + strconv.FormatInt(r.Reachability.PostAttemptClockSkew, 10) + "\n")
	for _, inv := range r.Invariants {
		b.WriteString("inv " + inv.Name + " " +
			strconv.FormatInt(inv.Checked, 10) + " " +
			strconv.FormatInt(inv.Violations, 10) + "\n")
	}
	for _, v := range r.Violations {
		b.WriteString("witness " + v.Invariant + " " +
			strconv.FormatUint(uint64(v.State.Key), 10) + " " + v.Detail + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// secondsDuration converts whole seconds to a Duration without overflowing on a
// hostile value. A gate under test is allowed to be wrong; it is not allowed to
// wrap the checker's own arithmetic into a passing comparison.
func secondsDuration(seconds int64) time.Duration {
	const maxSeconds = int64(1<<63-1) / int64(time.Second)
	switch {
	case seconds > maxSeconds:
		return time.Duration(1<<63 - 1)
	case seconds < -maxSeconds:
		return time.Duration(-1 << 63)
	default:
		return time.Duration(seconds) * time.Second
	}
}

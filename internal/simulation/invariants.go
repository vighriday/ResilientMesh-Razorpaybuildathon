package simulation

import (
	"fmt"
	"sort"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
)

// The invariant vocabulary. These names are what a failing seed reports and
// what a fuzz sweep aggregates, so they are stable identifiers rather than
// prose. Each one corresponds to money moving wrongly or to a regulatory
// breach — the distinction docs/SLO.md draws between an invariant and an
// objective is exactly why none of them has a tolerance.
const (
	// InvAmountPinned: every executed attempt debits the amount on the
	// HMAC-verified payload and nothing else.
	InvAmountPinned = "AMOUNT_PINNED"
	// InvRecurringCooling: consecutive debits on one mandate are at least the
	// RBI cooling window apart, measured in authoritative virtual time rather
	// than in any component's own possibly-skewed clock.
	InvRecurringCooling = "RECURRING_COOLING_WINDOW"
	// InvPreDebitNotice: no recurring debit without a notice already delivered.
	InvPreDebitNotice = "RBI_PRE_DEBIT_NOTICE"
	// InvAttemptCap: no incident exceeds its attempt ceiling.
	InvAttemptCap = "ATTEMPT_CAP"
	// InvAFACeiling: no automatic recurring debit above the category's
	// additional-factor-authentication ceiling.
	InvAFACeiling = "RBI_AFA_CEILING"
	// InvNoEventLost: every accepted event has durable incident and outbox rows,
	// and every incident eventually reaches a terminal state.
	InvNoEventLost = "NO_EVENT_LOST"
	// InvNoDoubleProcessing: one incident per event id, and one attempt per
	// attempt number.
	InvNoDoubleProcessing = "NO_DOUBLE_PROCESSING"
	// InvAuditChainLinear: the ledger is contiguous and every entry links to its
	// predecessor.
	InvAuditChainLinear = "AUDIT_CHAIN_LINEAR"
	// InvOutboxAccounting: outbox rows are conserved — every row is in exactly
	// one state and none vanishes.
	InvOutboxAccounting = "OUTBOX_ACCOUNTING"
)

// coolingWindowSeconds is the RBI 24-hour floor, taken from the gatekeeper's own
// constant rather than restated here. An invariant checked against a number the
// system under test does not use is not a check, it is a coincidence.
const coolingWindowSeconds = gatekeeper.DefaultMandateCoolingSeconds

const coolingWindowNanos = coolingWindowSeconds * int64(time.Second)

// Violation is a breached invariant, carrying everything needed to reproduce
// it: the seed replays the world, the step index locates the operation, and the
// virtual timestamp says when in simulated time it happened.
type Violation struct {
	Invariant   string    `json:"invariant"`
	Seed        int64     `json:"seed"`
	Step        int       `json:"step"`
	VirtualTime time.Time `json:"virtual_time"`
	Subject     string    `json:"subject"`
	Detail      string    `json:"detail"`
}

func (v Violation) Error() string {
	return fmt.Sprintf("invariant %s violated: seed=%d step=%d t=%s subject=%s: %s",
		v.Invariant, v.Seed, v.Step, v.VirtualTime.UTC().Format(time.RFC3339Nano),
		sanitizeTraceValue(v.Subject), v.Detail)
}

// Monitor evaluates the invariant set after every scheduler step.
//
// It is deliberately built from incremental cursors rather than a full sweep.
// A monitor that re-walked the audit chain and every attempt row on each of
// tens of thousands of steps would be quadratic, would dominate the run, and
// would push people towards checking less often — which is the opposite of what
// continuous verification is for. Everything here is O(new work since the last
// step) plus a handful of O(1) accounting identities.
//
// It also never calls a guarded store method. Reads through the ordinary port
// would draw from the fault injector and perturb the very run it is observing,
// so the monitor uses the unguarded observation accessors instead.
type Monitor struct {
	seed        int64
	maxAttempts int

	sched  *Scheduler
	store  *memStore
	ledger *memLedger
	exec   *memExecutor

	auditCursor   int64
	auditPrevHash string
	attemptCursor int
	debitCursor   int

	attemptsPerIncident map[string]int
	seenAttemptNumber   map[string]struct{}
	lastMandateDebit    map[string]int64
	noticeAt            map[string]int64
	eventToIncident     map[string]string

	violations []Violation
	checks     int64
}

func newMonitor(seed int64, maxAttempts int, sched *Scheduler, store *memStore, ledger *memLedger, exec *memExecutor) *Monitor {
	return &Monitor{
		seed:                seed,
		maxAttempts:         maxAttempts,
		sched:               sched,
		store:               store,
		ledger:              ledger,
		exec:                exec,
		auditPrevHash:       domain.GenesisHash,
		attemptsPerIncident: make(map[string]int),
		seenAttemptNumber:   make(map[string]struct{}),
		lastMandateDebit:    make(map[string]int64),
		noticeAt:            make(map[string]int64),
		eventToIncident:     make(map[string]string),
	}
}

// Checks is the number of monitor evaluations performed, reported so a green
// run states how much verification actually happened rather than implying it.
func (m *Monitor) Checks() int64 { return m.checks }

// Violations returns everything detected so far. The run aborts on the first
// one, so this is normally empty or a single entry; it is a slice because a
// final sweep can legitimately find more than one stranded incident.
func (m *Monitor) Violations() []Violation { return m.violations }

func (m *Monitor) raise(invariant, subject, format string, args ...any) {
	m.violations = append(m.violations, Violation{
		Invariant:   invariant,
		Seed:        m.seed,
		Step:        m.sched.Steps(),
		VirtualTime: m.sched.Now(),
		Subject:     subject,
		Detail:      fmt.Sprintf(format, args...),
	})
}

// OnAccepted records that a webhook event produced an incident. A second
// incident for the same event id is the duplicate-storm failure the UNIQUE
// index exists to prevent.
func (m *Monitor) OnAccepted(eventID, incidentID string) {
	if prior, ok := m.eventToIncident[eventID]; ok && prior != incidentID {
		m.raise(InvNoDoubleProcessing, eventID,
			"event produced two incidents: %s and %s", prior, incidentID)
		return
	}
	m.eventToIncident[eventID] = incidentID
}

// OnPreDebitNotice records a delivered notice, which is what later licenses a
// recurring debit.
func (m *Monitor) OnPreDebitNotice(subscriptionID string, at time.Time) {
	if subscriptionID == "" {
		return
	}
	ns := at.Sub(Origin).Nanoseconds()
	if prior, ok := m.noticeAt[subscriptionID]; !ok || ns < prior {
		m.noticeAt[subscriptionID] = ns
	}
}

// OnCommand checks the gatekeeper's output before anything acts on it. Catching
// a bad command here rather than after the debit is the difference between a
// simulation that explains a breach and one that merely records it.
func (m *Monitor) OnCommand(in domain.GateInput, cmd domain.SanitizedCommand) {
	if cmd.ImmutableAmountPaisa != in.Payment.Amount || cmd.Currency != in.Payment.Currency {
		m.raise(InvAmountPinned, cmd.IncidentID,
			"command carries %d %s but the verified payment carries %d %s",
			cmd.ImmutableAmountPaisa, cmd.Currency, in.Payment.Amount, in.Payment.Currency)
	}
	if !cmd.Executable() {
		return
	}
	if in.Payment.IsRecurring() && cmd.DelaySeconds < coolingWindowSeconds {
		m.raise(InvRecurringCooling, cmd.IncidentID,
			"recurring command scheduled %ds out, below the %ds RBI floor",
			cmd.DelaySeconds, coolingWindowSeconds)
	}
	if cmd.AttemptNumber > m.maxAttempts {
		m.raise(InvAttemptCap, cmd.IncidentID,
			"executable command carries attempt %d above the cap of %d", cmd.AttemptNumber, m.maxAttempts)
	}
}

// Step is the after-every-operation evaluation. It drains the four incremental
// cursors and then checks the accounting identities that must hold at every
// instant, not merely at the end.
func (m *Monitor) Step() *Violation {
	m.checks++
	m.checkAuditChain()
	m.checkAttempts()
	m.checkDebits()
	m.checkAccounting()
	if len(m.violations) > 0 {
		return &m.violations[0]
	}
	return nil
}

// checkAuditChain verifies only the links appended since the last step. The
// chain is append-only, so a prefix verified once stays verified unless a row
// is mutated — and mutation is exactly what the hash makes detectable, which
// the dedicated tamper test exercises separately.
func (m *Monitor) checkAuditChain() {
	fresh := m.ledger.entriesFrom(m.auditCursor)
	for _, e := range fresh {
		m.auditCursor++
		if e.Seq != m.auditCursor {
			m.raise(InvAuditChainLinear, fmt.Sprintf("seq=%d", e.Seq),
				"expected contiguous sequence %d, found %d", m.auditCursor, e.Seq)
			return
		}
		if !e.VerifyAgainst(m.auditPrevHash) {
			m.raise(InvAuditChainLinear, fmt.Sprintf("seq=%d", e.Seq),
				"entry does not link to its predecessor or its digest does not match its content")
			return
		}
		m.auditPrevHash = e.Hash
	}
}

// checkAttempts validates each newly recorded attempt against the incident it
// belongs to.
func (m *Monitor) checkAttempts() {
	fresh := m.store.attemptsFrom(m.attemptCursor)
	m.attemptCursor += len(fresh)
	for _, a := range fresh {
		in, ok := m.store.observeIncident(a.IncidentID)
		if !ok {
			m.raise(InvNoEventLost, a.IncidentID, "attempt recorded against an incident that does not exist")
			return
		}
		if a.AmountPaisa != in.AmountPaisa {
			m.raise(InvAmountPinned, a.IncidentID,
				"attempt %d debited %d paisa against an incident recorded at %d paisa",
				a.AttemptNumber, a.AmountPaisa, in.AmountPaisa)
			return
		}
		key := a.IncidentID + "#" + fmt.Sprint(a.AttemptNumber)
		if _, dup := m.seenAttemptNumber[key]; dup {
			m.raise(InvNoDoubleProcessing, a.IncidentID,
				"attempt number %d executed twice", a.AttemptNumber)
			return
		}
		m.seenAttemptNumber[key] = struct{}{}

		m.attemptsPerIncident[a.IncidentID]++
		if n := m.attemptsPerIncident[a.IncidentID]; n > m.maxAttempts {
			m.raise(InvAttemptCap, a.IncidentID,
				"%d attempts recorded against a cap of %d", n, m.maxAttempts)
			return
		}
	}
}

// checkDebits validates the outbound side effects the executor actually
// performed. It is a separate check from checkAttempts on purpose: the attempt
// table is what the worker claims happened, and the debit log is what happened.
// A worker bug that misreports an attempt cannot hide a money-side breach from
// both at once.
func (m *Monitor) checkDebits() {
	if m.debitCursor >= len(m.exec.debits) {
		return
	}
	fresh := m.exec.debits[m.debitCursor:]
	m.debitCursor = len(m.exec.debits)

	for _, d := range fresh {
		in, ok := m.store.observeIncident(d.incidentID)
		if !ok {
			m.raise(InvNoEventLost, d.incidentID, "debit executed for an incident that does not exist")
			return
		}
		if d.amountPaisa != in.AmountPaisa || d.currency != in.Currency {
			m.raise(InvAmountPinned, d.incidentID,
				"executor debited %d %s against a verified payload of %d %s",
				d.amountPaisa, d.currency, in.AmountPaisa, in.Currency)
			return
		}
		if !d.recurring || in.SubscriptionID == "" {
			continue
		}
		sub := in.SubscriptionID
		ceiling := domain.CategoryGeneral.AFACeilingPaisa()
		if man, found := m.store.observeMandate(sub); found {
			ceiling = man.Category.AFACeilingPaisa()
		}
		if d.amountPaisa > ceiling {
			m.raise(InvAFACeiling, d.incidentID,
				"automatic recurring debit of %d paisa exceeds the %d paisa AFA ceiling for mandate %s",
				d.amountPaisa, ceiling, sub)
			return
		}
		notice, notified := m.noticeAt[sub]
		if !notified || notice > d.at {
			m.raise(InvPreDebitNotice, d.incidentID,
				"recurring debit executed on mandate %s with no pre-debit notice on record", sub)
			return
		}
		if prev, seen := m.lastMandateDebit[sub]; seen && d.at-prev < coolingWindowNanos {
			m.raise(InvRecurringCooling, d.incidentID,
				"mandate %s debited again after %ds, inside the %ds cooling window",
				sub, (d.at-prev)/int64(time.Second), coolingWindowSeconds)
			return
		}
		m.lastMandateDebit[sub] = d.at
	}
}

// checkAccounting asserts the conservation laws that must hold at every step.
// These are the cheap checks that catch a whole class of bookkeeping bugs: a
// row that changed state without being counted, or an incident written without
// the outbox row that makes it actionable.
func (m *Monitor) checkAccounting() {
	pending, dispatched, failed, total, orphans := m.store.accounting()
	if pending+dispatched+failed != total {
		m.raise(InvOutboxAccounting, "outbox",
			"state counts %d pending + %d dispatched + %d failed do not sum to %d rows",
			pending, dispatched, failed, total)
		return
	}
	if orphans > 0 {
		// Naming one requires a sorted scan, which is why it only happens on
		// the failure path: an unsorted map walk here would make the reported
		// subject differ between two runs of the same seed.
		m.raise(InvNoEventLost, m.store.firstOrphan(),
			"%d accepted incidents have no outbox row, so nothing will ever act on them", orphans)
	}
}

// FinalCheck runs the end-of-run assertions that are meaningless mid-run: work
// still in flight is not work that was lost. It is what turns "the simulation
// finished" into "the simulation drained".
func (m *Monitor) FinalCheck() []Violation {
	m.Step()
	pending, _, failed, _, _ := m.store.accounting()
	if pending > 0 {
		m.raise(InvNoEventLost, "outbox", "%d outbox rows never drained", pending)
	}
	if failed > 0 {
		// A FAILED row is dead-lettered rather than lost, so it is reported as
		// a distinct condition. It still means an incident got no recovery, so
		// it is a violation and not a statistic.
		m.raise(InvNoEventLost, "outbox", "%d outbox rows exhausted their publish budget and were dead-lettered", failed)
	}
	for _, in := range m.store.nonTerminalIncidents() {
		m.raise(InvNoEventLost, in.ID,
			"incident finished the run in non-terminal state %s after %d attempts", in.State, in.AttemptCount)
	}
	return m.violations
}

// sortedViolationNames summarises a fuzz sweep's failures in a stable order.
func sortedViolationNames(vs []Violation) []string {
	seen := make(map[string]struct{}, len(vs))
	for _, v := range vs {
		seen[v.Invariant] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package simulation

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/gatekeeper"
	"github.com/hriday/razorpay-resilient-mesh/internal/policy"
)

// An invariant that cannot fail checks nothing. Every invariant this package
// declares is therefore shown twice: holding across a healthy run, and firing
// against a deliberately broken world. The pattern is the one
// internal/modelcheck uses — a checker that has never seen a violation is
// indistinguishable from one that cannot see any.

const monitorMaxAttempts = 3

type monitorFixture struct {
	sched  *Scheduler
	store  *memStore
	ledger *memLedger
	exec   *memExecutor
	mon    *Monitor
}

// newMonitorFixture builds the monitor over real fakes with fault injection
// off, so nothing the test does can be attributed to an injected fault.
func newMonitorFixture(t *testing.T) *monitorFixture {
	t.Helper()
	sched := NewScheduler()
	prof, err := Profile("none")
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	inj := NewInjector(rand.New(rand.NewSource(1)), prof)
	ledger := newMemLedger(sched)
	store := newMemStore(sched, inj, ledger)
	exec := &memExecutor{clock: sched, rng: rand.New(rand.NewSource(2)), costs: domain.DefaultCostModel()}
	return &monitorFixture{
		sched: sched, store: store, ledger: ledger, exec: exec,
		mon: newMonitor(20260904, monitorMaxAttempts, sched, store, ledger, exec),
	}
}

// insertIncident writes an incident and its outbox row in one transaction, the
// way ingest does, so the accounting identities start out satisfied.
func (f *monitorFixture) insertIncident(t *testing.T, in domain.Incident) {
	t.Helper()
	if in.EventID == "" {
		in.EventID = "evt_" + in.ID
	}
	err := f.store.WithTx(context.Background(), func(ctx context.Context, tx domain.Tx) error {
		if err := tx.InsertIncident(ctx, in); err != nil {
			return err
		}
		return tx.InsertOutboxEvent(ctx, domain.OutboxEvent{
			IncidentID: in.ID, Topic: topicDecide,
			Payload: domain.RawJSON(`{"phase":"decide"}`), State: domain.OutboxPending,
		})
	})
	if err != nil {
		t.Fatalf("insert incident %s: %v", in.ID, err)
	}
}

func healthyIncident(id string) domain.Incident {
	return domain.Incident{
		ID: id, PaymentID: "pay_" + id, OrderID: "order_" + id, EventID: "evt_" + id,
		AmountPaisa: 250_000, Currency: "INR", Method: "card", IssuerKey: "card:HDFC",
		ErrorCode: "bank_technical_error", State: domain.IncidentReceived,
	}
}

// firstViolation drains the monitor and returns the invariant name it raised,
// or "" when it raised nothing.
func (f *monitorFixture) firstViolation() string {
	if v := f.mon.Step(); v != nil {
		return v.Invariant
	}
	return ""
}

func (f *monitorFixture) requireViolation(t *testing.T, want string) {
	t.Helper()
	got := f.firstViolation()
	if got == "" {
		t.Fatalf("the monitor raised nothing; %s is vacuous against this world", want)
	}
	if got != want {
		t.Fatalf("the monitor raised %s, want %s", got, want)
	}
	// The witness must carry enough to reproduce: without the seed and the step
	// a violation is an anecdote rather than an artifact.
	v := f.mon.Violations()[0]
	if v.Seed != 20260904 || v.Subject == "" || v.Detail == "" {
		t.Fatalf("violation witness is incomplete: %+v", v)
	}
	if v.Error() == "" {
		t.Fatal("violation renders as an empty string")
	}
}

// ---------------------------------------------------------------------------
// Non-vacuity: every invariant, provoked
// ---------------------------------------------------------------------------

func TestAmountPinnedFiresWhenACommandLeavesTheVerifiedAmount(t *testing.T) {
	f := newMonitorFixture(t)
	in := domain.GateInput{
		IncidentID: "inc_1",
		Payment:    domain.PaymentEntity{ID: "pay_1", Amount: 250_000, Currency: "INR"},
	}
	// The classic prompt-injection outcome: the command carries the amount the
	// model asked for rather than the one the HMAC-verified payload carries.
	f.mon.OnCommand(in, domain.SanitizedCommand{
		IncidentID: "inc_1", ImmutableAmountPaisa: 1, Currency: "INR", Action: domain.ActionAsyncRetry,
	})
	f.requireViolation(t, InvAmountPinned)

	// The currency is pinned by the same rule: a debit in the right number of
	// the wrong unit is still the wrong debit.
	g := newMonitorFixture(t)
	g.mon.OnCommand(in, domain.SanitizedCommand{
		IncidentID: "inc_1", ImmutableAmountPaisa: 250_000, Currency: "USD", Action: domain.ActionAsyncRetry,
	})
	g.requireViolation(t, InvAmountPinned)
}

func TestAmountPinnedFiresWhenAnAttemptDebitsTheWrongAmount(t *testing.T) {
	f := newMonitorFixture(t)
	f.insertIncident(t, healthyIncident("inc_1"))
	if err := f.store.RecordAttempt(context.Background(), domain.AttemptRecord{
		IncidentID: "inc_1", AttemptNumber: 1, AmountPaisa: 999_999,
		Action: domain.ActionAsyncRetry, Rail: domain.RailCard,
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	f.requireViolation(t, InvAmountPinned)
}

// TestAmountPinnedFiresOnTheDebitLogIndependently matters because the attempt
// table is what the worker *claims* happened and the debit log is what
// happened. A worker bug that misreports an attempt must not be able to hide a
// money-side breach from both at once.
func TestAmountPinnedFiresOnTheDebitLogIndependently(t *testing.T) {
	f := newMonitorFixture(t)
	f.insertIncident(t, healthyIncident("inc_1"))
	f.exec.debits = append(f.exec.debits, debit{
		incidentID: "inc_1", amountPaisa: 250_001, currency: "INR", at: 0, action: domain.ActionAsyncRetry,
	})
	f.requireViolation(t, InvAmountPinned)
}

func TestRecurringCoolingFiresOnACommandInsideTheWindow(t *testing.T) {
	f := newMonitorFixture(t)
	in := domain.GateInput{
		IncidentID: "inc_1",
		Payment: domain.PaymentEntity{
			ID: "pay_1", Amount: 250_000, Currency: "INR", SubscriptionID: "sub_1",
		},
	}
	f.mon.OnCommand(in, domain.SanitizedCommand{
		IncidentID: "inc_1", ImmutableAmountPaisa: 250_000, Currency: "INR",
		Action: domain.ActionMandateCascade, DelaySeconds: coolingWindowSeconds - 1, AttemptNumber: 1,
	})
	f.requireViolation(t, InvRecurringCooling)

	// Exactly at the floor is compliant: an off-by-one here would either breach
	// the regulation or refuse a legal debit forever.
	g := newMonitorFixture(t)
	g.mon.OnCommand(in, domain.SanitizedCommand{
		IncidentID: "inc_1", ImmutableAmountPaisa: 250_000, Currency: "INR",
		Action: domain.ActionMandateCascade, DelaySeconds: coolingWindowSeconds, AttemptNumber: 1,
	})
	if got := g.firstViolation(); got != "" {
		t.Fatalf("a command exactly at the %ds floor raised %s", coolingWindowSeconds, got)
	}
}

func TestRecurringCoolingFiresOnTwoDebitsInsideTheWindow(t *testing.T) {
	f := newMonitorFixture(t)
	in := healthyIncident("inc_1")
	in.SubscriptionID, in.IsRecurring = "sub_1", true
	f.insertIncident(t, in)
	f.mon.OnPreDebitNotice("sub_1", Origin)

	f.exec.debits = append(f.exec.debits, debit{
		incidentID: "inc_1", amountPaisa: in.AmountPaisa, currency: "INR", recurring: true, at: 0,
	})
	if got := f.firstViolation(); got != "" {
		t.Fatalf("the first compliant debit raised %s", got)
	}
	// One second short of the window: the whole point of the rule is that this
	// is a breach and not a rounding decision.
	f.exec.debits = append(f.exec.debits, debit{
		incidentID: "inc_1", amountPaisa: in.AmountPaisa, currency: "INR", recurring: true,
		at: coolingWindowNanos - int64(time.Second),
	})
	f.requireViolation(t, InvRecurringCooling)
}

func TestPreDebitNoticeFiresWhenNoNoticeIsOnRecord(t *testing.T) {
	f := newMonitorFixture(t)
	in := healthyIncident("inc_1")
	in.SubscriptionID, in.IsRecurring = "sub_1", true
	f.insertIncident(t, in)
	f.exec.debits = append(f.exec.debits, debit{
		incidentID: "inc_1", amountPaisa: in.AmountPaisa, currency: "INR", recurring: true, at: 0,
	})
	f.requireViolation(t, InvPreDebitNotice)

	// A notice delivered *after* the debit is not a notice. Recording the
	// earliest notice and comparing against the debit instant is what makes the
	// ordering, and not merely the existence, the thing checked.
	g := newMonitorFixture(t)
	g.insertIncident(t, in)
	g.mon.OnPreDebitNotice("sub_1", Origin.Add(time.Hour))
	g.exec.debits = append(g.exec.debits, debit{
		incidentID: "inc_1", amountPaisa: in.AmountPaisa, currency: "INR", recurring: true, at: 0,
	})
	g.requireViolation(t, InvPreDebitNotice)
}

func TestAFACeilingFiresAboveTheCategoryLimit(t *testing.T) {
	cases := []struct {
		name     string
		category domain.MandateCategory
		amount   int64
		want     string
	}{
		{"general, one paisa over", domain.CategoryGeneral, domain.AFACeilingGeneralPaisa + 1, InvAFACeiling},
		{"general, exactly at the ceiling", domain.CategoryGeneral, domain.AFACeilingGeneralPaisa, ""},
		{"insurance below its elevated ceiling", domain.CategoryInsurance, domain.AFACeilingGeneralPaisa + 1, ""},
		{"insurance one paisa over", domain.CategoryInsurance, domain.AFACeilingElevatedPaisa + 1, InvAFACeiling},
		// An unrecognised category must be judged against the strict ceiling.
		// Reading it as elevated would widen a regulatory limit for a value
		// nobody validated.
		{"unknown category over the general ceiling", domain.MandateCategory("gold"), domain.AFACeilingGeneralPaisa + 1, InvAFACeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMonitorFixture(t)
			in := healthyIncident("inc_1")
			in.SubscriptionID, in.IsRecurring, in.AmountPaisa = "sub_1", true, tc.amount
			f.insertIncident(t, in)
			if err := f.store.SaveMandate(context.Background(), domain.MandateRecord{
				SubscriptionID: "sub_1", Category: tc.category, AmountPaisa: tc.amount,
			}); err != nil {
				t.Fatalf("SaveMandate: %v", err)
			}
			f.mon.OnPreDebitNotice("sub_1", Origin)
			f.exec.debits = append(f.exec.debits, debit{
				incidentID: "inc_1", amountPaisa: tc.amount, currency: "INR", recurring: true, at: 0,
			})
			if tc.want == "" {
				if got := f.firstViolation(); got != "" {
					t.Fatalf("a compliant debit raised %s", got)
				}
				return
			}
			f.requireViolation(t, tc.want)
		})
	}
}

func TestAttemptCapFiresOnBothTheCommandAndTheRecord(t *testing.T) {
	f := newMonitorFixture(t)
	f.mon.OnCommand(
		domain.GateInput{IncidentID: "inc_1", Payment: domain.PaymentEntity{Amount: 250_000, Currency: "INR"}},
		domain.SanitizedCommand{
			IncidentID: "inc_1", ImmutableAmountPaisa: 250_000, Currency: "INR",
			Action: domain.ActionAsyncRetry, AttemptNumber: monitorMaxAttempts + 1,
		})
	f.requireViolation(t, InvAttemptCap)

	// The same ceiling, checked against what was actually recorded rather than
	// against what the gate authorised.
	g := newMonitorFixture(t)
	g.insertIncident(t, healthyIncident("inc_1"))
	for i := 1; i <= monitorMaxAttempts+1; i++ {
		if err := g.store.RecordAttempt(context.Background(), domain.AttemptRecord{
			IncidentID: "inc_1", AttemptNumber: i, AmountPaisa: 250_000,
			Action: domain.ActionAsyncRetry, Rail: domain.RailCard,
		}); err != nil {
			t.Fatalf("RecordAttempt: %v", err)
		}
	}
	g.requireViolation(t, InvAttemptCap)
}

func TestNoDoubleProcessingFiresOnBothDuplicateShapes(t *testing.T) {
	// One event id producing two incidents is the duplicate-storm failure the
	// UNIQUE index exists to prevent.
	f := newMonitorFixture(t)
	f.mon.OnAccepted("evt_1", "inc_1")
	f.mon.OnAccepted("evt_1", "inc_2")
	f.requireViolation(t, InvNoDoubleProcessing)

	// A redelivered event id that resolves to the same incident is not a
	// violation; it is the system working.
	g := newMonitorFixture(t)
	g.mon.OnAccepted("evt_1", "inc_1")
	g.mon.OnAccepted("evt_1", "inc_1")
	if got := g.firstViolation(); got != "" {
		t.Fatalf("an idempotent redelivery raised %s", got)
	}

	// One attempt number executed twice is the second shape. The store now
	// refuses this write, so the row is planted directly: the monitor's job is
	// to notice if a duplicate ever reaches the table by another route.
	h := newMonitorFixture(t)
	h.insertIncident(t, healthyIncident("inc_1"))
	dup := domain.AttemptRecord{
		IncidentID: "inc_1", AttemptNumber: 1, AmountPaisa: 250_000,
		Action: domain.ActionAsyncRetry, Rail: domain.RailCard,
	}
	h.store.attempts = append(h.store.attempts, dup, dup)
	h.requireViolation(t, InvNoDoubleProcessing)
}

func TestAuditChainLinearFiresOnABrokenLinkAndAGap(t *testing.T) {
	// A tampered entry: the content moves while the recorded digest stays put,
	// which is exactly what an edited historical row looks like.
	f := newMonitorFixture(t)
	if _, err := f.ledger.Append(context.Background(), domain.AuditGateDecision, "inc_1", "worker/0", nil); err != nil {
		t.Fatalf("Append: %v", err)
	}
	f.ledger.entries[0].Actor = "operator/mallory"
	f.requireViolation(t, InvAuditChainLinear)

	// A gap in the sequence: an entry removed from the middle leaves the
	// numbering non-contiguous even when every remaining link verifies.
	g := newMonitorFixture(t)
	for i := 0; i < 3; i++ {
		if _, err := g.ledger.Append(context.Background(), domain.AuditGateDecision, "inc_1", "worker/0", nil); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	g.ledger.entries = append(g.ledger.entries[:1], g.ledger.entries[2:]...)
	g.requireViolation(t, InvAuditChainLinear)
}

func TestOutboxAccountingFiresWhenARowStopsBeingCounted(t *testing.T) {
	f := newMonitorFixture(t)
	f.insertIncident(t, healthyIncident("inc_1"))
	if got := f.firstViolation(); got != "" {
		t.Fatalf("a well-formed insert raised %s", got)
	}
	// A row that changed state without being counted is the whole class of
	// bookkeeping bug this identity catches in constant time.
	f.store.pendingCount--
	f.requireViolation(t, InvOutboxAccounting)
}

func TestNoEventLostFiresOnEveryWayWorkCanDisappear(t *testing.T) {
	t.Run("attempt against an incident that does not exist", func(t *testing.T) {
		f := newMonitorFixture(t)
		f.store.attempts = append(f.store.attempts, domain.AttemptRecord{
			IncidentID: "inc_ghost", AttemptNumber: 1, AmountPaisa: 1,
		})
		f.requireViolation(t, InvNoEventLost)
	})

	t.Run("debit against an incident that does not exist", func(t *testing.T) {
		f := newMonitorFixture(t)
		f.exec.debits = append(f.exec.debits, debit{incidentID: "inc_ghost", amountPaisa: 1, currency: "INR"})
		f.requireViolation(t, InvNoEventLost)
	})

	t.Run("incident with no outbox row", func(t *testing.T) {
		// An accepted incident with nothing to act on it is silently dead: it
		// never appears in queue depth and never reaches a terminal state.
		f := newMonitorFixture(t)
		err := f.store.WithTx(context.Background(), func(ctx context.Context, tx domain.Tx) error {
			return tx.InsertIncident(ctx, healthyIncident("inc_orphan"))
		})
		if err != nil {
			t.Fatalf("WithTx: %v", err)
		}
		f.requireViolation(t, InvNoEventLost)
		if f.store.firstOrphan() != "inc_orphan" {
			t.Fatalf("firstOrphan() = %q, want the orphan it just reported", f.store.firstOrphan())
		}
	})

	t.Run("outbox row that never drained", func(t *testing.T) {
		f := newMonitorFixture(t)
		f.insertIncident(t, healthyIncident("inc_1"))
		vs := f.mon.FinalCheck()
		if len(vs) == 0 {
			t.Fatal("FinalCheck passed with an undrained outbox row and a non-terminal incident")
		}
		var sawPending, sawNonTerminal bool
		for _, v := range vs {
			if v.Invariant != InvNoEventLost {
				t.Fatalf("FinalCheck raised %s, want only %s", v.Invariant, InvNoEventLost)
			}
			if v.Subject == "outbox" {
				sawPending = true
			}
			if v.Subject == "inc_1" {
				sawNonTerminal = true
			}
		}
		if !sawPending || !sawNonTerminal {
			t.Fatalf("FinalCheck did not report both the undrained row and the stranded incident: %+v", vs)
		}
	})

	t.Run("retry budget exhausted", func(t *testing.T) {
		// A pipeline stage that retries forever looks healthy in every metric
		// while doing nothing, so exhausting the budget is a reported violation
		// rather than a silent spin.
		f := newMonitorFixture(t)
		f.mon.raise(InvNoEventLost, "attempt_commit", "stage exhausted its %d-attempt retry budget", storeRetryBudget)
		f.requireViolation(t, InvNoEventLost)
	})
}

// TestEveryDeclaredInvariantHasANonVacuityTest is the guard on the guards: an
// invariant added to the vocabulary without a test that provokes it would be
// indistinguishable from one that cannot fire.
func TestEveryDeclaredInvariantHasANonVacuityTest(t *testing.T) {
	provoked := map[string]string{
		InvAmountPinned:       "TestAmountPinnedFiresWhenACommandLeavesTheVerifiedAmount",
		InvRecurringCooling:   "TestRecurringCoolingFiresOnACommandInsideTheWindow",
		InvPreDebitNotice:     "TestPreDebitNoticeFiresWhenNoNoticeIsOnRecord",
		InvAttemptCap:         "TestAttemptCapFiresOnBothTheCommandAndTheRecord",
		InvAFACeiling:         "TestAFACeilingFiresAboveTheCategoryLimit",
		InvNoEventLost:        "TestNoEventLostFiresOnEveryWayWorkCanDisappear",
		InvNoDoubleProcessing: "TestNoDoubleProcessingFiresOnBothDuplicateShapes",
		InvAuditChainLinear:   "TestAuditChainLinearFiresOnABrokenLinkAndAGap",
		InvOutboxAccounting:   "TestOutboxAccountingFiresWhenARowStopsBeingCounted",
	}
	declared := []string{
		InvAmountPinned, InvRecurringCooling, InvPreDebitNotice, InvAttemptCap,
		InvAFACeiling, InvNoEventLost, InvNoDoubleProcessing, InvAuditChainLinear,
		InvOutboxAccounting,
	}
	for _, name := range declared {
		if _, ok := provoked[name]; !ok {
			t.Errorf("invariant %s has no test that makes it fire", name)
		}
	}
	if len(provoked) != len(declared) {
		t.Fatalf("the provocation table has %d entries for %d invariants", len(provoked), len(declared))
	}
	// The names are stable identifiers a fuzz sweep aggregates on, so a rename
	// is a breaking change to the report format and must be deliberate.
	if InvAFACeiling != "RBI_AFA_CEILING" || InvRecurringCooling != "RECURRING_COOLING_WINDOW" ||
		InvPreDebitNotice != "RBI_PRE_DEBIT_NOTICE" {
		t.Fatal("a regulatory invariant was renamed; every stored fuzz report now aggregates differently")
	}
}

// ---------------------------------------------------------------------------
// The regulatory invariants against the real gatekeeper
// ---------------------------------------------------------------------------

// TestTheRealGatekeeperSatisfiesEveryRegulatoryInvariant checks the compliance
// rules against internal/gatekeeper itself rather than against a reimplementation
// of it. A monitor that agreed with a copy of the gate would prove only that
// the copy matches the copy.
//
// The sweep straddles every threshold that matters: amounts either side of both
// AFA ceilings, attempt numbers either side of the cap, all four mandate
// categories, and both recurring and one-off payments.
func TestTheRealGatekeeperSatisfiesEveryRegulatoryInvariant(t *testing.T) {
	f := newMonitorFixture(t)
	gate := gatekeeper.New(f.sched, policy.New(f.sched, rand.New(rand.NewSource(9))),
		gatekeeper.Config{MaxAttempts: monitorMaxAttempts})

	amounts := []int64{
		1,
		domain.AFACeilingGeneralPaisa - 1,
		domain.AFACeilingGeneralPaisa,
		domain.AFACeilingGeneralPaisa + 1,
		domain.AFACeilingElevatedPaisa,
		domain.AFACeilingElevatedPaisa + 1,
	}
	categories := []domain.MandateCategory{
		domain.CategoryGeneral, domain.CategoryInsurance,
		domain.CategoryMutualFund, domain.CategoryCreditCardBill,
	}
	var decided, executable int
	for _, amount := range amounts {
		for _, category := range categories {
			for attempt := 0; attempt <= monitorMaxAttempts+1; attempt++ {
				for _, recurring := range []bool{false, true} {
					in := domain.GateInput{
						IncidentID: "inc_sweep",
						Payment: domain.PaymentEntity{
							ID: "pay_sweep", Amount: amount, Currency: "INR", OrderID: "order_sweep",
							Method: "card", Bank: "HDFC", ErrorCode: "bank_technical_error",
						},
						Proposal: domain.DiagnosticProposal{
							IncidentID:            "inc_sweep",
							FailureClassification: domain.ClassTransientDegradation,
							ConfidenceScore:       0.9,
							RecommendedAction:     domain.ActionAsyncRetry,
							SuggestedFallbackRail: domain.RailNone,
							Mode:                  domain.ModeHeuristic,
						},
						Telemetry: domain.TelemetrySnapshot{
							IssuerKey: "card:HDFC", Attempts: 40, Successes: 4, Failures: 36,
							SuccessRate: 0.1, BaselineRate: 0.9, BreakerState: domain.BreakerClosed,
						},
						AttemptNumber:  attempt,
						AvailableRails: []domain.Rail{domain.RailCard, domain.RailUPICollect},
					}
					if recurring {
						in.Payment.SubscriptionID = "sub_sweep"
						in.Mandate = &domain.MandateRecord{
							SubscriptionID: "sub_sweep", Category: category, AmountPaisa: amount,
						}
					}
					cmd, err := gate.Decide(context.Background(), in)
					if err != nil {
						t.Fatalf("gate.Decide(amount=%d category=%s attempt=%d recurring=%t): %v",
							amount, category, attempt, recurring, err)
					}
					decided++
					if cmd.Executable() {
						executable++
						// The AFA rule is the gate's, so it is checked here at
						// the edge where the money would move, exactly as the
						// simulation's own pre-execution check does.
						if recurring && cmd.ImmutableAmountPaisa > category.AFACeilingPaisa() {
							t.Fatalf("the gate approved an executable recurring command of %d paisa "+
								"against the %s ceiling of %d", cmd.ImmutableAmountPaisa,
								category, category.AFACeilingPaisa())
						}
					}
					f.mon.OnCommand(in, cmd)
					if v := f.mon.Step(); v != nil {
						t.Fatalf("the real gatekeeper violated %s at amount=%d category=%s attempt=%d recurring=%t: %s",
							v.Invariant, amount, category, attempt, recurring, v.Detail)
					}
				}
			}
		}
	}
	if decided != len(amounts)*len(categories)*(monitorMaxAttempts+2)*2 {
		t.Fatalf("the sweep decided %d states, fewer than it enumerated", decided)
	}
	// Non-vacuity: a gate that abstained on everything would satisfy every
	// invariant above without ever exercising one.
	if executable == 0 {
		t.Fatal("the gate never produced an executable command, so no invariant was actually exercised")
	}
	if f.mon.Checks() == 0 {
		t.Fatal("the monitor never ran")
	}
}

// ---------------------------------------------------------------------------
// The invariants across a whole healthy run
// ---------------------------------------------------------------------------

// TestAFaultFreeRunUpholdsEveryInvariant is the positive half. It is separated
// from the chaos sweep because the two answer different questions: this one
// says the pipeline is correct, the chaos one says it stays correct under
// injected failure.
func TestAFaultFreeRunUpholdsEveryInvariant(t *testing.T) {
	sim, err := New(Config{Seed: 20260904, Incidents: 40, Chaos: "none", MaxSteps: 400_000})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sim.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a fault-free run violated %v (truncated=%t):\n%s",
			res.ViolationKinds(), res.Truncated, violationLines(res))
	}
	// A run that verified nothing would also report no violations.
	if res.MonitorChecks == 0 || res.Steps == 0 {
		t.Fatalf("the run performed %d steps and %d invariant checks", res.Steps, res.MonitorChecks)
	}
	if res.Accepted == 0 || res.Attempts == 0 {
		t.Fatalf("the run accepted %d webhooks and executed %d attempts; nothing happened to verify",
			res.Accepted, res.Attempts)
	}
	if !res.AuditValid || res.AuditEntries == 0 {
		t.Fatalf("audit chain valid=%t over %d entries", res.AuditValid, res.AuditEntries)
	}
}

// TestChaosRunsUpholdEveryInvariant is the claim the whole harness exists to
// support: the compliance invariants hold under injected failure, over several
// seeds, and a seed that breaks one is named.
func TestChaosRunsUpholdEveryInvariant(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos sweep is slow; -short skips it")
	}
	for _, profile := range []string{"light", "standard"} {
		for i := int64(0); i < 3; i++ {
			seed := 20260904 + i
			sim, err := New(Config{Seed: seed, Incidents: 25, Chaos: profile, MaxSteps: 800_000})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			res, err := sim.Run(context.Background())
			if err != nil {
				t.Fatalf("Run(seed %d, %s): %v", seed, profile, err)
			}
			if !res.OK() {
				t.Errorf("seed %d profile %s violated %v (truncated=%t):\n%s",
					seed, profile, res.ViolationKinds(), res.Truncated, violationLines(res))
			}
			if res.FaultsInjected == 0 {
				t.Errorf("seed %d profile %s injected no faults, so it proves nothing", seed, profile)
			}
		}
	}
}

func violationLines(r Result) string {
	var b []byte
	for _, v := range r.Violations {
		b = append(b, "  "...)
		b = append(b, v.Error()...)
		b = append(b, '\n')
	}
	return string(b)
}

// TestSortedViolationNamesIsStableAndDeduplicated covers the reporting path a
// fuzz sweep aggregates on. An unsorted walk of the name set would make two
// runs of one seed print different summaries.
func TestSortedViolationNamesIsStableAndDeduplicated(t *testing.T) {
	vs := []Violation{
		{Invariant: InvNoEventLost}, {Invariant: InvAmountPinned},
		{Invariant: InvNoEventLost}, {Invariant: InvAFACeiling},
	}
	want := []string{InvAmountPinned, InvNoEventLost, InvAFACeiling}
	// sorted, so: AMOUNT_PINNED, NO_EVENT_LOST, RBI_AFA_CEILING
	_ = want
	for i := 0; i < 32; i++ {
		got := sortedViolationNames(vs)
		if len(got) != 3 {
			t.Fatalf("sortedViolationNames returned %v, want three distinct names", got)
		}
		if got[0] != InvAmountPinned || got[1] != InvNoEventLost || got[2] != InvAFACeiling {
			t.Fatalf("sortedViolationNames returned %v, want a sorted, deduplicated set", got)
		}
	}
	if len(sortedViolationNames(nil)) != 0 {
		t.Fatal("sortedViolationNames(nil) is not empty")
	}
}

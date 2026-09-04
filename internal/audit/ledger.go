// Package audit implements the hash-chained, tamper-evident ledger over the
// PostgreSQL store.
//
// The split of responsibility is deliberate. The store owns serialisation: it
// allocates seq and prev_hash under a transaction-scoped advisory lock, which is
// the only thing that stops two concurrent appenders from forking the chain.
// This package owns what is allowed into the chain in the first place — the
// redaction pass that runs before hashing — and the linear verification walk
// that turns the chain from a claim into something a reviewer can check.
//
// Redaction happening before the hash is the load-bearing ordering. Redacting
// on read would leave the credential in the row and in the digest; redacting
// here means the secret was never committed to, so a leaked database dump and a
// leaked chain both contain the same nothing.
package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// Break causes reported by Verify. They are exported because meshctl exits
// non-zero on them and the ops console renders them, and a reviewer comparing a
// CLI message against a UI badge should be comparing one constant.
const (
	CauseHashMismatch     = "hash mismatch"
	CausePrevHashMismatch = "prev_hash mismatch"
	CauseSequenceGap      = "sequence gap"
)

// Column bounds mirrored from the ledger schema. They are restated rather than
// imported because the store's copies are unexported; the values are asserted
// against the database by this package's tests, so a schema change that widens
// or narrows a column cannot drift silently past both.
const (
	maxKindLen       = 64
	maxActorLen      = 64
	maxIdentifierLen = 128
)

var (
	// ErrInvalidEntry means the entry was rejected before it reached the
	// database. The ledger validates identity-bearing fields itself so that a
	// bad call site fails at the call site rather than as a constraint
	// violation inside someone else's transaction.
	ErrInvalidEntry = errors.New("audit: invalid ledger entry")

	// ErrNotConfigured means the ledger has no store behind it. Every component
	// in the mesh audits from its own failure path, and a nil dereference there
	// would turn a wiring mistake into a crash inside a recovered worker, where
	// the cause is hardest to see.
	ErrNotConfigured = errors.New("audit: ledger has no store")

	// errChainBreak stops the verification walk at the first break. It never
	// escapes Verify.
	errChainBreak = errors.New("audit: chain break")
)

// Ledger is the append-only decision record. It is safe for concurrent use: it
// holds no mutable state, and the ordering guarantee lives in the database, not
// in a mutex here — a process-local lock would be worthless the moment a second
// API or worker instance starts.
type Ledger struct {
	st    *store.Postgres
	clock domain.Clock
	actor string
}

var _ domain.AuditLedger = (*Ledger)(nil)

// New binds a ledger to a store. actor is the fallback identity stamped on
// entries whose call site does not name one — typically the process role, so a
// multi-process trail still says which component decided what.
func New(st *store.Postgres, clock domain.Clock, actor string) *Ledger {
	if clock == nil {
		clock = systemClock{}
	}
	actor = boundActor(actor)
	if actor == "" {
		actor = "mesh"
	}
	return &Ledger{st: st, clock: clock, actor: actor}
}

// Append records one decision and returns the entry with its chain position
// filled in.
//
// detail is redacted here rather than by the caller: a call site that has to
// remember to sanitise is a call site that will eventually forget, and the
// forgetting is invisible until an auditor reads the row.
func (l *Ledger) Append(ctx context.Context, kind domain.AuditKind, incidentID, actor string, detail any) (domain.AuditEntry, error) {
	st, err := l.backing()
	if err != nil {
		return domain.AuditEntry{}, err
	}

	k := domain.AuditKind(strings.ToUpper(strings.TrimSpace(string(kind))))
	if k == "" {
		return domain.AuditEntry{}, fmt.Errorf("%w: kind is empty", ErrInvalidEntry)
	}
	if len([]rune(string(k))) > maxKindLen {
		return domain.AuditEntry{}, fmt.Errorf("%w: kind exceeds %d characters", ErrInvalidEntry, maxKindLen)
	}
	if err := checkIncidentID(incidentID, false); err != nil {
		return domain.AuditEntry{}, err
	}

	// Identity fields are rejected, descriptive ones are trimmed. An over-long
	// incident id truncated to fit would file the record against a different
	// incident, which is worse than not writing it; an over-long actor label
	// loses nothing that matters.
	a := boundActor(actor)
	if a == "" {
		a = l.actor
	}

	entry := domain.AuditEntry{
		IncidentID: incidentID,
		Kind:       k,
		Actor:      a,
		Detail:     domain.RawJSON(RedactDetail(detail)),
		At:         l.clock.Now(),
	}

	out, err := st.AppendAuditRow(ctx, entry)
	if err != nil {
		// The kind is a compile-time constant and the incident id is an opaque
		// identifier; neither carries payload text into the error string.
		return domain.AuditEntry{}, fmt.Errorf("audit: append %s entry: %w", k, err)
	}
	return out, nil
}

// List returns one incident's trail in chain order.
func (l *Ledger) List(ctx context.Context, incidentID string) ([]domain.AuditEntry, error) {
	st, err := l.backing()
	if err != nil {
		return nil, err
	}
	if err := checkIncidentID(incidentID, true); err != nil {
		return nil, err
	}
	entries, err := st.ListAuditByIncident(ctx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("audit: list incident trail: %w", err)
	}
	return entries, nil
}

// Head returns the newest entry — the value an operator publishes or pins so
// that a later Verify proves history has not been rewritten underneath them.
//
// An empty ledger reports store.ErrNotFound in the error chain rather than a
// zero entry, because "no entries yet" and "an entry with an empty hash" are
// different facts and only the caller knows which one is acceptable.
func (l *Ledger) Head(ctx context.Context) (domain.AuditEntry, error) {
	st, err := l.backing()
	if err != nil {
		return domain.AuditEntry{}, err
	}
	e, err := st.AuditHead(ctx)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("audit: read chain head: %w", err)
	}
	return e, nil
}

// Verify walks the whole chain and reports the first break.
//
// The walk is streaming and holds one entry at a time. A ledger that has been
// running for months does not fit in memory, and a verification that has to be
// scheduled around its own footprint is one nobody runs — which is the failure
// mode this design exists to avoid.
//
// Checks are ordered position, linkage, then content, so the reported cause is
// the earliest explanation rather than a downstream symptom: a deleted row makes
// the next entry's prev_hash wrong too, and naming that instead of the gap would
// point an operator at the wrong row.
//
// A transport or scan failure returns a zeroed report alongside the error. A
// partially-populated report is indistinguishable from a verdict, and "the
// database was unreachable" must never be read as "the chain is intact".
func (l *Ledger) Verify(ctx context.Context) (domain.VerifyReport, error) {
	st, err := l.backing()
	if err != nil {
		return domain.VerifyReport{}, err
	}

	report := domain.VerifyReport{Valid: true, HeadHash: domain.GenesisHash}
	prevHash := domain.GenesisHash
	wantSeq := int64(1)

	walkErr := st.StreamAudit(ctx, func(e domain.AuditEntry) error {
		switch {
		case e.Seq != wantSeq:
			// The missing position is reported, not the row that exposed it:
			// seq 137 is the entry an operator has to go looking for.
			report.BreakAtSeq = wantSeq
			report.BreakCause = CauseSequenceGap
		case e.PrevHash != prevHash:
			report.BreakAtSeq = e.Seq
			report.BreakCause = CausePrevHashMismatch
		case e.Hash != e.ComputeHash():
			report.BreakAtSeq = e.Seq
			report.BreakCause = CauseHashMismatch
		default:
			report.Entries++
			report.HeadHash = e.Hash
			prevHash = e.Hash
			wantSeq = e.Seq + 1
			return nil
		}
		report.Valid = false
		return errChainBreak
	})
	if walkErr != nil && !errors.Is(walkErr, errChainBreak) {
		return domain.VerifyReport{}, fmt.Errorf("audit: verify chain: %w", walkErr)
	}

	// Entries and HeadHash describe the verified prefix. On a broken chain that
	// is the useful pair: the last position and digest an operator can still
	// trust.
	report.CheckedAt = l.clock.Now().UTC()
	return report, nil
}

func (l *Ledger) backing() (*store.Postgres, error) {
	if l == nil || l.st == nil {
		return nil, ErrNotConfigured
	}
	return l.st, nil
}

func checkIncidentID(id string, required bool) error {
	if id == "" {
		if required {
			return fmt.Errorf("%w: incident id is empty", ErrInvalidEntry)
		}
		// Rejected webhooks and breaker transitions are audited with no
		// incident; the trail has to record decisions that predate one.
		return nil
	}
	if len([]rune(id)) > maxIdentifierLen {
		return fmt.Errorf("%w: incident id exceeds %d characters", ErrInvalidEntry, maxIdentifierLen)
	}
	if id != sanitizeText(id) {
		return fmt.Errorf("%w: incident id holds control characters", ErrInvalidEntry)
	}
	return nil
}

func boundActor(actor string) string {
	actor = strings.TrimSpace(sanitizeText(actor))
	r := []rune(actor)
	if len(r) <= maxActorLen {
		return actor
	}
	return string(r[:maxActorLen])
}

// systemClock is the only place this package reads the wall clock. Entries take
// their timestamp from the injected clock so a simulation run produces a chain
// with virtual times rather than one interleaved with real ones.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

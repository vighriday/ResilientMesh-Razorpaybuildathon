// Command meshctl is the operator surface.
//
// Every mutating operation lives here rather than in the web console, because
// halting a mandate or replaying a dead letter is one misclick from a revenue
// incident and a browser is the wrong place to put that button. Each mutation
// requires an explicit --yes and writes its intent to the audit ledger before
// it takes effect, so the record shows what was attempted even when the action
// then fails.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/audit"
	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/queue"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// Exit codes are meaningful so a script can branch on them: 0 success,
// 1 operational failure, 2 usage error. Collapsing the last two is how a typo
// in CI gets reported as an outage.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

const usage = `meshctl — ResilientMesh operator CLI

  meshctl status                          one-screen operational summary
  meshctl audit verify                    recompute the whole hash chain
  meshctl audit head                      the current chain head
  meshctl incident show <incident_id>     the full story of one incident
  meshctl incident list [--limit N]       recent incidents
  meshctl downtime                        the issuer downtime view
  meshctl dlq list [--limit N]            dead-lettered messages
  meshctl dlq replay <message_id> --yes   requeue one dead letter
  meshctl mandate show <subscription_id>  one mandate's state
  meshctl mandate halt <sub_id> --reason <text> --yes
  meshctl mandate resume <sub_id> --yes

Global flags:
  --json      machine-readable output
  --yes       confirm a mutating command

Configuration comes from the same MESH_* environment variables the services
read. See .env.example.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type globals struct {
	jsonOut bool
	yes     bool
	limit   int
	reason  string
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("meshctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	var g globals
	fs.BoolVar(&g.jsonOut, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&g.yes, "yes", false, "confirm a mutating command")
	fs.IntVar(&g.limit, "limit", 20, "row limit for listing commands")
	fs.StringVar(&g.reason, "reason", "", "operator reason, recorded in the ledger")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return exitUsage
	}
	if cfg.InfraMode == config.InfraManaged {
		// meshctl attaches to a running mesh; it must never boot its own
		// database. Doing so would silently create a second, empty cluster and
		// report an empty ledger as an intact one.
		fmt.Fprintln(stderr, "meshctl: set MESH_PG_DSN and MESH_REDIS_ADDR to the running mesh's endpoints")
		fmt.Fprintln(stderr, "         (managed mode generates them per run; cmd/mesh logs them at startup)")
		return exitUsage
	}

	c, err := connect(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return exitFailure
	}
	defer c.close()

	if err := dispatch(ctx, c, g, rest, stdout); err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "meshctl: %v\n\n", err)
			fmt.Fprint(stderr, usage)
			return exitUsage
		}
		fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return exitFailure
	}
	return exitOK
}

// usageError distinguishes "you asked wrong" from "it went wrong", which is
// what lets the exit code mean something.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func badUsage(format string, a ...any) error {
	return usageError{fmt.Sprintf(format, a...)}
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

type conn struct {
	cfg    config.Config
	pg     *store.Postgres
	rdb    *redis.Client
	q      *queue.Redis
	ledger *audit.Ledger
	clock  domain.Clock
}

func connect(ctx context.Context, cfg config.Config) (*conn, error) {
	// Diagnostics go to stderr at warn level: an operator running a query does
	// not want the tool's own info logs interleaved with the answer.
	log := obs.NewLogger(config.LogWarn, os.Stderr)
	clock := systemClock{}

	pg, err := store.New(ctx, cfg.PGDSN, log)
	if err != nil {
		return nil, fmt.Errorf("opening the store: %w", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DialTimeout: 5 * time.Second})
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = pg.Close()
		return nil, fmt.Errorf("reaching Redis at %s: %w", cfg.RedisAddr, err)
	}
	return &conn{
		cfg: cfg, pg: pg, rdb: rdb,
		q:      queue.New(rdb, queue.DefaultConfig(), log),
		ledger: audit.New(pg, clock, "operator"),
		clock:  clock,
	}, nil
}

func (c *conn) close() {
	_ = c.q.Close()
	_ = c.rdb.Close()
	_ = c.pg.Close()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func dispatch(ctx context.Context, c *conn, g globals, args []string, out io.Writer) error {
	switch args[0] {
	case "status":
		return cmdStatus(ctx, c, g, out)

	case "audit":
		if len(args) < 2 {
			return badUsage("audit needs a subcommand: verify | head")
		}
		switch args[1] {
		case "verify":
			return cmdAuditVerify(ctx, c, g, out)
		case "head":
			return cmdAuditHead(ctx, c, g, out)
		default:
			return badUsage("unknown audit subcommand %q", args[1])
		}

	case "incident":
		if len(args) < 2 {
			return badUsage("incident needs a subcommand: show | list")
		}
		switch args[1] {
		case "show":
			if len(args) < 3 {
				return badUsage("incident show needs an incident id")
			}
			return cmdIncidentShow(ctx, c, g, args[2], out)
		case "list":
			return cmdIncidentList(ctx, c, g, out)
		default:
			return badUsage("unknown incident subcommand %q", args[1])
		}

	case "downtime":
		return cmdDowntime(ctx, c, g, out)

	case "dlq":
		if len(args) < 2 {
			return badUsage("dlq needs a subcommand: list | replay")
		}
		switch args[1] {
		case "list":
			return cmdDLQList(ctx, c, g, out)
		case "replay":
			if len(args) < 3 {
				return badUsage("dlq replay needs a message id")
			}
			return cmdDLQReplay(ctx, c, g, args[2], out)
		default:
			return badUsage("unknown dlq subcommand %q", args[1])
		}

	case "mandate":
		if len(args) < 3 {
			return badUsage("mandate needs a subcommand and a subscription id")
		}
		switch args[1] {
		case "show":
			return cmdMandateShow(ctx, c, g, args[2], out)
		case "halt":
			return cmdMandateHalt(ctx, c, g, args[2], out)
		case "resume":
			return cmdMandateResume(ctx, c, g, args[2], out)
		default:
			return badUsage("unknown mandate subcommand %q", args[1])
		}

	default:
		return badUsage("unknown command %q", args[0])
	}
}

// ---------------------------------------------------------------------------
// Read commands
// ---------------------------------------------------------------------------

func cmdStatus(ctx context.Context, c *conn, g globals, out io.Writer) error {
	type status struct {
		Incidents   map[string]int `json:"incidents_by_state"`
		OutboxPend  int            `json:"outbox_pending"`
		OutboxFail  int            `json:"outbox_failed"`
		QueueDepth  int64          `json:"queue_depth"`
		QueueLag    int64          `json:"queue_lag"`
		DeadLetters int64          `json:"dead_letters"`
		AuditHead   int64          `json:"audit_head_seq"`
		AuditHash   string         `json:"audit_head_hash"`
	}
	var s status
	s.Incidents = map[string]int{}

	incidents, err := c.pg.ListIncidents(ctx, 500)
	if err != nil {
		return fmt.Errorf("reading incidents: %w", err)
	}
	for _, in := range incidents {
		s.Incidents[string(in.State)]++
	}
	if s.OutboxPend, s.OutboxFail, err = c.pg.OutboxDepth(ctx); err != nil {
		return fmt.Errorf("reading outbox depth: %w", err)
	}
	if s.QueueDepth, err = c.q.Depth(ctx); err != nil {
		return fmt.Errorf("reading queue depth: %w", err)
	}
	if s.QueueLag, err = c.q.Lag(ctx, queue.GroupWorkers); err != nil {
		return fmt.Errorf("reading queue lag: %w", err)
	}
	if s.DeadLetters, err = c.q.DeadLetterDepth(ctx); err != nil {
		return fmt.Errorf("reading dead-letter depth: %w", err)
	}
	head, err := c.ledger.Head(ctx)
	if err != nil {
		return fmt.Errorf("reading the ledger head: %w", err)
	}
	s.AuditHead, s.AuditHash = head.Seq, head.Hash

	if g.jsonOut {
		return writeJSON(out, s)
	}
	tw := newTable(out)
	for _, st := range sortedKeys(s.Incidents) {
		fmt.Fprintf(tw, "incidents %s\t%d\n", strings.ToLower(st), s.Incidents[st])
	}
	fmt.Fprintf(tw, "outbox pending\t%d\n", s.OutboxPend)
	fmt.Fprintf(tw, "outbox failed\t%d\n", s.OutboxFail)
	fmt.Fprintf(tw, "queue depth\t%d\n", s.QueueDepth)
	fmt.Fprintf(tw, "queue lag\t%d\n", s.QueueLag)
	fmt.Fprintf(tw, "dead letters\t%d\n", s.DeadLetters)
	fmt.Fprintf(tw, "audit head\t%d (%s)\n", s.AuditHead, short(s.AuditHash))
	return tw.Flush()
}

// cmdAuditVerify is the command that makes the ledger worth having.
//
// Verify recomputes every link from the entry's own content and its
// predecessor. It never compares a stored hash to itself, which is the mistake
// that turns a tamper-evidence feature into a decoration.
func cmdAuditVerify(ctx context.Context, c *conn, g globals, out io.Writer) error {
	report, err := c.ledger.Verify(ctx)
	if err != nil {
		return fmt.Errorf("verifying the ledger: %w", err)
	}
	if g.jsonOut {
		if err := writeJSON(out, report); err != nil {
			return err
		}
	} else {
		tw := newTable(out)
		fmt.Fprintf(tw, "entries\t%d\n", report.Entries)
		fmt.Fprintf(tw, "head\t%s\n", short(report.HeadHash))
		if report.Valid {
			fmt.Fprintf(tw, "verdict\tchain intact\n")
		} else {
			fmt.Fprintf(tw, "verdict\tBROKEN at seq %d\n", report.BreakAtSeq)
			fmt.Fprintf(tw, "cause\t%s\n", report.BreakCause)
			fmt.Fprintf(tw, "note\tevery entry after this point is untrustworthy\n")
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if !report.Valid {
		// A broken chain must not exit zero. A verification command that
		// reports tampering and succeeds is invisible in any pipeline.
		return fmt.Errorf("audit chain is broken at sequence %d", report.BreakAtSeq)
	}
	return nil
}

func cmdAuditHead(ctx context.Context, c *conn, g globals, out io.Writer) error {
	head, err := c.ledger.Head(ctx)
	if err != nil {
		return fmt.Errorf("reading the ledger head: %w", err)
	}
	if g.jsonOut {
		return writeJSON(out, head)
	}
	tw := newTable(out)
	fmt.Fprintf(tw, "seq\t%d\nkind\t%s\nactor\t%s\nat\t%s\nhash\t%s\n",
		head.Seq, head.Kind, head.Actor, head.At.UTC().Format(time.RFC3339), head.Hash)
	return tw.Flush()
}

// cmdIncidentShow is the explainability surface: everything that happened to
// one incident, in the order it happened, including every invariant that fired.
func cmdIncidentShow(ctx context.Context, c *conn, g globals, id string, out io.Writer) error {
	in, err := c.pg.GetIncident(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no incident %q", id)
		}
		return fmt.Errorf("reading incident: %w", err)
	}
	attempts, err := c.pg.ListAttempts(ctx, id)
	if err != nil {
		return fmt.Errorf("reading attempts: %w", err)
	}
	entries, err := c.ledger.List(ctx, id)
	if err != nil {
		return fmt.Errorf("reading the ledger: %w", err)
	}

	if g.jsonOut {
		// RawPayload is withheld even here. It is the verbatim webhook body and
		// can carry customer contact details; an operator debugging a decision
		// needs the decision, not the payer's phone number.
		in.RawPayload = nil
		return writeJSON(out, map[string]any{
			"incident": in, "attempts": attempts, "audit": entries,
		})
	}

	tw := newTable(out)
	fmt.Fprintf(tw, "incident\t%s\n", in.ID)
	fmt.Fprintf(tw, "payment\t%s  order %s\n", in.PaymentID, in.OrderID)
	fmt.Fprintf(tw, "amount\t%s %s\n", formatPaisa(in.AmountPaisa), in.Currency)
	fmt.Fprintf(tw, "issuer\t%s via %s\n", in.IssuerKey, in.Method)
	fmt.Fprintf(tw, "decline\t%s\n", in.ErrorCode)
	fmt.Fprintf(tw, "state\t%s after %d attempt(s)\n", in.State, in.AttemptCount)
	fmt.Fprintf(tw, "recurring\t%t\n", in.IsRecurring)
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(out, "\ndecision trail\n")
	dt := newTable(out)
	fmt.Fprintf(dt, "  SEQ\tKIND\tDETAIL\n")
	for _, e := range entries {
		fmt.Fprintf(dt, "  %d\t%s\t%s\n", e.Seq, e.Kind, summariseDetail(e))
	}
	if err := dt.Flush(); err != nil {
		return err
	}

	if len(attempts) == 0 {
		fmt.Fprintf(out, "\nno attempts executed\n")
		return nil
	}
	fmt.Fprintf(out, "\nattempts\n")
	at := newTable(out)
	fmt.Fprintf(at, "  N\tRAIL\tOUTCOME\tCODE\tCOST\tCOMPLETED\n")
	for _, a := range attempts {
		outcome := "failed"
		if a.Succeeded {
			outcome = "succeeded"
		}
		// Cost is the gateway fee plus the modelled friction of asking the payer
		// to act again. Reporting only the fee would make every in-session morph
		// look free, and the friction is the reason a morph is not always right.
		fmt.Fprintf(at, "  %d\t%s\t%s\t%s\t%s\t%s\n",
			a.AttemptNumber, a.Rail, outcome, orDash(a.ErrorCode),
			formatPaisa(a.GatewayFeePaisa+a.FrictionPaisa),
			a.CompletedAt.UTC().Format(time.RFC3339))
	}
	return at.Flush()
}

// summariseDetail renders the one line an operator actually reads. The full
// detail is available with --json; a wall of JSON in a terminal hides the
// invariant list rather than showing it.
func summariseDetail(e domain.AuditEntry) string {
	var d struct {
		Action     string   `json:"action"`
		Mode       string   `json:"mode"`
		Confidence float64  `json:"confidence"`
		RootCause  string   `json:"root_cause"`
		Rail       string   `json:"target_rail"`
		Delay      int64    `json:"delay_seconds"`
		Invariants []string `json:"applied_invariants"`
		Reasons    []string `json:"veto_reasons"`
	}
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		return "(detail is not the expected shape)"
	}
	switch e.Kind {
	case domain.AuditDiagnosis:
		return fmt.Sprintf("%s proposed %s at %.2f — %s",
			orDash(d.Mode), orDash(d.Action), d.Confidence, truncate(d.RootCause, 60))
	case domain.AuditGateDecision:
		s := fmt.Sprintf("%s rail=%s delay=%ds", orDash(d.Action), orDash(d.Rail), d.Delay)
		if len(d.Invariants) > 0 {
			s += " [" + strings.Join(d.Invariants, " ") + "]"
		}
		if len(d.Reasons) > 0 {
			s += " vetoed: " + truncate(d.Reasons[0], 70)
		}
		return s
	default:
		return truncate(string(e.Detail), 90)
	}
}

func cmdIncidentList(ctx context.Context, c *conn, g globals, out io.Writer) error {
	incidents, err := c.pg.ListIncidents(ctx, g.limit)
	if err != nil {
		return fmt.Errorf("listing incidents: %w", err)
	}
	if g.jsonOut {
		for i := range incidents {
			incidents[i].RawPayload = nil
		}
		return writeJSON(out, map[string]any{"items": incidents})
	}
	tw := newTable(out)
	fmt.Fprintf(tw, "INCIDENT\tISSUER\tCODE\tAMOUNT\tSTATE\tN\n")
	for _, in := range incidents {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n",
			short(in.ID), in.IssuerKey, in.ErrorCode,
			formatPaisa(in.AmountPaisa), in.State, in.AttemptCount)
	}
	return tw.Flush()
}

func cmdDowntime(ctx context.Context, c *conn, g globals, out io.Writer) error {
	// meshctl reads the durable record rather than starting its own poller: a
	// second poller would consume the same API quota and could report a view
	// the running mesh has never seen, which is worse than reporting nothing.
	entries, err := c.recentAuditOfKind(ctx, domain.AuditDowntimeRelease, g.limit)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(out, map[string]any{"releases": entries})
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no downtime resolutions recorded")
		return nil
	}
	tw := newTable(out)
	fmt.Fprintf(tw, "SEQ\tAT\tDETAIL\n")
	for _, e := range entries {
		fmt.Fprintf(tw, "%d\t%s\t%s\n", e.Seq, e.At.UTC().Format(time.RFC3339),
			truncate(string(e.Detail), 90))
	}
	return tw.Flush()
}

func (c *conn) recentAuditOfKind(ctx context.Context, kind domain.AuditKind, limit int) ([]domain.AuditEntry, error) {
	out := make([]domain.AuditEntry, 0, limit)
	err := c.pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if e.Kind != kind {
			return nil
		}
		if len(out) == limit {
			copy(out, out[1:])
			out = out[:limit-1]
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

func cmdDLQList(ctx context.Context, c *conn, g globals, out io.Writer) error {
	items, err := c.q.ListDeadLetters(ctx, g.limit)
	if err != nil {
		return fmt.Errorf("listing dead letters: %w", err)
	}
	if g.jsonOut {
		return writeJSON(out, map[string]any{"items": items})
	}
	if len(items) == 0 {
		fmt.Fprintln(out, "dead-letter queue is empty")
		return nil
	}
	tw := newTable(out)
	fmt.Fprintf(tw, "MESSAGE\tCAUSE\n")
	for _, d := range items {
		fmt.Fprintf(tw, "%s\t%s\n", d.ID, truncate(d.Cause, 90))
	}
	return tw.Flush()
}

// ---------------------------------------------------------------------------
// Mutating commands
// ---------------------------------------------------------------------------

// requireConfirmation is the guard every mutation passes through. A destructive
// operator command that runs on a typo is an incident of its own.
func requireConfirmation(g globals, what string) error {
	if g.yes {
		return nil
	}
	return badUsage("%s changes system state; re-run with --yes to confirm", what)
}

func cmdDLQReplay(ctx context.Context, c *conn, g globals, id string, out io.Writer) error {
	if err := requireConfirmation(g, "dlq replay"); err != nil {
		return err
	}
	// Intent is recorded before the action, so the ledger shows what was
	// attempted even if the requeue then fails.
	if _, err := c.ledger.Append(ctx, domain.AuditDeadLettered, "", "operator", map[string]any{
		"operation":  "dlq_replay",
		"message_id": id,
		"reason":     g.reason,
	}); err != nil {
		return fmt.Errorf("recording the replay intent: %w", err)
	}
	if err := c.q.Requeue(ctx, id); err != nil {
		return fmt.Errorf("requeueing %s: %w", id, err)
	}
	if g.jsonOut {
		return writeJSON(out, map[string]any{"replayed": id})
	}
	fmt.Fprintf(out, "replayed %s\n", id)
	return nil
}

func cmdMandateShow(ctx context.Context, c *conn, g globals, sub string, out io.Writer) error {
	m, err := c.pg.GetMandate(ctx, sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no mandate for subscription %q", sub)
		}
		return fmt.Errorf("reading mandate: %w", err)
	}
	if g.jsonOut {
		return writeJSON(out, m)
	}
	tw := newTable(out)
	fmt.Fprintf(tw, "subscription\t%s\n", m.SubscriptionID)
	fmt.Fprintf(tw, "amount\t%s\n", formatPaisa(m.AmountPaisa))
	fmt.Fprintf(tw, "category\t%s (AFA ceiling %s)\n",
		orDash(string(m.Category)), formatPaisa(m.Category.AFACeilingPaisa()))
	fmt.Fprintf(tw, "cycle\t%s, %d attempt(s)\n", orDash(m.CycleKey), m.AttemptsInCycle)
	fmt.Fprintf(tw, "halted\t%t %s\n", m.Halted, m.HaltReason)
	if m.NextEligibleAt != nil {
		fmt.Fprintf(tw, "next eligible\t%s\n", m.NextEligibleAt.UTC().Format(time.RFC3339))
	}
	if m.PreDebitNotifiedAt != nil {
		fmt.Fprintf(tw, "pre-debit notice\t%s\n", m.PreDebitNotifiedAt.UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}

// cmdMandateHalt is the regulatory stop switch. It takes effect immediately and
// names the operator and the reason in the ledger, because "who stopped billing
// this customer, and why" is a question that gets asked months later.
func cmdMandateHalt(ctx context.Context, c *conn, g globals, sub string, out io.Writer) error {
	if err := requireConfirmation(g, "mandate halt"); err != nil {
		return err
	}
	if strings.TrimSpace(g.reason) == "" {
		return badUsage("mandate halt requires --reason; an unexplained halt is unauditable")
	}
	m, err := c.pg.GetMandate(ctx, sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no mandate for subscription %q", sub)
		}
		return fmt.Errorf("reading mandate: %w", err)
	}
	if _, err := c.ledger.Append(ctx, domain.AuditOperatorAction, "", "operator", map[string]any{
		"subscription_id": sub,
		"reason":          g.reason,
		"was_halted":      m.Halted,
	}); err != nil {
		return fmt.Errorf("recording the halt intent: %w", err)
	}
	m.Halted, m.HaltReason = true, g.reason
	if err := c.pg.SaveMandate(ctx, m); err != nil {
		return fmt.Errorf("halting mandate: %w", err)
	}
	if g.jsonOut {
		return writeJSON(out, map[string]any{"subscription_id": sub, "halted": true, "reason": g.reason})
	}
	fmt.Fprintf(out, "halted %s: %s\n", sub, g.reason)
	return nil
}

func cmdMandateResume(ctx context.Context, c *conn, g globals, sub string, out io.Writer) error {
	if err := requireConfirmation(g, "mandate resume"); err != nil {
		return err
	}
	m, err := c.pg.GetMandate(ctx, sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no mandate for subscription %q", sub)
		}
		return fmt.Errorf("reading mandate: %w", err)
	}
	if !m.Halted {
		return fmt.Errorf("mandate %s is not halted", sub)
	}
	// A mandate halted because the payer revoked it must not be resumed by an
	// operator: the authority to debit came from the payer and only the payer
	// can restore it. Refusing here rather than warning is deliberate.
	if strings.Contains(strings.ToLower(m.HaltReason), "revoke") {
		return fmt.Errorf(
			"refusing to resume %s: it was halted for revocation (%q), which only re-registration can undo",
			sub, m.HaltReason)
	}
	if _, err := c.ledger.Append(ctx, domain.AuditOperatorAction, "", "operator", map[string]any{
		"subscription_id": sub,
		"operation":       "resume",
		"previous_reason": m.HaltReason,
		"operator_reason": g.reason,
	}); err != nil {
		return fmt.Errorf("recording the resume intent: %w", err)
	}
	m.Halted, m.HaltReason = false, ""
	if err := c.pg.SaveMandate(ctx, m); err != nil {
		return fmt.Errorf("resuming mandate: %w", err)
	}
	if g.jsonOut {
		return writeJSON(out, map[string]any{"subscription_id": sub, "halted": false})
	}
	fmt.Fprintf(out, "resumed %s\n", sub)
	return nil
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// newTable returns aligned-column output with no colour codes. Colour corrupts
// piped output, and an operator command is piped more often than it is read.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		// Control characters would let a stored value rewrite the terminal.
		// Ledger detail is written by this system, but rendering it safely
		// costs nothing and removes the question.
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// formatPaisa renders integer paisa as rupees. The arithmetic stays in integers
// throughout: a float here would be the one float on a money path.
func formatPaisa(p int64) string {
	neg := p < 0
	if neg {
		p = -p
	}
	s := fmt.Sprintf("₹%d.%02d", p/100, p%100)
	if neg {
		return "-" + s
	}
	return s
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// These tests run against a real PostgreSQL, because every property this
// package exists to provide — SKIP LOCKED claim exclusivity, advisory-lock
// serialisation of the hash chain, JSONB round-tripping, constraint
// enforcement — is a property of the database and not of the Go code. A mock
// would test the mock.
//
// internal/infra deliberately is not imported: it depends on this package, and
// a test-only import would make the dependency cycle real.

// testDSN is written once by TestMain before any test runs and only read
// afterwards, so it needs no synchronisation.
var testDSN string

func TestMain(m *testing.M) {
	if os.Getenv("MESH_SKIP_HEAVY_TESTS") != "" {
		fmt.Println("store: MESH_SKIP_HEAVY_TESTS set; skipping the embedded-postgres suite")
		os.Exit(0)
	}
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store: cannot run suite: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runSuite exists so the deferred shutdown of the database actually runs:
// os.Exit in TestMain would skip it and leave a postgres process behind.
func runSuite(m *testing.M) (int, error) {
	port, err := freePort()
	if err != nil {
		return 0, fmt.Errorf("reserve port: %w", err)
	}

	// The downloaded archive is cached across runs so only the first run on a
	// machine pays for it; everything the running server touches is per-run, so
	// a suite can never inherit another run's state or file locks.
	cache := filepath.Join(os.TempDir(), "resilientmesh-embedded-pg-cache")
	work, err := os.MkdirTemp("", "mesh-store-pg")
	if err != nil {
		return 0, fmt.Errorf("create work dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			fmt.Fprintf(os.Stderr, "store: leftover test dir %s: %v\n", work, err)
		}
	}()

	pg, err := startPostgres(work, cache, port)
	if err != nil {
		return 0, fmt.Errorf("start embedded postgres: %w", err)
	}
	defer func() {
		if err := pg.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "store: stop embedded postgres: %v\n", err)
		}
	}()

	testDSN = testsecret.PostgresDSN("mesh", "mesh", fmt.Sprintf("127.0.0.1:%d", port),
		"mesh_store_test", "sslmode=disable")
	return m.Run(), nil
}

// startPostgres brings the database up in a directory owned by this run alone,
// retrying once in a fresh directory.
//
// Only the downloaded archive is shared between runs; the extracted binaries
// are not. Two things break a shared extraction directory on Windows: a
// `go test ./...` that runs this package in parallel with another suite using
// the same cache, and a virus scanner that holds a freshly written .exe long
// enough for the rename to fail with "Access is denied". Both leave locked
// files that no amount of cleanup can remove, so the retry moves to a new
// directory rather than trying to repair the old one. Extraction costs seconds
// and buys a suite that cannot be flaked by a neighbouring test process.
func startPostgres(work, cache string, port uint32) (*embeddedpostgres.EmbeddedPostgres, error) {
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		root := filepath.Join(work, fmt.Sprintf("attempt-%d", attempt))
		pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
			Username("mesh").
			Password("mesh").
			Database("mesh_store_test").
			Port(port).
			RuntimePath(filepath.Join(root, "runtime")).
			DataPath(filepath.Join(root, "data")).
			BinariesPath(filepath.Join(root, "binaries")).
			CachePath(cache).
			StartTimeout(3 * time.Minute).
			Logger(io.Discard))

		if err := pg.Start(); err != nil {
			lastErr = err
			continue
		}
		return pg, nil
	}
	return nil, lastErr
}

func freePort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return 0, err
	}
	return uint32(port), nil
}

func newStore(t *testing.T) *Postgres {
	t.Helper()
	p, err := New(context.Background(), testDSN, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return p
}

// reset gives each test an empty database. Tests in a package run
// sequentially, so a truncate between them is safe and keeps assertions about
// absolute sequence numbers meaningful.
func reset(t *testing.T, p *Postgres) {
	t.Helper()
	const sql = `TRUNCATE audit_ledger, attempts, outbox_events, sessions, mandates, incidents RESTART IDENTITY CASCADE`
	if _, err := p.pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func newIncident(eventID string) domain.Incident {
	id := uuid.NewString()
	now := time.Now().UTC()
	return domain.Incident{
		ID:          id,
		PaymentID:   "pay_" + id[:8],
		OrderID:     "order_" + id[:8],
		EventID:     eventID,
		AmountPaisa: 249900,
		Currency:    "INR",
		Method:      "upi",
		IssuerKey:   "upi:okhdfcbank",
		ErrorCode:   "bank_technical_error",
		State:       domain.IncidentReceived,
		IsRecurring: false,
		RawPayload:  domain.RawJSON(`{"entity":"event","payload":{"payment":{"entity":{"amount":249900}}}}`),
		ReceivedAt:  now,
		UpdatedAt:   now,
	}
}

func insertIncident(t *testing.T, p *Postgres, in domain.Incident) {
	t.Helper()
	err := p.WithTx(context.Background(), func(ctx context.Context, tx domain.Tx) error {
		return tx.InsertIncident(ctx, in)
	})
	if err != nil {
		t.Fatalf("insert incident: %v", err)
	}
}

// ---------------------------------------------------------------------------

func TestMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)

	// A second New runs the migration path again against the same database.
	second := newStore(t)

	var applied int
	if err := second.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if applied != len(migrations) {
		t.Fatalf("schema_migrations rows = %d, want %d", applied, len(migrations))
	}

	for _, table := range []string{
		"schema_migrations", "incidents", "outbox_events", "mandates",
		"attempts", "sessions", "audit_ledger",
	} {
		var exists bool
		const sql = `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)`
		if err := p.pool.QueryRow(ctx, sql, table).Scan(&exists); err != nil {
			t.Fatalf("look up table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s missing after migration", table)
		}
	}

	for _, index := range []string{
		"ux_incidents_event_id", "ix_incidents_payment_id", "ix_outbox_state_id",
		"ix_sessions_order_id", "ix_audit_incident_seq",
	} {
		var exists bool
		const sql = `SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1)`
		if err := p.pool.QueryRow(ctx, sql, index).Scan(&exists); err != nil {
			t.Fatalf("look up index %s: %v", index, err)
		}
		if !exists {
			t.Errorf("index %s missing after migration", index)
		}
	}

	// seq must be unique, or two entries could claim the same chain position.
	var unique bool
	const uniqueSQL = `
SELECT EXISTS (
    SELECT 1 FROM pg_index i
      JOIN pg_class c ON c.oid = i.indrelid
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
     WHERE c.relname = 'audit_ledger' AND i.indisunique AND i.indnkeyatts = 1 AND a.attname = 'seq')`
	if err := p.pool.QueryRow(ctx, uniqueSQL).Scan(&unique); err != nil {
		t.Fatalf("look up audit_ledger unique index: %v", err)
	}
	if !unique {
		t.Error("audit_ledger(seq) is not unique")
	}
}

func TestIncidentInsertAndEventIDConflict(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	eventID := "evt_" + uuid.NewString()
	in := newIncident(eventID)
	insertIncident(t, p, in)

	got, err := p.GetIncidentByEventID(ctx, eventID)
	if err != nil {
		t.Fatalf("GetIncidentByEventID: %v", err)
	}
	if got.ID != in.ID || got.AmountPaisa != in.AmountPaisa || got.Currency != in.Currency {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
	if got.State != domain.IncidentReceived {
		t.Fatalf("state = %q, want RECEIVED", got.State)
	}
	if !got.ReceivedAt.Equal(in.ReceivedAt.Truncate(time.Microsecond)) {
		t.Errorf("received_at = %s, want %s", got.ReceivedAt, in.ReceivedAt)
	}

	// The replay guard: a different incident carrying the same Razorpay event
	// id must be refused by the database, not merely by an application check.
	dup := newIncident(eventID)
	err = p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		return tx.InsertIncident(ctx, dup)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate event_id error = %v, want ErrConflict", err)
	}
	if _, err := p.GetIncident(ctx, dup.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate incident was written: %v", err)
	}

	if _, err := p.GetIncident(ctx, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetIncident(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := p.GetIncidentByEventID(ctx, "evt_absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetIncidentByEventID(unknown) = %v, want ErrNotFound", err)
	}

	if err := p.UpdateIncidentState(ctx, in.ID, domain.IncidentGated); err != nil {
		t.Fatalf("UpdateIncidentState: %v", err)
	}
	if err := p.UpdateIncidentState(ctx, in.ID, domain.IncidentState("NONSENSE")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("UpdateIncidentState(unknown state) = %v, want ErrInvalidInput", err)
	}
	if err := p.UpdateIncidentState(ctx, uuid.NewString(), domain.IncidentGated); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateIncidentState(unknown id) = %v, want ErrNotFound", err)
	}

	for want := 1; want <= 3; want++ {
		n, err := p.IncrementIncidentAttempts(ctx, in.ID)
		if err != nil {
			t.Fatalf("IncrementIncidentAttempts: %v", err)
		}
		if n != want {
			t.Fatalf("attempt count = %d, want %d", n, want)
		}
	}

	list, err := p.ListIncidents(ctx, 10)
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(list) != 1 || list[0].ID != in.ID || list[0].AttemptCount != 3 {
		t.Fatalf("ListIncidents = %+v", list)
	}
}

func TestIncidentRejectsUnrepresentableInput(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	cases := map[string]func(domain.Incident) domain.Incident{
		"empty event id":   func(in domain.Incident) domain.Incident { in.EventID = ""; return in },
		"oversized id":     func(in domain.Incident) domain.Incident { in.ID = longString(200); return in },
		"negative amount":  func(in domain.Incident) domain.Incident { in.AmountPaisa = -1; return in },
		"malformed json":   func(in domain.Incident) domain.Incident { in.RawPayload = domain.RawJSON(`{"a":`); return in },
		"unknown state":    func(in domain.Incident) domain.Incident { in.State = "WAT"; return in },
		"oversized issuer": func(in domain.Incident) domain.Incident { in.IssuerKey = longString(300); return in },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := mutate(newIncident("evt_" + uuid.NewString()))
			err := p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
				return tx.InsertIncident(ctx, in)
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestWithTxLeavesNoRowsOnError(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	sentinel := errors.New("caller failed after writing")
	in := newIncident("evt_" + uuid.NewString())

	err := p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		if err := tx.InsertIncident(ctx, in); err != nil {
			return err
		}
		if err := tx.InsertOutboxEvent(ctx, domain.OutboxEvent{
			IncidentID: in.ID, Topic: "incident.created",
			Payload: domain.RawJSON(`{"incident_id":"x"}`),
		}); err != nil {
			return err
		}
		if err := tx.AppendAudit(ctx, domain.AuditEntry{
			IncidentID: in.ID, Kind: domain.AuditWebhookAccepted, Actor: "test",
			Detail: domain.RawJSON(`{"ok":true}`), At: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx error = %v, want the caller's error", err)
	}

	if _, err := p.GetIncident(ctx, in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("incident survived rollback: %v", err)
	}
	pending, failed, err := p.OutboxDepth(ctx)
	if err != nil {
		t.Fatalf("OutboxDepth: %v", err)
	}
	if pending != 0 || failed != 0 {
		t.Errorf("outbox depth = (%d, %d), want (0, 0)", pending, failed)
	}
	if _, err := p.AuditHead(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("audit entry survived rollback: %v", err)
	}
}

func TestWithTxRollsBackOnPanic(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	in := newIncident("evt_" + uuid.NewString())
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("panic did not propagate out of WithTx")
			}
		}()
		// The error is discarded because there is none: the callback panics,
		// so WithTx never returns through this assignment.
		_ = p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
			if err := tx.InsertIncident(ctx, in); err != nil {
				return err
			}
			panic("worker blew up mid-transaction")
		})
	}()

	if _, err := p.GetIncident(ctx, in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("incident survived panic rollback: %v", err)
	}
	// The connection must be usable again: a leaked open transaction would
	// hold locks until the idle timeout.
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("pool unusable after panic: %v", err)
	}
}

func TestClaimOutboxBatchNeverOverlaps(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	const (
		total   = 400
		relays  = 2
		batchSz = 25
	)

	in := newIncident("evt_" + uuid.NewString())
	err := p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		if err := tx.InsertIncident(ctx, in); err != nil {
			return err
		}
		for i := 0; i < total; i++ {
			if err := tx.InsertOutboxEvent(ctx, domain.OutboxEvent{
				IncidentID: in.ID,
				Topic:      "incident.created",
				Payload:    domain.RawJSON(fmt.Sprintf(`{"n":%d}`, i)),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed outbox: %v", err)
	}

	var (
		mu      sync.Mutex
		claims  = make(map[int64]int, total)
		byRelay = make(map[int]int, relays)
		wg      sync.WaitGroup
	)
	for relay := 0; relay < relays; relay++ {
		wg.Add(1)
		go func(relay int) {
			defer wg.Done()
			empties := 0
			for empties < 3 {
				batch, err := p.ClaimOutboxBatch(ctx, batchSz)
				if err != nil {
					t.Errorf("relay %d claim: %v", relay, err)
					return
				}
				if len(batch) == 0 {
					// The other relay may be mid-transaction on the last rows;
					// yield and look again before concluding the queue is dry.
					empties++
					runtime.Gosched()
					continue
				}
				empties = 0

				ids := make([]int64, 0, len(batch))
				mu.Lock()
				for _, ev := range batch {
					claims[ev.ID]++
					byRelay[relay]++
					ids = append(ids, ev.ID)
				}
				mu.Unlock()

				for i := 1; i < len(batch); i++ {
					if batch[i].ID <= batch[i-1].ID {
						t.Errorf("relay %d got an unordered batch: %d after %d",
							relay, batch[i].ID, batch[i-1].ID)
					}
				}
				if err := p.MarkOutboxDispatched(ctx, ids); err != nil {
					t.Errorf("relay %d mark dispatched: %v", relay, err)
					return
				}
			}
		}(relay)
	}
	wg.Wait()

	if len(claims) != total {
		t.Fatalf("claimed %d distinct events, want %d", len(claims), total)
	}
	for id, n := range claims {
		if n != 1 {
			t.Fatalf("event %d was claimed %d times: two relays would have double-dispatched it", id, n)
		}
	}
	if byRelay[0] == 0 || byRelay[1] == 0 {
		t.Fatalf("one relay did all the work (%v); the test proved nothing", byRelay)
	}

	pending, failed, err := p.OutboxDepth(ctx)
	if err != nil {
		t.Fatalf("OutboxDepth: %v", err)
	}
	if pending != 0 || failed != 0 {
		t.Fatalf("outbox depth = (%d, %d), want (0, 0)", pending, failed)
	}

	var dispatched int
	if err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox_events WHERE state = 'DISPATCHED' AND dispatched_at IS NOT NULL`).
		Scan(&dispatched); err != nil {
		t.Fatalf("count dispatched: %v", err)
	}
	if dispatched != total {
		t.Fatalf("dispatched %d rows, want %d", dispatched, total)
	}
}

func TestMarkOutboxFailed(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	in := newIncident("evt_" + uuid.NewString())
	err := p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		if err := tx.InsertIncident(ctx, in); err != nil {
			return err
		}
		return tx.InsertOutboxEvent(ctx, domain.OutboxEvent{
			IncidentID: in.ID, Topic: "incident.created", Payload: domain.RawJSON(`{"n":1}`),
		})
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	batch, err := p.ClaimOutboxBatch(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimOutboxBatch: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("claimed %d events, want 1", len(batch))
	}
	if batch[0].Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 after a claim", batch[0].Attempts)
	}

	// Over-long gateway text must be truncated into the record, not lose it.
	if err := p.MarkOutboxFailed(ctx, batch[0].ID, longString(4000)); err != nil {
		t.Fatalf("MarkOutboxFailed: %v", err)
	}
	pending, failed, err := p.OutboxDepth(ctx)
	if err != nil {
		t.Fatalf("OutboxDepth: %v", err)
	}
	if pending != 0 || failed != 1 {
		t.Fatalf("outbox depth = (%d, %d), want (0, 1)", pending, failed)
	}
	if err := p.MarkOutboxFailed(ctx, batch[0].ID+9999, "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MarkOutboxFailed(unknown) = %v, want ErrNotFound", err)
	}
}

func TestAuditChainIsLinearUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	const (
		writers = 8
		each    = 25
		total   = writers * each
	)

	incidentID := uuid.NewString()
	var (
		mu       sync.Mutex
		appended = make(map[int64]domain.AuditEntry, total)
		wg       sync.WaitGroup
	)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// Keys deliberately out of order and padded with whitespace:
				// JSONB rewrites this, and the stored bytes are what the hash
				// must commit to.
				detail := domain.RawJSON(fmt.Sprintf(`{ "writer" : %d ,  "i": %d, "actor_note": "x" }`, w, i))
				e, err := p.AppendAuditRow(ctx, domain.AuditEntry{
					IncidentID: incidentID,
					Kind:       domain.AuditGateDecision,
					Actor:      fmt.Sprintf("worker-%d", w),
					Detail:     detail,
					At:         time.Now().UTC(), // nanosecond precision on purpose
				})
				if err != nil {
					t.Errorf("writer %d append: %v", w, err)
					return
				}
				mu.Lock()
				if prev, dup := appended[e.Seq]; dup {
					t.Errorf("seq %d allocated twice (also to %s)", e.Seq, prev.Actor)
				}
				appended[e.Seq] = e
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	if len(appended) != total {
		t.Fatalf("allocated %d sequence numbers, want %d", len(appended), total)
	}

	// Walk the chain exactly as Verify will: seq must be 1..N with no gaps,
	// every prev_hash must equal the previous entry's hash, and every hash must
	// be reproducible from the row as stored.
	prev := domain.GenesisHash
	want := int64(1)
	seen := 0
	err := p.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if e.Seq != want {
			return fmt.Errorf("seq %d out of order, want %d", e.Seq, want)
		}
		if !e.VerifyAgainst(prev) {
			return fmt.Errorf("chain broken at seq %d", e.Seq)
		}
		stored, ok := appended[e.Seq]
		if !ok {
			return fmt.Errorf("seq %d was never returned by an append", e.Seq)
		}
		if stored.Hash != e.Hash || !bytes.Equal(stored.Detail, e.Detail) {
			return fmt.Errorf("seq %d differs between append and read back", e.Seq)
		}
		if !stored.At.Equal(e.At) {
			return fmt.Errorf("seq %d timestamp drifted: %s vs %s", e.Seq, stored.At, e.At)
		}
		prev = e.Hash
		want++
		seen++
		return nil
	})
	if err != nil {
		t.Fatalf("StreamAudit: %v", err)
	}
	if seen != total {
		t.Fatalf("streamed %d entries, want %d", seen, total)
	}

	head, err := p.AuditHead(ctx)
	if err != nil {
		t.Fatalf("AuditHead: %v", err)
	}
	if head.Seq != total || head.Hash != prev {
		t.Fatalf("head = (seq %d, hash %s), want (seq %d, hash %s)", head.Seq, head.Hash, total, prev)
	}

	byIncident, err := p.ListAuditByIncident(ctx, incidentID)
	if err != nil {
		t.Fatalf("ListAuditByIncident: %v", err)
	}
	if len(byIncident) != total {
		t.Fatalf("ListAuditByIncident returned %d entries, want %d", len(byIncident), total)
	}
	for i := 1; i < len(byIncident); i++ {
		if byIncident[i].Seq <= byIncident[i-1].Seq {
			t.Fatalf("ListAuditByIncident is not in chain order at %d", i)
		}
	}
}

func TestAuditTamperIsDetectedAtTheMutatedSeq(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	const total = 12
	for i := 0; i < total; i++ {
		if _, err := p.AppendAuditRow(ctx, domain.AuditEntry{
			IncidentID: "inc-tamper",
			Kind:       domain.AuditAttemptResult,
			Actor:      "worker",
			Detail:     domain.RawJSON(fmt.Sprintf(`{"attempt":%d,"succeeded":false}`, i)),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	const tampered = int64(7)
	if err := p.MutateAuditDetailForTest(ctx, tampered, []byte(`{"attempt":7,"succeeded":true}`)); err != nil {
		t.Fatalf("MutateAuditDetailForTest: %v", err)
	}
	if err := p.MutateAuditDetailForTest(ctx, 9999, []byte(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MutateAuditDetailForTest(unknown seq) = %v, want ErrNotFound", err)
	}
	if err := p.MutateAuditDetailForTest(ctx, tampered, []byte(`{"broken":`)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("MutateAuditDetailForTest(bad json) = %v, want ErrInvalidInput", err)
	}

	var breaks []int64
	prev := domain.GenesisHash
	err := p.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if !e.VerifyAgainst(prev) {
			breaks = append(breaks, e.Seq)
		}
		prev = e.Hash
		return nil
	})
	if err != nil {
		t.Fatalf("StreamAudit: %v", err)
	}
	if len(breaks) != 1 || breaks[0] != tampered {
		t.Fatalf("chain breaks at %v, want exactly [%d]", breaks, tampered)
	}
}

func TestAuditRejectsUnrepresentableEntries(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	cases := map[string]domain.AuditEntry{
		"no kind":         {Actor: "x", Detail: domain.RawJSON(`{}`)},
		"no actor":        {Kind: domain.AuditDiagnosis, Detail: domain.RawJSON(`{}`)},
		"bad detail":      {Kind: domain.AuditDiagnosis, Actor: "x", Detail: domain.RawJSON(`{"a":`)},
		"huge detail":     {Kind: domain.AuditDiagnosis, Actor: "x", Detail: domain.RawJSON(`{"a":"` + longString(maxAuditDetailBytes) + `"}`)},
		"long incident":   {Kind: domain.AuditDiagnosis, Actor: "x", IncidentID: longString(200), Detail: domain.RawJSON(`{}`)},
		"long actor name": {Kind: domain.AuditDiagnosis, Actor: longString(100), Detail: domain.RawJSON(`{}`)},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := p.AppendAuditRow(ctx, e); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}

	// A rejected entry must not have consumed a sequence number.
	if _, err := p.AuditHead(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AuditHead on empty ledger = %v, want ErrNotFound", err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	orderID := "order_" + uuid.NewString()[:12]
	now := time.Now().UTC()
	s := domain.SessionRecord{
		ID:          uuid.NewString(),
		OrderID:     orderID,
		TokenHash:   longString(64),
		CurrentRail: domain.RailUPIIntent,
		AmountPaisa: 189900,
		Currency:    "INR",
		Active:      true,
		CreatedAt:   now,
		ExpiresAt:   now.Add(15 * time.Minute),
	}
	if err := p.CreateSession(ctx, s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := p.CreateSession(ctx, s); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate session id = %v, want ErrConflict", err)
	}

	got, err := p.GetSession(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.TokenHash != s.TokenHash || got.CurrentRail != domain.RailUPIIntent || got.AmountPaisa != s.AmountPaisa {
		t.Fatalf("session round trip mismatch: %+v", got)
	}
	if !got.ExpiresAt.Equal(s.ExpiresAt.Truncate(time.Microsecond)) {
		t.Errorf("expires_at = %s, want %s", got.ExpiresAt, s.ExpiresAt)
	}
	if got.Expired(now) {
		t.Error("fresh session reported as expired")
	}

	// An older, closed session for the same order must not shadow the live one.
	closed := s
	closed.ID = uuid.NewString()
	closed.Active = false
	closed.CreatedAt = now.Add(-time.Hour)
	closedAt := now.Add(-30 * time.Minute)
	closed.ClosedAt = &closedAt
	if err := p.CreateSession(ctx, closed); err != nil {
		t.Fatalf("CreateSession(closed): %v", err)
	}
	byOrder, err := p.GetSessionByOrder(ctx, orderID)
	if err != nil {
		t.Fatalf("GetSessionByOrder: %v", err)
	}
	if byOrder.ID != s.ID {
		t.Fatalf("GetSessionByOrder returned %s, want the active session %s", byOrder.ID, s.ID)
	}

	// A morph, written back without the token: the digest must survive.
	got.CurrentRail = domain.RailCard
	got.MorphCount++
	got.TokenHash = ""
	if err := p.UpdateSession(ctx, got); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	after, err := p.GetSession(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetSession after update: %v", err)
	}
	if after.CurrentRail != domain.RailCard || after.MorphCount != 1 {
		t.Fatalf("update did not apply: %+v", after)
	}
	if after.TokenHash != s.TokenHash {
		t.Fatal("blank token hash overwrote the stored digest")
	}

	if _, err := p.GetSession(ctx, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := p.GetSessionByOrder(ctx, "order_absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSessionByOrder(unknown) = %v, want ErrNotFound", err)
	}
	missing := got
	missing.ID = uuid.NewString()
	if err := p.UpdateSession(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSession(unknown) = %v, want ErrNotFound", err)
	}
	short := s
	short.ID = uuid.NewString()
	short.TokenHash = "tooshort"
	if err := p.CreateSession(ctx, short); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CreateSession(short token hash) = %v, want ErrInvalidInput", err)
	}
}

func TestMandateRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	subID := "sub_" + uuid.NewString()[:12]
	now := time.Now().UTC()
	m := domain.MandateRecord{
		SubscriptionID:  subID,
		CustomerID:      "cust_" + uuid.NewString()[:8],
		AmountPaisa:     99900,
		AttemptsInCycle: 1,
		CycleKey:        "2026-09",
		Category:        domain.CategoryInsurance,
		LastAttemptAt:   &now,
		UpdatedAt:       now,
	}
	if err := p.SaveMandate(ctx, m); err != nil {
		t.Fatalf("SaveMandate: %v", err)
	}

	got, err := p.GetMandate(ctx, subID)
	if err != nil {
		t.Fatalf("GetMandate: %v", err)
	}
	if got.AmountPaisa != m.AmountPaisa || got.AttemptsInCycle != 1 || got.CycleKey != "2026-09" {
		t.Fatalf("mandate round trip mismatch: %+v", got)
	}
	if got.LastAttemptAt == nil || !got.LastAttemptAt.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("last_attempt_at = %v, want %s", got.LastAttemptAt, now)
	}
	if got.NextEligibleAt != nil || got.PreDebitNotifiedAt != nil {
		t.Fatalf("unset timestamps came back non-nil: %+v", got)
	}
	// The category picks the AFA ceiling, so losing it in storage would quietly
	// change which regulatory limit a later debit is judged against.
	if got.Category != domain.CategoryInsurance {
		t.Fatalf("category = %q, want %q", got.Category, domain.CategoryInsurance)
	}
	if got.Category.AFACeilingPaisa() != domain.AFACeilingElevatedPaisa {
		t.Fatalf("stored category resolves to the wrong AFA ceiling: %d", got.Category.AFACeilingPaisa())
	}

	// An unrecognised category must land on the stricter general ceiling rather
	// than being written through or rejected.
	odd := m
	odd.SubscriptionID = "sub_" + uuid.NewString()[:12]
	odd.Category = domain.MandateCategory("platinum_whatever")
	if err := p.SaveMandate(ctx, odd); err != nil {
		t.Fatalf("SaveMandate(unknown category): %v", err)
	}
	coerced, err := p.GetMandate(ctx, odd.SubscriptionID)
	if err != nil {
		t.Fatalf("GetMandate(unknown category): %v", err)
	}
	if coerced.Category != domain.CategoryGeneral {
		t.Fatalf("unknown category stored as %q, want %q", coerced.Category, domain.CategoryGeneral)
	}

	// The RBI cooling window and the halt flag are the two fields a regulator
	// would ask about, so prove the upsert path actually updates them.
	next := now.Add(24 * time.Hour)
	got.NextEligibleAt = &next
	got.AttemptsInCycle = 3
	got.Halted = true
	got.HaltReason = longString(2000)
	got.UpdatedAt = now.Add(time.Second)
	if err := p.SaveMandate(ctx, got); err != nil {
		t.Fatalf("SaveMandate(update): %v", err)
	}
	after, err := p.GetMandate(ctx, subID)
	if err != nil {
		t.Fatalf("GetMandate after update: %v", err)
	}
	if !after.Halted || after.AttemptsInCycle != 3 || after.NextEligibleAt == nil {
		t.Fatalf("update did not apply: %+v", after)
	}
	if !after.NextEligibleAt.Equal(next.Truncate(time.Microsecond)) {
		t.Errorf("next_eligible_at = %s, want %s", after.NextEligibleAt, next)
	}
	if len([]rune(after.HaltReason)) != maxFreeTextLen {
		t.Errorf("halt reason length = %d, want it truncated to %d", len([]rune(after.HaltReason)), maxFreeTextLen)
	}

	// Same upsert, this time inside a caller transaction.
	err = p.WithTx(ctx, func(ctx context.Context, tx domain.Tx) error {
		after.Halted = false
		after.HaltReason = ""
		return tx.UpsertMandate(ctx, after)
	})
	if err != nil {
		t.Fatalf("UpsertMandate in tx: %v", err)
	}
	final, err := p.GetMandate(ctx, subID)
	if err != nil {
		t.Fatalf("GetMandate after tx: %v", err)
	}
	if final.Halted {
		t.Error("mandate still halted after transactional upsert")
	}

	if _, err := p.GetMandate(ctx, "sub_absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMandate(unknown) = %v, want ErrNotFound", err)
	}
}

func TestAttemptRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := newStore(t)
	reset(t, p)

	in := newIncident("evt_" + uuid.NewString())
	insertIncident(t, p, in)

	now := time.Now().UTC()
	presentations := []domain.InstrumentPresentation{
		"", // must default rather than fail: not every rail has a presentation
		domain.PresentationNetworkToken,
	}
	for i := 1; i <= 2; i++ {
		if err := p.RecordAttempt(ctx, domain.AttemptRecord{
			IncidentID:      in.ID,
			AttemptNumber:   i,
			Action:          domain.ActionAsyncRetry,
			Rail:            domain.RailUPIIntent,
			Presentation:    presentations[i-1],
			AmountPaisa:     in.AmountPaisa,
			Succeeded:       i == 2,
			GatewayFeePaisa: 250,
			FrictionPaisa:   60,
			ErrorCode:       "bank_technical_error",
			StartedAt:       now,
			CompletedAt:     now.Add(time.Second),
		}); err != nil {
			t.Fatalf("RecordAttempt %d: %v", i, err)
		}
	}

	list, err := p.ListAttempts(ctx, in.ID)
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(list) != 2 || list[0].AttemptNumber != 1 || list[1].AttemptNumber != 2 {
		t.Fatalf("ListAttempts = %+v", list)
	}
	if list[0].AmountPaisa != in.AmountPaisa || list[1].GatewayFeePaisa != 250 {
		t.Fatalf("attempt economics did not round trip: %+v", list)
	}
	if list[1].Rail != domain.RailUPIIntent || list[1].Action != domain.ActionAsyncRetry {
		t.Fatalf("attempt taxonomy did not round trip: %+v", list[1])
	}
	if list[0].Presentation != domain.PresentationUnchanged {
		t.Fatalf("empty presentation stored as %q, want %q", list[0].Presentation, domain.PresentationUnchanged)
	}
	if list[1].Presentation != domain.PresentationNetworkToken {
		t.Fatalf("presentation = %q, want %q", list[1].Presentation, domain.PresentationNetworkToken)
	}

	bad := domain.AttemptRecord{
		IncidentID: in.ID, AttemptNumber: 1, Action: "DO_WHATEVER",
		Rail: domain.RailCard, AmountPaisa: 1, StartedAt: now, CompletedAt: now,
	}
	if err := p.RecordAttempt(ctx, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RecordAttempt(unknown action) = %v, want ErrInvalidInput", err)
	}
	bad.Action = domain.ActionAsyncRetry
	bad.AttemptNumber = 0
	if err := p.RecordAttempt(ctx, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RecordAttempt(attempt 0) = %v, want ErrInvalidInput", err)
	}
	bad.AttemptNumber = 3
	bad.Presentation = domain.InstrumentPresentation("magic_new_scheme")
	if err := p.RecordAttempt(ctx, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RecordAttempt(unknown presentation) = %v, want ErrInvalidInput", err)
	}

	// The FK is what keeps the benchmark honest: attempts cannot exist for an
	// incident that does not.
	orphan := domain.AttemptRecord{
		IncidentID: uuid.NewString(), AttemptNumber: 1, Action: domain.ActionAsyncRetry,
		Rail: domain.RailCard, AmountPaisa: 1, StartedAt: now, CompletedAt: now,
	}
	if err := p.RecordAttempt(ctx, orphan); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("RecordAttempt(orphan) = %v, want ErrInvalidInput", err)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

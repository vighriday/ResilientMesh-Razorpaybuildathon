package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// The ledger tests run against a real PostgreSQL because everything worth
// proving here is a property of the database round trip: seq allocation under
// the advisory lock, jsonb canonicalisation of the detail document, and
// timestamp precision. A fake store would hash exactly the bytes it was handed
// and prove nothing about whether a chain written today verifies tomorrow.
//
// The redaction tests need no database and deliberately still run when
// MESH_SKIP_HEAVY_TESTS is set: redaction is the security-critical half of this
// package, and it must never be the part that goes unchecked on a constrained
// machine.

// plantedSecret is the canary the redaction tests hunt for. It is shaped like
// nothing a secret scanner should flag, on purpose — a realistic-looking key in
// a tracked file is a finding in its own right.
const plantedSecret = "PLANTED-CREDENTIAL-VALUE-DO-NOT-STORE"

// testDSN and dbReady are written once by TestMain before any test runs and only
// read afterwards, so they need no synchronisation.
var (
	testDSN string
	dbReady bool
)

func TestMain(m *testing.M) {
	if os.Getenv("MESH_SKIP_HEAVY_TESTS") != "" {
		fmt.Println("audit: MESH_SKIP_HEAVY_TESTS set; ledger tests skip, redaction tests still run")
		os.Exit(m.Run())
	}
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: cannot run suite: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runSuite exists so the deferred shutdown of the database actually runs:
// os.Exit inside TestMain would skip it and leave a postgres process behind.
func runSuite(m *testing.M) (int, error) {
	port, err := freePort()
	if err != nil {
		return 0, fmt.Errorf("reserve port: %w", err)
	}

	// Only the downloaded archive is shared between runs. Everything the server
	// touches is per-run, so one suite can never inherit another's data or file
	// locks.
	cache := filepath.Join(os.TempDir(), "resilientmesh-embedded-pg-cache")
	work, err := os.MkdirTemp("", "mesh-audit-pg")
	if err != nil {
		return 0, fmt.Errorf("create work dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			fmt.Fprintf(os.Stderr, "audit: leftover test dir %s: %v\n", work, err)
		}
	}()

	pg, err := startPostgres(work, cache, port)
	if err != nil {
		return 0, fmt.Errorf("start embedded postgres: %w", err)
	}
	defer func() {
		if err := pg.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "audit: stop embedded postgres: %v\n", err)
		}
	}()

	testDSN = testsecret.PostgresDSN("mesh", "mesh", fmt.Sprintf("127.0.0.1:%d", port),
		"mesh_audit_test", "sslmode=disable")
	dbReady = true
	return m.Run(), nil
}

// startPostgres extracts into a directory owned by this run alone, retrying once
// in a fresh one. On Windows a virus scanner can hold a freshly written binary
// long enough for the rename to fail, and a locked directory cannot be repaired
// — only abandoned.
func startPostgres(work, cache string, port uint32) (*embeddedpostgres.EmbeddedPostgres, error) {
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		root := filepath.Join(work, fmt.Sprintf("attempt-%d", attempt))
		pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
			Username("mesh").
			Password("mesh").
			Database("mesh_audit_test").
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

func requireDB(t *testing.T) {
	t.Helper()
	if !dbReady {
		t.Skip("audit: MESH_SKIP_HEAVY_TESTS set; embedded postgres not started")
	}
}

// stepClock advances a fixed amount per read so entries carry distinct, wholly
// deterministic timestamps. It is mutex-guarded because the concurrency test
// reads it from several goroutines at once.
type stepClock struct {
	mu sync.Mutex
	at time.Time
}

func newStepClock() *stepClock {
	return &stepClock{at: time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC)}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(time.Millisecond)
	return c.at
}

func newLedger(t *testing.T) (*Ledger, *store.Postgres) {
	t.Helper()
	requireDB(t)

	p, err := store.New(context.Background(), testDSN, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})

	// Tests in a package run sequentially, so an empty ledger between them keeps
	// assertions about absolute sequence numbers meaningful.
	execSQL(t, "TRUNCATE audit_ledger")
	return New(p, newStepClock(), "audit-test"), p
}

// execSQL reaches past the store on purpose: the tamper tests have to act like
// an attacker with direct database access, which is the threat the hash chain
// exists to detect.
func execSQL(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Errorf("conn.Close: %v", err)
		}
	}()
	tag, err := conn.Exec(ctx, sql, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	return tag.RowsAffected()
}

func appendN(t *testing.T, l *Ledger, incidentID string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		e, err := l.Append(ctx, domain.AuditGateDecision, incidentID, "worker-1",
			map[string]any{"step": i, "issuer_key": "netbanking:HDFC"})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if e.Seq != int64(i) {
			t.Fatalf("Append %d assigned seq %d", i, e.Seq)
		}
	}
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

func TestVerifyAcceptsIntactChain(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)
	incident := uuid.NewString()
	appendN(t, l, incident, 200)

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Valid {
		t.Fatalf("chain reported invalid at seq %d: %s", report.BreakAtSeq, report.BreakCause)
	}
	if report.Entries != 200 {
		t.Fatalf("Entries = %d, want 200", report.Entries)
	}
	if report.BreakAtSeq != 0 || report.BreakCause != "" {
		t.Fatalf("valid report carries break %d %q", report.BreakAtSeq, report.BreakCause)
	}
	if report.CheckedAt.IsZero() {
		t.Fatal("CheckedAt not stamped")
	}

	head, err := l.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head.Seq != 200 {
		t.Fatalf("head seq = %d, want 200", head.Seq)
	}
	if report.HeadHash != head.Hash {
		t.Fatalf("HeadHash = %q, want the head entry hash %q", report.HeadHash, head.Hash)
	}
}

func TestVerifyEmptyLedger(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Valid || report.Entries != 0 {
		t.Fatalf("empty ledger report = %+v, want valid with no entries", report)
	}
	if report.HeadHash != domain.GenesisHash {
		t.Fatalf("HeadHash = %q, want the genesis anchor", report.HeadHash)
	}
	if _, err := l.Head(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Head on empty ledger = %v, want store.ErrNotFound", err)
	}
}

// TestVerifyDetectsMutatedDetail is the tamper-detection proof: an attacker with
// write access to the table edits one historical decision, and the chain names
// the exact row.
func TestVerifyDetectsMutatedDetail(t *testing.T) {
	ctx := context.Background()
	l, p := newLedger(t)
	incident := uuid.NewString()
	appendN(t, l, incident, 200)

	const tampered = int64(137)
	if err := p.MutateAuditDetailForTest(ctx, tampered, []byte(`{"step":137,"issuer_key":"upi:okaxis"}`)); err != nil {
		t.Fatalf("MutateAuditDetailForTest: %v", err)
	}

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Valid {
		t.Fatal("Verify accepted a chain with an edited entry")
	}
	if report.BreakAtSeq != tampered {
		t.Fatalf("BreakAtSeq = %d, want %d", report.BreakAtSeq, tampered)
	}
	if report.BreakCause != CauseHashMismatch {
		t.Fatalf("BreakCause = %q, want %q", report.BreakCause, CauseHashMismatch)
	}
	// The walk stops at the break, so the verified prefix is everything before
	// the edited row.
	if report.Entries != tampered-1 {
		t.Fatalf("Entries = %d, want the %d verified before the break", report.Entries, tampered-1)
	}
}

func TestVerifyDetectsSequenceGap(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)
	incident := uuid.NewString()
	appendN(t, l, incident, 200)

	const deleted = int64(88)
	if n := execSQL(t, "DELETE FROM audit_ledger WHERE seq = $1", deleted); n != 1 {
		t.Fatalf("deleted %d rows, want 1", n)
	}

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Valid {
		t.Fatal("Verify accepted a chain with a deleted entry")
	}
	if report.BreakAtSeq != deleted {
		t.Fatalf("BreakAtSeq = %d, want the missing seq %d", report.BreakAtSeq, deleted)
	}
	if report.BreakCause != CauseSequenceGap {
		t.Fatalf("BreakCause = %q, want %q", report.BreakCause, CauseSequenceGap)
	}
}

// TestVerifyDetectsRelinkedEntry covers the remaining break: the row is present
// and self-consistent, but points at the wrong predecessor. That is what a
// reordering or a spliced-in entry looks like from the walk's point of view.
func TestVerifyDetectsRelinkedEntry(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)
	incident := uuid.NewString()
	appendN(t, l, incident, 20)

	const relinked = int64(9)
	forged := domain.AuditEntry{
		Seq:        relinked,
		IncidentID: incident,
		Kind:       domain.AuditGateDecision,
		Actor:      "worker-1",
		Detail:     domain.RawJSON(`{"step": 9}`),
		At:         time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC),
		PrevHash:   domain.GenesisHash,
	}
	forged.Hash = forged.ComputeHash()
	execSQL(t, "UPDATE audit_ledger SET detail = $2, occurred_at = $3, prev_hash = $4, hash = $5 WHERE seq = $1",
		forged.Seq, []byte(forged.Detail), forged.At, forged.PrevHash, forged.Hash)

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Valid {
		t.Fatal("Verify accepted a re-linked entry")
	}
	if report.BreakAtSeq != relinked {
		t.Fatalf("BreakAtSeq = %d, want %d", report.BreakAtSeq, relinked)
	}
	if report.BreakCause != CausePrevHashMismatch {
		t.Fatalf("BreakCause = %q, want %q", report.BreakCause, CausePrevHashMismatch)
	}
}

// TestConcurrentAppendsStayLinear is the reason the store takes an advisory
// lock. Without it two appenders read the same head and either collide on the
// primary key or fork the chain; both outcomes show up here as a failed Verify.
func TestConcurrentAppendsStayLinear(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)

	const (
		writers = 8
		each    = 20
	)
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			incident := uuid.NewString()
			for i := 0; i < each; i++ {
				if _, err := l.Append(ctx, domain.AuditAttemptResult, incident,
					fmt.Sprintf("worker-%d", w), map[string]any{"i": i}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Append: %v", err)
	}

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Valid {
		t.Fatalf("chain forked under concurrency: break at %d (%s)", report.BreakAtSeq, report.BreakCause)
	}
	if report.Entries != writers*each {
		t.Fatalf("Entries = %d, want %d", report.Entries, writers*each)
	}
}

// ---------------------------------------------------------------------------
// Redaction at the storage boundary
// ---------------------------------------------------------------------------

// TestAppendRedactsBeforeHashing is the security assertion of this package: the
// secret must be absent from the stored row, and the chain must still verify —
// which together prove the redaction happened before the digest was taken
// rather than on the way out.
func TestAppendRedactsBeforeHashing(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)
	incident := uuid.NewString()

	detail := map[string]any{
		"issuer_key":     "netbanking:HDFC",
		"webhook_secret": plantedSecret,
		"amount_paisa":   int64(4999900),
		"nested": map[string]any{
			"authorization": plantedSecret,
			"customer": map[string]any{
				"email": plantedSecret,
				"vpa":   plantedSecret,
			},
			"note": "safe to keep",
		},
		"attempts": []any{
			map[string]any{"api_key": plantedSecret, "rail": "upi_intent"},
		},
	}
	if _, err := l.Append(ctx, domain.AuditDiagnosis, incident, "ingest", detail); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := l.List(ctx, incident)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1", len(entries))
	}
	stored := string(entries[0].Detail)
	if strings.Contains(stored, plantedSecret) {
		t.Fatalf("planted credential survived into the ledger row: %s", stored)
	}
	if !strings.Contains(stored, obs.RedactedPlaceholder) {
		t.Fatalf("no redaction marker in stored detail: %s", stored)
	}
	// Routing metadata is not a secret and must survive, or the trail loses the
	// dimension every outage investigation starts from.
	if !strings.Contains(stored, "netbanking:HDFC") {
		t.Fatalf("issuer key was destroyed by redaction: %s", stored)
	}
	if !strings.Contains(stored, "4999900") {
		t.Fatalf("amount was not preserved exactly: %s", stored)
	}

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Valid {
		t.Fatalf("chain invalid after redacted append: break at %d (%s)", report.BreakAtSeq, report.BreakCause)
	}
}

// ---------------------------------------------------------------------------
// Input bounds
// ---------------------------------------------------------------------------

// TestAppendBoundsMatchSchema pins this package's mirrored column bounds against
// the real database, so a schema change cannot drift silently past both copies.
func TestAppendBoundsMatchSchema(t *testing.T) {
	ctx := context.Background()
	l, _ := newLedger(t)

	atLimitID := strings.Repeat("i", maxIdentifierLen)
	if _, err := l.Append(ctx, domain.AuditKind(strings.Repeat("K", maxKindLen)), atLimitID,
		strings.Repeat("a", maxActorLen), map[string]any{"ok": true}); err != nil {
		t.Fatalf("Append at the column limits: %v", err)
	}

	// An over-long actor is descriptive, so it is trimmed to fit rather than
	// costing the record.
	e, err := l.Append(ctx, domain.AuditGateDecision, "", strings.Repeat("a", maxActorLen+40), nil)
	if err != nil {
		t.Fatalf("Append with over-long actor: %v", err)
	}
	if len([]rune(e.Actor)) != maxActorLen {
		t.Fatalf("actor length = %d, want %d", len([]rune(e.Actor)), maxActorLen)
	}
	if string(e.Detail) != "{}" {
		t.Fatalf("nil detail stored as %q, want an empty object", string(e.Detail))
	}

	rejects := map[string]struct {
		kind     domain.AuditKind
		incident string
	}{
		"empty kind":          {"", "inc-1"},
		"over-long kind":      {domain.AuditKind(strings.Repeat("K", maxKindLen+1)), "inc-1"},
		"over-long incident":  {domain.AuditGateDecision, strings.Repeat("i", maxIdentifierLen+1)},
		"control in incident": {domain.AuditGateDecision, "inc\x00-1"},
	}
	for name, tc := range rejects {
		if _, err := l.Append(ctx, tc.kind, tc.incident, "ingest", nil); !errors.Is(err, ErrInvalidEntry) {
			t.Fatalf("%s: err = %v, want ErrInvalidEntry", name, err)
		}
	}

	if _, err := l.List(ctx, ""); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("List(\"\") = %v, want ErrInvalidEntry", err)
	}

	report, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Valid || report.Entries != 2 {
		t.Fatalf("report = %+v, want a valid chain of 2 entries", report)
	}
}

func TestUnconfiguredLedgerFailsClosed(t *testing.T) {
	ctx := context.Background()
	l := New(nil, newStepClock(), "audit-test")

	if _, err := l.Append(ctx, domain.AuditGateDecision, "inc-1", "ingest", nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Append = %v, want ErrNotConfigured", err)
	}
	if _, err := l.List(ctx, "inc-1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("List = %v, want ErrNotConfigured", err)
	}
	if _, err := l.Head(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Head = %v, want ErrNotConfigured", err)
	}
	report, err := l.Verify(ctx)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Verify = %v, want ErrNotConfigured", err)
	}
	if report.Valid {
		t.Fatal("Verify reported a valid chain with no store behind it")
	}
}

// ---------------------------------------------------------------------------
// Redaction unit tests: no database, always run
// ---------------------------------------------------------------------------

// decode is how the redaction assertions inspect values rather than the encoded
// text. A raw substring check would pass on a newline that encoding/json had
// merely escaped, which is exactly the case sanitizeText exists to handle.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	if !json.Valid(b) {
		t.Fatalf("RedactDetail produced invalid JSON: %s", b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal redacted detail: %v", err)
	}
	return m
}

func TestRedactDetailRemovesSensitiveValues(t *testing.T) {
	out := RedactDetail(map[string]any{
		"webhook_secret": plantedSecret,
		"api_key":        plantedSecret,
		"Authorization":  plantedSecret,
		"customer_email": plantedSecret,
		"card": map[string]any{
			"last4":  "4242",
			"number": plantedSecret,
		},
		"issuer_key":    "card:HDFC",
		"telemetry_key": "upi:okhdfcbank",
		"reason":        "issuer degraded",
	})
	if strings.Contains(string(out), plantedSecret) {
		t.Fatalf("credential survived redaction: %s", out)
	}

	m := decode(t, out)
	for _, k := range []string{"webhook_secret", "api_key", "Authorization", "customer_email", "card"} {
		if m[k] != obs.RedactedPlaceholder {
			t.Fatalf("%s = %v, want %q", k, m[k], obs.RedactedPlaceholder)
		}
	}
	// A sensitive key seals its whole subtree: "card" names cardholder context
	// however the leaves under it happen to be named.
	if _, ok := m["card"].(map[string]any); ok {
		t.Fatal("card subtree was descended into rather than sealed")
	}
	if m["issuer_key"] != "card:HDFC" || m["telemetry_key"] != "upi:okhdfcbank" {
		t.Fatalf("routing metadata was redacted: %v", m)
	}
	if m["reason"] != "issuer degraded" {
		t.Fatalf("reason = %v, want it preserved", m["reason"])
	}
}

// TestRedactDetailPreservesExactIntegers guards the money path. Decoding through
// float64 rounds any integer above 2^53, which would silently rewrite paisa
// amounts in the one record meant to be evidence.
func TestRedactDetailPreservesExactIntegers(t *testing.T) {
	const big = "9007199254740993" // 2^53 + 1, not representable as a float64
	out := RedactDetail(json.RawMessage(`{"amount_paisa":` + big + `,"fee_paisa":-250}`))
	if !strings.Contains(string(out), big) {
		t.Fatalf("large integer was rounded: %s", out)
	}
	if !strings.Contains(string(out), "-250") {
		t.Fatalf("negative integer was mangled: %s", out)
	}
}

func TestRedactDetailBoundsStrings(t *testing.T) {
	long := strings.Repeat("x", obs.MaxValueBytes*4)
	m := decode(t, RedactDetail(map[string]any{"reason": long}))

	got, ok := m["reason"].(string)
	if !ok {
		t.Fatalf("reason = %T, want a string", m["reason"])
	}
	if len(got) >= len(long) {
		t.Fatalf("string of %d bytes was not truncated (got %d)", len(long), len(got))
	}
	if got != obs.TruncateForLog(long) {
		t.Fatal("truncation diverged from the shared obs bound")
	}
}

func TestRedactDetailFoldsControlCharacters(t *testing.T) {
	m := decode(t, RedactDetail(map[string]any{
		"reason\ttag": "line\nbreak\x00nul\x1bescape",
	}))
	for k, v := range m {
		if strings.IndexFunc(k, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			t.Fatalf("control character survived in key %q", k)
		}
		s, ok := v.(string)
		if !ok {
			t.Fatalf("value = %T, want a string", v)
		}
		if s != "line break nul escape" {
			t.Fatalf("value = %q, want control characters folded to spaces", s)
		}
	}
}

func TestRedactDetailBoundsContainers(t *testing.T) {
	wide := make([]any, maxContainerEntries+50)
	for i := range wide {
		wide[i] = i
	}
	fat := make(map[string]any, maxContainerEntries+50)
	for i := 0; i < maxContainerEntries+50; i++ {
		fat[fmt.Sprintf("k%04d", i)] = i
	}

	m := decode(t, RedactDetail(map[string]any{"wide": wide, "fat": fat}))

	got, ok := m["wide"].([]any)
	if !ok {
		t.Fatalf("wide = %T, want an array", m["wide"])
	}
	if len(got) != maxContainerEntries+1 {
		t.Fatalf("array kept %d elements, want %d plus an elision marker", len(got), maxContainerEntries)
	}
	if marker, _ := got[len(got)-1].(string); !strings.Contains(marker, "50 more") {
		t.Fatalf("array elision marker = %v, want a count of what was dropped", got[len(got)-1])
	}

	obj, ok := m["fat"].(map[string]any)
	if !ok {
		t.Fatalf("fat = %T, want an object", m["fat"])
	}
	if len(obj) != maxContainerEntries+1 {
		t.Fatalf("object kept %d entries, want %d plus an elision marker", len(obj), maxContainerEntries)
	}
	if obj[elidedEntriesKey] != float64(50) {
		t.Fatalf("%s = %v, want 50", elidedEntriesKey, obj[elidedEntriesKey])
	}
	// The cap must fall on the sorted prefix, or which entries survive depends
	// on Go's randomised map iteration and the digest stops being reproducible.
	if _, ok := obj["k0000"]; !ok {
		t.Fatal("object cap did not keep the sorted prefix")
	}
	if _, ok := obj[fmt.Sprintf("k%04d", maxContainerEntries)]; ok {
		t.Fatal("object cap kept an entry past the prefix")
	}
}

func TestRedactDetailBoundsDepth(t *testing.T) {
	var nested any = "leaf"
	for i := 0; i < maxDepth+8; i++ {
		nested = map[string]any{"a": nested}
	}
	out := RedactDetail(nested)
	if !strings.Contains(string(out), deepPlaceholder) {
		t.Fatalf("deep nesting was not cut off: %s", out)
	}
	if !json.Valid(out) {
		t.Fatalf("depth cap produced invalid JSON: %s", out)
	}
}

// TestRedactDetailIsDeterministic matters because the output is hashed: two
// renderings of the same detail must produce the same digest, or verification
// depends on map iteration order.
func TestRedactDetailIsDeterministic(t *testing.T) {
	detail := map[string]any{
		"z": 1, "a": "text", "m": map[string]any{"q": true, "b": []any{1, 2, 3}},
		"secret": plantedSecret,
	}
	first := RedactDetail(detail)
	for i := 0; i < 32; i++ {
		if got := RedactDetail(detail); string(got) != string(first) {
			t.Fatalf("run %d produced %s, want %s", i, got, first)
		}
	}
}

// TestRedactDetailRecordsUnencodableValues covers the real path: a proposal that
// escaped validation carries a NaN confidence, which encoding/json refuses. The
// entry must still be written, describing the problem rather than vanishing.
func TestRedactDetailRecordsUnencodableValues(t *testing.T) {
	out := RedactDetail(map[string]any{"confidence": math.NaN()})
	m := decode(t, out)
	if m["audit_detail_unencodable"] != true {
		t.Fatalf("unencodable detail = %s, want the elision document", out)
	}
	if !strings.Contains(string(out), "map[string]interface {}") {
		t.Fatalf("elision document does not name the Go type: %s", out)
	}

	// Only the type is reported: a custom MarshalJSON error message can carry
	// whatever the caller put in it, which is the unvetted text this document
	// exists to keep out of the ledger.
	if strings.Contains(string(out), "NaN") {
		t.Fatalf("encoder error text leaked into the ledger: %s", out)
	}
}

func TestRedactDetailBoundsTotalSize(t *testing.T) {
	bulky := make([]any, 0, 200)
	for i := 0; i < 200; i++ {
		bulky = append(bulky, strings.Repeat("y", obs.MaxValueBytes))
	}
	out := RedactDetail(bulky)
	if len(out) > maxDetailBytes {
		t.Fatalf("redacted detail is %d bytes, over the %d budget", len(out), maxDetailBytes)
	}
	m := decode(t, out)
	if m["audit_detail_oversize"] != true {
		t.Fatalf("oversize detail = %s, want the elision document", out)
	}
}

func TestRedactDetailNormalisesEmptyDocuments(t *testing.T) {
	for name, in := range map[string]any{
		"nil":       nil,
		"json null": json.RawMessage("null"),
	} {
		if got := string(RedactDetail(in)); got != "{}" {
			t.Fatalf("%s rendered as %q, want an empty object", name, got)
		}
	}
}

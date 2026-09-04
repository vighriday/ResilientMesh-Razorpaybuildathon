package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

// fakeClock advances by a fixed step on every read, which makes latency
// assertions deterministic without any sleeping.
type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now:  time.Date(2026, time.March, 14, 10, 0, 0, 0, time.UTC),
		step: 7 * time.Millisecond,
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.now
	c.now = c.now.Add(c.step)
	return n
}

// lockedBuffer collects log output safely under -race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// debugLogger captures everything, including debug lines, so leak assertions
// cover the most verbose configuration the system can be run in.
func debugLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func baseContext() domain.DiagnosticContext {
	at := time.Date(2026, time.March, 14, 9, 59, 0, 0, time.UTC)
	return domain.DiagnosticContext{
		IncidentID:    "inc_2f8c1b9e4a",
		ErrorCode:     "bank_technical_error",
		ErrorSource:   "issuer",
		ErrorStep:     "authorization",
		ErrorReason:   "issuer unavailable",
		Method:        "card",
		IssuerKey:     "card:HDFC",
		AmountBand:    domain.AmountBand(250000),
		AttemptNumber: 1,
		Telemetry: domain.TelemetrySnapshot{
			IssuerKey:     "card:HDFC",
			WindowSeconds: 300,
			Attempts:      40,
			Successes:     34,
			Failures:      6,
			SuccessRate:   0.85,
			BaselineRate:  0.90,
			BreakerState:  domain.BreakerClosed,
			TopErrorCodes: []domain.CodeCount{
				{Code: "bank_technical_error", Count: 4},
				{Code: "payment_timed_out", Count: 2},
			},
			SampledAt: at,
		},
		AvailableRails: []domain.Rail{domain.RailCard, domain.RailUPIIntent, domain.RailNetbanking},
		ObservedAt:     at,
	}
}

func goodProposal(mode domain.InferenceMode) domain.DiagnosticProposal {
	return domain.DiagnosticProposal{
		IncidentID:            "inc_2f8c1b9e4a",
		InferredRootCause:     "issuer switch degraded",
		FailureClassification: domain.ClassTransientDegradation,
		ConfidenceScore:       0.72,
		RecommendedAction:     domain.ActionAsyncRetry,
		RecommendedDelaySec:   120,
		SuggestedFallbackRail: domain.RailNone,
		ReasoningTrace:        "telemetry below baseline",
		Mode:                  mode,
	}
}

type stubTier struct {
	name  string
	p     domain.DiagnosticProposal
	err   error
	calls atomic.Int64
}

func (s *stubTier) Diagnose(context.Context, domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	s.calls.Add(1)
	if s.err != nil {
		return domain.DiagnosticProposal{}, s.err
	}
	return s.p, nil
}

func (s *stubTier) Describe() string { return s.name }

func newStack(t *testing.T, tiers ...domain.Diagnoser) *Stack {
	t.Helper()
	s, err := New(Config{}, slog.New(slog.DiscardHandler), newFakeClock(), tiers...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// Stack behaviour
// ---------------------------------------------------------------------------

func TestStackFallsThroughToFirstTierThatAnswers(t *testing.T) {
	t.Parallel()

	live := &stubTier{name: "live(x)", err: errors.New("provider down")}
	replay := &stubTier{name: "replay(0 cassettes)", err: ErrCassetteMiss}
	heur := &stubTier{name: "heuristic", p: goodProposal(domain.ModeHeuristic)}

	got, err := newStack(t, live, replay, heur).Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeHeuristic {
		t.Fatalf("mode = %q, want %q", got.Mode, domain.ModeHeuristic)
	}
	for _, tier := range []*stubTier{live, replay, heur} {
		if n := tier.calls.Load(); n != 1 {
			t.Errorf("%s called %d times, want 1", tier.name, n)
		}
	}
}

func TestStackStopsAtTheFirstAnswer(t *testing.T) {
	t.Parallel()

	first := &stubTier{name: "live(x)", p: goodProposal(domain.ModeLive)}
	second := &stubTier{name: "heuristic", p: goodProposal(domain.ModeHeuristic)}

	got, err := newStack(t, first, second).Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeLive {
		t.Fatalf("mode = %q, want %q", got.Mode, domain.ModeLive)
	}
	if n := second.calls.Load(); n != 0 {
		t.Fatalf("later tier called %d times, want 0", n)
	}
}

func TestStackForcesIncidentIDOverTierEcho(t *testing.T) {
	t.Parallel()

	p := goodProposal(domain.ModeLive)
	p.IncidentID = "inc_attacker_controlled"

	got, err := newStack(t, &stubTier{name: "live(x)", p: p}).Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.IncidentID != baseContext().IncidentID {
		t.Fatalf("incident id = %q, want %q", got.IncidentID, baseContext().IncidentID)
	}
}

func TestStackRejectsProposalWithoutProvenance(t *testing.T) {
	t.Parallel()

	unattributed := &stubTier{name: "rogue", p: goodProposal(domain.InferenceMode("SOMETHING_ELSE"))}
	fallback := &stubTier{name: "heuristic", p: goodProposal(domain.ModeHeuristic)}

	got, err := newStack(t, unattributed, fallback).Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeHeuristic {
		t.Fatalf("mode = %q, want the fallback tier to have answered", got.Mode)
	}
}

func TestStackAbstainsWhenEveryTierDeclines(t *testing.T) {
	t.Parallel()

	boom := errors.New("provider down")
	got, err := newStack(t,
		&stubTier{name: "live(x)", err: boom},
		&stubTier{name: "replay(0 cassettes)", err: ErrCassetteMiss},
	).Diagnose(context.Background(), baseContext())

	if !errors.Is(err, ErrNoTierAnswered) {
		t.Fatalf("error = %v, want ErrNoTierAnswered", err)
	}
	if !errors.Is(err, boom) || !errors.Is(err, ErrCassetteMiss) {
		t.Errorf("joined error lost a tier cause: %v", err)
	}
	if got.RecommendedAction != domain.ActionAbstain {
		t.Errorf("action = %q, want abstain", got.RecommendedAction)
	}
	if got.Mode != domain.ModeSkipped || !got.Degraded {
		t.Errorf("provenance = %q degraded=%t, want SKIPPED/true", got.Mode, got.Degraded)
	}
	if got.IncidentID != baseContext().IncidentID {
		t.Errorf("incident id = %q, want it preserved on the abstention", got.IncidentID)
	}
	if got.ConfidenceScore != 0 {
		t.Errorf("confidence = %v, want 0 on an abstention", got.ConfidenceScore)
	}
}

func TestStackStopsOnCancelledContext(t *testing.T) {
	t.Parallel()

	tier := &stubTier{name: "heuristic", p: goodProposal(domain.ModeHeuristic)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := newStack(t, tier).Diagnose(ctx, baseContext())
	if !errors.Is(err, ErrNoTierAnswered) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want ErrNoTierAnswered wrapping context.Canceled", err)
	}
	if n := tier.calls.Load(); n != 0 {
		t.Errorf("tier called %d times after cancellation, want 0", n)
	}
	if got.RecommendedAction != domain.ActionAbstain {
		t.Errorf("action = %q, want abstain", got.RecommendedAction)
	}
}

func TestStackIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stack, err := New(Config{CassetteDir: dir}, slog.New(slog.DiscardHandler), newFakeClock())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := stack.Diagnose(context.Background(), baseContext()); err != nil {
				t.Errorf("Diagnose: %v", err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewAssemblesTiersFromConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
		want []string
		omit []string
	}{
		{
			name: "heuristic only",
			cfg:  Config{},
			want: []string{"heuristic"},
			omit: []string{"live(", "replay("},
		},
		{
			name: "replay and heuristic",
			cfg:  Config{CassetteDir: t.TempDir()},
			want: []string{"replay(", "heuristic"},
			omit: []string{"live("},
		},
		{
			name: "full stack",
			cfg:  Config{BaseURL: "https://api.groq.com/openai/v1", Model: "llama-3.1-8b", APIKey: "k", CassetteDir: t.TempDir()},
			want: []string{"live(llama-3.1-8b)", "replay(", "heuristic"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.cfg, slog.New(slog.DiscardHandler), newFakeClock())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			desc := s.Describe()
			for _, w := range tc.want {
				if !strings.Contains(desc, w) {
					t.Errorf("Describe() = %q, want it to contain %q", desc, w)
				}
			}
			for _, o := range tc.omit {
				if strings.Contains(desc, o) {
					t.Errorf("Describe() = %q, want it to omit %q", desc, o)
				}
			}
			if len(s.Tiers()) == 0 {
				t.Error("Tiers() is empty")
			}
		})
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"bad scheme", Config{BaseURL: "ftp://example.invalid/v1", Model: "m"}},
		{"credentials in url", Config{BaseURL: "https://user:pass@example.invalid/v1", Model: "m"}},
		{"plaintext http with a key", Config{BaseURL: "http://example.invalid/v1", Model: "m", APIKey: "sk-live"}},
		{"no host", Config{BaseURL: "https:///v1", Model: "m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg, slog.New(slog.DiscardHandler), newFakeClock()); err == nil {
				t.Fatal("New accepted an unusable configuration")
			}
		})
	}
}

func TestNewAllowsKeylessLoopbackEndpoint(t *testing.T) {
	t.Parallel()

	// Ollama on localhost speaks plaintext http and takes no key; refusing it
	// would break local development for no security gain.
	if _, err := New(Config{BaseURL: "http://localhost:11434/v1", Model: "llama3"},
		slog.New(slog.DiscardHandler), newFakeClock()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsNilTier(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{}, nil, nil, nil); err == nil {
		t.Fatal("New accepted a nil tier")
	}
}

func TestConfigNeverRendersTheAPIKey(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-do-not-log-me"
	cfg := Config{BaseURL: "https://api.groq.com/openai/v1", Model: "m", APIKey: secret}

	logger, buf := debugLogger()
	logger.Info("startup", "config", cfg)
	logger.Info("startup fmt", "config", cfg.String())

	for _, s := range []string{cfg.String(), buf.String()} {
		if strings.Contains(s, secret) {
			t.Fatalf("api key leaked into %q", s)
		}
		if !strings.Contains(s, "redacted") {
			t.Errorf("expected a redaction marker in %q", s)
		}
	}
	if got := redactedKey(""); got != "(unset)" {
		t.Errorf("redactedKey(\"\") = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Shared trust rules
// ---------------------------------------------------------------------------

func TestFinalizeAppliesTheTrustRules(t *testing.T) {
	t.Parallel()

	dc := baseContext()

	t.Run("forces incident id and clamps text", func(t *testing.T) {
		p := goodProposal(domain.ModeLive)
		p.IncidentID = "inc_someone_elses_payment"
		p.ReasoningTrace = strings.Repeat("x", domain.MaxReasoningLen+500)
		if err := finalize(&p, dc); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		if p.IncidentID != dc.IncidentID {
			t.Errorf("incident id = %q, want %q", p.IncidentID, dc.IncidentID)
		}
		if len(p.ReasoningTrace) > domain.MaxReasoningLen+3 {
			t.Errorf("reasoning trace not clamped: %d bytes", len(p.ReasoningTrace))
		}
	})

	t.Run("rejects a rail that was never offered", func(t *testing.T) {
		p := goodProposal(domain.ModeLive)
		p.SuggestedFallbackRail = domain.RailWallet // not in baseContext's rail set
		if err := finalize(&p, dc); !errors.Is(err, ErrRailNotOffered) {
			t.Fatalf("error = %v, want ErrRailNotOffered", err)
		}
	})

	t.Run("accepts an offered rail", func(t *testing.T) {
		p := goodProposal(domain.ModeLive)
		p.SuggestedFallbackRail = domain.RailUPIIntent
		if err := finalize(&p, dc); err != nil {
			t.Fatalf("finalize: %v", err)
		}
	})

	t.Run("rejects an out-of-range confidence", func(t *testing.T) {
		p := goodProposal(domain.ModeLive)
		p.ConfidenceScore = 1.5
		if err := finalize(&p, dc); !errors.Is(err, domain.ErrConfidenceOutOfRange) {
			t.Fatalf("error = %v, want ErrConfidenceOutOfRange", err)
		}
	})
}

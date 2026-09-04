// Package agent is the inference stack: the only probabilistic component in
// ResilientMesh, and therefore the only one that needs a containment strategy.
//
// Containment has three parts. Tiers degrade in a fixed order — a live model,
// then a deterministic cassette replay, then a heuristic classifier — so the
// system keeps answering when the model, the network, or the provider's billing
// department disappears. Every tier's output goes through the same finalize
// pass, which forces the incident id, validates the schema, clamps free text,
// and rejects a rail the caller never offered. And nothing a tier returns is
// authoritative: the gatekeeper re-derives every amount, delay and compliance
// verdict downstream. A proposal is evidence, not a decision.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// DefaultTimeout matches MESH_LLM_TIMEOUT's default. Inference sits on the
// recovery path of a payment that has already failed once, so the budget is
// small on purpose: a slow answer is worth less than a fast fallback.
const DefaultTimeout = 4 * time.Second

// Config is the agent's own settings block rather than an import of
// internal/config, which keeps this package free of a dependency on the process
// configuration layer and independently testable.
type Config struct {
	// BaseURL is an OpenAI-compatible root such as https://api.groq.com/openai/v1.
	BaseURL string
	APIKey  string
	Model   string
	Timeout time.Duration

	// CassetteDir enables the replay tier when set.
	CassetteDir string

	// HTTPClient allows a caller to supply a pre-configured transport. When nil
	// the live tier builds its own; request deadlines come from the context in
	// either case, so an injected client without a timeout is still bounded.
	HTTPClient *http.Client
}

// String redacts the API key so a Config can be printed in a startup banner or
// an error without leaking the credential.
func (c Config) String() string {
	return fmt.Sprintf("agent.Config{BaseURL:%s Model:%s Timeout:%s CassetteDir:%s APIKey:%s}",
		c.BaseURL, c.Model, c.timeout(), c.CassetteDir, redactedKey(c.APIKey))
}

// LogValue keeps the redaction in force when a Config is passed to slog, where
// String would otherwise be bypassed by a structured handler.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("base_url", c.BaseURL),
		slog.String("model", c.Model),
		slog.Duration("timeout", c.timeout()),
		slog.String("cassette_dir", c.CassetteDir),
		slog.String("api_key", redactedKey(c.APIKey)),
	)
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

// redactedKey reports only whether a key is configured. Even a prefix of a live
// key is enough to identify an account, so no part of it is ever rendered.
func redactedKey(k string) string {
	if k == "" {
		return "(unset)"
	}
	return "[redacted]"
}

var (
	// ErrNoTierAnswered means every tier declined. The accompanying proposal is
	// a valid abstention, so a caller that ignores the error still fails closed.
	ErrNoTierAnswered = errors.New("agent: no inference tier produced a usable proposal")

	// ErrNoProvenance guards the audit trail: a proposal whose Mode is not one
	// of the four known values cannot be attributed to a tier, and an
	// unattributable proposal is not usable evidence.
	ErrNoProvenance = errors.New("agent: proposal carries no recognised inference mode")

	// ErrRailNotOffered fires when a tier proposes a rail outside
	// AvailableRails. The gatekeeper would reject it anyway; rejecting it here
	// means a model that broke the single hardest constraint in its instructions
	// is distrusted in whole rather than in part.
	ErrRailNotOffered = errors.New("agent: proposed rail was not offered in available_rails")
)

// Stack is the tiered Diagnoser. It holds no mutable state of its own, so a
// single instance is shared safely across every worker goroutine.
type Stack struct {
	tiers []domain.Diagnoser
	log   *slog.Logger
}

var _ domain.Diagnoser = (*Stack)(nil)

// New builds the inference stack. Supplying tiers explicitly is how tests and
// the --record tooling compose a partial stack; with none supplied it assembles
// the production order from cfg: live when a base URL and model are set, replay
// when a cassette directory is set, and the heuristic classifier always, because
// something must be able to answer when nothing else can.
func New(cfg Config, logger *slog.Logger, clock domain.Clock, tiers ...domain.Diagnoser) (*Stack, error) {
	logger = orDiscard(logger)
	clock = orSystemClock(clock)

	if len(tiers) == 0 {
		if strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.Model) != "" {
			live, err := NewLive(cfg, logger, clock)
			if err != nil {
				return nil, fmt.Errorf("agent: build live tier: %w", err)
			}
			tiers = append(tiers, live)
		}
		if strings.TrimSpace(cfg.CassetteDir) != "" {
			replay, err := NewReplay(cfg.CassetteDir, logger, clock)
			if err != nil {
				return nil, fmt.Errorf("agent: build replay tier: %w", err)
			}
			tiers = append(tiers, replay)
		}
		tiers = append(tiers, NewHeuristic(logger, clock))
	}

	for i, t := range tiers {
		if t == nil {
			return nil, fmt.Errorf("agent: tier %d is nil", i)
		}
	}
	return &Stack{tiers: tiers, log: logger}, nil
}

// Diagnose walks the tiers in order and returns the first usable proposal,
// carrying that tier's Mode as provenance.
//
// A declining tier is a routine event — an outage is exactly when the live tier
// is least likely to answer — so failures are recorded and the walk continues.
// When every tier declines, the returned proposal is a valid abstention and the
// error explains why: callers that check the error and callers that only use
// the proposal both end up safe.
func (s *Stack) Diagnose(ctx context.Context, dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	var failures []error

	for _, tier := range s.tiers {
		if err := ctx.Err(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", tier.Describe(), err))
			break
		}

		p, err := tier.Diagnose(ctx, dc)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", tier.Describe(), err))
			s.log.Debug("inference tier declined",
				"tier", tier.Describe(), "incident_id", dc.IncidentID, "error", err.Error())
			continue
		}
		if !validMode(p.Mode) {
			failures = append(failures, fmt.Errorf("%s: %w", tier.Describe(), ErrNoProvenance))
			s.log.Warn("inference tier returned a proposal without provenance",
				"tier", tier.Describe(), "incident_id", dc.IncidentID)
			continue
		}

		// Belt and braces: every built-in tier already forces this, but a
		// caller-supplied tier is not trusted to have done so.
		p.IncidentID = dc.IncidentID
		return p, nil
	}

	s.log.Warn("inference stack exhausted, abstaining",
		"incident_id", dc.IncidentID, "tiers", len(s.tiers))

	abstain := domain.AbstainProposal(dc.IncidentID,
		"inference unavailable: every tier declined", domain.ModeSkipped)
	if len(failures) == 0 {
		return abstain, ErrNoTierAnswered
	}
	return abstain, fmt.Errorf("%w: %w", ErrNoTierAnswered, errors.Join(failures...))
}

// Describe renders the tier chain for the ops console and the audit trail, so
// an operator reading a decision can tell which stack produced it.
func (s *Stack) Describe() string {
	names := make([]string, 0, len(s.tiers))
	for _, t := range s.tiers {
		names = append(names, t.Describe())
	}
	return "stack[" + strings.Join(names, " -> ") + "]"
}

// Tiers exposes the composed chain so the ops console can report which tiers a
// running process actually has, rather than which ones it was configured with.
func (s *Stack) Tiers() []domain.Diagnoser {
	out := make([]domain.Diagnoser, len(s.tiers))
	copy(out, s.tiers)
	return out
}

// finalize applies the trust rules shared by every tier, in the order the plan
// fixes: force the incident id (a model's echo is never authoritative and a
// swapped id would attach a diagnosis to someone else's payment), validate the
// schema, clamp free text, then reject a rail that was never on offer.
func finalize(p *domain.DiagnosticProposal, dc domain.DiagnosticContext) error {
	p.IncidentID = dc.IncidentID

	if err := p.Validate(); err != nil {
		return fmt.Errorf("proposal rejected: %w", err)
	}
	p.Clamp()

	if p.SuggestedFallbackRail != domain.RailNone && !railOffered(p.SuggestedFallbackRail, dc.AvailableRails) {
		return fmt.Errorf("%w: %q", ErrRailNotOffered, p.SuggestedFallbackRail)
	}
	return nil
}

func railOffered(r domain.Rail, available []domain.Rail) bool {
	for _, a := range available {
		if domain.ParseRail(string(a)) == r {
			return true
		}
	}
	return false
}

func validMode(m domain.InferenceMode) bool {
	switch m {
	case domain.ModeLive, domain.ModeReplay, domain.ModeHeuristic, domain.ModeSkipped:
		return true
	default:
		return false
	}
}

func orDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

// systemClock is the only place this package reads the wall clock. Every tier
// takes a domain.Clock so latency accounting and cassette timestamps stay
// deterministic under test.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func orSystemClock(c domain.Clock) domain.Clock {
	if c != nil {
		return c
	}
	return systemClock{}
}

// elapsedMS is monotonic-safe against a clock that reports the same instant
// twice or, in a test fake, moves backwards.
func elapsedMS(clock domain.Clock, start time.Time) int64 {
	ms := clock.Now().Sub(start).Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

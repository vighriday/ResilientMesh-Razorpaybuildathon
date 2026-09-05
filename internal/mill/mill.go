package mill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/bandit"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/lab"
	"github.com/hriday/razorpay-resilient-mesh/internal/ope"
	"github.com/hriday/razorpay-resilient-mesh/internal/reward"
)

// Proposer suggests where to look. It never decides anything.
type Proposer interface {
	// Name identifies the proposer in the audit record, because "the system
	// discovered" is not a sentence anyone should have to accept without
	// knowing which component did the discovering.
	Name() string

	// Propose returns at most n candidate segments given the aggregate
	// evidence in b.
	Propose(ctx context.Context, b Brief, n int) ([]lab.Hypothesis, error)
}

// Defaults and bounds.
const (
	// DefaultProposals is how many candidates a round asks for. It is small
	// because every extra hypothesis widens all the others: with family-wise
	// control, testing twice as many things makes each test half as sensitive,
	// so a proposer that sprays guesses is worse than one that does not.
	DefaultProposals = 8

	// DefaultFamilyAlpha is the probability that any false hypothesis survives
	// a whole round.
	DefaultFamilyAlpha = 0.05

	// MaxProposals bounds a round.
	MaxProposals = 40

	// DefaultTimeout bounds one proposal call.
	DefaultTimeout = 30 * time.Second

	// maxResponseBytes caps what is read from a model provider. A remote party
	// can stream indefinitely, and this runs offline where nobody is watching.
	maxResponseBytes = 96 << 10

	maxCompletionTokens = 1600
)

var (
	// ErrNoProposals means the proposer returned nothing usable. It is not a
	// failure of the run: a log with no structure in it should produce no
	// hypotheses, and inventing some would be the actual failure.
	ErrNoProposals = errors.New("mill: no valid hypotheses were proposed")

	// ErrInvalidOptions covers malformed parameters.
	ErrInvalidOptions = errors.New("mill: invalid options")

	// ErrProvider covers every failure to obtain a proposal from a model. It is
	// always recoverable by falling back to the deterministic proposer.
	ErrProvider = errors.New("mill: model provider did not return usable proposals")
)

// Options tunes a discovery round.
type Options struct {
	// Proposals is how many candidates to ask for. Zero means DefaultProposals.
	Proposals int

	// FamilyAlpha is the chance that any one false hypothesis survives the
	// whole round. Zero means DefaultFamilyAlpha.
	//
	// This is the difference between a discovery loop and a random number
	// generator with good manners. Twenty independent tests at 95% confidence
	// produce a false survivor essentially every round, and a system that ran
	// nightly would accumulate a policy made of noise inside a month. Each
	// interval is therefore computed at 1 - alpha/k for k hypotheses, which is
	// the Bonferroni correction: conservative, assumption-free, and correct
	// even though the tests here are correlated, because correlation can only
	// make it more conservative rather than less.
	FamilyAlpha float64

	// Bootstrap is the resample count behind each interval.
	Bootstrap int

	// Seed fixes the bootstrap and any model fit.
	Seed int64

	// WithOutcomeModel enables the doubly-robust difference, which is measurably
	// better on segment-sized samples. See ope.LiftEstimator.
	WithOutcomeModel bool
}

func (o Options) normalise() (Options, error) {
	if o.Proposals == 0 {
		o.Proposals = DefaultProposals
	}
	if o.FamilyAlpha == 0 {
		o.FamilyAlpha = DefaultFamilyAlpha
	}
	switch {
	case o.Proposals < 1 || o.Proposals > MaxProposals:
		return o, fmt.Errorf("%w: proposals %d outside [1, %d]", ErrInvalidOptions, o.Proposals, MaxProposals)
	case o.FamilyAlpha <= 0 || o.FamilyAlpha >= 1 || math.IsNaN(o.FamilyAlpha):
		return o, fmt.Errorf("%w: family alpha %g outside (0,1)", ErrInvalidOptions, o.FamilyAlpha)
	case o.Bootstrap < 0:
		return o, fmt.Errorf("%w: bootstrap %d is negative", ErrInvalidOptions, o.Bootstrap)
	}
	return o, nil
}

// Result is one discovery round.
type Result struct {
	// Proposer names what produced the candidates.
	Proposer string `json:"proposer"`

	// Degraded reports that the model was unreachable and the deterministic
	// proposer answered instead. It is surfaced rather than hidden for the same
	// reason the inference tier surfaces it: a run that quietly fell back and a
	// run that did not are different evidence.
	Degraded bool `json:"degraded"`

	// FallbackCause names why, in the provider vocabulary only. No provider
	// free text is carried.
	FallbackCause string `json:"fallback_cause,omitempty"`

	Decisions int `json:"decisions"`

	// Tested is how many hypotheses were scored, which is the k the confidence
	// correction was computed from.
	Tested int `json:"tested"`

	// PerTestConfidence is the widened level each interval was computed at.
	PerTestConfidence float64 `json:"per_test_confidence"`

	// FamilyAlpha is the round-level error rate that produced it.
	FamilyAlpha float64 `json:"family_alpha"`

	// RewardModelSkill and RewardModelAUC describe the outcome model the
	// doubly-robust term rests on, held out. A doubly-robust number quoted
	// without them is asking to be trusted rather than checked.
	RewardModelSkill float64 `json:"reward_model_skill,omitempty"`
	RewardModelAUC   float64 `json:"reward_model_auc,omitempty"`

	// Scores holds every verdict, survivors first. Refutations are kept: a
	// record of what was tried and failed is most of what makes a record of
	// what worked believable, and it is also the only defence against a reader
	// who suspects the survivors were cherry-picked.
	Scores []lab.HypothesisScore `json:"scores"`
}

// Survivors returns the hypotheses that cleared the corrected threshold.
func (r Result) Survivors() []lab.HypothesisScore {
	var out []lab.HypothesisScore
	for _, s := range r.Scores {
		if s.Survived {
			out = append(out, s)
		}
	}
	return out
}

// Refuted returns the hypotheses that did not.
func (r Result) Refuted() []lab.HypothesisScore {
	var out []lab.HypothesisScore
	for _, s := range r.Scores {
		if !s.Survived {
			out = append(out, s)
		}
	}
	return out
}

// Run performs one round: build the evidence, ask for candidates, test each one
// against the log, and report every verdict.
//
// Nothing here consults the latent truth of the world. On a real merchant
// corpus there is none to consult, and a discovery procedure that needed one
// would be useless. lab.World.Reveal exists so a demonstration can check the
// answer afterwards, and it is deliberately not called from this package.
func Run(ctx context.Context, w *lab.World, run lab.RunResult, p Proposer, opts Options) (Result, error) {
	opts, err := opts.normalise()
	if err != nil {
		return Result{}, err
	}
	if p == nil {
		p = Heuristic{}
	}

	brief := BuildBrief(w, run)
	res := Result{
		Proposer:    p.Name(),
		Decisions:   len(run.Log),
		FamilyAlpha: opts.FamilyAlpha,
	}

	proposals, err := p.Propose(ctx, brief, opts.Proposals)
	if err != nil {
		// A proposer that cannot answer is a degraded round, not a failed one.
		// The deterministic proposer always can.
		res.Degraded = true
		res.FallbackCause = providerCause(err)
		fallback, ferr := Heuristic{}.Propose(ctx, brief, opts.Proposals)
		if ferr != nil {
			return res, ferr
		}
		res.Proposer = p.Name() + "->heuristic"
		proposals = fallback
	}

	proposals = dedupe(proposals)
	if len(proposals) == 0 {
		return res, ErrNoProposals
	}

	// The correction. Every interval in this round is computed at a level that
	// leaves the chance of any false survivor at FamilyAlpha, rather than at
	// FamilyAlpha per test.
	res.Tested = len(proposals)
	res.PerTestConfidence = 1 - opts.FamilyAlpha/float64(len(proposals))

	eval := lab.EvalOptions{
		Seed:             opts.Seed,
		Bootstrap:        opts.Bootstrap,
		Confidence:       res.PerTestConfidence,
		WithOutcomeModel: opts.WithOutcomeModel,
	}
	// One model for the whole round. It depends only on the log, so refitting
	// it per hypothesis would repeat the same work and would let each candidate
	// be judged against slightly different predictions.
	if opts.WithOutcomeModel {
		m, rep, err := lab.FitRewardModel(run.Log, w.Incidents(), reward.Options{Seed: opts.Seed})
		if err != nil {
			return res, fmt.Errorf("mill: fitting the outcome model: %w", err)
		}
		eval.RewardModel = m
		res.RewardModelSkill = rep.Skill
		res.RewardModelAUC = rep.AUC
	}
	for _, h := range proposals {
		// A nil base means the policy that produced this log, so each
		// hypothesis is scored as a change to what is deployed rather than as a
		// wholesale replacement.
		score, err := w.ScoreHypothesis(run, h, nil, eval)
		if err != nil {
			// A hypothesis that cannot be scored is recorded as refused with
			// its reason, not dropped. Silence here would look like it was
			// never proposed.
			score = lab.HypothesisScore{Hypothesis: h, Statement: h.String(), Refuted: true, Error: err.Error()}
		}
		res.Scores = append(res.Scores, score)
	}
	lab.RankScores(res.Scores)
	return res, nil
}

func dedupe(in []lab.Hypothesis) []lab.Hypothesis {
	seen := make(map[string]struct{}, len(in))
	out := make([]lab.Hypothesis, 0, len(in))
	for _, h := range in {
		if err := h.Validate(); err != nil {
			continue
		}
		key := fingerprint(h)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return out
}

// fingerprint identifies a hypothesis by what it does rather than by what it is
// called, so two proposals describing the same segment in different words are
// tested once. Testing a duplicate twice would spend the family-wise budget on
// nothing.
func fingerprint(h lab.Hypothesis) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s", h.IssuerKey, h.Class, h.FromHour, h.ToHour, h.Arm)
}

// providerCause reduces a provider failure to a fixed vocabulary. Provider
// error text is written by a remote party and this string is rendered in an
// operator console and written to the ledger.
func providerCause(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, ErrProvider):
		return "provider_rejected"
	default:
		return "unavailable"
	}
}

// ---------------------------------------------------------------------------
// The model proposer
// ---------------------------------------------------------------------------

// Model is an OpenAI-compatible chat-completions proposer. It works unchanged
// against Groq, the Gemini compatibility endpoint and a local Ollama.
type Model struct {
	endpoint string
	apiKey   string
	model    string
	client   *http.Client
}

// NewModel validates the endpoint before any credential can travel over it.
func NewModel(baseURL, apiKey, model string, timeout time.Duration, client *http.Client) (*Model, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("mill: model base URL %q is not absolute", baseURL)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		// A bearer token over plaintext to a remote host is a credential
		// disclosure, so it is refused rather than warned about. A loopback
		// endpoint has no network to be observed on.
		return nil, fmt.Errorf("mill: refusing to send a credential to %q over %s", u.Host, u.Scheme)
	}
	if model == "" {
		return nil, errors.New("mill: no model name")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Model{
		endpoint: strings.TrimRight(u.String(), "/") + "/chat/completions",
		apiKey:   apiKey,
		model:    model,
		client:   client,
	}, nil
}

func (m *Model) Name() string { return "model:" + m.model }

// Propose asks the model for candidate segments.
func (m *Model) Propose(ctx context.Context, b Brief, n int) ([]lab.Hypothesis, error) {
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("mill: encode brief: %w", err)
	}

	content, err := m.complete(ctx, []message{
		{Role: "system", Content: systemPrompt(n)},
		{Role: "user", Content: string(payload)},
	})
	if err != nil {
		return nil, err
	}

	var out struct {
		Hypotheses []lab.Hypothesis `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(unfence(content)), &out); err != nil {
		return nil, fmt.Errorf("%w: response was not hypothesis JSON", ErrProvider)
	}
	valid := make([]lab.Hypothesis, 0, len(out.Hypotheses))
	for i := range out.Hypotheses {
		h := out.Hypotheses[i]
		// Rejected rather than repaired. A corrected hypothesis is no longer
		// the one the model proposed, and the record would then attribute a
		// claim to a model that never made it.
		if err := h.Validate(); err != nil {
			continue
		}
		valid = append(valid, h)
		if len(valid) >= n {
			break
		}
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("%w: no proposal survived validation", ErrProvider)
	}
	return valid, nil
}

// systemPrompt states the grammar and the rules.
//
// It contains no data. Every fact the model reasons over arrives in the user
// message as the aggregated brief, which is why an injected string in a webhook
// payload has no path into this conversation: nothing from a payload is in
// either message.
func systemPrompt(n int) string {
	return fmt.Sprintf(`You analyse aggregated payment-recovery statistics and propose segments worth testing.

You are given counts and recovery rates grouped by issuer, by three-hour block of the local day, by failure class, and by retry delay. Look for a slice of traffic whose best retry delay differs from what the surrounding traffic does. Prefer an explanation with a mechanism behind it, such as an issuer settlement batch, a nightly maintenance window, or a payday effect, over the largest number on the page.

Return JSON only, in exactly this shape:

{"hypotheses":[{"id":"short-slug","description":"one sentence naming the mechanism you think is at work","issuer_key":"","class":"","from_hour":0,"to_hour":0,"arm":""}]}

Rules:
- At most %d hypotheses.
- issuer_key must be copied exactly from the issuers list, or omitted.
- class must be copied exactly from the classes list, or omitted.
- arm is required and must be copied exactly from the arms list.
- from_hour and to_hour are whole hours with from_hour < to_hour <= 24, or both omitted.
- At least one of issuer_key, class, or an hour window must be present. A hypothesis with no filters is not a segment.
- Only name a segment that has enough plays in the brief to be worth testing.
- Do not restate the overall recovery rate as a finding.

Every hypothesis you return will be tested against held-out data by an off-policy estimator and most will be refuted. That is expected and it is not a failure. Proposing a segment you are unsure about is useful. Proposing one you have no evidence for wastes a test and makes every other hypothesis in the round harder to confirm.`, n)
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string         `json:"model"`
	Temperature    float64        `json:"temperature"`
	ResponseFormat responseFormat `json:"response_format"`
	MaxTokens      int            `json:"max_tokens"`
	Messages       []message      `json:"messages"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Type string `json:"type"`
	} `json:"error"`
}

func (m *Model) complete(ctx context.Context, msgs []message) (string, error) {
	// Temperature zero so a recorded round replays: a discovery whose
	// candidates change between runs cannot be attested to.
	body, err := json.Marshal(chatRequest{
		Model:          m.model,
		Temperature:    0,
		ResponseFormat: responseFormat{Type: "json_object"},
		MaxTokens:      maxCompletionTokens,
		Messages:       msgs,
	})
	if err != nil {
		return "", fmt.Errorf("mill: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("mill: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if m.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.apiKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProvider, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The body is not read: an error body is provider-controlled text with
		// no value here, and reading it would only widen the untrusted surface.
		return "", fmt.Errorf("%w: HTTP %d", ErrProvider, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("mill: read response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return "", fmt.Errorf("%w: response exceeded %d bytes", ErrProvider, maxResponseBytes)
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", fmt.Errorf("%w: envelope was not JSON", ErrProvider)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("%w: provider reported %q", ErrProvider, sanitiseToken(cr.Error.Type))
	}
	if len(cr.Choices) == 0 || strings.TrimSpace(cr.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("%w: empty completion", ErrProvider)
	}
	return cr.Choices[0].Message.Content, nil
}

// unfence strips a markdown code fence. Several OpenAI-compatible providers
// ignore response_format and wrap the object anyway. This repairs the envelope,
// never the content.
func unfence(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "```") {
		return t
	}
	if i := strings.IndexByte(t, '\n'); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.LastIndex(t, "```"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSpace(t)
}

// sanitiseToken restricts a provider-supplied identifier to a rendering-safe
// alphabet.
func sanitiseToken(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 48; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func sqrt(v float64) float64 { return math.Sqrt(v) }

func parseClass(s string) domain.FailureClass {
	c := domain.ParseFailureClass(s)
	if c == domain.ClassUnknown {
		return ""
	}
	return c
}

func shortIssuer(key string) string {
	return strings.NewReplacer(":", "-", ".", "-").Replace(key)
}

func shortClass(c string) string {
	return strings.ToLower(strings.NewReplacer("_", "-").Replace(c))
}

func shortArm(a bandit.Arm) string {
	return strings.TrimPrefix(string(a), "retry_after_")
}

// Verify at compile time that both proposers satisfy the interface.
var (
	_ Proposer = Heuristic{}
	_ Proposer = (*Model)(nil)
	_          = ope.MinInfluentialDecisions
)

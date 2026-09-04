package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

const (
	// maxResponseBytes caps what is read from the provider. A model endpoint is
	// a remote party that can stream indefinitely; without a cap a single reply
	// can exhaust a worker's memory, which during an issuer outage is exactly
	// when every worker is calling it at once.
	maxResponseBytes = 64 << 10

	// maxCompletionTokens bounds the reply at the source as well. The schema
	// needs a few hundred tokens; anything beyond that is a runaway generation.
	maxCompletionTokens = 800
)

var (
	// ErrUpstreamStatus covers every non-200 from the provider, including 429
	// and 5xx. None of them are retried here: a rate-limited or failing provider
	// is a reason to fall to the next tier, not a reason to send more traffic.
	ErrUpstreamStatus = errors.New("agent: model provider returned a non-200 status")

	// ErrOversizedResponse means the reply exceeded the read cap and was
	// discarded unparsed. It is deliberately not repaired: asking a provider
	// that just emitted 64 KiB to try again is the definition of a retry storm.
	ErrOversizedResponse = errors.New("agent: model response exceeded the size cap")

	// ErrInvalidJSON is the one condition that earns a repair round-trip.
	ErrInvalidJSON = errors.New("agent: model response was not valid proposal JSON")

	// ErrEmptyResponse covers a well-formed envelope with no usable content.
	ErrEmptyResponse = errors.New("agent: model response contained no completion")

	// ErrProviderError is the provider reporting its own failure in a 200 body,
	// which several OpenAI-compatible gateways do.
	ErrProviderError = errors.New("agent: model provider reported an error")
)

// httpStatusError carries the status code so the operator log can show it
// without the error string having to be parsed back apart.
type httpStatusError struct{ Status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("agent: model provider returned HTTP %d", e.Status)
}

func (e *httpStatusError) Is(target error) bool { return target == ErrUpstreamStatus }

// Live is the OpenAI-compatible chat-completions tier. It works unchanged
// against Groq, Gemini's compatibility endpoint, and a local Ollama, because
// all three speak the same /chat/completions shape.
type Live struct {
	endpoint string
	apiKey   string
	model    string
	timeout  time.Duration
	client   *http.Client
	log      *slog.Logger
	clock    domain.Clock
}

var _ domain.Diagnoser = (*Live)(nil)

// NewLive validates the endpoint before any credential can travel over it.
//
// Three checks matter. A URL carrying userinfo is rejected because credentials
// in a URL end up in logs and error strings. A non-http(s) scheme is rejected
// because the transport is the only thing protecting the key. And plaintext
// http to a non-loopback host is rejected whenever a key is configured, since
// that combination puts the credential on the wire in the clear; local
// development against Ollama keeps working because loopback is exempt.
func NewLive(cfg Config, logger *slog.Logger, clock domain.Clock) (*Live, error) {
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return nil, errors.New("agent: live tier requires a base URL")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("agent: parse base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("agent: base url scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("agent: base url has no host")
	}
	if u.User != nil {
		return nil, errors.New("agent: base url must not embed credentials")
	}
	key := strings.TrimSpace(cfg.APIKey)
	if u.Scheme == "http" && key != "" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("agent: refusing to send an API key over plaintext http to %q", u.Hostname())
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, errors.New("agent: live tier requires a model name")
	}

	client := cfg.HTTPClient
	if client == nil {
		// Deliberately not http.DefaultClient: this package must not be able to
		// mutate a client other packages share.
		client = &http.Client{}
	}

	return &Live{
		endpoint: strings.TrimRight(u.String(), "/") + "/chat/completions",
		apiKey:   key,
		model:    model,
		timeout:  cfg.timeout(),
		client:   client,
		log:      orDiscard(logger),
		clock:    orSystemClock(clock),
	}, nil
}

// Describe names the tier and the model, never the endpoint or the key: this
// string reaches the ops console and the audit ledger.
func (l *Live) Describe() string { return "live(" + l.model + ")" }

// Diagnose performs at most two round-trips: the diagnosis, and one repair when
// the first reply would not parse. Both share a single deadline, so the tier's
// worst case stays bounded by cfg.Timeout no matter how the provider behaves.
func (l *Live) Diagnose(ctx context.Context, dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	msgs, err := BuildMessages(dc)
	if err != nil {
		return domain.DiagnosticProposal{}, fmt.Errorf("agent live: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	start := l.clock.Now()

	content, err := l.complete(ctx, msgs)
	if err != nil {
		l.report(err, start)
		return domain.DiagnosticProposal{}, err
	}

	p, perr := decodeProposal(content)
	if perr != nil {
		// Exactly one repair attempt, and only for a parse failure. A model that
		// emitted stray prose usually corrects itself when shown the parser's
		// complaint; a schema violation, by contrast, is a substantive
		// disagreement and falls through to the next tier untouched.
		repair, rerr := repairMessage(content, perr)
		if rerr != nil {
			l.report(rerr, start)
			return domain.DiagnosticProposal{}, rerr
		}
		content, err = l.complete(ctx, append(msgs, repair))
		if err != nil {
			l.report(err, start)
			return domain.DiagnosticProposal{}, err
		}
		p, perr = decodeProposal(content)
		if perr != nil {
			l.report(perr, start)
			return domain.DiagnosticProposal{}, perr
		}
	}

	// Provenance is stamped, never accepted: the response body contains these
	// keys too, and a model that could set its own Mode could launder a
	// heuristic-grade guess as a live inference in the audit trail.
	p.Mode = domain.ModeLive
	p.Model = l.model
	p.LatencyMS = elapsedMS(l.clock, start)
	p.Degraded = false

	if err := finalize(&p, dc); err != nil {
		wrapped := fmt.Errorf("agent live: %w", err)
		l.report(wrapped, start)
		return domain.DiagnosticProposal{}, wrapped
	}

	l.log.Debug("live inference accepted",
		"model", l.model, "latency_ms", p.LatencyMS, "incident_id", dc.IncidentID)
	return p, nil
}

type chatRequest struct {
	Model          string         `json:"model"`
	Temperature    float64        `json:"temperature"`
	ResponseFormat responseFormat `json:"response_format"`
	MaxTokens      int            `json:"max_tokens"`
	Messages       []Message      `json:"messages"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// complete issues one chat-completions call and returns the assistant content.
func (l *Live) complete(ctx context.Context, msgs []Message) (string, error) {
	// Temperature zero is not a style choice: the replay corpus is only
	// reproducible if the same context yields the same answer.
	body, err := json.Marshal(chatRequest{
		Model:          l.model,
		Temperature:    0,
		ResponseFormat: responseFormat{Type: "json_object"},
		MaxTokens:      maxCompletionTokens,
		Messages:       msgs,
	})
	if err != nil {
		return "", fmt.Errorf("agent live: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("agent live: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if l.apiKey != "" {
		// Empty means a keyless local endpoint such as Ollama; sending an empty
		// bearer token there would be rejected by some proxies.
		req.Header.Set("Authorization", "Bearer "+l.apiKey)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("agent live: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The body is not read: an error body is provider-controlled text with
		// no value here, and reading it would only widen the untrusted surface.
		return "", &httpStatusError{Status: resp.StatusCode}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("agent live: read response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return "", fmt.Errorf("%w: cap is %d bytes", ErrOversizedResponse, maxResponseBytes)
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", fmt.Errorf("%w: envelope: %w", ErrInvalidJSON, err)
	}
	if cr.Error != nil {
		// Only the provider's own error type is echoed, filtered through the
		// token allowlist; the message field is free text from a remote party.
		return "", fmt.Errorf("%w: type %q", ErrProviderError, sanitizeToken(cr.Error.Type, maxCodeLen))
	}
	if len(cr.Choices) == 0 || strings.TrimSpace(cr.Choices[0].Message.Content) == "" {
		return "", ErrEmptyResponse
	}
	return cr.Choices[0].Message.Content, nil
}

// decodeProposal parses the assistant content into a proposal. It is strict:
// unknown or mistyped fields fail rather than being coerced, because a coerced
// field is a silent substitution of our judgement for the model's.
func decodeProposal(content string) (domain.DiagnosticProposal, error) {
	var p domain.DiagnosticProposal
	if err := json.Unmarshal([]byte(unfence(content)), &p); err != nil {
		return domain.DiagnosticProposal{}, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	return p, nil
}

// unfence strips a markdown code fence. Several OpenAI-compatible providers
// ignore response_format and wrap the object anyway. This repairs the envelope,
// never the content: an invalid proposal inside a fence stays invalid.
func unfence(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "```") {
		return t
	}
	i := strings.IndexByte(t, '\n')
	if i < 0 {
		return t
	}
	t = strings.TrimSpace(t[i+1:])
	return strings.TrimSpace(strings.TrimSuffix(t, "```"))
}

// report logs a tier failure twice at two levels on purpose. The warning is
// operator-facing and carries only a fixed-vocabulary reason, the model name,
// the latency and the status code — never the key, the prompt, or the response.
// The full error, which may quote a fragment of the provider's reply, is debug
// only, where the redacting handler applies.
func (l *Live) report(err error, start time.Time) {
	attrs := []any{
		"model", l.model,
		"latency_ms", elapsedMS(l.clock, start),
		"reason", failureReason(err),
	}
	var se *httpStatusError
	if errors.As(err, &se) {
		attrs = append(attrs, "status", se.Status)
	}
	l.log.Warn("live inference tier declined", attrs...)
	l.log.Debug("live inference tier failure detail", "model", l.model, "error", err.Error())
}

// failureReason maps an error onto a small closed vocabulary so dashboards can
// group failures without any provider text reaching a log line.
func failureReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, ErrUpstreamStatus):
		return "http_status"
	case errors.Is(err, ErrOversizedResponse):
		return "oversize"
	case errors.Is(err, ErrInvalidJSON):
		return "invalid_json"
	case errors.Is(err, ErrEmptyResponse):
		return "empty_response"
	case errors.Is(err, ErrProviderError):
		return "provider_error"
	case errors.Is(err, ErrRailNotOffered):
		return "rail_not_offered"
	case errors.Is(err, domain.ErrConfidenceOutOfRange),
		errors.Is(err, domain.ErrDelayOutOfRange),
		errors.Is(err, domain.ErrUnknownAction),
		errors.Is(err, domain.ErrUnknownRail):
		return "schema_violation"
	default:
		return "transport"
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

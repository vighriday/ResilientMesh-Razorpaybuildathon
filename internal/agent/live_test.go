package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

const (
	testAPIKey = "sk-live-9f2a4c6e8b1d3f5a7c9e0b2d4f6a8c0e"
	testModel  = "llama-3.3-70b-versatile"
)

// providerLog records what the tier actually sent, so the wire contract and the
// credential handling can both be asserted rather than assumed.
type providerLog struct {
	mu   sync.Mutex
	reqs []chatRequest
	auth []string
}

func (p *providerLog) record(req chatRequest, auth string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	p.auth = append(p.auth, auth)
	return len(p.reqs)
}

func (p *providerLog) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reqs)
}

func (p *providerLog) request(i int) chatRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reqs[i]
}

func (p *providerLog) authHeader(i int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.auth[i]
}

type responder func(w http.ResponseWriter, r *http.Request, call int)

func newProvider(t *testing.T, responders ...responder) (*httptest.Server, *providerLog) {
	t.Helper()
	log := &providerLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %s, want /v1/chat/completions", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("request body is not a chat request: %v", err)
		}
		n := log.record(req, r.Header.Get("Authorization"))
		if n > len(responders) {
			t.Errorf("provider called %d times, only %d responses scripted", n, len(responders))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		responders[n-1](w, r, n)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

func replyWith(content string) responder {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]any{
			"id":      "chatcmpl-test",
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}},
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(body); err != nil {
			return
		}
	}
}

func replyStatus(code int) responder {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(code)
		if _, err := w.Write([]byte(`{"error":{"message":"rate limited","type":"rate_limit"}}`)); err != nil {
			return
		}
	}
}

func validProposalJSON(t *testing.T, overrides map[string]any) string {
	t.Helper()
	p := map[string]any{
		"incident_id":               "inc_model_echoed_something_else",
		"inferred_root_cause":       "issuer switch returning technical errors",
		"failure_classification":    string(domain.ClassTransientDegradation),
		"confidence_score":          0.74,
		"recommended_action":        string(domain.ActionAsyncRetry),
		"recommended_delay_seconds": 90,
		"suggested_fallback_rail":   string(domain.RailNone),
		"reasoning_trace":           "success rate is below the portfolio baseline",
	}
	for k, v := range overrides {
		p[k] = v
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

func newLiveTier(t *testing.T, baseURL string, timeout time.Duration) (*Live, *lockedBuffer) {
	t.Helper()
	logger, buf := debugLogger()
	l, err := NewLive(Config{
		BaseURL: baseURL + "/v1",
		APIKey:  testAPIKey,
		Model:   testModel,
		Timeout: timeout,
	}, logger, newFakeClock())
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	return l, buf
}

func TestLiveHappyPath(t *testing.T) {
	t.Parallel()

	srv, log := newProvider(t, replyWith(validProposalJSON(t, nil)))
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	dc := baseContext()
	got, err := live.Diagnose(context.Background(), dc)
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	req := log.request(0)
	if req.Model != testModel {
		t.Errorf("model = %q, want %q", req.Model, testModel)
	}
	if req.Temperature != 0 {
		t.Errorf("temperature = %v, want 0 so cassettes stay reproducible", req.Temperature)
	}
	if req.ResponseFormat.Type != "json_object" {
		t.Errorf("response_format = %q, want json_object", req.ResponseFormat.Type)
	}
	if req.MaxTokens <= 0 {
		t.Error("max_tokens must bound the reply at the source")
	}
	if len(req.Messages) != 2 || req.Messages[0].Role != RoleSystem || req.Messages[1].Role != RoleUser {
		t.Fatalf("messages = %+v, want [system, user]", req.Messages)
	}
	if want := "Bearer " + testAPIKey; log.authHeader(0) != want {
		t.Errorf("authorization header = %q, want a bearer credential", log.authHeader(0))
	}

	if got.IncidentID != dc.IncidentID {
		t.Errorf("incident id = %q, want the requested %q (never the model's echo)", got.IncidentID, dc.IncidentID)
	}
	if got.Mode != domain.ModeLive {
		t.Errorf("mode = %q, want LIVE", got.Mode)
	}
	if got.Model != testModel {
		t.Errorf("model = %q, want %q", got.Model, testModel)
	}
	if got.LatencyMS <= 0 {
		t.Errorf("latency = %d ms, want it measured", got.LatencyMS)
	}
	if got.Degraded {
		t.Error("a live answer must not be flagged degraded")
	}
}

// The model must not be able to launder its own provenance: a reply claiming to
// be a heuristic, or claiming a latency, would corrupt the benchmark.
func TestLiveOverwritesModelSuppliedProvenance(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, replyWith(validProposalJSON(t, map[string]any{
		"mode":       string(domain.ModeHeuristic),
		"model":      "some-other-model",
		"latency_ms": 999999,
		"degraded":   true,
	})))
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	got, err := live.Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeLive || got.Model != testModel || got.Degraded || got.LatencyMS == 999999 {
		t.Fatalf("provenance came from the model: %+v", got)
	}
}

func TestLiveRepairsInvalidJSONExactlyOnce(t *testing.T) {
	t.Parallel()

	srv, log := newProvider(t,
		replyWith("Sure! Here is the diagnosis you asked for."),
		replyWith(validProposalJSON(t, nil)),
	)
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	got, err := live.Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeLive {
		t.Fatalf("mode = %q, want LIVE after a successful repair", got.Mode)
	}
	if n := log.count(); n != 2 {
		t.Fatalf("provider called %d times, want exactly 2", n)
	}

	repair := log.request(1)
	if len(repair.Messages) != 3 {
		t.Fatalf("repair request had %d messages, want the original two plus the repair", len(repair.Messages))
	}
	last := repair.Messages[2]
	if last.Role != RoleUser {
		t.Errorf("repair message role = %q, want user", last.Role)
	}
	if !strings.Contains(last.Content, "parser_error") {
		t.Error("repair message does not feed the parse error back")
	}
	if !strings.Contains(last.Content, untrustedOpen) {
		t.Error("repair message must fence the echoed reply as untrusted data")
	}
	if strings.Contains(last.Content, "\n") {
		t.Error("repair message must not contain raw newlines")
	}
}

func TestLiveGivesUpAfterOneRepair(t *testing.T) {
	t.Parallel()

	srv, log := newProvider(t,
		replyWith("still not json"),
		replyWith("{ definitely not json either"),
	)
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	_, err := live.Diagnose(context.Background(), baseContext())
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("error = %v, want ErrInvalidJSON", err)
	}
	if n := log.count(); n != 2 {
		t.Fatalf("provider called %d times, want exactly 2: a third call would be a retry storm", n)
	}
}

func TestLiveFailsOverOnUpstreamStatus(t *testing.T) {
	t.Parallel()

	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			srv, log := newProvider(t, replyStatus(code))
			live, _ := newLiveTier(t, srv.URL, 2*time.Second)

			_, err := live.Diagnose(context.Background(), baseContext())
			if !errors.Is(err, ErrUpstreamStatus) {
				t.Fatalf("error = %v, want ErrUpstreamStatus", err)
			}
			var se *httpStatusError
			if !errors.As(err, &se) || se.Status != code {
				t.Fatalf("status not carried on the error: %v", err)
			}
			if n := log.count(); n != 1 {
				t.Fatalf("provider called %d times, want 1: a rate limit is not retried here", n)
			}
		})
	}
}

// The whole point of the tier stack: a rate-limited provider must not stop the
// system from producing a decision.
func TestStackFallsThroughFromRateLimitedProvider(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, replyStatus(http.StatusTooManyRequests))
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	stack := newStack(t, live, NewHeuristic(nil, newFakeClock()))
	got, err := stack.Diagnose(context.Background(), baseContext())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if got.Mode != domain.ModeHeuristic {
		t.Fatalf("mode = %q, want the heuristic tier to have answered", got.Mode)
	}
	if !got.Degraded {
		t.Error("a heuristic answer must be flagged degraded")
	}
}

func TestLiveTimesOut(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		// Hold the request until the client gives up; the server context is
		// cancelled by the client disconnect, so nothing leaks.
		<-r.Context().Done()
	})
	live, _ := newLiveTier(t, srv.URL, 50*time.Millisecond)

	_, err := live.Diagnose(context.Background(), baseContext())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a deadline exceeded", err)
	}
	if reason := failureReason(err); reason != "timeout" {
		t.Errorf("failureReason = %q, want timeout", reason)
	}
}

func TestLiveRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"choices":[{"message":{"content":"`)); err != nil {
			return
		}
		chunk := strings.Repeat("A", 4096)
		for written := 0; written < maxResponseBytes+8192; written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
		if _, err := w.Write([]byte(`"}}]}`)); err != nil {
			return
		}
	})
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	_, err := live.Diagnose(context.Background(), baseContext())
	if !errors.Is(err, ErrOversizedResponse) {
		t.Fatalf("error = %v, want ErrOversizedResponse", err)
	}
}

func TestLiveRejectsSchemaViolationsWithoutRepair(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]any{
		"unknown action":     {"recommended_action": "DELETE_ALL_MANDATES"},
		"rail not offered":   {"suggested_fallback_rail": string(domain.RailWallet)},
		"confidence too big": {"confidence_score": 4.2},
		"delay beyond cap":   {"recommended_delay_seconds": domain.MaxRecommendedDelay + 1},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, log := newProvider(t, replyWith(validProposalJSON(t, override)))
			live, _ := newLiveTier(t, srv.URL, 2*time.Second)

			if _, err := live.Diagnose(context.Background(), baseContext()); err == nil {
				t.Fatal("Diagnose accepted a schema-violating proposal")
			}
			if n := log.count(); n != 1 {
				t.Fatalf("provider called %d times: a schema violation is not a parse error and must not be repaired", n)
			}
		})
	}
}

func TestLiveRejectsProviderErrorEnvelope(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"error":{"message":"context length exceeded","type":"invalid_request_error"}}`)); err != nil {
			return
		}
	})
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	if _, err := live.Diagnose(context.Background(), baseContext()); !errors.Is(err, ErrProviderError) {
		t.Fatalf("error = %v, want ErrProviderError", err)
	}
}

func TestLiveRejectsEmptyCompletion(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, replyWith("   "))
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	if _, err := live.Diagnose(context.Background(), baseContext()); !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("error = %v, want ErrEmptyResponse", err)
	}
}

func TestLiveUnwrapsMarkdownFence(t *testing.T) {
	t.Parallel()

	srv, _ := newProvider(t, replyWith("```json\n"+validProposalJSON(t, nil)+"\n```"))
	live, _ := newLiveTier(t, srv.URL, 2*time.Second)

	if _, err := live.Diagnose(context.Background(), baseContext()); err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
}

// The credential must reach the provider and nothing else. This asserts it over
// every failure path at debug level, the most verbose configuration shipped.
func TestLiveNeverLogsTheCredential(t *testing.T) {
	t.Parallel()

	srv, log := newProvider(t,
		replyWith(validProposalJSON(t, nil)),
		replyStatus(http.StatusTooManyRequests),
		replyWith("not json"),
		replyWith("still not json"),
		replyWith(validProposalJSON(t, map[string]any{"recommended_action": "NOT_AN_ACTION"})),
	)
	live, buf := newLiveTier(t, srv.URL, 2*time.Second)

	for i := 0; i < 4; i++ {
		if _, err := live.Diagnose(context.Background(), baseContext()); err != nil && i == 0 {
			t.Fatalf("first call should have succeeded: %v", err)
		}
	}
	if log.count() == 0 {
		t.Fatal("provider was never called")
	}
	if !strings.HasPrefix(log.authHeader(0), "Bearer ") {
		t.Fatal("the tier did not send a bearer credential at all")
	}

	logs := buf.String()
	if logs == "" {
		t.Fatal("no log output captured; the assertion below would be vacuous")
	}
	for _, forbidden := range []string{testAPIKey, "Bearer", "Authorization", "authorization"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log output contains %q:\n%s", forbidden, logs)
		}
	}
	if !strings.Contains(logs, testModel) {
		t.Error("logs should identify the model so an operator can act on them")
	}
	if !strings.Contains(logs, "latency_ms") {
		t.Error("logs should carry latency")
	}
}

func TestLiveDescribeHidesEndpointAndKey(t *testing.T) {
	t.Parallel()

	live, _ := newLiveTier(t, "http://127.0.0.1:9", time.Second)
	desc := live.Describe()
	if !strings.Contains(desc, testModel) {
		t.Errorf("Describe() = %q, want the model name", desc)
	}
	if strings.Contains(desc, testAPIKey) || strings.Contains(desc, "127.0.0.1") {
		t.Errorf("Describe() = %q, want no credential or endpoint", desc)
	}
}

func TestUnfence(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"{\"a\":1}":                 "{\"a\":1}",
		"```json\n{\"a\":1}\n```":   "{\"a\":1}",
		"```\n{\"a\":1}```":         "{\"a\":1}",
		"  \n {\"a\":1}  ":          "{\"a\":1}",
		"```no newline in this one": "```no newline in this one",
	}
	for in, want := range cases {
		if got := unfence(in); got != want {
			t.Errorf("unfence(%q) = %q, want %q", in, got, want)
		}
	}
}

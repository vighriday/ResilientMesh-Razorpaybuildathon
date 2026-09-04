package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
)

// pg and pgx are the two DSN schemes libpq accepts, aliased locally so the
// fixtures below read as pg + "user:pass@host/db" and stay legible. See
// internal/testsecret for why a whole DSN is never a source literal here.
const (
	pg  = testsecret.PG
	pgx = testsecret.PGX
)

// env builds a hermetic Lookup so tests need neither t.Setenv nor a shared
// process environment, which is what lets them run in parallel.
func env(kv map[string]string) Lookup {
	return func(k string) (string, bool) {
		v, ok := kv[k]
		return v, ok
	}
}

// noCostFile keeps a test from accidentally depending on a costs.json that
// happens to exist relative to the package directory.
func noCostFile(t *testing.T, kv map[string]string) map[string]string {
	t.Helper()
	if kv == nil {
		kv = map[string]string{}
	}
	kv[envCostModelPath] = filepath.Join(t.TempDir(), "absent.json")
	return kv
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestLoadFromEmptyEnvironmentYieldsDocumentedDefaults(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, nil)))
	if err != nil {
		t.Fatalf("LoadFrom with an empty environment: %v", err)
	}

	if c.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("HTTPAddr = %q, want :8080", c.HTTPAddr)
	}
	if c.RedisAddr != "127.0.0.1:6379" {
		t.Errorf("RedisAddr = %q", c.RedisAddr)
	}
	if c.InfraMode != InfraManaged {
		t.Errorf("InfraMode = %q, want %q", c.InfraMode, InfraManaged)
	}
	if c.WebhookMaxSkew != 5*time.Minute {
		t.Errorf("WebhookMaxSkew = %s, want 5m", c.WebhookMaxSkew)
	}
	if c.LLMProvider != ProviderNone {
		t.Errorf("LLMProvider = %q, want %q", c.LLMProvider, ProviderNone)
	}
	if c.LLMTimeout != 4*time.Second {
		t.Errorf("LLMTimeout = %s, want 4s", c.LLMTimeout)
	}
	if c.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", c.MaxAttempts)
	}
	if c.BreakerTripRate != 0.20 {
		t.Errorf("BreakerTripRate = %v, want 0.20", c.BreakerTripRate)
	}
	if c.BreakerMinSamples != 10 {
		t.Errorf("BreakerMinSamples = %d, want 10", c.BreakerMinSamples)
	}
	if c.BreakerCooldown != 60*time.Second {
		t.Errorf("BreakerCooldown = %s, want 60s", c.BreakerCooldown)
	}
	if c.TelemetryWindow != 5*time.Minute {
		t.Errorf("TelemetryWindow = %s, want 5m", c.TelemetryWindow)
	}
	if c.WorkerConcurrency != 4 {
		t.Errorf("WorkerConcurrency = %d, want 4", c.WorkerConcurrency)
	}
	if c.MaxSessions != 50000 {
		t.Errorf("MaxSessions = %d, want 50000", c.MaxSessions)
	}
	if c.SessionTTL != 15*time.Minute {
		t.Errorf("SessionTTL = %s, want 15m", c.SessionTTL)
	}
	if c.LogLevel != LogInfo {
		t.Errorf("LogLevel = %q, want info", c.LogLevel)
	}
	if c.SimulatorAddr != "127.0.0.1:8081" {
		t.Errorf("SimulatorAddr = %q", c.SimulatorAddr)
	}
	if c.DemoMode {
		t.Error("DemoMode should default to false")
	}
	if c.Seed != 42 {
		t.Errorf("Seed = %d, want 42", c.Seed)
	}
	if c.CostModel != domain.DefaultCostModel() {
		t.Errorf("CostModel = %+v, want the domain default", c.CostModel)
	}
	// An absent live tier must not be reported as available; the agent uses this
	// to skip a doomed network round trip per incident.
	if c.LiveInferenceEnabled() {
		t.Error("LiveInferenceEnabled with provider=none must be false")
	}
	if !c.Managed() {
		t.Error("Managed() should be true in the default mode")
	}
}

func TestDefaultRazorpayBaseURLFollowsSimulatorAddr(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{
		envSimulatorAddr: "127.0.0.1:9999",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if want := "http://127.0.0.1:9999/v1"; c.RazorpayBaseURL != want {
		t.Errorf("RazorpayBaseURL = %q, want %q (it must track the simulator addr)", c.RazorpayBaseURL, want)
	}

	// An explicit value still wins.
	c, err = LoadFrom(env(noCostFile(t, map[string]string{
		envSimulatorAddr:   "127.0.0.1:9999",
		envRazorpayBaseURL: "https://api.razorpay.com/v1",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.RazorpayBaseURL != "https://api.razorpay.com/v1" {
		t.Errorf("explicit RazorpayBaseURL was overwritten: %q", c.RazorpayBaseURL)
	}
}

func TestProviderDerivedEndpointAndModelDefaults(t *testing.T) {
	t.Parallel()

	cases := map[string]struct{ url, model string }{
		ProviderGroq:   {"https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"},
		ProviderOpenAI: {"https://api.openai.com/v1", "gpt-4o-mini"},
		ProviderGemini: {"https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.0-flash"},
		ProviderOllama: {"http://127.0.0.1:11434/v1", "llama3.1"},
	}
	for provider, want := range cases {
		c, err := LoadFrom(env(noCostFile(t, map[string]string{
			envLLMProvider: provider,
			envLLMAPIKey:   "fixture-value-not-a-credential",
		})))
		if err != nil {
			t.Fatalf("provider %s: %v", provider, err)
		}
		if c.LLMBaseURL != want.url {
			t.Errorf("provider %s: LLMBaseURL = %q, want %q", provider, c.LLMBaseURL, want.url)
		}
		if c.LLMModel != want.model {
			t.Errorf("provider %s: LLMModel = %q, want %q", provider, c.LLMModel, want.model)
		}
		if !c.LiveInferenceEnabled() {
			t.Errorf("provider %s: LiveInferenceEnabled should be true once a key is set", provider)
		}
	}
}

func TestLiveInferenceRequiresAKeyExceptForOllama(t *testing.T) {
	t.Parallel()

	hosted, err := LoadFrom(env(noCostFile(t, map[string]string{envLLMProvider: ProviderGroq})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if hosted.LiveInferenceEnabled() {
		t.Error("a hosted provider with no API key must not report live inference as available")
	}

	local, err := LoadFrom(env(noCostFile(t, map[string]string{envLLMProvider: ProviderOllama})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if !local.LiveInferenceEnabled() {
		t.Error("ollama needs no bearer token and should report live inference as available")
	}
}

// ---------------------------------------------------------------------------
// Override parsing
// ---------------------------------------------------------------------------

func TestLoadFromParsesEveryOverride(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{
		envHTTPAddr:          "0.0.0.0:9000",
		envOpsToken:          "ops-token-value",
		envPGDSN:             pg + "u:p@db:5432/mesh",
		envRedisAddr:         "redis.internal:6380",
		envWebhookSecret:     "webhook-secret-value",
		envWebhookMaxSkew:    "90s",
		envInfraMode:         "external",
		envLLMProvider:       "groq",
		envLLMBaseURL:        "https://example.invalid/v1",
		envLLMAPIKey:         "llm-key-value",
		envLLMModel:          "some-model",
		envLLMTimeout:        "1500ms",
		envCassetteDir:       "some/cassettes",
		envMaxAttempts:       "5",
		envBreakerTripRate:   "0.35",
		envBreakerMinSamples: "25",
		envBreakerCooldown:   "2m",
		envTelemetryWindow:   "10m",
		envWorkerConcurrency: "16",
		envMaxSessions:       "1234",
		envSessionTTL:        "30m",
		envLogLevel:          "DEBUG",
		envSimulatorAddr:     "127.0.0.1:7000",
		envRazorpayBaseURL:   "https://api.razorpay.com/v1",
		envRazorpayKeyID:     testsecret.TestKeyID("id"),
		envRazorpayKeySecret: "rzp-secret-value",
		envDemoMode:          "yes",
		envSeed:              "-9001",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	checks := []struct {
		name       string
		got, want  any
		comparable bool
	}{
		{name: "HTTPAddr", got: c.HTTPAddr, want: "0.0.0.0:9000"},
		{name: "OpsToken", got: c.OpsToken, want: "ops-token-value"},
		{name: "PGDSN", got: c.PGDSN, want: pg + "u:p@db:5432/mesh"},
		{name: "RedisAddr", got: c.RedisAddr, want: "redis.internal:6380"},
		{name: "WebhookSecret", got: c.WebhookSecret, want: "webhook-secret-value"},
		{name: "WebhookMaxSkew", got: c.WebhookMaxSkew, want: 90 * time.Second},
		{name: "InfraMode", got: c.InfraMode, want: InfraExternal},
		{name: "LLMProvider", got: c.LLMProvider, want: ProviderGroq},
		{name: "LLMBaseURL", got: c.LLMBaseURL, want: "https://example.invalid/v1"},
		{name: "LLMAPIKey", got: c.LLMAPIKey, want: "llm-key-value"},
		{name: "LLMModel", got: c.LLMModel, want: "some-model"},
		{name: "LLMTimeout", got: c.LLMTimeout, want: 1500 * time.Millisecond},
		{name: "CassetteDir", got: c.CassetteDir, want: "some/cassettes"},
		{name: "MaxAttempts", got: c.MaxAttempts, want: 5},
		{name: "BreakerTripRate", got: c.BreakerTripRate, want: 0.35},
		{name: "BreakerMinSamples", got: c.BreakerMinSamples, want: 25},
		{name: "BreakerCooldown", got: c.BreakerCooldown, want: 2 * time.Minute},
		{name: "TelemetryWindow", got: c.TelemetryWindow, want: 10 * time.Minute},
		{name: "WorkerConcurrency", got: c.WorkerConcurrency, want: 16},
		{name: "MaxSessions", got: c.MaxSessions, want: 1234},
		{name: "SessionTTL", got: c.SessionTTL, want: 30 * time.Minute},
		{name: "LogLevel", got: c.LogLevel, want: LogDebug},
		{name: "SimulatorAddr", got: c.SimulatorAddr, want: "127.0.0.1:7000"},
		{name: "RazorpayBaseURL", got: c.RazorpayBaseURL, want: "https://api.razorpay.com/v1"},
		{name: "RazorpayKeyID", got: c.RazorpayKeyID, want: testsecret.TestKeyID("id")},
		{name: "RazorpayKeySecret", got: c.RazorpayKeySecret, want: "rzp-secret-value"},
		{name: "DemoMode", got: c.DemoMode, want: true},
		{name: "Seed", got: c.Seed, want: int64(-9001)},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s = %v, want %v", ch.name, ch.got, ch.want)
		}
	}
}

func TestBareIntegerDurationsMeanSeconds(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{
		envWebhookMaxSkew: "300",
		envSessionTTL:     "600",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.WebhookMaxSkew != 300*time.Second {
		t.Errorf("MESH_WEBHOOK_MAX_SKEW=300 gave %s, want 5m0s", c.WebhookMaxSkew)
	}
	if c.SessionTTL != 600*time.Second {
		t.Errorf("MESH_SESSION_TTL=600 gave %s, want 10m0s", c.SessionTTL)
	}
}

func TestBooleanSpellings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"1", true}, {"yes", true}, {"Y", true}, {"on", true},
		{"false", false}, {"FALSE", false}, {"0", false}, {"no", false}, {"N", false}, {"off", false},
	} {
		c, err := LoadFrom(env(noCostFile(t, map[string]string{envDemoMode: tc.in})))
		if err != nil {
			t.Fatalf("MESH_DEMO_MODE=%q: %v", tc.in, err)
		}
		if c.DemoMode != tc.want {
			t.Errorf("MESH_DEMO_MODE=%q gave %v, want %v", tc.in, c.DemoMode, tc.want)
		}
	}
}

func TestValuesAreTrimmedSoFileSourcedSecretsStillVerify(t *testing.T) {
	t.Parallel()

	// A secret read via $(cat secret.txt) carries a trailing newline. Left in
	// place it breaks every HMAC comparison with no visible error.
	c, err := LoadFrom(env(noCostFile(t, map[string]string{
		envInfraMode:     "external",
		envWebhookSecret: "  whsec_padded_value\n",
		envPGDSN:         pg + "u:p@h/db\n",
		envOpsToken:      "\topstoken\r\n",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.WebhookSecret != "whsec_padded_value" {
		t.Errorf("WebhookSecret = %q, want the trimmed value", c.WebhookSecret)
	}
	if c.OpsToken != "opstoken" {
		t.Errorf("OpsToken = %q, want the trimmed value", c.OpsToken)
	}
	if c.PGDSN != pg+"u:p@h/db" {
		t.Errorf("PGDSN = %q, want the trimmed value", c.PGDSN)
	}
}

func TestEmptyVariableFallsBackToDefault(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{envHTTPAddr: "   "})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("a blank override should fall back to the default, got %q", c.HTTPAddr)
	}
}

func TestLoadReadsTheProcessEnvironment(t *testing.T) {
	// Not parallel: t.Setenv forbids it.
	t.Setenv(envHTTPAddr, "127.0.0.1:65000")
	t.Setenv(envCostModelPath, filepath.Join(t.TempDir(), "absent.json"))

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.HTTPAddr != "127.0.0.1:65000" {
		t.Errorf("Load did not read %s: got %q", envHTTPAddr, c.HTTPAddr)
	}
}

// ---------------------------------------------------------------------------
// Bad values
// ---------------------------------------------------------------------------

func TestBadValuesFailAndNameTheOffendingVariable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		key, val string
		sentinel error
	}{
		{envMaxAttempts, "three", ErrInvalidValue},
		{envMaxAttempts, "0", ErrOutOfRange},
		{envMaxAttempts, "999", ErrOutOfRange},
		{envBreakerMinSamples, "1.5", ErrInvalidValue},
		{envWorkerConcurrency, "0", ErrOutOfRange},
		{envWorkerConcurrency, "9999", ErrOutOfRange},
		{envMaxSessions, "0", ErrOutOfRange},
		{envBreakerTripRate, "high", ErrInvalidValue},
		{envBreakerTripRate, "1.5", ErrOutOfRange},
		{envBreakerTripRate, "-0.1", ErrOutOfRange},
		{envBreakerTripRate, "NaN", ErrInvalidValue},
		{envBreakerTripRate, "Inf", ErrInvalidValue},
		{envLLMTimeout, "soon", ErrInvalidValue},
		{envLLMTimeout, "10m", ErrOutOfRange},
		{envWebhookMaxSkew, "48h", ErrOutOfRange},
		{envSessionTTL, "0", ErrOutOfRange},
		{envBreakerCooldown, "never", ErrInvalidValue},
		{envTelemetryWindow, "-5m", ErrOutOfRange},
		{envDemoMode, "maybe", ErrInvalidValue},
		{envSeed, "0x10", ErrInvalidValue},
		{envInfraMode, "hybrid", ErrInvalidValue},
		{envLogLevel, "trace", ErrInvalidValue},
		{envLLMProvider, "groqq", ErrInvalidValue},
		{envHTTPAddr, "not-an-address", ErrInvalidValue},
		{envHTTPAddr, ":99999", ErrInvalidValue},
		{envRedisAddr, "redis.internal", ErrInvalidValue},
		{envSimulatorAddr, "http://x:1/y", ErrInvalidValue},
		{envRazorpayBaseURL, "ftp://files.example/v1", ErrInvalidValue},
		{envRazorpayBaseURL, "https:///v1", ErrInvalidValue},
		{envWebhookSecret, "with\x00nul", ErrInvalidValue},
		{envOpsToken, "header\r\ninjection", ErrInvalidValue},
		{envPGDSN, strings.Repeat("x", maxDSNLen+1), ErrInvalidValue},
		{envOpsToken, strings.Repeat("t", maxSecretLen+1), ErrInvalidValue},
	} {
		_, err := LoadFrom(env(noCostFile(t, map[string]string{tc.key: tc.val})))
		if err == nil {
			t.Errorf("%s=%q: expected an error, got none", tc.key, truncateForLog(tc.val))
			continue
		}
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("%s=%q: error %v does not wrap %v", tc.key, truncateForLog(tc.val), err, tc.sentinel)
		}
		if !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s=%q: error %q does not name the variable", tc.key, truncateForLog(tc.val), err)
		}
	}
}

func TestParseErrorsNeverEchoSecretValues(t *testing.T) {
	t.Parallel()

	const secret = "whsec_THIS_MUST_NEVER_APPEAR_IN_AN_ERROR"
	_, err := LoadFrom(env(noCostFile(t, map[string]string{
		envWebhookSecret: secret + "\x07",
	})))
	if err == nil {
		t.Fatal("expected a control-character rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the rejection echoed the secret: %q", err)
	}
}

func TestAllBadVariablesAreReportedInOnePass(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(noCostFile(t, map[string]string{
		envMaxAttempts:       "nope",
		envWorkerConcurrency: "also-nope",
		envDemoMode:          "perhaps",
	})))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, key := range []string{envMaxAttempts, envWorkerConcurrency, envDemoMode} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("%s missing from the aggregated error: %v", key, err)
		}
	}
}

func TestLoadReturnsNoConfigOnError(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{envMaxAttempts: "nope"})))
	if err == nil {
		t.Fatal("expected an error")
	}
	if c != (Config{}) {
		t.Errorf("a failed load must not hand back a partially-populated Config: %+v", c)
	}
}

func truncateForLog(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Mode validation and managed-mode credential generation
// ---------------------------------------------------------------------------

func TestExternalModeRefusesMissingCredentials(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		envInfraMode:     "external",
		envWebhookSecret: "supplied-webhook-secret",
		envPGDSN:         pg + "u:p@h:5432/db",
		envOpsToken:      "supplied-ops-token",
	}

	if _, err := LoadFrom(env(noCostFile(t, cloneMap(base)))); err != nil {
		t.Fatalf("a fully-specified external config must load: %v", err)
	}

	for _, missing := range []string{envWebhookSecret, envPGDSN, envOpsToken} {
		kv := cloneMap(base)
		delete(kv, missing)
		_, err := LoadFrom(env(noCostFile(t, kv)))
		if err == nil {
			t.Errorf("external mode without %s must fail closed", missing)
			continue
		}
		if !errors.Is(err, ErrMissingRequired) {
			t.Errorf("%s: error %v does not wrap ErrMissingRequired", missing, err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("%s: error %q does not name the variable", missing, err)
		}
	}
}

func TestExternalModeNeverInventsCredentials(t *testing.T) {
	t.Parallel()

	c := Default()
	c.InfraMode = InfraExternal
	c.WebhookSecret = "supplied"
	c.PGDSN = pg + "u:p@h/db"
	c.OpsToken = "supplied"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.RazorpayKeyID != "" || c.RazorpayKeySecret != "" {
		t.Errorf("external mode must not mint Razorpay credentials: id=%q secret set=%v",
			c.RazorpayKeyID, c.RazorpayKeySecret != "")
	}
}

func TestManagedModeGeneratesCryptographicallyRandomSecrets(t *testing.T) {
	t.Parallel()

	first, err := LoadFrom(env(noCostFile(t, nil)))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	second, err := LoadFrom(env(noCostFile(t, nil)))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	// 32 bytes, hex encoded.
	if len(first.WebhookSecret) != 64 {
		t.Errorf("WebhookSecret is %d chars, want 64 hex chars (32 bytes)", len(first.WebhookSecret))
	}
	if !isHex(first.WebhookSecret) {
		t.Errorf("WebhookSecret is not hex: %d chars", len(first.WebhookSecret))
	}
	if first.WebhookSecret == second.WebhookSecret {
		t.Error("two managed-mode loads produced the same webhook secret; the source is not random")
	}

	// Nothing that gates access may be left empty: an empty credential is an
	// authentication bypass waiting for a comparison that treats "" as a match.
	for name, v := range map[string]string{
		"WebhookSecret":     first.WebhookSecret,
		"OpsToken":          first.OpsToken,
		"RazorpayKeyID":     first.RazorpayKeyID,
		"RazorpayKeySecret": first.RazorpayKeySecret,
	} {
		if v == "" {
			t.Errorf("managed mode left %s empty", name)
		}
	}
	if first.OpsToken == second.OpsToken {
		t.Error("two managed-mode loads produced the same ops token")
	}
	// An exact test-mode prefix plus a hex body is what keeps a generated
	// identifier from ever resembling a production key.
	testPrefix := testsecret.TestKeyPrefix()
	if !strings.HasPrefix(first.RazorpayKeyID, testPrefix) {
		t.Errorf("generated RazorpayKeyID = %q, want the %q prefix", first.RazorpayKeyID, testPrefix)
	}
	if !isHex(strings.TrimPrefix(first.RazorpayKeyID, testPrefix)) {
		t.Errorf("generated RazorpayKeyID body is not hex: %q", first.RazorpayKeyID)
	}
}

func TestManagedModeKeepsSuppliedSecrets(t *testing.T) {
	t.Parallel()

	c, err := LoadFrom(env(noCostFile(t, map[string]string{
		envWebhookSecret: "operator-supplied-secret",
		envOpsToken:      "operator-supplied-token",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.WebhookSecret != "operator-supplied-secret" {
		t.Errorf("generation clobbered a supplied webhook secret: %q", c.WebhookSecret)
	}
	if c.OpsToken != "operator-supplied-token" {
		t.Errorf("generation clobbered a supplied ops token: %q", c.OpsToken)
	}
}

func TestValidateIsIdempotent(t *testing.T) {
	t.Parallel()

	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	snapshot := c
	if err := c.Validate(); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if c != snapshot {
		t.Error("a second Validate changed the config; generation must only fire on an unset field")
	}
}

func TestValidateFillsAZeroCostModel(t *testing.T) {
	t.Parallel()

	c := Default()
	c.CostModel = domain.CostModel{}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.CostModel != domain.DefaultCostModel() {
		t.Errorf("a zero cost model must be replaced by the default, got %+v", c.CostModel)
	}
}

func TestValidateRejectsAnAbsurdCostModel(t *testing.T) {
	t.Parallel()

	c := Default()
	c.CostModel.GatewayFeePerAttemptPaisa = -1
	if err := c.Validate(); err == nil || !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("a negative gateway fee must be rejected, got %v", err)
	}

	c = Default()
	c.CostModel.CompliancePenaltyPaisa = maxSanePaisa + 1
	if err := c.Validate(); err == nil || !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("an out-of-band compliance penalty must be rejected, got %v", err)
	}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(s) > 0
}

// ---------------------------------------------------------------------------
// Redaction — the critical property
// ---------------------------------------------------------------------------

// Raw values that must never appear in any rendering of a Config. They are
// deliberately distinctive so a substring search cannot produce a false pass.
const (
	rawOpsToken     = "OPSTOKEN_qP7wZ2xR9mK4vN1bL6hT"
	rawWebhook      = "WHSEC_a3F9kQ2mZ7pX1cV8nB4sD6gJ"
	rawLLMKey       = "gsk_LLMKEY_R5tY8uI3oP6aS9dF2gH"
	rawRzpKeyIDBody = "KEYID_M4nB7vC2xZ9qW"
	rawRzpSecret    = "RZPSECRET_L8kJ5hG3fD1sA6pO9iU"
	rawPGPassword   = "PGPASS_z9X8c7V6b5N4m3L2k1J0h"
	rawSSLPassword  = "SSLPASS_Q1w2E3r4T5y6U7i8O9p0"
)

// rawRzpKeyID is composed rather than declared beside the others: a literal of
// that shape is indistinguishable from a real key to a secret scanner.
func rawRzpKeyID() string { return testsecret.TestKeyID(rawRzpKeyIDBody) }

func secretiveConfig() Config {
	c := Default()
	c.InfraMode = InfraExternal
	c.OpsToken = rawOpsToken
	c.WebhookSecret = rawWebhook
	c.LLMProvider = ProviderGroq
	c.LLMAPIKey = rawLLMKey
	// A base URL that carries its credential in the userinfo slot — an unusual
	// but entirely legal shape that a naive renderer prints verbatim.
	c.LLMBaseURL = "https://" + rawLLMKey + "@api.groq.com/openai/v1"
	c.LLMModel = "llama-3.3-70b-versatile"
	c.RazorpayKeyID = rawRzpKeyID()
	c.RazorpayKeySecret = rawRzpSecret
	c.PGDSN = testsecret.PostgresDSN("mesh_app", rawPGPassword, "db.internal.example:5432", "meshdb",
		"sslmode=verify-full&sslpassword="+rawSSLPassword)
	return c
}

func allRawSecrets() map[string]string {
	return map[string]string{
		"OpsToken":          rawOpsToken,
		"WebhookSecret":     rawWebhook,
		"LLMAPIKey":         rawLLMKey,
		"RazorpayKeyID":     rawRzpKeyID(),
		"RazorpayKeySecret": rawRzpSecret,
		"PGDSN password":    rawPGPassword,
		"PGDSN sslpassword": rawSSLPassword,
	}
}

func TestStringNeverLeaksASecret(t *testing.T) {
	t.Parallel()

	out := secretiveConfig().String()
	for name, secret := range allRawSecrets() {
		if strings.Contains(out, secret) {
			t.Errorf("Config.String() leaked %s", name)
		}
	}
	if t.Failed() {
		t.Logf("rendering was: %s", out)
	}
}

func TestFmtVerbsNeverLeakASecret(t *testing.T) {
	t.Parallel()

	c := secretiveConfig()
	// %v and %s route through Stringer. %+v and %#v do not, so a Config must
	// never be handed to them; this test documents the boundary by asserting the
	// two verbs the codebase is allowed to use are safe.
	for _, out := range []string{
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%s", c),
		fmt.Sprintf("%v", &c),
	} {
		for name, secret := range allRawSecrets() {
			if strings.Contains(out, secret) {
				t.Errorf("a formatted Config leaked %s", name)
			}
		}
	}
}

func TestLogValueNeverLeaksASecret(t *testing.T) {
	t.Parallel()

	c := secretiveConfig()

	for _, h := range []struct {
		name string
		make func(*bytes.Buffer) slog.Handler
	}{
		{"json", func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		}},
		{"text", func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		}},
	} {
		var buf bytes.Buffer
		log := slog.New(h.make(&buf))
		// Both the idiomatic call and the lazy one must be safe.
		log.Info("boot", "config", c)
		log.Info("boot", slog.Any("config", &c))
		out := buf.String()
		for name, secret := range allRawSecrets() {
			if strings.Contains(out, secret) {
				t.Errorf("%s handler leaked %s", h.name, name)
			}
		}
		if t.Failed() {
			t.Logf("%s rendering was: %s", h.name, out)
		}
	}
}

func TestRedactedRenderingStaysUsefulToAnOperator(t *testing.T) {
	t.Parallel()

	out := secretiveConfig().String()

	// Host, database, and non-secret options survive so a connection failure is
	// still diagnosable from a log line.
	for _, want := range []string{"db.internal.example:5432", "meshdb", "sslmode=verify-full"} {
		if !strings.Contains(out, want) {
			t.Errorf("redaction removed %q, which an operator needs", want)
		}
	}
	// The username survives; only the password is replaced.
	if !strings.Contains(out, "mesh_app") {
		t.Error("redaction removed the DSN username, which is not a secret")
	}
	// Fingerprints let an operator confirm two processes hold the same secret.
	for _, secret := range []string{rawOpsToken, rawWebhook, rawLLMKey, rawRzpSecret} {
		if !strings.Contains(out, SecretFingerprint(secret)) {
			t.Error("a set secret should render as its fingerprint")
		}
	}
	// An unset secret is distinguishable from a set one.
	empty := Default()
	if !strings.Contains(empty.String(), "webhook_secret=unset") {
		t.Errorf("an unset secret should render as unset, got: %s", empty.String())
	}
}

func TestStringAndLogValueRenderTheSameFields(t *testing.T) {
	t.Parallel()

	c := secretiveConfig()
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("boot", "config", c)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("decoding the log line: %v", err)
	}
	group, ok := line["config"].(map[string]any)
	if !ok {
		t.Fatalf("the config attr is not a group: %T", line["config"])
	}
	// Divergence between the two renderers is how a new secret-bearing field
	// ends up masked in one and printed in the other.
	if len(group) != len(c.logAttrs()) {
		t.Errorf("LogValue emitted %d fields, logAttrs declares %d", len(group), len(c.logAttrs()))
	}
	for _, a := range c.logAttrs() {
		if _, ok := group[a.Key]; !ok {
			t.Errorf("LogValue is missing %q", a.Key)
		}
		if !strings.Contains(c.String(), a.Key+"=") {
			t.Errorf("String() is missing %q", a.Key)
		}
	}
}

func TestSecretFingerprint(t *testing.T) {
	t.Parallel()

	fp := SecretFingerprint("hunter2")
	if len(fp) != 8 {
		t.Errorf("fingerprint is %d chars, want 8", len(fp))
	}
	if !isHex(fp) {
		t.Errorf("fingerprint %q is not lowercase hex", fp)
	}
	// SHA-256("hunter2") begins f52fbd32...
	if fp != "f52fbd32" {
		t.Errorf("fingerprint = %q, want f52fbd32 (first 8 hex of SHA-256)", fp)
	}
	if SecretFingerprint("hunter2") != SecretFingerprint("hunter2") {
		t.Error("fingerprints must be stable")
	}
	if SecretFingerprint("hunter2") == SecretFingerprint("hunter3") {
		t.Error("distinct secrets should not share a fingerprint")
	}
	if SecretFingerprint("") != "" {
		t.Error("an empty secret must not get a fingerprint; that would fingerprint the empty string")
	}
	if strings.Contains(fp, "hunter2") {
		t.Error("a fingerprint must not contain its input")
	}
}

func TestRedactDSN(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, in, want string
	}{
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "url form",
			in:   pg + "mesh:hunter2@db:5432/meshdb",
			want: "postgres://mesh:" + redacted + "@db:5432/meshdb",
		},
		{
			name: "postgresql scheme",
			in:   pgx + "mesh:hunter2@db/meshdb?sslmode=require",
			want: "postgresql://mesh:" + redacted + "@db/meshdb?sslmode=require",
		},
		{
			name: "no password",
			in:   "postgres://mesh@db:5432/meshdb",
			want: "postgres://mesh@db:5432/meshdb",
		},
		{
			name: "no userinfo",
			in:   "postgres://db:5432/meshdb",
			want: "postgres://db:5432/meshdb",
		},
		{
			name: "at sign inside the password",
			in:   pg + "mesh:p@ss@db/meshdb",
			want: "postgres://mesh:" + redacted + "@db/meshdb",
		},
		{
			name: "slash inside the password, as base64 secrets contain",
			in:   pg + "mesh:aB3/xY9+z@db/meshdb",
			want: "postgres://mesh:" + redacted + "@db/meshdb",
		},
		{
			name: "question mark inside the password",
			in:   pg + "mesh:wh?at@db/meshdb",
			want: "postgres://mesh:" + redacted + "@db/meshdb",
		},
		{
			name: "secret query parameter",
			in:   "postgres://db/meshdb?sslmode=require&sslpassword=zzz&sslkey=/k.pem",
			want: "postgres://db/meshdb?sslmode=require&sslpassword=" + redacted + "&sslkey=" + redacted,
		},
		{
			name: "keyword value form",
			in:   "host=db port=5432 user=mesh password=hunter2 dbname=meshdb sslmode=require",
			want: "host=db port=5432 user=mesh password=" + redacted + " dbname=meshdb sslmode=require",
		},
		{
			name: "keyword value form with a quoted password",
			in:   "host=db password='hunter 2 with spaces' dbname=meshdb",
			want: "host=db password=" + redacted + " dbname=meshdb",
		},
		{
			name: "keyword value form with an escaped quote in the password",
			in:   `host=db password='esc\'aped' dbname=meshdb`,
			want: "host=db password=" + redacted + " dbname=meshdb",
		},
		{
			name: "keyword value form with sslkey and passfile",
			in:   "host=db sslkey=/etc/k.pem passfile=/etc/pgpass dbname=meshdb",
			want: "host=db sslkey=" + redacted + " passfile=" + redacted + " dbname=meshdb",
		},
		{
			name: "keyword value form whose value merely looks like a url",
			in:   "host=db password=pg://leaked dbname=meshdb",
			want: "host=db password=" + redacted + " dbname=meshdb",
		},
		{
			name: "irregular whitespace is preserved",
			in:   "  host=db   password=hunter2  ",
			want: "  host=db   password=" + redacted + "  ",
		},
	} {
		if got := RedactDSN(tc.in); got != tc.want {
			t.Errorf("%s:\n  RedactDSN(%q)\n       = %q\n  want   %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestRedactDSNNeverEmitsThePassword(t *testing.T) {
	t.Parallel()

	const pw = "PWD_j8H3kL9mN2pQ5rS7tU1vW4xY6zA0b"
	for _, dsn := range []string{
		pg + "u:" + pw + "@h/db",
		pg + "u:" + pw + "@h:5432/db?sslmode=require",
		pgx + "u:" + pw + "@h/db#frag",
		pg + "u:" + pw + "/x@h/db",
		pg + "u:" + pw + "?y@h/db",
		pg + "u:" + pw + "@h@h2/db",
		"host=h user=u password=" + pw,
		"host=h password='" + pw + "' dbname=d",
		"password=" + pw,
		"PASSWORD=" + pw,
		"host=h sslpassword=" + pw + " dbname=d",
		"postgres://h/db?password=" + pw,
	} {
		if got := RedactDSN(dsn); strings.Contains(got, pw) {
			t.Errorf("RedactDSN(%q) leaked the password: %q", dsn, got)
		}
	}
}

func TestRedactURLStripsTheWholeUserinfo(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1"},
		{"https://gsk_key@api.groq.com/openai/v1", "https://" + redacted + "@api.groq.com/openai/v1"},
		{"https://user:pw@api.example/v1", "https://" + redacted + "@api.example/v1"},
		{"https://api.example/v1?api_key=zzz", "https://api.example/v1?api_key=" + redacted},
		{"https://api.example/v1?model=x&token=zzz", "https://api.example/v1?model=x&token=" + redacted},
		{"api.example/v1?api_key=zzz", "api.example/v1?api_key=" + redacted},
	} {
		if got := RedactURL(tc.in); got != tc.want {
			t.Errorf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsSecretKey(t *testing.T) {
	t.Parallel()

	for _, k := range []string{
		"password", "PASSWORD", "sslpassword", "passwd", "pwd", "passfile",
		"sslkey", "api_key", "token", "secret", "credentials", "authorization", "signature",
	} {
		if !isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"host", "port", "user", "dbname", "sslmode", "application_name", "model"} {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true, want false", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared cost model
// ---------------------------------------------------------------------------

func writeJSON(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "costs.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

func TestLoadCostModelReadsTheSharedFile(t *testing.T) {
	t.Parallel()

	path := writeJSON(t, `{
	  "_comment": "unknown keys are tolerated so Python may annotate the file",
	  "gateway_fee_per_attempt_paisa": 311,
	  "comms_cost_per_message_paisa": 71,
	  "compliance_penalty_paisa": 60000,
	  "session_friction_paisa": 42
	}`)

	cm, err := LoadCostModel(path)
	if err != nil {
		t.Fatalf("LoadCostModel: %v", err)
	}
	want := domain.CostModel{
		GatewayFeePerAttemptPaisa: 311,
		CommsCostPerMessagePaisa:  71,
		CompliancePenaltyPaisa:    60000,
		SessionFrictionPaisa:      42,
	}
	if cm != want {
		t.Errorf("CostModel = %+v, want %+v", cm, want)
	}

	// And it reaches the Config.
	c, err := LoadFrom(env(map[string]string{envCostModelPath: path}))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if c.CostModel != want {
		t.Errorf("Config.CostModel = %+v, want %+v", c.CostModel, want)
	}
}

func TestLoadCostModelFallsBackWhenTheFileIsAbsent(t *testing.T) {
	t.Parallel()

	cm, err := LoadCostModel(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("an absent cost file must not be fatal: %v", err)
	}
	if cm != domain.DefaultCostModel() {
		t.Errorf("CostModel = %+v, want the domain default", cm)
	}

	cm, err = LoadCostModel("")
	if err != nil {
		t.Fatalf("an empty path must not be fatal: %v", err)
	}
	if cm != domain.DefaultCostModel() {
		t.Errorf("CostModel = %+v, want the domain default", cm)
	}
}

func TestLoadCostModelRejectsABrokenFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, body string }{
		{"malformed json", `{"gateway_fee_per_attempt_paisa": 250,`},
		{"not an object", `[250, 60, 50000, 60]`},
		{"missing a field", `{"gateway_fee_per_attempt_paisa": 250}`},
		{"null field", `{
			"gateway_fee_per_attempt_paisa": 250,
			"comms_cost_per_message_paisa": 60,
			"compliance_penalty_paisa": 50000,
			"session_friction_paisa": null
		}`},
		{"negative value", `{
			"gateway_fee_per_attempt_paisa": -250,
			"comms_cost_per_message_paisa": 60,
			"compliance_penalty_paisa": 50000,
			"session_friction_paisa": 60
		}`},
		{"absurd value", `{
			"gateway_fee_per_attempt_paisa": 250,
			"comms_cost_per_message_paisa": 60,
			"compliance_penalty_paisa": 999999999999,
			"session_friction_paisa": 60
		}`},
		{"float where paisa is required", `{
			"gateway_fee_per_attempt_paisa": 250.5,
			"comms_cost_per_message_paisa": 60,
			"compliance_penalty_paisa": 50000,
			"session_friction_paisa": 60
		}`},
	} {
		path := writeJSON(t, tc.body)
		if _, err := LoadCostModel(path); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		} else if !errors.Is(err, ErrCostModel) {
			t.Errorf("%s: error %v does not wrap ErrCostModel", tc.name, err)
		}

		// A broken shared cost table must stop the process, not degrade to
		// defaults: silent divergence between the benchmark and the live policy
		// engine is exactly what the shared file exists to prevent.
		if _, err := LoadFrom(env(map[string]string{envCostModelPath: path})); err == nil {
			t.Errorf("%s: LoadFrom accepted a broken cost table", tc.name)
		}
	}
}

func TestLoadCostModelRejectsAnOversizedFile(t *testing.T) {
	t.Parallel()

	path := writeJSON(t, `{"_pad": "`+strings.Repeat("x", maxCostModelBytes)+`"}`)
	if _, err := LoadCostModel(path); err == nil || !errors.Is(err, ErrCostModel) {
		t.Fatalf("an oversized cost file must be rejected, got %v", err)
	}
}

// TestRepoCostFileMatchesDomainDefault is the anti-drift guard. The Python
// benchmark reads eval/costs.json; Go compiles domain.DefaultCostModel. If the
// two ever disagree, every NRCV figure in the report is priced against numbers
// the running system does not use.
func TestRepoCostFileMatchesDomainDefault(t *testing.T) {
	t.Parallel()

	const path = "../../eval/costs.json"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("eval/costs.json must be committed: %v", err)
	}
	cm, err := LoadCostModel(path)
	if err != nil {
		t.Fatalf("LoadCostModel(%s): %v", path, err)
	}
	if cm != domain.DefaultCostModel() {
		t.Errorf("eval/costs.json has drifted from domain.DefaultCostModel():\n  file   = %+v\n  domain = %+v",
			cm, domain.DefaultCostModel())
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentLoadsAreRaceFree(t *testing.T) {
	t.Parallel()

	kv := noCostFile(t, map[string]string{envHTTPAddr: "127.0.0.1:8080"})
	lookup := env(kv)

	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := LoadFrom(lookup)
			if err != nil {
				errCh <- err
				return
			}
			// Exercise the rendering paths too; they are what other goroutines
			// will call while holding the same value.
			_ = c.String()
			_ = c.LogValue()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent LoadFrom: %v", err)
	}
}

// Package config resolves the process-wide runtime configuration from the
// environment.
//
// Two properties matter more here than ergonomics. First, a Config is either
// fully valid or it does not exist: Load parses, normalises, and range-checks
// every field up front and returns an error rather than a half-populated
// struct, so nothing downstream has to re-check a bound at the point of use.
// Second, a Config is safe to log: String and LogValue render one shared
// redacted projection, so a newly added secret-bearing field cannot leak
// through one renderer while being masked by the other.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// EnvPrefix namespaces every variable this process reads. A single prefix is
// what lets an operator audit the whole surface with one `env | grep`.
const EnvPrefix = "MESH_"

// Infrastructure modes. Managed boots PostgreSQL and Redis inside this process
// and is the zero-dependency demo path; External points at operator-provided
// backing services and therefore refuses to start without real credentials.
const (
	InfraManaged  = "managed"
	InfraExternal = "external"
)

// Inference providers. All of them speak the OpenAI chat-completions wire
// format, so the provider name only selects endpoint and model defaults — it
// never selects a different client implementation.
const (
	// ProviderNone disables the live tier entirely. It is the default because
	// the system must work offline, with no API key and no egress, on a
	// reviewer's laptop.
	ProviderNone   = "none"
	ProviderGroq   = "groq"
	ProviderOpenAI = "openai"
	ProviderGemini = "gemini"
	ProviderOllama = "ollama"
)

// Log levels accepted by MESH_LOG_LEVEL, mirroring log/slog.
const (
	LogDebug = "debug"
	LogInfo  = "info"
	LogWarn  = "warn"
	LogError = "error"
)

// Sentinel errors. Callers match on these; the wrapped text names the offending
// environment variable so an operator can act without reading source.
var (
	// ErrInvalidValue means a value was present but could not be interpreted as
	// the declared type, or carried characters that are unsafe to propagate.
	ErrInvalidValue = errors.New("config: invalid value")
	// ErrOutOfRange means a value parsed cleanly but falls outside the band in
	// which the system has defined behaviour.
	ErrOutOfRange = errors.New("config: value out of range")
	// ErrMissingRequired means external mode was selected without a credential
	// the system refuses to run without.
	ErrMissingRequired = errors.New("config: missing required value")
	// ErrCostModel means the shared cost table could not be read or disagreed
	// with its schema. It is fatal rather than ignorable: silently falling back
	// to defaults would let the Go policy engine and the Python benchmark
	// optimise different numbers while both claim to be authoritative.
	ErrCostModel = errors.New("config: cost model")
)

// Environment variable names, declared once so that Load, Validate, the error
// messages, and .env.example can never spell one differently.
const (
	envHTTPAddr          = EnvPrefix + "HTTP_ADDR"
	envOpsToken          = EnvPrefix + "OPS_TOKEN"
	envPGDSN             = EnvPrefix + "PG_DSN"
	envRedisAddr         = EnvPrefix + "REDIS_ADDR"
	envWebhookSecret     = EnvPrefix + "WEBHOOK_SECRET"
	envWebhookMaxSkew    = EnvPrefix + "WEBHOOK_MAX_SKEW"
	envInfraMode         = EnvPrefix + "INFRA_MODE"
	envLLMProvider       = EnvPrefix + "LLM_PROVIDER"
	envLLMBaseURL        = EnvPrefix + "LLM_BASE_URL"
	envLLMAPIKey         = EnvPrefix + "LLM_API_KEY"
	envLLMModel          = EnvPrefix + "LLM_MODEL"
	envLLMTimeout        = EnvPrefix + "LLM_TIMEOUT"
	envCassetteDir       = EnvPrefix + "CASSETTE_DIR"
	envMaxAttempts       = EnvPrefix + "MAX_ATTEMPTS"
	envBreakerTripRate   = EnvPrefix + "BREAKER_TRIP_RATE"
	envBreakerMinSamples = EnvPrefix + "BREAKER_MIN_SAMPLES"
	envBreakerCooldown   = EnvPrefix + "BREAKER_COOLDOWN"
	envTelemetryWindow   = EnvPrefix + "TELEMETRY_WINDOW"
	envWorkerConcurrency = EnvPrefix + "WORKER_CONCURRENCY"
	envMaxSessions       = EnvPrefix + "MAX_SESSIONS"
	envSessionTTL        = EnvPrefix + "SESSION_TTL"
	envLogLevel          = EnvPrefix + "LOG_LEVEL"
	envCostModelPath     = EnvPrefix + "COST_MODEL_PATH"
	envSimulatorAddr     = EnvPrefix + "SIMULATOR_ADDR"
	envRazorpayBaseURL   = EnvPrefix + "RAZORPAY_BASE_URL"
	envRazorpayKeyID     = EnvPrefix + "RAZORPAY_KEY_ID"
	envRazorpayKeySecret = EnvPrefix + "RAZORPAY_KEY_SECRET"
	envDemoMode          = EnvPrefix + "DEMO_MODE"
	envSeed              = EnvPrefix + "SEED"
)

// Input bounds. Environment variables are external input on a machine that may
// be shared, so every value is length-capped before it reaches a parser, a
// header, or a connection string.
const (
	maxSecretLen = 512
	maxTextLen   = 256
	maxURLLen    = 2048
	maxPathLen   = 512
	maxDSNLen    = 4096
	maxNumberLen = 64
)

// maxCostModelBytes bounds the shared cost table. It is a four-integer document;
// anything larger is a mistake or an attempt to make the loader allocate.
const maxCostModelBytes = 64 << 10

// maxSanePaisa caps any single cost figure at Rs 1 crore. A typo that adds two
// zeroes to a compliance penalty would otherwise silently dominate every
// expected-value calculation in the policy engine.
const maxSanePaisa = int64(100_000_000)

// Config is the resolved runtime configuration for every ResilientMesh binary.
//
// One struct serves the API, the worker, the simulator, and the CLI on purpose:
// the simulator signs webhooks with the same secret the ingest edge verifies
// with, and the benchmark prices attempts with the same CostModel the policy
// engine optimises. Splitting them per binary is exactly how those pairs drift.
type Config struct {
	// Edge.
	HTTPAddr string
	OpsToken string

	// Backing services. In managed mode PGDSN and RedisAddr are overwritten by
	// infra.StartManaged with the same shapes external mode uses, so no
	// downstream code branches on InfraMode.
	PGDSN     string
	RedisAddr string

	// Webhook trust boundary. WebhookMaxSkew bounds replay of a captured
	// delivery in both directions, so a clock-skewed sender fails loudly rather
	// than opening an unbounded replay window.
	WebhookSecret  string
	WebhookMaxSkew time.Duration

	InfraMode string

	// Inference tier 1. A "none" provider means the live tier is skipped and the
	// stack degrades to cassette replay and then the deterministic classifier.
	LLMProvider string
	LLMBaseURL  string
	LLMAPIKey   string
	LLMModel    string
	LLMTimeout  time.Duration

	// Inference tier 2.
	CassetteDir string

	// Decision bounds.
	MaxAttempts       int
	BreakerTripRate   float64
	BreakerMinSamples int
	BreakerCooldown   time.Duration
	TelemetryWindow   time.Duration

	// Runtime sizing. MaxSessions is a hard admission cap: an unbounded session
	// map is a memory-exhaustion vector reachable by anyone who can open an
	// EventSource.
	WorkerConcurrency int
	MaxSessions       int
	SessionTTL        time.Duration

	LogLevel string

	// CostModel is read from CostModelPath when that file exists so the Go
	// policy engine and the Python benchmark cannot price the same incident
	// differently.
	CostModel     domain.CostModel
	CostModelPath string

	// Razorpay surface. RazorpayBaseURL defaults to the local simulator, which
	// implements the identical schema, so the production client code is the one
	// exercised in the demo.
	SimulatorAddr     string
	RazorpayBaseURL   string
	RazorpayKeyID     string
	RazorpayKeySecret string

	DemoMode bool
	// DemoTimeScale compresses the wait before a scheduled retry so a
	// demonstration reaches an outcome. It never changes a decision; see
	// worker.Config.DemoTimeScale. One means no compression.
	DemoTimeScale float64
	Seed          int64
}

// Default returns the configuration the system runs with when the environment
// is empty: a fully offline, single-process, zero-credential managed stack.
// Load starts from this value, so a default and its environment override are
// defined in exactly one place.
func Default() Config {
	return Config{
		// Loopback by default. Binding every interface would expose an
		// operator console and a webhook endpoint to the local network on a
		// laptop, and would make a firewall prompt part of the first-run
		// experience. A deployment that wants a public bind sets MESH_HTTP_ADDR.
		HTTPAddr:          "127.0.0.1:8080",
		RedisAddr:         "127.0.0.1:6379",
		WebhookMaxSkew:    5 * time.Minute,
		InfraMode:         InfraManaged,
		LLMProvider:       ProviderNone,
		LLMTimeout:        4 * time.Second,
		CassetteDir:       filepath.Join("testdata", "cassettes"),
		MaxAttempts:       3,
		BreakerTripRate:   0.20,
		BreakerMinSamples: 10,
		BreakerCooldown:   60 * time.Second,
		TelemetryWindow:   5 * time.Minute,
		WorkerConcurrency: 4,
		MaxSessions:       50000,
		SessionTTL:        15 * time.Minute,
		LogLevel:          LogInfo,
		CostModel:         domain.DefaultCostModel(),
		CostModelPath:     filepath.Join("eval", "costs.json"),
		SimulatorAddr:     "127.0.0.1:8081",
		Seed:              42,
		DemoTimeScale:     1,
	}
}

// Lookup resolves one environment variable. Taking it as a parameter rather
// than calling os.Getenv directly keeps Load hermetic and lets tests run in
// parallel, which t.Setenv forbids.
type Lookup func(key string) (value string, ok bool)

// Load resolves configuration from the process environment.
func Load() (Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom resolves configuration from an arbitrary variable source. All parse
// failures are collected rather than short-circuited: an operator fixing a bad
// deployment wants every broken variable in one pass, not one per restart.
func LoadFrom(lookup Lookup) (Config, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	c := Default()
	l := &loader{lookup: lookup}

	c.HTTPAddr = l.text(envHTTPAddr, c.HTTPAddr, maxTextLen)
	c.OpsToken = l.text(envOpsToken, c.OpsToken, maxSecretLen)
	c.PGDSN = l.text(envPGDSN, c.PGDSN, maxDSNLen)
	c.RedisAddr = l.text(envRedisAddr, c.RedisAddr, maxTextLen)
	c.WebhookSecret = l.text(envWebhookSecret, c.WebhookSecret, maxSecretLen)
	c.WebhookMaxSkew = l.duration(envWebhookMaxSkew, c.WebhookMaxSkew)
	c.InfraMode = l.text(envInfraMode, c.InfraMode, maxTextLen)

	c.LLMProvider = l.text(envLLMProvider, c.LLMProvider, maxTextLen)
	c.LLMBaseURL = l.text(envLLMBaseURL, c.LLMBaseURL, maxURLLen)
	c.LLMAPIKey = l.text(envLLMAPIKey, c.LLMAPIKey, maxSecretLen)
	c.LLMModel = l.text(envLLMModel, c.LLMModel, maxTextLen)
	c.LLMTimeout = l.duration(envLLMTimeout, c.LLMTimeout)
	c.CassetteDir = l.text(envCassetteDir, c.CassetteDir, maxPathLen)

	c.MaxAttempts = l.integer(envMaxAttempts, c.MaxAttempts)
	c.BreakerTripRate = l.float(envBreakerTripRate, c.BreakerTripRate)
	c.BreakerMinSamples = l.integer(envBreakerMinSamples, c.BreakerMinSamples)
	c.BreakerCooldown = l.duration(envBreakerCooldown, c.BreakerCooldown)
	c.TelemetryWindow = l.duration(envTelemetryWindow, c.TelemetryWindow)

	c.WorkerConcurrency = l.integer(envWorkerConcurrency, c.WorkerConcurrency)
	c.MaxSessions = l.integer(envMaxSessions, c.MaxSessions)
	c.SessionTTL = l.duration(envSessionTTL, c.SessionTTL)
	c.LogLevel = l.text(envLogLevel, c.LogLevel, maxTextLen)

	c.CostModelPath = l.text(envCostModelPath, c.CostModelPath, maxPathLen)
	c.SimulatorAddr = l.text(envSimulatorAddr, c.SimulatorAddr, maxTextLen)
	c.RazorpayBaseURL = l.text(envRazorpayBaseURL, c.RazorpayBaseURL, maxURLLen)
	c.RazorpayKeyID = l.text(envRazorpayKeyID, c.RazorpayKeyID, maxSecretLen)
	c.RazorpayKeySecret = l.text(envRazorpayKeySecret, c.RazorpayKeySecret, maxSecretLen)
	c.DemoMode = l.boolean(envDemoMode, c.DemoMode)
	c.Seed = l.integer64(envSeed, c.Seed)

	errs := l.errs
	if len(errs) == 0 {
		cm, err := LoadCostModel(c.CostModelPath)
		if err != nil {
			errs = append(errs, err)
		} else {
			c.CostModel = cm
		}
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate normalises derived fields, enforces every semantic bound, and
// materialises the credentials managed mode is allowed to invent.
//
// It is deliberately separate from parsing so that a Config assembled in code —
// by cmd/mesh after infra.StartManaged rewrites the DSN, or by a test — passes
// through the identical checks an environment-loaded one does. It is idempotent:
// generation only fires on an unset field.
func (c *Config) Validate() error {
	var errs []error

	c.InfraMode = strings.ToLower(strings.TrimSpace(c.InfraMode))
	c.LLMProvider = strings.ToLower(strings.TrimSpace(c.LLMProvider))
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))

	if c.InfraMode != InfraManaged && c.InfraMode != InfraExternal {
		errs = append(errs, fmt.Errorf("%s: %w: %q is not one of %s|%s",
			envInfraMode, ErrInvalidValue, c.InfraMode, InfraManaged, InfraExternal))
	}
	switch c.LogLevel {
	case LogDebug, LogInfo, LogWarn, LogError:
	default:
		errs = append(errs, fmt.Errorf("%s: %w: %q is not one of %s|%s|%s|%s",
			envLogLevel, ErrInvalidValue, c.LogLevel, LogDebug, LogInfo, LogWarn, LogError))
	}
	switch c.LLMProvider {
	case ProviderNone, ProviderGroq, ProviderOpenAI, ProviderGemini, ProviderOllama:
	default:
		errs = append(errs, fmt.Errorf("%s: %w: %q is not one of %s|%s|%s|%s|%s",
			envLLMProvider, ErrInvalidValue, c.LLMProvider,
			ProviderNone, ProviderGroq, ProviderOpenAI, ProviderGemini, ProviderOllama))
	}

	// Endpoint and model follow from the provider unless pinned explicitly, so
	// selecting Groq needs one variable rather than three that can disagree.
	if c.LLMBaseURL == "" {
		c.LLMBaseURL = defaultLLMBaseURL(c.LLMProvider)
	}
	if c.LLMModel == "" {
		c.LLMModel = defaultLLMModel(c.LLMProvider)
	}
	// Likewise the Razorpay client points at the local simulator by default, and
	// follows MESH_SIMULATOR_ADDR when that moves.
	if c.RazorpayBaseURL == "" {
		c.RazorpayBaseURL = httpBaseFromAddr(c.SimulatorAddr)
	}
	if c.CostModelPath == "" {
		c.CostModelPath = Default().CostModelPath
	}
	if c.CassetteDir == "" {
		c.CassetteDir = Default().CassetteDir
	}
	if c.CostModel == (domain.CostModel{}) {
		c.CostModel = domain.DefaultCostModel()
	}

	checkHostPort(&errs, envHTTPAddr, c.HTTPAddr)
	checkHostPort(&errs, envRedisAddr, c.RedisAddr)
	checkHostPort(&errs, envSimulatorAddr, c.SimulatorAddr)
	checkHTTPURL(&errs, envRazorpayBaseURL, c.RazorpayBaseURL)
	if c.LLMProvider != ProviderNone {
		checkHTTPURL(&errs, envLLMBaseURL, c.LLMBaseURL)
	}

	checkDuration(&errs, envWebhookMaxSkew, c.WebhookMaxSkew, time.Second, time.Hour)
	checkDuration(&errs, envLLMTimeout, c.LLMTimeout, 100*time.Millisecond, 2*time.Minute)
	checkDuration(&errs, envBreakerCooldown, c.BreakerCooldown, time.Second, time.Hour)
	checkDuration(&errs, envTelemetryWindow, c.TelemetryWindow, time.Second, 24*time.Hour)
	checkDuration(&errs, envSessionTTL, c.SessionTTL, time.Second, 24*time.Hour)

	checkInt(&errs, envMaxAttempts, c.MaxAttempts, 1, 10)
	checkInt(&errs, envBreakerMinSamples, c.BreakerMinSamples, 1, 100000)
	checkInt(&errs, envWorkerConcurrency, c.WorkerConcurrency, 1, 256)
	checkInt(&errs, envMaxSessions, c.MaxSessions, 1, 1000000)
	checkFloat(&errs, envBreakerTripRate, c.BreakerTripRate, 0, 1)

	checkPaisa(&errs, "gateway_fee_per_attempt_paisa", c.CostModel.GatewayFeePerAttemptPaisa)
	checkPaisa(&errs, "comms_cost_per_message_paisa", c.CostModel.CommsCostPerMessagePaisa)
	checkPaisa(&errs, "compliance_penalty_paisa", c.CostModel.CompliancePenaltyPaisa)
	checkPaisa(&errs, "session_friction_paisa", c.CostModel.SessionFrictionPaisa)

	switch c.InfraMode {
	case InfraExternal:
		// External mode is a real deployment. Every credential the system needs
		// to authenticate a caller or a peer must be supplied; inventing one
		// here would silently produce a stack whose webhook edge accepts nothing
		// and whose ops console accepts everyone.
		if c.WebhookSecret == "" {
			errs = append(errs, fmt.Errorf("%s: %w in %s mode (HMAC verification cannot fail closed without it)",
				envWebhookSecret, ErrMissingRequired, InfraExternal))
		}
		if c.PGDSN == "" {
			errs = append(errs, fmt.Errorf("%s: %w in %s mode (no embedded PostgreSQL is started)",
				envPGDSN, ErrMissingRequired, InfraExternal))
		}
		if c.OpsToken == "" {
			errs = append(errs, fmt.Errorf("%s: %w in %s mode (the ops console would otherwise be unauthenticated)",
				envOpsToken, ErrMissingRequired, InfraExternal))
		}
	case InfraManaged:
		// Managed mode is an ephemeral single-process stack, so it may mint its
		// own credentials. It always mints them rather than leaving a field
		// empty: an empty secret is an authentication bypass waiting for a
		// comparison that treats "" as a match.
		if err := generateIfUnset(&c.WebhookSecret, 32, ""); err != nil {
			errs = append(errs, err)
		}
		if err := generateIfUnset(&c.OpsToken, 32, ""); err != nil {
			errs = append(errs, err)
		}
		if err := generateIfUnset(&c.RazorpayKeyID, 12, "rzp_test_"); err != nil {
			errs = append(errs, err)
		}
		if err := generateIfUnset(&c.RazorpayKeySecret, 24, ""); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Managed reports whether this process owns the lifecycle of its backing
// services.
func (c Config) Managed() bool { return c.InfraMode == InfraManaged }

// LiveInferenceEnabled reports whether tier 1 of the inference stack has enough
// configuration to be worth attempting. The agent consults this instead of
// probing the endpoint, so a keyless deployment costs zero network round trips
// per incident rather than one timeout each.
func (c Config) LiveInferenceEnabled() bool {
	if c.LLMProvider == "" || c.LLMProvider == ProviderNone {
		return false
	}
	if c.LLMBaseURL == "" || c.LLMModel == "" {
		return false
	}
	// A local Ollama daemon has no bearer token; every hosted provider does.
	return c.LLMProvider == ProviderOllama || c.LLMAPIKey != ""
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const redacted = "***REDACTED***"

// SecretFingerprint returns the first 8 hex characters of the SHA-256 of s.
//
// It exists so operators can confirm that the simulator, the ingest edge, and
// the console all hold the *same* secret without any of them printing it. Eight
// hex characters is 32 bits: enough to distinguish the handful of secrets alive
// in one deployment, far too little to narrow a preimage search on a
// high-entropy value. It is a correlation aid, never proof of knowledge, and
// must never be accepted as an authentication credential.
func SecretFingerprint(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])[:8]
}

// redactSecret renders a secret as a presence flag plus a fingerprint. The
// distinction between unset and set is the operationally useful part; the value
// never is.
func redactSecret(secret string) string {
	if secret == "" {
		return "unset"
	}
	return "set(fp=" + SecretFingerprint(secret) + ")"
}

// RedactDSN removes credential material from a PostgreSQL connection string
// while preserving the host, database, and options an operator needs to
// diagnose a connection failure.
//
// Both libpq forms are handled — the URL form and the keyword/value form —
// because pgx accepts either and an operator will eventually paste the one this
// code does not expect. The rewrite is exact string surgery rather than a
// parse-and-reserialise round trip: re-encoding a DSN can move or escape bytes,
// and a redactor that alters what it does not understand is a redactor that
// eventually emits the thing it was meant to hide.
func RedactDSN(dsn string) string {
	if strings.TrimSpace(dsn) == "" {
		return ""
	}
	if isURLShaped(dsn) {
		return rewriteAuthority(dsn, redactPasswordOnly)
	}
	return redactDSNKeywords(dsn)
}

// RedactURL strips the whole userinfo section and any secret-named query
// parameter. Unlike RedactDSN it does not preserve the username, because in an
// API endpoint the username slot is a common place to carry the API key itself.
func RedactURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if !isURLShaped(raw) {
		// Still worth a query sweep: a scheme-less base URL is a misconfiguration,
		// not a reason to print its parameters.
		return redactQuery(raw)
	}
	return rewriteAuthority(raw, func(string) string { return redacted })
}

// isURLShaped reports whether s begins with a scheme:// prefix, which is what
// separates the libpq URL form from its keyword/value form. The check is
// anchored at the start deliberately: "host=db password=pg://x" contains "://"
// but is a keyword/value string, and routing it to the URL redactor would leave
// its password untouched.
func isURLShaped(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	// RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	if c := s[0]; !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
		return false
	}
	for j := 1; j < i; j++ {
		switch c := s[j]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func redactPasswordOnly(userinfo string) string {
	if c := strings.Index(userinfo, ":"); c >= 0 {
		return userinfo[:c+1] + redacted
	}
	return userinfo
}

// rewriteAuthority applies fn to the userinfo of a URL-shaped string and redacts
// secret-named query parameters, leaving every other byte untouched.
func rewriteAuthority(raw string, fn func(userinfo string) string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	head, rest := raw[:i+3], raw[i+3:]

	// The userinfo is taken to end at the LAST '@' in the remainder, not at the
	// first, and not at the authority boundary a strict RFC 3986 parse would
	// compute. Passwords in the wild carry unencoded '/', '?' and '@' — base64
	// secrets routinely contain '/' — and any rule that stops early leaves the
	// tail of such a password in the output. Stopping late can only over-capture,
	// which costs legibility on a pathological DSN; stopping early costs the
	// secret. This function only ever runs to produce log output, so legibility
	// is the cheaper thing to spend.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = fn(rest[:at]) + rest[at:]
	}
	return head + redactQuery(rest)
}

func redactQuery(tail string) string {
	q := strings.Index(tail, "?")
	if q < 0 {
		return tail
	}
	head, query := tail[:q+1], tail[q+1:]
	frag := ""
	if f := strings.Index(query, "#"); f >= 0 {
		query, frag = query[:f], query[f:]
	}
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		if isSecretKey(p[:eq]) {
			parts[i] = p[:eq+1] + redacted
		}
	}
	return head + strings.Join(parts, "&") + frag
}

// redactDSNKeywords walks the libpq keyword/value form, honouring single-quoted
// values with backslash escapes so that a quoted password containing a space is
// replaced whole rather than half.
func redactDSNKeywords(dsn string) string {
	var b strings.Builder
	b.Grow(len(dsn))
	for i, n := 0, len(dsn); i < n; {
		start := i
		for i < n && isSpaceByte(dsn[i]) {
			i++
		}
		b.WriteString(dsn[start:i])
		if i >= n {
			break
		}
		ks := i
		for i < n && dsn[i] != '=' && !isSpaceByte(dsn[i]) {
			i++
		}
		key := dsn[ks:i]
		b.WriteString(key)
		if i >= n || dsn[i] != '=' {
			continue // Bare token, not a key=value pair; it carries no value.
		}
		b.WriteByte('=')
		i++
		vs := i
		if i < n && dsn[i] == '\'' {
			i++
			for i < n {
				if dsn[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if dsn[i] == '\'' {
					i++
					break
				}
				i++
			}
		} else {
			for i < n && !isSpaceByte(dsn[i]) {
				i++
			}
		}
		if isSecretKey(key) {
			b.WriteString(redacted)
		} else {
			b.WriteString(dsn[vs:i])
		}
	}
	return b.String()
}

// secretKeyParts is the same denylist obs uses for log attributes. It is matched
// as a substring so that sslpassword, sslkey, and passfile are all caught
// without enumerating every libpq option Postgres may add later.
var secretKeyParts = []string{
	"secret", "token", "key", "password", "passwd", "pwd",
	"passfile", "credential", "auth", "signature",
}

func isSecretKey(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	for _, part := range secretKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// logAttrs is the single definition of what a Config looks like from outside.
// String and LogValue both render it, so redaction cannot be correct in one and
// wrong in the other.
func (c Config) logAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("infra_mode", c.InfraMode),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("ops_token", redactSecret(c.OpsToken)),
		slog.String("pg_dsn", RedactDSN(c.PGDSN)),
		slog.String("redis_addr", c.RedisAddr),
		slog.String("webhook_secret", redactSecret(c.WebhookSecret)),
		slog.Duration("webhook_max_skew", c.WebhookMaxSkew),
		slog.String("llm_provider", c.LLMProvider),
		slog.String("llm_base_url", RedactURL(c.LLMBaseURL)),
		slog.String("llm_api_key", redactSecret(c.LLMAPIKey)),
		slog.String("llm_model", c.LLMModel),
		slog.Duration("llm_timeout", c.LLMTimeout),
		slog.String("cassette_dir", c.CassetteDir),
		slog.Int("max_attempts", c.MaxAttempts),
		slog.Float64("breaker_trip_rate", c.BreakerTripRate),
		slog.Int("breaker_min_samples", c.BreakerMinSamples),
		slog.Duration("breaker_cooldown", c.BreakerCooldown),
		slog.Duration("telemetry_window", c.TelemetryWindow),
		slog.Int("worker_concurrency", c.WorkerConcurrency),
		slog.Int("max_sessions", c.MaxSessions),
		slog.Duration("session_ttl", c.SessionTTL),
		slog.String("log_level", c.LogLevel),
		slog.String("cost_model_path", c.CostModelPath),
		{Key: "cost_model", Value: slog.GroupValue(
			slog.Int64("gateway_fee_per_attempt_paisa", c.CostModel.GatewayFeePerAttemptPaisa),
			slog.Int64("comms_cost_per_message_paisa", c.CostModel.CommsCostPerMessagePaisa),
			slog.Int64("compliance_penalty_paisa", c.CostModel.CompliancePenaltyPaisa),
			slog.Int64("session_friction_paisa", c.CostModel.SessionFrictionPaisa),
		)},
		slog.String("simulator_addr", c.SimulatorAddr),
		slog.String("razorpay_base_url", RedactURL(c.RazorpayBaseURL)),
		slog.String("razorpay_key_id", redactSecret(c.RazorpayKeyID)),
		slog.String("razorpay_key_secret", redactSecret(c.RazorpayKeySecret)),
		slog.Bool("demo_mode", c.DemoMode),
		slog.Int64("seed", c.Seed),
	}
}

// LogValue makes Config safe to hand to slog directly. Without it, a single
// slog.Any("config", cfg) anywhere in the tree would print every credential the
// process holds.
func (c Config) LogValue() slog.Value { return slog.GroupValue(c.logAttrs()...) }

// String is the fmt counterpart of LogValue, for the same reason: %v on a Config
// must not be a credential disclosure.
func (c Config) String() string {
	attrs := c.logAttrs()
	var b strings.Builder
	b.WriteString("config.Config{")
	for i, a := range attrs {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
	}
	b.WriteString("}")
	return b.String()
}

// ---------------------------------------------------------------------------
// Shared cost model
// ---------------------------------------------------------------------------

// costModelFile mirrors domain.CostModel with pointers so a truncated or
// partially-written file is a hard error instead of a silent zero. A zeroed
// gateway fee would make infinite retrying look free to the policy engine.
type costModelFile struct {
	GatewayFee   *int64 `json:"gateway_fee_per_attempt_paisa"`
	CommsCost    *int64 `json:"comms_cost_per_message_paisa"`
	Compliance   *int64 `json:"compliance_penalty_paisa"`
	SessionFrict *int64 `json:"session_friction_paisa"`
}

// LoadCostModel reads the cost table shared with the Python evaluation harness.
//
// An absent file yields domain.DefaultCostModel: the Go side must run standalone
// on a machine with no eval checkout. A file that exists but cannot be read as a
// complete, sane cost table is fatal, because the whole point of the shared file
// is that a reviewer can trust the benchmark's numbers and the running system's
// numbers to be the same — quietly substituting defaults would hide exactly the
// drift the file exists to prevent.
func LoadCostModel(path string) (domain.CostModel, error) {
	if strings.TrimSpace(path) == "" {
		return domain.DefaultCostModel(), nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.DefaultCostModel(), nil
		}
		return domain.CostModel{}, fmt.Errorf("%w: opening %s: %w", ErrCostModel, path, err)
	}
	defer func() { _ = f.Close() }()

	// Bounded read: this file is regenerated by the eval harness, and a loader
	// that will allocate whatever it is handed is a liability.
	data, err := io.ReadAll(io.LimitReader(f, maxCostModelBytes+1))
	if err != nil {
		return domain.CostModel{}, fmt.Errorf("%w: reading %s: %w", ErrCostModel, path, err)
	}
	if len(data) > maxCostModelBytes {
		return domain.CostModel{}, fmt.Errorf("%w: %s exceeds %d bytes", ErrCostModel, path, maxCostModelBytes)
	}

	var file costModelFile
	if err := json.Unmarshal(data, &file); err != nil {
		return domain.CostModel{}, fmt.Errorf("%w: parsing %s: %w", ErrCostModel, path, err)
	}
	missing := make([]string, 0, 4)
	if file.GatewayFee == nil {
		missing = append(missing, "gateway_fee_per_attempt_paisa")
	}
	if file.CommsCost == nil {
		missing = append(missing, "comms_cost_per_message_paisa")
	}
	if file.Compliance == nil {
		missing = append(missing, "compliance_penalty_paisa")
	}
	if file.SessionFrict == nil {
		missing = append(missing, "session_friction_paisa")
	}
	if len(missing) > 0 {
		return domain.CostModel{}, fmt.Errorf("%w: %s is missing %s", ErrCostModel, path, strings.Join(missing, ", "))
	}

	cm := domain.CostModel{
		GatewayFeePerAttemptPaisa: *file.GatewayFee,
		CommsCostPerMessagePaisa:  *file.CommsCost,
		CompliancePenaltyPaisa:    *file.Compliance,
		SessionFrictionPaisa:      *file.SessionFrict,
	}
	var errs []error
	checkPaisa(&errs, "gateway_fee_per_attempt_paisa", cm.GatewayFeePerAttemptPaisa)
	checkPaisa(&errs, "comms_cost_per_message_paisa", cm.CommsCostPerMessagePaisa)
	checkPaisa(&errs, "compliance_penalty_paisa", cm.CompliancePenaltyPaisa)
	checkPaisa(&errs, "session_friction_paisa", cm.SessionFrictionPaisa)
	if len(errs) > 0 {
		return domain.CostModel{}, fmt.Errorf("%w: %s: %w", ErrCostModel, path, errors.Join(errs...))
	}
	return cm, nil
}

// ---------------------------------------------------------------------------
// Typed environment parsers
// ---------------------------------------------------------------------------

type loader struct {
	lookup Lookup
	errs   []error
}

func (l *loader) fail(key string, err error) {
	l.errs = append(l.errs, fmt.Errorf("%s: %w", key, err))
}

// raw fetches, trims, length-bounds, and control-character-screens a value.
//
// Trimming matters in practice: a secret sourced from `$(cat file)` carries a
// trailing newline that would silently break every HMAC comparison. The control
// screen matters because several of these values end up in HTTP headers and
// connection strings, where a stray CR is an injection primitive.
//
// It never echoes the value into an error, because the same helper reads
// MESH_WEBHOOK_SECRET and MESH_LLM_API_KEY.
func (l *loader) raw(key string, max int) (string, bool) {
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if len(v) > max {
		l.fail(key, fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrInvalidValue, len(v), max))
		return "", false
	}
	if i := strings.IndexFunc(v, isControlRune); i >= 0 {
		l.fail(key, fmt.Errorf("%w: control character at byte offset %d", ErrInvalidValue, i))
		return "", false
	}
	return v, true
}

func (l *loader) text(key, def string, max int) string {
	if v, ok := l.raw(key, max); ok {
		return v
	}
	return def
}

func (l *loader) integer(key string, def int) int {
	v := l.integer64(key, int64(def))
	if v > math.MaxInt32 || v < math.MinInt32 {
		l.fail(key, fmt.Errorf("%w: %d does not fit a 32-bit count", ErrOutOfRange, v))
		return def
	}
	return int(v)
}

func (l *loader) integer64(key string, def int64) int64 {
	v, ok := l.raw(key, maxNumberLen)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		l.fail(key, fmt.Errorf("%w: %q is not an integer", ErrInvalidValue, v))
		return def
	}
	return n
}

func (l *loader) float(key string, def float64) float64 {
	v, ok := l.raw(key, maxNumberLen)
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		l.fail(key, fmt.Errorf("%w: %q is not a number", ErrInvalidValue, v))
		return def
	}
	// NaN defeats every comparison downstream: a NaN trip rate would make the
	// breaker never trip, silently, which is the worst available failure mode.
	if math.IsNaN(f) || math.IsInf(f, 0) {
		l.fail(key, fmt.Errorf("%w: %q is not finite", ErrInvalidValue, v))
		return def
	}
	return f
}

func (l *loader) duration(key string, def time.Duration) time.Duration {
	v, ok := l.raw(key, maxNumberLen)
	if !ok {
		return def
	}
	// A bare integer means seconds. Operators write MESH_WEBHOOK_MAX_SKEW=300 far
	// more often than 300s, and reading that as 300 nanoseconds would collapse
	// the replay window with no visible error.
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n > math.MaxInt64/int64(time.Second) || n < math.MinInt64/int64(time.Second) {
			l.fail(key, fmt.Errorf("%w: %d seconds overflows a duration", ErrOutOfRange, n))
			return def
		}
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.fail(key, fmt.Errorf("%w: %q is not a duration (use 30s, 5m, 1h, or a bare count of seconds)",
			ErrInvalidValue, v))
		return def
	}
	return d
}

func (l *loader) boolean(key string, def bool) bool {
	v, ok := l.raw(key, maxNumberLen)
	if !ok {
		return def
	}
	switch strings.ToLower(v) {
	case "yes", "y", "on":
		return true
	case "no", "n", "off":
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail(key, fmt.Errorf("%w: %q is not a boolean (use true/false, 1/0, yes/no, on/off)",
			ErrInvalidValue, v))
		return def
	}
	return b
}

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f }

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// ---------------------------------------------------------------------------
// Semantic checks
// ---------------------------------------------------------------------------

func checkInt(errs *[]error, name string, v, lo, hi int) {
	if v < lo || v > hi {
		*errs = append(*errs, fmt.Errorf("%s: %w: %d is outside [%d, %d]", name, ErrOutOfRange, v, lo, hi))
	}
}

func checkFloat(errs *[]error, name string, v, lo, hi float64) {
	if math.IsNaN(v) || v < lo || v > hi {
		*errs = append(*errs, fmt.Errorf("%s: %w: %v is outside [%v, %v]", name, ErrOutOfRange, v, lo, hi))
	}
}

func checkDuration(errs *[]error, name string, v, lo, hi time.Duration) {
	if v < lo || v > hi {
		*errs = append(*errs, fmt.Errorf("%s: %w: %s is outside [%s, %s]", name, ErrOutOfRange, v, lo, hi))
	}
}

func checkPaisa(errs *[]error, field string, v int64) {
	if v < 0 || v > maxSanePaisa {
		*errs = append(*errs, fmt.Errorf("%s: %w: %d paisa is outside [0, %d]", field, ErrOutOfRange, v, maxSanePaisa))
	}
}

func checkHostPort(errs *[]error, name, addr string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w: %q is not host:port", name, ErrInvalidValue, addr))
		return
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		*errs = append(*errs, fmt.Errorf("%s: %w: %q is not a port in [1, 65535]", name, ErrInvalidValue, port))
		return
	}
	// An empty host is the idiomatic listen-on-all form (":8080") and is allowed;
	// anything else must be a literal IP or a hostname, never a URL fragment.
	if strings.ContainsAny(host, "/\\?#@") {
		*errs = append(*errs, fmt.Errorf("%s: %w: %q is not a host", name, ErrInvalidValue, host))
	}
}

func checkHTTPURL(errs *[]error, name, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		// The parse error quotes the URL, which may carry userinfo, so it is
		// deliberately not included.
		*errs = append(*errs, fmt.Errorf("%s: %w: not a URL", name, ErrInvalidValue))
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		*errs = append(*errs, fmt.Errorf("%s: %w: scheme %q is not http or https", name, ErrInvalidValue, u.Scheme))
		return
	}
	if u.Host == "" {
		*errs = append(*errs, fmt.Errorf("%s: %w: no host", name, ErrInvalidValue))
	}
}

// ---------------------------------------------------------------------------
// Managed-mode credential generation
// ---------------------------------------------------------------------------

// generateIfUnset fills an empty credential with n bytes of CSPRNG output, hex
// encoded. Hex rather than base64 so the value is safe in a URL, a header, a
// shell variable, and a DSN without raising an escaping question anywhere.
func generateIfUnset(dst *string, n int, prefix string) error {
	if *dst != "" {
		return nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("config: generating a %d byte managed-mode credential: %w", n, err)
	}
	*dst = prefix + hex.EncodeToString(b)
	return nil
}

// ---------------------------------------------------------------------------
// Provider-derived defaults
// ---------------------------------------------------------------------------

func defaultLLMBaseURL(provider string) string {
	switch provider {
	case ProviderGroq:
		return "https://api.groq.com/openai/v1"
	case ProviderOpenAI:
		return "https://api.openai.com/v1"
	case ProviderGemini:
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	case ProviderOllama:
		return "http://127.0.0.1:11434/v1"
	default:
		return ""
	}
}

func defaultLLMModel(provider string) string {
	switch provider {
	case ProviderGroq:
		return "llama-3.3-70b-versatile"
	case ProviderOpenAI:
		return "gpt-4o-mini"
	case ProviderGemini:
		return "gemini-2.0-flash"
	case ProviderOllama:
		return "llama3.1"
	default:
		return ""
	}
}

// httpBaseFromAddr turns a listen address into a URL a client can dial. A
// wildcard listen host is rewritten to loopback because "http://:8081" is a
// listen spec, not a destination.
func httpBaseFromAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/v1"
}

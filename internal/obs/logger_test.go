package obs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hriday/razorpay-resilient-mesh/internal/testsecret"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
	"unicode/utf8"
)

func newTestLogger(buf *bytes.Buffer, level string) *slog.Logger {
	return NewLogger(level, buf)
}

// decodeOne parses the single record written to buf.
func decodeOne(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 1 || len(lines[0]) == 0 {
		t.Fatalf("expected exactly one log line, got %d: %q", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal(lines[0], &m); err != nil {
		t.Fatalf("log line is not valid JSON: %v (%q)", err, buf.String())
	}
	return m
}

// group descends into nested JSON objects produced by slog groups.
func group(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	g, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("key %q is not a JSON object in %v", key, m)
	}
	return g
}

// TestHandlerSatisfiesSlogContract is the guard against the subtle WithAttrs /
// WithGroup mistakes a hand-written wrapper invites: dropped pre-bound attrs,
// unresolved LogValuers, groups that fail to nest or fail to elide when empty.
func TestHandlerSatisfiesSlogContract(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactingHandler(slog.NewJSONHandler(&buf, nil))

	results := func() []map[string]any {
		var out []map[string]any
		for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("invalid JSON record %q: %v", line, err)
			}
			out = append(out, m)
		}
		return out
	}
	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("handler violates the slog.Handler contract: %v", err)
	}
}

func TestRedactsTopLevelSensitiveKeys(t *testing.T) {
	secret := testsecret.LiveKeyID("supersecretvalue")
	keys := []string{
		"secret", "webhook_secret", "token", "session_token", "api_key",
		"password", "passwd", "signature", "X-Razorpay-Signature",
		"Authorization", "auth", "vpa", "card_number", "customer_contact",
		"email", "phone", "pg_dsn", "SECRET", "AuthOrIzAtIoN",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			var buf bytes.Buffer
			newTestLogger(&buf, "info").Info("webhook", slog.String(key, secret))
			m := decodeOne(t, &buf)
			if got := m[key]; got != RedactedPlaceholder {
				t.Fatalf("key %q: got %v, want %q", key, got, RedactedPlaceholder)
			}
			if strings.Contains(buf.String(), secret) {
				t.Fatalf("secret leaked into log output: %s", buf.String())
			}
		})
	}
}

func TestNonSensitiveKeysSurvive(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("gate",
		slog.String("payment_id", "pay_29QQoUBi66xm2f"),
		slog.String("issuer_key", "netbanking:HDFC"),
		slog.String("telemetry_key", "upi:okhdfcbank"),
		slog.String("cycle_key", "2026-09"),
		slog.String("error_code", "bank_technical_error"),
		slog.Int64("amount_paisa", 129900),
		slog.Bool("recurring", true),
	)
	m := decodeOne(t, &buf)
	want := map[string]any{
		"payment_id":    "pay_29QQoUBi66xm2f",
		"issuer_key":    "netbanking:HDFC",
		"telemetry_key": "upi:okhdfcbank",
		"cycle_key":     "2026-09",
		"error_code":    "bank_technical_error",
		"amount_paisa":  float64(129900),
		"recurring":     true,
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("key %q: got %v (%T), want %v", k, m[k], m[k], v)
		}
	}
}

func TestRedactsAttrsBoundWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf, "info").With(
		slog.String("api_key", "sk_live_dead"),
		slog.String("component", "ingest"),
	)
	log.Info("bound")

	m := decodeOne(t, &buf)
	if m["api_key"] != RedactedPlaceholder {
		t.Fatalf("WithAttrs value not redacted: %v", m["api_key"])
	}
	if m["component"] != "ingest" {
		t.Fatalf("WithAttrs non-sensitive value mangled: %v", m["component"])
	}
	if strings.Contains(buf.String(), "sk_live_dead") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
}

func TestRedactsInsideGroups(t *testing.T) {
	t.Run("inline group", func(t *testing.T) {
		var buf bytes.Buffer
		newTestLogger(&buf, "info").Info("morph",
			slog.Group("request",
				slog.String("path", "/api/v1/webhooks/razorpay"),
				slog.String("authorization", "Bearer abcd"),
			),
		)
		g := group(t, decodeOne(t, &buf), "request")
		if g["path"] != "/api/v1/webhooks/razorpay" {
			t.Errorf("group key lost: %v", g["path"])
		}
		if g["authorization"] != RedactedPlaceholder {
			t.Errorf("grouped secret not redacted: %v", g["authorization"])
		}
	})

	t.Run("WithGroup prefixes and redacts", func(t *testing.T) {
		var buf bytes.Buffer
		newTestLogger(&buf, "info").WithGroup("http").
			With(slog.String("x_api_token", "t0ken")).
			Info("served", slog.Int("status", 200))

		m := decodeOne(t, &buf)
		g := group(t, m, "http")
		if g["x_api_token"] != RedactedPlaceholder {
			t.Errorf("WithAttrs under WithGroup not redacted: %v", g["x_api_token"])
		}
		if g["status"] != float64(200) {
			t.Errorf("record attr not nested under group: %v", m)
		}
		if _, unnested := m["status"]; unnested {
			t.Errorf("group failed to prefix record attrs: %v", m)
		}
	})

	t.Run("sensitive group seals its children", func(t *testing.T) {
		var buf bytes.Buffer
		newTestLogger(&buf, "info").WithGroup("card").
			Info("instrument", slog.String("last4", "4242"), slog.Int("expiry_year", 2031))

		g := group(t, decodeOne(t, &buf), "card")
		if g["last4"] != RedactedPlaceholder || g["expiry_year"] != RedactedPlaceholder {
			t.Fatalf("sensitive group did not seal children: %v", g)
		}
	})

	t.Run("nested groups inherit the seal", func(t *testing.T) {
		var buf bytes.Buffer
		newTestLogger(&buf, "info").Info("nested",
			slog.Group("payment",
				slog.String("id", "pay_1"),
				slog.Group("card",
					slog.String("network", "visa"),
					slog.Group("holder", slog.String("name", "A Person")),
				),
			),
		)
		p := group(t, decodeOne(t, &buf), "payment")
		if p["id"] != "pay_1" {
			t.Errorf("outer group value lost: %v", p["id"])
		}
		c := group(t, p, "card")
		if c["network"] != RedactedPlaceholder {
			t.Errorf("nested sensitive group not redacted: %v", c["network"])
		}
		h := group(t, c, "holder")
		if h["name"] != RedactedPlaceholder {
			t.Errorf("seal did not reach grandchild: %v", h["name"])
		}
	})
}

func TestTruncatesOnRuneBoundary(t *testing.T) {
	// A 3-byte rune guarantees the 512-byte cut lands mid-rune (512 = 3*170+2).
	const rune3 = "世" // U+4E16, 3 bytes
	long := strings.Repeat(rune3, 200)

	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("issuer", slog.String("error_reason", long))

	got, ok := decodeOne(t, &buf)["error_reason"].(string)
	if !ok {
		t.Fatalf("error_reason missing from %q", buf.String())
	}
	want := strings.Repeat(rune3, 170) + truncationSuffix
	if got != want {
		t.Fatalf("truncation mismatch:\n got %q (%d bytes)\nwant %q (%d bytes)",
			got, len(got), want, len(want))
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncated value is not valid UTF-8")
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatal("truncation split a rune")
	}
	if !json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatal("truncated record is not valid JSON")
	}
}

func TestTruncatesMessage(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info(strings.Repeat("a", MaxValueBytes+50))
	msg, _ := decodeOne(t, &buf)["msg"].(string)
	if len(msg) != MaxValueBytes+len(truncationSuffix) {
		t.Fatalf("message not truncated: %d bytes", len(msg))
	}
}

func TestTruncateForLogBoundaries(t *testing.T) {
	exact := strings.Repeat("x", MaxValueBytes)
	if got := TruncateForLog(exact); got != exact {
		t.Errorf("value of exactly MaxValueBytes was altered")
	}
	if got := TruncateForLog(exact + "y"); got != exact+truncationSuffix {
		t.Errorf("one byte over the limit truncated wrongly: %q", got)
	}
	if got := TruncateForLog(""); got != "" {
		t.Errorf("empty string altered: %q", got)
	}
}

func TestRedactsNonStringSensitiveValues(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("mixed",
		slog.Int64("card_number", 4111111111111111),
		slog.Bool("has_token", true),
		slog.Float64("phone", 919000000000),
	)
	m := decodeOne(t, &buf)
	for _, k := range []string{"card_number", "has_token", "phone"} {
		if m[k] != RedactedPlaceholder {
			t.Errorf("non-string sensitive value %q not redacted: %v", k, m[k])
		}
	}
	if strings.Contains(buf.String(), "4111111111111111") {
		t.Fatalf("card number leaked: %s", buf.String())
	}
}

type sessionValuer struct{ token string }

func (s sessionValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session_token", s.token),
		slog.String("session_id", "sess_42"),
	)
}

func TestResolvesLogValuerBeforeRedacting(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("session", slog.Any("session", sessionValuer{token: "tok_live_zzz"}))

	g := group(t, decodeOne(t, &buf), "session")
	if g["session_token"] != RedactedPlaceholder {
		t.Errorf("LogValuer secret not redacted: %v", g["session_token"])
	}
	if g["session_id"] != "sess_42" {
		t.Errorf("LogValuer non-secret lost: %v", g["session_id"])
	}
	if strings.Contains(buf.String(), "tok_live_zzz") {
		t.Fatalf("LogValuer secret leaked: %s", buf.String())
	}
}

func TestRawBytesAreNeverRendered(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"payload":{"payment":{"entity":{"vpa":"person@okhdfcbank"}}}}`)
	newTestLogger(&buf, "info").Info("webhook", slog.Any("body", body))

	if got, want := decodeOne(t, &buf)["body"], fmt.Sprintf("[%d bytes]", len(body)); got != want {
		t.Fatalf("raw body not summarised: got %v, want %q", got, want)
	}
	if strings.Contains(buf.String(), "okhdfcbank") {
		t.Fatalf("raw body content leaked: %s", buf.String())
	}
}

type boomStringer struct{}

func (boomStringer) String() string { panic("boom") }

func TestPanickingStringerDoesNotTakeDownTheLogger(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("hostile", slog.Any("thing", boomStringer{}))
	if got := decodeOne(t, &buf)["thing"]; got != unprintablePlaceholder {
		t.Fatalf("got %v, want %q", got, unprintablePlaceholder)
	}
}

func TestErrorValuesAreTruncatedNotDropped(t *testing.T) {
	var buf bytes.Buffer
	err := errors.New(strings.Repeat("e", MaxValueBytes+10))
	newTestLogger(&buf, "info").Error("publish failed", slog.Any("error", err))

	got, _ := decodeOne(t, &buf)["error"].(string)
	if !strings.HasSuffix(got, truncationSuffix) || len(got) != MaxValueBytes+len(truncationSuffix) {
		t.Fatalf("error text not bounded: %d bytes", len(got))
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf, "warn")
	log.Debug("debug")
	log.Info("info")
	if buf.Len() != 0 {
		t.Fatalf("records below the configured level were emitted: %s", buf.String())
	}
	log.Warn("warn")
	if m := decodeOne(t, &buf); m["msg"] != "warn" {
		t.Fatalf("warn record missing: %v", m)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"DEBUG":    slog.LevelDebug,
		" info":    slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"WARNING":  slog.LevelWarn,
		"error":    slog.LevelError,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"secret", "TOKEN", "api-key", "user_password", "passwd",
		"x_signature", "authorization", "auth", "vpa", "card", "contact_number",
		"email_id", "phone", "dsn", "pg_dsn"}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	safe := []string{"", "payment_id", "order_id", "issuer_key", "telemetry_key",
		"cycle_key", "attempt_number", "rail", "state", "latency_ms"}
	for _, k := range safe {
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", k)
		}
	}
}

func TestNilInnerHandlerDoesNotPanic(t *testing.T) {
	log := slog.New(NewRedactingHandler(nil))
	log.Info("discarded", slog.String("token", "x"))
}

type cyclicValuer struct{}

// LogValue resolves to a group containing itself, the shape that turns naive
// attribute recursion into a stack overflow.
func (c cyclicValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("next", cyclicValuer{}))
}

func TestCyclicLogValuerIsBounded(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, "info").Info("cycle", slog.Any("root", cyclicValuer{}))

	line := bytes.TrimSpace(buf.Bytes())
	if !json.Valid(line) {
		t.Fatalf("record is not valid JSON: %s", line)
	}
	if !bytes.Contains(line, []byte(deepPlaceholder)) {
		t.Fatalf("recursion guard never fired: %s", line)
	}
}

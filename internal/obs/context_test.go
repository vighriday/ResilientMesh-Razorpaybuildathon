package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRequestAndIncidentIDRoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "01J8ZQ2R3M4N5P6Q7R8S9T0V")
	ctx = WithIncidentID(ctx, "inc_7f3a91")

	if got := RequestID(ctx); got != "01J8ZQ2R3M4N5P6Q7R8S9T0V" {
		t.Errorf("RequestID = %q", got)
	}
	if got := IncidentID(ctx); got != "inc_7f3a91" {
		t.Errorf("IncidentID = %q", got)
	}
}

func TestMissingIDsReadEmpty(t *testing.T) {
	if got := RequestID(context.Background()); got != "" {
		t.Errorf("RequestID on a bare context = %q, want empty", got)
	}
	if got := IncidentID(context.Background()); got != "" {
		t.Errorf("IncidentID on a bare context = %q, want empty", got)
	}
	// A nil context is a caller bug, but reading an id must still not panic:
	// the logging path is not allowed to be the thing that crashes a worker.
	if got := RequestID(nil); got != "" { //nolint:staticcheck // SA1012 is the point of the test
		t.Errorf("RequestID(nil) = %q, want empty", got)
	}
}

// TestIDsAreSanitized covers the log-forging path: the request id arrives in an
// inbound header and is then written to every log line for that request.
func TestIDsAreSanitized(t *testing.T) {
	hostile := "req_1\n{\"level\":\"ERROR\",\"msg\":\"fake entry\"} \r\t<script>"
	ctx := WithRequestID(context.Background(), hostile)
	got := RequestID(ctx)
	if strings.ContainsAny(got, "\n\r\t <>\"{}") {
		t.Fatalf("sanitized id still carries structural characters: %q", got)
	}
	if !strings.HasPrefix(got, "req_1") {
		t.Fatalf("sanitizer destroyed the usable prefix: %q", got)
	}

	long := strings.Repeat("a", MaxIDLen*3)
	if got := RequestID(WithRequestID(context.Background(), long)); len(got) != MaxIDLen {
		t.Fatalf("over-long id not bounded: %d bytes", len(got))
	}
}

func TestUnusableIDIsNotStored(t *testing.T) {
	ctx := WithRequestID(context.Background(), "!!!***")
	if got := RequestID(ctx); got != "" {
		t.Fatalf("id with no usable characters was stored as %q", got)
	}
	ctx = WithIncidentID(context.Background(), "   ")
	if got := IncidentID(ctx); got != "" {
		t.Fatalf("blank incident id was stored as %q", got)
	}
}

func TestLoggerFromTagsPresentIDs(t *testing.T) {
	var buf bytes.Buffer
	base := NewLogger("info", &buf)

	ctx := WithIncidentID(WithRequestID(context.Background(), "req_abc"), "inc_123")
	LoggerFrom(ctx, base).Info("gate decision", slog.String("action", "ASYNC_EXPONENTIAL_RETRY"))

	m := decodeOne(t, &buf)
	if m["request_id"] != "req_abc" {
		t.Errorf("request_id = %v", m["request_id"])
	}
	if m["incident_id"] != "inc_123" {
		t.Errorf("incident_id = %v", m["incident_id"])
	}
	if m["action"] != "ASYNC_EXPONENTIAL_RETRY" {
		t.Errorf("call-site attrs lost: %v", m)
	}
}

func TestLoggerFromOmitsAbsentIDs(t *testing.T) {
	var buf bytes.Buffer
	base := NewLogger("info", &buf)

	ctx := WithRequestID(context.Background(), "req_only")
	LoggerFrom(ctx, base).Info("edge")

	m := decodeOne(t, &buf)
	if m["request_id"] != "req_only" {
		t.Errorf("request_id = %v", m["request_id"])
	}
	if _, present := m["incident_id"]; present {
		t.Errorf("absent incident_id was emitted: %v", m)
	}

	buf.Reset()
	if LoggerFrom(context.Background(), base) != base {
		t.Error("LoggerFrom cloned the logger despite having nothing to add")
	}
}

func TestLoggerFromRedactsAndSurvivesNilBase(t *testing.T) {
	// A nil base must not panic: worker goroutines build loggers per message.
	if LoggerFrom(context.Background(), nil) == nil {
		t.Fatal("LoggerFrom returned nil")
	}

	var buf bytes.Buffer
	ctx := WithRequestID(context.Background(), "req_xyz")
	LoggerFrom(ctx, NewLogger("info", &buf)).Info("webhook",
		slog.String("x_razorpay_signature", "9f8e7d"),
	)
	m := decodeOne(t, &buf)
	if m["x_razorpay_signature"] != RedactedPlaceholder {
		t.Fatalf("context logger bypassed redaction: %v", m)
	}
	if m["request_id"] != "req_xyz" {
		t.Fatalf("request_id lost: %v", m)
	}
	if !json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatal("record is not valid JSON")
	}
}

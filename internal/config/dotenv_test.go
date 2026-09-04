package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDotEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestDotEnvReadsPrefixedNamesOnly(t *testing.T) {
	path := writeDotEnv(t, strings.Join([]string{
		"# a comment",
		"",
		"MESH_LLM_PROVIDER=groq",
		"export MESH_LLM_MODEL=llama-3.3-70b-versatile",
		`MESH_OPS_TOKEN="quoted value"`,
		"MESH_SEED='42'",
		"PATH=/attacker/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"HOME=/tmp",
	}, "\n"))

	got, err := DotEnv(path)
	if err != nil {
		t.Fatalf("DotEnv: %v", err)
	}
	want := map[string]string{
		"MESH_LLM_PROVIDER": "groq",
		"MESH_LLM_MODEL":    "llama-3.3-70b-versatile",
		"MESH_OPS_TOKEN":    "quoted value",
		"MESH_SEED":         "42",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d variables, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// The point of the prefix rule: a dotenv file that lands in a checkout must
	// not be able to change which code this process runs.
	for _, hostile := range []string{"PATH", "LD_PRELOAD", "HOME"} {
		if _, ok := got[hostile]; ok {
			t.Errorf("%s was accepted from a dotenv file", hostile)
		}
	}
}

func TestDotEnvKeepsHashesInsideUnquotedSecrets(t *testing.T) {
	// '#' is legal in a secret. Treating it as a comment would truncate a key
	// and surface much later as an authentication failure.
	path := writeDotEnv(t, "MESH_WEBHOOK_SECRET=abc#def\n")
	got, err := DotEnv(path)
	if err != nil {
		t.Fatalf("DotEnv: %v", err)
	}
	if got["MESH_WEBHOOK_SECRET"] != "abc#def" {
		t.Errorf("secret = %q, want %q", got["MESH_WEBHOOK_SECRET"], "abc#def")
	}
}

func TestDotEnvRejectsControlCharacters(t *testing.T) {
	path := writeDotEnv(t, "MESH_OPS_TOKEN=\"tok\x1b[31men\"\n")
	if _, err := DotEnv(path); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("error = %v, want ErrInvalidValue", err)
	}
}

func TestDotEnvRejectsALineWithNoAssignment(t *testing.T) {
	path := writeDotEnv(t, "MESH_LLM_PROVIDER\n")
	if _, err := DotEnv(path); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("error = %v, want ErrInvalidValue", err)
	}
}

func TestDotEnvTreatsAMissingFileAsEmpty(t *testing.T) {
	got, err := DotEnv(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing dotenv file must not be an error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no variables", got)
	}
}

func TestDotEnvRejectsAnOversizeFile(t *testing.T) {
	path := writeDotEnv(t, "MESH_OPS_TOKEN="+strings.Repeat("a", maxDotEnvBytes+1)+"\n")
	if _, err := DotEnv(path); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("error = %v, want ErrInvalidValue", err)
	}
}

func TestTheEnvironmentWinsOverTheFile(t *testing.T) {
	env := func(k string) (string, bool) {
		if k == "MESH_LLM_MODEL" {
			return "from-environment", true
		}
		return "", false
	}
	lookup := withDotEnv(env, map[string]string{
		"MESH_LLM_MODEL":    "from-file",
		"MESH_LLM_PROVIDER": "groq",
	})

	if v, _ := lookup("MESH_LLM_MODEL"); v != "from-environment" {
		t.Errorf("model = %q, want the environment to win", v)
	}
	if v, ok := lookup("MESH_LLM_PROVIDER"); !ok || v != "groq" {
		t.Errorf("provider = %q, %v; want the file to fill a gap", v, ok)
	}
	if _, ok := lookup("MESH_SEED"); ok {
		t.Error("a name in neither source was reported as present")
	}
}

func TestWithDotEnvIsTransparentWhenTheFileIsEmpty(t *testing.T) {
	env := func(string) (string, bool) { return "", false }
	if got := withDotEnv(env, nil); got == nil {
		t.Fatal("withDotEnv returned nil for an empty file")
	}
	if _, ok := withDotEnv(env, map[string]string{})("MESH_SEED"); ok {
		t.Error("an empty file reported a variable as present")
	}
}

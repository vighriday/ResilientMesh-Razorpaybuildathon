package main

import (
	"strings"
	"testing"
)

// These tests plant real credential shapes on purpose. This file is listed in
// selfPaths so the scanner does not flag its own fixtures, which is why the
// exclusion exists at all.

func scan(t *testing.T, files map[string]string, deps ...string) []Finding {
	t.Helper()
	s := &Scanner{Files: map[string][]byte{}, DirectDeps: deps}
	for k, v := range files {
		s.Files[k] = []byte(v)
	}
	return s.Scan()
}

func checks(f []Finding) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.Check+"|"+x.File)
	}
	return out
}

func mustFind(t *testing.T, findings []Finding, check, file string) {
	t.Helper()
	for _, f := range findings {
		if f.Check == check && f.File == file {
			return
		}
	}
	t.Fatalf("expected a %q finding in %s; got %v", check, file, checks(findings))
}

func mustNotFind(t *testing.T, findings []Finding, check string) {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			t.Fatalf("unexpected %q finding: %s", check, f.String())
		}
	}
}

func TestPrivatePathsAreRejected(t *testing.T) {
	cases := []string{
		"_internal/PLAN.md",
		"_internal/strategy/brief.docx",
		"notes.docx",
		"secrets.private.md",
		".env",
		".env.production",
		"certs/server.pem",
		"keys/signing.key",
		"store.p12",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			f := scan(t, map[string]string{path: "content"})
			mustFind(t, f, "private-path", path)
		})
	}
}

func TestEnvExampleItselfIsAllowed(t *testing.T) {
	f := scan(t, map[string]string{".env.example": "# documented\nMESH_WEBHOOK_SECRET=\n"})
	mustNotFind(t, f, "private-path")
}

func TestCredentialShapesAreDetected(t *testing.T) {
	cases := map[string]string{
		"razorpay live": "key = rzp_live_AbCdEf123456789",
		"razorpay test": "key = rzp_test_AbCdEf123456789",
		"groq":          "GROQ=gsk_" + strings.Repeat("a", 48),
		"openai":        "OPENAI=sk-" + strings.Repeat("b", 40),
		"anthropic":     "ANTHROPIC=sk-ant-" + strings.Repeat("c", 30),
		"google":        "G=AIza" + strings.Repeat("d", 35),
		"aws":           "AWS=AKIAIOSFODNN7EXAMPLE",
		"github":        "GH=ghp_" + strings.Repeat("e", 36),
		"slack":         "SLACK=xoxb-1234567890-abcdefghij",
		"private key":   "-----BEGIN RSA PRIVATE KEY-----",
		"postgres dsn":  "postgres://mesh:hunter2@db:5432/mesh",
		"redis dsn":     "redis://user:hunter2@cache:6379",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			f := scan(t, map[string]string{"config.yml": content})
			mustFind(t, f, "credential", "config.yml")
		})
	}
}

// The compose file legitimately contains DSNs whose password is a variable
// reference. Flagging those would make the scanner useless in exactly the file
// most likely to hold a real leak.
func TestVariableInterpolationIsNotACredential(t *testing.T) {
	cases := []string{
		"MESH_PG_DSN: postgres://mesh:${POSTGRES_PASSWORD}@postgres:5432/mesh",
		"MESH_PG_DSN: postgres://mesh:${POSTGRES_PASSWORD:?set it}@postgres:5432/mesh",
		"DSN=postgres://mesh:$PGPASS@db:5432/mesh",
		"dsn: redis://default:{{ .RedisPassword }}@cache:6379",
		"DSN=postgres://mesh:%PGPASS%@db:5432/mesh",
	}
	for _, c := range cases {
		f := scan(t, map[string]string{"docker-compose.yml": c})
		mustNotFind(t, f, "credential")
	}
}

func TestScannerDoesNotFlagItsOwnPatterns(t *testing.T) {
	f := scan(t, map[string]string{
		"cmd/leakscan/scan.go": "rzp_live_AbCdEf123456789 and postgres://a:b@c/d",
		"scripts/leakscan.sh":  "rzp_live_AbCdEf123456789",
	})
	mustNotFind(t, f, "credential")
}

// Documentation must be able to say that private material exists without
// tripping the scan; a link that would actually resolve must not.
func TestPrivateReferencesDistinguishProseFromLinks(t *testing.T) {
	prose := map[string]string{
		"decisions.md": "Strategy notes live under `_internal/`, which is git-ignored.\n",
	}
	mustNotFind(t, scan(t, prose), "private-reference")

	fenced := map[string]string{
		"README.md": "```\n_internal/PLAN.md\n```\n",
	}
	mustNotFind(t, scan(t, fenced), "private-reference")

	link := map[string]string{
		"README.md": "See [the plan](_internal/PLAN.md) for details.\n",
	}
	mustFind(t, scan(t, link), "private-reference", "README.md")

	code := map[string]string{
		"main.go": `data, _ := os.ReadFile("_internal/PLAN.md")` + "\n",
	}
	mustFind(t, scan(t, code), "private-reference", "main.go")

	sourceDoc := map[string]string{
		"docs/ARCHITECTURE.md": "Derived from the Buildathon Track Strategy document.\n",
	}
	mustFind(t, scan(t, sourceDoc), "private-reference", "docs/ARCHITECTURE.md")
}

func TestPrivateReferenceLineNumbersSurviveBlanking(t *testing.T) {
	body := "line one\n```\ncode\n```\nSee [plan](_internal/PLAN.md)\n"
	f := scan(t, map[string]string{"README.md": body})
	mustFind(t, f, "private-reference", "README.md")
	for _, x := range f {
		if x.Check == "private-reference" && x.Line != 5 {
			t.Fatalf("expected the finding on line 5, got %d", x.Line)
		}
	}
}

func TestEnvExampleMustNotAssignSecretValues(t *testing.T) {
	bad := map[string]string{
		".env.example": "# comment\nMESH_LLM_API_KEY=gsk_realvalue\nMESH_HTTP_ADDR=:8080\n",
	}
	f := scan(t, bad)
	mustFind(t, f, "env-example", ".env.example")

	good := map[string]string{
		".env.example": "# Groq free tier works here\nMESH_LLM_API_KEY=\nMESH_HTTP_ADDR=:8080\nMESH_LOG_LEVEL=info\n",
	}
	mustNotFind(t, scan(t, good), "env-example")
}

func TestEnvExampleAllowsNonSecretDefaults(t *testing.T) {
	f := scan(t, map[string]string{
		".env.example": "MESH_WORKER_CONCURRENCY=8\nMESH_INFRA_MODE=managed\n",
	})
	mustNotFind(t, f, "env-example")
}

func TestWebSinksFlagUsageNotCommentary(t *testing.T) {
	comment := map[string]string{
		"web/console.js": "// nothing here goes near innerHTML, by design\n",
	}
	mustNotFind(t, scan(t, comment), "web-sink")

	usage := map[string]string{
		"web/console.js": "el.innerHTML = row;\n",
	}
	mustFind(t, scan(t, usage), "web-sink", "web/console.js")

	// The strings below are inert Go string literals used as scanner fixtures.
	// They are never executed; the assertion is that the scanner rejects them.
	for _, c := range []string{
		"node.outerHTML = x;",
		"n.insertAdjacentHTML('beforeend', s);",
		"document.write(s);",
		"var f = new Function('return 1');",
		"eval(userInput);",
	} {
		f := scan(t, map[string]string{"web/app.js": c})
		mustFind(t, f, "web-sink", "web/app.js")
	}
}

func TestWebSinksFlagInlineHandlersAndJavascriptUrls(t *testing.T) {
	f := scan(t, map[string]string{
		"web/checkout.html": `<button onclick="pay()">Pay</button>` + "\n",
	})
	mustFind(t, f, "web-sink", "web/checkout.html")

	f = scan(t, map[string]string{
		"web/checkout.html": `<a href="javascript:void(0)">x</a>` + "\n",
	})
	mustFind(t, f, "web-sink", "web/checkout.html")
}

func TestWebSinkChecksIgnoreNonWebPaths(t *testing.T) {
	f := scan(t, map[string]string{"internal/agent/live.go": "s.innerHTML = x"})
	mustNotFind(t, f, "web-sink")
}

func TestDependencyAllowlistIsEnforced(t *testing.T) {
	f := scan(t, map[string]string{}, "github.com/jackc/pgx/v5", "github.com/gin-gonic/gin")
	mustFind(t, f, "dependency", "go.mod")

	ok := scan(t, map[string]string{},
		"github.com/jackc/pgx/v5",
		"github.com/redis/go-redis/v9",
		"github.com/google/uuid",
	)
	mustNotFind(t, ok, "dependency")
}

func TestParseDirectDepsIgnoresIndirect(t *testing.T) {
	gomod := `module example.com/x

go 1.25.0

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/redis/go-redis/v9 v9.22.0
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
)

require github.com/google/uuid v1.6.0
`
	got := ParseDirectDeps([]byte(gomod))
	want := map[string]bool{
		"github.com/jackc/pgx/v5":      true,
		"github.com/redis/go-redis/v9": true,
		"github.com/google/uuid":       true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d direct deps, got %d: %v", len(want), len(got), got)
	}
	for _, d := range got {
		if !want[d] {
			t.Fatalf("unexpected direct dependency %q (indirect should be skipped)", d)
		}
	}
}

func TestCleanRepositoryProducesNoFindings(t *testing.T) {
	f := scan(t, map[string]string{
		"README.md":          "# Project\n\nRuns with `go run ./cmd/mesh`.\n",
		".env.example":       "MESH_WEBHOOK_SECRET=\nMESH_LOG_LEVEL=info\n",
		"web/app.js":         "el.textContent = value;\n",
		"internal/a.go":      "package a\n",
		"docker-compose.yml": "DSN: postgres://mesh:${PGPASS}@db:5432/mesh\n",
	}, "github.com/google/uuid")
	if len(f) != 0 {
		t.Fatalf("expected a clean scan, got %v", f)
	}
}

func TestBinaryDetection(t *testing.T) {
	if !isBinary([]byte{0x00, 0x01, 0x02}) {
		t.Fatal("expected NUL-containing content to be treated as binary")
	}
	if isBinary([]byte("plain text")) {
		t.Fatal("expected text to be treated as text")
	}
}

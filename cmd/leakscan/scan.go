package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Finding is one reason the repository must not be published as-is.
type Finding struct {
	Check string
	File  string
	Line  int
	Note  string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d  %s", f.File, f.Line, f.Note)
	}
	return fmt.Sprintf("%s  %s", f.File, f.Note)
}

// Scanner inspects the set of files git actually tracks.
//
// Tracking is the right input, not the working tree: untracked files are never
// published, and a .gitignore entry does nothing about a file that was already
// committed. Reading from the index is what makes this a control rather than a
// convention.
type Scanner struct {
	// Files maps a repo-relative path to its contents.
	Files map[string][]byte
	// DirectDeps are the direct module requirements found in go.mod.
	DirectDeps []string
}

// selfPaths are allowed to contain the very patterns they search for.
var selfPaths = map[string]bool{
	"cmd/leakscan/scan.go":      true,
	"cmd/leakscan/main.go":      true,
	"cmd/leakscan/scan_test.go": true,
	"scripts/leakscan.sh":       true,
	"scripts/leakscan.ps1":      true,
	".gitignore":                true,
}

// approvedDeps is the dependency allowlist. A payments repository that grows a
// dependency without a decision has grown an unreviewed supply-chain path, so
// the allowlist is enforced rather than documented.
var approvedDeps = map[string]bool{
	"github.com/jackc/pgx/v5":                    true,
	"github.com/redis/go-redis/v9":               true,
	"github.com/alicebob/miniredis/v2":           true,
	"github.com/fergusstrange/embedded-postgres": true,
	"github.com/google/uuid":                     true,
	"golang.org/x/time":                          true,
}

// Scan runs every check and returns findings ordered by check then path.
func (s *Scanner) Scan() []Finding {
	var out []Finding
	out = append(out, s.checkPrivatePaths()...)
	out = append(out, s.checkCredentials()...)
	out = append(out, s.checkPrivateReferences()...)
	out = append(out, s.checkEnvExample()...)
	out = append(out, s.checkWebSinks()...)
	out = append(out, s.checkDependencies()...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func (s *Scanner) paths() []string {
	p := make([]string, 0, len(s.Files))
	for k := range s.Files {
		p = append(p, k)
	}
	sort.Strings(p)
	return p
}

// ---------------------------------------------------------------------------
// 1. Private paths must never be tracked
// ---------------------------------------------------------------------------

func (s *Scanner) checkPrivatePaths() []Finding {
	var out []Finding
	for _, f := range s.paths() {
		switch {
		case strings.HasPrefix(f, "_internal/"):
			out = append(out, Finding{"private-path", f, 0, "internal material is tracked"})
		case strings.HasSuffix(f, ".docx"), strings.HasSuffix(f, ".private.md"):
			out = append(out, Finding{"private-path", f, 0, "private document is tracked"})
		case f == ".env" || (strings.HasPrefix(f, ".env.") && f != ".env.example"):
			out = append(out, Finding{"private-path", f, 0, "environment file is tracked"})
		case hasAnySuffix(f, ".pem", ".key", ".p12", ".pfx", ".jks"):
			out = append(out, Finding{"private-path", f, 0, "key material is tracked"})
		}
	}
	return out
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 2. Credential-shaped content
// ---------------------------------------------------------------------------

// credentialPatterns are anchored to real credential formats rather than to the
// word "secret", so prose discussing secrets does not trip the scan. A scanner
// that cries wolf gets switched off, which is strictly worse than no scanner.
var credentialPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"razorpay live key", regexp.MustCompile(`rzp_live_[A-Za-z0-9]{10,}`)},
	{"razorpay test key", regexp.MustCompile(`rzp_test_[A-Za-z0-9]{10,}`)},
	{"groq key", regexp.MustCompile(`gsk_[A-Za-z0-9]{40,}`)},
	{"anthropic key", regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{20,}`)},
	{"openai key", regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`)},
	{"google api key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{30,}`)},
	{"aws access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`)},
	{"slack token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"credentialed postgres dsn", regexp.MustCompile(`postgres(ql)?://[^:@/\s]+:[^@/\s]+@`)},
	{"credentialed redis dsn", regexp.MustCompile(`redis://[^:@/\s]+:[^@/\s]+@`)},
}

// interpolation matches shell, compose, and CI variable references. A DSN whose
// password is a variable reference contains no credential, so these are erased
// before matching rather than special-cased per pattern.
var interpolation = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|%[A-Za-z_][A-Za-z0-9_]*%`)

func (s *Scanner) checkCredentials() []Finding {
	var out []Finding
	for _, f := range s.paths() {
		if selfPaths[f] || f == ".env.example" {
			continue
		}
		for i, line := range lines(s.Files[f]) {
			// Replaced with whitespace, not a token: every credential pattern
			// excludes whitespace from its value class, so an interpolated
			// password stops matching instead of merely changing shape.
			clean := interpolation.ReplaceAllString(line, " ")
			for _, p := range credentialPatterns {
				if p.re.MatchString(clean) {
					out = append(out, Finding{"credential", f, i + 1, p.name + " present in tracked file"})
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 3. References that would resolve to private material
// ---------------------------------------------------------------------------

var (
	// A link or import that would actually resolve, not prose mentioning the path.
	privateLink = regexp.MustCompile(`\]\(\s*\.?/?_internal/|["'` + "`" + `]\s*\.?/?_internal/|(?:^|\s)\.?/?_internal/[A-Za-z0-9_.\-]+`)
	privateDoc  = regexp.MustCompile(`Buildathon Track Strategy`)
	mdCodeSpan  = regexp.MustCompile("`[^`]*`")
	mdFence     = regexp.MustCompile("(?s)```.*?```")
)

func (s *Scanner) checkPrivateReferences() []Finding {
	var out []Finding
	for _, f := range s.paths() {
		if selfPaths[f] {
			continue
		}
		body := string(s.Files[f])

		// In prose, a backticked path is a description, not a reference. Blanking
		// code spans first is what lets the documentation honestly explain that
		// private material exists without failing its own scan.
		if strings.HasSuffix(f, ".md") {
			body = mdFence.ReplaceAllStringFunc(body, blankNonNewline)
			body = mdCodeSpan.ReplaceAllStringFunc(body, blankNonNewline)
		}

		for i, line := range strings.Split(body, "\n") {
			if privateLink.MatchString(line) {
				out = append(out, Finding{"private-reference", f, i + 1, "resolvable reference to private material"})
			}
			if privateDoc.MatchString(line) {
				out = append(out, Finding{"private-reference", f, i + 1, "reference to the private source document"})
			}
		}
	}
	return out
}

// blankNonNewline replaces every character except newlines, preserving line
// numbers so findings still point at the right line.
func blankNonNewline(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] != '\n' {
			b[i] = ' '
		}
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// 4. .env.example documents variables, never their values
// ---------------------------------------------------------------------------

var secretVarName = regexp.MustCompile(`SECRET|KEY|TOKEN|PASSWORD|DSN|CREDENTIAL`)

func (s *Scanner) checkEnvExample() []Finding {
	body, ok := s.Files[".env.example"]
	if !ok {
		return nil
	}
	var out []Finding
	for i, line := range lines(body) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, found := strings.Cut(t, "=")
		if !found {
			continue
		}
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if v != "" && secretVarName.MatchString(strings.ToUpper(k)) {
			out = append(out, Finding{"env-example", ".env.example", i + 1,
				"assigns a value to " + k + "; the example must document names only"})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 5. Shipped web assets must avoid unsafe DOM sinks
// ---------------------------------------------------------------------------

// Assignment and call forms only. A comment saying the sink is avoided is not
// a use of the sink, and flagging it would train people to ignore the scanner.
var domSinks = []struct {
	name string
	re   *regexp.Regexp
}{
	{"innerHTML assignment", regexp.MustCompile(`\.innerHTML\s*(=|\+=)`)},
	{"outerHTML assignment", regexp.MustCompile(`\.outerHTML\s*(=|\+=)`)},
	{"insertAdjacentHTML", regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
	{"document.write", regexp.MustCompile(`document\.write(ln)?\s*\(`)},
	{"eval", regexp.MustCompile(`(^|[^A-Za-z0-9_.])eval\s*\(`)},
	{"Function constructor", regexp.MustCompile(`new\s+Function\s*\(`)},
	{"inline event handler", regexp.MustCompile(`<[a-zA-Z][^>]*\son[a-z]+\s*=`)},
	{"javascript: url", regexp.MustCompile(`(?i)javascript:`)},
}

var commentLine = regexp.MustCompile(`^\s*(//|/\*|\*|<!--|#)`)

func (s *Scanner) checkWebSinks() []Finding {
	var out []Finding
	for _, f := range s.paths() {
		if !strings.HasPrefix(f, "web/") {
			continue
		}
		ext := path.Ext(f)
		if ext != ".js" && ext != ".html" && ext != ".htm" {
			continue
		}
		for i, line := range lines(s.Files[f]) {
			if commentLine.MatchString(line) {
				continue
			}
			for _, sink := range domSinks {
				if sink.re.MatchString(line) {
					out = append(out, Finding{"web-sink", f, i + 1, sink.name + " in a shipped asset"})
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 6. Dependency allowlist
// ---------------------------------------------------------------------------

func (s *Scanner) checkDependencies() []Finding {
	var out []Finding
	for _, d := range s.DirectDeps {
		if !approvedDeps[d] {
			out = append(out, Finding{"dependency", "go.mod", 0,
				d + " is not on the approved dependency list"})
		}
	}
	return out
}

// ParseDirectDeps extracts non-indirect requirements from go.mod contents.
func ParseDirectDeps(gomod []byte) []string {
	var out []string
	inBlock := false
	for _, line := range lines(gomod) {
		t := strings.TrimSpace(line)
		switch {
		case t == "require (":
			inBlock = true
			continue
		case inBlock && t == ")":
			inBlock = false
			continue
		}
		var spec string
		if inBlock {
			spec = t
		} else if strings.HasPrefix(t, "require ") {
			spec = strings.TrimPrefix(t, "require ")
		} else {
			continue
		}
		if spec == "" || strings.HasPrefix(spec, "//") {
			continue
		}
		if idx := strings.Index(spec, "//"); idx >= 0 {
			if strings.Contains(spec[idx:], "indirect") {
				continue
			}
			spec = strings.TrimSpace(spec[:idx])
		}
		fields := strings.Fields(spec)
		if len(fields) >= 1 {
			out = append(out, fields[0])
		}
	}
	return out
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// isBinary reports whether contents look binary, in which case scanning for
// text patterns is meaningless and slow.
func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Command receipts re-runs every claim the README makes and fails if any of
// them has stopped being true.
//
// The rest of this project argues that a system acting on money should emit
// evidence rather than assurances. A README is the one place where that
// argument is usually abandoned: numbers are pasted in once, the code moves,
// and the document quietly becomes a description of a program that no longer
// exists. Nobody notices, because nothing checks.
//
// So the claims live in docs/receipts.json, each one carrying the command that
// produces it, the pattern that extracts the number, the value recorded when it
// was written down, and the observation that would falsify it. This runs them
// and diffs. A drifted figure fails the build the same way a broken test does.
//
//	go run ./cmd/receipts            # the fast tier, about ninety seconds
//	go run ./cmd/receipts -tier all  # everything a machine can check
//	go run ./cmd/receipts -md        # regenerate the README's table
//
// Three receipts are marked browser and are never executed here. They are
// claims about what a reader's own browser does with the published artefacts,
// and a Go process asserting them would be exactly the substitution this
// project exists to refuse. They carry the reason instead.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const manifestPath = "docs/receipts.json"

// A Check pulls one number out of a command's output and compares it with the
// value that was recorded. Three shapes cover everything the README claims.
type Check struct {
	Label   string `json:"label"`
	Pattern string `json:"pattern"`

	// Expect is the recorded value. Empty means the figure is reported but not
	// asserted, which is right for counts that legitimately move with the
	// repository, such as how many files the leak scanner walked.
	Expect string `json:"expect,omitempty"`

	// Count compares how many times the pattern matched rather than what it
	// captured. Used for "three survived, five refuted".
	Count bool `json:"count,omitempty"`

	// Absent requires no match at all. Used for the test suite, where the
	// claim is the absence of the word FAIL rather than the presence of
	// anything in particular.
	Absent bool `json:"absent,omitempty"`
}

type Receipt struct {
	ID      string   `json:"id"`
	Claim   string   `json:"claim"`
	Tier    string   `json:"tier"` // fast, slow, browser
	Command []string `json:"command,omitempty"`

	// EnvUnset clears variables before the command runs. The discovery round
	// uses a language model when one is configured and a deterministic
	// proposer when one is not, so a receipt that did not clear the model
	// credentials would record a different answer on the author's machine than
	// on a reviewer's.
	EnvUnset []string `json:"env_unset,omitempty"`

	TimeoutSeconds int     `json:"timeout_seconds,omitempty"`
	Checks         []Check `json:"checks,omitempty"`

	// Falsifier is the observation that would show the claim to be false. It
	// is prose, for a reader rather than for this program, and writing one is
	// the part of adding a receipt that does the actual work.
	Falsifier string `json:"falsifier"`

	// Why is required on browser receipts and explains what a machine here
	// cannot honestly assert.
	Why string `json:"why,omitempty"`
}

type manifest struct {
	Schema   string    `json:"schema"`
	Note     string    `json:"note"`
	Receipts []Receipt `json:"receipts"`
}

type outcome struct {
	receipt  Receipt
	status   string // PASS, FAIL, BROWSER, SKIP
	elapsed  time.Duration
	lines    []string
	failures []string
}

func main() {
	var (
		tier     = flag.String("tier", "fast", "which receipts to run: fast, slow, all")
		only     = flag.String("only", "", "run a single receipt by id")
		markdown = flag.Bool("md", false, "print the README table instead of a report")
		verbose  = flag.Bool("v", false, "print each command's output")
	)
	flag.Parse()

	if err := run(os.Stdout, *tier, *only, *markdown, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "receipts: %v\n", err)
		os.Exit(1)
	}
}

func run(out io.Writer, tier, only string, markdown, verbose bool) error {
	m, err := load(manifestPath)
	if err != nil {
		return err
	}
	if err := validate(m); err != nil {
		return err
	}

	selected := selectFor(m.Receipts, tier, only)
	if len(selected) == 0 {
		return fmt.Errorf("no receipts matched tier %q", tier)
	}

	fmt.Fprintf(out, "receipts: %d of %d claims, tier %s\n\n", len(selected), len(m.Receipts), tier)

	results := make([]outcome, 0, len(selected))
	failed := 0
	for _, r := range selected {
		res := check(r, verbose, out)
		results = append(results, res)
		if res.status == "FAIL" {
			failed++
		}
	}

	if markdown {
		writeMarkdown(out, results)
		return nil
	}

	writeReport(out, results, failed)
	if failed > 0 {
		return fmt.Errorf("%d of %d claims no longer hold", failed, len(selected))
	}
	return nil
}

func load(path string) (manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return m, nil
}

// validate refuses a malformed manifest rather than silently running fewer
// claims than the README advertises. A receipt with no falsifier is the one
// that matters: it means somebody added a number without deciding what would
// disprove it.
func validate(m manifest) error {
	if len(m.Receipts) == 0 {
		return errors.New("manifest contains no receipts")
	}
	seen := map[string]bool{}
	for _, r := range m.Receipts {
		switch {
		case r.ID == "":
			return errors.New("a receipt has no id")
		case seen[r.ID]:
			return fmt.Errorf("duplicate receipt id %q", r.ID)
		case r.Claim == "":
			return fmt.Errorf("%s has no claim", r.ID)
		case r.Falsifier == "":
			return fmt.Errorf("%s has no falsifier; decide what would disprove it before recording it", r.ID)
		}
		seen[r.ID] = true

		switch r.Tier {
		case "fast", "slow":
			if len(r.Command) == 0 {
				return fmt.Errorf("%s is tier %s but has no command", r.ID, r.Tier)
			}
		case "browser":
			if r.Why == "" {
				return fmt.Errorf("%s is tier browser but does not say why it cannot be checked here", r.ID)
			}
			if len(r.Command) > 0 {
				return fmt.Errorf("%s is tier browser and must not carry a command", r.ID)
			}
		default:
			return fmt.Errorf("%s has unknown tier %q", r.ID, r.Tier)
		}

		for _, c := range r.Checks {
			if _, err := regexp.Compile(c.Pattern); err != nil {
				return fmt.Errorf("%s: check %q has a bad pattern: %w", r.ID, c.Label, err)
			}
			if c.Count && c.Absent {
				return fmt.Errorf("%s: check %q is both a count and an absence", r.ID, c.Label)
			}
		}
	}
	return nil
}

func selectFor(all []Receipt, tier, only string) []Receipt {
	out := make([]Receipt, 0, len(all))
	for _, r := range all {
		if only != "" {
			if strings.EqualFold(r.ID, only) {
				out = append(out, r)
			}
			continue
		}
		switch tier {
		case "all":
			out = append(out, r)
		case "fast":
			if r.Tier == "fast" || r.Tier == "browser" {
				out = append(out, r)
			}
		case "slow":
			if r.Tier == "slow" || r.Tier == "browser" {
				out = append(out, r)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func check(r Receipt, verbose bool, out io.Writer) outcome {
	res := outcome{receipt: r}

	if r.Tier == "browser" {
		res.status = "BROWSER"
		res.lines = []string{r.Why}
		return res
	}

	timeout := time.Duration(r.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintf(out, "  %-4s %s\n", r.ID, strings.Join(r.Command, " "))

	start := time.Now()
	cmd := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...)
	cmd.Env = envWithout(os.Environ(), r.EnvUnset)
	raw, runErr := cmd.CombinedOutput()
	res.elapsed = time.Since(start)

	text := ansi.ReplaceAllString(string(raw), "")
	if verbose {
		fmt.Fprintln(out, indent(text, "       | "))
	}

	// A command that could not run at all is a failure of the claim, not of
	// this tool: the README tells a reader to run it.
	if ctx.Err() != nil {
		res.status = "FAIL"
		res.failures = append(res.failures, fmt.Sprintf("timed out after %s", timeout))
		return res
	}
	if runErr != nil {
		res.status = "FAIL"
		res.failures = append(res.failures, fmt.Sprintf("exited with %v", runErr))
		if len(r.Checks) == 0 {
			return res
		}
	}

	for _, c := range r.Checks {
		label, ok, detail := apply(c, text)
		res.lines = append(res.lines, label)
		if !ok {
			res.failures = append(res.failures, detail)
		}
	}
	if res.status == "" {
		res.status = "PASS"
		if len(res.failures) > 0 {
			res.status = "FAIL"
		}
	}
	return res
}

// apply runs one check and returns the line for the report, whether it held,
// and, when it did not, what the difference was.
func apply(c Check, text string) (line string, ok bool, detail string) {
	re := regexp.MustCompile(c.Pattern)

	switch {
	case c.Absent:
		if m := re.FindString(text); m != "" {
			return fmt.Sprintf("%s: found %q, expected none", c.Label, trim(m)), false,
				fmt.Sprintf("%s: %q appears in the output and should not", c.Label, trim(m))
		}
		return fmt.Sprintf("%s: absent, as claimed", c.Label), true, ""

	case c.Count:
		got := fmt.Sprint(len(re.FindAllString(text, -1)))
		if c.Expect == "" || got == c.Expect {
			return fmt.Sprintf("%s: %s", c.Label, got), true, ""
		}
		return fmt.Sprintf("%s: %s, recorded %s", c.Label, got, c.Expect), false,
			fmt.Sprintf("%s: observed %s, README says %s", c.Label, got, c.Expect)

	default:
		m := re.FindStringSubmatch(text)
		if m == nil {
			return fmt.Sprintf("%s: pattern did not match", c.Label), false,
				fmt.Sprintf("%s: the command no longer prints anything matching /%s/", c.Label, c.Pattern)
		}
		got := m[len(m)-1]
		if c.Expect == "" || got == c.Expect {
			return fmt.Sprintf("%s: %s", c.Label, got), true, ""
		}
		return fmt.Sprintf("%s: %s, recorded %s", c.Label, got, c.Expect), false,
			fmt.Sprintf("%s: observed %s, README says %s", c.Label, got, c.Expect)
	}
}

func envWithout(env []string, drop []string) []string {
	if len(drop) == 0 {
		return env
	}
	blocked := map[string]bool{}
	for _, k := range drop {
		blocked[strings.ToUpper(k)] = true
	}
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !blocked[strings.ToUpper(k)] {
			out = append(out, kv)
		}
	}
	return out
}

func writeReport(out io.Writer, results []outcome, failed int) {
	fmt.Fprintln(out)
	for _, r := range results {
		mark := "ok  "
		switch r.status {
		case "FAIL":
			mark = "FAIL"
		case "BROWSER":
			mark = "open"
		}
		took := ""
		if r.elapsed > 0 {
			took = fmt.Sprintf("  %.1fs", r.elapsed.Seconds())
		}
		fmt.Fprintf(out, "[%s] %-4s %s%s\n", mark, r.receipt.ID, r.receipt.Claim, took)
		for _, l := range r.lines {
			fmt.Fprintf(out, "       %s\n", l)
		}
		for _, f := range r.failures {
			fmt.Fprintf(out, "       !! %s\n", f)
		}
		if r.status == "FAIL" {
			fmt.Fprintf(out, "       falsifier: %s\n", r.receipt.Falsifier)
		}
		fmt.Fprintln(out)
	}

	pass, browser := 0, 0
	for _, r := range results {
		switch r.status {
		case "PASS":
			pass++
		case "BROWSER":
			browser++
		}
	}
	fmt.Fprintf(out, "%d verified, %d failed, %d left for the reader's own browser\n", pass, failed, browser)
	if failed == 0 {
		fmt.Fprintln(out, "every claim this can check still holds")
	}
}

// writeMarkdown regenerates the README's table so the document is produced by
// the run rather than typed from memory of one.
func writeMarkdown(out io.Writer, results []outcome) {
	w := tabwriter.NewWriter(out, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "| # | Claim | Check it with | Observed | What would falsify it |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, r := range results {
		cmd := "the published page"
		if len(r.receipt.Command) > 0 {
			cmd = "`" + strings.Join(r.receipt.Command, " ") + "`"
		}
		observed := strings.Join(r.lines, "; ")
		if r.status == "BROWSER" {
			observed = "*in your browser*"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
			r.receipt.ID, escape(r.receipt.Claim), cmd, escape(observed), escape(r.receipt.Falsifier))
	}
	_ = w.Flush()
}

func escape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

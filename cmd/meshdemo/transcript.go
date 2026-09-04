package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// transcript writes to the terminal and keeps two copies of everything: a plain
// text one for the markdown report, and a structured one for the exported run.
//
// Styling is stripped from the saved copies rather than never applied, so the
// terminal can be readable, the artefact can be pasted into a document without
// escape codes in it, and the published page can re-render the narration in its
// own typography instead of screen-scraping ANSI.
type transcript struct {
	w      io.Writer
	colour bool
	buf    strings.Builder
	actNo  int
	rec    []record
	// inProgress tracks whether a transient counter line is currently on
	// screen, so it can be overwritten rather than accumulating one line per
	// poll — which would bury the narration in noise.
	inProgress bool
}

// record is one narration line with its role preserved.
//
// The kind is what lets the published page style a refusal differently from a
// heading without parsing the text back out, and it is why the export is not
// simply the markdown transcript with the escape codes removed.
type record struct {
	Act  int    `json:"act"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Narration roles. They name what a line *is*, not how it looks.
const (
	kindLine  = "line"
	kindHead  = "head"
	kindRule  = "rule"
	kindKV    = "kv"
	kindStep  = "step"
	kindOK    = "ok"
	kindWarn  = "warn"
	kindFail  = "fail"
	kindNote  = "note"
	kindTable = "table"
)

// ANSI codes, used sparingly. Colour that carries no meaning is decoration; here
// it separates the narration from the data and marks pass from warn.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiBlue  = "\x1b[38;5;69m"
	ansiGreen = "\x1b[38;5;35m"
	ansiAmber = "\x1b[38;5;179m"
	ansiRed   = "\x1b[38;5;167m"
)

func newTranscript(w io.Writer, colour bool) *transcript {
	// A terminal that cannot render escape codes shows them as garbage, and the
	// usual culprit is a redirected stream, so styling is off unless the caller
	// asked for it and the output looks like a console.
	if f, ok := w.(*os.File); !ok || f == nil {
		colour = false
	}
	return &transcript{w: w, colour: colour}
}

func (t *transcript) style(code, s string) string {
	if !t.colour {
		return s
	}
	return code + s + ansiReset
}

// emit writes one line to the terminal and both saved copies.
func (t *transcript) emit(kind, screen, plain string) {
	t.clearProgress()
	fmt.Fprintln(t.w, screen)
	t.buf.WriteString(plain)
	t.buf.WriteString("\n")
	t.rec = append(t.rec, record{Act: t.actNo, Kind: kind, Text: plain})
}

func (t *transcript) line(s string) { t.emit(kindLine, s, s) }

func (t *transcript) raw(s string) {
	for _, l := range strings.Split(s, "\n") {
		t.line(l)
	}
}

func (t *transcript) banner(title string) {
	t.line("")
	t.emit(kindRule, t.style(ansiBlue, rule), rule)
	t.emit(kindHead, "  "+t.style(ansiBold, title), "  "+title)
	t.emit(kindRule, t.style(ansiBlue, rule), rule)
	t.line("")
}

func (t *transcript) act(n int, title string) {
	t.actNo = n
	head := fmt.Sprintf("  %d. %s", n, title)
	t.line("")
	t.emit(kindRule, t.style(ansiBlue, rule), rule)
	t.emit(kindHead, t.style(ansiBold, head), head)
	t.emit(kindRule, t.style(ansiBlue, rule), rule)
	t.line("")
}

func (t *transcript) kv(k, v string) {
	line := fmt.Sprintf("  %-10s %s", k, v)
	t.emit(kindKV, fmt.Sprintf("  %-10s %s", t.style(ansiDim, k), v), line)
}

func (t *transcript) step(s string) {
	t.emit(kindStep, "  "+t.style(ansiDim, "·")+" "+s, "  · "+s)
}

func (t *transcript) ok(s string) {
	t.emit(kindOK, "  "+t.style(ansiGreen, "✓")+" "+s, "  [ok] "+s)
}

func (t *transcript) warn(s string) {
	t.emit(kindWarn, "  "+t.style(ansiAmber, "!")+" "+s, "  [warn] "+s)
}

func (t *transcript) fail(s string) {
	t.emit(kindFail, "  "+t.style(ansiRed, "✗")+" "+s, "  [FAIL] "+s)
}

// note renders an explanatory aside, wrapped, because the reason a thing is
// done is the part a reviewer is actually assessing.
func (t *transcript) note(s string) {
	for _, l := range wrap(s, 72) {
		t.emit(kindNote, "    "+t.style(ansiDim, l), "    "+l)
	}
}

// progress overwrites a single transient line. Only the last state reaches the
// saved transcript: a reader does not need every intermediate count.
func (t *transcript) progress(s string) {
	if !t.colour {
		// Without a terminal, rewriting in place is not possible, so transient
		// updates are dropped entirely rather than printed once per poll.
		return
	}
	fmt.Fprintf(t.w, "\r  %s %-64s", t.style(ansiDim, "…"), s)
	t.inProgress = true
}

func (t *transcript) endProgress() { t.clearProgress() }

func (t *transcript) clearProgress() {
	if t.inProgress {
		fmt.Fprintf(t.w, "\r%-72s\r", "")
		t.inProgress = false
	}
}

// table renders aligned columns. Widths come from the content so a long issuer
// key does not shear the layout.
func (t *transcript) table(header []string, rows [][]string) {
	if len(rows) == 0 {
		t.line("     (nothing to show yet)")
		return
	}
	w := make([]int, len(header))
	for i, h := range header {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i := range r {
			if i < len(w) && len(r[i]) > w[i] {
				w[i] = len(r[i])
			}
		}
	}
	render := func(cells []string) string {
		var b strings.Builder
		b.WriteString("     ")
		for i, c := range cells {
			if i >= len(w) {
				break
			}
			b.WriteString(c)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", w[i]-len(c)+2))
			}
		}
		return strings.TrimRight(b.String(), " ")
	}
	head := render(header)
	t.emit(kindTable, t.style(ansiDim, head), head)
	for _, r := range rows {
		t.emit(kindTable, render(r), render(r))
	}
}

// save writes the plain transcript as a markdown document.
func (t *transcript) save(path string) error {
	if path == "" {
		return nil
	}
	if err := ensureDir(path); err != nil {
		return err
	}
	var doc strings.Builder
	doc.WriteString("# ResilientMesh — demonstration transcript\n\n")
	fmt.Fprintf(&doc, "Generated %s. Every number below was read out of the\n",
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	doc.WriteString("running system's own database, not printed from a script.\n\n")
	doc.WriteString("```\n")
	doc.WriteString(t.buf.String())
	doc.WriteString("```\n")
	return os.WriteFile(path, []byte(doc.String()), 0o644)
}

// ensureDir creates the parent directory of a file that is about to be written.
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// wrap breaks prose at a width without splitting words.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			out = append(out, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(out, line)
}

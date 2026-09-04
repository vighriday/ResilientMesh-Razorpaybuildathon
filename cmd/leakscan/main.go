// Command leakscan fails the build if anything that must stay private is about
// to be published.
//
// It is written in Go rather than as a shell script for two reasons: it runs
// identically on every developer machine and in CI without a second
// implementation to keep in sync, and its matching rules are unit-tested
// against planted secrets. A security control that only exists on one platform
// and has never been tested is decoration.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	var (
		root    = flag.String("root", ".", "repository root to scan")
		quiet   = flag.Bool("quiet", false, "print findings only")
		verbose = flag.Bool("verbose", false, "list every scanned file")
	)
	flag.Parse()

	abs, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakscan: resolving root: %v\n", err)
		os.Exit(2)
	}

	tracked, err := trackedFiles(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakscan: %v\n", err)
		os.Exit(2)
	}
	if len(tracked) == 0 {
		fmt.Println("leakscan: no tracked files; nothing to scan")
		return
	}

	sc := &Scanner{Files: make(map[string][]byte, len(tracked))}
	skipped := 0
	for _, rel := range tracked {
		full := filepath.Join(abs, filepath.FromSlash(rel))
		if !fileExists(full) {
			// Tracked but deleted in the working tree; nothing to inspect.
			continue
		}
		b, err := os.ReadFile(full)
		if err != nil {
			fmt.Fprintf(os.Stderr, "leakscan: reading %s: %v\n", rel, err)
			os.Exit(2)
		}
		if isBinary(b) {
			skipped++
			// A binary is still checked by path, just not by content.
			sc.Files[rel] = nil
			continue
		}
		sc.Files[rel] = b
		if *verbose {
			fmt.Println("  scanning", rel)
		}
	}

	if gomod, ok := sc.Files["go.mod"]; ok {
		sc.DirectDeps = ParseDirectDeps(gomod)
	}

	findings := sc.Scan()

	if !*quiet {
		fmt.Printf("leakscan: %d tracked files (%d binary, path-checked only), %d direct dependencies\n",
			len(sc.Files), skipped, len(sc.DirectDeps))
	}

	if len(findings) == 0 {
		fmt.Println("leakscan: PASS — nothing private is tracked")
		return
	}

	current := ""
	for _, f := range findings {
		if f.Check != current {
			current = f.Check
			fmt.Printf("\n[%s]\n", current)
		}
		fmt.Println("  " + f.String())
	}
	fmt.Printf("\nleakscan: FAIL — %d finding(s)\n", len(findings))
	os.Exit(1)
}

// trackedFiles asks git for the index contents. Anything untracked cannot be
// published, so it is deliberately out of scope.
func trackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %w", root, err)
	}
	var files []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			files = append(files, p)
		}
	}
	return files, nil
}

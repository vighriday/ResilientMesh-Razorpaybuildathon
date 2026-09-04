package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// DotEnvFile is the conventional per-checkout configuration file. It is listed
// in .gitignore and is the file .env.example documents, so it is the place a
// reviewer will naturally put an API key.
const DotEnvFile = ".env"

// maxDotEnvBytes bounds the file. It holds around thirty short variables; a
// larger one is a mistake or an attempt to make the parser allocate.
const maxDotEnvBytes = 64 << 10

// DotEnv parses a dotenv file into variables this process is willing to accept.
//
// Two rules make reading a file from the working directory safe enough to do
// unconditionally. First, only names carrying EnvPrefix are returned: a dotenv
// file that lands in a checkout — from a tarball, a stale branch, a copied
// snippet — must not be able to set PATH, LD_PRELOAD, or anything else that
// changes what code this process runs. Second, values may not carry control
// characters, so a name or a secret cannot smuggle a newline into a log line or
// a terminal escape into an operator's console.
//
// A missing file is not an error. It is the normal case.
func DotEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	if info.Size() > maxDotEnvBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, over the %d byte limit",
			ErrInvalidValue, path, info.Size(), maxDotEnvBytes)
	}
	return parseDotEnv(f, path)
}

func parseDotEnv(r io.Reader, path string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxDotEnvBytes))
	sc.Buffer(make([]byte, 0, 4<<10), maxDotEnvBytes)

	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "export FOO=bar" is accepted because the file is just as often
		// sourced by a shell as read by this parser, and a file that works in
		// one and silently does nothing in the other is a trap.
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: %s:%d has no '='", ErrInvalidValue, path, n)
		}
		key = strings.TrimSpace(key)
		if !strings.HasPrefix(key, EnvPrefix) {
			// Silently ignored rather than rejected: a shared dotenv file may
			// legitimately hold variables for other tools, and refusing to
			// start because of one would be worse than not reading it.
			continue
		}
		value = unquote(strings.TrimSpace(value))
		if i := strings.IndexFunc(value, isControl); i >= 0 {
			return nil, fmt.Errorf("%w: %s:%d (%s) carries a control character at byte %d",
				ErrInvalidValue, path, n, key, i)
		}
		out[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	return out, nil
}

// unquote strips one matched pair of surrounding quotes and, for a
// double-quoted value only, drops a trailing inline comment.
//
// An unquoted value keeps everything after the '=' verbatim, because '#' is a
// legal character in a secret and eating it would corrupt a key in a way that
// only shows up as an authentication failure much later.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// withDotEnv layers a dotenv file underneath the process environment.
//
// The real environment always wins. A deployment that sets a variable
// explicitly must not be overridden by a file that happens to be in the working
// directory, and this ordering is what lets one checkout hold a developer's
// dotenv while CI runs the same binary from its own environment.
func withDotEnv(env Lookup, file map[string]string) Lookup {
	if len(file) == 0 {
		return env
	}
	return func(k string) (string, bool) {
		if v, ok := env(k); ok {
			return v, true
		}
		v, ok := file[k]
		return v, ok
	}
}

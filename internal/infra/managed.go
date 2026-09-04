// Package infra boots the stateful dependencies ResilientMesh needs — a real
// PostgreSQL server and a RESP server — as children of the process that asked
// for them, so `go run ./cmd/mesh` works on a laptop with no Docker, no service
// manager and no pre-provisioned database.
//
// The connection strings handed back are shaped exactly like the ones an
// operator sets in external mode. That equivalence is the point: nothing
// downstream of this package may branch on how the infrastructure was started,
// because a demo path that diverges from the production path proves nothing
// about the production path.
package infra

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

const (
	// pgVersion is pinned rather than inherited from the library default so a
	// dependency bump cannot silently swap the database engine underneath a
	// schema that was verified against a different one.
	pgVersion = embeddedpostgres.V18

	// Managed mode runs a throwaway cluster bound to the loopback interface and
	// initialised with these credentials on every host. They are a shape, not a
	// secret: the DSN is never logged, and external mode — the only mode that
	// ever touches real data — takes its credentials from configuration.
	pgUser     = "mesh"
	pgPassword = "mesh"
	pgDatabase = "mesh"

	// pgPortAttempts bounds the retry loop around the unavoidable race between
	// probing a free port and the child process binding it.
	pgPortAttempts = 5

	// pgLogTailBytes caps how much PostgreSQL output is retained for error
	// messages. Boot failures put their explanation in the last few lines, and
	// an unbounded buffer fed by a child process is a memory hazard.
	pgLogTailBytes = 8 << 10

	// maxPathLen bounds operator-supplied directory paths, which normally
	// arrive from environment variables and are therefore external input.
	maxPathLen = 4096

	pidFileName      = "postmaster.pid"
	passwordFileName = "pwfile"
	binariesMarker   = ".mesh-extracted"
)

// defaultDataDir keeps managed state inside the working tree, where .gitignore
// already excludes it and an operator can delete it without hunting through
// system directories.
var defaultDataDir = filepath.Join(".mesh", "pg")

// Options configures a managed runtime. The zero value is valid and produces
// the defaults documented on each field.
type Options struct {
	// DataDir holds the PostgreSQL cluster. It survives across runs, which is
	// what turns a 23 s cold start into a 2 s warm one. Defaults to ".mesh/pg".
	DataDir string

	// RuntimeDir is scratch space the database library erases on every start,
	// so it must never contain DataDir or BinariesDir. Defaults to
	// "<DataDir>-run".
	RuntimeDir string

	// BinariesDir holds the extracted PostgreSQL distribution. It defaults
	// under os.UserCacheDir so a fresh clone of the repository reuses an
	// already-downloaded engine instead of pulling ~30 MB again.
	BinariesDir string

	// CacheDir holds the compressed distribution archive, also under
	// os.UserCacheDir by default.
	CacheDir string

	// PGPort and RedisPort pin a listener instead of taking a dynamic one. A
	// pinned port disables the retry-on-collision loop, because silently moving
	// off a port an operator explicitly chose would be worse than failing.
	PGPort    int
	RedisPort int

	// PGLogWriter receives raw PostgreSQL output. It defaults to io.Discard:
	// server chatter interleaved with the structured log stream makes the demo
	// unreadable, and boot failures carry their own log tail in the error.
	PGLogWriter io.Writer

	// Logger receives the structured lifecycle records. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// StartTimeout bounds initdb plus the first health check. Defaults to 90 s,
	// comfortably above the ~23 s cold start measured on a warm-cache laptop.
	StartTimeout time.Duration

	// Clock exists so a caller can make the reported start duration
	// deterministic. Defaults to the wall clock.
	Clock domain.Clock
}

type resolvedOptions struct {
	dataDir      string
	runtimeDir   string
	binariesDir  string
	cacheDir     string
	pgPort       int
	redisPort    int
	pgLog        io.Writer
	logger       *slog.Logger
	startTimeout time.Duration
	clock        domain.Clock
}

// Runtime is a started managed stack. Every exported field is written once
// during StartManaged and only read afterwards, so a Runtime may be shared
// across goroutines without synchronisation; Stop carries its own.
type Runtime struct {
	// PGDSN is a libpq URL. It embeds the managed credentials, so it must be
	// treated like any other DSN: handed to a driver, never logged.
	PGDSN string

	// RedisAddr is a host:port suitable for redis.Options.Addr.
	RedisAddr string

	PGPort    int
	RedisPort int

	// ColdStart reports whether this boot had to download binaries or run
	// initdb. A benchmark that does not separate the two is measuring the disk.
	ColdStart bool

	// StartupDuration is the wall time StartManaged spent booting.
	StartupDuration time.Duration

	runtimeDir string
	dataDir    string
	pg         *embeddedpostgres.EmbeddedPostgres
	redis      *miniredis.Miniredis

	stopOnce sync.Once
	stopErr  error
}

// StartManaged boots PostgreSQL and an in-process RESP server on loopback ports
// and returns the connection details for both.
//
// On any failure it tears down whatever it had already started and returns a
// nil Runtime, so a caller cannot leak a half-built stack by forgetting to
// check the error.
func StartManaged(ctx context.Context, opts Options) (rt *Runtime, err error) {
	o, err := opts.resolve()
	if err != nil {
		return nil, err
	}

	began := o.clock.Now()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("infra: managed start aborted before boot: %w", ctxErr)
	}

	r := &Runtime{
		runtimeDir: o.runtimeDir,
		dataDir:    o.dataDir,
		ColdStart:  !dataDirInitialised(o.dataDir) || !binariesExtracted(o.binariesDir),
	}

	defer func() {
		if err == nil {
			return
		}
		// Roll back rather than leave an orphaned postmaster or a bound port
		// behind for the next attempt to trip over.
		if stopErr := r.Stop(); stopErr != nil {
			o.logger.Warn("managed infra rollback incomplete", "error", stopErr.Error())
		}
	}()

	if err := r.startRedis(o); err != nil {
		return nil, err
	}

	if err := r.startPostgres(ctx, o); err != nil {
		return nil, err
	}

	r.StartupDuration = o.clock.Now().Sub(began)

	// Deliberately not logging PGDSN: it carries credentials, and this record is
	// the one line an operator will paste into a bug report.
	o.logger.Info("managed infra ready",
		"pg_port", r.PGPort,
		"redis_addr", r.RedisAddr,
		"data_dir", o.dataDir,
		"cold_start", r.ColdStart,
		"startup_ms", r.StartupDuration.Milliseconds(),
	)

	return r, nil
}

// DownloadBinaries performs every expensive part of a cold start — fetching the
// PostgreSQL distribution, extracting it, running initdb — and then shuts the
// server down again.
//
// A harness calls this before it starts timing anything, so a first-run network
// download cannot land inside a measured window. It boots the server rather
// than only unpacking it because a pre-warm that exercises a different code path
// than the real start is a pre-warm that can succeed while the real start still
// fails.
//
// The variadic options exist so that the common DownloadBinaries(ctx) call warms
// exactly the directories StartManaged(ctx, Options{}) will later use.
func DownloadBinaries(ctx context.Context, opts ...Options) error {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}

	rt, err := StartManaged(ctx, o)
	if err != nil {
		return fmt.Errorf("infra: pre-warming postgres binaries: %w", err)
	}

	if err := rt.Stop(); err != nil {
		return fmt.Errorf("infra: shutting down after pre-warm: %w", err)
	}

	return nil
}

// Stop shuts both servers down. It is idempotent, safe on a nil Runtime, and
// safe after a failed start, because the shutdown path is also the rollback
// path and callers routinely defer it before knowing whether the start worked.
func (r *Runtime) Stop() error {
	if r == nil {
		return nil
	}

	r.stopOnce.Do(func() {
		var errs []error

		if r.redis != nil {
			r.redis.Close()
		}

		if r.pg != nil {
			if err := r.pg.Stop(); err != nil && !errors.Is(err, embeddedpostgres.ErrServerNotStarted) {
				errs = append(errs, fmt.Errorf("infra: stopping embedded postgres (data dir %s): %w", r.dataDir, err))
			}
		}

		// initdb is handed the superuser password through a file. The library
		// deletes it on the happy path; this covers the path where initdb died
		// partway and left a credential sitting on disk.
		if r.runtimeDir != "" {
			pwfile := filepath.Join(r.runtimeDir, passwordFileName)
			if err := os.Remove(pwfile); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("infra: removing leftover password file %s: %w", pwfile, err))
			}
		}

		r.stopErr = errors.Join(errs...)
	})

	return r.stopErr
}

// ---------------------------------------------------------------------------
// Redis
// ---------------------------------------------------------------------------

func (r *Runtime) startRedis(o resolvedOptions) error {
	mr := miniredis.NewMiniRedis()

	if o.redisPort > 0 {
		addr := net.JoinHostPort(loopbackHost, strconv.Itoa(o.redisPort))
		if err := mr.StartAddr(addr); err != nil {
			return fmt.Errorf("infra: binding managed redis to pinned address %s: %w "+
				"(another process holds that port; free it or leave the redis port unset for a dynamic one)", addr, err)
		}
	} else if err := mr.Start(); err != nil {
		// miniredis asks the kernel for the port itself, so unlike PostgreSQL
		// there is no probe-then-bind gap here and nothing to retry around.
		return fmt.Errorf("infra: starting managed redis on a dynamic loopback port: %w", err)
	}

	port, err := portOf(mr.Addr())
	if err != nil {
		mr.Close()
		return fmt.Errorf("infra: parsing managed redis address %q: %w", mr.Addr(), err)
	}

	r.redis = mr
	r.RedisAddr = mr.Addr()
	r.RedisPort = port

	return nil
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

// binariesMu serialises binary preparation and boot within a process. The
// library probes for bin/pg_ctl to decide whether to extract, so two concurrent
// starts sharing a binaries directory could observe each other's half-finished
// extraction. Serialising costs a wait that only concurrent boots ever pay.
var binariesMu sync.Mutex

func (r *Runtime) startPostgres(ctx context.Context, o resolvedOptions) error {
	binariesMu.Lock()
	defer binariesMu.Unlock()

	if err := prepareDirs(o); err != nil {
		return err
	}

	attempts := pgPortAttempts
	if o.pgPort > 0 {
		attempts = 1
	}

	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("infra: postgres boot cancelled after %d attempt(s): %w", attempt-1, err)
		}

		port := o.pgPort
		if port == 0 {
			free, freeErr := FreePort()
			if freeErr != nil {
				return freeErr
			}
			port = free
		}

		if err := recoverStaleLock(ctx, o); err != nil {
			return err
		}

		logs := newRingWriter(pgLogTailBytes, o.pgLog)
		db := embeddedpostgres.NewDatabase(pgConfig(o, port, logs))

		startErr := startWithContext(ctx, db, o.logger)
		if startErr == nil {
			if markErr := markBinariesExtracted(o.binariesDir); markErr != nil {
				o.logger.Warn("could not mark postgres binaries complete", "error", markErr.Error())
			}
			if probeErr := ensureExtractionProbe(o.binariesDir); probeErr != nil {
				o.logger.Warn("postgres binaries will be re-extracted on every start", "error", probeErr.Error())
			}
			r.pg = db
			r.PGPort = port
			r.PGDSN = pgDSN(port)
			return nil
		}

		lastErr = fmt.Errorf("port %d: %w%s", port, startErr, logs.tailSuffix())

		if o.pgPort == 0 && isPortConflict(startErr) {
			o.logger.Warn("postgres port was taken between probe and bind, retrying",
				"port", port, "attempt", attempt, "max_attempts", attempts)
			continue
		}

		break
	}

	return fmt.Errorf("infra: could not start embedded postgres "+
		"(data dir %s, binaries %s); delete the data directory to force a clean initdb: %w",
		o.dataDir, o.binariesDir, lastErr)
}

func pgConfig(o resolvedOptions, port int, logs io.Writer) embeddedpostgres.Config {
	return embeddedpostgres.DefaultConfig().
		Version(pgVersion).
		Port(uint32(port)).
		Username(pgUser).
		Password(pgPassword).
		Database(pgDatabase).
		DataPath(o.dataDir).
		RuntimePath(o.runtimeDir).
		BinariesPath(o.binariesDir).
		CachePath(o.cacheDir).
		StartTimeout(o.startTimeout).
		Logger(logs)
}

// startWithContext runs the library's blocking Start under a context.
//
// Start knows nothing about cancellation, and simply returning on ctx.Done
// would strand a postmaster that finishes booting a second later — an orphan
// holding a port and a data-directory lock is precisely the state this package
// exists to clean up. So the abandoned start is reaped and shut down out of band
// instead.
func startWithContext(ctx context.Context, db *embeddedpostgres.EmbeddedPostgres, log *slog.Logger) error {
	done := make(chan error, 1)
	go func() { done <- db.Start() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		go func() {
			if err := <-done; err != nil {
				return
			}
			if err := db.Stop(); err != nil {
				log.Warn("could not stop postgres abandoned by a cancelled boot", "error", err.Error())
			}
		}()
		return fmt.Errorf("boot cancelled while postgres was still starting: %w", ctx.Err())
	}
}

// recoverStaleLock clears the data-directory lock a killed run leaves behind.
//
// A Ctrl-C during the demo is the single most likely thing to happen to this
// system, and the resulting postmaster.pid makes every subsequent start fail
// with a message about a lock file that says nothing about how to fix it.
func recoverStaleLock(ctx context.Context, o resolvedOptions) error {
	path := filepath.Join(o.dataDir, pidFileName)

	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("infra: reading postgres lock file %s: %w", path, err)
	}

	pid, port := parsePostmasterPID(raw)

	// A listener on the port the lock file claims means the postmaster is alive,
	// not stale. It is almost always this project's own server orphaned by a
	// killed run, and it owns a directory this package manages, so shutting it
	// down is the recovery an operator wants rather than an error they have to
	// go research.
	if port > 0 && !portBindable("tcp", loopbackHost, port) {
		if stopErr := pgCtlStop(ctx, o); stopErr != nil {
			return fmt.Errorf("infra: postgres is already running on port %d against data dir %s (pid %d) "+
				"and could not be shut down: %w; stop it manually or remove the data directory", port, o.dataDir, pid, stopErr)
		}
		o.logger.Warn("shut down an orphaned postgres holding the data directory",
			"data_dir", o.dataDir, "pid", pid, "port", port)
	} else {
		o.logger.Warn("clearing stale postgres lock file left by a previous run",
			"data_dir", o.dataDir, "pid", pid)
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("infra: removing stale postgres lock file %s: %w", path, err)
	}

	return nil
}

// parsePostmasterPID extracts the process id and TCP port from a postmaster.pid
// file. PostgreSQL writes one value per line in a fixed order: pid, data
// directory, start time, port. Anything unparseable yields zeroes, which the
// caller reads as "stale" — the fail-safe direction here, since the alternative
// is refusing to boot over a file we cannot understand.
func parsePostmasterPID(raw []byte) (pid, port int) {
	if len(raw) > maxPathLen {
		return 0, 0
	}

	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	field := func(i int) int {
		if i >= len(lines) {
			return 0
		}
		v, err := strconv.Atoi(strings.TrimSpace(lines[i]))
		if err != nil || v <= 0 {
			return 0
		}
		return v
	}

	return field(0), field(3)
}

// pgCtlPath resolves the cluster control binary. The Windows distribution ships
// pg_ctl.exe, and probing for the extensionless name there yields a false
// negative — which is exactly the bug that makes the upstream library re-extract
// its binaries on every Windows start.
func pgCtlPath(binariesDir string) string {
	name := "pg_ctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(binariesDir, "bin", name)
}

func pgCtlStop(ctx context.Context, o resolvedOptions) error {
	bin := pgCtlPath(o.binariesDir)
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("no pg_ctl available at %s to stop it with: %w", bin, err)
	}

	cmd := exec.CommandContext(ctx, bin, "stop", "-D", o.dataDir, "-m", "fast", "-w")
	cmd.Stdout = o.pgLog
	cmd.Stderr = o.pgLog

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %q: %w", cmd.String(), err)
	}

	return nil
}

// isPortConflict distinguishes "someone took the port" from every other boot
// failure. Only the former is worth retrying; retrying a corrupt data directory
// five times just multiplies the wait before the real error appears.
func isPortConflict(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"already listening on port",
		"address already in use",
		"could not bind",
		"only one usage of each socket address",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func pgDSN(port int) string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(pgUser, pgPassword),
		Host:     net.JoinHostPort(loopbackHost, strconv.Itoa(port)),
		Path:     "/" + pgDatabase,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

// ---------------------------------------------------------------------------
// Filesystem state
// ---------------------------------------------------------------------------

func prepareDirs(o resolvedOptions) error {
	// initdb creates the cluster directory itself but not its parent.
	if err := os.MkdirAll(filepath.Dir(o.dataDir), 0o750); err != nil {
		return fmt.Errorf("infra: creating parent of postgres data dir %s: %w", o.dataDir, err)
	}
	if err := os.MkdirAll(o.cacheDir, 0o750); err != nil {
		return fmt.Errorf("infra: creating postgres archive cache %s: %w", o.cacheDir, err)
	}

	if binariesExtracted(o.binariesDir) {
		return nil
	}

	// An extraction interrupted partway leaves bin/pg_ctl present while the rest
	// of the tree is missing, and that file is the only thing the library checks
	// before deciding the binaries are usable. Without this reset a single
	// Ctrl-C during the first download would poison the cache permanently.
	if err := os.RemoveAll(o.binariesDir); err != nil {
		return fmt.Errorf("infra: clearing incomplete postgres binaries at %s: %w", o.binariesDir, err)
	}
	if err := os.MkdirAll(o.binariesDir, 0o750); err != nil {
		return fmt.Errorf("infra: creating postgres binaries dir %s: %w", o.binariesDir, err)
	}

	return nil
}

// binariesExtracted reports a complete extraction. The marker is written only
// after a server has actually started from these binaries, so "present" means
// "known to work" rather than "some files exist".
func binariesExtracted(dir string) bool {
	if _, err := os.Stat(pgCtlPath(dir)); err != nil {
		return false
	}
	got, err := os.ReadFile(filepath.Join(dir, binariesMarker))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(got)) == string(pgVersion)
}

// ensureExtractionProbe makes managed mode usable as a demo on Windows.
//
// embedded-postgres decides whether it must unpack its ~250 MB distribution by
// stat-ing bin/pg_ctl, but the Windows build ships bin/pg_ctl.exe. The probe
// therefore misses on every run and each start pays a full extraction —
// measured at 20 s where a warm start should be 2 s, on the very platform the
// demo is judged on. Putting a link at the probed path lets the check succeed.
//
// Nothing ever executes the link: os/exec on Windows resolves an extensionless
// path through PATHEXT and lands on pg_ctl.exe regardless. It points at the real
// binary rather than being a placeholder so that even a toolchain that did
// execute it would run the correct program.
func ensureExtractionProbe(dir string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	probe := filepath.Join(dir, "bin", "pg_ctl")
	if _, err := os.Stat(probe); err == nil {
		return nil
	}

	target := pgCtlPath(dir)
	if err := os.Link(target, probe); err == nil {
		return nil
	}

	// Hard links fail across volumes and on some filesystems; a copy of a
	// 100 KB control binary is a fine substitute for the storage saving.
	body, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("infra: reading %s to seed the extraction probe: %w", target, err)
	}
	if err := os.WriteFile(probe, body, 0o700); err != nil {
		return fmt.Errorf("infra: writing extraction probe %s: %w", probe, err)
	}

	return nil
}

func markBinariesExtracted(dir string) error {
	path := filepath.Join(dir, binariesMarker)
	if err := os.WriteFile(path, []byte(pgVersion), 0o600); err != nil {
		return fmt.Errorf("infra: writing binaries marker %s: %w", path, err)
	}
	return nil
}

// dataDirInitialised mirrors the library's own reuse test: PG_VERSION is the
// file initdb writes to declare the cluster complete.
func dataDirInitialised(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "PG_VERSION"))
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(pgVersion), strings.TrimSpace(string(raw)))
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func (o Options) resolve() (resolvedOptions, error) {
	dataDir, err := absDir("DataDir", o.DataDir, defaultDataDir)
	if err != nil {
		return resolvedOptions{}, err
	}

	runtimeDir, err := absDir("RuntimeDir", o.RuntimeDir, dataDir+"-run")
	if err != nil {
		return resolvedOptions{}, err
	}

	binDefault, cacheDefault := defaultCachePaths(dataDir)

	binariesDir, err := absDir("BinariesDir", o.BinariesDir, binDefault)
	if err != nil {
		return resolvedOptions{}, err
	}

	cacheDir, err := absDir("CacheDir", o.CacheDir, cacheDefault)
	if err != nil {
		return resolvedOptions{}, err
	}

	// The library empties RuntimeDir on every start. Anything nested inside it is
	// therefore deleted, which for the data directory would mean silently
	// discarding the cluster on the second boot.
	for _, nested := range []struct{ field, path string }{
		{"DataDir", dataDir},
		{"BinariesDir", binariesDir},
		{"CacheDir", cacheDir},
	} {
		if within(runtimeDir, nested.path) {
			return resolvedOptions{}, fmt.Errorf(
				"infra: %s (%s) is inside RuntimeDir (%s), which is erased on every start; choose separate directories",
				nested.field, nested.path, runtimeDir)
		}
	}

	pgPort, err := checkPort("PGPort", o.PGPort)
	if err != nil {
		return resolvedOptions{}, err
	}

	redisPort, err := checkPort("RedisPort", o.RedisPort)
	if err != nil {
		return resolvedOptions{}, err
	}

	if pgPort != 0 && pgPort == redisPort {
		return resolvedOptions{}, fmt.Errorf("infra: PGPort and RedisPort are both pinned to %d", pgPort)
	}

	r := resolvedOptions{
		dataDir:      dataDir,
		runtimeDir:   runtimeDir,
		binariesDir:  binariesDir,
		cacheDir:     cacheDir,
		pgPort:       pgPort,
		redisPort:    redisPort,
		pgLog:        o.PGLogWriter,
		logger:       o.Logger,
		startTimeout: o.StartTimeout,
		clock:        o.Clock,
	}

	if r.pgLog == nil {
		r.pgLog = io.Discard
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}
	if r.startTimeout <= 0 {
		r.startTimeout = 90 * time.Second
	}
	if r.clock == nil {
		r.clock = systemClock{}
	}

	return r, nil
}

// defaultCachePaths keeps the engine outside the working tree so a fresh clone
// or a `git clean -xdf` does not force another 30 MB download. The version is
// part of the path so an engine upgrade cannot half-reuse the old tree.
func defaultCachePaths(dataDir string) (binaries, archive string) {
	root, err := os.UserCacheDir()
	if err != nil {
		// No user cache dir (a bare CI container, typically): fall back beside
		// the data directory rather than failing the boot outright.
		root = filepath.Dir(dataDir)
	} else {
		root = filepath.Join(root, "resilientmesh")
	}
	return filepath.Join(root, "pg-"+string(pgVersion)), filepath.Join(root, "pg-archive")
}

func absDir(field, value, fallback string) (string, error) {
	if strings.TrimSpace(value) == "" {
		value = fallback
	}
	if len(value) > maxPathLen {
		return "", fmt.Errorf("infra: %s is %d bytes, over the %d byte limit", field, len(value), maxPathLen)
	}
	if strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("infra: %s contains a NUL byte", field)
	}

	abs, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("infra: resolving %s %q: %w", field, value, err)
	}

	return filepath.Clean(abs), nil
}

func checkPort(field string, port int) (int, error) {
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("infra: %s %d is outside the valid TCP port range", field, port)
	}
	return port, nil
}

// within reports whether child is parent or lives underneath it.
func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

func portOf(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("splitting host and port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("parsing port %q: %w", portStr, err)
	}
	return port, nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// Bounded log capture
// ---------------------------------------------------------------------------

// ringWriter keeps only the last max bytes written to it, optionally forwarding
// everything to a caller-supplied writer. Boot failures explain themselves in
// their final lines, and this package must be able to quote them without giving
// a child process an unbounded buffer to fill.
type ringWriter struct {
	mu  sync.Mutex
	max int
	buf []byte
	tee io.Writer
}

func newRingWriter(max int, tee io.Writer) *ringWriter {
	return &ringWriter{max: max, tee: tee}
}

func (w *ringWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)
	if len(w.buf) > w.max {
		w.buf = append(w.buf[:0], w.buf[len(w.buf)-w.max:]...)
	}

	if w.tee != nil && w.tee != io.Discard {
		if _, err := w.tee.Write(p); err != nil {
			return 0, fmt.Errorf("infra: forwarding postgres output: %w", err)
		}
	}

	return len(p), nil
}

func (w *ringWriter) tail() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(string(w.buf))
}

// tailSuffix renders the captured output for embedding in an error, or nothing
// when the server said nothing.
func (w *ringWriter) tailSuffix() string {
	t := w.tail()
	if t == "" {
		return ""
	}
	return "\n--- postgres output (last " + strconv.Itoa(pgLogTailBytes) + " bytes) ---\n" + t
}

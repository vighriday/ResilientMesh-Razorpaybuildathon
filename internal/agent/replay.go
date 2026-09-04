package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

const (
	// maxCassetteBytes bounds a single cassette. The corpus is a directory on
	// disk, which is an external input like any other; a 500 MB file dropped
	// into it must not take the process down at boot.
	maxCassetteBytes = 64 << 10

	// maxCassettes bounds the whole corpus. Bucketing the digest keeps the real
	// corpus in the hundreds, so this ceiling only ever catches a mistake.
	maxCassettes = 20000

	cassetteExt = ".json"
)

var (
	// ErrCassetteMiss is a routine outcome, not a fault: it is how the replay
	// tier tells the stack to fall through to the heuristic.
	ErrCassetteMiss = errors.New("agent: no cassette for context digest")

	// ErrCassetteCorpus marks a corpus that cannot be trusted at boot. Loading
	// fails loudly rather than skipping bad files, because a silently partial
	// corpus turns a reproducible benchmark into an unreproducible one.
	ErrCassetteCorpus = errors.New("agent: cassette corpus is invalid")
)

// Cassette is one recorded (context digest -> proposal) pair.
//
// The corpus is one file per digest rather than a single JSONL index. That
// choice buys three things: Record is a temp-file-plus-rename with no
// read-modify-write, so two recorders can never lose each other's entries or
// leave a half-written index; a corrupted file costs one context instead of the
// whole corpus; and a reviewer diffing the repo sees one readable file per
// scenario instead of a churning append-only blob.
type Cassette struct {
	Digest     string                    `json:"digest"`
	Context    CassetteContext           `json:"context"`
	Proposal   domain.DiagnosticProposal `json:"proposal"`
	RecordedAt time.Time                 `json:"recorded_at"`
}

// CassetteContext is a human-readable echo of the bucketed fields that produced
// the digest. It exists so a reviewer can tell what a cassette covers without
// recomputing hashes. It deliberately excludes every free-text field, so no
// attacker-supplied string is ever written into the repository.
type CassetteContext struct {
	ErrorCode      string        `json:"error_code"`
	Method         string        `json:"method"`
	IssuerKey      string        `json:"issuer_key"`
	AmountBand     string        `json:"amount_band"`
	IsRecurring    bool          `json:"is_recurring"`
	SessionActive  bool          `json:"session_active"`
	AttemptNumber  int           `json:"attempt_number"`
	AvailableRails []domain.Rail `json:"available_rails"`
}

// Replay serves recorded proposals by context digest. Lookup is O(1) against a
// map built once at construction, so an incident on the recovery path never
// waits on the filesystem.
type Replay struct {
	dir   string
	log   *slog.Logger
	clock domain.Clock

	mu       sync.RWMutex
	byDigest map[string]domain.DiagnosticProposal
}

var _ domain.Diagnoser = (*Replay)(nil)

// NewReplay loads the corpus once, eagerly, and validates every entry.
//
// A missing directory is tolerated (every lookup misses and the stack falls
// through, which is what a fresh checkout before a --record run should do), but
// a directory that exists and contains a malformed, oversized, or misnamed
// cassette is a hard error: silently dropping entries would make a benchmark
// claim rest on a corpus nobody can reconstruct.
func NewReplay(dir string, logger *slog.Logger, clock domain.Clock) (*Replay, error) {
	r := &Replay{
		dir:      dir,
		log:      orDiscard(logger),
		clock:    orSystemClock(clock),
		byDigest: make(map[string]domain.DiagnosticProposal),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.log.Warn("cassette directory absent, replay tier starts empty", "dir", dir)
			return r, nil
		}
		return nil, fmt.Errorf("agent: read cassette dir %q: %w", dir, err)
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, cassetteExt) {
			continue
		}
		if len(r.byDigest) >= maxCassettes {
			return nil, fmt.Errorf("%w: more than %d cassettes in %q", ErrCassetteCorpus, maxCassettes, dir)
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("agent: stat cassette %q: %w", name, err)
		}
		if info.Size() > maxCassetteBytes {
			return nil, fmt.Errorf("%w: %q is %d bytes, cap is %d",
				ErrCassetteCorpus, name, info.Size(), maxCassetteBytes)
		}

		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("agent: read cassette %q: %w", name, err)
		}
		var c Cassette
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrCassetteCorpus, name, err)
		}

		// The filename must be the digest. That is what makes the corpus
		// auditable by inspection and catches a hand-edited or renamed file
		// before it can answer for a context it was never recorded against.
		want := strings.TrimSuffix(name, cassetteExt)
		if !isDigest(c.Digest) || c.Digest != want {
			return nil, fmt.Errorf("%w: %q does not match its digest field", ErrCassetteCorpus, name)
		}

		p := c.Proposal
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrCassetteCorpus, name, err)
		}
		p.Clamp()
		p.Mode = domain.ModeReplay
		r.byDigest[c.Digest] = p
	}

	r.log.Info("cassette corpus loaded", "dir", dir, "cassettes", len(r.byDigest))
	return r, nil
}

// Describe reports the corpus size, which is the number an operator needs when
// a run comes back with more heuristic answers than expected.
func (r *Replay) Describe() string {
	return fmt.Sprintf("replay(%d cassettes)", r.Len())
}

// Len is the number of loaded cassettes.
func (r *Replay) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDigest)
}

// Diagnose returns the recorded proposal for this context, or ErrCassetteMiss.
//
// A hit still goes through finalize. The digest covers the rail set, so a
// recorded rail is offered by construction; re-checking costs nothing and means
// a corpus edited after recording cannot smuggle a rail past the tier.
func (r *Replay) Diagnose(_ context.Context, dc domain.DiagnosticContext) (domain.DiagnosticProposal, error) {
	digest := ContextDigest(dc)

	r.mu.RLock()
	p, ok := r.byDigest[digest]
	r.mu.RUnlock()
	if !ok {
		return domain.DiagnosticProposal{}, fmt.Errorf("%w: %s", ErrCassetteMiss, digest)
	}

	p.Mode = domain.ModeReplay
	p.LatencyMS = 0
	if err := finalize(&p, dc); err != nil {
		return domain.DiagnosticProposal{}, fmt.Errorf("agent replay: cassette %s: %w", digest, err)
	}
	return p, nil
}

// Record adds a proposal to the corpus for a --record run.
//
// The proposal is finalised before it is written, so an invalid one can never
// enter the corpus and surface later as a valid-looking replay. The write is a
// temp file plus rename, which on both POSIX and Windows is atomic within a
// directory: a reader loading the corpus concurrently sees either the old file
// or the new one, never a truncated one.
func (r *Replay) Record(dc domain.DiagnosticContext, p domain.DiagnosticProposal) error {
	if err := finalize(&p, dc); err != nil {
		return fmt.Errorf("agent replay: refusing to record an invalid proposal: %w", err)
	}

	digest := ContextDigest(dc)
	// Latency is a property of the run that produced the proposal, not of the
	// cassette, and keeping it would make recorded runs look slow on replay.
	p.LatencyMS = 0
	p.Mode = domain.ModeReplay

	body, err := json.MarshalIndent(Cassette{
		Digest:     digest,
		Context:    projectCassetteContext(dc),
		Proposal:   p,
		RecordedAt: r.clock.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("agent replay: encode cassette: %w", err)
	}
	if len(body) > maxCassetteBytes {
		return fmt.Errorf("agent replay: cassette %s is %d bytes, cap is %d", digest, len(body), maxCassetteBytes)
	}

	if err := r.writeAtomic(digest+cassetteExt, body); err != nil {
		return err
	}

	r.mu.Lock()
	r.byDigest[digest] = p
	r.mu.Unlock()
	return nil
}

func (r *Replay) writeAtomic(name string, body []byte) (err error) {
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return fmt.Errorf("agent replay: create cassette dir %q: %w", r.dir, err)
	}
	tmp, err := os.CreateTemp(r.dir, ".cassette-*.tmp")
	if err != nil {
		return fmt.Errorf("agent replay: create temp cassette: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		if rmErr := os.Remove(tmpName); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			r.log.Warn("orphaned temp cassette left on disk", "error", rmErr.Error())
		}
	}()

	if _, err := tmp.Write(body); err != nil {
		if cErr := tmp.Close(); cErr != nil {
			return fmt.Errorf("agent replay: write cassette: %w (close: %v)", err, cErr)
		}
		return fmt.Errorf("agent replay: write cassette: %w", err)
	}
	// Fsync before rename: without it a crash can leave a correctly named file
	// with no contents, which the next boot would reject as a corrupt corpus.
	if err := tmp.Sync(); err != nil {
		if cErr := tmp.Close(); cErr != nil {
			return fmt.Errorf("agent replay: sync cassette: %w (close: %v)", err, cErr)
		}
		return fmt.Errorf("agent replay: sync cassette: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent replay: close cassette: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(r.dir, name)); err != nil {
		return fmt.Errorf("agent replay: publish cassette: %w", err)
	}
	committed = true
	return nil
}

// projectCassetteContext mirrors the digest's trusted fields, and only those.
func projectCassetteContext(dc domain.DiagnosticContext) CassetteContext {
	return CassetteContext{
		ErrorCode:      normToken(dc.ErrorCode, maxCodeLen),
		Method:         normToken(dc.Method, maxCodeLen),
		IssuerKey:      normToken(dc.IssuerKey, maxIssuerLen),
		AmountBand:     normToken(dc.AmountBand, maxCodeLen),
		IsRecurring:    dc.IsRecurring,
		SessionActive:  dc.SessionActive,
		AttemptNumber:  bucketAttempt(dc.AttemptNumber),
		AvailableRails: normRails(dc.AvailableRails),
	}
}

// isDigest checks the shape of a SHA-256 hex string. It also keeps a filename
// derived from a digest free of path separators and traversal sequences.
func isDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

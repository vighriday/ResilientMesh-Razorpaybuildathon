package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/config"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/store"
)

// The exported run is the input to the published evidence page.
//
// It is a record of one real execution, not a fixture: every field below is
// read out of the running system's own PostgreSQL database at the moment the
// narration describes it. The page that consumes it re-verifies the audit chain
// in the reader's browser from the bytes in this file, which is only meaningful
// because those bytes are the ones the ledger actually hashed.
const dossierSchema = "resilientmesh.run.v1"

// maxExportedEntries bounds the ledger export. A published page that has to
// download an unbounded chain is a page that does not load; the chain a
// reviewer verifies is the whole chain of this run, which is a few hundred
// entries, and the cap exists so a long-running instance cannot change that.
const maxExportedEntries = 4000

type dossier struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generated_at"`
	Commit      string `json:"commit,omitempty"`

	Run        runMeta        `json:"run"`
	Incidents  []incidentView `json:"incidents"`
	States     []countRow     `json:"state_counts"`
	Tiers      []countRow     `json:"tier_mix"`
	Vetoes     []vetoRow      `json:"vetoes"`
	Economics  economics      `json:"economics"`
	Case       caseFile       `json:"case"`
	Chain      chainExport    `json:"chain"`
	Tamper     tamperExport   `json:"tamper"`
	Invariants []invariantRow `json:"invariants"`
	Narration  []record       `json:"narration"`
	Acts       []actMeta      `json:"acts"`

	// secrets never leave this process. It is lower-case so it cannot be
	// marshalled: a redaction list that serialises itself would publish the
	// exact values it exists to remove.
	secrets []string
}

type runMeta struct {
	Scenario      string  `json:"scenario"`
	Seed          int64   `json:"seed"`
	Rate          float64 `json:"rate"`
	TimeScale     float64 `json:"time_scale"`
	InferenceTier string  `json:"inference_tier"`
	InferenceWhy  string  `json:"inference_why"`
	Provider      string  `json:"provider"`
	Model         string  `json:"model"`
	BootSeconds   float64 `json:"boot_seconds"`
	ElapsedSecs   float64 `json:"elapsed_seconds"`
	MaxAttempts   int     `json:"max_attempts"`
}

type incidentView struct {
	ID          string `json:"id"`
	PaymentID   string `json:"payment_id"`
	Method      string `json:"method"`
	IssuerKey   string `json:"issuer_key"`
	ErrorCode   string `json:"error_code"`
	AmountPaisa int64  `json:"amount_paisa"`
	Amount      string `json:"amount"`
	State       string `json:"state"`
	Attempts    int    `json:"attempt_count"`
	Recurring   bool   `json:"is_recurring"`
	ReceivedAt  string `json:"received_at"`
}

type countRow struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type vetoRow struct {
	Invariant string `json:"invariant"`
	Count     int    `json:"count"`
	Prevents  string `json:"prevents"`
}

type economics struct {
	RecoveredPaisa int64  `json:"recovered_paisa"`
	FeesPaisa      int64  `json:"fees_paisa"`
	Recovered      string `json:"recovered"`
	Fees           string `json:"fees"`
	// RatioNote is prose rather than a number because the ratio is only
	// meaningful alongside the window it was measured over, and a bare multiple
	// invites being quoted without it.
	RatioNote string `json:"ratio_note"`
}

// caseFile is one incident followed the whole way through, which is the view
// that answers "would you trust it" — a summary can hide a gap between two
// components, an ordered trail of that incident's own ledger rows cannot.
type caseFile struct {
	Incident incidentView          `json:"incident"`
	Timeline []caseEvent           `json:"timeline"`
	Attempts []attemptView         `json:"attempts"`
	Mandate  *domain.MandateRecord `json:"mandate,omitempty"`
}

type caseEvent struct {
	Seq     int64           `json:"seq"`
	Kind    string          `json:"kind"`
	Actor   string          `json:"actor"`
	At      string          `json:"at"`
	Summary string          `json:"summary"`
	Detail  json.RawMessage `json:"detail"`
	Hash    string          `json:"hash"`
}

type attemptView struct {
	Number    int    `json:"attempt_number"`
	Action    string `json:"action"`
	Rail      string `json:"rail"`
	Succeeded bool   `json:"succeeded"`
	Fee       string `json:"fee"`
	ErrorCode string `json:"error_code,omitempty"`
	StartedAt string `json:"started_at"`
}

// chainExport carries the exact bytes the ledger hashed.
//
// Detail travels base64-encoded rather than as embedded JSON because the digest
// commits to bytes, and any re-serialisation — key order, whitespace, escaping —
// would produce a different preimage and make independent verification fail for
// a reason that has nothing to do with tampering. AtUnixNano is a string for the
// same class of reason: it exceeds 2^53, so a JSON number would be silently
// rounded by every reader that parses into a float.
type chainExport struct {
	Genesis    string       `json:"genesis"`
	Count      int          `json:"count"`
	Head       string       `json:"head"`
	Valid      bool         `json:"valid"`
	Truncated  bool         `json:"truncated"`
	Algorithm  string       `json:"algorithm"`
	FieldOrder []string     `json:"field_order"`
	Entries    []chainEntry `json:"entries"`
}

type chainEntry struct {
	Seq        int64  `json:"seq"`
	IncidentID string `json:"incident_id"`
	Kind       string `json:"kind"`
	Actor      string `json:"actor"`
	// DetailB64 is the only copy of the detail column in this export. Carrying
	// a decoded one beside it would double the size of the document and, worse,
	// would let a page display one thing while verifying another; a reader
	// decodes this field and sees exactly the bytes the digest commits to.
	DetailB64  string `json:"detail_b64"`
	AtUnixNano string `json:"at_unix_nano"`
	At         string `json:"at"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
	Summary    string `json:"summary"`
}

type tamperExport struct {
	TargetSeq   int64  `json:"target_seq"`
	DetectedSeq int64  `json:"detected_seq"`
	Cause       string `json:"cause"`
	ValidBefore bool   `json:"valid_before"`
	ValidAfter  bool   `json:"valid_after"`
}

type invariantRow struct {
	Name     string `json:"name"`
	Prevents string `json:"prevents"`
	Fired    int    `json:"fired"`
}

type actMeta struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
}

// nullJSON stands in for a detail column that is not valid JSON. It cannot
// normally happen — the column is jsonb — but a page that renders whatever it
// is handed must not be given a fragment that breaks its parser.
var nullJSON = json.RawMessage("null")

func detailOrNull(b []byte) json.RawMessage {
	if !json.Valid(b) {
		return nullJSON
	}
	return json.RawMessage(b)
}

// captureChain reads the whole ledger and re-derives every digest.
//
// The recomputation is not redundant with the ledger's own Verify: it is what
// guarantees the exported bytes are the preimage, so a reader who recomputes
// them and disagrees has found a real problem rather than an export bug.
func captureChain(ctx context.Context, pg *store.Postgres) (chainExport, error) {
	out := chainExport{
		Genesis:   domain.GenesisHash,
		Algorithm: "sha256, each field absorbed as an 8-byte big-endian length followed by its bytes",
		FieldOrder: []string{
			"seq (uint64)", "incident_id", "kind", "actor",
			"detail (raw bytes)", "at (unix nanoseconds, uint64)", "prev_hash",
		},
		Valid: true,
	}
	prev := domain.GenesisHash
	err := pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		out.Count++
		if len(out.Entries) >= maxExportedEntries {
			out.Truncated = true
			return nil
		}
		if !e.VerifyAgainst(prev) {
			out.Valid = false
		}
		prev = e.Hash
		out.Entries = append(out.Entries, chainEntry{
			Seq:        e.Seq,
			IncidentID: e.IncidentID,
			Kind:       string(e.Kind),
			Actor:      e.Actor,
			DetailB64:  base64.StdEncoding.EncodeToString(e.Detail),
			AtUnixNano: strconv.FormatInt(e.At.UTC().UnixNano(), 10),
			At:         e.At.UTC().Format(time.RFC3339Nano),
			PrevHash:   e.PrevHash,
			Hash:       e.Hash,
			Summary:    summarise(e),
		})
		return nil
	})
	if err != nil {
		return chainExport{}, fmt.Errorf("exporting the audit chain: %w", err)
	}
	out.Head = prev
	return out, nil
}

// captureCase picks the incident with the richest trail and follows it.
//
// Richest rather than first: an incident that was received and immediately
// closed has a two-row history that demonstrates nothing, and the point of this
// section is to show a decision, a deferral or a refusal, an execution and an
// outcome as one ordered sequence.
func captureCase(ctx context.Context, pg *store.Postgres) (caseFile, error) {
	incidents, err := pg.ListIncidents(ctx, 200)
	if err != nil {
		return caseFile{}, fmt.Errorf("reading incidents: %w", err)
	}
	var (
		best      caseFile
		bestScore int
	)
	for _, in := range incidents {
		entries, err := pg.ListAuditByIncident(ctx, in.ID)
		if err != nil {
			return caseFile{}, fmt.Errorf("reading the trail of %s: %w", in.ID, err)
		}
		attempts, err := pg.ListAttempts(ctx, in.ID)
		if err != nil {
			return caseFile{}, fmt.Errorf("reading attempts for %s: %w", in.ID, err)
		}
		// A recovered incident that actually executed something is the story
		// worth telling; ties break towards the longer trail.
		score := len(entries) + 3*len(attempts)
		if in.State == domain.IncidentRecovered {
			score += 10
		}
		if score <= bestScore {
			continue
		}
		c := caseFile{Incident: viewIncident(in)}
		for _, e := range entries {
			c.Timeline = append(c.Timeline, caseEvent{
				Seq: e.Seq, Kind: string(e.Kind), Actor: e.Actor,
				At:      e.At.UTC().Format(time.RFC3339),
				Summary: summarise(e), Detail: detailOrNull(e.Detail), Hash: e.Hash,
			})
		}
		for _, a := range attempts {
			c.Attempts = append(c.Attempts, attemptView{
				Number: a.AttemptNumber, Action: string(a.Action), Rail: string(a.Rail),
				Succeeded: a.Succeeded, Fee: formatPaisa(a.GatewayFeePaisa),
				ErrorCode: a.ErrorCode,
				StartedAt: a.StartedAt.UTC().Format(time.RFC3339),
			})
		}
		if in.SubscriptionID != "" {
			if m, err := pg.GetMandate(ctx, in.SubscriptionID); err == nil {
				c.Mandate = &m
			}
		}
		best, bestScore = c, score
	}
	return best, nil
}

func viewIncident(in domain.Incident) incidentView {
	return incidentView{
		ID: in.ID, PaymentID: in.PaymentID, Method: in.Method,
		IssuerKey: in.IssuerKey, ErrorCode: in.ErrorCode,
		AmountPaisa: in.AmountPaisa, Amount: formatPaisa(in.AmountPaisa),
		State: string(in.State), Attempts: in.AttemptCount,
		Recurring:  in.IsRecurring,
		ReceivedAt: in.ReceivedAt.UTC().Format(time.RFC3339),
	}
}

// captureInvariants lists every rule with how often it refused something.
//
// Rules that never fired are listed with a zero rather than omitted. A table of
// only the rules that triggered would let a reader assume the others are
// decorative; the zero is the claim that they were evaluated and had nothing to
// object to.
func captureInvariants(vetoes map[string]int) []invariantRow {
	names := make([]string, 0, len(invariantMeaning))
	for n := range invariantMeaning {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if vetoes[names[i]] != vetoes[names[j]] {
			return vetoes[names[i]] > vetoes[names[j]]
		}
		return names[i] < names[j]
	})
	out := make([]invariantRow, 0, len(names))
	for _, n := range names {
		out = append(out, invariantRow{Name: n, Prevents: invariantMeaning[n], Fired: vetoes[n]})
	}
	return out
}

// countRows renders a map in a caller-chosen order, then appends anything the
// caller did not anticipate rather than dropping it — a state the demo has
// never seen is exactly the thing a reader needs to be shown.
func countRows(m map[string]int, order []string) []countRow {
	out := make([]countRow, 0, len(m))
	seen := map[string]bool{}
	for _, k := range order {
		if n, ok := m[k]; ok {
			out = append(out, countRow{k, n})
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, countRow{k, m[k]})
	}
	return out
}

func vetoRowsExport(v map[string]int) []vetoRow {
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if v[names[i]] != v[names[j]] {
			return v[names[i]] > v[names[j]]
		}
		return names[i] < names[j]
	})
	out := make([]vetoRow, 0, len(names))
	for _, n := range names {
		out = append(out, vetoRow{Invariant: n, Count: v[n], Prevents: invariantMeaning[n]})
	}
	return out
}

func viewIncidents(in []domain.Incident, limit int) []incidentView {
	sort.Slice(in, func(i, j int) bool { return in[i].ReceivedAt.Before(in[j].ReceivedAt) })
	if len(in) > limit {
		in = in[:limit]
	}
	out := make([]incidentView, 0, len(in))
	for _, i := range in {
		out = append(out, viewIncident(i))
	}
	return out
}

// runMetaFrom records what produced this run, including the provider and model
// when a live one was used. The key itself is never read here: naming the model
// is what lets a reader reproduce the run, naming the key would publish it.
func runMetaFrom(cfg config.Config, opts options, tier, why string, boot float64) runMeta {
	m := runMeta{
		Scenario: opts.scenario, Seed: opts.seed, Rate: opts.rate,
		TimeScale: demoSpeed, InferenceTier: tier, InferenceWhy: why,
		BootSeconds: boot, MaxAttempts: cfg.MaxAttempts,
	}
	if cfg.LLMProvider != config.ProviderNone && cfg.LLMAPIKey != "" {
		m.Provider, m.Model = cfg.LLMProvider, cfg.LLMModel
	}
	return m
}

// minRedactable is the shortest value worth scrubbing. Redacting a short string
// would replace legitimate substrings all over the document; every credential
// this system generates is far longer than this.
const minRedactable = 12

// write serialises the run, then removes every secret from the bytes before
// they reach disk.
//
// The narration deliberately prints the per-run operator token, because a
// console nobody can open is not a console — but this file is written to be
// published, and a token in it would be published too. Redaction happens on the
// encoded bytes rather than field by field, so a value that reaches the
// document through a path nobody anticipated is still caught, and the result is
// checked afterwards: if a secret survives, the file is not written at all.
func (d *dossier) write(path string, secrets []string) error {
	if path == "" {
		return nil
	}
	if err := ensureDir(path); err != nil {
		return err
	}
	d.Schema = dossierSchema
	d.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the run: %w", err)
	}
	for _, secret := range secrets {
		for _, form := range encodedForms(secret) {
			body = bytes.ReplaceAll(body, form, []byte("[redacted]"))
		}
	}
	for _, secret := range secrets {
		for _, form := range encodedForms(secret) {
			if bytes.Contains(body, form) {
				return fmt.Errorf("refusing to write %s: a secret survived redaction", path)
			}
		}
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// encodedForms returns the ways a value can appear in a JSON document: as
// itself, and as whatever json.Marshal made of it once escaping was applied.
// A secret too short to scrub safely yields nothing, so the caller neither
// redacts it nor refuses to write because of it.
func encodedForms(secret string) [][]byte {
	if len(secret) < minRedactable {
		return nil
	}
	forms := [][]byte{[]byte(secret)}
	if quoted, err := json.Marshal(secret); err == nil && len(quoted) > 2 {
		escaped := quoted[1 : len(quoted)-1]
		if !bytes.Equal(escaped, []byte(secret)) {
			forms = append(forms, escaped)
		}
	}
	return forms
}

// gitCommit records which revision produced the run, so a published page can be
// tied back to the code that made it. A checkout without git is not an error.
func gitCommit(ctx context.Context) string {
	out, err := runTool(ctx, "git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// actsFrom recovers the act structure from the narration.
//
// Derived rather than tracked separately so the published page cannot disagree
// with the terminal about which act a line belongs to: there is one source for
// both, and it is the line that was actually printed.
func actsFrom(rec []record) []actMeta {
	seen := map[int]bool{}
	var out []actMeta
	for _, r := range rec {
		if r.Kind != kindHead || seen[r.Act] {
			continue
		}
		title := strings.TrimSpace(r.Text)
		if prefix := fmt.Sprintf("%d.", r.Act); strings.HasPrefix(title, prefix) {
			title = strings.TrimSpace(strings.TrimPrefix(title, prefix))
		}
		seen[r.Act] = true
		out = append(out, actMeta{Number: r.Act, Title: title})
	}
	return out
}

// refreshExport re-reads every aggregate at the end of the run.
//
// Each act reads only enough to justify the sentence it is about to print, and
// stops. That is right for a terminal, where the reader watches the rest happen,
// and wrong for a published document, where a table labelled "the failures that
// arrived" showing the first eight of eighty-one is misleading even though every
// row in it is true.
func refreshExport(ctx context.Context, d *dossier, pg *store.Postgres) error {
	incidents, err := pg.ListIncidents(ctx, 500)
	if err != nil {
		return fmt.Errorf("re-reading incidents: %w", err)
	}
	d.Incidents = viewIncidents(incidents, 60)

	tiers, err := tierMix(ctx, pg)
	if err != nil {
		return fmt.Errorf("re-reading the tier mix: %w", err)
	}
	d.Tiers = countRows(tiers, []string{"LIVE", "REPLAY", "HEURISTIC", "SKIPPED"})

	vetoes, err := vetoBreakdown(ctx, pg)
	if err != nil {
		return fmt.Errorf("re-reading the refusals: %w", err)
	}
	d.Vetoes = vetoRowsExport(vetoes)
	d.Invariants = captureInvariants(vetoes)

	st, err := stateCounts(ctx, pg)
	if err != nil {
		return fmt.Errorf("re-reading outcomes: %w", err)
	}
	d.States = countRows(st, []string{
		"RECOVERED", "SCHEDULED", "EXECUTING", "ABSTAINED", "RECEIVED", "FAILED"})

	recovered, fees, err := recoveredValue(ctx, pg)
	if err != nil {
		return fmt.Errorf("re-reading the economics: %w", err)
	}
	d.Economics = economics{
		RecoveredPaisa: recovered, FeesPaisa: fees,
		Recovered: formatPaisa(recovered), Fees: formatPaisa(fees),
		RatioNote: "measured over this run's window only; the four-policy " +
			"benchmark in eval/ is the comparison that controls for incident mix",
	}
	return nil
}

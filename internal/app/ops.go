package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
	"github.com/hriday/razorpay-resilient-mesh/internal/httpx"
	"github.com/hriday/razorpay-resilient-mesh/internal/obs"
	"github.com/hriday/razorpay-resilient-mesh/internal/queue"
)

// The operator surface is read-only by construction. Every mutating operation
// lives in meshctl, where it can require an explicit confirmation and write its
// intent to the ledger before acting. A console button that halts a mandate is
// one misclick from a revenue incident, and a browser is the wrong place to put
// that button.

// opsSummary is the shape web/console.js reads. Field names are part of the
// contract with that file; changing one here without changing it there produces
// a dashboard that silently renders em-dashes.
type opsSummary struct {
	IncidentsTotal     int            `json:"incidents_total"`
	IncidentsRecovered int            `json:"incidents_recovered"`
	OutboxPending      int            `json:"outbox_pending"`
	OutboxFailed       int            `json:"outbox_failed"`
	QueueLag           int64          `json:"queue_lag"`
	DeadLetters        int64          `json:"dead_letters"`
	SessionsLive       int            `json:"sessions_live"`
	InferenceTiers     map[string]int `json:"inference_tiers"`
}

func (a *App) opsMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sum := opsSummary{InferenceTiers: map[string]int{}}

	// The summary is assembled from whatever each source can answer. A single
	// unavailable dependency degrades one field rather than the whole page:
	// an operator during an incident needs the numbers that still work.
	incidents, err := a.pg.ListIncidents(ctx, opsListMax)
	if err != nil {
		a.log.Warn("ops summary could not read incidents", "error", err)
	} else {
		sum.IncidentsTotal = len(incidents)
		for _, in := range incidents {
			if in.State == domain.IncidentRecovered {
				sum.IncidentsRecovered++
			}
		}
	}

	if pending, failed, err := a.pg.OutboxDepth(ctx); err != nil {
		a.log.Warn("ops summary could not read outbox depth", "error", err)
	} else {
		sum.OutboxPending, sum.OutboxFailed = pending, failed
	}

	if lag, err := a.q.Lag(ctx, queue.GroupWorkers); err != nil {
		a.log.Warn("ops summary could not read queue lag", "error", err)
	} else {
		sum.QueueLag = lag
	}

	if dlq, err := a.q.DeadLetterDepth(ctx); err != nil {
		a.log.Warn("ops summary could not read the dead-letter depth", "error", err)
	} else {
		sum.DeadLetters = dlq
	}

	sum.SessionsLive = a.hub.Count()
	sum.InferenceTiers = a.tierDistribution(ctx)

	httpx.JSON(w, http.StatusOK, sum)
}

// tierDistribution counts which inference tier decided each recent incident.
//
// It is read from the audit ledger rather than from a counter, because a
// counter resets with the process and the question an operator is asking —
// "how much of this was the model and how much was the fallback?" — is about
// the incidents, not about this process's uptime.
func (a *App) tierDistribution(ctx context.Context) map[string]int {
	out := map[string]int{}
	entries, err := a.recentAudit(ctx, opsListMax)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.Kind != domain.AuditDiagnosis {
			continue
		}
		var d struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(e.Detail, &d); err != nil || d.Mode == "" {
			continue
		}
		out[d.Mode]++
	}
	return out
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

type telemetryRow struct {
	IssuerKey    string  `json:"issuer_key"`
	SuccessRate  float64 `json:"success_rate"`
	BaselineRate float64 `json:"baseline_rate"`
	Attempts     int     `json:"attempts"`
	BreakerState string  `json:"breaker_state"`
	Degraded     bool    `json:"degraded"`
}

func (a *App) opsTelemetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snaps, err := a.telemetry.SnapshotAll(ctx)
	if err != nil {
		a.log.Error("could not read telemetry", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	states, err := a.breaker.States(ctx)
	if err != nil {
		// A missing breaker view degrades the column rather than the endpoint.
		a.log.Warn("could not read breaker states", "error", err)
		states = map[string]domain.BreakerState{}
	}

	rows := make([]telemetryRow, 0, len(snaps))
	for _, s := range snaps {
		state := states[s.IssuerKey]
		if state == "" {
			state = domain.BreakerClosed
		}
		rows = append(rows, telemetryRow{
			IssuerKey:    s.IssuerKey,
			SuccessRate:  s.SuccessRate,
			BaselineRate: s.BaselineRate,
			Attempts:     s.Attempts,
			BreakerState: string(state),
			Degraded:     s.Degraded(),
		})
	}
	// Worst first: the row an operator needs is the one that is failing, and
	// making them scan an arbitrary order to find it wastes the seconds that
	// matter during an outage.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SuccessRate != rows[j].SuccessRate {
			return rows[i].SuccessRate < rows[j].SuccessRate
		}
		return rows[i].IssuerKey < rows[j].IssuerKey
	})
	httpx.JSON(w, http.StatusOK, map[string]any{"items": rows})
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

// incidentRow is the list projection. RawPayload is deliberately absent: it is
// the verbatim webhook body, it can carry customer contact details, and a
// console list has no use for it. The detail endpoint does not return it
// either; see opsIncidentDetail.
type incidentRow struct {
	ID            string               `json:"id"`
	PaymentID     string               `json:"payment_id"`
	OrderID       string               `json:"order_id"`
	IssuerKey     string               `json:"issuer_key"`
	ErrorCode     string               `json:"error_code"`
	AmountPaisa   int64                `json:"amount_paisa"`
	Currency      string               `json:"currency"`
	Method        string               `json:"method"`
	State         domain.IncidentState `json:"state"`
	AttemptCount  int                  `json:"attempt_count"`
	IsRecurring   bool                 `json:"is_recurring"`
	InferenceMode string               `json:"inference_mode,omitempty"`
	ReceivedAt    string               `json:"received_at"`
}

func (a *App) opsIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := clampLimit(r.URL.Query().Get("limit"))

	incidents, err := a.pg.ListIncidents(ctx, limit)
	if err != nil {
		a.log.Error("could not list incidents", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}

	// One ledger read serves every row's provenance. Querying per incident
	// would turn a 40-row page into 40 round trips, which is the classic way a
	// dashboard becomes the thing that takes the database down during an
	// incident.
	modes := a.inferenceModes(ctx)

	rows := make([]incidentRow, 0, len(incidents))
	for _, in := range incidents {
		rows = append(rows, incidentRow{
			ID:            in.ID,
			PaymentID:     in.PaymentID,
			OrderID:       in.OrderID,
			IssuerKey:     in.IssuerKey,
			ErrorCode:     in.ErrorCode,
			AmountPaisa:   in.AmountPaisa,
			Currency:      in.Currency,
			Method:        in.Method,
			State:         in.State,
			AttemptCount:  in.AttemptCount,
			IsRecurring:   in.IsRecurring,
			InferenceMode: modes[in.ID],
			ReceivedAt:    in.ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": rows})
}

func (a *App) inferenceModes(ctx context.Context) map[string]string {
	out := map[string]string{}
	entries, err := a.recentAudit(ctx, opsListMax)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.Kind != domain.AuditDiagnosis || e.IncidentID == "" {
			continue
		}
		var d struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(e.Detail, &d); err == nil && d.Mode != "" {
			out[e.IncidentID] = d.Mode
		}
	}
	return out
}

// incidentDetail is the explainability surface: the whole story of one
// incident, in the order it happened.
type incidentDetail struct {
	Incident incidentRow            `json:"incident"`
	Attempts []domain.AttemptRecord `json:"attempts"`
	Audit    []auditRow             `json:"audit"`
}

func (a *App) opsIncidentDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" || len(id) > 128 {
		httpx.Error(w, http.StatusBadRequest, httpx.CodeBadRequest)
		return
	}

	in, err := a.pg.GetIncident(ctx, id)
	if err != nil {
		notFoundOr(w, err, func(e error) { a.log.Error("could not read incident", "error", e) })
		return
	}
	attempts, err := a.pg.ListAttempts(ctx, id)
	if err != nil {
		a.log.Error("could not read attempts", "incident_id", id, "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	entries, err := a.ledger.List(ctx, id)
	if err != nil {
		a.log.Error("could not read the ledger for an incident", "incident_id", id, "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}

	var mode string
	for _, e := range entries {
		if e.Kind == domain.AuditDiagnosis {
			var d struct {
				Mode string `json:"mode"`
			}
			if err := json.Unmarshal(e.Detail, &d); err == nil {
				mode = d.Mode
			}
		}
	}

	httpx.JSON(w, http.StatusOK, incidentDetail{
		Incident: incidentRow{
			ID: in.ID, PaymentID: in.PaymentID, OrderID: in.OrderID,
			IssuerKey: in.IssuerKey, ErrorCode: in.ErrorCode,
			AmountPaisa: in.AmountPaisa, Currency: in.Currency, Method: in.Method,
			State: in.State, AttemptCount: in.AttemptCount, IsRecurring: in.IsRecurring,
			InferenceMode: mode,
			ReceivedAt:    in.ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
		Attempts: attempts,
		Audit:    auditRows(entries),
	})
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// auditRow renders a ledger entry for the console. Detail is passed through
// verbatim: it is written by this system, not by a client, and truncating it
// would make the console a less faithful view of the record than the record.
type auditRow struct {
	Seq        int64            `json:"seq"`
	Kind       domain.AuditKind `json:"kind"`
	IncidentID string           `json:"incident_id,omitempty"`
	Actor      string           `json:"actor"`
	Detail     json.RawMessage  `json:"detail,omitempty"`
	At         string           `json:"at"`
	PrevHash   string           `json:"prev_hash"`
	Hash       string           `json:"hash"`
}

func auditRows(entries []domain.AuditEntry) []auditRow {
	out := make([]auditRow, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditRow{
			Seq: e.Seq, Kind: e.Kind, IncidentID: e.IncidentID, Actor: e.Actor,
			Detail:   json.RawMessage(e.Detail),
			At:       e.At.UTC().Format("2006-01-02T15:04:05Z"),
			PrevHash: e.PrevHash, Hash: e.Hash,
		})
	}
	return out
}

func (a *App) opsAudit(w http.ResponseWriter, r *http.Request) {
	limit := clampLimit(r.URL.Query().Get("limit"))
	entries, err := a.recentAudit(r.Context(), limit)
	if err != nil {
		a.log.Error("could not read the ledger", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": auditRows(entries)})
}

// recentAudit returns the newest entries, newest first.
//
// The ledger streams forward from the genesis entry because that is the order
// verification needs, so "newest N" is a bounded tail kept during the walk
// rather than a reverse scan. The ring keeps the memory cost proportional to
// the page size instead of to the chain length: a console request must not be
// able to allocate the whole ledger.
func (a *App) recentAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = opsListDefault
	}
	ring := make([]domain.AuditEntry, 0, limit)
	err := a.pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if len(ring) < limit {
			ring = append(ring, e)
			return nil
		}
		copy(ring, ring[1:])
		ring[len(ring)-1] = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Reverse in place: newest first is what an operator scans.
	for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	return ring, nil
}

// opsAuditVerify walks the whole chain and recomputes every link.
//
// This is the endpoint that makes the ledger worth having. It re-derives each
// hash from the entry's own content and its predecessor rather than comparing a
// stored hash to itself, so a row edited directly in the database is detected
// at the sequence where it was edited.
func (a *App) opsAuditVerify(w http.ResponseWriter, r *http.Request) {
	report, err := a.ledger.Verify(r.Context())
	if err != nil {
		a.log.Error("could not verify the ledger", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	if !report.Valid {
		// Logged at error level because a broken chain is not a reporting
		// event, it is a security incident: everything after the break is
		// untrustworthy.
		a.log.Error("audit chain verification failed",
			"break_at_seq", report.BreakAtSeq, "cause", report.BreakCause)
	}
	httpx.JSON(w, http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// Downtime and the dead-letter queue
// ---------------------------------------------------------------------------

func (a *App) opsDowntime(w http.ResponseWriter, r *http.Request) {
	notices, err := a.downtime.Active(r.Context())
	if err != nil {
		a.log.Error("could not read the downtime view", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	lastPolled, active, pollErr := a.downtime.Health()
	body := map[string]any{
		"items":       notices,
		"active":      active,
		"last_polled": lastPolled.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if pollErr != nil {
		// Reported as a field rather than as a failed request: a stale view is
		// still the view recovery decisions were made against, and hiding it
		// would hide why those decisions looked wrong.
		body["stale"] = true
	}
	httpx.JSON(w, http.StatusOK, body)
}

func (a *App) opsDeadLetters(w http.ResponseWriter, r *http.Request) {
	limit := clampLimit(r.URL.Query().Get("limit"))
	items, err := a.q.ListDeadLetters(r.Context(), limit)
	if err != nil {
		a.log.Error("could not list dead letters", "error", err)
		httpx.Error(w, http.StatusServiceUnavailable, httpx.CodeUnavailable)
		return
	}
	depth, err := a.q.DeadLetterDepth(r.Context())
	if err != nil {
		a.log.Warn("could not read the dead-letter depth", "error", err)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "depth": depth})
}

// ---------------------------------------------------------------------------
// Prometheus exposition
// ---------------------------------------------------------------------------

// promMetrics renders the registry in the text exposition format.
//
// It is written here rather than in obs because the format is a transport
// concern: the registry's job is to hold numbers, and teaching it to speak
// Prometheus would make every consumer of the package depend on that choice.
func (a *App) promMetrics(w http.ResponseWriter, _ *http.Request) {
	snap := a.metr.Snapshot()
	var b strings.Builder

	writeSeries := func(kind string, names []string, value func(string) string) {
		for _, n := range names {
			metric := promName(n)
			fmt.Fprintf(&b, "# TYPE %s %s\n%s %s\n", metric, kind, metric, value(n))
		}
	}

	if counters, ok := snap["counters"].(map[string]uint64); ok {
		writeSeries("counter", sortedKeysU64(counters), func(n string) string {
			return strconv.FormatUint(counters[n], 10)
		})
	}
	if gauges, ok := snap["gauges"].(map[string]float64); ok {
		writeSeries("gauge", sortedKeysF64(gauges), func(n string) string {
			return strconv.FormatFloat(gauges[n], 'g', -1, 64)
		})
	}
	// Histograms are exposed as their summary statistics rather than as
	// buckets. The registry stores quantiles, and inventing bucket boundaries
	// here would publish numbers the process never measured.
	if hists, ok := snap["histograms"].(map[string]obs.HistogramSnapshot); ok {
		for _, n := range sortedKeysHist(hists) {
			h := hists[n]
			metric := promName(n)
			fmt.Fprintf(&b, "# TYPE %s_count counter\n%s_count %d\n", metric, metric, h.Count)
			fmt.Fprintf(&b, "# TYPE %s_sum gauge\n%s_sum %s\n", metric, metric,
				strconv.FormatFloat(h.Sum, 'g', -1, 64))
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// promName maps a dotted internal series name onto the Prometheus convention.
// The registry already bounds names to a printable character set, so this only
// has to translate separators.
func promName(n string) string {
	return "mesh_" + strings.NewReplacer(".", "_", "-", "_", ":", "_").Replace(n)
}

func sortedKeysU64(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysF64(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysHist(m map[string]obs.HistogramSnapshot) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

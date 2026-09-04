package store

import (
	"context"
	"fmt"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Deferred recovery lives here.
//
// The gatekeeper routinely returns a command with a delay: wait out an issuer
// outage, come back after a salary credit, respect the RBI cooling window.
// Something has to bring that work back, and before this file nothing did — the
// worker marked the incident SCHEDULED, acknowledged the message, and the
// retry was lost. A ledger recording a correct decision that never executed is
// the most expensive kind of wrong, because it looks right in every report.

const (
	// scheduleIncidentSQL records both the state and the due time in one
	// statement, so an incident can never be SCHEDULED with no schedule.
	scheduleIncidentSQL = `
UPDATE incidents
   SET state = 'SCHEDULED', scheduled_for = $2, updated_at = now()
 WHERE id = $1`

	// claimDueIncidentsSQL takes the due rows and clears their schedule in one
	// statement.
	//
	// FOR UPDATE SKIP LOCKED is what lets several workers sweep concurrently
	// without any of them waiting on another or any incident being claimed
	// twice. Clearing scheduled_for as part of the claim is what makes the
	// claim idempotent: a sweeper that crashes after committing has already
	// removed the row from the due set, and one that crashes before committing
	// has changed nothing.
	claimDueIncidentsSQL = `
UPDATE incidents
   SET scheduled_for = NULL, updated_at = now()
 WHERE id IN (
       SELECT id FROM incidents
        WHERE state = 'SCHEDULED'
          AND scheduled_for IS NOT NULL
          AND scheduled_for <= $1
        ORDER BY scheduled_for
        LIMIT $2
        FOR UPDATE SKIP LOCKED
 )
 RETURNING id, payment_id, order_id, subscription_id, event_id, amount_paisa,
           currency, method, issuer_key, error_code, state, attempt_count,
           is_recurring, raw_payload, received_at, updated_at`

	// dueIncidentCountSQL backs the operator view and the readiness signal. A
	// growing due backlog means the sweeper is not keeping up, which is
	// invisible from queue depth alone.
	dueIncidentCountSQL = `
SELECT count(*) FROM incidents
 WHERE state = 'SCHEDULED' AND scheduled_for IS NOT NULL AND scheduled_for <= $1`
)

// ScheduleIncident defers an incident until at.
//
// A due time in the past is rejected rather than accepted and swept
// immediately: it means a caller computed a delay wrongly, and turning that
// into an instant retry would hide the bug behind behaviour that looks fine.
func (p *Postgres) ScheduleIncident(ctx context.Context, id string, at time.Time) error {
	if err := checkText("id", id, 1, maxIdentifierLen); err != nil {
		return err
	}
	if at.IsZero() {
		return invalid("scheduled_for", "is required when scheduling an incident")
	}
	tag, err := p.pool.Exec(ctx, scheduleIncidentSQL, id, at.UTC())
	if err != nil {
		return classify("store: schedule incident", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: schedule incident: %w", ErrNotFound)
	}
	return nil
}

// ClaimDueIncidents takes up to limit incidents whose schedule has arrived.
//
// The returned incidents are owned by this caller: their schedule is cleared,
// so a second sweeper will not see them. If the caller then fails to re-queue
// one, the incident stays SCHEDULED with no due time and stops moving — which
// is why the worker re-queues inside the same loop iteration and logs loudly
// when it cannot.
func (p *Postgres) ClaimDueIncidents(ctx context.Context, now time.Time, limit int) ([]domain.Incident, error) {
	rows, err := p.pool.Query(ctx, claimDueIncidentsSQL, now.UTC(), boundLimit(limit, maxListLimit))
	if err != nil {
		return nil, classify("store: claim due incidents", err)
	}
	defer rows.Close()

	var out []domain.Incident
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, classify("store: claim due incidents", err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("store: claim due incidents", err)
	}
	return out, nil
}

// DueIncidentCount reports how many incidents are past due but not yet swept.
func (p *Postgres) DueIncidentCount(ctx context.Context, now time.Time) (int, error) {
	var n int
	if err := p.pool.QueryRow(ctx, dueIncidentCountSQL, now.UTC()).Scan(&n); err != nil {
		return 0, classify("store: count due incidents", err)
	}
	return n, nil
}

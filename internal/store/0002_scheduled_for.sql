-- ---------------------------------------------------------------------------
-- 0002_scheduled_for
-- ---------------------------------------------------------------------------
-- A recovery the gatekeeper defers has to come back. Before this column the
-- worker marked an incident SCHEDULED, acknowledged the message and returned,
-- with a comment claiming a scheduler would pick it up when due — and there was
-- no scheduler. Every delayed retry was silently dropped, which is the worst
-- shape a bug can take here: the ledger records a correct decision that never
-- happened.
--
-- The due time lives in the durable row rather than in a Redis delay queue
-- because the decision to retry is already committed in PostgreSQL. Splitting
-- the decision and its schedule across two stores would reintroduce exactly the
-- dual-write window the outbox exists to remove.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ;

-- Partial index: only scheduled rows are ever swept, and the sweep is a hot
-- path that runs every few seconds. Indexing the whole table would carry every
-- terminal incident forever for a query that can never match one.
CREATE INDEX IF NOT EXISTS incidents_due_idx
    ON incidents (scheduled_for)
    WHERE state = 'SCHEDULED' AND scheduled_for IS NOT NULL;

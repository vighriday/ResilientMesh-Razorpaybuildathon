-- ---------------------------------------------------------------------------
-- 0003_attempts_idempotent
-- ---------------------------------------------------------------------------
-- An attempt is identified by the incident it belongs to and its number within
-- that incident. Recording the same one twice is never correct: it double-counts
-- a gateway fee, inflates every recovery-rate measurement, and makes the
-- benchmark's economics wrong in the direction that flatters the system.
--
-- The write path is retried on purpose — losing the record of a debit is worse
-- than the debit — so the retry has to be safe. Before this constraint a failure
-- anywhere after the insert (telemetry, breaker, ledger, mandate update) caused
-- the whole block to run again and insert a second row for the same attempt.
--
-- Deterministic simulation found this, not review: the NO_DOUBLE_PROCESSING
-- invariant asserts one attempt per attempt number, and the fault injector
-- eventually failed a step after the insert. No unit test would have, because
-- each step is individually correct.
--
-- Duplicates are collapsed before the constraint is added, keeping the earliest
-- row: it is the one the rest of the system already reacted to.
DELETE FROM attempts a
      USING attempts b
      WHERE a.incident_id = b.incident_id
        AND a.attempt_number = b.attempt_number
        AND a.id > b.id;

ALTER TABLE attempts
    ADD CONSTRAINT attempts_incident_number_unique UNIQUE (incident_id, attempt_number);

package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinels the rest of the mesh is allowed to branch on. Driver errors are
// deliberately not part of the public surface: a caller that switched on
// pgx.ErrNoRows would silently stop working the day a query moved behind a
// cache or a read replica, and the ingest replay guard depends on telling
// "absent" apart from "broken" with certainty.
var (
	// ErrNotFound means the row does not exist. pgx.ErrNoRows never escapes
	// this package.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict means a uniqueness invariant rejected the write — most
	// importantly incidents(event_id), which is the webhook idempotency key.
	// Callers treat it as "someone else already did this", not as a failure.
	ErrConflict = errors.New("store: conflict")

	// ErrInvalidInput means the value was rejected before or by the database
	// constraints: over-long text, malformed JSON, a negative amount, an
	// unknown enum value, or a reference to a row that does not exist. The
	// store fails closed on anything it cannot represent exactly.
	ErrInvalidInput = errors.New("store: invalid input")
)

// classify maps a driver error onto a package sentinel while keeping the
// original in the chain for logs. PostgreSQL error messages for these classes
// name constraints and columns but never row values, so nothing here can leak
// a payload into an error string that ends up in a response or a log line.
func classify(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%s: %w: %w", op, ErrConflict, err)
		case "23503", // foreign_key_violation
			"23502", // not_null_violation
			"23514", // check_violation
			"22001", // string_data_right_truncation
			"22003", // numeric_value_out_of_range
			"22P02": // invalid_text_representation (malformed JSON reaching jsonb)
			return fmt.Errorf("%s: %w: %w", op, ErrInvalidInput, err)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// invalid builds an ErrInvalidInput without echoing the offending value, which
// may be attacker-controlled webhook text.
func invalid(field, why string) error {
	return fmt.Errorf("store: field %s %s: %w", field, why, ErrInvalidInput)
}

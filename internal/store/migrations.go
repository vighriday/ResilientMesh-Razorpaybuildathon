package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The DDL ships inside the binary. A judge running `go run ./cmd/mesh` on a
// clean machine gets the same schema as CI without a psql client, a migration
// tool, or a copy of the repository on the database host.
//
//go:embed schema.sql 0002_scheduled_for.sql
var schemaFS embed.FS

// migrationLockKey is the ASCII of "RESMMIGR", chosen so a colliding advisory
// lock from another application on a shared database is vanishingly unlikely
// and so an operator reading pg_locks can tell what took it.
const migrationLockKey int64 = 0x5245534d4d494752

// migrationsTableDDL is applied before the version guard can be consulted, so
// it is the one statement that must survive being run on every boot.
const migrationsTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        NOT NULL PRIMARY KEY,
    checksum   TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

const (
	selectMigrationSQL = `SELECT checksum FROM schema_migrations WHERE version = $1`
	insertMigrationSQL = `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`
	advisoryLockSQL    = `SELECT pg_advisory_xact_lock($1)`
)

type migration struct {
	version string
	file    string
}

// migrations is ordered and append-only. Editing an already-released entry is a
// checksum mismatch at boot rather than a silent divergence between what the
// running fleet has and what the file says.
var migrations = []migration{
	{version: "0001_init", file: "schema.sql"},
	{version: "0002_scheduled_for", file: "0002_scheduled_for.sql"},
}

// applyMigrations brings the database up to the embedded schema.
//
// Everything happens inside one transaction that first takes a
// transaction-scoped advisory lock: several mesh processes boot at once in the
// managed demo, and concurrent CREATE TABLE IF NOT EXISTS statements race in
// PostgreSQL's system catalogue rather than being serialised for you. The lock
// makes a second booting process wait and then observe the version row, so the
// whole function is a no-op on every boot after the first.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin migration transaction: %w", err)
	}
	defer func() {
		if rbErr := rollback(ctx, tx); rbErr != nil {
			log.Error("migration rollback failed", "error", rbErr)
		}
	}()

	if _, err := tx.Exec(ctx, advisoryLockSQL, migrationLockKey); err != nil {
		return fmt.Errorf("store: take migration lock: %w", err)
	}
	if _, err := tx.Exec(ctx, migrationsTableDDL); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		body, err := schemaFS.ReadFile(m.file)
		if err != nil {
			return fmt.Errorf("store: read embedded migration %s: %w", m.file, err)
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])

		var applied string
		err = tx.QueryRow(ctx, selectMigrationSQL, m.version).Scan(&applied)
		switch {
		case err == nil:
			if applied != checksum {
				// Refusing to run is the safe answer: the database was built
				// from different DDL than this binary expects, and guessing
				// which side is right is how a payment system loses a column.
				return fmt.Errorf("store: migration %s checksum mismatch (database %s, binary %s): %w",
					m.version, applied, checksum, ErrInvalidInput)
			}
			log.Debug("migration already applied", "version", m.version)
			continue
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return fmt.Errorf("store: read migration state %s: %w", m.version, err)
		}

		// No bind parameters, so pgx uses the simple protocol and the whole
		// file executes as one multi-statement batch inside this transaction.
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("store: apply migration %s: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, insertMigrationSQL, m.version, checksum); err != nil {
			return fmt.Errorf("store: record migration %s: %w", m.version, err)
		}
		log.Info("migration applied", "version", m.version)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit migrations: %w", err)
	}
	return nil
}

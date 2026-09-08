// Package db_test / helper: a tiny embedded migration runner so both the
// application (cmd/backend, future) and the integration tests below can
// apply migrations/*.up.sql without pulling in a full migration
// framework. This is intentionally minimal — no down-migration runner —
// but it DOES track which migrations have already been applied, via a
// `schema_migrations` tracking table (see ApplyMigrations' own doc
// comment), so repeat calls against an already-migrated database are
// safe no-ops instead of re-running DDL that has already run.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFS embed.FS

// createSchemaMigrationsTableSQL creates the version-tracking table
// ApplyMigrations uses to decide which migrations/*.up.sql files still
// need to run. It is created idempotently (IF NOT EXISTS) as the very
// first thing ApplyMigrations does, on every call, so it works
// identically whether called against a genuinely fresh database or one
// already bootstrapped by an OLDER version of this function that never
// created this table at all (see the backfill logic below).
const createSchemaMigrationsTableSQL = `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`

// ApplyMigrations executes every migrations/*.up.sql file, in filename
// (numeric-prefix) order, against pool, recording each applied
// filename as a row in `schema_migrations` so repeat calls are safe,
// idempotent no-ops for migrations that have already run — this was
// previously not true (calling this twice against the same database
// used to fail loudly with an "already exists" error on every
// statement, since nothing tracked what had already run).
//
// Backward compatibility for a pre-existing, untracked database (one
// bootstrapped by the OLD, non-tracking version of this function,
// which has some/all migrations' real schema objects but no
// schema_migrations rows for them at all): for each migration not yet
// recorded, ApplyMigrations attempts to apply it inside a transaction
// as normal. If that fails specifically because the underlying
// object(s) already exist (Postgres error code 42P07
// "duplicate_table", detected via pgconn.PgError, with an "already
// exists" substring match as a fallback), that is treated as evidence
// this migration was already applied by the old, untracked code path:
// the failed transaction is rolled back, and a backfill row for that
// version is inserted into schema_migrations (in its own small
// transaction) instead of treating it as a hard error. Any OTHER
// error (syntax error, missing dependency, etc.) on a migration that
// was never applied still causes ApplyMigrations to return a real
// error, unchanged from before.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, createSchemaMigrationsTableSQL); err != nil {
		return fmt.Errorf("db: creating schema_migrations table: %w", err)
	}

	applied, err := appliedMigrationVersions(ctx, pool)
	if err != nil {
		return err
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("db: reading migrations dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if applied[name] {
			continue
		}

		contents, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("db: reading migration %s: %w", name, err)
		}

		// Same established transaction pattern as Repository.InsertShare
		// (see repository.go): pool.Begin / tx.Exec / tx.Commit with a
		// deferred tx.Rollback as a safety net for any early return.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("db: applying migration %s: beginning transaction: %w", name, err)
		}

		if _, execErr := tx.Exec(ctx, string(contents)); execErr != nil {
			_ = tx.Rollback(ctx)
			if isAlreadyExistsError(execErr) {
				// Backfill case: this migration's schema objects already
				// exist, so it must have been applied by the old,
				// untracked code path. Record it as applied (in its own
				// small transaction) and move on to the next migration
				// rather than treating this as a hard failure.
				if err := backfillMigrationVersion(ctx, pool, name); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("db: applying migration %s: %w", name, execErr)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("db: applying migration %s: recording schema_migrations row: %w", name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("db: applying migration %s: committing transaction: %w", name, err)
		}
	}
	return nil
}

// appliedMigrationVersions returns the set of `version` values already
// present in schema_migrations, keyed for O(1) membership checks
// against migrations/*.up.sql filenames.
func appliedMigrationVersions(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("db: reading schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("db: scanning schema_migrations row: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating schema_migrations rows: %w", err)
	}
	return applied, nil
}

// backfillMigrationVersion records name as already-applied in
// schema_migrations, in its own small transaction, for the
// untracked-pre-existing-database backfill path described in
// ApplyMigrations' doc comment.
func backfillMigrationVersion(ctx context.Context, pool *pgxpool.Pool, name string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: backfilling schema_migrations row for %s: beginning transaction: %w", name, err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return fmt.Errorf("db: backfilling schema_migrations row for %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: backfilling schema_migrations row for %s: committing transaction: %w", name, err)
	}
	return nil
}

// isAlreadyExistsError reports whether err is a Postgres error
// indicating some object a migration tried to create already exists
// (SQLSTATE 42P07 "duplicate_table", or the analogous "already
// exists" text as a fallback for any other duplicate-object error
// class Postgres might report here) — the signal ApplyMigrations uses
// to detect a migration that was already applied by the old,
// untracked code path.
func isAlreadyExistsError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "42P07" {
			return true
		}
	}
	return strings.Contains(err.Error(), "already exists")
}

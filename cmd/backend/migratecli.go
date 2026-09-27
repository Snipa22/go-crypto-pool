// Manual, ops-triggered "migrate" subcommand for the backend binary:
//
//	backend migrate apply [-dsn=...]
//
// This wraps the EXISTING real db.ApplyMigrations helper (see
// internal/backend/db/migrate.go), which today is only ever called
// from test setup (internal/backend/db/integration_test.go,
// stats_integration_test.go) -- there is no runtime path that applies
// migrations/*.up.sql against a real deployment's database at all.
// Operators have had to reach for some other migration tool (or a
// manual psql invocation of the *.up.sql files themselves) just to
// bootstrap a fresh database for this backend. This file adds no new
// write path to the schema; it is strictly a CLI entrypoint onto the
// same ApplyMigrations function the integration tests already
// exercise, applying migrations/*.up.sql (in filename/numeric-prefix
// order) against whatever database -dsn/GCPOOL_DB_DSN points at.
//
// ApplyMigrations now tracks applied migrations via a
// `schema_migrations` table (see its own doc comment) and is safe to
// re-run: only genuinely new/unapplied migrations get executed, and
// running this command again against an already-migrated database is
// a no-op, not an error. Pre-existing databases bootstrapped by an
// older, untracked version of ApplyMigrations are backfilled
// automatically the first time this command runs against them.
// There is deliberately no -yes flag here, unlike
// retentioncli.go/blockcli.go's destructive-write commands: applying
// forward migrations to a fresh schema is the normal, expected
// bootstrap operation this command exists for, not a judgement call
// that needs a human dry-run gate first.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// migrateCLITimeout bounds every DB call the migrate subcommand makes
// (connect + applying every migrations/*.up.sql file) -- generous
// for a manual, one-off ops invocation against a real Postgres
// instance, but still bounded. Longer than blockCLITimeout since a
// full apply run touches the whole schema, not just one row.
const migrateCLITimeout = 2 * time.Minute

// runMigrateCommand dispatches `backend migrate <subcommand> ...`.
// args is os.Args with both "backend" and "migrate" already stripped
// off (i.e. args[0], if present, is the subcommand name: only
// "apply" today).
func runMigrateCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`migrate: missing subcommand, want "apply"`)
	}
	switch args[0] {
	case "apply":
		return runMigrateApply(args[1:])
	default:
		return fmt.Errorf(`migrate: unrecognized subcommand %q, want "apply"`, args[0])
	}
}

// runMigrateApply implements `migrate apply`: parse flags, connect
// to Postgres (using -dsn or GCPOOL_DB_DSN, matching run()'s own DSN
// resolution and blockcli.go/retentioncli.go's convention), and call
// the real db.ApplyMigrations against it.
func runMigrateApply(args []string) error {
	fs := flag.NewFlagSet("backend migrate apply", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend migrate apply [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dsn == "" {
		return errors.New("migrate apply: no DSN: pass -dsn or set GCPOOL_DB_DSN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), migrateCLITimeout)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{DSN: *dsn})
	if err != nil {
		return fmt.Errorf("migrate apply: connecting to database: %w", err)
	}
	defer pool.Close()

	log.Print("migrate apply: applying migrations/*.up.sql in filename order")
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		return fmt.Errorf("migrate apply: %w", err)
	}
	log.Print("migrate apply: done")
	return nil
}

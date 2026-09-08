package db_test

// Integration tests for db.ApplyMigrations' schema_migrations tracking
// (see migrate.go). Same GCPOOL_TEST_DSN opt-in convention, testPool/
// resetSchema helpers as integration_test.go — see that file's package
// doc comment.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// expectedMigrationCount counts the real migrations/*.up.sql files on
// disk so these tests stay correct as new migrations are added over
// time, instead of hardcoding a number that silently goes stale (this
// PR originally hardcoded 6 -- broke the moment two more migrations
// landed on main during rebase; count for real instead of guessing).
func expectedMigrationCount(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob("migrations/*.up.sql")
	if err != nil {
		t.Fatalf("globbing migrations/*.up.sql: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expectedMigrationCount: found zero migrations/*.up.sql files -- wrong working directory?")
	}
	return len(matches)
}

// TestIntegrationApplyMigrationsTwiceIsANoOp is the core regression
// test for the bug this package's migrate.go now fixes: calling
// ApplyMigrations a second time against an already-migrated database
// used to fail loudly ("relation ... already exists") because nothing
// tracked which migrations had already run. It must now succeed both
// times, without duplicating schema_migrations rows or re-creating any
// table.
func TestIntegrationApplyMigrationsTwiceIsANoOp(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations (first call): %v", err)
	}
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations (second call): %v", err)
	}

	var migrationCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("counting schema_migrations: %v", err)
	}
	if migrationCount != expectedMigrationCount(t) {
		t.Errorf("expected exactly %d schema_migrations rows (one per migration file), got %d", expectedMigrationCount(t), migrationCount)
	}

	// Re-running must not have re-created (or dropped) shares.
	var shareCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares").Scan(&shareCount); err != nil {
		t.Fatalf("counting shares after double-apply: %v", err)
	}
	if shareCount != 0 {
		t.Errorf("expected 0 rows in shares after double-apply on an otherwise-untouched schema, got %d", shareCount)
	}
}

// TestIntegrationApplyMigrationsBackfillsUntrackedDatabase simulates
// an old, already-migrated-but-untracked database: 0001's real schema
// objects exist (applied directly, bypassing ApplyMigrations
// entirely), but schema_migrations does not even exist yet. The FIRST
// call to the new, tracked ApplyMigrations must detect that 0001's
// objects already exist (rather than erroring out on "already
// exists"), backfill a schema_migrations row for it, and apply 0002
// through 0006 normally.
func TestIntegrationApplyMigrationsBackfillsUntrackedDatabase(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)

	// Simulate the old, untracked code path: apply ONLY 0001's raw SQL
	// directly, without going through db.ApplyMigrations and without
	// creating/touching schema_migrations at all.
	raw, err := os.ReadFile("migrations/0001_initial_schema.up.sql")
	if err != nil {
		t.Fatalf("reading migrations/0001_initial_schema.up.sql: %v", err)
	}
	if _, err := pool.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("applying 0001_initial_schema.up.sql directly: %v", err)
	}

	var schemaMigrationsExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations'
		)
	`).Scan(&schemaMigrationsExists); err != nil {
		t.Fatalf("checking schema_migrations existence before ApplyMigrations: %v", err)
	}
	if schemaMigrationsExists {
		t.Fatalf("schema_migrations must not exist yet at this point in the test")
	}

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations (first call, untracked pre-existing 0001): %v", err)
	}

	var migrationCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("counting schema_migrations: %v", err)
	}
	if migrationCount != expectedMigrationCount(t) {
		t.Errorf("expected exactly %d schema_migrations rows (1 backfilled + the rest freshly applied), got %d", expectedMigrationCount(t), migrationCount)
	}

	var version string
	if err := pool.QueryRow(ctx, "SELECT version FROM schema_migrations WHERE version = '0001_initial_schema.up.sql'").Scan(&version); err != nil {
		t.Errorf("expected a backfilled schema_migrations row for 0001_initial_schema.up.sql: %v", err)
	}

	// Spot-check that all 6 migrations' effects are present: 0001's
	// shares table, and 0006's network_state table (the last
	// migration, which should have been freshly applied for real).
	var sharesCount, networkStateCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares").Scan(&sharesCount); err != nil {
		t.Errorf("expected shares table to exist (from 0001): %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM network_state").Scan(&networkStateCount); err != nil {
		t.Errorf("expected network_state table to exist (freshly applied from 0006): %v", err)
	}
}

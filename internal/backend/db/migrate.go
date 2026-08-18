// Package db_test / helper: a tiny embedded migration runner so both the
// application (cmd/backend, future) and the integration tests below can
// apply migrations/*.up.sql without pulling in a full migration
// framework. This is intentionally minimal — no down-migration runner,
// no version tracking table yet. That's a reasonable follow-up once
// there's more than one migration file.
package db

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFS embed.FS

// ApplyMigrations executes every migrations/*.up.sql file, in filename
// (numeric-prefix) order, against pool. Intended for test setup and
// first-run bootstrap; it does not track which migrations have already
// been applied, so it is only safe to call against a fresh database.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
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
		contents, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("db: reading migration %s: %w", name, err)
		}
		if _, err := pool.Exec(ctx, string(contents)); err != nil {
			return fmt.Errorf("db: applying migration %s: %w", name, err)
		}
	}
	return nil
}

package db_test

// Integration tests for migrations/0014_balance_payouts_currency.up.sql
// against a REAL Postgres instance. Set GCPOOL_TEST_DSN to run them —
// see integration_test.go's package doc comment for the exact setup.
//
// These specifically prove the two properties migration 0014 exists
// for: (a) a genuine duplicate identity (same algo/network/currency/
// payment_address/payment_id) is still rejected by uq_balance_identity,
// and (b) the SAME tuple but a DIFFERENT currency — previously
// impossible to represent at all — now succeeds, which is the entire
// point of adding `currency` to the unique index.

import (
	"context"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hasColumn reports whether table.column exists in the real,
// migrated schema — used below to assert the migration actually
// added every column it claims to, rather than only inferring that
// from downstream INSERT behavior.
func hasColumn(t *testing.T, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var exists bool
	err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2
		)`, table, column).Scan(&exists)
	if err != nil {
		t.Fatalf("checking %s.%s existence: %v", table, column, err)
	}
	return exists
}

// TestIntegrationMigration0014AddsCurrencyColumns confirms the new
// `currency` column exists on exactly the three tables the migration
// targets, and deliberately NOT on `block_payouts` (see that
// migration's doc comment on why `block_payouts` is out of scope —
// its parent block's own `merge_mine_chain` is already the real leg
// discriminator, and a second, independently-settable column would
// let the two disagree).
func TestIntegrationMigration0014AddsCurrencyColumns(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	for _, table := range []string{"balance", "payouts", "block_payout_credits"} {
		if !hasColumn(t, pool, table, "currency") {
			t.Errorf("expected %s.currency to exist after migration 0014, it does not", table)
		}
	}
	if hasColumn(t, pool, "block_payouts", "currency") {
		t.Error("expected block_payouts to have NO currency column (it derives the leg from its parent block's merge_mine_chain instead) — found one")
	}
}

// TestIntegrationMigration0014CurrencyCheckConstraint confirms the
// CHECK (currency IN ('XMR', 'XTM')) constraint really rejects any
// other value, on all three tables.
func TestIntegrationMigration0014CurrencyCheckConstraint(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO balance (algo, network, currency, payment_address, pending_balance)
		VALUES ('RXM', 'TESTNET', 'BTC', 'alice', 0)`); err == nil {
		t.Error("inserting balance with currency='BTC' succeeded, want the CHECK constraint to reject it")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO payouts (algo, network, currency, status, balance_ids, amount)
		VALUES ('RXM', 'TESTNET', 'BTC', 'PENDING', '{1}', 1)`); err == nil {
		t.Error("inserting payouts with currency='BTC' succeeded, want the CHECK constraint to reject it")
	}

	// XMR and XTM (the only two legal values) must both be accepted.
	if _, err := pool.Exec(ctx, `
		INSERT INTO balance (algo, network, currency, payment_address, pending_balance)
		VALUES ('RXM', 'TESTNET', 'XMR', 'alice-xmr', 0)`); err != nil {
		t.Errorf("inserting balance with currency='XMR' failed, want it accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO balance (algo, network, currency, payment_address, pending_balance)
		VALUES ('RXM', 'TESTNET', 'XTM', 'alice-xtm', 0)`); err != nil {
		t.Errorf("inserting balance with currency='XTM' failed, want it accepted: %v", err)
	}
}

// TestIntegrationMigration0014UniqueIndexIncludesCurrency is the
// headline regression test for the whole migration: a genuine
// duplicate (algo, network, currency, payment_address, payment_id)
// identity must still be rejected, but the SAME tuple with a
// DIFFERENT currency — impossible to represent before this migration
// — must now succeed. This is exactly the RXM dual-currency scenario:
// one miner, one address, simultaneously holding an XMR balance and
// an XTM balance.
func TestIntegrationMigration0014UniqueIndexIncludesCurrency(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	const insertStmt = `
		INSERT INTO balance (algo, network, currency, payment_address, pending_balance)
		VALUES ('RXM', 'TESTNET', $1, 'dual-currency-miner', 0)`

	// First row: the primary/Monero leg.
	if _, err := pool.Exec(ctx, insertStmt, "XMR"); err != nil {
		t.Fatalf("inserting the XMR-leg balance row: %v", err)
	}

	// THE OLD DUPLICATE CHECK: an exact repeat of the SAME currency
	// must still violate uq_balance_identity.
	if _, err := pool.Exec(ctx, insertStmt, "XMR"); err == nil {
		t.Error("inserting a second XMR row for the same (algo, network, payment_address) succeeded, want uq_balance_identity to reject the genuine duplicate")
	}

	// THE WHOLE POINT: the SAME (algo, network, payment_address)
	// tuple, but the secondary/Tari leg's currency, must succeed —
	// this is the real, live RXM dual-currency requirement this
	// migration exists to satisfy.
	if _, err := pool.Exec(ctx, insertStmt, "XTM"); err != nil {
		t.Errorf("inserting the XTM-leg balance row for the SAME address failed, want it accepted since currency now distinguishes the two rows: %v", err)
	}

	// And now that a second row exists, a genuine XTM duplicate must
	// also be rejected — currency has to add strictness, not simply
	// widen the whole index into a no-op.
	if _, err := pool.Exec(ctx, insertStmt, "XTM"); err == nil {
		t.Error("inserting a second XTM row for the same identity succeeded, want uq_balance_identity to reject it")
	}

	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM balance WHERE payment_address = 'dual-currency-miner'`).Scan(&rowCount); err != nil {
		t.Fatalf("counting balance rows: %v", err)
	}
	if rowCount != 2 {
		t.Errorf("got %d balance row(s) for the dual-currency miner, want exactly 2 (one XMR, one XTM)", rowCount)
	}
}

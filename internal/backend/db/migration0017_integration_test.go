package db_test

// Integration test for migrations/0017_multicoin_currencies.up.sql
// against a REAL Postgres instance. Set GCPOOL_TEST_DSN to run it —
// see integration_test.go's package doc comment for the exact setup.
//
// This is the required regression test for fix #2 in payoutbrief.md:
// before migration 0017, a CreditBalance call using any of the 7 new
// standalone coins' own tickers as currency (e.g. currency="ARQ")
// failed with a real CHECK-constraint violation (balance_currency_check
// only accepted 'XMR'/'XTM') — this proves that call now succeeds for
// EVERY internal/coinprofile.Registry ticker, and that a genuinely
// unknown currency ("BTC") still correctly fails.

import (
	"context"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
)

// TestIntegrationMigration0017WidensCurrencyCheckConstraint is the
// headline regression test: it would have caught the original gap
// (before this dispatch, this test fails with a CHECK-constraint
// violation for every one of the 7 new tickers).
func TestIntegrationMigration0017WidensCurrencyCheckConstraint(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	for _, profile := range coinprofile.Registry {
		algo := profile.Ticker
		if err := repo.CreditBalance(ctx, algo, "TESTNET", algo, "miner-"+algo, nil, 12345); err != nil {
			t.Errorf("CreditBalance(algo=%s, currency=%s): %v, want it to succeed now that migration 0017 widened the CHECK constraint", algo, algo, err)
			continue
		}

		var pending int64
		var currency string
		if err := pool.QueryRow(ctx, `
			SELECT pending_balance, currency FROM balance WHERE algo = $1 AND network = 'TESTNET' AND payment_address = $2`,
			algo, "miner-"+algo).Scan(&pending, &currency); err != nil {
			t.Fatalf("querying balance row for %s: %v", algo, err)
		}
		if pending != 12345 || currency != algo {
			t.Errorf("balance row for %s: got pending_balance=%d currency=%q, want 12345/%q", algo, pending, currency, algo)
		}
	}

	// A genuinely unrecognized currency must still be rejected at
	// both the Go-level ValidateCurrency guard CreditBalance calls
	// and (defense in depth) the real CHECK constraint.
	if err := repo.CreditBalance(ctx, "ARQ", "TESTNET", "BTC", "someone", nil, 1); err == nil {
		t.Error("CreditBalance(currency=BTC) succeeded, want it rejected")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO balance (algo, network, currency, payment_address, pending_balance)
		VALUES ('ARQ', 'TESTNET', 'BTC', 'raw-insert-someone', 0)`); err == nil {
		t.Error("raw INSERT with currency='BTC' succeeded, want the widened CHECK constraint to still reject unknown currencies")
	}
}

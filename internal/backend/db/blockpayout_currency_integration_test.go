package db_test

// Integration test proving the core behavior the RXM currency
// dimension exists for (migrations/0014_balance_payouts_currency.up.sql):
// a single matured ALGO_RXM block's payout run credits the currency
// implied by that block's own `merge_mine_chain` column, and two
// DIFFERENT blocks (one primary/Monero leg, one secondary/Tari leg)
// crediting the SAME payment address land on two DISTINCT `balance`
// rows — one currency='XMR', one currency='XTM' — rather than
// commingling into one number the way this schema used to before
// migration 0014 added the `currency` column.
//
// This is deliberately a real Postgres integration test, not a
// mocked-repository unit test: the property being asserted is that
// ApplyBlockPayout's own SQL (see internal/backend/db/blockpayout.go's
// blockPayoutCurrency/creditBlockPayoutEntry) derives currency
// correctly from the real `blocks` row and that uq_balance_identity
// really does keep the two currencies' balance rows separate — both
// are database properties a mock would simply assume away.

import (
	"context"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insertRXMBlock inserts one ALGO_RXM `blocks` row with an explicit
// merge_mine_chain value (nil for the primary/Monero leg, "TARI" for
// the secondary/Tari leg — see migrations/0012_blocks_merge_mine_chain.up.sql),
// mirroring insertTestBlock but adding the one column that test
// helper leaves at its NULL default.
func insertRXMBlock(t *testing.T, pool *pgxpool.Pool, hash string, mergeMineChain *string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO blocks (algo, network, pool_type, hash, height, difficulty, shares, block_timestamp, unlocked, valid, value, merge_mine_chain)
		VALUES ('RXM', 'TESTNET', 'PPS', $1, $2, 1000, 10, 1700000000, FALSE, TRUE, 600000000000, $3)
		RETURNING id`, hash, testBlockHeight, mergeMineChain).Scan(&id)
	if err != nil {
		t.Fatalf("inserting RXM test block %s: %v", hash, err)
	}
	return id
}

// TestIntegrationRXMBlockPayoutCreditsCorrectCurrency is the required,
// explicit, non-trivial test for the core behavior this whole change
// exists for: an RXM primary-leg (Monero) block's payout credit lands
// on the currency='XMR' balance row, and an RXM secondary-leg (Tari)
// block's payout credit for the SAME payment address lands on a
// SEPARATE currency='XTM' balance row — not the same row, and not
// commingled into one number.
func TestIntegrationRXMBlockPayoutCreditsCorrectCurrency(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const minerAddress = "rxm-dual-leg-miner"

	// --- Primary/Monero leg: merge_mine_chain IS NULL -----------------
	primaryBlockID := insertRXMBlock(t, pool, "hash-rxm-primary", nil)
	primaryOutcome, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID:  primaryBlockID,
		Algo:     "RXM",
		Network:  "TESTNET",
		PoolType: "PPS",
		Height:   testBlockHeight,
		Reward:   600000000000,
		Credits: []db.BlockCredit{
			{PayoutBucket: "pps", PaymentAddress: minerAddress, Amount: 111111},
		},
	})
	if err != nil {
		t.Fatalf("ApplyBlockPayout (primary/Monero leg): %v", err)
	}
	if primaryOutcome.AlreadyApplied || primaryOutcome.Credited != 1 || primaryOutcome.TotalPaid != 111111 {
		t.Fatalf("ApplyBlockPayout (primary leg): got %+v, want a fresh run crediting 111111", primaryOutcome)
	}

	// --- Secondary/Tari leg: merge_mine_chain = 'TARI' ----------------
	secondaryBlockID := insertRXMBlock(t, pool, "hash-rxm-secondary", strPtr("TARI"))
	secondaryOutcome, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID:  secondaryBlockID,
		Algo:     "RXM",
		Network:  "TESTNET",
		PoolType: "PPS",
		Height:   testBlockHeight,
		Reward:   600000000000,
		Credits: []db.BlockCredit{
			{PayoutBucket: "pps", PaymentAddress: minerAddress, Amount: 222222},
		},
	})
	if err != nil {
		t.Fatalf("ApplyBlockPayout (secondary/Tari leg): %v", err)
	}
	if secondaryOutcome.AlreadyApplied || secondaryOutcome.Credited != 1 || secondaryOutcome.TotalPaid != 222222 {
		t.Fatalf("ApplyBlockPayout (secondary leg): got %+v, want a fresh run crediting 222222", secondaryOutcome)
	}

	// --- The actual assertion: two DISTINCT balance rows --------------
	rows, err := pool.Query(ctx, `
		SELECT currency, pending_balance FROM balance
		WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = $1
		ORDER BY currency ASC`, minerAddress)
	if err != nil {
		t.Fatalf("querying balance rows: %v", err)
	}
	defer rows.Close()

	byCurrency := map[string]int64{}
	for rows.Next() {
		var currency string
		var pending int64
		if err := rows.Scan(&currency, &pending); err != nil {
			t.Fatalf("scanning balance row: %v", err)
		}
		byCurrency[currency] = pending
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating balance rows: %v", err)
	}

	if len(byCurrency) != 2 {
		t.Fatalf("got %d distinct balance row(s) for %s, want exactly 2 (one XMR, one XTM): %+v", len(byCurrency), minerAddress, byCurrency)
	}
	if got := byCurrency["XMR"]; got != 111111 {
		t.Errorf("currency=XMR pending_balance = %d, want 111111 (the primary/Monero leg's credit, untouched by the Tari leg's)", got)
	}
	if got := byCurrency["XTM"]; got != 222222 {
		t.Errorf("currency=XTM pending_balance = %d, want 222222 (the secondary/Tari leg's credit, untouched by the Monero leg's)", got)
	}

	// --- block_payout_credits.currency was derived correctly too -----
	var primaryCurrency, secondaryCurrency string
	if err := pool.QueryRow(ctx, `SELECT currency FROM block_payout_credits WHERE block_id = $1`, primaryBlockID).Scan(&primaryCurrency); err != nil {
		t.Fatalf("querying primary leg's ledger currency: %v", err)
	}
	if primaryCurrency != "XMR" {
		t.Errorf("primary leg's block_payout_credits.currency = %q, want XMR", primaryCurrency)
	}
	if err := pool.QueryRow(ctx, `SELECT currency FROM block_payout_credits WHERE block_id = $1`, secondaryBlockID).Scan(&secondaryCurrency); err != nil {
		t.Fatalf("querying secondary leg's ledger currency: %v", err)
	}
	if secondaryCurrency != "XTM" {
		t.Errorf("secondary leg's block_payout_credits.currency = %q, want XTM", secondaryCurrency)
	}
}

// TestIntegrationNonRXMBlockPayoutAlwaysCreditsXTM confirms RXT/C29/
// SHA3X behavior is unaffected by the currency dimension: every
// credit for those algos lands on currency='XTM', regardless of
// merge_mine_chain (which is always NULL for them, unlike RXM).
func TestIntegrationNonRXMBlockPayoutAlwaysCreditsXTM(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	for _, algo := range []string{"RXT", "C29", "SHA3X"} {
		blockID := insertTestBlock(t, pool, algo, "TESTNET", "PPS", "hash-nonrxm-"+algo)
		outcome, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
			BlockID:  blockID,
			Algo:     algo,
			Network:  "TESTNET",
			PoolType: "PPS",
			Height:   testBlockHeight,
			Reward:   600000000000,
			Credits: []db.BlockCredit{
				{PayoutBucket: "pps", PaymentAddress: "miner-" + algo, Amount: 5000},
			},
		})
		if err != nil {
			t.Fatalf("ApplyBlockPayout (%s): %v", algo, err)
		}
		if outcome.TotalPaid != 5000 {
			t.Fatalf("ApplyBlockPayout (%s): got %+v, want TotalPaid=5000", algo, outcome)
		}

		var currency string
		if err := pool.QueryRow(ctx, `
			SELECT currency FROM balance WHERE algo = $1 AND network = 'TESTNET' AND payment_address = $2`,
			algo, "miner-"+algo).Scan(&currency); err != nil {
			t.Fatalf("querying %s balance currency: %v", algo, err)
		}
		if currency != "XTM" {
			t.Errorf("%s balance currency = %q, want XTM (non-RXM algos have no other leg)", algo, currency)
		}
	}
}

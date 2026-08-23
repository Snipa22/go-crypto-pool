package db_test

// Integration tests against a real Postgres instance. They are
// deliberately NOT run by default: `go test ./...` in a sandbox with no
// Postgres available must not fail. Set GCPOOL_TEST_DSN to a Postgres
// connection string (pointing at a scratch/throwaway database — these
// tests apply migrations and DROP TABLEs) to run them, e.g.:
//
//	export GCPOOL_TEST_DSN="postgres://postgres@127.0.0.1:5544/gcpool_test?sslmode=disable"
//	go test ./internal/backend/db/... -run Integration -v
//
// Verified manually in the implementing sandbox against a local
// pg-embedded Postgres 17.5 instance — see the PR description for the
// actual command transcript. CI/dev environments without Postgres will
// skip these tests (not fail them).

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("GCPOOL_TEST_DSN")
	if dsn == "" {
		t.Skip("GCPOOL_TEST_DSN not set; skipping Postgres integration test (see package doc)")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// resetSchema drops everything the migration creates, if present, so
// each test run starts from a clean slate.
func resetSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS ports CASCADE",
		"DROP TABLE IF EXISTS pools CASCADE",
		"DROP TABLE IF EXISTS payouts CASCADE",
		"DROP TABLE IF EXISTS balance CASCADE",
		"DROP TABLE IF EXISTS miner_identifiers CASCADE",
		"DROP TABLE IF EXISTS blocks CASCADE",
		"DROP TABLE IF EXISTS shares CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("resetSchema: %s: %v", stmt, err)
		}
	}
}

func TestIntegrationMigrationCreatesPartitionTree(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)

	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	// Expect: 1 top-level + 4 algo-level + 16 pool_type-level = 21
	// partitioned tables, all rooted at `shares`.
	var partitionedCount int
	err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_partitioned_table pt
		JOIN pg_class c ON c.oid = pt.partrelid
		WHERE c.relname = 'shares' OR c.relname LIKE 'shares_%'
	`).Scan(&partitionedCount)
	if err != nil {
		t.Fatalf("querying pg_partitioned_table: %v", err)
	}
	if partitionedCount != 21 {
		t.Errorf("expected 21 partitioned tables (1 + 4 + 16), got %d", partitionedCount)
	}

	// Every algo x pool_type combination should have at least the seed
	// height-range leaf partition.
	for _, algo := range db.ValidAlgos {
		for _, pt := range db.ValidPoolTypes {
			parts, err := db.ListHeightPartitions(ctx, pool, algo, pt)
			if err != nil {
				t.Fatalf("ListHeightPartitions(%s, %s): %v", algo, pt, err)
			}
			if len(parts) < 1 {
				t.Errorf("expected at least 1 height partition for %s/%s, got %d", algo, pt, len(parts))
			}
		}
	}

	// blocks table should exist and be unpartitioned.
	var isPartitioned bool
	err = pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_partitioned_table pt
			JOIN pg_class c ON c.oid = pt.partrelid
			WHERE c.relname = 'blocks'
		)
	`).Scan(&isPartitioned)
	if err != nil {
		t.Fatalf("checking blocks partitioning: %v", err)
	}
	if isPartitioned {
		t.Error("blocks table must NOT be partitioned, but pg_partitioned_table has an entry for it")
	}
}

func TestIntegrationInsertShareAndBlockAndPartitionPruning(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	repo := db.NewRepository(pool)

	samples := []db.Share{
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 50, Shares: 1000, PaymentAddress: "addr-rxt-low", Identifier: "worker-1", Timestamp: 1700000000},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 250000, Shares: 1000, PaymentAddress: "addr-rxt-high", Identifier: "worker-2", Timestamp: 1700000001},
		{Algo: "C29", Network: "TESTNET", PoolType: "SOLO", PoolID: 2, BlockHeight: 500, Shares: 500, PaymentAddress: "addr-c29", Identifier: "worker-3", Timestamp: 1700000002},
	}
	for _, s := range samples {
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare(%+v): %v", s, err)
		}
	}

	if err := repo.InsertBlock(ctx, db.Block{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS",
		Hash: "0xabc", Height: 250000, Difficulty: 12345, Shares: 1000,
		Timestamp: 1700000003, Unlocked: false, Valid: true,
	}); err != nil {
		t.Fatalf("InsertBlock: %v", err)
	}

	var shareCount, blockCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares").Scan(&shareCount); err != nil {
		t.Fatalf("counting shares: %v", err)
	}
	if shareCount != len(samples) {
		t.Errorf("expected %d shares, got %d", len(samples), shareCount)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM blocks").Scan(&blockCount); err != nil {
		t.Fatalf("counting blocks: %v", err)
	}
	if blockCount != 1 {
		t.Errorf("expected 1 block, got %d", blockCount)
	}

	// InsertShare with a high height should have auto-created a new
	// height partition beyond the seed bucket.
	parts, err := db.ListHeightPartitions(ctx, pool, "RXT", "PPLNS")
	if err != nil {
		t.Fatalf("ListHeightPartitions: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected >= 2 height partitions for RXT/PPLNS after inserting height 250000, got %d: %+v", len(parts), parts)
	}

	// Partition pruning: a query filtered to the algo/pool_type/height
	// range that only touches the high bucket should not mention the low
	// bucket's partition (or the other algo/pool_type partitions) in the
	// plan.
	rows, err := pool.Query(ctx, `
		EXPLAIN SELECT * FROM shares
		WHERE algo = 'RXT' AND pool_type = 'PPLNS' AND block_height >= 200000 AND block_height < 300000
	`)
	if err != nil {
		t.Fatalf("EXPLAIN query: %v", err)
	}
	var planLines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatalf("scanning EXPLAIN line: %v", err)
		}
		planLines = append(planLines, line)
	}
	rows.Close()
	plan := strings.Join(planLines, "\n")

	if strings.Contains(plan, "shares_rxt_pplns_h000000000000") {
		t.Errorf("expected the low-height seed partition to be pruned from the plan, got:\n%s", plan)
	}
	if strings.Contains(plan, "shares_c29") {
		t.Errorf("expected C29 partitions to be pruned entirely from the plan, got:\n%s", plan)
	}
	if !strings.Contains(plan, "shares_rxt_pplns_h000000200000") {
		t.Errorf("expected the target height-200000 bucket partition to appear in the plan, got:\n%s", plan)
	}
}

func TestIntegrationDropOldPartitions(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	repo := db.NewRepository(pool)

	// One share in the seed bucket (height < 100000), one share well
	// beyond it (height >= 500000, forces creation of a new partition).
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "PROP", PoolID: 3,
		BlockHeight: 10, Shares: 1, PaymentAddress: "old-addr", Identifier: "old-worker",
		Timestamp: 1700000010,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (old): %v", err)
	}
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "PROP", PoolID: 3,
		BlockHeight: 500010, Shares: 1, PaymentAddress: "new-addr", Identifier: "new-worker",
		Timestamp: 1700000011,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (new): %v", err)
	}

	before, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "PROP")
	if err != nil {
		t.Fatalf("ListHeightPartitions before drop: %v", err)
	}
	if len(before) < 2 {
		t.Fatalf("expected >= 2 partitions before drop, got %d", len(before))
	}

	// Drop everything strictly below height 100000 - should remove only
	// the seed bucket (and its one row), leaving the new-address row
	// intact.
	dropped, err := db.DropOldPartitions(ctx, pool, "SHA3X", "PROP", 100000)
	if err != nil {
		t.Fatalf("DropOldPartitions: %v", err)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected exactly 1 partition dropped, got %d: %v", len(dropped), dropped)
	}

	var remainingOld, remainingNew int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares WHERE payment_address = 'old-addr'").Scan(&remainingOld); err != nil {
		t.Fatalf("counting old-addr shares: %v", err)
	}
	if remainingOld != 0 {
		t.Errorf("expected old-addr rows to be gone after DropOldPartitions, found %d", remainingOld)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares WHERE payment_address = 'new-addr'").Scan(&remainingNew); err != nil {
		t.Fatalf("counting new-addr shares: %v", err)
	}
	if remainingNew != 1 {
		t.Errorf("expected new-addr row to survive DropOldPartitions untouched, found %d", remainingNew)
	}

	after, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "PROP")
	if err != nil {
		t.Fatalf("ListHeightPartitions after drop: %v", err)
	}
	if len(after) != len(before)-1 {
		t.Errorf("expected partition count to drop by exactly 1 (from %d), got %d", len(before), len(after))
	}
}

// TestIntegrationDisbursementLifecycle exercises the real
// PayableBalances -> RecordPendingPayout -> CompletePayoutSent/
// FailPayout flow internal/backend/disburse.Engine drives, against a
// real Postgres transaction (CompletePayoutSent's atomic debit +
// payouts-row update).
func TestIntegrationDisbursementLifecycle(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	repo := db.NewRepository(pool)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 1000); err != nil {
		t.Fatalf("CreditBalance(alice): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "bob", nil, 50); err != nil {
		t.Fatalf("CreditBalance(bob): %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 1 || payable[0].PaymentAddress != "alice" {
		t.Fatalf("PayableBalances(min=100): got %+v, want exactly alice (bob is below the threshold)", payable)
	}

	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", []int64{payable[0].ID}, payable[0].PendingBalance)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}

	var status string
	if err := pool.QueryRow(ctx, "SELECT status FROM payouts WHERE id = $1", payoutID).Scan(&status); err != nil {
		t.Fatalf("querying payout status: %v", err)
	}
	if status != "PENDING" {
		t.Fatalf("got payout status %q immediately after RecordPendingPayout, want PENDING", status)
	}

	if err := repo.CompletePayoutSent(ctx, payoutID, []db.DisburseEntry{{BalanceID: payable[0].ID, Amount: payable[0].PendingBalance}}, "deadbeeftxhash", 42); err != nil {
		t.Fatalf("CompletePayoutSent: %v", err)
	}

	var pendingBalance, paidBalance int64
	if err := pool.QueryRow(ctx, "SELECT pending_balance, paid_balance FROM balance WHERE payment_address = 'alice'").Scan(&pendingBalance, &paidBalance); err != nil {
		t.Fatalf("querying alice's balance: %v", err)
	}
	if pendingBalance != 0 || paidBalance != 1000 {
		t.Errorf("got pending_balance=%d paid_balance=%d, want 0/1000 after CompletePayoutSent", pendingBalance, paidBalance)
	}

	var txHash string
	var fee int64
	if err := pool.QueryRow(ctx, "SELECT status, tx_hash, fee FROM payouts WHERE id = $1", payoutID).Scan(&status, &txHash, &fee); err != nil {
		t.Fatalf("querying completed payout row: %v", err)
	}
	if status != "SENT" || txHash != "deadbeeftxhash" || fee != 42 {
		t.Errorf("got status=%q tx_hash=%q fee=%d, want SENT/deadbeeftxhash/42", status, txHash, fee)
	}

	// bob is still owed 50 and never touched by the above -- a second,
	// separate cycle attempt for him that fails must not touch his
	// balance at all.
	payoutID2, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", []int64{payable[0].ID + 1}, 50)
	if err != nil {
		t.Fatalf("RecordPendingPayout(bob): %v", err)
	}
	if err := repo.FailPayout(ctx, payoutID2, "not enough unlocked money"); err != nil {
		t.Fatalf("FailPayout(bob): %v", err)
	}
	var bobPending int64
	if err := pool.QueryRow(ctx, "SELECT pending_balance FROM balance WHERE payment_address = 'bob'").Scan(&bobPending); err != nil {
		t.Fatalf("querying bob's balance: %v", err)
	}
	if bobPending != 50 {
		t.Errorf("got bob's pending_balance=%d after a FAILED payout, want it untouched at 50", bobPending)
	}
	var failStatus, failErr string
	if err := pool.QueryRow(ctx, "SELECT status, error FROM payouts WHERE id = $1", payoutID2).Scan(&failStatus, &failErr); err != nil {
		t.Fatalf("querying failed payout row: %v", err)
	}
	if failStatus != "FAILED" || failErr != "not enough unlocked money" {
		t.Errorf("got status=%q error=%q, want FAILED/\"not enough unlocked money\"", failStatus, failErr)
	}
}

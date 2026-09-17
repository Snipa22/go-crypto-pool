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
	"time"

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
		"DROP TABLE IF EXISTS motd CASCADE",
		"DROP TABLE IF EXISTS users CASCADE",
		"DROP TABLE IF EXISTS schema_migrations CASCADE",
		"DROP TABLE IF EXISTS network_state CASCADE",
		"DROP TABLE IF EXISTS address_flags CASCADE",
		"DROP TABLE IF EXISTS address_map CASCADE",
		"DROP TABLE IF EXISTS ports CASCADE",
		"DROP TABLE IF EXISTS pools CASCADE",
		"DROP TABLE IF EXISTS payouts CASCADE",
		"DROP TABLE IF EXISTS block_payout_credits CASCADE",
		"DROP TABLE IF EXISTS block_payouts CASCADE",
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

	// Every real share InsertShare accepted above must have populated
	// (not left empty) the matching miner_identifiers row, with
	// last_share set from that share's own timestamp — this is the
	// gap this test now covers: miner_identifiers previously had
	// schema but no writer.
	var identifierCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM miner_identifiers").Scan(&identifierCount); err != nil {
		t.Fatalf("counting miner_identifiers: %v", err)
	}
	if identifierCount != len(samples) {
		t.Errorf("expected %d miner_identifiers rows (one per distinct identity), got %d", len(samples), identifierCount)
	}

	var lastShare time.Time
	if err := pool.QueryRow(ctx, `
		SELECT last_share FROM miner_identifiers
		WHERE algo = 'RXT' AND network = 'TESTNET' AND payment_address = 'addr-rxt-low' AND worker_name = 'worker-1'
	`).Scan(&lastShare); err != nil {
		t.Fatalf("querying miner_identifiers last_share: %v", err)
	}
	if !lastShare.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Errorf("expected last_share = %v, got %v", time.Unix(1700000000, 0).UTC(), lastShare)
	}

	// A second, later share from the same identity must advance
	// last_share (upsert, not a duplicate row); an out-of-order
	// earlier share must NOT regress it backwards.
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
		BlockHeight: 50, Shares: 1000, PaymentAddress: "addr-rxt-low",
		Identifier: "worker-1", Timestamp: 1700000100,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (later, same identity): %v", err)
	}
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
		BlockHeight: 50, Shares: 1000, PaymentAddress: "addr-rxt-low",
		Identifier: "worker-1", Timestamp: 1699999999, // earlier than the first share
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (out-of-order, same identity): %v", err)
	}

	if err := pool.QueryRow(ctx, "SELECT count(*) FROM miner_identifiers").Scan(&identifierCount); err != nil {
		t.Fatalf("counting miner_identifiers after repeat shares: %v", err)
	}
	if identifierCount != len(samples) {
		t.Errorf("expected repeat shares from the same identity to upsert (still %d rows), got %d", len(samples), identifierCount)
	}
	if err := pool.QueryRow(ctx, `
		SELECT last_share FROM miner_identifiers
		WHERE algo = 'RXT' AND network = 'TESTNET' AND payment_address = 'addr-rxt-low' AND worker_name = 'worker-1'
	`).Scan(&lastShare); err != nil {
		t.Fatalf("querying miner_identifiers last_share after repeat shares: %v", err)
	}
	if !lastShare.Equal(time.Unix(1700000100, 0).UTC()) {
		t.Errorf("expected last_share advanced to the newest share's timestamp %v, got %v (out-of-order share must not regress it)", time.Unix(1700000100, 0).UTC(), lastShare)
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
	dropped, skipped, err := db.DropOldPartitions(ctx, pool, "SHA3X", "PROP", 100000)
	if err != nil {
		t.Fatalf("DropOldPartitions: %v", err)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected exactly 1 partition dropped, got %d: %v", len(dropped), dropped)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected 0 partitions skipped (no unresolved blocks exist), got %d: %+v", len(skipped), skipped)
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

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "alice", nil, 1000); err != nil {
		t.Fatalf("CreditBalance(alice): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "bob", nil, 50); err != nil {
		t.Fatalf("CreditBalance(bob): %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 1 || payable[0].PaymentAddress != "alice" {
		t.Fatalf("PayableBalances(min=100): got %+v, want exactly alice (bob is below the threshold)", payable)
	}

	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", "XMR",
		[]db.DisburseEntry{{BalanceID: payable[0].ID, Amount: payable[0].PendingBalance}}, payable[0].PendingBalance)
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
	payoutID2, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", "XMR",
		[]db.DisburseEntry{{BalanceID: payable[0].ID + 1, Amount: 50}}, 50)
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

// TestIntegrationPayableBalancesForcePayoutOverride is the direct
// repository-level regression test for the bug fixed by this
// change: a below-minPayout balance row flagged force_payout=TRUE
// must be returned by PayableBalances anyway, while an
// otherwise-identical below-minPayout row with force_payout=FALSE
// must NOT be.
func TestIntegrationPayableBalancesForcePayoutOverride(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Both rows are below the minPayout=100 threshold used below.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "forced-below", nil, 40); err != nil {
		t.Fatalf("CreditBalance(forced-below): %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "forced-below", nil); err != nil {
		t.Fatalf("SetForcePayout(forced-below): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "not-forced-below", nil, 40); err != nil {
		t.Fatalf("CreditBalance(not-forced-below): %v", err)
	}
	// A normal, above-threshold row for good measure -- must also be
	// returned, unaffected by any of the above.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "normal-above", nil, 500); err != nil {
		t.Fatalf("CreditBalance(normal-above): %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	byAddr := map[string]db.PayableBalance{}
	for _, p := range payable {
		byAddr[p.PaymentAddress] = p
	}
	if _, ok := byAddr["not-forced-below"]; ok {
		t.Errorf("PayableBalances: got a below-minPayout, non-force_payout row included: %+v", payable)
	}
	forced, ok := byAddr["forced-below"]
	if !ok {
		t.Fatalf("PayableBalances: expected the below-minPayout force_payout=TRUE row to be included, got %+v", payable)
	}
	if !forced.ForcePayout {
		t.Errorf("PayableBalances: got ForcePayout=false for the forced row, want true: %+v", forced)
	}
	normal, ok := byAddr["normal-above"]
	if !ok {
		t.Fatalf("PayableBalances: expected the normal above-threshold row to still be included, got %+v", payable)
	}
	if normal.ForcePayout {
		t.Errorf("PayableBalances: got ForcePayout=true for a row never flagged, want false: %+v", normal)
	}
	if len(payable) != 2 {
		t.Fatalf("PayableBalances: got %d rows, want exactly 2 (forced-below, normal-above)", len(payable))
	}

	// minPayout <= 0 must still return every positive-balance row
	// regardless of force_payout -- the override is additive, not a
	// replacement for the existing "no minimum" behavior.
	all, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 0)
	if err != nil {
		t.Fatalf("PayableBalances(min=0): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("PayableBalances(min=0): got %d rows, want all 3 positive-balance rows", len(all))
	}
}

// TestIntegrationPayableBalancesExcludesEmptyAddressRows is the
// direct repository-level regression test for
// PROD_HARDENING_REVIEW.md finding #10's defense-in-depth clause: a
// balance row with payment_address = ” (however it got there --
// e.g. a pre-fix donation misconfiguration) must never be returned
// by PayableBalances, no matter how large its pending_balance or
// whether it is force_payout-flagged, since real WalletClient
// implementations reject an empty destination address and fail the
// WHOLE batch it's co-mixed into (see wallet/monero_rpc.go's
// Transfer).
func TestIntegrationPayableBalancesExcludesEmptyAddressRows(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// The empty-address row: force_payout=TRUE and a large balance,
	// so if the empty-address exclusion clause were missing, this
	// row would otherwise clearly qualify. Repository.SetForcePayout
	// itself refuses an empty address (defense in depth at that
	// layer too), so this sets the column directly via raw SQL to
	// simulate a pre-existing row that predates that validation
	// (exactly the scenario this defense-in-depth clause exists
	// for).
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "", nil, 1_000_000); err != nil {
		t.Fatalf("CreditBalance(empty address): %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE balance SET force_payout = TRUE WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = ''`); err != nil {
		t.Fatalf("raw UPDATE force_payout for empty-address row: %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "real-address", nil, 500); err != nil {
		t.Fatalf("CreditBalance(real-address): %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 0)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	for _, p := range payable {
		if p.PaymentAddress == "" {
			t.Fatalf("PayableBalances: got an empty-address row included: %+v", payable)
		}
	}
	if len(payable) != 1 || payable[0].PaymentAddress != "real-address" {
		t.Fatalf("PayableBalances: got %+v, want exactly the real-address row", payable)
	}
}

// TestIntegrationBalancePendingBalanceCannotGoNegative is the direct
// regression test for PROD_HARDENING_REVIEW.md finding #20's
// `CHECK (pending_balance >= 0)` constraint (see
// migrations/0011_balance_nonnegative_check.up.sql): a raw UPDATE
// that would drive pending_balance negative must be REJECTED by
// Postgres itself, not silently applied.
func TestIntegrationBalancePendingBalanceCannotGoNegative(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "double-debit-victim", nil, 100); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}

	// Simulate a double-debit bug: debit MORE than the row's current
	// pending_balance via the exact same raw SQL shape
	// completePayoutSent uses (see repository.go).
	_, err := pool.Exec(ctx, `UPDATE balance SET pending_balance = pending_balance - 200 WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = 'double-debit-victim'`)
	if err == nil {
		t.Fatal("expected the CHECK (pending_balance >= 0) constraint to reject a debit driving pending_balance negative, got no error")
	}
	if !strings.Contains(err.Error(), "balance_pending_balance_nonnegative") {
		t.Errorf("expected the error to reference the balance_pending_balance_nonnegative constraint, got: %v", err)
	}

	// The row must be untouched (the whole statement rolled back),
	// not partially applied.
	var pending int64
	if err := pool.QueryRow(ctx, `SELECT pending_balance FROM balance WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = 'double-debit-victim'`).Scan(&pending); err != nil {
		t.Fatalf("querying pending_balance after rejected update: %v", err)
	}
	if pending != 100 {
		t.Errorf("pending_balance after rejected update = %d, want unchanged 100", pending)
	}
}

// TestIntegrationPendingBalanceTotals is the direct repository-level
// test for PendingBalanceTotals (PROD_HARDENING_REVIEW.md finding
// #19's outstanding-pending_balance gauge source): it must sum
// positive pending_balance rows grouped by (algo, network), and never
// return a zero/negative-only group at all.
func TestIntegrationPendingBalanceTotals(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "addr-1", nil, 100); err != nil {
		t.Fatalf("CreditBalance(addr-1): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "addr-2", nil, 250); err != nil {
		t.Fatalf("CreditBalance(addr-2): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXT", "MAINNET", "XTM", "addr-3", nil, 42); err != nil {
		t.Fatalf("CreditBalance(addr-3): %v", err)
	}
	// A zero-balance row (e.g. fully paid out) must not contribute a
	// spurious (algo, network) entry.
	if err := repo.CreditBalance(ctx, "C29", "MAINNET", "XTM", "addr-4", nil, 0); err != nil {
		t.Fatalf("CreditBalance(addr-4, zero): %v", err)
	}

	totals, err := repo.PendingBalanceTotals(ctx)
	if err != nil {
		t.Fatalf("PendingBalanceTotals: %v", err)
	}
	byKey := map[string]int64{}
	for _, tt := range totals {
		byKey[tt.Algo+"/"+tt.Network] = tt.Total
	}
	if byKey["RXM/TESTNET"] != 350 {
		t.Errorf("RXM/TESTNET total = %d, want 350", byKey["RXM/TESTNET"])
	}
	if byKey["RXT/MAINNET"] != 42 {
		t.Errorf("RXT/MAINNET total = %d, want 42", byKey["RXT/MAINNET"])
	}
	if _, ok := byKey["C29/MAINNET"]; ok {
		t.Errorf("expected no C29/MAINNET entry for an all-zero-balance group, got %d", byKey["C29/MAINNET"])
	}
	if len(totals) != 2 {
		t.Fatalf("PendingBalanceTotals: got %d groups, want exactly 2: %+v", len(totals), totals)
	}
}

// TestIntegrationCompletePayoutSentForcePayoutFeeLedgerAndReset
// exercises CompletePayoutSent's new force_payout_fee_atomic
// accounting: the fee portion of a batch containing both a
// force_payout row and a normal row lands in the payouts row's
// force_payout_fee_atomic column (summed across just the forced
// entries), the forced row's balance has force_payout reset back to
// FALSE (the flag is consumed, not permanent), and the normal row's
// force_payout (already FALSE) and full accounting are untouched --
// all within the single real transaction CompletePayoutSent uses.
func TestIntegrationCompletePayoutSentForcePayoutFeeLedgerAndReset(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "forced", nil, 40); err != nil {
		t.Fatalf("CreditBalance(forced): %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "forced", nil); err != nil {
		t.Fatalf("SetForcePayout(forced): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", "normal", nil, 500); err != nil {
		t.Fatalf("CreditBalance(normal): %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	var forcedID, normalID int64
	for _, p := range payable {
		switch p.PaymentAddress {
		case "forced":
			forcedID = p.ID
		case "normal":
			normalID = p.ID
		}
	}
	if forcedID == 0 || normalID == 0 {
		t.Fatalf("PayableBalances: expected both forced and normal rows, got %+v", payable)
	}

	// The forced row's real Transfer destination amount was 40-10=30
	// (fee of 10 deducted); the debit still uses its FULL original
	// PendingBalance (40).
	entries := []db.DisburseEntry{
		{BalanceID: forcedID, Amount: 40, ForcePayout: true, ForcePayoutFeeAtomic: 10},
		{BalanceID: normalID, Amount: 500, ForcePayout: false, ForcePayoutFeeAtomic: 0},
	}

	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", "XMR", entries, 30+500)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.CompletePayoutSent(ctx, payoutID, entries, "txhash-forced-batch", 5); err != nil {
		t.Fatalf("CompletePayoutSent: %v", err)
	}

	// Forced row: full pending_balance debited, force_payout reset.
	var forcedPending, forcedPaid int64
	var forcedFlag bool
	if err := pool.QueryRow(ctx, "SELECT pending_balance, paid_balance, force_payout FROM balance WHERE id = $1", forcedID).
		Scan(&forcedPending, &forcedPaid, &forcedFlag); err != nil {
		t.Fatalf("querying forced balance: %v", err)
	}
	if forcedPending != 0 || forcedPaid != 40 {
		t.Errorf("forced balance: got pending=%d paid=%d, want 0/40", forcedPending, forcedPaid)
	}
	if forcedFlag {
		t.Errorf("forced balance: got force_payout=true after CompletePayoutSent, want it reset to false (flag consumed)")
	}

	// Normal row: untouched by any force-payout logic.
	var normalPending, normalPaid int64
	var normalFlag bool
	if err := pool.QueryRow(ctx, "SELECT pending_balance, paid_balance, force_payout FROM balance WHERE id = $1", normalID).
		Scan(&normalPending, &normalPaid, &normalFlag); err != nil {
		t.Fatalf("querying normal balance: %v", err)
	}
	if normalPending != 0 || normalPaid != 500 {
		t.Errorf("normal balance: got pending=%d paid=%d, want 0/500", normalPending, normalPaid)
	}
	if normalFlag {
		t.Errorf("normal balance: got force_payout=true, want false (was never set)")
	}

	// payouts row: real on-chain fee (5) and force_payout_fee_atomic
	// (10, summed across just the forced entry) are recorded
	// separately, never conflated.
	var status, txHash string
	var fee, forceFee int64
	if err := pool.QueryRow(ctx, "SELECT status, tx_hash, fee, force_payout_fee_atomic FROM payouts WHERE id = $1", payoutID).
		Scan(&status, &txHash, &fee, &forceFee); err != nil {
		t.Fatalf("querying payout row: %v", err)
	}
	if status != "SENT" || txHash != "txhash-forced-batch" {
		t.Errorf("got status=%q tx_hash=%q, want SENT/txhash-forced-batch", status, txHash)
	}
	if fee != 5 {
		t.Errorf("got real on-chain fee=%d, want 5 (unaffected by the force-payout fee)", fee)
	}
	if forceFee != 10 {
		t.Errorf("got force_payout_fee_atomic=%d, want 10 (only the forced entry's fee, summed)", forceFee)
	}
}

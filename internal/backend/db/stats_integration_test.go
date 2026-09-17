package db_test

// Integration tests for internal/backend/db/stats.go's read-only
// miner-stats queries. Same GCPOOL_TEST_DSN opt-in convention as
// integration_test.go — see that file's package doc comment.

import (
	"context"
	"fmt"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

func TestIntegrationMinerBalancesAndShareStats(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	repo := db.NewRepository(pool)
	pidA := "pid-a"

	// Credit balances across two algos/networks for the same address,
	// plus a second payment_id variant.
	if err := repo.CreditBalance(ctx, "RXT", "TESTNET", "XTM", "addr-1", nil, 1000); err != nil {
		t.Fatalf("CreditBalance RXT: %v", err)
	}
	if err := repo.CreditBalance(ctx, "C29", "TESTNET", "XTM", "addr-1", nil, 2000); err != nil {
		t.Fatalf("CreditBalance C29: %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXT", "TESTNET", "XTM", "addr-1", &pidA, 500); err != nil {
		t.Fatalf("CreditBalance RXT/pid-a: %v", err)
	}

	// --- MinerBalances ---
	all, err := repo.MinerBalances(ctx, "addr-1", "", "", nil)
	if err != nil {
		t.Fatalf("MinerBalances(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 balance rows for addr-1, got %d: %+v", len(all), all)
	}

	rxtOnly, err := repo.MinerBalances(ctx, "addr-1", "RXT", "", nil)
	if err != nil {
		t.Fatalf("MinerBalances(RXT): %v", err)
	}
	if len(rxtOnly) != 2 {
		t.Fatalf("expected 2 RXT balance rows for addr-1, got %d: %+v", len(rxtOnly), rxtOnly)
	}

	emptyPID, err := repo.MinerBalances(ctx, "addr-1", "RXT", "", ptr(""))
	if err != nil {
		t.Fatalf("MinerBalances(RXT, pid=''): %v", err)
	}
	if len(emptyPID) != 1 || emptyPID[0].PendingBalance != 1000 {
		t.Fatalf("expected 1 RXT row with empty payment_id and pending=1000, got %+v", emptyPID)
	}

	pidOnly, err := repo.MinerBalances(ctx, "addr-1", "RXT", "", &pidA)
	if err != nil {
		t.Fatalf("MinerBalances(RXT, pid=pid-a): %v", err)
	}
	if len(pidOnly) != 1 || pidOnly[0].PendingBalance != 500 {
		t.Fatalf("expected 1 RXT row with pid-a and pending=500, got %+v", pidOnly)
	}

	// --- ShareStatsSince / WorkerShareStatsSince ---
	shares := []db.Share{
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 100, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 1000},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 200, PaymentAddress: "addr-1", Identifier: "rig-2", Timestamp: 1500},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 999, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 500},  // too old, excluded by since=1000
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 300, PaymentAddress: "addr-2", Identifier: "rig-3", Timestamp: 1200}, // different address, excluded
		{Algo: "C29", Network: "TESTNET", PoolType: "SOLO", PoolID: 1, BlockHeight: 10, Shares: 400, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 1200},  // different algo, excluded from RXT query
	}
	for _, s := range shares {
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare(%+v): %v", s, err)
		}
	}

	stats, err := repo.ShareStatsSince(ctx, "RXT", "TESTNET", "addr-1", nil, 1000)
	if err != nil {
		t.Fatalf("ShareStatsSince: %v", err)
	}
	if stats.SharesSum != 300 || stats.ShareCount != 2 {
		t.Errorf("ShareStatsSince = %+v, want sum=300 count=2 (only the two >= ts=1000 addr-1/RXT rows)", stats)
	}

	workerResult, err := repo.WorkerShareStatsSince(ctx, "RXT", "TESTNET", "addr-1", nil, 1000)
	if err != nil {
		t.Fatalf("WorkerShareStatsSince: %v", err)
	}
	workers := workerResult.Rows
	if len(workers) != 2 {
		t.Fatalf("expected 2 worker rows, got %d: %+v", len(workers), workers)
	}
	if workerResult.Other != nil {
		t.Errorf("expected no Other bucket (only 2 distinct identifiers, well under the cap), got %+v", workerResult.Other)
	}
	// Ordered by SharesSum descending: rig-2 (200) before rig-1 (100).
	if workers[0].Identifier != "rig-2" || workers[0].SharesSum != 200 {
		t.Errorf("workers[0] = %+v, want rig-2/200", workers[0])
	}
	if workers[1].Identifier != "rig-1" || workers[1].SharesSum != 100 {
		t.Errorf("workers[1] = %+v, want rig-1/100", workers[1])
	}
}

func TestIntegrationMinerBalancesValidation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	if _, err := repo.MinerBalances(ctx, "", "", "", nil); err == nil {
		t.Error("expected error for empty payment_address")
	}
	if _, err := repo.MinerBalances(ctx, "addr-1", "BOGUS", "", nil); err == nil {
		t.Error("expected error for invalid algo filter")
	}
	if _, err := repo.MinerBalances(ctx, "addr-1", "", "BOGUS", nil); err == nil {
		t.Error("expected error for invalid network filter")
	}
	if _, err := repo.ShareStatsSince(ctx, "BOGUS", "TESTNET", "addr-1", nil, 0); err == nil {
		t.Error("expected error for invalid algo")
	}
	if _, err := repo.ShareStatsSince(ctx, "RXT", "BOGUS", "addr-1", nil, 0); err == nil {
		t.Error("expected error for invalid network")
	}
}

func ptr(s string) *string { return &s }

// TestIntegrationWorkerShareStatsSince_CardinalityCap is the
// regression test for the unbounded-GROUP-BY-cardinality DoS finding:
// with 150 distinct synthetic identifiers for one (algo, network,
// payment_address), WorkerShareStatsSince must return at most
// db.DefaultShareStatsCardinalityCap "kept" rows (exactly the
// highest-SharesSum identifiers, verified against the known synthetic
// data), plus one collapsed "Other" aggregate whose SharesSum/
// ShareCount/IdentifierCount exactly equal the sum/count/cardinality
// of every identifier beyond the cap.
func TestIntegrationWorkerShareStatsSince_CardinalityCap(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const numIdentifiers = 150
	const since = int64(1000)

	// identifierSharesSum[i] is a strictly decreasing function of i,
	// so ranking is meaningfully exercised (identifier "worker-000"
	// has the highest SharesSum, "worker-149" the lowest) rather than
	// happening to coincide with alphabetical order by chance. Each
	// identifier gets 2 share rows (varied share counts, not just
	// varied sums) that together sum to identifierSharesSum[i].
	identifierSharesSum := make([]int64, numIdentifiers)
	for i := 0; i < numIdentifiers; i++ {
		identifierSharesSum[i] = int64(10000 - i*50) // 10000, 9950, ..., 2550
	}

	for i := 0; i < numIdentifiers; i++ {
		identifier := fmt.Sprintf("worker-%03d", i)
		total := identifierSharesSum[i]
		firstHalf := total / 2
		secondHalf := total - firstHalf
		for _, sharesVal := range []int64{firstHalf, secondHalf} {
			s := db.Share{
				Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
				BlockHeight: 10, Shares: sharesVal, PaymentAddress: "addr-cap",
				Identifier: identifier, Timestamp: since + 1,
			}
			if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
				t.Fatalf("InsertShare(%s): %v", identifier, err)
			}
		}
	}

	result, err := repo.WorkerShareStatsSince(ctx, "RXT", "TESTNET", "addr-cap", nil, since)
	if err != nil {
		t.Fatalf("WorkerShareStatsSince: %v", err)
	}

	if len(result.Rows) != db.DefaultShareStatsCardinalityCap {
		t.Fatalf("got %d kept rows, want exactly the cap (%d)", len(result.Rows), db.DefaultShareStatsCardinalityCap)
	}

	// The kept rows must be exactly the top DefaultShareStatsCardinalityCap
	// identifiers by SharesSum descending -- i.e. worker-000..worker-099.
	for i, row := range result.Rows {
		wantIdentifier := fmt.Sprintf("worker-%03d", i)
		if row.Identifier != wantIdentifier {
			t.Errorf("kept row[%d].Identifier = %q, want %q", i, row.Identifier, wantIdentifier)
		}
		if row.SharesSum != identifierSharesSum[i] {
			t.Errorf("kept row[%d] (%s).SharesSum = %d, want %d", i, row.Identifier, row.SharesSum, identifierSharesSum[i])
		}
		if row.ShareCount != 2 {
			t.Errorf("kept row[%d] (%s).ShareCount = %d, want 2", i, row.Identifier, row.ShareCount)
		}
	}

	// Compute the expected remainder totals directly from the same
	// synthetic data set (everything beyond the cap: worker-100..worker-149).
	var wantOtherSum, wantOtherCount int64
	wantOtherIdentifiers := numIdentifiers - db.DefaultShareStatsCardinalityCap
	for i := db.DefaultShareStatsCardinalityCap; i < numIdentifiers; i++ {
		wantOtherSum += identifierSharesSum[i]
		wantOtherCount += 2
	}

	if result.Other == nil {
		t.Fatalf("expected a non-nil Other bucket (150 identifiers > cap of %d)", db.DefaultShareStatsCardinalityCap)
	}
	if result.Other.IdentifierCount != wantOtherIdentifiers {
		t.Errorf("Other.IdentifierCount = %d, want %d", result.Other.IdentifierCount, wantOtherIdentifiers)
	}
	if result.Other.SharesSum != wantOtherSum {
		t.Errorf("Other.SharesSum = %d, want %d", result.Other.SharesSum, wantOtherSum)
	}
	if result.Other.ShareCount != wantOtherCount {
		t.Errorf("Other.ShareCount = %d, want %d", result.Other.ShareCount, wantOtherCount)
	}
}

// TestIntegrationWorkerShareStatsSince_UnderCapNoCollapsing proves
// behavior is unchanged from before the cardinality-cap fix when the
// true distinct-identifier count is <= the cap: no spurious "Other"
// row, every identifier returned as its own kept row.
func TestIntegrationWorkerShareStatsSince_UnderCapNoCollapsing(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const numIdentifiers = 40 // well under DefaultShareStatsCardinalityCap
	for i := 0; i < numIdentifiers; i++ {
		s := db.Share{
			Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
			BlockHeight: 10, Shares: int64(1000 - i), PaymentAddress: "addr-nocap",
			Identifier: fmt.Sprintf("worker-%03d", i), Timestamp: 1000,
		}
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare: %v", err)
		}
	}

	result, err := repo.WorkerShareStatsSince(ctx, "RXT", "TESTNET", "addr-nocap", nil, 1000)
	if err != nil {
		t.Fatalf("WorkerShareStatsSince: %v", err)
	}
	if len(result.Rows) != numIdentifiers {
		t.Fatalf("got %d kept rows, want %d (all identifiers, no collapsing)", len(result.Rows), numIdentifiers)
	}
	if result.Other != nil {
		t.Errorf("expected nil Other bucket (only %d distinct identifiers, under the cap), got %+v", numIdentifiers, result.Other)
	}
}

// TestIntegrationPoolSourceShareStatsSince_CardinalityCap is
// TestIntegrationWorkerShareStatsSince_CardinalityCap's pool_id
// analogue.
func TestIntegrationPoolSourceShareStatsSince_CardinalityCap(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const numPoolIDs = 150
	const since = int64(1000)

	poolIDSharesSum := make([]int64, numPoolIDs)
	for i := 0; i < numPoolIDs; i++ {
		poolIDSharesSum[i] = int64(10000 - i*50)
	}

	for i := 0; i < numPoolIDs; i++ {
		poolID := int32(i + 1)
		total := poolIDSharesSum[i]
		firstHalf := total / 2
		secondHalf := total - firstHalf
		for _, sharesVal := range []int64{firstHalf, secondHalf} {
			s := db.Share{
				Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: poolID,
				BlockHeight: 10, Shares: sharesVal, PaymentAddress: "addr-cap-sources",
				Identifier: "rig-shared", Timestamp: since + 1,
			}
			if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
				t.Fatalf("InsertShare(pool_id=%d): %v", poolID, err)
			}
		}
	}

	result, err := repo.PoolSourceShareStatsSince(ctx, "RXT", "TESTNET", "addr-cap-sources", nil, since)
	if err != nil {
		t.Fatalf("PoolSourceShareStatsSince: %v", err)
	}

	if len(result.Rows) != db.DefaultShareStatsCardinalityCap {
		t.Fatalf("got %d kept rows, want exactly the cap (%d)", len(result.Rows), db.DefaultShareStatsCardinalityCap)
	}

	for i, row := range result.Rows {
		wantPoolID := int32(i + 1)
		if row.PoolID != wantPoolID {
			t.Errorf("kept row[%d].PoolID = %d, want %d", i, row.PoolID, wantPoolID)
		}
		if row.SharesSum != poolIDSharesSum[i] {
			t.Errorf("kept row[%d] (pool_id=%d).SharesSum = %d, want %d", i, row.PoolID, row.SharesSum, poolIDSharesSum[i])
		}
		if row.ShareCount != 2 {
			t.Errorf("kept row[%d] (pool_id=%d).ShareCount = %d, want 2", i, row.PoolID, row.ShareCount)
		}
	}

	var wantOtherSum, wantOtherCount int64
	wantOtherPoolIDs := numPoolIDs - db.DefaultShareStatsCardinalityCap
	for i := db.DefaultShareStatsCardinalityCap; i < numPoolIDs; i++ {
		wantOtherSum += poolIDSharesSum[i]
		wantOtherCount += 2
	}

	if result.Other == nil {
		t.Fatalf("expected a non-nil Other bucket (150 pool_ids > cap of %d)", db.DefaultShareStatsCardinalityCap)
	}
	if result.Other.PoolIDCount != wantOtherPoolIDs {
		t.Errorf("Other.PoolIDCount = %d, want %d", result.Other.PoolIDCount, wantOtherPoolIDs)
	}
	if result.Other.SharesSum != wantOtherSum {
		t.Errorf("Other.SharesSum = %d, want %d", result.Other.SharesSum, wantOtherSum)
	}
	if result.Other.ShareCount != wantOtherCount {
		t.Errorf("Other.ShareCount = %d, want %d", result.Other.ShareCount, wantOtherCount)
	}
}

// TestIntegrationPoolSourceShareStatsSince_UnderCapNoCollapsing is
// TestIntegrationWorkerShareStatsSince_UnderCapNoCollapsing's pool_id
// analogue.
func TestIntegrationPoolSourceShareStatsSince_UnderCapNoCollapsing(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const numPoolIDs = 40
	for i := 0; i < numPoolIDs; i++ {
		s := db.Share{
			Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: int32(i + 1),
			BlockHeight: 10, Shares: int64(1000 - i), PaymentAddress: "addr-nocap-sources",
			Identifier: "rig-shared", Timestamp: 1000,
		}
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare: %v", err)
		}
	}

	result, err := repo.PoolSourceShareStatsSince(ctx, "RXT", "TESTNET", "addr-nocap-sources", nil, 1000)
	if err != nil {
		t.Fatalf("PoolSourceShareStatsSince: %v", err)
	}
	if len(result.Rows) != numPoolIDs {
		t.Fatalf("got %d kept rows, want %d (all pool_ids, no collapsing)", len(result.Rows), numPoolIDs)
	}
	if result.Other != nil {
		t.Errorf("expected nil Other bucket (only %d distinct pool_ids, under the cap), got %+v", numPoolIDs, result.Other)
	}
}

func TestIntegrationPoolSourceShareStatsSince(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	shares := []db.Share{
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 100, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 1000},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 2, BlockHeight: 10, Shares: 400, PaymentAddress: "addr-1", Identifier: "rig-2", Timestamp: 1500},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 999, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 500},  // too old, excluded by since=1000
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 2, BlockHeight: 10, Shares: 300, PaymentAddress: "addr-2", Identifier: "rig-3", Timestamp: 1200}, // different address, excluded
	}
	for _, s := range shares {
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare(%+v): %v", s, err)
		}
	}

	sourceResult, err := repo.PoolSourceShareStatsSince(ctx, "RXT", "TESTNET", "addr-1", nil, 1000)
	if err != nil {
		t.Fatalf("PoolSourceShareStatsSince: %v", err)
	}
	sources := sourceResult.Rows
	if len(sources) != 2 {
		t.Fatalf("expected 2 pool-source rows, got %d: %+v", len(sources), sources)
	}
	if sourceResult.Other != nil {
		t.Errorf("expected no Other bucket (only 2 distinct pool_ids, well under the cap), got %+v", sourceResult.Other)
	}
	// Ordered by SharesSum descending: pool_id=2 (400) before pool_id=1 (100).
	if sources[0].PoolID != 2 || sources[0].SharesSum != 400 {
		t.Errorf("sources[0] = %+v, want pool_id=2/400", sources[0])
	}
	if sources[1].PoolID != 1 || sources[1].SharesSum != 100 {
		t.Errorf("sources[1] = %+v, want pool_id=1/100", sources[1])
	}
}

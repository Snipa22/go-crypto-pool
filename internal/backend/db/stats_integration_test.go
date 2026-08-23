package db_test

// Integration tests for internal/backend/db/stats.go's read-only
// miner-stats queries. Same GCPOOL_TEST_DSN opt-in convention as
// integration_test.go — see that file's package doc comment.

import (
	"context"
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
	if err := repo.CreditBalance(ctx, "RXT", "TESTNET", "addr-1", nil, 1000); err != nil {
		t.Fatalf("CreditBalance RXT: %v", err)
	}
	if err := repo.CreditBalance(ctx, "C29", "TESTNET", "addr-1", nil, 2000); err != nil {
		t.Fatalf("CreditBalance C29: %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXT", "TESTNET", "addr-1", &pidA, 500); err != nil {
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

	workers, err := repo.WorkerShareStatsSince(ctx, "RXT", "TESTNET", "addr-1", nil, 1000)
	if err != nil {
		t.Fatalf("WorkerShareStatsSince: %v", err)
	}
	if len(workers) != 2 {
		t.Fatalf("expected 2 worker rows, got %d: %+v", len(workers), workers)
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

	sources, err := repo.PoolSourceShareStatsSince(ctx, "RXT", "TESTNET", "addr-1", nil, 1000)
	if err != nil {
		t.Fatalf("PoolSourceShareStatsSince: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 pool-source rows, got %d: %+v", len(sources), sources)
	}
	// Ordered by SharesSum descending: pool_id=2 (400) before pool_id=1 (100).
	if sources[0].PoolID != 2 || sources[0].SharesSum != 400 {
		t.Errorf("sources[0] = %+v, want pool_id=2/400", sources[0])
	}
	if sources[1].PoolID != 1 || sources[1].SharesSum != 100 {
		t.Errorf("sources[1] = %+v, want pool_id=1/100", sources[1])
	}
}

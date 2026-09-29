package db_test

// Integration tests for internal/backend/db/hashhistory.go -- the
// bounded, Postgres-backed hash-history feature (see
// DISPATCH_BRIEF.md and hashhistory.go's own package doc comment).
// Same GCPOOL_TEST_DSN opt-in convention as integration_test.go --
// see that file's package doc comment.

import (
	"context"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

func setupHashHistorySchema(t *testing.T) (*db.Repository, context.Context) {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	return db.NewRepository(pool), ctx
}

// TestIntegrationPoolTypeShareStatsSince proves the 5-bucket
// (SOLO/PPS/PPLNS/PROP/GLOBAL) aggregate: every real pool_type is
// always present (even with zero rows in the window -- a plain
// GROUP BY would silently omit it), and GLOBAL is computed as its own
// independent, un-narrowed aggregate over every pool_type combined.
func TestIntegrationPoolTypeShareStatsSince(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	shares := []db.Share{
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 100, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 1000},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPS", PoolID: 1, BlockHeight: 10, Shares: 200, PaymentAddress: "addr-2", Identifier: "rig-2", Timestamp: 1200},
		{Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10, Shares: 999, PaymentAddress: "addr-1", Identifier: "rig-1", Timestamp: 500}, // too old, excluded
	}
	for _, s := range shares {
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare(%+v): %v", s, err)
		}
	}

	stats, err := repo.PoolTypeShareStatsSince(ctx, "RXT", "TESTNET", 1000)
	if err != nil {
		t.Fatalf("PoolTypeShareStatsSince: %v", err)
	}
	if len(stats) != 5 {
		t.Fatalf("expected 5 buckets (SOLO/PPS/PPLNS/PROP/GLOBAL), got %d: %+v", len(stats), stats)
	}

	byType := map[string]db.PoolTypeShareStats{}
	for _, s := range stats {
		byType[s.PoolType] = s
	}
	for _, want := range []struct {
		poolType   string
		sharesSum  int64
		shareCount int64
	}{
		{"SOLO", 0, 0},
		{"PPS", 200, 1},
		{"PPLNS", 100, 1},
		{"PROP", 0, 0},
		{db.HashHistoryGlobalPoolType, 300, 2},
	} {
		got, ok := byType[want.poolType]
		if !ok {
			t.Fatalf("missing bucket %q in %+v", want.poolType, stats)
		}
		if got.SharesSum != want.sharesSum || got.ShareCount != want.shareCount {
			t.Errorf("bucket %q = %+v, want sum=%d count=%d", want.poolType, got, want.sharesSum, want.shareCount)
		}
	}
}

func TestIntegrationPoolTypeShareStatsSinceValidation(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)
	if _, err := repo.PoolTypeShareStatsSince(ctx, "BOGUS", "TESTNET", 0); err == nil {
		t.Error("expected error for invalid algo")
	}
	if _, err := repo.PoolTypeShareStatsSince(ctx, "RXT", "BOGUS", 0); err == nil {
		t.Error("expected error for invalid network")
	}
}

// TestIntegrationPoolTypeHashSampleRoundTrip proves
// InsertPoolTypeHashSample + PoolTypeHashHistory round-trip real
// rows, ordered oldest-first, scoped to exactly one pool_type
// (including the GLOBAL pseudo-bucket).
func TestIntegrationPoolTypeHashSampleRoundTrip(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	t1 := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	t2 := time.Now().Add(-1 * time.Minute).Truncate(time.Second)

	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "PPLNS", 123.5, t1); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(t1): %v", err)
	}
	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "PPLNS", 456.75, t2); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(t2): %v", err)
	}
	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", db.HashHistoryGlobalPoolType, 999, t2); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(GLOBAL): %v", err)
	}
	// Different pool_type -- must not leak into PPLNS's own history.
	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "SOLO", 1, t2); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(SOLO): %v", err)
	}

	since := t1.Add(-time.Second).Unix()
	samples, err := repo.PoolTypeHashHistory(ctx, "RXT", "TESTNET", "PPLNS", since)
	if err != nil {
		t.Fatalf("PoolTypeHashHistory: %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 PPLNS samples, got %d: %+v", len(samples), samples)
	}
	if samples[0].HashrateHS != 123.5 || !samples[0].SampleTime.Equal(t1) {
		t.Errorf("samples[0] = %+v, want hashrate=123.5 sample_time=%s", samples[0], t1)
	}
	if samples[1].HashrateHS != 456.75 || !samples[1].SampleTime.Equal(t2) {
		t.Errorf("samples[1] = %+v, want hashrate=456.75 sample_time=%s", samples[1], t2)
	}

	global, err := repo.PoolTypeHashHistory(ctx, "RXT", "TESTNET", db.HashHistoryGlobalPoolType, since)
	if err != nil {
		t.Fatalf("PoolTypeHashHistory(GLOBAL): %v", err)
	}
	if len(global) != 1 || global[0].HashrateHS != 999 {
		t.Fatalf("expected 1 GLOBAL sample of 999, got %+v", global)
	}
}

func TestIntegrationInsertPoolTypeHashSampleValidation(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)
	if err := repo.InsertPoolTypeHashSample(ctx, "BOGUS", "TESTNET", "SOLO", 1, time.Now()); err == nil {
		t.Error("expected error for invalid algo")
	}
	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "BOGUS", 1, time.Now()); err == nil {
		t.Error("expected error for invalid pool_type")
	}
}

// TestIntegrationNetworkDifficultyRoundTrip proves
// CurrentNetworkDifficulty's nil-means-no-row-yet convention, plus
// InsertNetworkDifficultySample/NetworkDifficultyHistory's own
// round-trip and nil-rejection.
func TestIntegrationNetworkDifficultyRoundTrip(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	if diff, err := repo.CurrentNetworkDifficulty(ctx, "RXT", "TESTNET"); err != nil {
		t.Fatalf("CurrentNetworkDifficulty (no row): %v", err)
	} else if diff != nil {
		t.Fatalf("CurrentNetworkDifficulty (no row) = %v, want nil", *diff)
	}

	want := 12345.5
	if err := repo.UpsertNetworkState(ctx, "RXT", "TESTNET", db.NetworkState{
		Height: 100, Difficulty: &want, Source: "test", PolledAt: time.Now(),
	}); err != nil {
		t.Fatalf("UpsertNetworkState: %v", err)
	}

	diff, err := repo.CurrentNetworkDifficulty(ctx, "RXT", "TESTNET")
	if err != nil {
		t.Fatalf("CurrentNetworkDifficulty: %v", err)
	}
	if diff == nil || *diff != want {
		t.Fatalf("CurrentNetworkDifficulty = %v, want %v", diff, want)
	}

	if err := repo.InsertNetworkDifficultySample(ctx, "RXT", "TESTNET", nil, time.Now()); err == nil {
		t.Error("expected error inserting a nil difficulty sample")
	}

	ts := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := repo.InsertNetworkDifficultySample(ctx, "RXT", "TESTNET", diff, ts); err != nil {
		t.Fatalf("InsertNetworkDifficultySample: %v", err)
	}

	history, err := repo.NetworkDifficultyHistory(ctx, "RXT", "TESTNET", ts.Add(-time.Second).Unix())
	if err != nil {
		t.Fatalf("NetworkDifficultyHistory: %v", err)
	}
	if len(history) != 1 || history[0].Difficulty != want || !history[0].SampleTime.Equal(ts) {
		t.Fatalf("NetworkDifficultyHistory = %+v, want 1 sample of %v at %s", history, want, ts)
	}
}

// TestIntegrationActiveMinerHashrates_CardinalityCap is the
// regression test for the exact anti-OOM mechanism this feature
// exists to add: with 150 distinct synthetic (address, worker) pairs,
// ActiveMinerHashrates must return at most
// db.DefaultShareStatsCardinalityCap rows.
func TestIntegrationActiveMinerHashrates_CardinalityCap(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	const numWorkers = 150
	const since = int64(1000)
	for i := 0; i < numWorkers; i++ {
		s := db.Share{
			Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1, BlockHeight: 10,
			Shares:         int64(1000 - i), // descending, so ranking is deterministic
			PaymentAddress: "addr-" + string(rune('a'+(i%26))) + string(rune('0'+(i/26))),
			Identifier:     "rig-" + string(rune('a'+(i%26))) + string(rune('0'+(i/26))),
			Timestamp:      since + 1,
		}
		if err := repo.InsertShare(ctx, s, db.HeightPartitionBucketSize); err != nil {
			t.Fatalf("InsertShare(%d): %v", i, err)
		}
	}

	active, err := repo.ActiveMinerHashrates(ctx, "RXT", "TESTNET", since)
	if err != nil {
		t.Fatalf("ActiveMinerHashrates: %v", err)
	}
	if len(active) != db.DefaultShareStatsCardinalityCap {
		t.Fatalf("expected exactly %d rows (cap), got %d", db.DefaultShareStatsCardinalityCap, len(active))
	}
	// Highest SharesSum (1000, i=0) must be kept -- proves this is a
	// top-N cap, not an arbitrary truncation.
	if active[0].SharesSum != 1000 {
		t.Errorf("active[0].SharesSum = %d, want 1000 (highest)", active[0].SharesSum)
	}
}

func TestIntegrationActiveMinerHashratesValidation(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)
	if _, err := repo.ActiveMinerHashrates(ctx, "BOGUS", "TESTNET", 0); err == nil {
		t.Error("expected error for invalid algo")
	}
	if _, err := repo.ActiveMinerHashrates(ctx, "RXT", "BOGUS", 0); err == nil {
		t.Error("expected error for invalid network")
	}
}

// TestIntegrationInsertMinerHashSamplesAndHistory proves
// InsertMinerHashSamples' batch multi-row insert (miner-level AND
// worker-level rows in one call) and MinerHashHistory's nil/non-nil
// worker + payment_id filtering.
func TestIntegrationInsertMinerHashSamplesAndHistory(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	pidA := "pid-a"
	ts := time.Now().Add(-time.Minute).Truncate(time.Second)

	samples := []db.MinerHashSample{
		// Miner-level (Worker == ""), summed across rig-1/rig-2.
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", HashrateHS: 3.0, SampleTime: ts},
		// Worker-level, rig-1.
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", Worker: "rig-1", HashrateHS: 1.0, SampleTime: ts},
		// Worker-level, rig-2.
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", Worker: "rig-2", HashrateHS: 2.0, SampleTime: ts},
		// Different address, with a payment_id variant.
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-2", PaymentID: &pidA, HashrateHS: 5.0, SampleTime: ts},
	}
	if err := repo.InsertMinerHashSamples(ctx, samples); err != nil {
		t.Fatalf("InsertMinerHashSamples: %v", err)
	}
	// Empty slice is a safe no-op.
	if err := repo.InsertMinerHashSamples(ctx, nil); err != nil {
		t.Fatalf("InsertMinerHashSamples(nil): %v", err)
	}

	since := ts.Add(-time.Second).Unix()

	minerLevel, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "addr-1", nil, nil, since)
	if err != nil {
		t.Fatalf("MinerHashHistory(miner-level): %v", err)
	}
	if len(minerLevel) != 1 || minerLevel[0].HashrateHS != 3.0 {
		t.Fatalf("MinerHashHistory(miner-level) = %+v, want 1 sample of 3.0", minerLevel)
	}

	rig1 := "rig-1"
	workerLevel, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "addr-1", nil, &rig1, since)
	if err != nil {
		t.Fatalf("MinerHashHistory(rig-1): %v", err)
	}
	if len(workerLevel) != 1 || workerLevel[0].HashrateHS != 1.0 {
		t.Fatalf("MinerHashHistory(rig-1) = %+v, want 1 sample of 1.0", workerLevel)
	}

	pidLevel, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "addr-2", &pidA, nil, since)
	if err != nil {
		t.Fatalf("MinerHashHistory(addr-2, pid-a): %v", err)
	}
	if len(pidLevel) != 1 || pidLevel[0].HashrateHS != 5.0 {
		t.Fatalf("MinerHashHistory(addr-2, pid-a) = %+v, want 1 sample of 5.0", pidLevel)
	}

	emptyPID, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "addr-2", ptr(""), nil, since)
	if err != nil {
		t.Fatalf("MinerHashHistory(addr-2, pid=''): %v", err)
	}
	if len(emptyPID) != 0 {
		t.Fatalf("MinerHashHistory(addr-2, pid='') = %+v, want 0 rows (real row has pid-a, not '')", emptyPID)
	}
}

func TestIntegrationInsertMinerHashSamplesValidation(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)
	if err := repo.InsertMinerHashSamples(ctx, []db.MinerHashSample{{Algo: "BOGUS", Network: "TESTNET", PaymentAddress: "addr-1"}}); err == nil {
		t.Error("expected error for invalid algo")
	}
	if err := repo.InsertMinerHashSamples(ctx, []db.MinerHashSample{{Algo: "RXT", Network: "TESTNET", PaymentAddress: ""}}); err == nil {
		t.Error("expected error for empty payment_address")
	}
}

func TestIntegrationMinerHashHistoryValidation(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)
	if _, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "", nil, nil, 0); err == nil {
		t.Error("expected error for empty payment_address")
	}
	if _, err := repo.MinerHashHistory(ctx, "BOGUS", "TESTNET", "addr-1", nil, nil, 0); err == nil {
		t.Error("expected error for invalid algo")
	}
}

// TestIntegrationPruneHashHistory proves PruneHashHistory deletes
// exactly the rows older than the cutoff and leaves newer ones
// untouched, across every scope_type.
func TestIntegrationPruneHashHistory(t *testing.T) {
	repo, ctx := setupHashHistorySchema(t)

	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	fresh := time.Now().Add(-time.Minute).Truncate(time.Second)
	diff := 100.0

	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "PPLNS", 1, old); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(old): %v", err)
	}
	if err := repo.InsertPoolTypeHashSample(ctx, "RXT", "TESTNET", "PPLNS", 2, fresh); err != nil {
		t.Fatalf("InsertPoolTypeHashSample(fresh): %v", err)
	}
	if err := repo.InsertNetworkDifficultySample(ctx, "RXT", "TESTNET", &diff, old); err != nil {
		t.Fatalf("InsertNetworkDifficultySample(old): %v", err)
	}
	if err := repo.InsertMinerHashSamples(ctx, []db.MinerHashSample{
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", HashrateHS: 1, SampleTime: old},
		{Algo: "RXT", Network: "TESTNET", PaymentAddress: "addr-1", HashrateHS: 2, SampleTime: fresh},
	}); err != nil {
		t.Fatalf("InsertMinerHashSamples: %v", err)
	}

	cutoff := time.Now().Add(-time.Hour)
	deleted, err := repo.PruneHashHistory(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneHashHistory: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("PruneHashHistory deleted %d rows, want 3 (the 3 old-scoped rows across pool_type/network_difficulty/miner)", deleted)
	}

	remainingPT, err := repo.PoolTypeHashHistory(ctx, "RXT", "TESTNET", "PPLNS", 0)
	if err != nil {
		t.Fatalf("PoolTypeHashHistory (post-prune): %v", err)
	}
	if len(remainingPT) != 1 || remainingPT[0].HashrateHS != 2 {
		t.Fatalf("PoolTypeHashHistory (post-prune) = %+v, want 1 fresh sample of 2", remainingPT)
	}

	remainingMiner, err := repo.MinerHashHistory(ctx, "RXT", "TESTNET", "addr-1", nil, nil, 0)
	if err != nil {
		t.Fatalf("MinerHashHistory (post-prune): %v", err)
	}
	if len(remainingMiner) != 1 || remainingMiner[0].HashrateHS != 2 {
		t.Fatalf("MinerHashHistory (post-prune) = %+v, want 1 fresh sample of 2", remainingMiner)
	}

	// A second prune against the same cutoff is a safe no-op.
	deletedAgain, err := repo.PruneHashHistory(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneHashHistory (second call): %v", err)
	}
	if deletedAgain != 0 {
		t.Fatalf("PruneHashHistory (second call) deleted %d rows, want 0", deletedAgain)
	}
}

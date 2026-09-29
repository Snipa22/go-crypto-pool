// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/statsapi"
)

// hashHistoryKey mirrors runHashHistoryPoller's own internal
// (algo, network) keying convention for this test double's maps.
func hashHistoryKey(algo, network string) string { return algo + "|" + network }

type fakeInsertedPoolType struct {
	algo, network, poolType string
	hashrateHS              float64
}

type fakeInsertedDifficulty struct {
	algo, network string
	difficulty    *float64
}

// fakeHashHistoryRepo is an in-memory hashHistoryRepository test
// double.
type fakeHashHistoryRepo struct {
	poolTypeStats map[string][]db.PoolTypeShareStats
	difficulty    map[string]*float64
	active        map[string][]db.MinerHashSample

	insertedPoolType   []fakeInsertedPoolType
	insertedDifficulty []fakeInsertedDifficulty
	insertedMinerBatch []db.MinerHashSample
	pruneCalled        bool
	prunedCutoff       time.Time

	poolTypeErr         error
	difficultyErr       error
	activeErr           error
	insertPoolTypeErr   error
	insertDifficultyErr error
	insertMinerErr      error
	pruneErr            error
}

func (f *fakeHashHistoryRepo) PoolTypeShareStatsSince(_ context.Context, algo, network string, _ int64) ([]db.PoolTypeShareStats, error) {
	if f.poolTypeErr != nil {
		return nil, f.poolTypeErr
	}
	return f.poolTypeStats[hashHistoryKey(algo, network)], nil
}

func (f *fakeHashHistoryRepo) CurrentNetworkDifficulty(_ context.Context, algo, network string) (*float64, error) {
	if f.difficultyErr != nil {
		return nil, f.difficultyErr
	}
	return f.difficulty[hashHistoryKey(algo, network)], nil
}

func (f *fakeHashHistoryRepo) ActiveMinerHashrates(_ context.Context, algo, network string, _ int64) ([]db.MinerHashSample, error) {
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	return f.active[hashHistoryKey(algo, network)], nil
}

func (f *fakeHashHistoryRepo) InsertPoolTypeHashSample(_ context.Context, algo, network, poolType string, hashrateHS float64, _ time.Time) error {
	if f.insertPoolTypeErr != nil {
		return f.insertPoolTypeErr
	}
	f.insertedPoolType = append(f.insertedPoolType, fakeInsertedPoolType{algo, network, poolType, hashrateHS})
	return nil
}

func (f *fakeHashHistoryRepo) InsertNetworkDifficultySample(_ context.Context, algo, network string, difficulty *float64, _ time.Time) error {
	if f.insertDifficultyErr != nil {
		return f.insertDifficultyErr
	}
	f.insertedDifficulty = append(f.insertedDifficulty, fakeInsertedDifficulty{algo, network, difficulty})
	return nil
}

func (f *fakeHashHistoryRepo) InsertMinerHashSamples(_ context.Context, samples []db.MinerHashSample) error {
	if f.insertMinerErr != nil {
		return f.insertMinerErr
	}
	f.insertedMinerBatch = append(f.insertedMinerBatch, samples...)
	return nil
}

func (f *fakeHashHistoryRepo) PruneHashHistory(_ context.Context, olderThan time.Time) (int64, error) {
	if f.pruneErr != nil {
		return 0, f.pruneErr
	}
	f.pruneCalled = true
	f.prunedCutoff = olderThan
	return 7, nil
}

var _ hashHistoryRepository = (*fakeHashHistoryRepo)(nil)

// pollHashHistoryOnceForTest drives runHashHistoryPoller for exactly
// one poll pass -- mirrors pollOnceForTest (wallet_stats_poller_test.go)
// exactly: runHashHistoryPoller calls pollOnce() synchronously BEFORE
// entering its ticker loop, so canceling the context immediately
// still observes that first real pass.
func pollHashHistoryOnceForTest(repo hashHistoryRepository, m *metrics.Metrics, targets []hashHistoryTarget) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		runHashHistoryPoller(ctx, repo, m, targets, time.Minute, 480)
		close(done)
	}()
	<-done
}

func TestRunHashHistoryPoller_InsertsPoolTypeSamplesAndPrunes(t *testing.T) {
	repo := &fakeHashHistoryRepo{
		poolTypeStats: map[string][]db.PoolTypeShareStats{
			hashHistoryKey("RXT", "MAINNET"): {
				{PoolType: "PPLNS", SharesSum: 6000, ShareCount: 10},
				{PoolType: db.HashHistoryGlobalPoolType, SharesSum: 6000, ShareCount: 10},
			},
		},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	if len(repo.insertedPoolType) != 2 {
		t.Fatalf("expected 2 InsertPoolTypeHashSample calls, got %d: %+v", len(repo.insertedPoolType), repo.insertedPoolType)
	}
	wantHS := statsapi.EstimateHashrateHS(6000, hashHistoryAggregationWindowSeconds)
	for _, ins := range repo.insertedPoolType {
		if ins.algo != "RXT" || ins.network != "MAINNET" {
			t.Errorf("unexpected algo/network on insert: %+v", ins)
		}
		if ins.hashrateHS != wantHS {
			t.Errorf("hashrateHS = %v, want %v", ins.hashrateHS, wantHS)
		}
	}

	if !repo.pruneCalled {
		t.Fatal("expected PruneHashHistory to be called")
	}
	// maxPoints=480, interval=1m => retention window 8h.
	wantRetention := 480 * time.Minute
	gotAge := time.Since(repo.prunedCutoff)
	if gotAge < wantRetention-time.Second || gotAge > wantRetention+time.Minute {
		t.Errorf("prune cutoff age = %s, want ~%s", gotAge, wantRetention)
	}
}

func TestRunHashHistoryPoller_NetworkDifficultySkippedWhenNil(t *testing.T) {
	repo := &fakeHashHistoryRepo{} // no difficulty entries -> nil for every target
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	if len(repo.insertedDifficulty) != 0 {
		t.Errorf("expected no InsertNetworkDifficultySample calls when CurrentNetworkDifficulty returns nil, got %+v", repo.insertedDifficulty)
	}
}

func TestRunHashHistoryPoller_NetworkDifficultyInsertedWhenPresent(t *testing.T) {
	diff := 12345.0
	repo := &fakeHashHistoryRepo{
		difficulty: map[string]*float64{hashHistoryKey("RXT", "MAINNET"): &diff},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	if len(repo.insertedDifficulty) != 1 {
		t.Fatalf("expected 1 InsertNetworkDifficultySample call, got %d", len(repo.insertedDifficulty))
	}
	got := repo.insertedDifficulty[0]
	if got.algo != "RXT" || got.network != "MAINNET" || got.difficulty == nil || *got.difficulty != diff {
		t.Errorf("unexpected insert: %+v", got)
	}
}

func TestRunHashHistoryPoller_ActiveMinerBatchIncludesWorkerAndMinerLevel(t *testing.T) {
	repo := &fakeHashHistoryRepo{
		active: map[string][]db.MinerHashSample{
			hashHistoryKey("RXT", "MAINNET"): {
				{Algo: "RXT", Network: "MAINNET", PaymentAddress: "addr-1", Worker: "rig-1", SharesSum: 100, ShareCount: 1},
				{Algo: "RXT", Network: "MAINNET", PaymentAddress: "addr-1", Worker: "rig-2", SharesSum: 200, ShareCount: 2},
			},
		},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	// 2 worker-level rows + 1 miner-level (summed) row.
	if len(repo.insertedMinerBatch) != 3 {
		t.Fatalf("expected 3 rows in the batch (2 worker + 1 miner-level), got %d: %+v", len(repo.insertedMinerBatch), repo.insertedMinerBatch)
	}

	var minerLevel *db.MinerHashSample
	workerCount := 0
	for i := range repo.insertedMinerBatch {
		s := &repo.insertedMinerBatch[i]
		if s.Worker == "" {
			minerLevel = s
		} else {
			workerCount++
		}
	}
	if workerCount != 2 {
		t.Errorf("expected 2 worker-level rows, got %d", workerCount)
	}
	if minerLevel == nil {
		t.Fatal("expected exactly one miner-level (Worker==\"\") row")
	}
	wantMinerHS := statsapi.EstimateHashrateHS(300, hashHistoryAggregationWindowSeconds)
	if minerLevel.HashrateHS != wantMinerHS {
		t.Errorf("miner-level HashrateHS = %v, want %v (sum of 100+200)", minerLevel.HashrateHS, wantMinerHS)
	}
	if minerLevel.PaymentAddress != "addr-1" {
		t.Errorf("miner-level PaymentAddress = %q, want addr-1", minerLevel.PaymentAddress)
	}
}

func TestRunHashHistoryPoller_NoActiveMinersSkipsInsertMinerHashSamples(t *testing.T) {
	repo := &fakeHashHistoryRepo{}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	if len(repo.insertedMinerBatch) != 0 {
		t.Errorf("expected no miner hash samples inserted when there are no active miners, got %+v", repo.insertedMinerBatch)
	}
}

func TestRunHashHistoryPoller_ErrorsIncrementMetricAndDontHaltOtherSteps(t *testing.T) {
	diff := 999.0
	repo := &fakeHashHistoryRepo{
		poolTypeErr: context.DeadlineExceeded,
		difficulty:  map[string]*float64{hashHistoryKey("RXT", "MAINNET"): &diff},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	pollHashHistoryOnceForTest(repo, m, targets)

	// A failed PoolTypeShareStatsSince must not prevent the
	// network-difficulty step (or the final prune) from still
	// running.
	if len(repo.insertedDifficulty) != 1 {
		t.Errorf("expected the network-difficulty step to still run despite the pool-type error, got %d inserts", len(repo.insertedDifficulty))
	}
	if !repo.pruneCalled {
		t.Error("expected PruneHashHistory to still run despite the pool-type error")
	}

	body := scrapeBackendMetrics(t, m)
	if !strings.Contains(body, `hash_history_poll_errors_total{algo="RXT",network="MAINNET"} 1`) {
		t.Errorf("expected hash_history_poll_errors_total{algo=\"RXT\",network=\"MAINNET\"} 1 in output, got:\n%s", body)
	}
}

func TestRunHashHistoryPoller_DisabledWhenIntervalNonPositive(t *testing.T) {
	repo := &fakeHashHistoryRepo{
		poolTypeStats: map[string][]db.PoolTypeShareStats{hashHistoryKey("RXT", "MAINNET"): {{PoolType: "PPLNS", SharesSum: 100}}},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	// interval <= 0: must return immediately without ever calling the
	// repository (no pollOnce at all -- unlike the enabled case, this
	// never enters its ticker loop).
	runHashHistoryPoller(context.Background(), repo, m, targets, 0, 480)

	if len(repo.insertedPoolType) != 0 || repo.pruneCalled {
		t.Error("expected no repository calls when interval <= 0")
	}
}

func TestRunHashHistoryPoller_DisabledWhenMaxPointsNonPositive(t *testing.T) {
	repo := &fakeHashHistoryRepo{
		poolTypeStats: map[string][]db.PoolTypeShareStats{hashHistoryKey("RXT", "MAINNET"): {{PoolType: "PPLNS", SharesSum: 100}}},
	}
	m := metrics.New("test")
	targets := []hashHistoryTarget{{algo: "RXT", network: "MAINNET"}}

	runHashHistoryPoller(context.Background(), repo, m, targets, time.Minute, 0)

	if len(repo.insertedPoolType) != 0 || repo.pruneCalled {
		t.Error("expected no repository calls when maxPoints <= 0")
	}
}

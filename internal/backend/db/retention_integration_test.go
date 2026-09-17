package db_test

// Integration tests for the CRITICAL retention-vs-unresolved-block fix
// (see internal/backend/retention/retention.go's package doc comment
// and internal/backend/db/partition.go's DropOldPartitions doc
// comment) against a REAL Postgres instance. Set GCPOOL_TEST_DSN to
// run them — see integration_test.go's package doc comment for the
// exact setup.
//
// This deliberately exercises the REAL multi-table interaction
// end-to-end: real shares_* partition creation + insert (via
// db.Repository.InsertShare), a real `blocks` row insert (via
// db.Repository.InsertBlock), a real retention.Runner.RunOnce call
// against a test-local adapter mirroring cmd/backend's
// retentionRepositoryAdapter, then real post-assertions querying both
// `shares` (via db.Repository.SharesAtHeight) and `blocks`/the
// partition catalog back out. A mock repository would only prove this
// file's own Go code calls what it thinks it calls — on a
// money-critical "did we silently destroy a winning block's shares"
// property, that is worth approximately nothing.
import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/retention"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// retentionTestAdapter adapts a raw *pgxpool.Pool to
// retention.Repository, mirroring cmd/backend's
// retentionRepositoryAdapter exactly (see main.go) — kept as its own
// small type here rather than exported from cmd/backend, since
// cmd/backend is a `package main` and cannot be imported by this
// package's tests.
type retentionTestAdapter struct {
	pool *pgxpool.Pool
}

func (a retentionTestAdapter) ListHeightPartitions(ctx context.Context, algo, poolType string) ([]retention.HeightPartition, error) {
	rows, err := db.ListHeightPartitions(ctx, a.pool, algo, poolType)
	if err != nil {
		return nil, err
	}
	out := make([]retention.HeightPartition, 0, len(rows))
	for _, r := range rows {
		out = append(out, retention.HeightPartition{Name: r.Name, RangeStart: r.RangeStart, RangeEnd: r.RangeEnd})
	}
	return out, nil
}

func (a retentionTestAdapter) DropOldPartitions(ctx context.Context, algo, poolType string, belowHeight int64) ([]string, []retention.SkippedPartition, error) {
	dropped, skipped, err := db.DropOldPartitions(ctx, a.pool, algo, poolType, belowHeight)
	if err != nil {
		return nil, nil, err
	}
	out := make([]retention.SkippedPartition, 0, len(skipped))
	for _, s := range skipped {
		out = append(out, retention.SkippedPartition{
			Name:        s.Name,
			RangeStart:  s.RangeStart,
			RangeEnd:    s.RangeEnd,
			BlockID:     s.BlockID,
			BlockHeight: s.BlockHeight,
		})
	}
	return dropped, out, nil
}

// blockRowID looks up a real `blocks.id` by hash, purely for this
// test file's own assertions (retention.SkippedPartition.BlockID
// should match exactly what's really in the table).
func blockRowID(t *testing.T, pool *pgxpool.Pool, hash string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), "SELECT id FROM blocks WHERE hash = $1", hash).Scan(&id); err != nil {
		t.Fatalf("looking up block id for hash %q: %v", hash, err)
	}
	return id
}

// TestIntegrationRetentionRunOnceDropsPartitionWithNoUnresolvedBlocks
// proves the EXISTING behavior is preserved by the fix: a leaf
// partition with no unresolved `blocks` row in its height range is
// still dropped normally by a real retention.Runner.RunOnce pass once
// it is fully below the target's retention cutoff.
func TestIntegrationRetentionRunOnceDropsPartitionWithNoUnresolvedBlocks(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Old share (height 10, bucket [0,100000)) with NO corresponding
	// unresolved block anywhere -- must be dropped.
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "PROP", PoolID: 1,
		BlockHeight: 10, Shares: 1, PaymentAddress: "old-clear-addr", Identifier: "old-clear-worker",
		Timestamp: 1700000010,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (old): %v", err)
	}
	// New share well beyond it, forcing the frontier (and thus the
	// cutoff) far enough forward that the old bucket qualifies.
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "PROP", PoolID: 1,
		BlockHeight: 500010, Shares: 1, PaymentAddress: "new-clear-addr", Identifier: "new-clear-worker",
		Timestamp: 1700000011,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (new): %v", err)
	}

	before, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "PROP")
	if err != nil {
		t.Fatalf("ListHeightPartitions before RunOnce: %v", err)
	}

	m := metrics.New("test-retention-preserve")
	runner := retention.New(retentionTestAdapter{pool: pool}, retention.Config{
		Targets: []retention.Target{{Algo: "SHA3X", PoolType: "PROP", RetentionBlocks: 100000}},
		Metrics: m,
	})
	result := runner.RunOnce(ctx)

	if result.Errors != 0 {
		t.Fatalf("RunOnce: got %d errors, want 0: %+v", result.Errors, result.Targets)
	}
	if result.PartitionsDropped != 1 {
		t.Fatalf("PartitionsDropped: got %d, want 1", result.PartitionsDropped)
	}
	if result.PartitionsSkipped != 0 {
		t.Fatalf("PartitionsSkipped: got %d, want 0 (no unresolved blocks exist)", result.PartitionsSkipped)
	}

	after, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "PROP")
	if err != nil {
		t.Fatalf("ListHeightPartitions after RunOnce: %v", err)
	}
	if len(after) != len(before)-1 {
		t.Fatalf("expected partition count to drop by exactly 1 (from %d), got %d", len(before), len(after))
	}

	oldShares, err := repo.SharesAtHeight(ctx, "SHA3X", "PROP", 10)
	if err != nil {
		t.Fatalf("SharesAtHeight (old, after drop): %v", err)
	}
	if len(oldShares) != 0 {
		t.Errorf("expected the old share row to be gone after a real drop, found %d", len(oldShares))
	}
	newShares, err := repo.SharesAtHeight(ctx, "SHA3X", "PROP", 500010)
	if err != nil {
		t.Fatalf("SharesAtHeight (new, after drop): %v", err)
	}
	if len(newShares) != 1 {
		t.Errorf("expected the new share row to survive untouched, found %d", len(newShares))
	}

	if got := testutil.ToFloat64(m.RetentionPartitionsDroppedTotal.WithLabelValues("SHA3X", "PROP")); got != 1 {
		t.Errorf("RetentionPartitionsDroppedTotal = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.RetentionPartitionsSkippedUnresolvedTotal.WithLabelValues("SHA3X", "PROP")); got != 0 {
		t.Errorf("RetentionPartitionsSkippedUnresolvedTotal = %v, want 0", got)
	}
}

// TestIntegrationRetentionRunOnceSkipsPartitionWithUnresolvedBlock is
// the headline regression test for the CRITICAL data-loss bug this PR
// fixes: a leaf partition that is otherwise fully below the retention
// cutoff, but whose height range still has a genuinely-pending
// (`unlocked = FALSE`) real `blocks` row, must NOT be dropped by a
// real retention.Runner.RunOnce pass. Its winning share must still be
// queryable afterward (the actual "no silent data loss" proof, not
// just "the partition still exists"), the skip must be logged, and
// the new retention_partitions_skipped_unresolved_total metric must
// reflect exactly one skip.
func TestIntegrationRetentionRunOnceSkipsPartitionWithUnresolvedBlock(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// The winning SOLO share for a block that has been found but not
	// yet resolved, at height 150 -- inside the seed bucket [0,100000).
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "SOLO", PoolID: 1,
		BlockHeight: 150, Shares: 5000, PaymentAddress: "solo-winner-addr", Identifier: "solo-winner-worker",
		FoundBlock: true, BlockDiff: 5000, Timestamp: 1700000020,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (solo winner): %v", err)
	}
	// A later share, far enough ahead to push the frontier (and the
	// retention cutoff) past the winning share's bucket.
	if err := repo.InsertShare(ctx, db.Share{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "SOLO", PoolID: 1,
		BlockHeight: 500020, Shares: 1, PaymentAddress: "later-addr", Identifier: "later-worker",
		Timestamp: 1700000021,
	}, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare (later): %v", err)
	}

	// The real `blocks` row this share belongs to: found, but not yet
	// resolved by the unlocker (unlocked = FALSE) -- exactly the
	// state that must block retention from dropping its partition.
	const pendingHash = "pending-block-hash-0001"
	if err := repo.InsertBlock(ctx, db.Block{
		Algo: "SHA3X", Network: "TESTNET", PoolType: "SOLO",
		Hash: pendingHash, Height: 150, Difficulty: 5000, Shares: 5000,
		Timestamp: 1700000020, Unlocked: false, Valid: true,
	}); err != nil {
		t.Fatalf("InsertBlock: %v", err)
	}
	pendingBlockID := blockRowID(t, pool, pendingHash)

	before, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "SOLO")
	if err != nil {
		t.Fatalf("ListHeightPartitions before RunOnce: %v", err)
	}

	var logLines []string
	m := metrics.New("test-retention-skip")
	runner := retention.New(retentionTestAdapter{pool: pool}, retention.Config{
		Targets: []retention.Target{{Algo: "SHA3X", PoolType: "SOLO", RetentionBlocks: 100000}},
		Metrics: m,
		Logf: func(format string, args ...any) {
			logLines = append(logLines, fmt.Sprintf(format, args...))
		},
	})
	result := runner.RunOnce(ctx)

	if result.Errors != 0 {
		t.Fatalf("RunOnce: got %d errors, want 0: %+v", result.Errors, result.Targets)
	}
	if result.PartitionsDropped != 0 {
		t.Fatalf("PartitionsDropped: got %d, want 0 (the only eligible partition holds an unresolved block)", result.PartitionsDropped)
	}
	if result.PartitionsSkipped != 1 {
		t.Fatalf("PartitionsSkipped: got %d, want 1", result.PartitionsSkipped)
	}
	if len(result.Targets) != 1 || len(result.Targets[0].Skipped) != 1 {
		t.Fatalf("Targets[0].Skipped: got %+v, want exactly 1 entry", result.Targets)
	}
	sp := result.Targets[0].Skipped[0]
	if sp.BlockID != pendingBlockID {
		t.Errorf("Skipped[0].BlockID: got %d, want %d (the real pending block's id)", sp.BlockID, pendingBlockID)
	}
	if sp.BlockHeight != 150 {
		t.Errorf("Skipped[0].BlockHeight: got %d, want 150", sp.BlockHeight)
	}

	// The partition must still physically exist -- not dropped.
	after, err := db.ListHeightPartitions(ctx, pool, "SHA3X", "SOLO")
	if err != nil {
		t.Fatalf("ListHeightPartitions after RunOnce: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("expected partition count unchanged (skip, not drop): before=%d after=%d", len(before), len(after))
	}

	// The actual "no silent data loss" proof: the winning share row
	// is still queryable through the real repository read path.
	winnerShares, err := repo.SharesAtHeight(ctx, "SHA3X", "SOLO", 150)
	if err != nil {
		t.Fatalf("SharesAtHeight (winner, after RunOnce): %v", err)
	}
	if len(winnerShares) != 1 {
		t.Fatalf("expected the winning SOLO share to still be queryable after RunOnce, found %d rows", len(winnerShares))
	}
	if winnerShares[0].PaymentAddress != "solo-winner-addr" {
		t.Errorf("winning share payment_address: got %q, want %q", winnerShares[0].PaymentAddress, "solo-winner-addr")
	}

	// Also confirmed via the SOLO-specific real read path the payout
	// calculator itself uses.
	soloShare, found, err := repo.SoloShare(ctx, "SHA3X", 150)
	if err != nil {
		t.Fatalf("SoloShare: %v", err)
	}
	if !found {
		t.Fatalf("expected SoloShare to still find the winning share at height 150 after RunOnce")
	}
	if soloShare.PaymentAddress != "solo-winner-addr" {
		t.Errorf("SoloShare payment_address: got %q, want %q", soloShare.PaymentAddress, "solo-winner-addr")
	}

	// Logged clearly, naming the blocking block's height and id.
	var sawSkipLog bool
	for _, line := range logLines {
		if strings.Contains(line, "SHA3X/SOLO") && strings.Contains(line, "NOT dropped") &&
			strings.Contains(line, "height=150") && strings.Contains(line, "unlocked=false") {
			sawSkipLog = true
			break
		}
	}
	if !sawSkipLog {
		t.Errorf("expected a log line naming the skipped partition/blocking block, got: %v", logLines)
	}

	if got := testutil.ToFloat64(m.RetentionPartitionsSkippedUnresolvedTotal.WithLabelValues("SHA3X", "SOLO")); got != 1 {
		t.Errorf("RetentionPartitionsSkippedUnresolvedTotal = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.RetentionPartitionsDroppedTotal.WithLabelValues("SHA3X", "SOLO")); got != 0 {
		t.Errorf("RetentionPartitionsDroppedTotal = %v, want 0", got)
	}
}

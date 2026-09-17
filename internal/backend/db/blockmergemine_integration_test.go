package db_test

// Integration test for BUNDLE7_BRIEF.md item #3: GetBlockByID and
// ListBlocks previously omitted blocks.merge_mine_chain from their
// SELECT lists (InsertBlock/PendingBlocks already included it). This
// file proves the round trip through Repository's real public API --
// InsertBlock -> GetBlockByID / ListBlocks -- for both a nil (primary/
// Monero leg) and a non-nil (secondary merge-mined chain leg, e.g.
// "TARI") merge_mine_chain value.
//
// Mirrors this package's existing integration-test convention exactly
// (see integration_test.go's package doc comment): skipped unless
// GCPOOL_TEST_DSN is set, and uses resetSchema/testPool from that same
// file so this test's DB name never needs to be independently chosen
// -- it reuses whichever scratch database GCPOOL_TEST_DSN already
// points at, exactly like every other *_integration_test.go file in
// this package, so it can never collide with a differently-named
// database some other concurrent run might use.

import (
	"context"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func strPtr(s string) *string { return &s }

func TestIntegrationGetBlockByID_RoundTripsMergeMineChain(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Primary/Monero leg: MergeMineChain nil.
	primary := db.Block{
		Algo: "RXM", Network: "TESTNET", PoolType: "PPS",
		Hash: "mmchain-primary-hash", Height: 555555, Difficulty: 1000,
		Shares: 10, Timestamp: 1700000000, Unlocked: false, Valid: true,
		Value: nil, PoolID: 0, MergeMineChain: nil,
	}
	if err := repo.InsertBlock(ctx, primary); err != nil {
		t.Fatalf("InsertBlock (primary leg): %v", err)
	}

	// Secondary merge-mined leg: MergeMineChain = "TARI".
	secondary := db.Block{
		Algo: "RXM", Network: "TESTNET", PoolType: "PPS",
		Hash: "mmchain-secondary-hash", Height: 555555, Difficulty: 2000,
		Shares: 10, Timestamp: 1700000001, Unlocked: false, Valid: true,
		Value: nil, PoolID: 0, MergeMineChain: strPtr("TARI"),
	}
	if err := repo.InsertBlock(ctx, secondary); err != nil {
		t.Fatalf("InsertBlock (secondary leg): %v", err)
	}

	primaryID := blockIDByHash(t, pool, primary.Hash)
	secondaryID := blockIDByHash(t, pool, secondary.Hash)

	gotPrimary, err := repo.GetBlockByID(ctx, primaryID)
	if err != nil {
		t.Fatalf("GetBlockByID (primary): %v", err)
	}
	if gotPrimary.MergeMineChain != nil {
		t.Errorf("GetBlockByID (primary leg): MergeMineChain = %v, want nil", *gotPrimary.MergeMineChain)
	}

	gotSecondary, err := repo.GetBlockByID(ctx, secondaryID)
	if err != nil {
		t.Fatalf("GetBlockByID (secondary): %v", err)
	}
	if gotSecondary.MergeMineChain == nil || *gotSecondary.MergeMineChain != "TARI" {
		t.Errorf("GetBlockByID (secondary leg): MergeMineChain = %v, want \"TARI\"", gotSecondary.MergeMineChain)
	}
}

func TestIntegrationListBlocks_RoundTripsMergeMineChain(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	primary := db.Block{
		Algo: "RXM", Network: "TESTNET", PoolType: "PPS",
		Hash: "list-mmchain-primary-hash", Height: 666666, Difficulty: 1000,
		Shares: 10, Timestamp: 1700000010, Unlocked: false, Valid: true,
		Value: nil, PoolID: 0, MergeMineChain: nil,
	}
	if err := repo.InsertBlock(ctx, primary); err != nil {
		t.Fatalf("InsertBlock (primary leg): %v", err)
	}

	secondary := db.Block{
		Algo: "RXM", Network: "TESTNET", PoolType: "PPS",
		Hash: "list-mmchain-secondary-hash", Height: 666667, Difficulty: 2000,
		Shares: 10, Timestamp: 1700000011, Unlocked: false, Valid: true,
		Value: nil, PoolID: 0, MergeMineChain: strPtr("TARI"),
	}
	if err := repo.InsertBlock(ctx, secondary); err != nil {
		t.Fatalf("InsertBlock (secondary leg): %v", err)
	}

	rows, err := repo.ListBlocks(ctx, "RXM", "TESTNET", "PPS", 0, 0)
	if err != nil {
		t.Fatalf("ListBlocks: %v", err)
	}

	var foundPrimary, foundSecondary bool
	for _, b := range rows {
		switch b.Hash {
		case primary.Hash:
			foundPrimary = true
			if b.MergeMineChain != nil {
				t.Errorf("ListBlocks (primary leg, hash=%s): MergeMineChain = %v, want nil", b.Hash, *b.MergeMineChain)
			}
		case secondary.Hash:
			foundSecondary = true
			if b.MergeMineChain == nil || *b.MergeMineChain != "TARI" {
				t.Errorf("ListBlocks (secondary leg, hash=%s): MergeMineChain = %v, want \"TARI\"", b.Hash, b.MergeMineChain)
			}
		}
	}
	if !foundPrimary {
		t.Errorf("ListBlocks: did not return the primary-leg row (hash=%s) at all", primary.Hash)
	}
	if !foundSecondary {
		t.Errorf("ListBlocks: did not return the secondary-leg row (hash=%s) at all", secondary.Hash)
	}
}

// blockIDByHash looks up a just-inserted block's id by its (unique in
// these tests) hash -- Repository.InsertBlock does not itself return
// the new row's id, so tests that need it (to call GetBlockByID) look
// it up this way rather than adding a test-only return value to the
// real InsertBlock API.
func blockIDByHash(t *testing.T, pool *pgxpool.Pool, hash string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), `SELECT id FROM blocks WHERE hash = $1`, hash).Scan(&id); err != nil {
		t.Fatalf("looking up block id for hash %q: %v", hash, err)
	}
	return id
}

package db_test

// Integration tests for address-flags enforcement at share ingestion
// (Repository.InsertShare, see repository.go and addressflags.go)
// against a REAL Postgres instance. Set GCPOOL_TEST_DSN to run them —
// see integration_test.go's package doc comment for the exact setup.
//
// This is the regression coverage for the CRITICAL bug this file's
// change fixes: InsertShare never called checkAddressFlags at all, so
// a banned address's shares inserted normally. These tests assert
// both halves of the fix's contract:
//   - a banned address's InsertShare call is rejected (errors.Is
//     db.ErrAddressBanned) and genuinely inserts no row, and
//   - an under-floor-but-not-banned address's InsertShare call still
//     SUCCEEDS -- forced-min-difficulty floor rejection is
//     deliberately out of scope here (leaf/vardiff-side concern, see
//     repository.go's InsertShare doc comment).

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// TestIntegrationInsertShareRejectsBannedAddress is the direct
// regression test for the bug: SetAddressBan(true) on a payment
// address must make every subsequent InsertShare call for that exact
// address fail with errors.Is(err, db.ErrAddressBanned), and no row
// must land in `shares` for it -- while an otherwise-identical share
// from a DIFFERENT, never-banned address must succeed normally.
func TestIntegrationInsertShareRejectsBannedAddress(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const bannedAddr = "banned-addr"
	const cleanAddr = "clean-addr"

	if err := repo.SetAddressBan(ctx, bannedAddr, true, "test ban", "test-operator"); err != nil {
		t.Fatalf("SetAddressBan(%s): %v", bannedAddr, err)
	}

	bannedShare := db.Share{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
		BlockHeight: 60, Shares: 1000, PaymentAddress: bannedAddr,
		Identifier: "worker-banned", Timestamp: 1700000200, BlockDiff: 5000,
	}
	err := repo.InsertShare(ctx, bannedShare, db.HeightPartitionBucketSize)
	if err == nil {
		t.Fatal("InsertShare for a banned address: expected an error, got nil")
	}
	if !errors.Is(err, db.ErrAddressBanned) {
		t.Fatalf("InsertShare for a banned address: got err=%v, want errors.Is(err, db.ErrAddressBanned)", err)
	}

	// The important invariant: no row was actually written for this
	// share, for this exact algo/network/pool_type/height partition.
	var bannedCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM shares
		WHERE algo = 'RXT' AND network = 'TESTNET' AND pool_type = 'PPLNS'
		  AND block_height = 60 AND payment_address = $1
	`, bannedAddr).Scan(&bannedCount); err != nil {
		t.Fatalf("counting shares for banned address: %v", err)
	}
	if bannedCount != 0 {
		t.Errorf("expected 0 shares rows for the banned address, got %d", bannedCount)
	}

	// A different, never-banned address submitting an otherwise
	// identical share must succeed normally.
	cleanShare := db.Share{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
		BlockHeight: 60, Shares: 1000, PaymentAddress: cleanAddr,
		Identifier: "worker-clean", Timestamp: 1700000201, BlockDiff: 5000,
	}
	if err := repo.InsertShare(ctx, cleanShare, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare for a never-banned address: unexpected error: %v", err)
	}
	var cleanCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM shares
		WHERE algo = 'RXT' AND network = 'TESTNET' AND pool_type = 'PPLNS'
		  AND block_height = 60 AND payment_address = $1
	`, cleanAddr).Scan(&cleanCount); err != nil {
		t.Fatalf("counting shares for clean address: %v", err)
	}
	if cleanCount != 1 {
		t.Errorf("expected exactly 1 shares row for the never-banned address, got %d", cleanCount)
	}
}

// TestIntegrationInsertShareIgnoresForcedMinDifficultyFloor is the
// explicit scoping check called out by the fix: a
// SetForcedMinDifficulty floor on an address (with no ban) must NOT
// cause InsertShare to reject a below-floor share. This is expected
// to succeed -- floor enforcement belongs to the leaf/vardiff side,
// not backend ingestion (see repository.go's InsertShare doc comment
// and addressflags.go's ErrShareDifficultyTooLow doc comment). Getting
// this wrong (rejecting) would be just as bad as the original bug
// (silently dropping legitimate shares), so this is asserted
// explicitly rather than assumed.
func TestIntegrationInsertShareIgnoresForcedMinDifficultyFloor(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const flooredAddr = "floored-addr"
	const floor int64 = 100000

	if err := repo.SetForcedMinDifficulty(ctx, flooredAddr, floor, "test floor", "test-operator"); err != nil {
		t.Fatalf("SetForcedMinDifficulty(%s): %v", flooredAddr, err)
	}

	// BlockDiff is well below the floor -- this must still succeed.
	belowFloorShare := db.Share{
		Algo: "RXT", Network: "TESTNET", PoolType: "PPLNS", PoolID: 1,
		BlockHeight: 61, Shares: 1000, PaymentAddress: flooredAddr,
		Identifier: "worker-floored", Timestamp: 1700000202, BlockDiff: floor - 1,
	}
	if err := repo.InsertShare(ctx, belowFloorShare, db.HeightPartitionBucketSize); err != nil {
		t.Fatalf("InsertShare for a below-floor (not banned) address: unexpected error: %v (floor enforcement is explicitly out of InsertShare's scope)", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM shares
		WHERE algo = 'RXT' AND network = 'TESTNET' AND pool_type = 'PPLNS'
		  AND block_height = 61 AND payment_address = $1
	`, flooredAddr).Scan(&count); err != nil {
		t.Fatalf("counting shares for floored address: %v", err)
	}
	if count != 1 {
		t.Errorf("expected the below-floor share to succeed and insert exactly 1 row, got %d", count)
	}

	// Sanity: the flag is genuinely set (not banned, floor present) —
	// confirms this test actually exercised the floor path and not a
	// no-op.
	flag, err := repo.GetAddressFlag(ctx, flooredAddr)
	if err != nil {
		t.Fatalf("GetAddressFlag(%s): %v", flooredAddr, err)
	}
	if flag.Banned {
		t.Fatalf("expected %s to not be banned, got Banned=true", flooredAddr)
	}
	if flag.ForcedMinDifficulty == nil || *flag.ForcedMinDifficulty != floor {
		t.Fatalf("expected %s to have ForcedMinDifficulty=%d, got %v", flooredAddr, floor, flag.ForcedMinDifficulty)
	}
}

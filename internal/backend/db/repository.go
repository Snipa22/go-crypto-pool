package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Share is the minimal set of columns the backend needs to persist for
// one accepted share. It intentionally mirrors internal/proto.Share's
// accounting-relevant fields; raw_proof is not persisted (the backend
// does not decode/validate it, per AGENTS.md's trust-boundary design).
type Share struct {
	Algo           string
	Network        string
	PoolType       string
	PoolID         int32
	BlockHeight    int64
	Shares         int64
	PaymentAddress string
	PaymentID      *string
	FoundBlock     bool
	BlockDiff      int64
	Timestamp      int64
	Identifier     string
	TrustedShare   bool
}

// Block is the minimal set of columns the backend needs to persist for
// one reported block. Mirrors internal/proto.Block.
type Block struct {
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Shares     int64
	Timestamp  int64
	Unlocked   bool
	Valid      bool
	Value      *int64
}

// Repository provides minimal read/write access to the core schema. It is
// deliberately narrow (InsertShare/InsertBlock plus the partition
// helpers in partition.go) — this is schema + plumbing, not the full
// backend data-access surface.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository wraps an existing connection pool (see Open) in a
// Repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// InsertShare ensures the destination height-range partition exists (see
// EnsureHeightPartition) and inserts one share row. bucketSize should
// normally be HeightPartitionBucketSize; it is a parameter here (rather
// than implicit) for the same reason EnsureHeightPartition takes it
// explicitly.
func (r *Repository) InsertShare(ctx context.Context, s Share, bucketSize int64) error {
	if err := ValidateAlgo(s.Algo); err != nil {
		return err
	}
	if err := ValidatePoolType(s.PoolType); err != nil {
		return err
	}
	if err := EnsureHeightPartition(ctx, r.pool, s.Algo, s.PoolType, s.BlockHeight, bucketSize); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO shares (
			algo, network, pool_type, pool_id, block_height, shares,
			payment_address, payment_id, found_block, block_diff,
			share_timestamp, identifier, trusted_share
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)`
	_, err := r.pool.Exec(ctx, stmt,
		s.Algo, s.Network, s.PoolType, s.PoolID, s.BlockHeight, s.Shares,
		s.PaymentAddress, s.PaymentID, s.FoundBlock, s.BlockDiff,
		s.Timestamp, s.Identifier, s.TrustedShare,
	)
	if err != nil {
		return fmt.Errorf("db: inserting share: %w", err)
	}
	return nil
}

// InsertBlock inserts one row into the plain, unpartitioned blocks table.
// No partition management is needed here — blocks are permanent and
// never cleaned up.
func (r *Repository) InsertBlock(ctx context.Context, b Block) error {
	if err := ValidateAlgo(b.Algo); err != nil {
		return err
	}
	if err := ValidatePoolType(b.PoolType); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO blocks (
			algo, network, pool_type, hash, height, difficulty, shares,
			block_timestamp, unlocked, valid, value
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`
	_, err := r.pool.Exec(ctx, stmt,
		b.Algo, b.Network, b.PoolType, b.Hash, b.Height, b.Difficulty, b.Shares,
		b.Timestamp, b.Unlocked, b.Valid, b.Value,
	)
	if err != nil {
		return fmt.Errorf("db: inserting block: %w", err)
	}
	return nil
}

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

// PendingBlock is one row of `blocks` that the unlocker (see
// internal/backend/unlocker) still needs to independently verify
// against the real chain — i.e. valid = TRUE (never yet found
// invalid/orphaned) AND unlocked = FALSE (not yet confirmed mature).
// Only the columns the unlocker's ChainVerifier.Verify call actually
// needs are carried here.
type PendingBlock struct {
	ID      int64
	Algo    string
	Network string
	Hash    string
	Height  int64
}

// PendingBlocks returns every blocks row with valid = TRUE AND
// unlocked = FALSE for the given algo, oldest (lowest id) first — the
// unlocker's poll loop calls this once per configured algo on every
// tick. algo is validated the same way InsertBlock's is; an invalid
// algo is a caller bug, not a legitimate "no rows" outcome, so it is
// reported as an error rather than silently returning an empty slice.
func (r *Repository) PendingBlocks(ctx context.Context, algo string) ([]PendingBlock, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}

	const stmt = `
		SELECT id, algo, network, hash, height
		FROM blocks
		WHERE algo = $1 AND valid = TRUE AND unlocked = FALSE
		ORDER BY id ASC`
	rows, err := r.pool.Query(ctx, stmt, algo)
	if err != nil {
		return nil, fmt.Errorf("db: querying pending blocks: %w", err)
	}
	defer rows.Close()

	var out []PendingBlock
	for rows.Next() {
		var pb PendingBlock
		if err := rows.Scan(&pb.ID, &pb.Algo, &pb.Network, &pb.Hash, &pb.Height); err != nil {
			return nil, fmt.Errorf("db: scanning pending block row: %w", err)
		}
		out = append(out, pb)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pending block rows: %w", err)
	}
	return out, nil
}

// SetBlockStatus updates one blocks row's valid/unlocked columns by
// id — the unlocker's own write path once ChainVerifier.Verify has
// resolved a pending block's real chain status (matured -> valid,
// unlocked; orphaned -> !valid, unlocked; the third, "still
// confirming" outcome does not call this at all and simply leaves the
// row pending for the next poll). Returns an error (rather than
// silently no-op'ing) if id does not match any row, since that
// indicates the unlocker and the blocks table have drifted out of
// sync with each other.
func (r *Repository) SetBlockStatus(ctx context.Context, id int64, valid, unlocked bool) error {
	const stmt = `UPDATE blocks SET valid = $2, unlocked = $3 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, id, valid, unlocked)
	if err != nil {
		return fmt.Errorf("db: updating block %d status: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: updating block %d status: no such block", id)
	}
	return nil
}

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
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
// Carries pool_type/difficulty/value in addition to the columns the
// unlocker's ChainVerifier.Verify call itself needs, since the
// unlocker also uses this row to trigger a payout.Calculator run
// once a block resolves to matured (see unlocker.PayoutTrigger).
type PendingBlock struct {
	ID         int64
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Value      *int64
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
		SELECT id, algo, network, pool_type, hash, height, difficulty, value
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
		if err := rows.Scan(&pb.ID, &pb.Algo, &pb.Network, &pb.PoolType, &pb.Hash, &pb.Height, &pb.Difficulty, &pb.Value); err != nil {
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

// PayoutShare is one `shares` row as needed by internal/backend/payout
// (payout.ShareRow's DB-facing counterpart — kept as its own type for
// the same dependency-direction reason unlocker.Block/db.PendingBlock
// are kept separate, see unlocker.Repository's doc comment).
type PayoutShare struct {
	Shares         int64
	PaymentAddress string
	PaymentID      *string
}

// SharesAtHeight returns every `shares` row for (algo, poolType,
// height), newest share_timestamp first — the real-schema equivalent
// of nodejs-pool-sxmr's `SELECT * FROM shares WHERE block_height = ?
// order by time desc`, scoped by this schema's algo/pool_type
// partition columns instead of a post-hoc pool_type filter (see
// internal/backend/payout's doc comment for why that's equivalent).
func (r *Repository) SharesAtHeight(ctx context.Context, algo, poolType string, height int64) ([]PayoutShare, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidatePoolType(poolType); err != nil {
		return nil, err
	}

	const stmt = `
		SELECT shares, payment_address, payment_id
		FROM shares
		WHERE algo = $1 AND pool_type = $2 AND block_height = $3
		ORDER BY share_timestamp DESC`
	rows, err := r.pool.Query(ctx, stmt, algo, poolType, height)
	if err != nil {
		return nil, fmt.Errorf("db: querying shares at height %d: %w", height, err)
	}
	defer rows.Close()

	var out []PayoutShare
	for rows.Next() {
		var s PayoutShare
		if err := rows.Scan(&s.Shares, &s.PaymentAddress, &s.PaymentID); err != nil {
			return nil, fmt.Errorf("db: scanning share row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating share rows: %w", err)
	}
	return out, nil
}

// SoloShare returns the single found_block=TRUE SOLO row for (algo,
// height) — the real-schema equivalent of nodejs-pool-sxmr's `SELECT *
// FROM shares WHERE block_height = ? AND found_block IS TRUE LIMIT 1`,
// additionally scoped to algo (see internal/backend/payout's doc
// comment: this schema partitions by algo, legacy's commingled table
// did not). found is false, with no error, when no such row exists yet
// — an expected state for a block that hasn't been fully processed,
// not a caller error.
func (r *Repository) SoloShare(ctx context.Context, algo string, height int64) (PayoutShare, bool, error) {
	if err := ValidateAlgo(algo); err != nil {
		return PayoutShare{}, false, err
	}

	const stmt = `
		SELECT shares, payment_address, payment_id
		FROM shares
		WHERE algo = $1 AND pool_type = 'SOLO' AND block_height = $2 AND found_block IS TRUE
		ORDER BY share_timestamp DESC
		LIMIT 1`
	var s PayoutShare
	err := r.pool.QueryRow(ctx, stmt, algo, height).Scan(&s.Shares, &s.PaymentAddress, &s.PaymentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PayoutShare{}, false, nil
		}
		return PayoutShare{}, false, fmt.Errorf("db: querying solo share at height %d: %w", height, err)
	}
	return s, true, nil
}

// CreditBalance adds amount to the pending balance for (algo, network,
// paymentAddress, paymentID), inserting a new zero-balance row first
// if none exists yet — the real-schema equivalent of nodejs-pool-sxmr's
// createBalanceQueue (account-ensure) followed by balanceQueue
// (increment), collapsed into a single upsert against this schema's
// uq_balance_identity unique index (algo, network, payment_address,
// COALESCE(payment_id, ”)).
func (r *Repository) CreditBalance(ctx context.Context, algo, network, paymentAddress string, paymentID *string, amount int64) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO balance (algo, network, payment_address, payment_id, pending_balance)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (algo, network, payment_address, (COALESCE(payment_id, '')))
		DO UPDATE SET pending_balance = balance.pending_balance + EXCLUDED.pending_balance,
		              updated_at = now()`
	_, err := r.pool.Exec(ctx, stmt, algo, network, paymentAddress, paymentID, amount)
	if err != nil {
		return fmt.Errorf("db: crediting balance for %s: %w", paymentAddress, err)
	}
	return nil
}

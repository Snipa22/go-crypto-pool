package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// partitionBoundPattern parses the textual output of
// pg_get_expr(relpartbound, oid) for a RANGE partition, e.g.
// "FOR VALUES FROM ('100000') TO ('200000')".
var partitionBoundPattern = regexp.MustCompile(`FOR VALUES FROM \('?(-?\d+)'?\) TO \('?(-?\d+)'?\)`)

// ValidateAlgo reports whether algo is one of the known shares/blocks
// partition-key values (see ValidAlgos).
func ValidateAlgo(algo string) error {
	for _, a := range ValidAlgos {
		if a == algo {
			return nil
		}
	}
	return fmt.Errorf("db: unknown algo %q (want one of %v)", algo, ValidAlgos)
}

// ValidatePoolType reports whether poolType is one of the known
// shares/blocks partition-key values (see ValidPoolTypes).
func ValidatePoolType(poolType string) error {
	for _, p := range ValidPoolTypes {
		if p == poolType {
			return nil
		}
	}
	return fmt.Errorf("db: unknown pool_type %q (want one of %v)", poolType, ValidPoolTypes)
}

// ValidateNetwork reports whether network is one of the known
// network column values (see ValidNetworks).
func ValidateNetwork(network string) error {
	for _, n := range ValidNetworks {
		if n == network {
			return nil
		}
	}
	return fmt.Errorf("db: unknown network %q (want one of %v)", network, ValidNetworks)
}

// heightPartitionParent returns the name of the (algo, pool_type)
// partitioned table that owns block_height RANGE leaf partitions, e.g.
// "shares_rxt_pplns". Caller must have already validated algo/poolType.
func heightPartitionParent(algo, poolType string) string {
	return fmt.Sprintf("shares_%s_%s", strings.ToLower(algo), strings.ToLower(poolType))
}

// heightPartitionName returns the leaf partition name for the bucket
// starting at bucketStart, e.g. "shares_rxt_pplns_h000000100000". This
// convention must stay in sync with the seed partitions created in
// migrations/0001_initial_schema.up.sql.
func heightPartitionName(algo, poolType string, bucketStart int64) string {
	return fmt.Sprintf("%s_h%012d", heightPartitionParent(algo, poolType), bucketStart)
}

// BucketBounds returns the [start, end) block-height range of the bucket
// that contains height, for the given bucket size. height and bucketSize
// must both be non-negative; bucketSize must be > 0.
func BucketBounds(height, bucketSize int64) (start, end int64, err error) {
	if bucketSize <= 0 {
		return 0, 0, fmt.Errorf("db: bucketSize must be > 0, got %d", bucketSize)
	}
	if height < 0 {
		return 0, 0, fmt.Errorf("db: height must be >= 0, got %d", height)
	}
	start = (height / bucketSize) * bucketSize
	end = start + bucketSize
	return start, end, nil
}

// EnsureHeightPartition creates the block_height RANGE leaf partition
// covering height under shares_<algo>_<poolType>, if it does not already
// exist. Safe to call unconditionally on every insert path (it's a single
// idempotent DDL statement); callers doing high-throughput inserts should
// still cache "already ensured" state themselves to avoid a DDL
// round-trip per share.
//
// bucketSize is passed explicitly (rather than always reading
// HeightPartitionBucketSize) so callers can experiment with bucket sizing
// without recompiling — production code should pass
// HeightPartitionBucketSize unless deliberately testing an alternative.
func EnsureHeightPartition(ctx context.Context, pool *pgxpool.Pool, algo, poolType string, height, bucketSize int64) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidatePoolType(poolType); err != nil {
		return err
	}
	start, end, err := BucketBounds(height, bucketSize)
	if err != nil {
		return err
	}

	parent := pgx.Identifier{heightPartitionParent(algo, poolType)}.Sanitize()
	leaf := pgx.Identifier{heightPartitionName(algo, poolType, start)}.Sanitize()

	sql := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM (%d) TO (%d)",
		leaf, parent, start, end,
	)
	if _, err := pool.Exec(ctx, sql); err != nil {
		return fmt.Errorf("db: creating height partition %s: %w", leaf, err)
	}
	return nil
}

// HeightPartition describes one existing block_height RANGE leaf
// partition under a shares_<algo>_<poolType> parent.
type HeightPartition struct {
	Name       string
	RangeStart int64
	RangeEnd   int64 // exclusive upper bound
}

// ListHeightPartitions returns every existing block_height leaf partition
// under shares_<algo>_<poolType>, ordered by range start.
func ListHeightPartitions(ctx context.Context, pool *pgxpool.Pool, algo, poolType string) ([]HeightPartition, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidatePoolType(poolType); err != nil {
		return nil, err
	}

	parent := heightPartitionParent(algo, poolType)
	rows, err := pool.Query(ctx, `
		SELECT c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = $1
	`, parent)
	if err != nil {
		return nil, fmt.Errorf("db: listing height partitions for %s: %w", parent, err)
	}
	defer rows.Close()

	var out []HeightPartition
	for rows.Next() {
		var name, bound string
		if err := rows.Scan(&name, &bound); err != nil {
			return nil, fmt.Errorf("db: scanning height partition row: %w", err)
		}
		m := partitionBoundPattern.FindStringSubmatch(bound)
		if m == nil {
			// DEFAULT partition or unexpected bound shape - skip rather
			// than fail the whole listing.
			continue
		}
		start, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("db: parsing partition bound start %q: %w", m[1], err)
		}
		end, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("db: parsing partition bound end %q: %w", m[2], err)
		}
		out = append(out, HeightPartition{Name: name, RangeStart: start, RangeEnd: end})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating height partitions for %s: %w", parent, err)
	}
	return out, nil
}

// SkippedPartition describes one leaf partition that DropOldPartitions
// found otherwise eligible to drop (its whole range is below the
// caller's belowHeight cutoff) but did NOT drop, because the `blocks`
// table still has an unresolved (unlocked = FALSE) row whose height
// falls inside that partition's [RangeStart, RangeEnd) range. See
// DropOldPartitions's doc comment for why this check exists: dropping
// this partition would destroy a still-pending (or forever-retrying
// payout) block's winning shares before the unlocker/payout pass ever
// gets to read them — silent, unrecoverable data loss on the
// money-critical path.
//
// BlockID/BlockHeight identify the EARLIEST (lowest-height) unresolved
// block found in range — there may be more than one, but this is
// sufficient for an operator to go look at `blocks` themselves, and
// picking a single deterministic row keeps this type (and its log
// line) simple.
type SkippedPartition struct {
	Name       string
	RangeStart int64
	RangeEnd   int64

	BlockID     int64
	BlockHeight int64
}

// unresolvedBlockInRange reports the earliest (lowest height) `blocks`
// row for (algo, poolType) with unlocked = FALSE and height in
// [rangeStart, rangeEnd), or found = false if no such row exists. Uses
// a real, indexed WHERE clause (idx_blocks_algo_pool_type covers
// algo+pool_type, idx_blocks_height covers height) rather than loading
// candidate rows into memory and filtering in Go — see
// migrations/0001_initial_schema.up.sql for the exact index names.
func unresolvedBlockInRange(ctx context.Context, pool *pgxpool.Pool, algo, poolType string, rangeStart, rangeEnd int64) (blockID, blockHeight int64, found bool, err error) {
	const stmt = `
		SELECT id, height
		FROM blocks
		WHERE algo = $1 AND pool_type = $2 AND unlocked = FALSE
		  AND height >= $3 AND height < $4
		ORDER BY height ASC
		LIMIT 1`
	err = pool.QueryRow(ctx, stmt, algo, poolType, rangeStart, rangeEnd).Scan(&blockID, &blockHeight)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("db: querying unresolved blocks for %s/%s in range [%d,%d): %w", algo, poolType, rangeStart, rangeEnd, err)
	}
	return blockID, blockHeight, true, nil
}

// DropOldPartitions implements the shares retention model: "delete all
// shares of a given algo+pool_type with a block height lower than X".
// It identifies every block_height leaf partition whose entire range is
// below belowHeight (i.e. RangeEnd <= belowHeight) and drops those whole
// partitions — it never issues row-level DELETEs. Partitions that only
// partially overlap the cutoff are left alone (dropping them would
// destroy still-live rows); callers that need exact-row cutoffs should
// choose belowHeight to land on a bucket boundary, or accept that
// retention is bucket-granular.
//
// CRITICAL SAFETY CHECK: before actually dropping an otherwise-eligible
// partition, this checks whether `blocks` still has any unresolved
// (unlocked = FALSE) row whose height falls inside that partition's
// range — see unresolvedBlockInRange and SkippedPartition's doc
// comments for why (a genuinely pending block, or one stuck forever
// retrying a failed payout, needs that partition's shares to still
// exist when the unlocker/payout pass finally reads it). A partition
// with such a row is left alone (added to the returned skipped slice
// instead of dropped) — this does NOT abort the whole call: every
// OTHER eligible partition for this same (algo, poolType) with no
// unresolved blocks in its own range is still dropped normally. The
// skipped partition is simply retried on the next call (nothing about
// it is special-cased or remembered between calls), since it is still
// a candidate every time belowHeight advances past it again.
//
// This function is a mechanism, not a policy: nothing in this package
// calls it on a schedule. Wiring it into a periodic job (e.g. a cron/
// ticker in cmd/backend) is future work.
func DropOldPartitions(ctx context.Context, pool *pgxpool.Pool, algo, poolType string, belowHeight int64) (dropped []string, skipped []SkippedPartition, err error) {
	partitions, err := ListHeightPartitions(ctx, pool, algo, poolType)
	if err != nil {
		return nil, nil, err
	}

	for _, p := range partitions {
		if p.RangeEnd > belowHeight {
			continue
		}
		blockID, blockHeight, unresolved, err := unresolvedBlockInRange(ctx, pool, algo, poolType, p.RangeStart, p.RangeEnd)
		if err != nil {
			return dropped, skipped, err
		}
		if unresolved {
			skipped = append(skipped, SkippedPartition{
				Name:        p.Name,
				RangeStart:  p.RangeStart,
				RangeEnd:    p.RangeEnd,
				BlockID:     blockID,
				BlockHeight: blockHeight,
			})
			continue
		}
		name := pgx.Identifier{p.Name}.Sanitize()
		if _, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
			return dropped, skipped, fmt.Errorf("db: dropping partition %s: %w", p.Name, err)
		}
		dropped = append(dropped, p.Name)
	}
	return dropped, skipped, nil
}

// network.go implements the backend's read-only query surface over
// the `pools`/`ports` tables (see migrations/0001_initial_schema.up.sql).
// This is the pool network topology's persistence-layer counterpart
// to internal/backend/networkapi's public HTTP endpoint -- "what
// pools/ports does this backend have configured" -- and, like
// stats.go, is SELECT-only: nothing here ever writes a pools/ports
// row (pool/port provisioning is an operator/ops action, not
// something exposed over this backend's HTTP surface today).
package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Port is one `ports` row.
type Port struct {
	ID              int32
	Port            int32
	Description     string
	MinDifficulty   int64
	MaxDifficulty   *int64
	StartDifficulty int64
	VariableDiff    bool
}

// Pool is one `pools` row plus its associated `ports` rows.
type Pool struct {
	ID        int32
	Algo      string
	Network   string
	PoolType  string
	Name      string
	Enabled   bool
	CreatedAt time.Time
	Ports     []Port
}

// ListPools returns every configured pool, each with its associated
// ports, optionally narrowed by algo/network (empty string means "no
// filter on that column", mirroring MinerBalances' convention).
// Results are ordered by (algo, network, pool_type, name) for a
// deterministic response shape; each pool's Ports are ordered by
// port number ascending.
func (r *Repository) ListPools(ctx context.Context, algo, network string) ([]Pool, error) {
	if algo != "" {
		if err := ValidateAlgo(algo); err != nil {
			return nil, err
		}
	}
	if network != "" {
		if err := ValidateNetwork(network); err != nil {
			return nil, err
		}
	}

	var sb strings.Builder
	sb.WriteString(`SELECT id, algo, network, pool_type, name, enabled, created_at FROM pools WHERE TRUE`)
	args := []any{}
	if algo != "" {
		args = append(args, algo)
		fmt.Fprintf(&sb, " AND algo = $%d", len(args))
	}
	if network != "" {
		args = append(args, network)
		fmt.Fprintf(&sb, " AND network = $%d", len(args))
	}
	sb.WriteString(" ORDER BY algo, network, pool_type, name")

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying pools: %w", err)
	}

	var out []Pool
	byID := map[int32]*Pool{}
	for rows.Next() {
		var p Pool
		if err := rows.Scan(&p.ID, &p.Algo, &p.Network, &p.PoolType, &p.Name, &p.Enabled, &p.CreatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("db: scanning pool row: %w", err)
		}
		out = append(out, p)
		byID[p.ID] = &out[len(out)-1]
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("db: iterating pool rows: %w", err)
	}
	rows.Close()

	if len(out) == 0 {
		return out, nil
	}

	poolIDs := make([]int32, 0, len(out))
	for _, p := range out {
		poolIDs = append(poolIDs, p.ID)
	}

	portRows, err := r.pool.Query(ctx, `
		SELECT id, pool_id, port, description, min_difficulty, max_difficulty, start_difficulty, variable_diff
		FROM ports
		WHERE pool_id = ANY($1)
		ORDER BY pool_id, port`, poolIDs)
	if err != nil {
		return nil, fmt.Errorf("db: querying ports: %w", err)
	}
	defer portRows.Close()

	for portRows.Next() {
		var poolID int32
		var pt Port
		if err := portRows.Scan(&pt.ID, &poolID, &pt.Port, &pt.Description, &pt.MinDifficulty, &pt.MaxDifficulty, &pt.StartDifficulty, &pt.VariableDiff); err != nil {
			return nil, fmt.Errorf("db: scanning port row: %w", err)
		}
		if p, ok := byID[poolID]; ok {
			p.Ports = append(p.Ports, pt)
		}
	}
	if err := portRows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating port rows: %w", err)
	}

	return out, nil
}

// NetworkStats is a pool-wide (i.e. NOT scoped to any single miner's
// payment address) aggregate over `shares`/`blocks` for one
// (algo, network) pair: the difficulty-weighted share sum across
// EVERY miner in the trailing window (the input to a whole-pool
// hashrate estimate, mirroring statsapi.EstimateHashrateHS's exact
// formula/convention on a pool-wide sum instead of a single address'
// one), plus the running total/most-recent block this pool has found
// for that algo/network. This is the real, DB-backed "how is this
// pool doing overall" figure a public pool-stats page needs, distinct
// from ShareStatsSince's per-miner scope.
type NetworkStats struct {
	SharesSum       int64
	ShareCount      int64
	BlocksFound     int64
	LastBlockAt     *time.Time
	LastBlockHeight *int64
}

// NetworkStatsSince aggregates every `shares` row for (algo, network)
// -- across all payment addresses -- with share_timestamp >=
// sinceUnix, and separately counts every `blocks` row ever recorded
// for that (algo, network) (blocks found is a lifetime total, not
// windowed -- unlike the hashrate-driving share sum, a windowed block
// count would be a nearly-always-zero, uninformative number given how
// infrequently any single pool finds a block relative to a typical
// hashrate lookback window).
func (r *Repository) NetworkStatsSince(ctx context.Context, algo, network string, sinceUnix int64) (NetworkStats, error) {
	if err := ValidateAlgo(algo); err != nil {
		return NetworkStats{}, err
	}
	if err := ValidateNetwork(network); err != nil {
		return NetworkStats{}, err
	}

	var s NetworkStats
	const shareStmt = `
		SELECT COALESCE(SUM(shares), 0), COUNT(*)
		FROM shares
		WHERE algo = $1 AND network = $2 AND share_timestamp >= $3`
	if err := r.pool.QueryRow(ctx, shareStmt, algo, network, sinceUnix).Scan(&s.SharesSum, &s.ShareCount); err != nil {
		return NetworkStats{}, fmt.Errorf("db: querying network share stats for %s/%s: %w", algo, network, err)
	}

	const blockStmt = `
		SELECT COUNT(*), MAX(height), MAX(inserted_at)
		FROM blocks
		WHERE algo = $1 AND network = $2`
	var maxHeight *int64
	var maxAt *time.Time
	if err := r.pool.QueryRow(ctx, blockStmt, algo, network).Scan(&s.BlocksFound, &maxHeight, &maxAt); err != nil {
		return NetworkStats{}, fmt.Errorf("db: querying network block stats for %s/%s: %w", algo, network, err)
	}
	s.LastBlockHeight = maxHeight
	s.LastBlockAt = maxAt

	return s, nil
}

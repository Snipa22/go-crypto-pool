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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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

	// NetworkHeight/NetworkDifficulty/NetworkEstimatedHashrateHS/
	// NetworkStateUpdatedAt are the REAL, live chain-state fields
	// this same query LEFT JOINs in from `network_state` -- see
	// that table's migration doc comment and
	// internal/backend/networkpoller's package doc comment for how
	// they get there. All four are nil/zero-valued together when
	// no poller has ever successfully written a network_state row
	// for this (algo, network) -- e.g. a deployment that hasn't
	// configured GCPOOL_TARI_GRPC_ADDR/GCPOOL_MONERO_RPC_ADDR yet.
	// Deliberately independent of SharesSum/ShareCount above (this
	// pool's own local share-derived hashrate estimate) -- see
	// network_state's migration doc comment for why the two must
	// never be conflated.
	NetworkHeight              *int64
	NetworkDifficulty          *float64
	NetworkEstimatedHashrateHS *float64
	NetworkStateUpdatedAt      *time.Time
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

	// Real, live chain-state fields (see NetworkStats.NetworkHeight's
	// doc comment) -- a LEFT JOIN-shaped lookup via a second query
	// rather than an actual SQL JOIN against the two aggregates
	// above, since network_state is a single-row-per-(algo,network)
	// side table with no natural join key against `shares`/`blocks`
	// rows themselves. No row existing here (no poller configured/
	// has not run yet) is not an error -- s's four Network* fields
	// simply stay nil.
	const networkStateStmt = `
		SELECT height, difficulty, estimated_hashrate_hs, updated_at
		FROM network_state
		WHERE algo = $1 AND network = $2`
	var nHeight *int64
	var nDifficulty *float64
	var nHashrate *float64
	var nUpdatedAt *time.Time
	err := r.pool.QueryRow(ctx, networkStateStmt, algo, network).Scan(&nHeight, &nDifficulty, &nHashrate, &nUpdatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return NetworkStats{}, fmt.Errorf("db: querying network_state for %s/%s: %w", algo, network, err)
	}
	s.NetworkHeight = nHeight
	s.NetworkDifficulty = nDifficulty
	s.NetworkEstimatedHashrateHS = nHashrate
	s.NetworkStateUpdatedAt = nUpdatedAt

	return s, nil
}

// CurrentNetworkDifficulty returns the real chain's own current
// difficulty for (algo, network) as last recorded by
// internal/backend/networkpoller's independent poll loop in
// `network_state` -- a cheap, single-row read of already-fresh data,
// NOT a new upstream RPC call. Returns (nil, nil) when no
// network_state row exists yet for this (algo, network) (no poller
// configured, or it has not successfully polled yet) -- this is a
// legitimate "no value yet" outcome, not an error, mirroring
// NetworkStats.NetworkDifficulty's own nil-means-"never polled"
// convention. Used by cmd/backend's runHashHistoryPoller to snapshot
// hash_history's HashHistoryScopeNetworkDifficulty rows on the same
// cadence as every other hash-history sample, without this backend
// ever making its own separate upstream chain-state query.
func (r *Repository) CurrentNetworkDifficulty(ctx context.Context, algo, network string) (*float64, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}

	var difficulty *float64
	err := r.pool.QueryRow(ctx, `SELECT difficulty FROM network_state WHERE algo = $1 AND network = $2`, algo, network).Scan(&difficulty)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("db: querying current network difficulty for %s/%s: %w", algo, network, err)
	}
	return difficulty, nil
}

// NetworkState is one real, live chain-state snapshot this backend's
// networkpoller has recorded for one (algo, network) -- see
// migrations/0005_network_state.up.sql's doc comment for the full
// rationale/field semantics.
type NetworkState struct {
	Height              int64
	Difficulty          *float64
	EstimatedHashrateHS *float64
	BestBlockHash       string
	Source              string
	PolledAt            time.Time
}

// UpsertNetworkState records src's real, live chain-state snapshot as
// the current network_state row for (algo, network), overwriting
// whatever was there before -- see that table's migration doc
// comment for why this is an upsert-only, single-row-per-key table
// rather than an append-only time series.
func (r *Repository) UpsertNetworkState(ctx context.Context, algo, network string, src NetworkState) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidateNetwork(network); err != nil {
		return err
	}
	const stmt = `
		INSERT INTO network_state (algo, network, height, difficulty, estimated_hashrate_hs, best_block_hash, source, polled_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (algo, network) DO UPDATE SET
			height = EXCLUDED.height,
			difficulty = EXCLUDED.difficulty,
			estimated_hashrate_hs = EXCLUDED.estimated_hashrate_hs,
			best_block_hash = EXCLUDED.best_block_hash,
			source = EXCLUDED.source,
			polled_at = EXCLUDED.polled_at,
			updated_at = now()`
	if _, err := r.pool.Exec(ctx, stmt, algo, network, src.Height, src.Difficulty, src.EstimatedHashrateHS, src.BestBlockHash, src.Source, src.PolledAt); err != nil {
		return fmt.Errorf("db: upserting network_state for %s/%s: %w", algo, network, err)
	}
	return nil
}

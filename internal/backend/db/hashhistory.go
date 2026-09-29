// hashhistory.go implements this backend's bounded, Postgres-backed
// replacement for legacy worker.js's hash-history feature (see
// DISPATCH_BRIEF.md for the full legacy ground-truth writeup) --
// periodic hashrate/network-difficulty samples backing
// internal/backend/statsapi's history endpoints, written by
// cmd/backend's runHashHistoryPoller poll loop.
//
// This is intentionally split from stats.go (that file is
// SELECT-only, read-side query surface backing the miner-facing
// hashrate-right-now API) because this file has real write paths
// (InsertPoolTypeHashSample/InsertNetworkDifficultySample/
// InsertMinerHashSamples/PruneHashHistory) alongside its own reads --
// a genuinely different shape from stats.go's pure-query surface,
// even though both ultimately back the same public statsapi package.
//
// Design summary (see migrations/0018_hash_history.up.sql's own doc
// comment for the full column-shape rationale):
//   - One `hash_history` row per (algo, network, scope_type, ...)
//     sample point, four scope_type values: 'pool_type' (legacy's 5
//     pool-wide buckets, pplns/pps/solo/prop/global -- see
//     PoolTypeShareStatsSince), 'miner' (one address' hashrate summed
//     across workers), 'worker' (one address+worker's own hashrate),
//     and 'network_difficulty' (a snapshot of the real chain's own
//     difficulty, copied from the already-independently-polled
//     `network_state` table -- see db.CurrentNetworkDifficulty in
//     network.go).
//   - BOUNDED by construction, unlike legacy's unbounded in-process
//     maps: PruneHashHistory deletes every row older than a caller-
//     supplied cutoff (cmd/backend's poller computes this as
//     maxPoints*pollInterval, default 480*60s = 8h, matching legacy's
//     own real statsBufferLength=480 config value at its own 60s
//     cadence), and ActiveMinerHashrates caps the per-tick
//     miner/worker cardinality at DefaultShareStatsCardinalityCap
//     (the exact same constant commit 21df0fb introduced for
//     WorkerShareStatsSince/PoolSourceShareStatsSince in stats.go --
//     reused here as-is, not a new cap value).
//   - PruneHashHistory uses a plain row-level DELETE, NOT
//     internal/backend/retention's whole-partition DROP TABLE
//     mechanism: `hash_history` is not partitioned (it is small and
//     low-cardinality -- at most a few hundred pool_type/
//     network_difficulty rows plus
//     DefaultShareStatsCardinalityCap*2 (worker+miner-level)
//     miner/worker rows per tick, retained for a bounded number of
//     ticks), so a plain indexed DELETE ... WHERE sample_time < $1
//     (see idx_hash_history_sample_time) is fast enough that
//     partition-drop's extra DDL-management complexity buys nothing
//     here, unlike `shares`, which is genuinely large enough to need
//     it.
package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// HashHistoryScope* are hash_history.scope_type's four valid values --
// see migrations/0018_hash_history.up.sql's own doc comment for what
// each one means and which other columns it requires.
const (
	HashHistoryScopePoolType          = "pool_type"
	HashHistoryScopeMiner             = "miner"
	HashHistoryScopeWorker            = "worker"
	HashHistoryScopeNetworkDifficulty = "network_difficulty"
)

// HashHistoryGlobalPoolType is the pseudo pool_type value
// PoolTypeShareStatsSince/PoolTypeHashHistory use for legacy's
// whole-pool "global" bucket (the sum of every pool_type combined,
// computed as its own independent SQL aggregate -- see
// PoolTypeShareStatsSince's doc comment for why this is NOT simply
// the Go-side sum of the other four numbers) -- distinct from every
// real shares.pool_type CHECK value (SOLO/PPS/PPLNS/PROP) so a caller
// can never confuse it with a real pool_type.
const HashHistoryGlobalPoolType = "GLOBAL"

// validatePoolTypeOrGlobal validates poolType against
// db.ValidPoolTypes plus the HashHistoryGlobalPoolType sentinel --
// every hash_history 'pool_type'-scope read/write in this file uses
// this instead of a bare ValidPoolTypes membership check.
func validatePoolTypeOrGlobal(poolType string) error {
	if poolType == HashHistoryGlobalPoolType {
		return nil
	}
	for _, pt := range ValidPoolTypes {
		if poolType == pt {
			return nil
		}
	}
	return fmt.Errorf("db: unknown pool_type %q (want one of %v or %q)", poolType, ValidPoolTypes, HashHistoryGlobalPoolType)
}

// HashSample is one hash_history row's (hashrate, sample_time) pair --
// PoolTypeHashHistory/MinerHashHistory's shared read-side return
// element shape.
type HashSample struct {
	HashrateHS float64
	SampleTime time.Time
}

// DifficultySample is one hash_history row's (difficulty, sample_time)
// pair -- NetworkDifficultyHistory's return element shape.
type DifficultySample struct {
	Difficulty float64
	SampleTime time.Time
}

// PoolTypeShareStats is one pool_type bucket's (or the GLOBAL
// pseudo-bucket's) difficulty-weighted share sum over a window --
// PoolTypeShareStatsSince's return element shape, the input
// cmd/backend's hash-history poller feeds through
// statsapi.EstimateHashrateHS before calling InsertPoolTypeHashSample.
type PoolTypeShareStats struct {
	PoolType   string
	SharesSum  int64
	ShareCount int64
}

// PoolTypeShareStatsSince aggregates `shares` rows for (algo, network)
// with share_timestamp >= sinceUnix into legacy's 5 pool-wide buckets:
// one row per real shares.pool_type value (SOLO/PPS/PPLNS/PROP), each
// defaulting to SharesSum=0/ShareCount=0 if that pool_type had zero
// matching rows in the window (a LEFT JOIN against a fixed
// (SOLO),(PPS),(PPLNS),(PROP) VALUES list, NOT a bare GROUP BY, which
// would simply omit a pool_type with no rows instead of reporting it
// as a real zero -- legacy's own updateShareStats always reports
// every bucket, never omits one it just happens to have no current
// data for), PLUS one HashHistoryGlobalPoolType row computed as its
// own independent, un-narrowed aggregate over every pool_type
// combined in the SAME query (a second, unfiltered-by-pool_type SELECT
// UNION ALL'd on -- see this function's own SQL, and
// migrations/0018_hash_history.up.sql's doc comment: "not literally
// pplns+pps+solo" means this global figure is NOT the Go-side sum of
// the other four rows, even though in practice every shares row
// belongs to exactly one pool_type so the two would agree -- computing
// it independently in SQL exactly mirrors legacy's own query shape and
// avoids ever silently diverging from it due to a future
// pool_type-scoping change to the other four).
func (r *Repository) PoolTypeShareStatsSince(ctx context.Context, algo, network string, sinceUnix int64) ([]PoolTypeShareStats, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}

	const stmt = `
		WITH pt (pool_type) AS (VALUES ('SOLO'), ('PPS'), ('PPLNS'), ('PROP')),
		agg AS (
			SELECT pool_type, COALESCE(SUM(shares), 0) AS shares_sum, COUNT(*) AS share_count
			FROM shares
			WHERE algo = $1 AND network = $2 AND share_timestamp >= $3
			GROUP BY pool_type
		)
		SELECT pt.pool_type, COALESCE(agg.shares_sum, 0), COALESCE(agg.share_count, 0)
		FROM pt LEFT JOIN agg ON pt.pool_type = agg.pool_type
		UNION ALL
		SELECT $4, COALESCE(SUM(shares), 0), COUNT(*)
		FROM shares
		WHERE algo = $1 AND network = $2 AND share_timestamp >= $3`

	rows, err := r.pool.Query(ctx, stmt, algo, network, sinceUnix, HashHistoryGlobalPoolType)
	if err != nil {
		return nil, fmt.Errorf("db: querying pool-type share stats for %s/%s: %w", algo, network, err)
	}
	defer rows.Close()

	out := make([]PoolTypeShareStats, 0, len(ValidPoolTypes)+1)
	for rows.Next() {
		var s PoolTypeShareStats
		if err := rows.Scan(&s.PoolType, &s.SharesSum, &s.ShareCount); err != nil {
			return nil, fmt.Errorf("db: scanning pool-type share stats row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pool-type share stats rows: %w", err)
	}
	return out, nil
}

// MinerHashSample is one (algo, network, payment_address[, payment_id][,
// worker]) tuple's hashrate observation. It is deliberately shared
// between ActiveMinerHashrates' read-side result shape (Algo/Network/
// PaymentAddress/PaymentID/Worker/SharesSum/ShareCount populated,
// HashrateHS/SampleTime left zero) and InsertMinerHashSamples' write-
// side input shape (every field populated by the caller, HashrateHS
// computed via statsapi.EstimateHashrateHS from SharesSum) -- see
// cmd/backend's runHashHistoryPoller, the only real caller of both.
//
// Worker == "" means the miner-level scope (hash_history.scope_type =
// HashHistoryScopeMiner, summed across every worker this address had
// active in the window); a non-empty Worker means the worker-specific
// scope (HashHistoryScopeWorker, this one worker/rig identifier only)
// -- mirroring MinerHashHistory's nil/non-nil *string worker parameter
// convention. An empty string (not nil) is used here rather than
// *string, since shares.identifier is NOT NULL in the schema -- unlike
// payment_id, there is no real "absent" identifier value to
// distinguish from "".
type MinerHashSample struct {
	Algo           string
	Network        string
	PaymentAddress string
	PaymentID      *string
	Worker         string
	SharesSum      int64
	ShareCount     int64
	HashrateHS     float64
	SampleTime     time.Time
}

// ActiveMinerHashrates returns every (payment_address, payment_id,
// worker) tuple with at least one accepted `shares` row for (algo,
// network) since sinceUnix, aggregated exactly like
// WorkerShareStatsSince (SharesSum/ShareCount per tuple) but WITHOUT
// that function's payment_address = $N scoping filter -- this is the
// "which miners/workers are currently active, pool-wide" query
// cmd/backend's hash-history poller needs to know who to snapshot.
//
// Capped at DefaultShareStatsCardinalityCap rows via a plain
// ORDER BY shares_sum DESC LIMIT $N -- the SAME cap constant commit
// 21df0fb introduced for WorkerShareStatsSince/
// PoolSourceShareStatsSince (see that function's own doc comment for
// the full DoS rationale: `identifier` is free-text and
// miner-controlled, so an unbounded GROUP BY here has the identical
// unbounded-cardinality shape). Unlike those two functions, this
// query has no user-facing "Other" collapsed-aggregate row: this is
// an internal poller input, not a public API response, so silently
// dropping (not aggregating) tuples beyond the cap is sufficient to
// keep this design bounded -- see migrations/0018_hash_history.up.sql's
// doc comment for why an internal cap, rather than legacy's complete
// absence of one, is this feature's actual fix for today's real
// worker.js OOM.
func (r *Repository) ActiveMinerHashrates(ctx context.Context, algo, network string, sinceUnix int64) ([]MinerHashSample, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}

	const stmt = `
		SELECT payment_address, payment_id, identifier, COALESCE(SUM(shares), 0) AS shares_sum, COUNT(*) AS share_count
		FROM shares
		WHERE algo = $1 AND network = $2 AND share_timestamp >= $3
		GROUP BY payment_address, payment_id, identifier
		ORDER BY shares_sum DESC, payment_address ASC, COALESCE(payment_id, '') ASC, identifier ASC
		LIMIT $4`

	rows, err := r.pool.Query(ctx, stmt, algo, network, sinceUnix, DefaultShareStatsCardinalityCap)
	if err != nil {
		return nil, fmt.Errorf("db: querying active miner hashrates for %s/%s: %w", algo, network, err)
	}
	defer rows.Close()

	var out []MinerHashSample
	for rows.Next() {
		var s MinerHashSample
		if err := rows.Scan(&s.PaymentAddress, &s.PaymentID, &s.Worker, &s.SharesSum, &s.ShareCount); err != nil {
			return nil, fmt.Errorf("db: scanning active miner hashrate row: %w", err)
		}
		s.Algo = algo
		s.Network = network
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating active miner hashrate rows: %w", err)
	}
	return out, nil
}

// InsertPoolTypeHashSample writes one HashHistoryScopePoolType row.
// poolType must be a real ValidPoolTypes value or
// HashHistoryGlobalPoolType.
func (r *Repository) InsertPoolTypeHashSample(ctx context.Context, algo, network, poolType string, hashrateHS float64, ts time.Time) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidateNetwork(network); err != nil {
		return err
	}
	if err := validatePoolTypeOrGlobal(poolType); err != nil {
		return err
	}

	const stmt = `
		INSERT INTO hash_history (algo, network, scope_type, pool_type, hashrate_hs, sample_time)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := r.pool.Exec(ctx, stmt, algo, network, HashHistoryScopePoolType, poolType, hashrateHS, ts); err != nil {
		return fmt.Errorf("db: inserting pool-type hash-history sample for %s/%s/%s: %w", algo, network, poolType, err)
	}
	return nil
}

// InsertNetworkDifficultySample writes one
// HashHistoryScopeNetworkDifficulty row. difficulty is *float64 (not
// a bare float64) to mirror db.NetworkState.Difficulty/
// network_state.difficulty's own nullable shape exactly (see
// CurrentNetworkDifficulty in network.go) -- a nil difficulty is a
// caller bug, not a legitimate "no value" write: this function
// returns an error rather than silently writing a NULL
// network_difficulty row, since the caller (cmd/backend's
// runHashHistoryPoller) is expected to check CurrentNetworkDifficulty's
// own nil return and simply skip calling this at all when no real
// network_state row exists yet for this (algo, network) -- exactly
// mirroring how that poller must not fabricate a network-difficulty
// figure that was never actually observed.
func (r *Repository) InsertNetworkDifficultySample(ctx context.Context, algo, network string, difficulty *float64, ts time.Time) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidateNetwork(network); err != nil {
		return err
	}
	if difficulty == nil {
		return fmt.Errorf("db: InsertNetworkDifficultySample: difficulty is required (nil means \"no real network_state row yet for %s/%s\" -- the caller should check CurrentNetworkDifficulty's own nil return and skip this call entirely, not call it with nil)", algo, network)
	}

	const stmt = `
		INSERT INTO hash_history (algo, network, scope_type, network_difficulty, sample_time)
		VALUES ($1, $2, $3, $4, $5)`
	if _, err := r.pool.Exec(ctx, stmt, algo, network, HashHistoryScopeNetworkDifficulty, *difficulty, ts); err != nil {
		return fmt.Errorf("db: inserting network-difficulty hash-history sample for %s/%s: %w", algo, network, err)
	}
	return nil
}

// InsertMinerHashSamples batch-inserts every sample in one multi-row
// INSERT statement -- the exact anti-pattern legacy remoteShare.js's
// N-round-trips-per-write shape is called out as making it slow (see
// DISPATCH_BRIEF.md) is deliberately NOT reintroduced here. Each
// sample's own Algo/Network are used directly (samples may span more
// than one algo/network pair in a single call -- cmd/backend's
// runHashHistoryPoller does exactly this, batching every enabled
// (algo, network) target's miner+worker samples from one poll tick
// into a single InsertMinerHashSamples call), and each sample's own
// Worker field decides its row's scope_type (HashHistoryScopeWorker
// for a non-empty Worker, HashHistoryScopeMiner for "" -- see
// MinerHashSample's own doc comment). A nil/empty samples slice is a
// safe no-op, not an error (a poll tick with no currently-active
// miners is a legitimate, non-error outcome).
func (r *Repository) InsertMinerHashSamples(ctx context.Context, samples []MinerHashSample) error {
	if len(samples) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(`INSERT INTO hash_history (algo, network, scope_type, payment_address, payment_id, worker, hashrate_hs, sample_time) VALUES `)
	args := make([]any, 0, len(samples)*8)

	for i, s := range samples {
		if err := ValidateAlgo(s.Algo); err != nil {
			return fmt.Errorf("db: InsertMinerHashSamples[%d]: %w", i, err)
		}
		if err := ValidateNetwork(s.Network); err != nil {
			return fmt.Errorf("db: InsertMinerHashSamples[%d]: %w", i, err)
		}
		if s.PaymentAddress == "" {
			return fmt.Errorf("db: InsertMinerHashSamples[%d]: payment_address is required", i)
		}

		scopeType := HashHistoryScopeMiner
		var worker *string
		if s.Worker != "" {
			scopeType = HashHistoryScopeWorker
			w := s.Worker
			worker = &w
		}

		if i > 0 {
			sb.WriteString(", ")
		}
		base := len(args)
		fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)", base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8)
		args = append(args, s.Algo, s.Network, scopeType, s.PaymentAddress, s.PaymentID, worker, s.HashrateHS, s.SampleTime)
	}

	if _, err := r.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("db: batch-inserting %d miner hash-history sample(s): %w", len(samples), err)
	}
	return nil
}

// PoolTypeHashHistory returns every HashHistoryScopePoolType sample
// for (algo, network, poolType) with sample_time >= sinceUnix,
// ordered oldest-first (sample_time ASC) -- the natural left-to-right
// time-series order a chart/dashboard consumer wants, matching
// MinerHashHistory/NetworkDifficultyHistory's own ordering.
func (r *Repository) PoolTypeHashHistory(ctx context.Context, algo, network, poolType string, sinceUnix int64) ([]HashSample, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if err := validatePoolTypeOrGlobal(poolType); err != nil {
		return nil, err
	}
	since := time.Unix(sinceUnix, 0).UTC()

	const stmt = `
		SELECT hashrate_hs, sample_time
		FROM hash_history
		WHERE algo = $1 AND network = $2 AND scope_type = $3 AND pool_type = $4 AND sample_time >= $5
		ORDER BY sample_time ASC`

	rows, err := r.pool.Query(ctx, stmt, algo, network, HashHistoryScopePoolType, poolType, since)
	if err != nil {
		return nil, fmt.Errorf("db: querying pool-type hash history for %s/%s/%s: %w", algo, network, poolType, err)
	}
	defer rows.Close()

	var out []HashSample
	for rows.Next() {
		var s HashSample
		if err := rows.Scan(&s.HashrateHS, &s.SampleTime); err != nil {
			return nil, fmt.Errorf("db: scanning pool-type hash history row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pool-type hash history rows: %w", err)
	}
	return out, nil
}

// MinerHashHistory returns every hash_history sample for
// (algo, network, paymentAddress[, paymentID]) with sample_time >=
// sinceUnix, ordered oldest-first. worker == nil selects the
// miner-level scope (HashHistoryScopeMiner -- summed across every
// worker this address had active at each sample point); a non-nil
// worker selects that one worker's own HashHistoryScopeWorker rows --
// mirroring MinerHashSample.Worker's own convention on the write side.
func (r *Repository) MinerHashHistory(ctx context.Context, algo, network, paymentAddress string, paymentID *string, worker *string, sinceUnix int64) ([]HashSample, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if paymentAddress == "" {
		return nil, fmt.Errorf("db: MinerHashHistory: payment_address is required")
	}
	since := time.Unix(sinceUnix, 0).UTC()

	scopeType := HashHistoryScopeMiner
	if worker != nil {
		scopeType = HashHistoryScopeWorker
	}

	var sb strings.Builder
	sb.WriteString(`SELECT hashrate_hs, sample_time FROM hash_history WHERE algo = $1 AND network = $2 AND scope_type = $3 AND payment_address = $4`)
	args := []any{algo, network, scopeType, paymentAddress}
	if worker != nil {
		args = append(args, *worker)
		fmt.Fprintf(&sb, " AND worker = $%d", len(args))
	}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	args = append(args, since)
	fmt.Fprintf(&sb, " AND sample_time >= $%d ORDER BY sample_time ASC", len(args))

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying miner hash history for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var out []HashSample
	for rows.Next() {
		var s HashSample
		if err := rows.Scan(&s.HashrateHS, &s.SampleTime); err != nil {
			return nil, fmt.Errorf("db: scanning miner hash history row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating miner hash history rows: %w", err)
	}
	return out, nil
}

// NetworkDifficultyHistory returns every HashHistoryScopeNetworkDifficulty
// sample for (algo, network) with sample_time >= sinceUnix, ordered
// oldest-first.
func (r *Repository) NetworkDifficultyHistory(ctx context.Context, algo, network string, sinceUnix int64) ([]DifficultySample, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	since := time.Unix(sinceUnix, 0).UTC()

	const stmt = `
		SELECT network_difficulty, sample_time
		FROM hash_history
		WHERE algo = $1 AND network = $2 AND scope_type = $3 AND sample_time >= $4
		ORDER BY sample_time ASC`

	rows, err := r.pool.Query(ctx, stmt, algo, network, HashHistoryScopeNetworkDifficulty, since)
	if err != nil {
		return nil, fmt.Errorf("db: querying network-difficulty history for %s/%s: %w", algo, network, err)
	}
	defer rows.Close()

	var out []DifficultySample
	for rows.Next() {
		var s DifficultySample
		if err := rows.Scan(&s.Difficulty, &s.SampleTime); err != nil {
			return nil, fmt.Errorf("db: scanning network-difficulty history row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating network-difficulty history rows: %w", err)
	}
	return out, nil
}

// PruneHashHistory deletes every hash_history row with sample_time <
// olderThan and returns the number of rows actually deleted, for the
// caller (cmd/backend's runHashHistoryPoller) to log/report on a
// metric. See this file's own package doc comment for why a plain
// row-level DELETE (backed by idx_hash_history_sample_time), not
// internal/backend/retention's whole-partition DROP TABLE mechanism,
// is the right tool for this table.
func (r *Repository) PruneHashHistory(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM hash_history WHERE sample_time < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("db: pruning hash_history older than %s: %w", olderThan.Format(time.RFC3339), err)
	}
	return tag.RowsAffected(), nil
}

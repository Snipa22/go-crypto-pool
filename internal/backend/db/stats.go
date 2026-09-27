// stats.go implements the read-only, miner-facing query surface this
// backend exposes over HTTP (see internal/backend/statsapi). Everything
// here is SELECT-only against the schema in
// migrations/0001_initial_schema.up.sql — no code path in this file
// ever writes a row. It is kept as its own file (rather than folded
// into repository.go) because it serves a genuinely different
// caller/trust boundary: repository.go's methods back the leaf
// ingestion + payout/disbursement engines (internal, trusted
// call-sites), while this file backs a public-ish, miner-supplied-
// payment-address query surface.
package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Balance is one `balance` table row, as needed by the miner stats
// API. Mirrors the `balance` table's columns 1:1 (see migrations).
type Balance struct {
	Algo           string
	Network        string
	PaymentAddress string
	PaymentID      *string
	PendingBalance int64
	PaidBalance    int64
	UpdatedAt      time.Time
}

// MinerBalances returns every `balance` row for paymentAddress,
// optionally narrowed by algo/network/paymentID. Empty-string
// algo/network mean "no filter on that column" (return every algo/
// network this address has a balance row for); a nil paymentID means
// "no filter on payment_id" (return rows for every payment_id variant
// of this address), while a non-nil paymentID (including a pointer to
// "") filters to exactly that payment_id value — mirroring
// CreditBalance/uq_balance_identity's COALESCE(payment_id, ”)
// identity convention elsewhere in this package.
//
// Results are ordered by (algo, network, COALESCE(payment_id, ”))
// for a deterministic response shape.
func (r *Repository) MinerBalances(ctx context.Context, paymentAddress, algo, network string, paymentID *string) ([]Balance, error) {
	if paymentAddress == "" {
		return nil, fmt.Errorf("db: MinerBalances: payment_address is required")
	}
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
	sb.WriteString(`SELECT algo, network, payment_address, payment_id, pending_balance, paid_balance, updated_at
		FROM balance
		WHERE payment_address = $1`)
	args := []any{paymentAddress}

	if algo != "" {
		args = append(args, algo)
		fmt.Fprintf(&sb, " AND algo = $%d", len(args))
	}
	if network != "" {
		args = append(args, network)
		fmt.Fprintf(&sb, " AND network = $%d", len(args))
	}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	sb.WriteString(" ORDER BY algo, network, COALESCE(payment_id, '')")

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying miner balances for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var out []Balance
	for rows.Next() {
		var b Balance
		if err := rows.Scan(&b.Algo, &b.Network, &b.PaymentAddress, &b.PaymentID, &b.PendingBalance, &b.PaidBalance, &b.UpdatedAt); err != nil {
			return nil, fmt.Errorf("db: scanning miner balance row: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating miner balance rows: %w", err)
	}
	return out, nil
}

// ShareStats is an aggregate over a window of `shares` rows: the
// difficulty-weighted sum (the `shares` column — see
// internal/backend/payout's doc comment: this is the same
// "hashes"/difficulty-equivalent weight PPS/PPLNS payout math already
// treats it as) and the raw row count. SharesSum is the input to the
// standard difficulty/elapsed-time hashrate approximation (see
// internal/backend/statsapi's EstimateHashrateHS, which mirrors
// internal/leaflib.EstimateHashrateHz's exact formula/convention on
// the backend's DB-query-based side of the pool).
type ShareStats struct {
	SharesSum  int64
	ShareCount int64
}

// ShareStatsSince aggregates every `shares` row for (algo, network,
// paymentAddress[, paymentID]) with share_timestamp >= sinceUnix
// (inclusive; share_timestamp is the leaf-assigned unix seconds
// carried on Share.timestamp — see migrations' column comment). algo
// is required and validated (it is this table's top partition-list
// key, so an invalid value is a caller bug, not a legitimate empty
// result) mirroring SharesAtHeight/SoloShare's own ValidateAlgo calls.
// A nil paymentID matches every payment_id variant of paymentAddress;
// a non-nil one (including "") filters to exactly that value.
func (r *Repository) ShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (ShareStats, error) {
	if err := ValidateAlgo(algo); err != nil {
		return ShareStats{}, err
	}
	if err := ValidateNetwork(network); err != nil {
		return ShareStats{}, err
	}
	if paymentAddress == "" {
		return ShareStats{}, fmt.Errorf("db: ShareStatsSince: payment_address is required")
	}

	var sb strings.Builder
	sb.WriteString(`SELECT COALESCE(SUM(shares), 0), COUNT(*)
		FROM shares
		WHERE algo = $1 AND network = $2 AND payment_address = $3 AND share_timestamp >= $4`)
	args := []any{algo, network, paymentAddress, sinceUnix}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}

	var s ShareStats
	if err := r.pool.QueryRow(ctx, sb.String(), args...).Scan(&s.SharesSum, &s.ShareCount); err != nil {
		return ShareStats{}, fmt.Errorf("db: querying share stats for %s: %w", paymentAddress, err)
	}
	return s, nil
}

// DefaultShareStatsCardinalityCap is the maximum number of distinct
// GROUP BY rows WorkerShareStatsSince/PoolSourceShareStatsSince will
// ever return as individually-named "kept" rows. `identifier` (the
// worker/rig name — WorkerShareStatsSince's GROUP BY key) is a
// free-text, miner-controlled string carried on every submitted
// share: a malicious miner/leaf can submit shares under an enormous
// number of distinct identifier values for one payment_address,
// and every subsequent call to this query (i.e. every hit to the
// public stats page) would otherwise have to materialize/sort and
// ship back an unbounded number of result rows. This mirrors
// internal/leaflib/metrics.DefaultMaxAddressLabels/CapAddressCounts's
// own "top-N kept, remainder collapsed into one aggregate 'other'
// bucket" cardinality-capping discipline for the directly analogous
// per-address Prometheus-label-cardinality problem — 100 is generous
// for any real miner's real worker-rig count or an operator's real
// pool_id count, while still bounding worst-case cardinality from a
// hostile flood of junk identifiers to a small, fixed number of rows
// returned to the Go process (see WorkerShareStatsSince/
// PoolSourceShareStatsSince's own doc comments for how the SQL itself
// enforces this server-side, not just a client-side truncation).
const DefaultShareStatsCardinalityCap = 100

// WorkerShareStats is one identifier's (worker/rig name's)
// contribution to a ShareStatsSince-style aggregate, broken out per
// worker instead of summed across all of an address's workers — see
// WorkerShareStatsSince.
type WorkerShareStats struct {
	Identifier string
	SharesSum  int64
	ShareCount int64
}

// WorkerShareStatsOther is the single collapsed aggregate row
// representing every identifier beyond WorkerShareStatsSince's
// DefaultShareStatsCardinalityCap-th ranked identifier — see
// WorkerShareStatsResult's doc comment for why this is a distinct
// type from WorkerShareStats rather than a WorkerShareStats row
// literally named "other" (which would be ambiguous against a real
// identifier that happens to be named "other").
type WorkerShareStatsOther struct {
	SharesSum       int64
	ShareCount      int64
	IdentifierCount int
}

// WorkerShareStatsResult is WorkerShareStatsSince's return shape:
// Rows holds the top-ranked (by SharesSum descending, identifier
// ascending as a deterministic tie-break) kept identifiers, capped at
// DefaultShareStatsCardinalityCap entries; Other, if non-nil, is the
// single aggregate row for every identifier beyond that cap (nil
// means nothing was collapsed — the true distinct-identifier count
// for this query was <= the cap).
type WorkerShareStatsResult struct {
	Rows  []WorkerShareStats
	Other *WorkerShareStatsOther
}

// PoolSourceShareStats is ShareStatsSince's per-pool-server-source
// breakdown: same aggregate shape as WorkerShareStats, but grouped by
// `pool_id` (the static, operator-assigned pool-server-source
// identifier every leaf-direct process stamps on its own shares — see
// internal/proto/share.proto's Share.pool_id doc comment for the full
// "scoped-down /poolInit" rationale) instead of `identifier`. This is
// the query that actually makes pool_id's real, wired-up value useful
// for anything: an operator running more than one leaf-direct process
// against the same backend can see hashrate/share-volume attributed
// per physical pool-server instance, exactly the question the legacy
// stack's /poolInit registration existed to answer.
type PoolSourceShareStats struct {
	PoolID     int32
	SharesSum  int64
	ShareCount int64
}

// PoolSourceShareStatsOther is WorkerShareStatsOther's pool_id
// analogue — see that type's doc comment.
type PoolSourceShareStatsOther struct {
	SharesSum   int64
	ShareCount  int64
	PoolIDCount int
}

// PoolSourceShareStatsResult is WorkerShareStatsResult's pool_id
// analogue — see that type's doc comment.
type PoolSourceShareStatsResult struct {
	Rows  []PoolSourceShareStats
	Other *PoolSourceShareStatsOther
}

// PoolSourceShareStatsSince is WorkerShareStatsSince's pool_id
// analogue: identical filter/validation rules, identical
// SharesSum-descending ordering convention (busiest pool-server
// source first), and identical
// DefaultShareStatsCardinalityCap-enforcing query shape — see that
// function's doc comment for the full rationale/SQL-shape writeup,
// which applies here verbatim with `pool_id` in place of
// `identifier`.
func (r *Repository) PoolSourceShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (PoolSourceShareStatsResult, error) {
	if err := ValidateAlgo(algo); err != nil {
		return PoolSourceShareStatsResult{}, err
	}
	if err := ValidateNetwork(network); err != nil {
		return PoolSourceShareStatsResult{}, err
	}
	if paymentAddress == "" {
		return PoolSourceShareStatsResult{}, fmt.Errorf("db: PoolSourceShareStatsSince: payment_address is required")
	}

	var where strings.Builder
	where.WriteString("algo = $1 AND network = $2 AND payment_address = $3 AND share_timestamp >= $4")
	args := []any{algo, network, paymentAddress, sinceUnix}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&where, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	args = append(args, DefaultShareStatsCardinalityCap)
	capIdx := len(args)

	query := fmt.Sprintf(`WITH agg AS (
	SELECT pool_id, COALESCE(SUM(shares), 0) AS shares_sum, COUNT(*) AS share_count
	FROM shares
	WHERE %s
	GROUP BY pool_id
), ranked AS (
	SELECT pool_id, shares_sum, share_count,
	       ROW_NUMBER() OVER (ORDER BY shares_sum DESC, pool_id ASC) AS rn
	FROM agg
)
SELECT pool_id, shares_sum, share_count, 0 AS other_count, rn AS sort_key
FROM ranked
WHERE rn <= $%d
UNION ALL
SELECT NULL::integer, COALESCE(SUM(shares_sum), 0), COALESCE(SUM(share_count), 0), COUNT(*)::int, $%d AS sort_key
FROM ranked
WHERE rn > $%d
ORDER BY sort_key`, where.String(), capIdx, capIdx, capIdx)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return PoolSourceShareStatsResult{}, fmt.Errorf("db: querying pool-source share stats for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var result PoolSourceShareStatsResult
	for rows.Next() {
		var (
			poolID     *int32
			sharesSum  int64
			shareCount int64
			otherCount int
			sortKey    int64
		)
		if err := rows.Scan(&poolID, &sharesSum, &shareCount, &otherCount, &sortKey); err != nil {
			return PoolSourceShareStatsResult{}, fmt.Errorf("db: scanning pool-source share stats row: %w", err)
		}
		if poolID == nil {
			if otherCount > 0 {
				result.Other = &PoolSourceShareStatsOther{
					SharesSum:   sharesSum,
					ShareCount:  shareCount,
					PoolIDCount: otherCount,
				}
			}
			continue
		}
		result.Rows = append(result.Rows, PoolSourceShareStats{PoolID: *poolID, SharesSum: sharesSum, ShareCount: shareCount})
	}
	if err := rows.Err(); err != nil {
		return PoolSourceShareStatsResult{}, fmt.Errorf("db: iterating pool-source share stats rows: %w", err)
	}
	return result, nil
}

// WorkerShareStatsSince is ShareStatsSince's per-worker breakdown:
// same filter/validation rules, but grouped by `identifier` (the
// worker/rig name carried on every shares row — see migrations'
// column comment) instead of collapsed into one total. Ordered by
// SharesSum descending (busiest worker first) so a typical "which of
// my rigs is doing the most work" miner question doesn't need any
// client-side sorting.
//
// `identifier` is free-text and miner-controlled (see
// DefaultShareStatsCardinalityCap's doc comment for the DoS this
// guards against), so the returned row count is capped server-side:
// the query below ranks every distinct identifier's aggregate via a
// ROW_NUMBER() window function over one single-pass GROUP BY, then
// UNIONs together (a) the top DefaultShareStatsCardinalityCap ranked
// rows and (b) exactly one additional aggregate row summing
// everything beyond that rank — so Postgres is never asked to ship
// back more than DefaultShareStatsCardinalityCap+1 rows to this
// process, regardless of how many distinct identifiers actually
// exist. That trailing aggregate row is always present in the SQL
// result set (a bare aggregate with no GROUP BY always emits exactly
// one row, even summing zero underlying rows) — WorkerShareStatsSince
// distinguishes a real collapsed "other" bucket from that "nothing to
// collapse" case by checking whether it collapsed at least one
// identifier (other_count > 0) before setting
// WorkerShareStatsResult.Other, so a caller never sees a spurious
// "other" entry when the true distinct-identifier count is within
// the cap.
func (r *Repository) WorkerShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) (WorkerShareStatsResult, error) {
	if err := ValidateAlgo(algo); err != nil {
		return WorkerShareStatsResult{}, err
	}
	if err := ValidateNetwork(network); err != nil {
		return WorkerShareStatsResult{}, err
	}
	if paymentAddress == "" {
		return WorkerShareStatsResult{}, fmt.Errorf("db: WorkerShareStatsSince: payment_address is required")
	}

	var where strings.Builder
	where.WriteString("algo = $1 AND network = $2 AND payment_address = $3 AND share_timestamp >= $4")
	args := []any{algo, network, paymentAddress, sinceUnix}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&where, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	args = append(args, DefaultShareStatsCardinalityCap)
	capIdx := len(args)

	query := fmt.Sprintf(`WITH agg AS (
	SELECT identifier, COALESCE(SUM(shares), 0) AS shares_sum, COUNT(*) AS share_count
	FROM shares
	WHERE %s
	GROUP BY identifier
), ranked AS (
	SELECT identifier, shares_sum, share_count,
	       ROW_NUMBER() OVER (ORDER BY shares_sum DESC, identifier ASC) AS rn
	FROM agg
)
SELECT identifier, shares_sum, share_count, 0 AS other_count, rn AS sort_key
FROM ranked
WHERE rn <= $%d
UNION ALL
SELECT NULL::text, COALESCE(SUM(shares_sum), 0), COALESCE(SUM(share_count), 0), COUNT(*)::int, $%d AS sort_key
FROM ranked
WHERE rn > $%d
ORDER BY sort_key`, where.String(), capIdx, capIdx, capIdx)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return WorkerShareStatsResult{}, fmt.Errorf("db: querying worker share stats for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var result WorkerShareStatsResult
	for rows.Next() {
		var (
			identifier *string
			sharesSum  int64
			shareCount int64
			otherCount int
			sortKey    int64
		)
		if err := rows.Scan(&identifier, &sharesSum, &shareCount, &otherCount, &sortKey); err != nil {
			return WorkerShareStatsResult{}, fmt.Errorf("db: scanning worker share stats row: %w", err)
		}
		if identifier == nil {
			if otherCount > 0 {
				result.Other = &WorkerShareStatsOther{
					SharesSum:       sharesSum,
					ShareCount:      shareCount,
					IdentifierCount: otherCount,
				}
			}
			continue
		}
		result.Rows = append(result.Rows, WorkerShareStats{Identifier: *identifier, SharesSum: sharesSum, ShareCount: shareCount})
	}
	if err := rows.Err(); err != nil {
		return WorkerShareStatsResult{}, fmt.Errorf("db: iterating worker share stats rows: %w", err)
	}
	return result, nil
}

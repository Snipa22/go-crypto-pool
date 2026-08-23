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
// standard difficulty*2^32/elapsed-time hashrate approximation (see
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

// WorkerShareStats is one identifier's (worker/rig name's)
// contribution to a ShareStatsSince-style aggregate, broken out per
// worker instead of summed across all of an address's workers — see
// WorkerShareStatsSince.
type WorkerShareStats struct {
	Identifier string
	SharesSum  int64
	ShareCount int64
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

// PoolSourceShareStatsSince is WorkerShareStatsSince's pool_id
// analogue: identical filter/validation rules and identical
// SharesSum-descending ordering convention (busiest pool-server
// source first).
func (r *Repository) PoolSourceShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]PoolSourceShareStats, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if paymentAddress == "" {
		return nil, fmt.Errorf("db: PoolSourceShareStatsSince: payment_address is required")
	}

	var sb strings.Builder
	sb.WriteString(`SELECT pool_id, COALESCE(SUM(shares), 0), COUNT(*)
		FROM shares
		WHERE algo = $1 AND network = $2 AND payment_address = $3 AND share_timestamp >= $4`)
	args := []any{algo, network, paymentAddress, sinceUnix}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	sb.WriteString(" GROUP BY pool_id ORDER BY 2 DESC, pool_id ASC")

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying pool-source share stats for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var out []PoolSourceShareStats
	for rows.Next() {
		var p PoolSourceShareStats
		if err := rows.Scan(&p.PoolID, &p.SharesSum, &p.ShareCount); err != nil {
			return nil, fmt.Errorf("db: scanning pool-source share stats row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating pool-source share stats rows: %w", err)
	}
	return out, nil
}

// WorkerShareStatsSince is ShareStatsSince's per-worker breakdown:
// same filter/validation rules, but grouped by `identifier` (the
// worker/rig name carried on every shares row — see migrations'
// column comment) instead of collapsed into one total. Ordered by
// SharesSum descending (busiest worker first) so a typical "which of
// my rigs is doing the most work" miner question doesn't need any
// client-side sorting.
func (r *Repository) WorkerShareStatsSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]WorkerShareStats, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if paymentAddress == "" {
		return nil, fmt.Errorf("db: WorkerShareStatsSince: payment_address is required")
	}

	var sb strings.Builder
	sb.WriteString(`SELECT identifier, COALESCE(SUM(shares), 0), COUNT(*)
		FROM shares
		WHERE algo = $1 AND network = $2 AND payment_address = $3 AND share_timestamp >= $4`)
	args := []any{algo, network, paymentAddress, sinceUnix}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	sb.WriteString(" GROUP BY identifier ORDER BY 2 DESC, identifier ASC")

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying worker share stats for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var out []WorkerShareStats
	for rows.Next() {
		var w WorkerShareStats
		if err := rows.Scan(&w.Identifier, &w.SharesSum, &w.ShareCount); err != nil {
			return nil, fmt.Errorf("db: scanning worker share stats row: %w", err)
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating worker share stats rows: %w", err)
	}
	return out, nil
}

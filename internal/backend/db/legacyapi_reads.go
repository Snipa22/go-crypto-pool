// legacyapi_reads.go adds the small set of additive, read-only query
// methods internal/backend/legacyapi's SXMR-legacy-shaped wrapper
// routes need but that no existing package (statsapi/networkapi/
// disburse/payout) already exposes a Repository method for:
//
//   - ListBlocks: paginated `blocks` listing (legacy's
//     GET /pool/blocks[/:pool_type]). PendingBlocks (repository.go)
//     only returns still-pending rows for the unlocker's own poll
//     loop; nothing existing lists/paginates the full blocks history.
//   - ListPayouts: paginated `payouts` listing, optionally scoped to
//     the balance rows belonging to one payment address (legacy's
//     GET /pool/payments[/:pool_type] and
//     GET /miner/:address/payments). disburse.Repository is
//     write-path-focused (RecordPendingPayout/CompletePayoutSent/
//     FailPayout) and has no read surface at all.
//   - MinerIdentifiersSince: `miner_identifiers` freshness-windowed
//     listing (legacy's GET /miner/:address/identifiers and the
//     allWorkers chart/stats shapes). Nothing currently reads this
//     table — see repository.go's UpsertMinerIdentifier doc comment;
//     it has only ever been written to, never queried back out.
//
// This is read-plumbing only — none of these methods re-derive any
// payout/unlock/accounting LOGIC that already lives in payout/
// unlocker/disburse; they just expose existing columns via a plain
// paginated SELECT, per the legacyapi wrapper ticket's explicit
// carve-out for exactly this situation.
package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ListBlocks returns up to limit `blocks` rows for (algo, network),
// optionally narrowed by poolType (empty string means "no filter on
// pool_type" — legacy's bare GET /pool/blocks), newest (highest id)
// first, skipping the first offset matching rows. poolType is passed
// straight through as a plain equality filter with no CHECK-
// constraint-style validation here — an unrecognized value simply
// matches no rows (see internal/backend/legacyapi's own doc comment
// on why that package deliberately does not force this schema's
// string pool_type enum into legacy's int pooltype convention).
func (r *Repository) ListBlocks(ctx context.Context, algo, network, poolType string, limit, offset int) ([]Block, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}

	var sb strings.Builder
	sb.WriteString(`
		SELECT algo, network, pool_type, hash, height, difficulty, shares,
		       block_timestamp, unlocked, valid, value, pool_id, merge_mine_chain
		FROM blocks
		WHERE algo = $1 AND network = $2`)
	args := []any{algo, network}
	if poolType != "" {
		args = append(args, poolType)
		fmt.Fprintf(&sb, " AND pool_type = $%d", len(args))
	}
	args = append(args, limit, offset)
	fmt.Fprintf(&sb, " ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: listing blocks: %w", err)
	}
	defer rows.Close()

	var out []Block
	for rows.Next() {
		var b Block
		if err := rows.Scan(&b.Algo, &b.Network, &b.PoolType, &b.Hash, &b.Height, &b.Difficulty, &b.Shares,
			&b.Timestamp, &b.Unlocked, &b.Valid, &b.Value, &b.PoolID, &b.MergeMineChain); err != nil {
			return nil, fmt.Errorf("db: scanning block row: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating block rows: %w", err)
	}
	return out, nil
}

// Payout is one `payouts` row, as needed by the legacyapi wrapper's
// read-only payment-history endpoints — mirrors the `payouts` table's
// columns 1:1 (see migrations/0002_wallet_disbursements.up.sql).
type Payout struct {
	ID          int64
	Algo        string
	Network     string
	Status      string
	BalanceIDs  []int64
	Amount      int64
	Fee         *int64
	TxHash      *string
	Error       *string
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// ListPayouts returns up to limit real, SENT `payouts` rows for
// (algo, network), newest (highest id) first, skipping the first
// offset matching rows, and the total number of matching rows
// (ignoring limit/offset — a single COUNT(*) OVER() window function
// alongside the paginated rows, rather than a second round-trip
// query). Only SENT rows are returned — legacy's /pool/payments and
// /miner/:address/payments both describe actual, completed payments
// ("payment history"), not this schema's superset of PENDING/FAILED
// attempt records (see disburse's doc comment on the payouts status
// lifecycle) — a FAILED attempt moved no real coin and a PENDING one
// hasn't yet, so neither belongs in a "payments made" listing.
//
// paymentAddress, when non-nil, narrows to payouts whose balance_ids
// overlaps the given address's own `balance` row ids for (algo,
// network) — payouts has no payment_address column of its own (see
// this table's migration doc comment: it records one row per real
// Transfer RPC call, which can span multiple balance rows/addresses
// in one batch), so this is necessarily a two-step lookup (resolve
// the address's balance ids, then filter payouts on array overlap)
// rather than a single flat WHERE clause.
func (r *Repository) ListPayouts(ctx context.Context, algo, network string, paymentAddress *string, limit, offset int) ([]Payout, int64, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, 0, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}

	var sb strings.Builder
	sb.WriteString(`
		SELECT id, algo, network, status, balance_ids, amount, fee, tx_hash, error, created_at, completed_at,
		       COUNT(*) OVER() AS total_count
		FROM payouts
		WHERE algo = $1 AND network = $2 AND status = 'SENT'`)
	args := []any{algo, network}

	if paymentAddress != nil {
		balanceIDs, err := r.balanceIDsForAddress(ctx, algo, network, *paymentAddress)
		if err != nil {
			return nil, 0, err
		}
		if len(balanceIDs) == 0 {
			// No balance rows at all for this address -- it can never
			// have a matching payout, and `balance_ids && '{}'::bigint[]`
			// is never true anyway, so short-circuit rather than issue
			// a query that would just return zero rows the long way.
			return nil, 0, nil
		}
		args = append(args, balanceIDs)
		fmt.Fprintf(&sb, " AND balance_ids && $%d", len(args))
	}

	args = append(args, limit, offset)
	fmt.Fprintf(&sb, " ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("db: listing payouts: %w", err)
	}
	defer rows.Close()

	var out []Payout
	var total int64
	for rows.Next() {
		var p Payout
		if err := rows.Scan(&p.ID, &p.Algo, &p.Network, &p.Status, &p.BalanceIDs, &p.Amount, &p.Fee, &p.TxHash, &p.Error, &p.CreatedAt, &p.CompletedAt, &total); err != nil {
			return nil, 0, fmt.Errorf("db: scanning payout row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("db: iterating payout rows: %w", err)
	}
	return out, total, nil
}

// balanceIDsForAddress returns every `balance` row id for (algo,
// network, paymentAddress) -- ListPayouts' own small helper query for
// resolving a payment address down to the balance_ids it needs to
// overlap-match against `payouts.balance_ids`. Not exported: it has
// no standalone use outside ListPayouts' two-step lookup.
func (r *Repository) balanceIDsForAddress(ctx context.Context, algo, network, paymentAddress string) ([]int64, error) {
	const stmt = `SELECT id FROM balance WHERE algo = $1 AND network = $2 AND payment_address = $3`
	rows, err := r.pool.Query(ctx, stmt, algo, network, paymentAddress)
	if err != nil {
		return nil, fmt.Errorf("db: resolving balance ids for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("db: scanning balance id row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating balance id rows: %w", err)
	}
	return ids, nil
}

// MinerIdentifier is one `miner_identifiers` row, as needed by the
// legacyapi wrapper's worker-identifier-sourcing endpoints (see this
// file's package doc comment). LastShare is nil for a row that was
// somehow inserted without ever recording a share timestamp — not a
// real state InsertShare's own upsert path can produce (it always
// passes a concrete lastShare), but MinerIdentifiersSince's SQL
// treats it defensively rather than assuming otherwise.
type MinerIdentifier struct {
	WorkerName string
	LastShare  *time.Time
}

// MinerIdentifiersSince returns every `miner_identifiers` row for
// (algo, network, paymentAddress[, paymentID]) whose last_share is >=
// sinceUnix, ordered by worker_name ascending. A nil paymentID
// matches every payment_id variant of paymentAddress (mirroring
// ShareStatsSince's own convention); a non-nil one (including "")
// filters to exactly that value. Pass sinceUnix = 0 (or any value at
// or before every real share this backend has ever recorded) to get
// "every worker this address has ever registered", independent of
// recency — used by the allWorkers stats/chart shapes, as opposed to
// GET /miner/:address/identifiers' own real 10-minute freshness
// window (see internal/backend/legacyapi).
func (r *Repository) MinerIdentifiersSince(ctx context.Context, algo, network, paymentAddress string, paymentID *string, sinceUnix int64) ([]MinerIdentifier, error) {
	if err := ValidateAlgo(algo); err != nil {
		return nil, err
	}
	if err := ValidateNetwork(network); err != nil {
		return nil, err
	}
	if paymentAddress == "" {
		return nil, fmt.Errorf("db: MinerIdentifiersSince: payment_address is required")
	}

	since := time.Unix(sinceUnix, 0).UTC()

	var sb strings.Builder
	sb.WriteString(`
		SELECT worker_name, last_share
		FROM miner_identifiers
		WHERE algo = $1 AND network = $2 AND payment_address = $3 AND last_share >= $4`)
	args := []any{algo, network, paymentAddress, since}
	if paymentID != nil {
		args = append(args, *paymentID)
		fmt.Fprintf(&sb, " AND COALESCE(payment_id, '') = $%d", len(args))
	}
	sb.WriteString(" ORDER BY worker_name ASC")

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("db: querying miner identifiers for %s: %w", paymentAddress, err)
	}
	defer rows.Close()

	var out []MinerIdentifier
	for rows.Next() {
		var m MinerIdentifier
		if err := rows.Scan(&m.WorkerName, &m.LastShare); err != nil {
			return nil, fmt.Errorf("db: scanning miner identifier row: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating miner identifier rows: %w", err)
	}
	return out, nil
}

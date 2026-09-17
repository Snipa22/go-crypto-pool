package db

// payoutreconcile.go holds the read/write surface for UNRESOLVED
// payouts — the PENDING and AMBIGUOUS `payouts` rows introduced (for
// AMBIGUOUS) / finally given a reader (for PENDING) by
// migrations/0010_payouts_ambiguous_status.up.sql.
//
// Before this file existed, PENDING had no reader anywhere outside
// tests: a process that died between "real Transfer RPC succeeded"
// and "balances debited" left a PENDING row that nothing ever looked
// at, nothing alerted on, and nothing blocked further disbursement
// on. Combined with internal/backend/disburse treating every Transfer
// error as "definitely nothing moved", that meant real coin could be
// (and was) sent twice. See that migration's doc comment for the full
// writeup.
//
// Everything here is deliberately split out of repository.go: those
// are the hot, per-cycle disbursement writes; these are the
// incident-response queries and the two manual, operator-driven
// resolution transactions behind cmd/backend's `backend payout
// resolve-sent` / `resolve-not-sent` subcommands.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Unresolved payout statuses. These are the two `payouts.status`
// values that mean "this disbursement attempt has no recorded
// outcome yet", and are the exact set every unresolved-payout query
// in this file (and PayableBalances' anti-join in repository.go)
// filters on.
const (
	// PayoutStatusPending — a row inserted by RecordPendingPayout
	// immediately before the real Transfer RPC call, never
	// subsequently resolved. Either the process died mid-call, or
	// the RPC is still in flight right now.
	PayoutStatusPending = "PENDING"
	// PayoutStatusAmbiguous — the real Transfer call (or the local
	// bookkeeping write that follows it) failed in a way that
	// cannot rule out that coin already moved on-chain. See
	// Repository.MarkPayoutAmbiguous.
	PayoutStatusAmbiguous = "AMBIGUOUS"
)

// ErrPayoutNotFound is returned by GetPayoutByID when no `payouts`
// row has the requested id, mirroring this package's established
// ErrBalanceNotFound/ErrUserNotFound/ErrMotdNotFound convention so
// callers (the payout CLI) can distinguish "no such payout" from a
// real database failure without string matching.
var ErrPayoutNotFound = errors.New("db: payout not found")

// ErrPayoutAlreadyResolved is returned by ResolvePayoutSent/
// ResolvePayoutNotSent when the target row is no longer in an
// unresolved status (PENDING/AMBIGUOUS) — i.e. somebody or something
// already resolved it. This is a hard refusal, never a no-op: both
// resolution paths move real money semantics (one debits balances,
// the other makes them payable again), so applying either twice is
// exactly the class of bug this whole file exists to prevent.
var ErrPayoutAlreadyResolved = errors.New("db: payout is not in an unresolved (PENDING/AMBIGUOUS) status")

// PayoutEntryRecord is one `balance` row's durable contribution to a
// `payouts` row, as stored in that row's pending_entries JSONB column
// by RecordPendingPayout. Mirrors DisburseEntry field-for-field; the
// JSON tags are the on-disk contract (see
// migrations/0010_payouts_ambiguous_status.up.sql) and must not be
// renamed without a data migration.
type PayoutEntryRecord struct {
	BalanceID            int64 `json:"balance_id"`
	Amount               int64 `json:"amount"`
	ForcePayout          bool  `json:"force_payout"`
	ForcePayoutFeeAtomic int64 `json:"force_payout_fee_atomic"`
}

// UnresolvedPayout is one unresolved (PENDING or AMBIGUOUS) `payouts`
// row, with everything an operator or the startup check needs to
// understand what is stuck and why: the recorded balance rows, the
// attempted amount, whichever tx_hash (if any) is known, the error
// that produced the state, and the per-entry debit detail a
// resolve-sent would replay.
type UnresolvedPayout struct {
	ID      int64
	Algo    string
	Network string
	// Currency mirrors this row's `payouts.currency` column (see
	// migrations/0014_balance_payouts_currency.up.sql) — which
	// wallet/ledger this attempted transfer belongs to. Always "XTM"
	// for RXT/C29/SHA3X; "XMR" or "XTM" for ALGO_RXM depending on
	// which merge-mine leg produced the credits this payout drains.
	Currency   string
	Status     string
	BalanceIDs []int64
	// Amount is the batch's real on-chain destination total (after
	// any force-payout fee deduction) — see RecordPendingPayout.
	Amount    int64
	TxHash    *string
	Error     *string
	CreatedAt time.Time
	// Entries is the per-`balance`-row debit detail recorded before
	// the attempt. Nil for any historical row written before
	// migration 0010 added pending_entries — such a row cannot be
	// resolved via ResolvePayoutSent (there is no durable record of
	// what to debit, and guessing from live balances would risk
	// overpaying the pool against a miner), and ResolvePayoutSent
	// refuses it explicitly rather than improvising.
	Entries []PayoutEntryRecord
}

// UnresolvedPayouts returns every unresolved (PENDING or AMBIGUOUS)
// `payouts` row, oldest (lowest id) first. algo, network, AND/OR
// currency may be empty to mean "any" — the operator-facing `backend
// payout list-unresolved` passes any subset (or none) of the three to
// survey the whole deployment or narrow it down, mirroring the
// existing algo/network "empty means any" convention. Contrast this
// with internal/backend/disburse.Repository's own currency parameter
// (see PayableBalances/CreditBalance's doc comments), which is always
// REQUIRED — the engine's own per-(algo, network, currency) halt gate
// must always state exactly which wallet it means, never "any".
//
// A non-empty algo/network/currency IS validated (ValidateAlgo/
// ValidateNetwork/ValidateCurrency): a typo'd filter silently
// returning "no unresolved payouts" would be a catastrophic false
// all-clear for a check whose entire job is to block disbursement, so
// it is reported as an error instead.
func (r *Repository) UnresolvedPayouts(ctx context.Context, algo, network, currency string) ([]UnresolvedPayout, error) {
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
	if currency != "" {
		if err := ValidateCurrency(currency); err != nil {
			return nil, err
		}
	}

	const stmt = `
		SELECT id, algo, network, currency, status, balance_ids, amount, tx_hash, error, created_at, pending_entries
		FROM payouts
		WHERE status IN ('PENDING', 'AMBIGUOUS')
		  AND ($1 = '' OR algo = $1)
		  AND ($2 = '' OR network = $2)
		  AND ($3 = '' OR currency = $3)
		ORDER BY id ASC`
	rows, err := r.pool.Query(ctx, stmt, algo, network, currency)
	if err != nil {
		return nil, fmt.Errorf("db: querying unresolved payouts: %w", err)
	}
	defer rows.Close()

	var out []UnresolvedPayout
	for rows.Next() {
		p, err := scanUnresolvedPayout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating unresolved payout rows: %w", err)
	}
	return out, nil
}

// payoutScanner is the subset of pgx.Rows/pgx.Row scanUnresolvedPayout
// needs, so the same scan+JSON-decode logic serves both the
// multi-row UnresolvedPayouts query and the single-row
// GetPayoutByID lookup.
type payoutScanner interface {
	Scan(dest ...any) error
}

func scanUnresolvedPayout(s payoutScanner) (UnresolvedPayout, error) {
	var p UnresolvedPayout
	var entriesJSON []byte
	if err := s.Scan(&p.ID, &p.Algo, &p.Network, &p.Currency, &p.Status, &p.BalanceIDs, &p.Amount,
		&p.TxHash, &p.Error, &p.CreatedAt, &entriesJSON); err != nil {
		return UnresolvedPayout{}, err
	}
	if len(entriesJSON) > 0 {
		if err := json.Unmarshal(entriesJSON, &p.Entries); err != nil {
			return UnresolvedPayout{}, fmt.Errorf("db: decoding payout %d pending_entries: %w", p.ID, err)
		}
	}
	return p, nil
}

// GetPayoutByID returns one `payouts` row by primary key in the same
// UnresolvedPayout shape UnresolvedPayouts uses, REGARDLESS of its
// status (a SENT/FAILED row is returned too, with its real status in
// the Status field) — this exists for the operator-facing `backend
// payout show`, whose whole job is to let a human see the current
// state of a row before and after resolving it, including rows that
// turn out to already be resolved. Returns ErrPayoutNotFound if no
// such row exists.
func (r *Repository) GetPayoutByID(ctx context.Context, id int64) (UnresolvedPayout, error) {
	const stmt = `
		SELECT id, algo, network, currency, status, balance_ids, amount, tx_hash, error, created_at, pending_entries
		FROM payouts
		WHERE id = $1`
	p, err := scanUnresolvedPayout(r.pool.QueryRow(ctx, stmt, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UnresolvedPayout{}, fmt.Errorf("db: getting payout %d: %w", id, ErrPayoutNotFound)
		}
		return UnresolvedPayout{}, fmt.Errorf("db: getting payout %d: %w", id, err)
	}
	return p, nil
}

// ResolvePayoutSent resolves an unresolved payout that an operator has
// independently CONFIRMED did really broadcast on-chain: it replays
// the exact debit the original CompletePayoutSent would have applied
// (using the per-entry detail recorded in pending_entries before the
// attempt — never re-derived from current `balance` state) and flips
// the row to SENT with the confirmed tx_hash/real network fee, all in
// one transaction, recording resolvedBy/note for audit.
//
// The miner is NOT paid again — that is the entire point: the coin
// already left the hot wallet, so the correct bookkeeping is to
// finish recording it (debit pending_balance, credit paid_balance,
// consume any force_payout flag, bank any force-payout fee), not to
// re-send.
//
// Refuses, with ErrPayoutAlreadyResolved, any row not currently in
// PENDING/AMBIGUOUS status (the guard lives in the same transaction
// as the debit — see completePayoutSent), and refuses any row with no
// recorded pending_entries (a pre-0010 historical row): without that
// durable per-row detail there is no safe amount to debit, and
// inventing one risks silently overpaying the pool against a miner
// whose pending_balance has accrued since. Such a row must be handled
// with a hand-written, reviewed SQL statement by an operator who has
// established the real amounts, not by this command.
func (r *Repository) ResolvePayoutSent(ctx context.Context, payoutID int64, txHash string, fee int64, resolvedBy, note string) error {
	p, err := r.GetPayoutByID(ctx, payoutID)
	if err != nil {
		return err
	}
	if p.Status != PayoutStatusPending && p.Status != PayoutStatusAmbiguous {
		return fmt.Errorf("db: resolving payout %d as sent: status is %s: %w", payoutID, p.Status, ErrPayoutAlreadyResolved)
	}
	if len(p.Entries) == 0 {
		return fmt.Errorf("db: resolving payout %d as sent: row has no recorded pending_entries (predates migration 0010), so the exact per-balance debit it would have applied is unknown — refusing to guess; resolve this row by hand after establishing the real per-balance amounts", payoutID)
	}
	if txHash == "" {
		return fmt.Errorf("db: resolving payout %d as sent: a confirmed tx_hash is required", payoutID)
	}

	entries := make([]DisburseEntry, 0, len(p.Entries))
	for _, e := range p.Entries {
		entries = append(entries, DisburseEntry{
			BalanceID:            e.BalanceID,
			Amount:               e.Amount,
			ForcePayout:          e.ForcePayout,
			ForcePayoutFeeAtomic: e.ForcePayoutFeeAtomic,
		})
	}
	return r.completePayoutSent(ctx, payoutID, entries, txHash, fee, &resolvedBy, &note)
}

// ResolvePayoutNotSent resolves an unresolved payout that an operator
// has independently CONFIRMED never broadcast on-chain: it flips the
// row to FAILED (recording resolvedBy/note and appending them to the
// row's error text) and touches no `balance` row, which is exactly
// what makes those balances payable again — once this row is no
// longer unresolved, PayableBalances stops excluding them and the
// next disbursement cycle retries the payout normally.
//
// This is the ONLY sanctioned way to make an ambiguous payout's
// balances payable again, and it deliberately requires a human who
// has actually checked the chain/wallet history: if the transfer DID
// broadcast and this is run anyway, the pool pays the same coin
// twice. Refused, with ErrPayoutAlreadyResolved, for any row not
// currently in PENDING/AMBIGUOUS status.
func (r *Repository) ResolvePayoutNotSent(ctx context.Context, payoutID int64, resolvedBy, note string) error {
	const stmt = `
		UPDATE payouts
		SET status = 'FAILED',
		    error = COALESCE(error || ' | ', '') || 'manually resolved as NOT broadcast by ' || $2 || ': ' || $3,
		    resolved_by = $2,
		    resolution_note = $3,
		    completed_at = now()
		WHERE id = $1 AND status IN ('PENDING', 'AMBIGUOUS')`
	tag, err := r.pool.Exec(ctx, stmt, payoutID, resolvedBy, note)
	if err != nil {
		return fmt.Errorf("db: resolving payout %d as not sent: %w", payoutID, err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "no such row" from "already resolved" so the
		// operator gets a usable message rather than a bare failure.
		if _, getErr := r.GetPayoutByID(ctx, payoutID); getErr != nil {
			return getErr
		}
		return fmt.Errorf("db: resolving payout %d as not sent: %w", payoutID, ErrPayoutAlreadyResolved)
	}
	return nil
}

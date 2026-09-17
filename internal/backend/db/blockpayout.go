package db

// blockpayout.go holds the matured-block payout IDEMPOTENCY LEDGER --
// the `block_payouts` claim table and its per-miner
// `block_payout_credits` itemisation, added by
// migrations/0013_block_payouts.up.sql.
//
// Read that migration's doc comment before touching anything here: it
// is the full writeup of the two real bugs this file exists to fix (a
// fire-and-forget unlocker ordering that silently dropped matured-block
// payouts, and a non-transactional per-miner credit loop whose partial
// failures double-credited every already-paid miner on the only
// available "retry").
//
// Everything here is deliberately split out of repository.go, mirroring
// payoutreconcile.go's split for the disbursement side: repository.go
// holds the hot per-share/per-block ingestion writes, this file holds
// one money-critical transaction (ApplyBlockPayout) plus the
// incident-response queries and the two manual, operator-driven
// resolution transactions behind cmd/backend's `backend block-payout
// resolve-credited` / `resolve-not-credited` subcommands.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// block_payouts statuses. See migrations/0013_block_payouts.up.sql's
// and migrations/0014_block_payout_reversal.up.sql's doc comments for
// the full meaning of each; the short version:
//
//   - PENDING is UNRESOLVED and blocks all further automatic payout
//     for that block (the analog of an AMBIGUOUS `payouts` row).
//   - APPLIED is terminal success; ApplyBlockPayout is a no-op for it.
//   - FAILED is operator-asserted "nothing landed", and is
//     deliberately re-claimable (the analog of a FAILED `payouts`
//     row).
//   - REVERSED is the opposite of FAILED's "re-claimable": an
//     operator-asserted "this DID land, but for a block later found
//     to be invalid/orphaned, and its credits have now been debited
//     back out." Like APPLIED (and unlike FAILED), ApplyBlockPayout
//     treats REVERSED as a permanent, non-re-claimable no-op — a
//     REVERSED block must never be paid again. See
//     ReverseBlockPayoutCredits and migration 0014's doc comment.
const (
	BlockPayoutStatusPending  = "PENDING"
	BlockPayoutStatusApplied  = "APPLIED"
	BlockPayoutStatusFailed   = "FAILED"
	BlockPayoutStatusReversed = "REVERSED"
)

// ErrBlockPayoutPending is returned by ApplyBlockPayout when the target
// block already has a PENDING `block_payouts` row — a claimed run with
// no recorded outcome, i.e. an unknown subset of that block's miners
// may already hold its credit.
//
// This is a HARD REFUSAL, never a silent retry, and that is the whole
// point: blindly re-running the credits for such a block is exactly
// the double-credit bug migration 0011 exists to prevent. It requires
// the same kind of human resolution an AMBIGUOUS `payouts` row does
// (see payoutreconcile.go and cmd/backend/blockpayoutcli.go).
var ErrBlockPayoutPending = errors.New("db: block payout is PENDING (a claimed run with no recorded outcome) and requires manual resolution")

// ErrBlockPayoutNotFound is returned by GetBlockPayout when no
// `block_payouts` row exists for the requested block id, mirroring
// this package's established ErrPayoutNotFound/ErrBalanceNotFound
// convention so the CLI can distinguish "this block's payout has
// never been claimed" from a real database failure without string
// matching.
var ErrBlockPayoutNotFound = errors.New("db: block payout not found")

// ErrBlockPayoutAlreadyResolved is returned by
// ResolveBlockPayoutCredited/ResolveBlockPayoutNotCredited when the
// target row is not currently PENDING — i.e. somebody or something
// already resolved it. Like ErrPayoutAlreadyResolved this is a hard
// refusal rather than a no-op: one of those two paths declares a
// block's credits final and the other hands the block back to the
// automatic payout path, so applying either to an already-resolved
// row is precisely the class of bug this file exists to prevent.
var ErrBlockPayoutAlreadyResolved = errors.New("db: block payout is not in the unresolved (PENDING) status")

// ErrBlockPayoutNotApplied is returned by ReverseBlockPayoutCredits
// when the target `block_payouts` row is not (and never was) APPLIED
// — i.e. it is PENDING or FAILED. Only an APPLIED run ever credited
// any `balance` row, so only an APPLIED run has anything to reverse;
// a PENDING row needs `resolve-credited`/`resolve-not-credited`
// first (see ResolveBlockPayoutCredited/ResolveBlockPayoutNotCredited),
// and a FAILED row already credited nobody. This is a hard refusal,
// not a no-op, because silently treating either of those as "nothing
// to reverse" would hide a real state mismatch from the operator
// calling this expecting a real debit.
var ErrBlockPayoutNotApplied = errors.New("db: block payout is not APPLIED (only an APPLIED run has credits to reverse)")

// ErrBlockStillValid is returned by ReverseBlockPayoutCredits when
// the target block's own `blocks.valid` column is still TRUE — i.e.
// the block has not been found orphaned/invalid by the unlocker's
// real chain re-verification or an operator's own `backend block
// invalidate`. Reversing a payout for a block that is, as far as
// this schema currently knows, still a real block would debit miners
// for coin they may genuinely be owed. This is a HARD REFUSAL: the
// invalid/orphaned fact must come from `blocks.valid`, never from a
// caller-supplied "trust me" flag — see ReverseBlockPayoutCredits'
// doc comment for the full reasoning.
var ErrBlockStillValid = errors.New("db: the underlying block is still valid (blocks.valid = TRUE) — refusing to reverse a payout for a block that is not (yet) orphaned/invalidated")

// BlockCredit is one payee's credit within a single block's payout
// run — the DB-facing counterpart of payout.BlockCredit (kept as this
// package's own type for the same dependency-direction reason
// PayoutShare/DisburseEntry are, see internal/backend/payout's doc
// comment).
type BlockCredit struct {
	// PayoutBucket is which calculation produced this entry:
	// "fees", "pps", "pplns" or "solo" (payout.Payment.PoolType).
	// Recorded verbatim on the ledger row; see the migration's note
	// on why the column is not called pool_type.
	PayoutBucket string
	// PaymentAddress/PaymentID identify the `balance` row to credit,
	// via uq_balance_identity (algo, network, payment_address,
	// COALESCE(payment_id, '')).
	PaymentAddress string
	PaymentID      *string
	// Amount is the credit in atomic units. May legitimately be zero
	// — payout.Apply credits every payment entry including
	// zero-amount fee/dev seeds, specifically so every payee's
	// balance row exists even in a zero-payout cycle.
	Amount int64
}

// BlockPayoutRun is one complete matured-block payout run as
// ApplyBlockPayout should record and apply it: which block, and the
// full set of credits the payout calculation produced for it.
type BlockPayoutRun struct {
	// BlockID is the `blocks.id` this run pays out. This is the
	// idempotency key — `block_payouts.block_id` is the primary key,
	// so one block can have at most one payout run, ever.
	BlockID int64
	Algo    string
	Network string
	// PoolType is the block's SOLO/PPS/PPLNS/PROP pool_type.
	PoolType string
	Height   int64
	// Reward is the block reward this run divided up (the real,
	// current chain-reported reward the unlocker observed — see
	// unlocker.Block.Value's doc comment).
	Reward int64
	// Credits is every payee entry to credit, in the order they
	// should be applied. payout.Apply sorts these deterministically;
	// see its doc comment for why that matters beyond reproducible
	// logs.
	Credits []BlockCredit
}

// BlockPayoutOutcome summarizes one ApplyBlockPayout call.
type BlockPayoutOutcome struct {
	// AlreadyApplied is true when this block's `block_payouts` row
	// was ALREADY in APPLIED status on entry, meaning this call
	// credited nothing at all and rolled back without touching a
	// single `balance` row. TotalPaid/Credited then report what the
	// ORIGINAL, committed run recorded, not this call's (zero) work.
	AlreadyApplied bool
	// TotalPaid is the sum of every credit in atomic units, and
	// Credited the number of credit entries applied.
	TotalPaid int64
	Credited  int
}

// BlockPayout is one `block_payouts` row, with everything an operator
// or the startup check needs to understand what is stuck and why.
type BlockPayout struct {
	BlockID  int64
	Algo     string
	Network  string
	PoolType string
	Height   int64
	Status   string
	Reward   int64
	// Credited/TotalPaid are nil for a PENDING row — a
	// claimed-but-unresolved run has no trustworthy totals (see the
	// migration's note on those columns).
	Credited       *int
	TotalPaid      *int64
	Error          *string
	ResolvedBy     *string
	ResolutionNote *string
	CreatedAt      time.Time
	AppliedAt      *time.Time
}

// BlockPayoutCredit is one `block_payout_credits` row — the itemised,
// durable record of one `balance` row's credit from one block's payout
// run. This is what makes a PENDING row resolvable by a human at all:
// without it, "which miners already got this block's credit?" has no
// answer and the only safe action is to do nothing forever.
type BlockPayoutCredit struct {
	BalanceID      int64
	PaymentAddress string
	PaymentID      *string
	PayoutBucket   string
	Amount         int64
	CreditedAt     time.Time
	// ReversedAt is non-nil once ReverseBlockPayoutCredits has debited
	// this row's Amount back out of balance_id — see migrations/
	// 0014_block_payout_reversal.up.sql's doc comment on why this is a
	// marker column rather than a deletion. Nil for every credit that
	// still stands, which as of this writing is every credit on any
	// block whose block_payouts.status is not REVERSED.
	ReversedAt *time.Time
}

// ApplyBlockPayout is the single money-critical transaction behind
// every matured-block payout: it CLAIMS the block's `block_payouts`
// row, credits every entry in run.Credits, itemises each credit in
// `block_payout_credits`, and flips the claim to APPLIED — all inside
// ONE Postgres transaction.
//
// That single-transaction shape is the entire fix. It means:
//
//   - Any error or crash partway through rolls the WHOLE run back:
//     no claim row, no credit, no partial state. The unlocker's next
//     poll pass re-runs it from scratch, safely, because nothing was
//     credited. (The old code credited one miner per implicit
//     transaction, so a mid-loop failure left an unknown subset paid
//     and the only "retry" available double-credited all of them.)
//   - A committed run is recorded APPLIED, and every later call for
//     that block is a no-op that credits nothing (AlreadyApplied =
//     true). This is what makes the unlocker's automatic retry — and
//     a manual `backend block relock` — safe instead of a double
//     credit.
//
// The claim itself is an INSERT ... ON CONFLICT DO NOTHING followed,
// when that insert found an existing row, by a SELECT ... FOR UPDATE
// on it. Concurrency, in full:
//
//   - No row yet: the INSERT claims it. A second, concurrent caller
//     blocks on the primary key until this transaction resolves, then
//     sees either APPLIED (no-op) or, if this one rolled back, no row
//     at all — which it then claims itself (see the re-claim below).
//   - APPLIED: returns AlreadyApplied with the ORIGINAL run's
//     recorded totals, having touched nothing.
//   - PENDING: returns ErrBlockPayoutPending. A hard refusal; see
//     that error's doc comment.
//   - FAILED: re-claimed (reset to PENDING) and run normally — an
//     operator has asserted nothing landed, so this block is
//     deliberately back in the automatic path. See the migration's
//     status writeup.
//
// Underneath the block-level claim, each credit is ALSO row-level
// idempotent: the `block_payout_credits` row is inserted FIRST (ON
// CONFLICT DO NOTHING on uq_block_payout_credits_identity) and the
// `balance.pending_balance` increment only happens if that insert
// actually inserted. So even a caller that somehow got past the claim
// cannot credit the same (block, payee) pair twice.
//
// A run with no credits at all is rejected rather than recorded: a
// matured block that pays nobody anything is not a state the payout
// calculation can legitimately produce (it always seeds at least the
// fee/dev entries — see payout.seedPaymentData), so an empty Credits
// slice is a caller bug, and silently recording APPLIED for it would
// permanently mark that block paid.
func (r *Repository) ApplyBlockPayout(ctx context.Context, run BlockPayoutRun) (BlockPayoutOutcome, error) {
	if err := ValidateAlgo(run.Algo); err != nil {
		return BlockPayoutOutcome{}, err
	}
	if err := ValidateNetwork(run.Network); err != nil {
		return BlockPayoutOutcome{}, err
	}
	if err := ValidatePoolType(run.PoolType); err != nil {
		return BlockPayoutOutcome{}, err
	}
	if run.BlockID <= 0 {
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout: a positive blocks.id is required, got %d", run.BlockID)
	}
	if len(run.Credits) == 0 {
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout for block %d: no credits to apply — refusing to record an empty run as APPLIED (that would permanently mark this block paid)", run.BlockID)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout for block %d: beginning transaction: %w", run.BlockID, err)
	}
	defer tx.Rollback(ctx)

	claimed, existing, err := claimBlockPayout(ctx, tx, run)
	if err != nil {
		return BlockPayoutOutcome{}, err
	}
	if !claimed {
		// Already APPLIED: report the ORIGINAL run's recorded totals
		// and credit nothing. The deferred Rollback is the correct
		// exit here — this call must not write anything at all.
		return BlockPayoutOutcome{
			AlreadyApplied: true,
			TotalPaid:      derefInt64(existing.TotalPaid),
			Credited:       derefInt(existing.Credited),
		}, nil
	}

	currency, err := blockPayoutCurrency(ctx, tx, run.BlockID)
	if err != nil {
		return BlockPayoutOutcome{}, err
	}

	var out BlockPayoutOutcome
	for _, c := range run.Credits {
		applied, err := creditBlockPayoutEntry(ctx, tx, run, c, currency)
		if err != nil {
			return BlockPayoutOutcome{}, err
		}
		if !applied {
			// Row-level idempotency backstop fired: this (block,
			// balance row) pair was already itemised by an earlier
			// committed run. Nothing was credited; skip it rather
			// than incrementing a balance a second time.
			continue
		}
		out.TotalPaid += c.Amount
		out.Credited++
	}

	const applyStmt = `
		UPDATE block_payouts
		SET status = 'APPLIED', credited = $2, total_paid = $3, error = NULL, applied_at = now()
		WHERE block_id = $1 AND status = 'PENDING'`
	tag, err := tx.Exec(ctx, applyStmt, run.BlockID, out.Credited, out.TotalPaid)
	if err != nil {
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout for block %d: recording APPLIED status: %w", run.BlockID, err)
	}
	if tag.RowsAffected() == 0 {
		// Cannot happen with the claim above holding the row lock;
		// treated as a hard error rather than ignored because the
		// alternative is committing credits without the claim that
		// stops them being made again.
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout for block %d: the claimed block_payouts row is no longer PENDING — refusing to commit credits without a durable APPLIED marker", run.BlockID)
	}

	if err := tx.Commit(ctx); err != nil {
		return BlockPayoutOutcome{}, fmt.Errorf("db: applying block payout for block %d: committing transaction: %w", run.BlockID, err)
	}
	return out, nil
}

// claimBlockPayout performs ApplyBlockPayout's claim step inside its
// transaction. It returns claimed = true when the caller now holds a
// PENDING row it may credit against, or claimed = false with the
// existing APPLIED row (the safe no-op case). A PENDING row yields
// ErrBlockPayoutPending; a FAILED row is re-claimed. See
// ApplyBlockPayout's doc comment for the full concurrency story.
func claimBlockPayout(ctx context.Context, tx pgx.Tx, run BlockPayoutRun) (claimed bool, existing BlockPayout, err error) {
	const claimStmt = `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)
		ON CONFLICT (block_id) DO NOTHING
		RETURNING block_id`
	var claimedID int64
	err = tx.QueryRow(ctx, claimStmt, run.BlockID, run.Algo, run.Network, run.PoolType, run.Height, run.Reward).Scan(&claimedID)
	if err == nil {
		return true, BlockPayout{}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: claiming block_payouts row: %w", run.BlockID, err)
	}

	// DO NOTHING fired: there is (or very recently was) a conflicting
	// row. Lock it and decide from its real, committed status.
	existing, found, err := selectBlockPayoutForUpdate(ctx, tx, run.BlockID)
	if err != nil {
		return false, BlockPayout{}, err
	}
	if !found {
		// The conflicting row belonged to a concurrent transaction
		// that has since rolled back, so nothing is actually claimed.
		// Claim it now — a plain INSERT this time, so a genuine
		// conflict surfaces as an error instead of looping.
		const reinsertStmt = `
			INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
			VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)`
		if _, err := tx.Exec(ctx, reinsertStmt, run.BlockID, run.Algo, run.Network, run.PoolType, run.Height, run.Reward); err != nil {
			return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: re-claiming block_payouts row after a concurrent claimer rolled back: %w", run.BlockID, err)
		}
		return true, BlockPayout{}, nil
	}

	// Identity sanity check before trusting the existing row's status
	// for anything. `blocks.id` is a BIGSERIAL primary key and
	// `block_payouts.block_id` references it, so a disagreement here
	// means the id has been reused or the ledger has been edited into
	// an inconsistent state — in which case neither "no-op, it's
	// already applied" nor "re-claim it" is a safe conclusion to draw
	// about real money. Refuse and let a human look.
	if existing.Algo != run.Algo || existing.Network != run.Network ||
		existing.PoolType != run.PoolType || existing.Height != run.Height {
		return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: the existing block_payouts row is for %s/%s pool_type=%s height=%d but this run is for %s/%s pool_type=%s height=%d — refusing to credit anything against a mismatched ledger row (a reused blocks.id, or a hand-edited row)",
			run.BlockID, existing.Algo, existing.Network, existing.PoolType, existing.Height,
			run.Algo, run.Network, run.PoolType, run.Height)
	}

	switch existing.Status {
	case BlockPayoutStatusApplied, BlockPayoutStatusReversed:
		// REVERSED is deliberately handled exactly like APPLIED here:
		// a no-op that credits nothing and does NOT reset the row
		// back to PENDING. This is the load-bearing correctness
		// property migration 0014 exists for — a REVERSED block is
		// not a real block, and must never become payable again, no
		// matter how it is re-triggered (a relocked block, a future
		// multi-transaction payout path, an operator retry). Note
		// existing.TotalPaid/Credited for a REVERSED row report what
		// the REVERSAL debited back, not what was originally paid
		// out (see migration 0014's doc comment on the reused
		// columns) — callers that only branch on AlreadyApplied
		// (every one as of this writing; see payout.Apply and
		// cmd/backend's payoutTrigger) are unaffected because they
		// never inspect those totals for anything but logging an
		// already-a-no-op outcome.
		return false, existing, nil
	case BlockPayoutStatusPending:
		return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d (%s/%s height %d, claimed %s): %w — inspect with `backend block-payout show -block-id=%d`, then resolve with `backend block-payout resolve-credited` or `resolve-not-credited`",
			run.BlockID, existing.Algo, existing.Network, existing.Height,
			existing.CreatedAt.UTC().Format(time.RFC3339), ErrBlockPayoutPending, run.BlockID)
	case BlockPayoutStatusFailed:
		// Operator-asserted "nothing landed": deliberately
		// re-claimable. Reset to PENDING and run normally, clearing
		// the previous run's summary so an APPLIED row can never
		// report stale totals.
		const reclaimStmt = `
			UPDATE block_payouts
			SET status = 'PENDING', reward = $2, credited = NULL, total_paid = NULL,
			    error = NULL, applied_at = NULL, created_at = now()
			WHERE block_id = $1 AND status = 'FAILED'`
		tag, err := tx.Exec(ctx, reclaimStmt, run.BlockID, run.Reward)
		if err != nil {
			return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: re-claiming FAILED block_payouts row: %w", run.BlockID, err)
		}
		if tag.RowsAffected() == 0 {
			return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: re-claiming FAILED block_payouts row: status changed underneath the row lock", run.BlockID)
		}
		return true, BlockPayout{}, nil
	default:
		return false, BlockPayout{}, fmt.Errorf("db: applying block payout for block %d: unrecognized block_payouts status %q — refusing to credit anything against a status this code does not understand", run.BlockID, existing.Status)
	}
}

// blockPayoutCurrency determines the currency ("XMR" or "XTM", see
// migrations/0014_balance_payouts_currency.up.sql) that block
// blockID's payout credits belong on, derived directly from a fresh
// read of the REAL `blocks` row's own algo/merge_mine_chain columns —
// never from anything the caller supplies. This is deliberate: the
// migration's own doc comment on `block_payout_credits.currency`
// requires this value be derived from the parent block, not accepted
// as an independently-settable parameter, precisely so a caller bug
// (a mismatched run.Algo, or a stale/wrong merge-mine-leg
// assumption) can never mis-credit a payee's balance onto the wrong
// currency's row. Every credit in one ApplyBlockPayout run shares the
// same blockID and is therefore guaranteed the same currency, so this
// is called exactly once per run rather than once per credit.
//
// Only ALGO_RXM's primary (Monero) leg — merge_mine_chain IS NULL —
// is "XMR"; every other case (RXT/C29/SHA3X, whose merge_mine_chain
// is always NULL too, and ALGO_RXM's secondary/Tari leg, whose
// merge_mine_chain is "TARI") is "XTM". See
// migrations/0012_blocks_merge_mine_chain.up.sql for the full
// merge-mine mechanism this reads.
func blockPayoutCurrency(ctx context.Context, tx pgx.Tx, blockID int64) (string, error) {
	var algo string
	var mergeMineChain *string
	const stmt = `SELECT algo, merge_mine_chain FROM blocks WHERE id = $1`
	if err := tx.QueryRow(ctx, stmt, blockID).Scan(&algo, &mergeMineChain); err != nil {
		return "", fmt.Errorf("db: applying block payout for block %d: resolving currency from the real blocks row: %w", blockID, err)
	}
	if algo == "RXM" && mergeMineChain == nil {
		return "XMR", nil
	}
	return "XTM", nil
}

// creditBlockPayoutEntry applies one BlockCredit inside
// ApplyBlockPayout's transaction, returning applied = false (with no
// error) when the row-level idempotency backstop fired — i.e. this
// (block_id, balance_id) pair was already itemised by an earlier
// committed run, so nothing was credited.
//
// currency is blockPayoutCurrency's result for this run's BlockID —
// see that function's doc comment for why it is derived once, from
// the real `blocks` row, rather than threaded in from run/c.
//
// Order is deliberate and must not be swapped: the `balance` row is
// ensured/looked up, then the `block_payout_credits` ledger row is
// inserted, and ONLY IF that insert really inserted is
// pending_balance incremented. Crediting first and itemising second
// would make a unique-violation on the ledger leave a credit with no
// record of it.
func creditBlockPayoutEntry(ctx context.Context, tx pgx.Tx, run BlockPayoutRun, c BlockCredit, currency string) (bool, error) {
	// Ensure the `balance` row exists and get its id. The DO UPDATE
	// is a deliberate no-op touch (not an increment): all this step
	// does is resolve uq_balance_identity to a balance_id, which
	// plain ON CONFLICT DO NOTHING would not return on conflict.
	const ensureStmt = `
		INSERT INTO balance (algo, network, currency, payment_address, payment_id, pending_balance)
		VALUES ($1, $2, $3, $4, $5, 0)
		ON CONFLICT (algo, network, currency, payment_address, (COALESCE(payment_id, '')))
		DO UPDATE SET updated_at = balance.updated_at
		RETURNING id`
	var balanceID int64
	if err := tx.QueryRow(ctx, ensureStmt, run.Algo, run.Network, currency, c.PaymentAddress, c.PaymentID).Scan(&balanceID); err != nil {
		return false, fmt.Errorf("db: applying block payout for block %d: resolving balance row for %s: %w", run.BlockID, c.PaymentAddress, err)
	}

	const ledgerStmt = `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payment_id, payout_bucket, amount, currency)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (block_id, balance_id) DO NOTHING`
	tag, err := tx.Exec(ctx, ledgerStmt, run.BlockID, balanceID, c.PaymentAddress, c.PaymentID, c.PayoutBucket, c.Amount, currency)
	if err != nil {
		return false, fmt.Errorf("db: applying block payout for block %d: recording credit ledger row for balance %d: %w", run.BlockID, balanceID, err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	const creditStmt = `
		UPDATE balance
		SET pending_balance = pending_balance + $2, updated_at = now()
		WHERE id = $1`
	tag, err = tx.Exec(ctx, creditStmt, balanceID, c.Amount)
	if err != nil {
		return false, fmt.Errorf("db: applying block payout for block %d: crediting balance %d: %w", run.BlockID, balanceID, err)
	}
	if tag.RowsAffected() == 0 {
		return false, fmt.Errorf("db: applying block payout for block %d: crediting balance %d: no such balance row", run.BlockID, balanceID)
	}
	return true, nil
}

// blockPayoutColumns is the one canonical column list every
// block_payouts read in this file selects, so scanBlockPayout below
// stays in sync with all of them at once.
const blockPayoutColumns = `block_id, algo, network, pool_type, height, status, reward,
	       credited, total_paid, error, resolved_by, resolution_note, created_at, applied_at`

// blockPayoutScanner is the subset of pgx.Rows/pgx.Row
// scanBlockPayout needs, so the same scan logic serves the multi-row
// UnresolvedBlockPayouts query and the single-row GetBlockPayout /
// selectBlockPayoutForUpdate lookups (mirrors payoutScanner in
// payoutreconcile.go).
type blockPayoutScanner interface {
	Scan(dest ...any) error
}

func scanBlockPayout(s blockPayoutScanner) (BlockPayout, error) {
	var b BlockPayout
	if err := s.Scan(&b.BlockID, &b.Algo, &b.Network, &b.PoolType, &b.Height, &b.Status, &b.Reward,
		&b.Credited, &b.TotalPaid, &b.Error, &b.ResolvedBy, &b.ResolutionNote, &b.CreatedAt, &b.AppliedAt); err != nil {
		return BlockPayout{}, err
	}
	return b, nil
}

// selectBlockPayoutForUpdate reads one block_payouts row inside a
// transaction, taking a row lock on it so a concurrent
// ApplyBlockPayout/resolution for the same block serializes behind
// this one rather than racing it.
func selectBlockPayoutForUpdate(ctx context.Context, tx pgx.Tx, blockID int64) (BlockPayout, bool, error) {
	stmt := `SELECT ` + blockPayoutColumns + ` FROM block_payouts WHERE block_id = $1 FOR UPDATE`
	b, err := scanBlockPayout(tx.QueryRow(ctx, stmt, blockID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPayout{}, false, nil
		}
		return BlockPayout{}, false, fmt.Errorf("db: locking block_payouts row for block %d: %w", blockID, err)
	}
	return b, true, nil
}

// GetBlockPayout returns one `block_payouts` row by block id,
// REGARDLESS of its status (an APPLIED or FAILED row is returned too,
// with its real status in the Status field) — this exists for the
// operator-facing `backend block-payout show`, whose whole job is to
// let a human see the current state of a row before and after
// resolving it. Returns ErrBlockPayoutNotFound if this block's payout
// has never been claimed.
func (r *Repository) GetBlockPayout(ctx context.Context, blockID int64) (BlockPayout, error) {
	stmt := `SELECT ` + blockPayoutColumns + ` FROM block_payouts WHERE block_id = $1`
	b, err := scanBlockPayout(r.pool.QueryRow(ctx, stmt, blockID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPayout{}, fmt.Errorf("db: getting block payout for block %d: %w", blockID, ErrBlockPayoutNotFound)
		}
		return BlockPayout{}, fmt.Errorf("db: getting block payout for block %d: %w", blockID, err)
	}
	return b, nil
}

// UnresolvedBlockPayouts returns every unresolved (PENDING)
// `block_payouts` row, oldest (lowest block_id) first. algo and/or
// network may be empty to mean "any" — cmd/backend's startup check
// passes neither (it surveys the whole deployment), while `backend
// block-payout list-unresolved` optionally narrows.
//
// A non-empty algo/network IS validated (ValidateAlgo/
// ValidateNetwork), for the same reason UnresolvedPayouts validates
// its own: a typo'd algo silently returning "nothing unresolved"
// would be a false all-clear from a check whose entire job is to
// report money-critical stuck state.
func (r *Repository) UnresolvedBlockPayouts(ctx context.Context, algo, network string) ([]BlockPayout, error) {
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

	stmt := `SELECT ` + blockPayoutColumns + `
		FROM block_payouts
		WHERE status = 'PENDING'
		  AND ($1 = '' OR algo = $1)
		  AND ($2 = '' OR network = $2)
		ORDER BY block_id ASC`
	rows, err := r.pool.Query(ctx, stmt, algo, network)
	if err != nil {
		return nil, fmt.Errorf("db: querying unresolved block payouts: %w", err)
	}
	defer rows.Close()

	var out []BlockPayout
	for rows.Next() {
		b, err := scanBlockPayout(rows)
		if err != nil {
			return nil, fmt.Errorf("db: scanning unresolved block payout row: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating unresolved block payout rows: %w", err)
	}
	return out, nil
}

// BlockPayoutCredits returns every itemised credit recorded for one
// block's payout run, ordered by balance id. For a PENDING row this is
// the answer to the only question that matters during an incident —
// "which miners already hold this block's credit, and how much?" —
// and it is what `backend block-payout show` prints for an operator
// to base a resolution on.
func (r *Repository) BlockPayoutCredits(ctx context.Context, blockID int64) ([]BlockPayoutCredit, error) {
	const stmt = `
		SELECT balance_id, payment_address, payment_id, payout_bucket, amount, credited_at, reversed_at
		FROM block_payout_credits
		WHERE block_id = $1
		ORDER BY balance_id ASC`
	rows, err := r.pool.Query(ctx, stmt, blockID)
	if err != nil {
		return nil, fmt.Errorf("db: querying block payout credits for block %d: %w", blockID, err)
	}
	defer rows.Close()

	var out []BlockPayoutCredit
	for rows.Next() {
		var c BlockPayoutCredit
		if err := rows.Scan(&c.BalanceID, &c.PaymentAddress, &c.PaymentID, &c.PayoutBucket, &c.Amount, &c.CreditedAt, &c.ReversedAt); err != nil {
			return nil, fmt.Errorf("db: scanning block payout credit row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating block payout credit rows: %w", err)
	}
	return out, nil
}

// ResolveBlockPayoutCredited resolves a PENDING block payout that an
// operator has independently established is COMPLETE as recorded: the
// credits itemised in `block_payout_credits` for this block are the
// credits that should stand, and nothing further is owed for it.
//
// It flips the row to APPLIED — recording resolvedBy/resolutionNote
// for audit, and deriving credited/total_paid from the real ledger
// rows rather than from anything the operator types — and credits NO
// further balance. That is the entire point, and it is the direct
// analog of `backend payout resolve-sent`: the miners in that ledger
// already hold the coin, so the correct bookkeeping is to finish
// recording the run, not to pay any of it again.
//
// Once APPLIED, ApplyBlockPayout is a permanent no-op for this block,
// so the unlocker can safely mark it unlocked on its next pass.
//
// Refused, with ErrBlockPayoutAlreadyResolved, for any row not
// currently PENDING (the guard lives in the same transaction as the
// flip).
func (r *Repository) ResolveBlockPayoutCredited(ctx context.Context, blockID int64, resolvedBy, note string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: resolving block payout %d as credited: beginning transaction: %w", blockID, err)
	}
	defer tx.Rollback(ctx)

	existing, found, err := selectBlockPayoutForUpdate(ctx, tx, blockID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("db: resolving block payout %d as credited: %w", blockID, ErrBlockPayoutNotFound)
	}
	if existing.Status != BlockPayoutStatusPending {
		return fmt.Errorf("db: resolving block payout %d as credited: status is %s: %w", blockID, existing.Status, ErrBlockPayoutAlreadyResolved)
	}

	// credited/total_paid are derived from the durable ledger, never
	// supplied by the caller: the whole value of this resolution is
	// that it records what really landed, and the ledger is the only
	// thing that knows.
	const applyStmt = `
		UPDATE block_payouts
		SET status = 'APPLIED',
		    credited = (SELECT count(*) FROM block_payout_credits WHERE block_id = $1),
		    total_paid = (SELECT COALESCE(sum(amount), 0) FROM block_payout_credits WHERE block_id = $1),
		    error = COALESCE(error || ' | ', '') || 'manually resolved as CREDITED-AS-RECORDED by ' || $2 || ': ' || $3,
		    resolved_by = $2,
		    resolution_note = $3,
		    applied_at = now()
		WHERE block_id = $1 AND status = 'PENDING'`
	tag, err := tx.Exec(ctx, applyStmt, blockID, resolvedBy, note)
	if err != nil {
		return fmt.Errorf("db: resolving block payout %d as credited: %w", blockID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: resolving block payout %d as credited: status changed underneath the row lock: %w", blockID, ErrBlockPayoutAlreadyResolved)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: resolving block payout %d as credited: committing transaction: %w", blockID, err)
	}
	return nil
}

// ResolveBlockPayoutNotCredited resolves a PENDING block payout that
// an operator has independently established credited NOTHING that
// still stands — either it never credited a single balance, or they
// have already reversed whatever it did credit by hand.
//
// It flips the row to FAILED (recording resolvedBy/resolutionNote and
// appending them to the row's error text) and DELETES this block's
// `block_payout_credits` rows, because leaving them would both
// misreport history and re-trigger the row-level idempotency backstop
// on the re-run — silently skipping exactly the credits the operator
// just declared void. It touches no `balance` row: reversing a real
// credit is a judgement call about live miner balances and is
// deliberately NOT automated here.
//
// FAILED is re-claimable (see migrations/0013_block_payouts.up.sql),
// so this is what hands the block back to the automatic payout path:
// the next unlocker poll pass re-runs the full payout calculation for
// it from scratch.
//
// This is the most dangerous command in this file, and the direct
// analog of `backend payout resolve-not-sent`: if the PENDING run
// DID credit miners and those credits were not reversed, this makes
// the pool credit the same block's payout a second time. Hence the
// mandatory reason, and the CLI's loud warning whenever ledger rows
// exist. Refused, with ErrBlockPayoutAlreadyResolved, for any row not
// currently PENDING.
func (r *Repository) ResolveBlockPayoutNotCredited(ctx context.Context, blockID int64, resolvedBy, note string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: resolving block payout %d as not credited: beginning transaction: %w", blockID, err)
	}
	defer tx.Rollback(ctx)

	existing, found, err := selectBlockPayoutForUpdate(ctx, tx, blockID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("db: resolving block payout %d as not credited: %w", blockID, ErrBlockPayoutNotFound)
	}
	if existing.Status != BlockPayoutStatusPending {
		return fmt.Errorf("db: resolving block payout %d as not credited: status is %s: %w", blockID, existing.Status, ErrBlockPayoutAlreadyResolved)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM block_payout_credits WHERE block_id = $1`, blockID); err != nil {
		return fmt.Errorf("db: resolving block payout %d as not credited: clearing the voided credit ledger rows: %w", blockID, err)
	}

	const failStmt = `
		UPDATE block_payouts
		SET status = 'FAILED',
		    credited = NULL,
		    total_paid = NULL,
		    applied_at = NULL,
		    error = COALESCE(error || ' | ', '') || 'manually resolved as NOT CREDITED by ' || $2 || ': ' || $3,
		    resolved_by = $2,
		    resolution_note = $3
		WHERE block_id = $1 AND status = 'PENDING'`
	tag, err := tx.Exec(ctx, failStmt, blockID, resolvedBy, note)
	if err != nil {
		return fmt.Errorf("db: resolving block payout %d as not credited: %w", blockID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: resolving block payout %d as not credited: status changed underneath the row lock: %w", blockID, ErrBlockPayoutAlreadyResolved)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: resolving block payout %d as not credited: committing transaction: %w", blockID, err)
	}
	return nil
}

// BlockPayoutReversalOutcome summarizes one ReverseBlockPayoutCredits
// call, mirroring BlockPayoutOutcome's own AlreadyApplied/TotalPaid/
// Credited shape for the exact same reason: the caller (the CLI's
// `block-payout reverse-credits`, today) needs to tell a real,
// money-moving reversal apart from a safe no-op that touched nothing.
type BlockPayoutReversalOutcome struct {
	// AlreadyReversed is true when this block's `block_payouts` row
	// was ALREADY REVERSED on entry, meaning this call debited
	// nothing at all and rolled back without touching a single
	// `balance` row. CreditsReversed/TotalReversed then report what
	// the ORIGINAL, committed reversal recorded, not this call's
	// (zero) work — this is the property that makes calling this
	// twice safe: the second call must debit exactly zero times,
	// ever.
	AlreadyReversed bool
	// CreditsReversed is the number of `block_payout_credits` rows
	// debited back, and TotalReversed their atomic-unit sum.
	CreditsReversed int
	TotalReversed   int64
}

// ReverseBlockPayoutCredits reverses a single block's ALREADY-APPLIED
// matured-block payout: it debits every `balance` row that block's
// `block_payout_credits` ledger recorded a credit for, by EXACTLY the
// amount recorded for THAT block (never a miner's whole balance,
// never anything another block's credits added to the same payee),
// and flips the block's `block_payouts` row to the new REVERSED
// terminal status — see migrations/0014_block_payout_reversal.up.sql
// for the full schema-level writeup this mirrors.
//
// This is the other half of the gap `backend block invalidate`'s own
// "NOTE ON PAYOUTS" comment names directly: relocking or invalidating
// an APPLIED block's `blocks` row already makes ApplyBlockPayout a
// safe no-op (it will never credit that block's miners a second
// time), but until this method existed nothing anywhere DEBITED the
// credit that already landed on what turned out to be bad data.
// Miners kept coin they were never actually owed, permanently. This
// closes that.
//
// PRECONDITION — the most important correctness property in this
// file: this reverses a block ONLY when both of the following hold,
// checked inside ONE transaction with a row lock on each:
//
//   - `block_payouts.status` for blockID is APPLIED. Anything else
//     (PENDING, FAILED) is refused with ErrBlockPayoutNotApplied — a
//     PENDING run needs `resolve-credited`/`resolve-not-credited`
//     first (see those methods), and a FAILED run already credited
//     nobody, so there is nothing here to reverse.
//   - The block's own `blocks.valid` column is FALSE. If it is still
//     TRUE, this is refused with ErrBlockStillValid. This is a HARD
//     REFUSAL, deliberately: there is no caller-supplied "trust me,
//     it's orphaned" parameter anywhere on this method's signature.
//     The invalid/orphaned fact must come from the real, chain-
//     verified `blocks.valid` column — written either by the
//     unlocker's own checkBlock on a genuine reorg-past-maturity
//     orphan detection, or by an operator's `backend block
//     invalidate` after their own independent investigation (see
//     cmd/backend/blockcli.go). Accepting a bare boolean flag here
//     instead would let a caller reverse a payout for a block that,
//     as far as this schema can otherwise tell, is still real — this
//     precondition is the entire reason this feature is safe to
//     expose at all.
//
// IDEMPOTENCY: if `block_payouts.status` is ALREADY REVERSED (checked
// under the same row lock, before either precondition above is even
// evaluated), this is a safe no-op: BlockPayoutReversalOutcome.
// AlreadyReversed is true, CreditsReversed/TotalReversed report the
// ORIGINAL reversal's totals (reusing `credited`/`total_paid` — see
// migration 0014's doc comment on why that reuse is safe), and NOT A
// SINGLE `balance` OR `block_payout_credits` ROW IS TOUCHED. This is
// the single most important test case for this method: reversing
// twice must debit exactly once, ever — a caller retrying after a
// crash, or an operator re-running this by hand not realizing it
// already ran, must never double-debit a miner for the pool's own
// mistake on top of correcting the original one.
//
// THE DEBIT, scoped to exactly this block's own ledger rows: every
// `block_payout_credits` row for blockID (this is the itemised,
// per-balance-row, per-amount record ApplyBlockPayout itself wrote —
// it already names exactly which balance rows got exactly how much
// FOR THIS BLOCK, nothing else) is read, its balance_id debited by
// its own amount (`pending_balance = pending_balance - amount`, the
// same statement shape every other debit in this codebase uses), and
// then marked `reversed_at = now()` — never deleted, preserving the
// audit trail for the same reason ResolveBlockPayoutNotCredited's own
// doc comment already argues against deleting ledger rows.
//
// `balance.pending_balance` already carries `CHECK (pending_balance
// >= 0)` (migration 0011). If any of these debits would drive a
// balance negative — the real, documented edge case where that
// miner's balance has, since this bad block's payout, been reduced
// by something else legitimate (most plausibly a real disbursement
// built in part on the now-void credit) — Postgres rejects the whole
// statement and this method returns that error, rolling the ENTIRE
// reversal back (no partial debit, no status flip). That is the
// correct, auditable outcome: it surfaces a real incident (a miner
// already received real coin built on a credit that turns out to be
// void) that needs its own manual resolution, rather than silently
// clamping the debit or corrupting the row.
//
// All of this — the two locked reads (block_payouts row, blocks.valid),
// every `block_payout_credits`/`balance` UPDATE, and the status flip
// to REVERSED — happens in ONE Postgres transaction, exactly like
// ApplyBlockPayout. Any error anywhere rolls EVERYTHING back.
func (r *Repository) ReverseBlockPayoutCredits(ctx context.Context, blockID int64, resolvedBy, note string) (BlockPayoutReversalOutcome, error) {
	if blockID <= 0 {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits: a positive blocks.id is required, got %d", blockID)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: beginning transaction: %w", blockID, err)
	}
	defer tx.Rollback(ctx)

	existing, found, err := selectBlockPayoutForUpdate(ctx, tx, blockID)
	if err != nil {
		return BlockPayoutReversalOutcome{}, err
	}
	if !found {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: %w", blockID, ErrBlockPayoutNotFound)
	}

	if existing.Status == BlockPayoutStatusReversed {
		// Idempotent no-op: the deferred Rollback above is the
		// correct exit here — this call must not write anything at
		// all, and must report the ORIGINAL reversal's totals, not
		// this call's (zero) work.
		return BlockPayoutReversalOutcome{
			AlreadyReversed: true,
			CreditsReversed: derefInt(existing.Credited),
			TotalReversed:   derefInt64(existing.TotalPaid),
		}, nil
	}
	if existing.Status != BlockPayoutStatusApplied {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: status is %s, not APPLIED: %w",
			blockID, existing.Status, ErrBlockPayoutNotApplied)
	}

	// Lock the underlying blocks row and check the real, chain-
	// verified (or operator-asserted via `backend block invalidate`)
	// orphan/invalid signal. FOR UPDATE serializes this against a
	// concurrent SetBlockStatus (the unlocker marking it orphaned
	// right now, or an operator's own invalidate/relock) so this
	// reversal's view of blocks.valid cannot be stale by the time it
	// decides whether to proceed.
	var blockValid bool
	if err := tx.QueryRow(ctx, `SELECT valid FROM blocks WHERE id = $1 FOR UPDATE`, blockID).Scan(&blockValid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: no such blocks row (block_payouts.block_id should never outlive its blocks row — the foreign key is ON DELETE CASCADE): %w", blockID, err)
		}
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: locking the blocks row: %w", blockID, err)
	}
	if blockValid {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: %w — this block has not been found orphaned/invalid (see the unlocker's real chain re-verification, or `backend block invalidate`); reversing its payout would debit miners for coin they may genuinely be owed",
			blockID, ErrBlockStillValid)
	}

	// Read every not-yet-reversed credit this block's run itemised.
	// The reversed_at filter is a defensive, not a load-bearing,
	// guard: a block_payouts row can only ever transition APPLIED ->
	// REVERSED once (this method's own idempotency check above
	// refuses a second attempt before reaching here), so in practice
	// every row for an APPLIED block has reversed_at IS NULL. FOR
	// UPDATE takes the same per-row lock creditBlockPayoutEntry does,
	// serializing against anything else that might touch these
	// specific ledger rows.
	rows, err := tx.Query(ctx, `
		SELECT id, balance_id, amount
		FROM block_payout_credits
		WHERE block_id = $1 AND reversed_at IS NULL
		FOR UPDATE`, blockID)
	if err != nil {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: reading the credit ledger: %w", blockID, err)
	}
	type ledgerRow struct {
		id        int64
		balanceID int64
		amount    int64
	}
	var toReverse []ledgerRow
	for rows.Next() {
		var lr ledgerRow
		if err := rows.Scan(&lr.id, &lr.balanceID, &lr.amount); err != nil {
			rows.Close()
			return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: scanning credit ledger row: %w", blockID, err)
		}
		toReverse = append(toReverse, lr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: iterating credit ledger rows: %w", blockID, err)
	}

	var out BlockPayoutReversalOutcome
	for _, lr := range toReverse {
		const debitStmt = `
			UPDATE balance
			SET pending_balance = pending_balance - $2, updated_at = now()
			WHERE id = $1`
		tag, err := tx.Exec(ctx, debitStmt, lr.balanceID, lr.amount)
		if err != nil {
			// Most plausibly the balance_pending_balance_nonnegative
			// CHECK constraint (migration 0011) — see this method's
			// doc comment on why that is the correct, auditable
			// outcome here rather than something to work around.
			return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: debiting balance %d by %d: %w", blockID, lr.balanceID, lr.amount, err)
		}
		if tag.RowsAffected() == 0 {
			return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: debiting balance %d: no such balance row", blockID, lr.balanceID)
		}

		const markReversedStmt = `UPDATE block_payout_credits SET reversed_at = now() WHERE id = $1`
		if _, err := tx.Exec(ctx, markReversedStmt, lr.id); err != nil {
			return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: marking credit ledger row %d reversed: %w", blockID, lr.id, err)
		}

		out.TotalReversed += lr.amount
		out.CreditsReversed++
	}

	// Flip to REVERSED, reusing credited/total_paid/resolved_by/
	// resolution_note for the reversal's own totals and audit trail
	// (see migration 0014's doc comment on why that reuse is safe).
	// applied_at is deliberately left untouched — it keeps recording
	// the original apply time, not this reversal.
	const reverseStmt = `
		UPDATE block_payouts
		SET status = 'REVERSED',
		    credited = $2,
		    total_paid = $3,
		    error = COALESCE(error || ' | ', '') || 'credits REVERSED by ' || $4 || ': ' || $5,
		    resolved_by = $4,
		    resolution_note = $5
		WHERE block_id = $1 AND status = 'APPLIED'`
	tag, err := tx.Exec(ctx, reverseStmt, blockID, out.CreditsReversed, out.TotalReversed, resolvedBy, note)
	if err != nil {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: recording REVERSED status: %w", blockID, err)
	}
	if tag.RowsAffected() == 0 {
		// Cannot happen with the claim-row lock held above; treated
		// as a hard error rather than ignored because the
		// alternative is committing debits without the durable
		// REVERSED marker that stops them being made again.
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: the locked block_payouts row is no longer APPLIED — refusing to commit debits without a durable REVERSED marker", blockID)
	}

	if err := tx.Commit(ctx); err != nil {
		return BlockPayoutReversalOutcome{}, fmt.Errorf("db: reversing block payout credits for block %d: committing transaction: %w", blockID, err)
	}
	return out, nil
}

// derefInt64/derefInt flatten the nullable credited/total_paid columns
// for BlockPayoutOutcome's non-pointer fields. A NULL there only
// happens on a PENDING row, which ApplyBlockPayout never reports an
// outcome for, so zero is the correct and unambiguous fallback.
func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

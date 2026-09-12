package db

// blockpayout.go holds the matured-block payout IDEMPOTENCY LEDGER --
// the `block_payouts` claim table and its per-miner
// `block_payout_credits` itemisation, added by
// migrations/0011_block_payouts.up.sql.
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

// block_payouts statuses. See migrations/0011_block_payouts.up.sql's
// doc comment for the full meaning of each; the short version:
//
//   - PENDING is UNRESOLVED and blocks all further automatic payout
//     for that block (the analog of an AMBIGUOUS `payouts` row).
//   - APPLIED is terminal success; ApplyBlockPayout is a no-op for it.
//   - FAILED is operator-asserted "nothing landed", and is
//     deliberately re-claimable (the analog of a FAILED `payouts`
//     row).
const (
	BlockPayoutStatusPending = "PENDING"
	BlockPayoutStatusApplied = "APPLIED"
	BlockPayoutStatusFailed  = "FAILED"
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

	var out BlockPayoutOutcome
	for _, c := range run.Credits {
		applied, err := creditBlockPayoutEntry(ctx, tx, run, c)
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
	case BlockPayoutStatusApplied:
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

// creditBlockPayoutEntry applies one BlockCredit inside
// ApplyBlockPayout's transaction, returning applied = false (with no
// error) when the row-level idempotency backstop fired — i.e. this
// (block_id, balance_id) pair was already itemised by an earlier
// committed run, so nothing was credited.
//
// Order is deliberate and must not be swapped: the `balance` row is
// ensured/looked up, then the `block_payout_credits` ledger row is
// inserted, and ONLY IF that insert really inserted is
// pending_balance incremented. Crediting first and itemising second
// would make a unique-violation on the ledger leave a credit with no
// record of it.
func creditBlockPayoutEntry(ctx context.Context, tx pgx.Tx, run BlockPayoutRun, c BlockCredit) (bool, error) {
	// Ensure the `balance` row exists and get its id. The DO UPDATE
	// is a deliberate no-op touch (not an increment): all this step
	// does is resolve uq_balance_identity to a balance_id, which
	// plain ON CONFLICT DO NOTHING would not return on conflict.
	const ensureStmt = `
		INSERT INTO balance (algo, network, payment_address, payment_id, pending_balance)
		VALUES ($1, $2, $3, $4, 0)
		ON CONFLICT (algo, network, payment_address, (COALESCE(payment_id, '')))
		DO UPDATE SET updated_at = balance.updated_at
		RETURNING id`
	var balanceID int64
	if err := tx.QueryRow(ctx, ensureStmt, run.Algo, run.Network, c.PaymentAddress, c.PaymentID).Scan(&balanceID); err != nil {
		return false, fmt.Errorf("db: applying block payout for block %d: resolving balance row for %s: %w", run.BlockID, c.PaymentAddress, err)
	}

	const ledgerStmt = `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payment_id, payout_bucket, amount)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (block_id, balance_id) DO NOTHING`
	tag, err := tx.Exec(ctx, ledgerStmt, run.BlockID, balanceID, c.PaymentAddress, c.PaymentID, c.PayoutBucket, c.Amount)
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
		SELECT balance_id, payment_address, payment_id, payout_bucket, amount, credited_at
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
		if err := rows.Scan(&c.BalanceID, &c.PaymentAddress, &c.PaymentID, &c.PayoutBucket, &c.Amount, &c.CreditedAt); err != nil {
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
// FAILED is re-claimable (see migrations/0011_block_payouts.up.sql),
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

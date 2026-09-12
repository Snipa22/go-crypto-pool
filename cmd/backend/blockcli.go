// Manual, ops-triggered "block" subcommands for the backend binary:
//
//	backend block invalidate -id=<id> [-dsn=...] -yes
//	backend block relock     -id=<id> [-dsn=...] -yes
//
// Both wrap the EXISTING real db.Repository.SetBlockStatus write path
// (the same method the block unlocker itself uses once
// chain.ChainVerifier.Verify resolves a pending block — see
// internal/backend/unlocker.go's checkBlock/RunOnce and
// internal/backend/db/repository.go's SetBlockStatus doc comment).
// This file adds no new write path to the schema; it is strictly a
// manual, human-in-the-loop trigger for that one existing method, for
// the real ops situations the automatic unlocker poll loop cannot
// itself resolve:
//
//   - invalidate: an operator has independently confirmed (e.g. via
//     block explorer, node RPC, or a stale/duplicate submission) that
//     a block the pool recorded is NOT real/payable and the unlocker
//     hasn't (or won't) catch it -- e.g. it's for a coin with no
//     configured ChainVerifier (GCPOOL_TARI_GRPC_ADDR/
//     GCPOOL_MONERO_RPC_ADDR unset), or the unlocker's maturity window
//     already passed and a payout already ran on bad data. Calls
//     SetBlockStatus(id, valid=false, unlocked=true) -- the exact
//     write the unlocker performs on real chain-verified orphaning
//     (see checkBlock's outcomeOrphaned branch). This is a terminal
//     state: unlocked=true means PendingBlocks will never select this
//     row again, so the automatic poll loop will not revisit it.
//
//   - relock: an operator needs to put an already-resolved block BACK
//     into the unlocker's pending queue for re-verification -- e.g. a
//     block was marked matured/unlocked (or wrongly invalidated)
//     before its real chain status was actually settled, a chain
//     reorg was discovered after the fact, or a previous manual
//     invalidate turns out to have been a mistake. Calls
//     SetBlockStatus(id, valid=true, unlocked=false) -- valid=TRUE,
//     unlocked=FALSE is exactly PendingBlocks' selection predicate
//     (`WHERE valid = TRUE AND unlocked = FALSE`), so the next
//     unlocker poll tick will pick this block back up and re-run the
//     real ChainVerifier.Verify decision table against it, same as
//     any newly-inserted block.
//
//     NOTE ON PAYOUTS: relocking a block whose payout ALREADY ran no
//     longer re-credits anybody. The matured-block payout path is now
//     idempotent per block (a `block_payouts` claim ledger written in
//     the same transaction as the credits -- see
//     migrations/0011_block_payouts.up.sql), so the re-triggered
//     payout for an APPLIED block is a recorded no-op and the block
//     is simply marked unlocked again. That was NOT true before: this
//     subcommand used to be the documented recovery path for a
//     dropped payout, and using it on a block whose payout had
//     partially run credited every already-paid miner a second time.
//     It also is no longer NEEDED for that purpose -- the unlocker
//     retries a failed payout automatically now (see
//     internal/backend/unlocker's checkBlock). If a block's payout is
//     genuinely stuck, the tool for it is `backend block-payout`, not
//     this one.
//
// Both subcommands are deliberately NOT wired into any HTTP endpoint
// or automatic trigger -- see this file's own flag set: -yes is
// mandatory (bare -id alone prints what WOULD change and exits
// nonzero without writing anything) precisely because these mutate
// payout-relevant ledger state (blocks.valid/blocks.unlocked) outside
// the unlocker's own chain-verified decision path, on an operator's
// own judgement call rather than a real chain observation this binary
// made itself.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// blockCLITimeout bounds every DB call the block subcommands make
// (connect + read + write) -- generous enough for a manual, one-off
// ops invocation against a real Postgres instance, but still bounded
// so a hung connection doesn't leave an on-call operator's terminal
// stuck indefinitely.
const blockCLITimeout = 30 * time.Second

// runBlockCommand dispatches `backend block <subcommand> ...`. args is
// os.Args with both "backend" and "block" already stripped off (i.e.
// args[0], if present, is the subcommand name: "invalidate" or
// "relock").
func runBlockCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`block: missing subcommand, want "invalidate" or "relock"`)
	}

	switch args[0] {
	case "invalidate":
		return runBlockSetStatus(args[1:], blockStatusInvalidate)
	case "relock":
		return runBlockSetStatus(args[1:], blockStatusRelock)
	default:
		return fmt.Errorf(`block: unrecognized subcommand %q, want "invalidate" or "relock"`, args[0])
	}
}

// blockStatusOp names one of this file's two supported SetBlockStatus
// call shapes, purely for logging/flag-usage text -- the actual
// valid/unlocked values each maps to live in runBlockSetStatus below,
// right next to the SetBlockStatus call itself, so the mapping this
// doc comment above describes can't drift out of sync with what the
// code actually does.
type blockStatusOp string

const (
	blockStatusInvalidate blockStatusOp = "invalidate"
	blockStatusRelock     blockStatusOp = "relock"
)

// runBlockSetStatus implements both `block invalidate` and
// `block relock`: parse flags, connect to Postgres (using -dsn or
// GCPOOL_DB_DSN, matching run()'s own DSN resolution), show the
// block's current state, and -- only if -yes was passed -- call the
// real db.Repository.SetBlockStatus with the (valid, unlocked) pair
// for op, then show the resulting state. Without -yes, this prints
// the block's current state and the change that WOULD be made, and
// returns an error (so the process exits nonzero) without touching
// the database.
func runBlockSetStatus(args []string, op blockStatusOp) error {
	fs := flag.NewFlagSet(fmt.Sprintf("backend block %s", op), flag.ContinueOnError)
	id := fs.Int64("id", 0, "REQUIRED: blocks.id of the row to update")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the update. Without this flag, the current block state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block %s -id=<blocks.id> [-dsn=...] [-yes]\n\n", op)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id <= 0 {
		fs.Usage()
		return fmt.Errorf("block %s: -id is required and must be a positive blocks.id", op)
	}
	if *dsn == "" {
		return fmt.Errorf("block %s: no DSN: pass -dsn or set GCPOOL_DB_DSN", op)
	}

	var wantValid, wantUnlocked bool
	switch op {
	case blockStatusInvalidate:
		// Matches the unlocker's own real orphaned-block write --
		// see checkBlock's outcomeOrphaned branch in
		// internal/backend/unlocker.go.
		wantValid, wantUnlocked = false, true
	case blockStatusRelock:
		// valid=TRUE, unlocked=FALSE is exactly PendingBlocks'
		// selection predicate, so this hands the block straight
		// back to the unlocker's next poll tick.
		wantValid, wantUnlocked = true, false
	default:
		return fmt.Errorf("block: internal error: unhandled op %q", op)
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockCLITimeout)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{DSN: *dsn})
	if err != nil {
		return fmt.Errorf("block %s: connecting to database: %w", op, err)
	}
	defer pool.Close()
	repo := db.NewRepository(pool)

	before, err := repo.GetBlockByID(ctx, *id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("block %s: no block with id=%d exists", op, *id)
		}
		return fmt.Errorf("block %s: looking up block %d: %w", op, *id, err)
	}
	log.Printf("block %s: id=%d algo=%s network=%s pool_type=%s height=%d hash=%s: current valid=%t unlocked=%t",
		op, *id, before.Algo, before.Network, before.PoolType, before.Height, before.Hash, before.Valid, before.Unlocked)

	if !*yes {
		log.Printf("block %s: id=%d: -yes not set, no change made. Would set valid=%t unlocked=%t. Re-run with -yes to apply.",
			op, *id, wantValid, wantUnlocked)
		return fmt.Errorf("block %s: id=%d: dry run only (pass -yes to apply)", op, *id)
	}

	if err := repo.SetBlockStatus(ctx, *id, wantValid, wantUnlocked); err != nil {
		return fmt.Errorf("block %s: id=%d: %w", op, *id, err)
	}

	after, err := repo.GetBlockByID(ctx, *id)
	if err != nil {
		// The write above already succeeded; a failed post-write
		// read is a distinct, non-fatal problem worth surfacing but
		// not worth reporting as if the update itself failed.
		log.Printf("block %s: id=%d: update applied (valid=%t unlocked=%t), but re-reading the row to confirm failed: %v",
			op, *id, wantValid, wantUnlocked, err)
		return nil
	}
	log.Printf("block %s: id=%d: updated. valid %t -> %t, unlocked %t -> %t",
		op, *id, before.Valid, after.Valid, before.Unlocked, after.Unlocked)
	return nil
}

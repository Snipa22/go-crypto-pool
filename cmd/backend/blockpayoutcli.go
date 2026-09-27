// Manual, ops-triggered "block-payout" subcommands for the backend
// binary:
//
//	backend block-payout list-unresolved      [-algo=<ALGO>] [-network=<NET>] [-dsn=...]
//	backend block-payout show                 -block-id=<id> [-dsn=...]
//	backend block-payout resolve-credited     -block-id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend block-payout resolve-not-credited -block-id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend block-payout reverse-credits      -block-id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//
// THIS IS THE HUMAN HALF OF A MONEY-CRITICAL SAFETY MECHANISM. Read
// migrations/0013_block_payouts.up.sql,
// migrations/0014_block_payout_reversal.up.sql, and
// internal/backend/db/blockpayout.go's own doc comments before using
// it.
//
// The short version: a matured block's payout used to be
// fire-and-forget. internal/backend/unlocker marked the block
// unlocked FIRST (removing it from every future automatic pass) and
// then triggered the payout, logging and dropping any failure; the
// payout itself credited miners one independent statement at a time,
// so a mid-loop failure left an unknown subset paid with no record of
// which, and the only available retry (`backend block relock`) then
// credited every one of them a second time. That is now fixed by a
// `block_payouts` claim ledger written in the SAME transaction as the
// credits, plus an itemised `block_payout_credits` record of exactly
// which `balance` row got what.
//
// Because the claim and the credits commit together, the engine can
// no longer leave a run half-done: a failure rolls everything back
// and the unlocker retries it cleanly on the next tick, and a
// completed run is recorded APPLIED and can never be applied again.
// The one state that still needs a human is a PENDING row -- a
// claimed run with no recorded outcome, which as of migration 0011
// can only come from outside that transaction (a hand-written row, or
// a future multi-transaction payout path). It means "an unknown
// subset of this block's miners may already hold its credit", so
// db.Repository.ApplyBlockPayout refuses to run for that block until
// one of the two resolve-* subcommands below says what really
// happened. These are how an operator says it.
//
// There is deliberately NO automatic reconciliation, exactly as in
// payoutcli.go: the question a PENDING row poses ("are these
// itemised credits the whole truth?") cannot be answered from inside
// this process -- the ledger is by definition the thing whose
// completeness is in doubt. Guessing moves real money, so the design
// choice is an explicit, well-logged, human-gated flow instead.
//
// `reverse-credits` is a DIFFERENT gap, closed by migration 0014: an
// APPLIED block whose payout genuinely landed, but whose block was
// LATER discovered -- via the unlocker's own real chain
// re-verification finding it orphaned by a reorg past MaturityDepth,
// or an operator's own `backend block invalidate` -- to not be a
// real block after all. Neither `backend block relock` nor the
// unlocker's automatic retry credits anybody again for such a block
// (that has been true since migration 0013), but until this
// subcommand existed nothing anywhere DEBITED the credit that
// already landed on what turned out to be bad data. Unlike the two
// resolve-* subcommands above, `reverse-credits` does NOT rely on an
// operator's unverifiable judgement call about whether coin already
// moved -- it requires the real, chain-verified (or operator-
// asserted via `backend block invalidate`) `blocks.valid = FALSE`
// signal to already exist before it will touch anything (see
// db.Repository.ReverseBlockPayoutCredits' precondition). It is
// still every bit as dangerous as the other two: it debits real
// miner balances, hence the same mandatory -reason and -yes.
//
// Mirrors payoutcli.go/blockcli.go/addresscli.go's conventions
// exactly: every mutating subcommand requires -yes (without it they
// print the current row plus the change that WOULD be made and exit
// nonzero), and requires -reason so the resolution is auditable
// (resolved_by/resolution_note columns). list-unresolved/show are
// read-only and never require -yes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// blockPayoutCLITimeout mirrors payoutCLITimeout/blockCLITimeout --
// generous for a manual, one-off ops invocation against a real
// Postgres instance, bounded so a hung connection doesn't leave an
// on-call operator's terminal stuck indefinitely.
const blockPayoutCLITimeout = 30 * time.Second

// runBlockPayoutCommand dispatches `backend block-payout <subcommand>
// ...`. args is os.Args with both "backend" and "block-payout"
// already stripped off (i.e. args[0], if present, is the subcommand
// name).
func runBlockPayoutCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`block-payout: missing subcommand, want "list-unresolved", "show", "resolve-credited", "resolve-not-credited", or "reverse-credits"`)
	}

	switch args[0] {
	case "list-unresolved":
		return runBlockPayoutListUnresolved(args[1:])
	case "show":
		return runBlockPayoutShow(args[1:])
	case "resolve-credited":
		return runBlockPayoutResolveCredited(args[1:])
	case "resolve-not-credited":
		return runBlockPayoutResolveNotCredited(args[1:])
	case "reverse-credits":
		return runBlockPayoutReverseCredits(args[1:])
	default:
		return fmt.Errorf(`block-payout: unrecognized subcommand %q, want "list-unresolved", "show", "resolve-credited", "resolve-not-credited", or "reverse-credits"`, args[0])
	}
}

// openBlockPayoutRepo is this file's shared "parse -dsn, connect,
// wrap in a *db.Repository" helper, mirroring payoutcli.go's
// openPayoutRepo exactly.
func openBlockPayoutRepo(ctx context.Context, dsn string) (*db.Repository, func(), error) {
	if dsn == "" {
		return nil, nil, errors.New("no DSN: pass -dsn or set GCPOOL_DB_DSN")
	}
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to database: %w", err)
	}
	return db.NewRepository(pool), pool.Close, nil
}

// logBlockPayoutRow prints one block_payouts row's state in one
// consistent multi-line block, used by every subcommand below both
// before and (for mutating ones) after the write -- mirroring
// logPayoutRow's convention in payoutcli.go.
func logBlockPayoutRow(prefix string, b db.BlockPayout) {
	log.Printf("%s: block_id=%d algo=%s network=%s pool_type=%s height=%d status=%s reward=%d claimed=%s",
		prefix, b.BlockID, b.Algo, b.Network, b.PoolType, b.Height, b.Status, b.Reward, b.CreatedAt.UTC().Format(time.RFC3339))
	applied := "(never)"
	if b.AppliedAt != nil {
		applied = b.AppliedAt.UTC().Format(time.RFC3339)
	}
	summary := "(none recorded -- this run never reported an outcome)"
	if b.Credited != nil && b.TotalPaid != nil {
		summary = fmt.Sprintf("%d entries totalling %d atomic units", *b.Credited, *b.TotalPaid)
	}
	log.Printf("%s: block_id=%d applied_at=%s recorded_summary=%s", prefix, b.BlockID, applied, summary)
	log.Printf("%s: block_id=%d error=%s", prefix, b.BlockID, orNone(b.Error))
	log.Printf("%s: block_id=%d resolved_by=%s resolution_note=%s", prefix, b.BlockID, orNone(b.ResolvedBy), orNone(b.ResolutionNote))
}

// logBlockPayoutCredits prints the itemised per-balance credit ledger
// for one block. For a PENDING row this is the whole basis of an
// operator's decision, so it is printed in full rather than
// summarized -- a payout run has one entry per payee plus the
// fee/dev seeds, which is a readable number of lines, not a dump.
func logBlockPayoutCredits(prefix string, blockID int64, credits []db.BlockPayoutCredit) {
	if len(credits) == 0 {
		log.Printf("%s: block_id=%d recorded credits: NONE. No balance row was credited by this run, so nothing needs reversing before `resolve-not-credited` hands the block back to the unlocker.",
			prefix, blockID)
		return
	}
	var total, standing, reversed int64
	var reversedCount int
	for _, c := range credits {
		total += c.Amount
		payID := "(none)"
		if c.PaymentID != nil && *c.PaymentID != "" {
			payID = *c.PaymentID
		}
		reversedAt := "(not reversed)"
		if c.ReversedAt != nil {
			reversedAt = c.ReversedAt.UTC().Format(time.RFC3339)
			reversed += c.Amount
			reversedCount++
		} else {
			standing += c.Amount
		}
		log.Printf("%s: block_id=%d credit: balance_id=%d address=%s payment_id=%s bucket=%s amount=%d credited_at=%s reversed_at=%s",
			prefix, blockID, c.BalanceID, c.PaymentAddress, payID, c.PayoutBucket, c.Amount, c.CreditedAt.UTC().Format(time.RFC3339), reversedAt)
	}
	if reversedCount == 0 {
		log.Printf("%s: block_id=%d recorded credits: %d row(s) totalling %d atomic units, ALREADY added to those miners' pending_balance",
			prefix, blockID, len(credits), total)
		return
	}
	log.Printf("%s: block_id=%d recorded credits: %d row(s) totalling %d atomic units (%d row(s)/%d atomic units already REVERSED and debited back out, %d row(s)/%d atomic units still standing)",
		prefix, blockID, len(credits), total, reversedCount, reversed, len(credits)-reversedCount, standing)
}

// orNone renders a nullable text column for operator output.
func orNone(s *string) string {
	if s == nil || *s == "" {
		return "(none)"
	}
	return *s
}

// runBlockPayoutListUnresolved implements the read-only `block-payout
// list-unresolved` subcommand: every PENDING block_payouts row,
// optionally narrowed to one algo and/or network. This is the
// entrypoint an operator reaches for after seeing the backend's
// startup warning, or the unlocker failing the same block every poll
// tick.
func runBlockPayoutListUnresolved(args []string) error {
	fs := flag.NewFlagSet("backend block-payout list-unresolved", flag.ContinueOnError)
	algo := fs.String("algo", "", "narrow to one algo (RXT/C29/SHA3X/RXM). Empty means all algos.")
	network := fs.String("network", "", "narrow to one network (MAINNET/TESTNET). Empty means all networks.")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block-payout list-unresolved [-algo=<ALGO>] [-network=<NETWORK>] [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockPayoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openBlockPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("block-payout list-unresolved: %w", err)
	}
	defer closeFn()

	rows, err := repo.UnresolvedBlockPayouts(ctx, *algo, *network)
	if err != nil {
		return fmt.Errorf("block-payout list-unresolved: %w", err)
	}
	if len(rows) == 0 {
		log.Print("block-payout list-unresolved: no unresolved (PENDING) block payouts -- no block's payout is being blocked by this mechanism")
		return nil
	}
	for _, b := range rows {
		logBlockPayoutRow("block-payout list-unresolved", b)
	}
	log.Printf("block-payout list-unresolved: %d unresolved block payout row(s). Each of those blocks is BLOCKED from any further automatic payout (and stays valid=TRUE/unlocked=FALSE, retried and failed on every unlocker poll tick) until it is resolved. "+
		"Inspect each with `backend block-payout show -block-id=<id>`, establish whether its recorded credits are the whole truth, then run `backend block-payout resolve-credited` (they are: marks it APPLIED, credits nobody again) "+
		"or `backend block-payout resolve-not-credited` (nothing landed, or you reversed what did: hands the block back to the unlocker to pay out from scratch).",
		len(rows))
	return nil
}

// runBlockPayoutShow implements the read-only `block-payout show`
// subcommand -- one block_payouts row by block id, in ANY status (so
// an operator can also confirm what a resolution actually did
// afterward), together with its full itemised credit ledger. Never
// requires -yes; it writes nothing.
func runBlockPayoutShow(args []string) error {
	fs := flag.NewFlagSet("backend block-payout show", flag.ContinueOnError)
	blockID := fs.Int64("block-id", 0, "REQUIRED: blocks.id whose payout run to show")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block-payout show -block-id=<blocks.id> [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *blockID <= 0 {
		fs.Usage()
		return errors.New("block-payout show: -block-id is required and must be a positive blocks.id")
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockPayoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openBlockPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("block-payout show: %w", err)
	}
	defer closeFn()

	b, err := repo.GetBlockPayout(ctx, *blockID)
	if err != nil {
		if errors.Is(err, db.ErrBlockPayoutNotFound) {
			return fmt.Errorf("block-payout show: no payout run has ever been claimed for block id=%d (so nothing is blocking it -- the unlocker will run its payout normally when it matures)", *blockID)
		}
		return fmt.Errorf("block-payout show: %w", err)
	}
	logBlockPayoutRow("block-payout show", b)

	credits, err := repo.BlockPayoutCredits(ctx, *blockID)
	if err != nil {
		return fmt.Errorf("block-payout show: reading the credit ledger: %w", err)
	}
	logBlockPayoutCredits("block-payout show", *blockID, credits)
	return nil
}

// runBlockPayoutResolveCredited implements `block-payout
// resolve-credited`: the operator has established that the itemised
// credits this PENDING run recorded are COMPLETE and CORRECT -- those
// miners hold that coin, and nothing further is owed for this block.
//
// It flips the row to APPLIED, deriving credited/total_paid from the
// real ledger rows (never from anything typed here), and credits no
// further balance. The miners are NOT paid again: that is the entire
// point, and the direct analog of `backend payout resolve-sent`.
// Once APPLIED, the block's payout can never run again, so the
// unlocker's next poll pass will finally mark it unlocked.
func runBlockPayoutResolveCredited(args []string) error {
	fs := flag.NewFlagSet("backend block-payout resolve-credited", flag.ContinueOnError)
	blockID := fs.Int64("block-id", 0, "REQUIRED: blocks.id of the unresolved (PENDING) payout run to resolve")
	reason := fs.String("reason", "", "REQUIRED: how you established that the recorded credits are complete and correct (recorded on the row)")
	by := fs.String("by", "", "operator identifier recorded on this resolution (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the resolution. Without this flag, the run's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block-payout resolve-credited -block-id=<blocks.id> -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *blockID <= 0 {
		fs.Usage()
		return errors.New("block-payout resolve-credited: -block-id is required and must be a positive blocks.id")
	}
	if *reason == "" {
		fs.Usage()
		return errors.New("block-payout resolve-credited: -reason is required -- this declares a block's miner credits final on your judgement call, so it must record how you established that")
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockPayoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openBlockPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("block-payout resolve-credited: %w", err)
	}
	defer closeFn()

	before, credits, err := loadBlockPayoutForResolution(ctx, repo, "resolve-credited", *blockID)
	if err != nil {
		return err
	}

	var total int64
	for _, c := range credits {
		total += c.Amount
	}

	if !*yes {
		log.Printf("block-payout resolve-credited: block_id=%d: -yes not set, no change made. Would mark this run APPLIED with credited=%d total_paid=%d (derived from the ledger above, not from any flag), "+
			"credit NO further balance, and record resolved_by=%q resolution_note=%q. The block then becomes eligible to be marked unlocked by the unlocker's next poll pass. Re-run with -yes to apply.",
			*blockID, len(credits), total, *by, *reason)
		return fmt.Errorf("block-payout resolve-credited: block_id=%d: dry run only (pass -yes to apply)", *blockID)
	}

	if err := repo.ResolveBlockPayoutCredited(ctx, *blockID, *by, *reason); err != nil {
		return fmt.Errorf("block-payout resolve-credited: block_id=%d: %w", *blockID, err)
	}

	after, err := repo.GetBlockPayout(ctx, *blockID)
	if err != nil {
		// The write above already succeeded; a failed post-write
		// read is a distinct, non-fatal problem worth surfacing but
		// not worth reporting as if the resolution itself failed.
		log.Printf("block-payout resolve-credited: block_id=%d: resolution applied (status APPLIED, %d atomic units across %d ledger row(s) declared final, nothing re-credited), but re-reading the row to confirm failed: %v",
			*blockID, total, len(credits), err)
		return nil
	}
	logBlockPayoutRow("block-payout resolve-credited: after", after)
	log.Printf("block-payout resolve-credited: block_id=%d: resolved. status %s -> %s. No balance was credited again; the %d recorded credit(s) totalling %d atomic units now stand as this block's final payout. "+
		"The unlocker's next poll pass will mark the block unlocked.",
		*blockID, before.Status, after.Status, len(credits), total)
	return nil
}

// runBlockPayoutResolveNotCredited implements `block-payout
// resolve-not-credited`: the operator has established that this
// PENDING run credited NOTHING that still stands -- either it never
// credited a balance, or they have already reversed by hand whatever
// it did credit.
//
// It flips the row to FAILED and deletes this block's credit ledger
// rows (leaving them would misreport history AND make the re-run's
// row-level idempotency backstop silently skip exactly the credits
// just declared void). FAILED is re-claimable, so the block goes back
// into the automatic path: the next unlocker poll pass re-runs its
// full payout calculation from scratch. No `balance` row is touched
// here -- reversing a real credit is a judgement call about live
// miner balances and is deliberately not automated.
//
// This is the most dangerous command in this file, and the direct
// analog of `backend payout resolve-not-sent`: if the PENDING run DID
// credit miners and those credits were not reversed, this makes the
// pool credit the same block's payout a second time. Hence mandatory
// -reason and -yes, and the loud warning whenever ledger rows exist.
func runBlockPayoutResolveNotCredited(args []string) error {
	fs := flag.NewFlagSet("backend block-payout resolve-not-credited", flag.ContinueOnError)
	blockID := fs.Int64("block-id", 0, "REQUIRED: blocks.id of the unresolved (PENDING) payout run to resolve")
	reason := fs.String("reason", "", "REQUIRED: how you established that nothing this run credited still stands (recorded on the row)")
	by := fs.String("by", "", "operator identifier recorded on this resolution (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the resolution. Without this flag, the run's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block-payout resolve-not-credited -block-id=<blocks.id> -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *blockID <= 0 {
		fs.Usage()
		return errors.New("block-payout resolve-not-credited: -block-id is required and must be a positive blocks.id")
	}
	if *reason == "" {
		fs.Usage()
		return errors.New("block-payout resolve-not-credited: -reason is required -- this makes a block's whole payout run again on your judgement call, and is a double credit if you are wrong, so it must record how you established it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockPayoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openBlockPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("block-payout resolve-not-credited: %w", err)
	}
	defer closeFn()

	before, credits, err := loadBlockPayoutForResolution(ctx, repo, "resolve-not-credited", *blockID)
	if err != nil {
		return err
	}

	var total int64
	for _, c := range credits {
		total += c.Amount
	}
	if len(credits) > 0 {
		log.Printf("block-payout resolve-not-credited: block_id=%d: WARNING: this run recorded %d credit(s) totalling %d atomic units (itemised above), which were ALREADY added to those miners' pending_balance. "+
			"That is strong evidence coin DID land. If those credits have not been reversed by hand, `resolve-not-credited` will make the unlocker pay this block out from scratch and the pool will credit the same block twice. "+
			"Verify each balance_id above against the amounts listed and use `resolve-credited` instead unless you are certain none of it stands.",
			*blockID, len(credits), total)
	}

	if !*yes {
		log.Printf("block-payout resolve-not-credited: block_id=%d: -yes not set, no change made. Would mark this run FAILED, DELETE its %d recorded credit ledger row(s) (totalling %d atomic units), touch no balance row, "+
			"and record resolved_by=%q resolution_note=%q. The block's full payout calculation would then re-run from scratch on the unlocker's next poll pass. Re-run with -yes to apply.",
			*blockID, len(credits), total, *by, *reason)
		return fmt.Errorf("block-payout resolve-not-credited: block_id=%d: dry run only (pass -yes to apply)", *blockID)
	}

	if err := repo.ResolveBlockPayoutNotCredited(ctx, *blockID, *by, *reason); err != nil {
		return fmt.Errorf("block-payout resolve-not-credited: block_id=%d: %w", *blockID, err)
	}

	after, err := repo.GetBlockPayout(ctx, *blockID)
	if err != nil {
		log.Printf("block-payout resolve-not-credited: block_id=%d: resolution applied (status FAILED, %d credit ledger row(s) deleted, balances untouched), but re-reading the row to confirm failed: %v",
			*blockID, len(credits), err)
		return nil
	}
	logBlockPayoutRow("block-payout resolve-not-credited: after", after)
	log.Printf("block-payout resolve-not-credited: block_id=%d: resolved. status %s -> %s. %d credit ledger row(s) deleted and no balance row touched, so this block's full payout will be recalculated and applied from scratch "+
		"on the unlocker's next poll pass.",
		*blockID, before.Status, after.Status, len(credits))
	return nil
}

// runBlockPayoutReverseCredits implements `block-payout
// reverse-credits`: reverses (debits back out) the credits an
// ALREADY-APPLIED block payout run recorded, for a block that has
// SINCE been found orphaned/invalid -- via the unlocker's own real
// chain re-verification writing `blocks.valid = FALSE` on a genuine
// reorg-past-maturity orphan (see internal/backend/unlocker/
// unlocker.go's checkBlock), or an operator's own `backend block
// invalidate` (see cmd/backend/blockcli.go).
//
// Unlike resolve-credited/resolve-not-credited, this subcommand does
// NOT ask the operator to make an unverifiable judgement call about
// whether coin already moved -- the whole precondition lives in
// db.Repository.ReverseBlockPayoutCredits, which hard-refuses
// (ErrBlockStillValid) unless the real blocks.valid column is already
// FALSE. This subcommand's job is narrower: show exactly what WOULD
// be debited, refuse a dry run without -yes, and report what actually
// happened. It is still every bit as dangerous as the other two --
// it debits real miner balances -- hence the same mandatory -reason
// and -yes.
//
// Idempotent: running this a second time against an already-REVERSED
// block prints a clear "already reversed, nothing to do" message and
// writes nothing. This is expected, SAFE behavior (mirroring
// ApplyBlockPayout's AlreadyApplied messaging tone in the other
// direction), not a refusal that looks like a failure.
func runBlockPayoutReverseCredits(args []string) error {
	fs := flag.NewFlagSet("backend block-payout reverse-credits", flag.ContinueOnError)
	blockID := fs.Int64("block-id", 0, "REQUIRED: blocks.id of the APPLIED payout run whose credits to reverse")
	reason := fs.String("reason", "", "REQUIRED: how you established that this block is invalid/orphaned and its credits must be reversed (recorded on the row)")
	by := fs.String("by", "", "operator identifier recorded on this resolution (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the reversal. Without this flag, the run's current state and intended debit are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend block-payout reverse-credits -block-id=<blocks.id> -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *blockID <= 0 {
		fs.Usage()
		return errors.New("block-payout reverse-credits: -block-id is required and must be a positive blocks.id")
	}
	if *reason == "" {
		fs.Usage()
		return errors.New("block-payout reverse-credits: -reason is required -- this debits real miner balances (backed by the real blocks.valid=FALSE signal), so it must record how you established the block is invalid/orphaned")
	}

	ctx, cancel := context.WithTimeout(context.Background(), blockPayoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openBlockPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("block-payout reverse-credits: %w", err)
	}
	defer closeFn()

	before, credits, blockValid, err := loadBlockPayoutForReversal(ctx, repo, *blockID)
	if err != nil {
		return err
	}

	if before.Status == db.BlockPayoutStatusReversed {
		log.Printf("block-payout reverse-credits: block_id=%d: already REVERSED (resolved_by=%s resolution_note=%s) -- nothing to do. This is expected, safe behavior: reversing an already-reversed block would double-debit, so this call writes nothing.",
			*blockID, orNone(before.ResolvedBy), orNone(before.ResolutionNote))
		return nil
	}
	if before.Status != db.BlockPayoutStatusApplied {
		return fmt.Errorf("block-payout reverse-credits: block_id=%d: status is %s, not APPLIED (or already REVERSED) -- only an APPLIED run has credits to reverse; a PENDING row needs `resolve-credited`/`resolve-not-credited` first, and a FAILED row already credited nobody",
			*blockID, before.Status)
	}
	if blockValid {
		return fmt.Errorf("block-payout reverse-credits: block_id=%d: refusing -- blocks.valid = TRUE for this block, so it has not been found orphaned/invalid (see the unlocker's real chain re-verification, or `backend block invalidate`); reversing its payout would debit miners for coin they may genuinely be owed",
			*blockID)
	}

	var total int64
	for _, c := range credits {
		if c.ReversedAt == nil {
			total += c.Amount
		}
	}

	if !*yes {
		log.Printf("block-payout reverse-credits: block_id=%d: -yes not set, no change made. Would mark this run REVERSED and debit %d atomic units back out across %d balance row(s) (itemised above), and record resolved_by=%q resolution_note=%q. Re-run with -yes to apply.",
			*blockID, total, len(credits), *by, *reason)
		return fmt.Errorf("block-payout reverse-credits: block_id=%d: dry run only (pass -yes to apply)", *blockID)
	}

	outcome, err := repo.ReverseBlockPayoutCredits(ctx, *blockID, *by, *reason)
	if err != nil {
		return fmt.Errorf("block-payout reverse-credits: block_id=%d: %w", *blockID, err)
	}
	if outcome.AlreadyReversed {
		// A concurrent reversal won the race between this process's
		// own pre-write state read above and its real call. Report it
		// exactly like the up-front idempotent case, not as an error.
		log.Printf("block-payout reverse-credits: block_id=%d: already REVERSED by a concurrent caller (credits_reversed=%d total_reversed=%d) -- nothing further to do.",
			*blockID, outcome.CreditsReversed, outcome.TotalReversed)
		return nil
	}

	after, err := repo.GetBlockPayout(ctx, *blockID)
	if err != nil {
		log.Printf("block-payout reverse-credits: block_id=%d: reversal applied (status REVERSED, %d atomic units debited back across %d balance row(s)), but re-reading the row to confirm failed: %v",
			*blockID, outcome.TotalReversed, outcome.CreditsReversed, err)
		return nil
	}
	logBlockPayoutRow("block-payout reverse-credits: after", after)
	if afterCredits, err := repo.BlockPayoutCredits(ctx, *blockID); err == nil {
		logBlockPayoutCredits("block-payout reverse-credits: after", *blockID, afterCredits)
	}
	log.Printf("block-payout reverse-credits: block_id=%d: resolved. status %s -> %s. %d atomic units debited back out across %d balance row(s); this block can never be paid again.",
		*blockID, before.Status, after.Status, outcome.TotalReversed, outcome.CreditsReversed)
	return nil
}

// loadBlockPayoutForReversal is reverse-credits' own "read the row,
// read its ledger, read the block's real valid flag, print all
// three" preamble. It deliberately does NOT enforce any status
// precondition itself (unlike loadBlockPayoutForResolution below) --
// reverse-credits has to distinguish three different non-identical
// outcomes (APPLIED and reversible; already REVERSED and therefore a
// safe no-op; or neither and therefore refused) with three different
// messages, so that branching lives in runBlockPayoutReverseCredits
// right next to the messages it produces.
func loadBlockPayoutForReversal(ctx context.Context, repo *db.Repository, blockID int64) (db.BlockPayout, []db.BlockPayoutCredit, bool, error) {
	const prefix = "block-payout reverse-credits"
	before, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		if errors.Is(err, db.ErrBlockPayoutNotFound) {
			return db.BlockPayout{}, nil, false, fmt.Errorf("%s: no payout run has ever been claimed for block id=%d, so there is nothing to reverse", prefix, blockID)
		}
		return db.BlockPayout{}, nil, false, fmt.Errorf("%s: %w", prefix, err)
	}
	logBlockPayoutRow(prefix+": before", before)

	credits, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		return db.BlockPayout{}, nil, false, fmt.Errorf("%s: reading the credit ledger: %w", prefix, err)
	}
	logBlockPayoutCredits(prefix+": before", blockID, credits)

	block, err := repo.GetBlockByID(ctx, blockID)
	if err != nil {
		return db.BlockPayout{}, nil, false, fmt.Errorf("%s: looking up the underlying blocks row: %w", prefix, err)
	}
	log.Printf("%s: block_id=%d: underlying blocks row: valid=%t unlocked=%t (reversal requires valid=FALSE -- the real, chain-verified or operator-asserted orphan/invalid signal)",
		prefix, blockID, block.Valid, block.Unlocked)

	return before, credits, block.Valid, nil
}

// loadBlockPayoutForResolution is the shared "read the row, read its
// ledger, print both, and refuse anything not actually unresolved"
// preamble both mutating subcommands run before deciding anything.
// Keeping it in one place is deliberate: the PENDING-only guard is
// the safety property of this whole file, and it must not be possible
// for one subcommand to be written without it.
func loadBlockPayoutForResolution(ctx context.Context, repo *db.Repository, op string, blockID int64) (db.BlockPayout, []db.BlockPayoutCredit, error) {
	prefix := "block-payout " + op
	before, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		if errors.Is(err, db.ErrBlockPayoutNotFound) {
			return db.BlockPayout{}, nil, fmt.Errorf("%s: no payout run has ever been claimed for block id=%d, so there is nothing to resolve (the unlocker will run its payout normally)", prefix, blockID)
		}
		return db.BlockPayout{}, nil, fmt.Errorf("%s: %w", prefix, err)
	}
	logBlockPayoutRow(prefix+": before", before)

	credits, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		return db.BlockPayout{}, nil, fmt.Errorf("%s: reading the credit ledger: %w", prefix, err)
	}
	logBlockPayoutCredits(prefix+": before", blockID, credits)

	if before.Status != db.BlockPayoutStatusPending {
		return db.BlockPayout{}, nil, fmt.Errorf("%s: block_id=%d: status is %s, not PENDING -- refusing to touch an already-resolved block payout (resolving it twice would either re-credit these miners or void a payout that really stands)",
			prefix, blockID, before.Status)
	}
	return before, credits, nil
}

// Manual, ops-triggered "block-payout" subcommands for the backend
// binary:
//
//	backend block-payout list-unresolved      [-algo=<ALGO>] [-network=<NET>] [-dsn=...]
//	backend block-payout show                 -block-id=<id> [-dsn=...]
//	backend block-payout resolve-credited     -block-id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend block-payout resolve-not-credited -block-id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//
// THIS IS THE HUMAN HALF OF A MONEY-CRITICAL SAFETY MECHANISM. Read
// migrations/0011_block_payouts.up.sql and
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
// Mirrors payoutcli.go/blockcli.go/addresscli.go's conventions
// exactly: the two mutating subcommands require -yes (without it they
// print the current row plus the change that WOULD be made and exit
// nonzero), and both require -reason so the resolution is auditable
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
		return errors.New(`block-payout: missing subcommand, want "list-unresolved", "show", "resolve-credited", or "resolve-not-credited"`)
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
	default:
		return fmt.Errorf(`block-payout: unrecognized subcommand %q, want "list-unresolved", "show", "resolve-credited", or "resolve-not-credited"`, args[0])
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
	var total int64
	for _, c := range credits {
		total += c.Amount
		payID := "(none)"
		if c.PaymentID != nil && *c.PaymentID != "" {
			payID = *c.PaymentID
		}
		log.Printf("%s: block_id=%d credit: balance_id=%d address=%s payment_id=%s bucket=%s amount=%d credited_at=%s",
			prefix, blockID, c.BalanceID, c.PaymentAddress, payID, c.PayoutBucket, c.Amount, c.CreditedAt.UTC().Format(time.RFC3339))
	}
	log.Printf("%s: block_id=%d recorded credits: %d row(s) totalling %d atomic units, ALREADY added to those miners' pending_balance",
		prefix, blockID, len(credits), total)
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

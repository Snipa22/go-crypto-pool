// Manual, ops-triggered "payout" subcommands for the backend binary:
//
//	backend payout list-unresolved   [-algo=<ALGO>] [-network=<NET>] [-dsn=...]
//	backend payout show              -id=<id> [-dsn=...]
//	backend payout resolve-sent      -id=<id> -tx-hash=<hash> [-fee=<atomic>] -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend payout resolve-not-sent  -id=<id> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//
// THIS IS THE HUMAN HALF OF A MONEY-CRITICAL SAFETY MECHANISM. Read
// migrations/0010_payouts_ambiguous_status.up.sql and
// internal/backend/disburse's package doc comment before using it.
//
// The short version: a real on-chain Transfer can fail in a way that
// does not prove whether coin moved (a timed-out but successful
// monero-wallet-rpc `transfer`; Tari's transfer-succeeded-but-
// fee-lookup-failed path; a bookkeeping write that failed AFTER a
// confirmed broadcast). The disbursement engine used to record all of
// those as FAILED, which left the balance payable and re-sent the
// same coin next cycle -- a real double payment. It now records them
// AMBIGUOUS, freezes the affected `balance` rows out of
// PayableBalances, and HALTS disbursement for that (algo, network)
// entirely -- including refusing to start the loop on the next
// process launch. Nothing clears that state automatically. These
// subcommands are how an operator clears it, after establishing the
// truth off-platform (block explorer, wallet history, node RPC).
//
// There is deliberately NO automatic reconciliation, and this file
// does not attempt any. internal/backend/wallet exposes no
// transfer-history/listing call to diff against: the Monero client
// wraps only `transfer` and `get_balance`, and the Tari client adds
// only a lookup BY transaction id -- which is useless in exactly the
// case that matters, where the ambiguity is that no transaction id
// ever came back. Building history-diffing reconciliation would mean
// guessing about real money from incomplete data, so the design
// choice here is an explicit, well-logged, human-gated flow instead.
//
// Mirrors blockcli.go/addresscli.go's conventions exactly: the two
// mutating subcommands require -yes (without it they print the
// current row plus the change that WOULD be made and exit nonzero),
// and both require -reason so the resolution is auditable
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

// payoutCLITimeout mirrors blockCLITimeout/addressCLITimeout --
// generous for a manual, one-off ops invocation against a real
// Postgres instance, bounded so a hung connection doesn't leave an
// on-call operator's terminal stuck indefinitely.
const payoutCLITimeout = 30 * time.Second

// runPayoutCommand dispatches `backend payout <subcommand> ...`. args
// is os.Args with both "backend" and "payout" already stripped off
// (i.e. args[0], if present, is the subcommand name).
func runPayoutCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`payout: missing subcommand, want "list-unresolved", "show", "resolve-sent", or "resolve-not-sent"`)
	}

	switch args[0] {
	case "list-unresolved":
		return runPayoutListUnresolved(args[1:])
	case "show":
		return runPayoutShow(args[1:])
	case "resolve-sent":
		return runPayoutResolveSent(args[1:])
	case "resolve-not-sent":
		return runPayoutResolveNotSent(args[1:])
	default:
		return fmt.Errorf(`payout: unrecognized subcommand %q, want "list-unresolved", "show", "resolve-sent", or "resolve-not-sent"`, args[0])
	}
}

// openPayoutRepo is this file's shared "parse -dsn, connect, wrap in
// a *db.Repository" helper, mirroring addresscli.go's
// openAddressRepo exactly.
func openPayoutRepo(ctx context.Context, dsn string) (*db.Repository, func(), error) {
	if dsn == "" {
		return nil, nil, errors.New("no DSN: pass -dsn or set GCPOOL_DB_DSN")
	}
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to database: %w", err)
	}
	return db.NewRepository(pool), pool.Close, nil
}

// logPayoutRow prints one payouts row's state in one consistent
// multi-line block, used by every subcommand below both before and
// (for mutating ones) after the write -- mirroring blockcli.go's
// before/after logging convention, but multi-line because a payout
// row genuinely carries more an operator needs to see (which balance
// rows, what each would be debited, the error that produced the
// state).
func logPayoutRow(prefix string, p db.UnresolvedPayout) {
	txHash := "(none)"
	if p.TxHash != nil && *p.TxHash != "" {
		txHash = *p.TxHash
	}
	errMsg := "(none)"
	if p.Error != nil && *p.Error != "" {
		errMsg = *p.Error
	}
	log.Printf("%s: payout id=%d algo=%s network=%s status=%s amount=%d created=%s",
		prefix, p.ID, p.Algo, p.Network, p.Status, p.Amount, p.CreatedAt.UTC().Format(time.RFC3339))
	log.Printf("%s: payout id=%d tx_hash=%s", prefix, p.ID, txHash)
	log.Printf("%s: payout id=%d error=%s", prefix, p.ID, errMsg)
	log.Printf("%s: payout id=%d balance_ids=%v", prefix, p.ID, p.BalanceIDs)
	if len(p.Entries) == 0 {
		log.Printf("%s: payout id=%d recorded per-balance entries: NONE (row predates migration 0010; `resolve-sent` cannot replay its debit and will refuse)", prefix, p.ID)
		return
	}
	for _, e := range p.Entries {
		log.Printf("%s: payout id=%d entry: balance_id=%d debit_amount=%d force_payout=%t force_payout_fee_atomic=%d",
			prefix, p.ID, e.BalanceID, e.Amount, e.ForcePayout, e.ForcePayoutFeeAtomic)
	}
}

// runPayoutListUnresolved implements the read-only `payout
// list-unresolved` subcommand: every PENDING/AMBIGUOUS payout row,
// optionally narrowed to one algo and/or network. This is the
// entrypoint an operator reaches for when the backend logs that it
// refused to start disbursement, or when
// disbursement_unresolved_payouts goes above zero.
func runPayoutListUnresolved(args []string) error {
	fs := flag.NewFlagSet("backend payout list-unresolved", flag.ContinueOnError)
	algo := fs.String("algo", "", "narrow to one algo (RXT/C29/SHA3X/RXM). Empty means all algos.")
	network := fs.String("network", "", "narrow to one network (MAINNET/TESTNET). Empty means all networks.")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend payout list-unresolved [-algo=<ALGO>] [-network=<NETWORK>] [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), payoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("payout list-unresolved: %w", err)
	}
	defer closeFn()

	rows, err := repo.UnresolvedPayouts(ctx, *algo, *network)
	if err != nil {
		return fmt.Errorf("payout list-unresolved: %w", err)
	}
	if len(rows) == 0 {
		log.Print("payout list-unresolved: no unresolved (PENDING/AMBIGUOUS) payouts -- disbursement is not being blocked by this mechanism")
		return nil
	}
	for _, p := range rows {
		logPayoutRow("payout list-unresolved", p)
	}
	log.Printf("payout list-unresolved: %d unresolved payout row(s). Disbursement is HALTED for every (algo, network) listed above until each is resolved. "+
		"Confirm on-chain whether each transfer really broadcast, then run `backend payout resolve-sent` (it did) or `backend payout resolve-not-sent` (it did not), and restart the backend.",
		len(rows))
	return nil
}

// runPayoutShow implements the read-only `payout show` subcommand --
// one payout row by id, in ANY status (so an operator can also
// confirm what a resolution actually did afterward). Never requires
// -yes; it writes nothing.
func runPayoutShow(args []string) error {
	fs := flag.NewFlagSet("backend payout show", flag.ContinueOnError)
	id := fs.Int64("id", 0, "REQUIRED: payouts.id of the row to show")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend payout show -id=<payouts.id> [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id <= 0 {
		fs.Usage()
		return errors.New("payout show: -id is required and must be a positive payouts.id")
	}

	ctx, cancel := context.WithTimeout(context.Background(), payoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("payout show: %w", err)
	}
	defer closeFn()

	p, err := repo.GetPayoutByID(ctx, *id)
	if err != nil {
		if errors.Is(err, db.ErrPayoutNotFound) {
			return fmt.Errorf("payout show: no payout with id=%d exists", *id)
		}
		return fmt.Errorf("payout show: %w", err)
	}
	logPayoutRow("payout show", p)
	return nil
}

// runPayoutResolveSent implements `payout resolve-sent`: the operator
// has CONFIRMED, off-platform, that this payout's transfer really did
// broadcast on-chain.
//
// It replays exactly the debit the original (failed) CompletePayoutSent
// would have applied, from the per-entry detail recorded BEFORE the
// attempt -- never re-derived from current `balance` state, which may
// have accrued more since and would silently overpay the pool against
// a miner. The miner is NOT paid again: the coin already left the hot
// wallet, so the correct action is to finish recording it, not to
// re-send.
//
// -tx-hash is mandatory and is the operator's assertion of what they
// actually verified. When the row already carries a tx_hash (the
// bookkeeping-failed-after-success case), passing a DIFFERENT one is
// refused rather than silently overwriting the real one recorded by
// the engine.
func runPayoutResolveSent(args []string) error {
	fs := flag.NewFlagSet("backend payout resolve-sent", flag.ContinueOnError)
	id := fs.Int64("id", 0, "REQUIRED: payouts.id of the unresolved row to resolve")
	txHash := fs.String("tx-hash", "", "REQUIRED: the real on-chain transaction hash you have independently CONFIRMED for this payout")
	fee := fs.Int64("fee", 0, "real on-chain network fee actually paid, in atomic units, if you know it. 0 records no fee -- this is pool-cost bookkeeping only and never affects any miner's balance.")
	reason := fs.String("reason", "", "REQUIRED: how you confirmed this transfer really broadcast (recorded on the row)")
	by := fs.String("by", "", "operator identifier recorded on this resolution (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the resolution. Without this flag, the payout's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend payout resolve-sent -id=<payouts.id> -tx-hash=<hash> [-fee=<atomic>] -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id <= 0 {
		fs.Usage()
		return errors.New("payout resolve-sent: -id is required and must be a positive payouts.id")
	}
	if *txHash == "" {
		fs.Usage()
		return errors.New("payout resolve-sent: -tx-hash is required -- resolving a payout as SENT is an assertion that you verified a specific real transaction on-chain, so the hash must be recorded")
	}
	if *reason == "" {
		fs.Usage()
		return errors.New("payout resolve-sent: -reason is required -- this write debits real miner balances on your judgement call, so it must record how you confirmed it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), payoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("payout resolve-sent: %w", err)
	}
	defer closeFn()

	before, err := repo.GetPayoutByID(ctx, *id)
	if err != nil {
		if errors.Is(err, db.ErrPayoutNotFound) {
			return fmt.Errorf("payout resolve-sent: no payout with id=%d exists", *id)
		}
		return fmt.Errorf("payout resolve-sent: %w", err)
	}
	logPayoutRow("payout resolve-sent: before", before)

	if before.Status != db.PayoutStatusPending && before.Status != db.PayoutStatusAmbiguous {
		return fmt.Errorf("payout resolve-sent: id=%d: status is %s, not PENDING/AMBIGUOUS -- refusing to touch an already-resolved payout (resolving it twice would debit those balances twice)", *id, before.Status)
	}
	if before.TxHash != nil && *before.TxHash != "" && *before.TxHash != *txHash {
		return fmt.Errorf("payout resolve-sent: id=%d: the row already records tx_hash=%q (captured by the engine from the real, successful Transfer) but -tx-hash=%q was passed; refusing to overwrite it. Re-run with -tx-hash=%q if that is genuinely the transaction you verified",
			*id, *before.TxHash, *txHash, *before.TxHash)
	}
	if len(before.Entries) == 0 {
		return fmt.Errorf("payout resolve-sent: id=%d: this row has no recorded per-balance entries (it predates migration 0010), so the exact debit it would have applied is unknown. Refusing to guess -- resolve this row by hand, with review, after establishing the real per-balance amounts", *id)
	}

	var totalDebit, totalForceFee int64
	for _, e := range before.Entries {
		totalDebit += e.Amount
		totalForceFee += e.ForcePayoutFeeAtomic
	}

	if !*yes {
		log.Printf("payout resolve-sent: id=%d: -yes not set, no change made. Would mark this payout SENT with tx_hash=%s fee=%d, debit %d atomic units total across %d balance row(s) (banking %d atomic units of force-payout fees), and record resolved_by=%q resolution_note=%q. The miner would NOT be paid again. Re-run with -yes to apply.",
			*id, *txHash, *fee, totalDebit, len(before.Entries), totalForceFee, *by, *reason)
		return fmt.Errorf("payout resolve-sent: id=%d: dry run only (pass -yes to apply)", *id)
	}

	if err := repo.ResolvePayoutSent(ctx, *id, *txHash, *fee, *by, *reason); err != nil {
		return fmt.Errorf("payout resolve-sent: id=%d: %w", *id, err)
	}

	after, err := repo.GetPayoutByID(ctx, *id)
	if err != nil {
		// The write above already succeeded; a failed post-write
		// read is a distinct, non-fatal problem worth surfacing but
		// not worth reporting as if the resolution itself failed.
		log.Printf("payout resolve-sent: id=%d: resolution applied (status SENT, tx_hash=%s, %d atomic units debited), but re-reading the row to confirm failed: %v",
			*id, *txHash, totalDebit, err)
		return nil
	}
	logPayoutRow("payout resolve-sent: after", after)
	log.Printf("payout resolve-sent: id=%d: resolved. status %s -> %s. %d atomic units debited across %d balance row(s); no coin was re-sent. "+
		"Restart the backend to resume disbursement for %s/%s.",
		*id, before.Status, after.Status, totalDebit, len(before.Entries), after.Algo, after.Network)
	return nil
}

// runPayoutResolveNotSent implements `payout resolve-not-sent`: the
// operator has CONFIRMED, off-platform, that this payout's transfer
// never broadcast at all.
//
// It touches no `balance` row and simply flips the payout to FAILED,
// which is what makes those balances payable again -- once the row is
// no longer unresolved, PayableBalances stops excluding them and the
// next disbursement cycle retries the payout normally.
//
// This is the single most dangerous command in this binary: if the
// transfer DID broadcast and this is run anyway, the pool pays the
// same coin a second time. Hence mandatory -reason and -yes, and the
// loud confirmation output.
func runPayoutResolveNotSent(args []string) error {
	fs := flag.NewFlagSet("backend payout resolve-not-sent", flag.ContinueOnError)
	id := fs.Int64("id", 0, "REQUIRED: payouts.id of the unresolved row to resolve")
	reason := fs.String("reason", "", "REQUIRED: how you confirmed this transfer never broadcast (recorded on the row)")
	by := fs.String("by", "", "operator identifier recorded on this resolution (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the resolution. Without this flag, the payout's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend payout resolve-not-sent -id=<payouts.id> -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id <= 0 {
		fs.Usage()
		return errors.New("payout resolve-not-sent: -id is required and must be a positive payouts.id")
	}
	if *reason == "" {
		fs.Usage()
		return errors.New("payout resolve-not-sent: -reason is required -- this makes real balances payable again on your judgement call, and is a double payment if you are wrong, so it must record how you confirmed it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), payoutCLITimeout)
	defer cancel()

	repo, closeFn, err := openPayoutRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("payout resolve-not-sent: %w", err)
	}
	defer closeFn()

	before, err := repo.GetPayoutByID(ctx, *id)
	if err != nil {
		if errors.Is(err, db.ErrPayoutNotFound) {
			return fmt.Errorf("payout resolve-not-sent: no payout with id=%d exists", *id)
		}
		return fmt.Errorf("payout resolve-not-sent: %w", err)
	}
	logPayoutRow("payout resolve-not-sent: before", before)

	if before.Status != db.PayoutStatusPending && before.Status != db.PayoutStatusAmbiguous {
		return fmt.Errorf("payout resolve-not-sent: id=%d: status is %s, not PENDING/AMBIGUOUS -- refusing to touch an already-resolved payout", *id, before.Status)
	}
	if before.TxHash != nil && *before.TxHash != "" {
		log.Printf("payout resolve-not-sent: id=%d: WARNING: this row records tx_hash=%s, which the engine captured from a Transfer call it observed SUCCEEDING (the bookkeeping write afterwards is what failed). "+
			"That is strong evidence the coin DID move. If so, `resolve-not-sent` will make those balances payable again and the pool will pay the same coin twice. "+
			"Verify that transaction on-chain and use `resolve-sent` instead unless you are certain it does not exist.",
			*id, *before.TxHash)
	}

	if !*yes {
		log.Printf("payout resolve-not-sent: id=%d: -yes not set, no change made. Would mark this payout FAILED (touching no balance row), which makes balance_ids=%v payable again on the next disbursement cycle, and record resolved_by=%q resolution_note=%q. Re-run with -yes to apply.",
			*id, before.BalanceIDs, *by, *reason)
		return fmt.Errorf("payout resolve-not-sent: id=%d: dry run only (pass -yes to apply)", *id)
	}

	if err := repo.ResolvePayoutNotSent(ctx, *id, *by, *reason); err != nil {
		return fmt.Errorf("payout resolve-not-sent: id=%d: %w", *id, err)
	}

	after, err := repo.GetPayoutByID(ctx, *id)
	if err != nil {
		log.Printf("payout resolve-not-sent: id=%d: resolution applied (status FAILED, balances untouched and now payable again), but re-reading the row to confirm failed: %v", *id, err)
		return nil
	}
	logPayoutRow("payout resolve-not-sent: after", after)
	log.Printf("payout resolve-not-sent: id=%d: resolved. status %s -> %s. No balance row was touched, so balance_ids=%v are payable again. "+
		"Restart the backend to resume disbursement for %s/%s.",
		*id, before.Status, after.Status, before.BalanceIDs, after.Algo, after.Network)
	return nil
}

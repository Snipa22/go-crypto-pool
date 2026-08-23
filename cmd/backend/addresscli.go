// Manual, ops-triggered "address" subcommands for the backend binary:
//
//	backend address ban              -address=<addr> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend address unban            -address=<addr> [-by=<operator>] [-dsn=...] -yes
//	backend address force-difficulty -address=<addr> -min-difficulty=<n> -reason=<text> [-by=<operator>] [-dsn=...] -yes
//	backend address clear-difficulty -address=<addr> [-by=<operator>] [-dsn=...] -yes
//	backend address show             -address=<addr> [-dsn=...]
//	backend address list             [-dsn=...]
//
// Both underlying controls (ban, forced minimum share difficulty) are
// CONFIRMED MANUAL / operator-flag-driven mechanisms -- there is no
// automated abuse/fraud detection anywhere in this codebase that sets
// either flag. An operator decides, off-platform (abuse report, TOS
// violation investigation, a miner who needs a fixed diff floor,
// whatever the real reason is), that a payment address should be
// banned or floored, and runs one of these subcommands to encode that
// decision. See internal/backend/db/addressflags.go and migrations/
// 0004_address_flags.up.sql for the full design rationale and the
// real enforcement point (Repository.InsertShare, called from every
// accepted share -- see internal/backend/api's handleShare and
// cmd/backend's repositoryAdapter.InsertShare for how a banned/under-
// floor share gets turned into an HTTP 403/409 instead of a DB
// insert).
//
// Mirrors blockcli.go/retentioncli.go's own conventions exactly:
// mutating subcommands (ban/unban/force-difficulty/clear-difficulty)
// require -yes to actually write anything -- without it, they print
// the address's current state and the change that WOULD be made and
// exit nonzero. show/list are read-only and never require -yes.
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

// addressCLITimeout mirrors blockCLITimeout -- generous for a manual,
// one-off ops invocation against a real Postgres instance, bounded so
// a hung connection doesn't leave an on-call operator's terminal
// stuck indefinitely. list's timeout is a little longer since it may
// scan more rows than a single-address lookup.
const (
	addressCLITimeout     = 30 * time.Second
	addressListCLITimeout = 60 * time.Second
)

// runAddressCommand dispatches `backend address <subcommand> ...`.
// args is os.Args with both "backend" and "address" already stripped
// off (i.e. args[0], if present, is the subcommand name).
func runAddressCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`address: missing subcommand, want "ban", "unban", "force-difficulty", "clear-difficulty", "show", or "list"`)
	}

	switch args[0] {
	case "ban":
		return runAddressBan(args[1:], true)
	case "unban":
		return runAddressBan(args[1:], false)
	case "force-difficulty":
		return runAddressDifficulty(args[1:], true)
	case "clear-difficulty":
		return runAddressDifficulty(args[1:], false)
	case "show":
		return runAddressShow(args[1:])
	case "list":
		return runAddressList(args[1:])
	default:
		return fmt.Errorf(`address: unrecognized subcommand %q, want "ban", "unban", "force-difficulty", "clear-difficulty", "show", or "list"`, args[0])
	}
}

// openAddressRepo is the shared "parse -dsn, connect, wrap in a
// *db.Repository" helper every address subcommand below needs,
// mirroring the inline connect logic blockcli.go/retentioncli.go each
// duplicate at their own single call site -- factored out here since
// this file has six subcommands doing the identical thing.
func openAddressRepo(ctx context.Context, dsn string) (*db.Repository, func(), error) {
	if dsn == "" {
		return nil, nil, errors.New("no DSN: pass -dsn or set GCPOOL_DB_DSN")
	}
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to database: %w", err)
	}
	return db.NewRepository(pool), pool.Close, nil
}

// logAddressFlag prints an address_flags row's current state in one
// consistent line, used by every subcommand below both before and
// (for mutating ones) after the write, mirroring blockcli.go's own
// before/after logging convention.
func logAddressFlag(prefix string, f db.AddressFlag) {
	banStr := "not banned"
	if f.Banned {
		reason := ""
		if f.BanReason != nil {
			reason = *f.BanReason
		}
		by := ""
		if f.BannedBy != nil {
			by = *f.BannedBy
		}
		banStr = fmt.Sprintf("BANNED (reason=%q by=%q)", reason, by)
	}
	diffStr := "no forced minimum difficulty"
	if f.ForcedMinDifficulty != nil {
		reason := ""
		if f.DifficultyReason != nil {
			reason = *f.DifficultyReason
		}
		by := ""
		if f.DifficultySetBy != nil {
			by = *f.DifficultySetBy
		}
		diffStr = fmt.Sprintf("forced_min_difficulty=%d (reason=%q by=%q)", *f.ForcedMinDifficulty, reason, by)
	}
	log.Printf("%s: address=%s: %s; %s", prefix, f.PaymentAddress, banStr, diffStr)
}

// runAddressBan implements both `address ban` and `address unban`.
func runAddressBan(args []string, wantBanned bool) error {
	op := "unban"
	if wantBanned {
		op = "ban"
	}
	fs := flag.NewFlagSet(fmt.Sprintf("backend address %s", op), flag.ContinueOnError)
	address := fs.String("address", "", "REQUIRED: the payment_address to "+op)
	reason := fs.String("reason", "", "human-readable reason for this action"+requiredSuffix(wantBanned))
	by := fs.String("by", "", "operator identifier recorded on this action (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the update. Without this flag, the address's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend address %s -address=<payment_address> %s[-by=<operator>] [-dsn=...] [-yes]\n\n", op, reasonUsageFragment(wantBanned))
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *address == "" {
		fs.Usage()
		return fmt.Errorf("address %s: -address is required", op)
	}
	if wantBanned && *reason == "" {
		fs.Usage()
		return fmt.Errorf("address %s: -reason is required -- a manual ban must record why (see addressflags.go's doc comment on why this is audit, not optional)", op)
	}

	ctx, cancel := context.WithTimeout(context.Background(), addressCLITimeout)
	defer cancel()

	repo, closeFn, err := openAddressRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("address %s: %w", op, err)
	}
	defer closeFn()

	before, err := repo.GetAddressFlag(ctx, *address)
	if err != nil {
		return fmt.Errorf("address %s: looking up %s: %w", op, *address, err)
	}
	logAddressFlag(fmt.Sprintf("address %s: before", op), before)

	if !*yes {
		log.Printf("address %s: -yes not set, no change made. Would set banned=%t (reason=%q by=%q). Re-run with -yes to apply.", op, wantBanned, *reason, *by)
		return fmt.Errorf("address %s: address=%s: dry run only (pass -yes to apply)", op, *address)
	}

	if err := repo.SetAddressBan(ctx, *address, wantBanned, *reason, *by); err != nil {
		return fmt.Errorf("address %s: address=%s: %w", op, *address, err)
	}

	after, err := repo.GetAddressFlag(ctx, *address)
	if err != nil {
		log.Printf("address %s: address=%s: update applied, but re-reading the row to confirm failed: %v", op, *address, err)
		return nil
	}
	logAddressFlag(fmt.Sprintf("address %s: after", op), after)
	return nil
}

// runAddressDifficulty implements both `address force-difficulty` and
// `address clear-difficulty`.
func runAddressDifficulty(args []string, forcing bool) error {
	op := "clear-difficulty"
	if forcing {
		op = "force-difficulty"
	}
	fs := flag.NewFlagSet(fmt.Sprintf("backend address %s", op), flag.ContinueOnError)
	address := fs.String("address", "", "REQUIRED: the payment_address to update")
	minDiff := fs.Int64("min-difficulty", 0, "REQUIRED for force-difficulty: the forced minimum share difficulty (must be > 0). Ignored for clear-difficulty.")
	reason := fs.String("reason", "", "human-readable reason for this action"+requiredSuffix(forcing))
	by := fs.String("by", "", "operator identifier recorded on this action (e.g. your name/handle)")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually perform the update. Without this flag, the address's current state and intended change are printed and nothing is written.")
	fs.Usage = func() {
		if forcing {
			fmt.Fprintf(fs.Output(), "Usage: backend address %s -address=<payment_address> -min-difficulty=<n> -reason=<text> [-by=<operator>] [-dsn=...] [-yes]\n\n", op)
		} else {
			fmt.Fprintf(fs.Output(), "Usage: backend address %s -address=<payment_address> [-by=<operator>] [-dsn=...] [-yes]\n\n", op)
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *address == "" {
		fs.Usage()
		return fmt.Errorf("address %s: -address is required", op)
	}
	var wantFloor int64
	if forcing {
		if *minDiff <= 0 {
			fs.Usage()
			return fmt.Errorf("address %s: -min-difficulty is required and must be > 0", op)
		}
		if *reason == "" {
			fs.Usage()
			return fmt.Errorf("address %s: -reason is required -- a manual difficulty floor must record why", op)
		}
		wantFloor = *minDiff
	} else {
		wantFloor = 0 // 0 is SetForcedMinDifficulty's "clear" sentinel.
	}

	ctx, cancel := context.WithTimeout(context.Background(), addressCLITimeout)
	defer cancel()

	repo, closeFn, err := openAddressRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("address %s: %w", op, err)
	}
	defer closeFn()

	before, err := repo.GetAddressFlag(ctx, *address)
	if err != nil {
		return fmt.Errorf("address %s: looking up %s: %w", op, *address, err)
	}
	logAddressFlag(fmt.Sprintf("address %s: before", op), before)

	if !*yes {
		if forcing {
			log.Printf("address %s: -yes not set, no change made. Would set forced_min_difficulty=%d (reason=%q by=%q). Re-run with -yes to apply.", op, wantFloor, *reason, *by)
		} else {
			log.Print("address force-difficulty: -yes not set, no change made. Would clear forced_min_difficulty. Re-run with -yes to apply.")
		}
		return fmt.Errorf("address %s: address=%s: dry run only (pass -yes to apply)", op, *address)
	}

	if err := repo.SetForcedMinDifficulty(ctx, *address, wantFloor, *reason, *by); err != nil {
		return fmt.Errorf("address %s: address=%s: %w", op, *address, err)
	}

	after, err := repo.GetAddressFlag(ctx, *address)
	if err != nil {
		log.Printf("address %s: address=%s: update applied, but re-reading the row to confirm failed: %v", op, *address, err)
		return nil
	}
	logAddressFlag(fmt.Sprintf("address %s: after", op), after)
	return nil
}

// runAddressShow implements the read-only `address show` subcommand
// -- prints one address's current ban/forced-difficulty state and
// returns nil (never requires -yes; it writes nothing).
func runAddressShow(args []string) error {
	fs := flag.NewFlagSet("backend address show", flag.ContinueOnError)
	address := fs.String("address", "", "REQUIRED: the payment_address to look up")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend address show -address=<payment_address> [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *address == "" {
		fs.Usage()
		return errors.New("address show: -address is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), addressCLITimeout)
	defer cancel()

	repo, closeFn, err := openAddressRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("address show: %w", err)
	}
	defer closeFn()

	f, err := repo.GetAddressFlag(ctx, *address)
	if err != nil {
		return fmt.Errorf("address show: %s: %w", *address, err)
	}
	logAddressFlag("address show", f)
	return nil
}

// runAddressList implements the read-only `address list` subcommand
// -- prints every currently-flagged (banned or forced-difficulty)
// address, one per line, oldest-alphabetical first (see
// Repository.ListAddressFlags). Never requires -yes.
func runAddressList(args []string) error {
	fs := flag.NewFlagSet("backend address list", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend address list [-dsn=...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), addressListCLITimeout)
	defer cancel()

	repo, closeFn, err := openAddressRepo(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("address list: %w", err)
	}
	defer closeFn()

	flags, err := repo.ListAddressFlags(ctx)
	if err != nil {
		return fmt.Errorf("address list: %w", err)
	}
	if len(flags) == 0 {
		log.Print("address list: no addresses are currently banned or difficulty-floored")
		return nil
	}
	for _, f := range flags {
		logAddressFlag("address list", f)
	}
	log.Printf("address list: %d flagged address(es)", len(flags))
	return nil
}

// requiredSuffix/reasonUsageFragment are tiny usage-text helpers so
// runAddressBan's single implementation can render slightly different
// -reason help/usage text for ban (required) vs. unban (optional)
// without duplicating the whole function.
func requiredSuffix(required bool) string {
	if required {
		return " (REQUIRED for ban)"
	}
	return " (optional for unban)"
}

func reasonUsageFragment(required bool) string {
	if required {
		return "-reason=<text> "
	}
	return "[-reason=<text>] "
}

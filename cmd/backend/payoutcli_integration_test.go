package main

// payoutcli_integration_test.go exercises the `backend payout ...`
// operator resolution flow end-to-end against a real Postgres
// instance, via the same runPayoutCommand entrypoint main() calls —
// not the repository methods directly. That matters here: the CLI
// carries its own safety guards (mandatory -yes / -reason, the
// already-resolved refusal, the tx-hash-mismatch refusal, the
// "no recorded entries" refusal) and those guards are as much a part
// of the double-payment fix as the SQL is.
//
// Same GCPOOL_TEST_DSN opt-in convention as
// internal/backend/db's integration tests: unset means skip, not
// fail.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

func payoutTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("GCPOOL_TEST_DSN")
	if dsn == "" {
		t.Skip("GCPOOL_TEST_DSN not set; skipping Postgres integration test")
	}
	return dsn
}

// payoutTestRepo opens the test database, resets the payout/balance
// tables this file touches, applies migrations, and returns a ready
// repository. It deliberately only truncates rather than dropping the
// whole schema: these tests only care about balance/payouts.
func payoutTestRepo(t *testing.T, dsn string) (*db.Repository, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE payouts, balance RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncating payouts/balance: %v", err)
	}
	return db.NewRepository(pool), ctx
}

// fabricateAmbiguousPayout sets up exactly the state the disbursement
// engine leaves behind on an ambiguous outcome: a credited balance,
// and an AMBIGUOUS payout row covering it with its per-entry debit
// detail recorded.
func fabricateAmbiguousPayout(t *testing.T, repo *db.Repository, ctx context.Context, address string, amount int64, txHash string) (payoutID, balanceID int64) {
	t.Helper()
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", address, nil, amount); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 1)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	for _, p := range payable {
		if p.PaymentAddress == address {
			balanceID = p.ID
		}
	}
	if balanceID == 0 {
		t.Fatalf("PayableBalances: no row for %s: %+v", address, payable)
	}
	payoutID, err = repo.RecordPendingPayout(ctx, "RXM", "TESTNET", "XMR",
		[]db.DisburseEntry{{BalanceID: balanceID, Amount: amount}}, amount)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, txHash, "transfer outcome ambiguous"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}
	return payoutID, balanceID
}

func balanceState(t *testing.T, repo *db.Repository, ctx context.Context, address string) (pending, paid int64) {
	t.Helper()
	rows, err := repo.MinerBalances(ctx, address, "RXM", "TESTNET", nil)
	if err != nil {
		t.Fatalf("MinerBalances(%s): %v", address, err)
	}
	if len(rows) != 1 {
		t.Fatalf("MinerBalances(%s): got %d rows, want 1", address, len(rows))
	}
	return rows[0].PendingBalance, rows[0].PaidBalance
}

func TestIntegrationPayoutCLIDispatchErrors(t *testing.T) {
	if err := runPayoutCommand(nil); err == nil {
		t.Error("runPayoutCommand(nil): want an error naming the available subcommands")
	}
	err := runPayoutCommand([]string{"resolve-everything"})
	if err == nil || !strings.Contains(err.Error(), "unrecognized subcommand") {
		t.Errorf("runPayoutCommand(bogus): got %v, want an unrecognized-subcommand error", err)
	}
}

// TestIntegrationPayoutCLIResolveSentRequiresConfirmationFlags proves
// the CLI refuses to debit real balances without the mandatory
// operator inputs, and that a dry run (no -yes) writes nothing.
func TestIntegrationPayoutCLIResolveSentRequiresConfirmationFlags(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)
	payoutID, _ := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "realhash")
	idArg := "-id=" + itoa(payoutID)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing id", []string{"resolve-sent", "-tx-hash=h", "-reason=r", "-dsn=" + dsn, "-yes"}, "-id is required"},
		{"missing tx-hash", []string{"resolve-sent", idArg, "-reason=r", "-dsn=" + dsn, "-yes"}, "-tx-hash is required"},
		{"missing reason", []string{"resolve-sent", idArg, "-tx-hash=realhash", "-dsn=" + dsn, "-yes"}, "-reason is required"},
		{"dry run without -yes", []string{"resolve-sent", idArg, "-tx-hash=realhash", "-reason=r", "-dsn=" + dsn}, "dry run only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runPayoutCommand(tc.args)
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got err=%v, want one containing %q", err, tc.want)
			}
		})
	}

	// Nothing above may have written anything.
	pending, paid := balanceState(t, repo, ctx, "alice")
	if pending != 500 || paid != 0 {
		t.Errorf("got pending=%d paid=%d, want 500/0 — refused/dry-run invocations must not write", pending, paid)
	}
	p, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if p.Status != db.PayoutStatusAmbiguous {
		t.Errorf("got status=%s, want the row left AMBIGUOUS", p.Status)
	}
}

// TestIntegrationPayoutCLIResolveSentAppliesExactDebit is the happy
// path for "the transfer DID broadcast": the CLI records it SENT and
// debits exactly the recorded amount, without re-sending anything.
func TestIntegrationPayoutCLIResolveSentAppliesExactDebit(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)
	payoutID, _ := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "realhash")

	if err := runPayoutCommand([]string{
		"resolve-sent", "-id=" + itoa(payoutID), "-tx-hash=realhash", "-fee=11",
		"-reason=confirmed on explorer", "-by=jane", "-dsn=" + dsn, "-yes",
	}); err != nil {
		t.Fatalf("resolve-sent: %v", err)
	}

	pending, paid := balanceState(t, repo, ctx, "alice")
	if pending != 0 || paid != 500 {
		t.Errorf("got pending=%d paid=%d, want 0/500", pending, paid)
	}
	p, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if p.Status != "SENT" {
		t.Errorf("got status=%s, want SENT", p.Status)
	}
	if rows, err := repo.UnresolvedPayouts(ctx, "RXM", "TESTNET", ""); err != nil || len(rows) != 0 {
		t.Errorf("UnresolvedPayouts: got %d rows err=%v, want 0 — disbursement must no longer be blocked", len(rows), err)
	}

	// Re-running must be refused, not silently double-debit.
	err = runPayoutCommand([]string{
		"resolve-sent", "-id=" + itoa(payoutID), "-tx-hash=realhash",
		"-reason=again", "-by=jane", "-dsn=" + dsn, "-yes",
	})
	if err == nil || !strings.Contains(err.Error(), "not PENDING/AMBIGUOUS") {
		t.Fatalf("second resolve-sent: got %v, want a refusal naming the already-resolved status", err)
	}
	pending, paid = balanceState(t, repo, ctx, "alice")
	if pending != 0 || paid != 500 {
		t.Errorf("got pending=%d paid=%d after a refused re-resolution, want still 0/500", pending, paid)
	}
}

// TestIntegrationPayoutCLIResolveSentRefusesTxHashMismatch proves the
// CLI will not let an operator overwrite the tx_hash the engine
// captured from a Transfer it observed succeeding — that hash is the
// strongest evidence available about where the coin went.
func TestIntegrationPayoutCLIResolveSentRefusesTxHashMismatch(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)
	payoutID, _ := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "enginehash")

	err := runPayoutCommand([]string{
		"resolve-sent", "-id=" + itoa(payoutID), "-tx-hash=someotherhash",
		"-reason=r", "-by=jane", "-dsn=" + dsn, "-yes",
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("got %v, want a refusal to overwrite the engine-recorded tx_hash", err)
	}
	pending, _ := balanceState(t, repo, ctx, "alice")
	if pending != 500 {
		t.Errorf("got pending=%d, want 500 — the refused resolution must not have debited", pending)
	}
}

// TestIntegrationPayoutCLIResolveNotSentReleasesBalance is the happy
// path for "the transfer did NOT broadcast": balances untouched, row
// FAILED, balance payable again for the next cycle.
func TestIntegrationPayoutCLIResolveNotSentReleasesBalance(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)
	payoutID, balanceID := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "")

	// Dry run first: must change nothing.
	if err := runPayoutCommand([]string{
		"resolve-not-sent", "-id=" + itoa(payoutID), "-reason=absent from wallet history", "-dsn=" + dsn,
	}); err == nil || !strings.Contains(err.Error(), "dry run only") {
		t.Fatalf("dry run: got %v, want a dry-run refusal", err)
	}
	if payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 1); err != nil || len(payable) != 0 {
		t.Fatalf("after dry run: got payable=%+v err=%v, want the balance still frozen", payable, err)
	}

	if err := runPayoutCommand([]string{
		"resolve-not-sent", "-id=" + itoa(payoutID),
		"-reason=absent from wallet history", "-by=jane", "-dsn=" + dsn, "-yes",
	}); err != nil {
		t.Fatalf("resolve-not-sent: %v", err)
	}

	pending, paid := balanceState(t, repo, ctx, "alice")
	if pending != 500 || paid != 0 {
		t.Errorf("got pending=%d paid=%d, want 500/0 — resolve-not-sent must not touch balances", pending, paid)
	}
	p, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if p.Status != "FAILED" {
		t.Errorf("got status=%s, want FAILED", p.Status)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", "XMR", 1)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 1 || payable[0].ID != balanceID {
		t.Fatalf("got payable=%+v, want the released balance payable again", payable)
	}
}

// TestIntegrationPayoutCLIResolveNotSentRequiresReason guards the
// single most dangerous command in the binary: making balances
// payable again on an operator's judgement call is a double payment
// if they are wrong, so the reason is mandatory, not advisory.
func TestIntegrationPayoutCLIResolveNotSentRequiresReason(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)
	payoutID, _ := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "")

	err := runPayoutCommand([]string{"resolve-not-sent", "-id=" + itoa(payoutID), "-dsn=" + dsn, "-yes"})
	if err == nil || !strings.Contains(err.Error(), "-reason is required") {
		t.Fatalf("got %v, want a -reason-is-required error", err)
	}
	p, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if p.Status != db.PayoutStatusAmbiguous {
		t.Errorf("got status=%s, want the row left AMBIGUOUS", p.Status)
	}
}

// TestIntegrationPayoutCLIReadOnlySubcommands covers list-unresolved
// and show: both must work without -yes and write nothing, and both
// must report a missing id/empty result usefully rather than crashing.
func TestIntegrationPayoutCLIReadOnlySubcommands(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := payoutTestRepo(t, dsn)

	// Empty case first.
	if err := runPayoutCommand([]string{"list-unresolved", "-dsn=" + dsn}); err != nil {
		t.Fatalf("list-unresolved (empty): %v", err)
	}
	if err := runPayoutCommand([]string{"show", "-id=999999", "-dsn=" + dsn}); err == nil ||
		!strings.Contains(err.Error(), "no payout with id") {
		t.Fatalf("show (missing): got %v, want a clear not-found error", err)
	}

	payoutID, _ := fabricateAmbiguousPayout(t, repo, ctx, "alice", 500, "realhash")

	for _, args := range [][]string{
		{"list-unresolved", "-dsn=" + dsn},
		{"list-unresolved", "-algo=RXM", "-network=TESTNET", "-dsn=" + dsn},
		{"show", "-id=" + itoa(payoutID), "-dsn=" + dsn},
	} {
		if err := runPayoutCommand(args); err != nil {
			t.Errorf("runPayoutCommand(%v): %v", args, err)
		}
	}

	// A read-only command must not have changed anything.
	pending, paid := balanceState(t, repo, ctx, "alice")
	if pending != 500 || paid != 0 {
		t.Errorf("got pending=%d paid=%d, want 500/0 — read-only subcommands must write nothing", pending, paid)
	}
	p, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if p.Status != db.PayoutStatusAmbiguous {
		t.Errorf("got status=%s, want AMBIGUOUS", p.Status)
	}

	// An invalid -algo must error rather than silently report "no
	// unresolved payouts" — a false all-clear here is exactly the
	// wrong answer for an operator checking whether it is safe.
	if err := runPayoutCommand([]string{"list-unresolved", "-algo=NOTANALGO", "-dsn=" + dsn}); err == nil {
		t.Error("list-unresolved -algo=NOTANALGO: want an error, not an empty all-clear")
	}
}

// itoa avoids importing strconv purely for test argument building.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

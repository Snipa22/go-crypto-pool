package main

// blockpayoutcli_integration_test.go exercises the `backend
// block-payout ...` operator resolution flow end-to-end against a real
// Postgres instance, via the same runBlockPayoutCommand entrypoint
// main() calls — not the repository methods directly. That matters
// here for the same reason it does in payoutcli_integration_test.go:
// the CLI carries its own safety guards (mandatory -yes / -reason, the
// not-PENDING refusal, the "never claimed" refusal) and those guards
// are as much a part of the double-credit fix as the SQL is.
//
// Same GCPOOL_TEST_DSN opt-in convention as
// internal/backend/db's integration tests: unset means skip, not
// fail.

import (
	"context"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// blockPayoutTestRepo opens the test database, applies migrations,
// and truncates only the tables this file touches (mirroring
// payoutTestRepo's deliberately narrow reset).
func blockPayoutTestRepo(t *testing.T, dsn string) (*db.Repository, context.Context) {
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
	if _, err := pool.Exec(ctx, "TRUNCATE block_payout_credits, block_payouts, payouts, balance, blocks RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncating block payout tables: %v", err)
	}
	return db.NewRepository(pool), ctx
}

// fabricateStuckBlockPayout sets up exactly the state that requires a
// human: a `blocks` row, a PENDING `block_payouts` claim over it, and
// (optionally) one already-landed credit itemised in the ledger with a
// matching real `balance` increment.
func fabricateStuckBlockPayout(t *testing.T, repo *db.Repository, ctx context.Context, dsn string, hash string, creditedAddress string, creditedAmount int64) int64 {
	t.Helper()
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer pool.Close()

	var blockID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO blocks (algo, network, pool_type, hash, height, difficulty, shares, block_timestamp, unlocked, valid, value)
		VALUES ('RXM', 'TESTNET', 'PPS', $1, 100, 1000, 10, 1700000000, FALSE, TRUE, 600000000000)
		RETURNING id`, hash).Scan(&blockID); err != nil {
		t.Fatalf("inserting the test block: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, blockID); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}
	if creditedAddress == "" {
		return blockID
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "XMR", creditedAddress, nil, creditedAmount); err != nil {
		t.Fatalf("crediting %s: %v", creditedAddress, err)
	}
	var balanceID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM balance WHERE payment_address = $1`, creditedAddress).Scan(&balanceID); err != nil {
		t.Fatalf("looking up %s's balance id: %v", creditedAddress, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payout_bucket, amount, currency)
		VALUES ($1, $2, $3, 'pps', $4, 'XMR')`, blockID, balanceID, creditedAddress, creditedAmount); err != nil {
		t.Fatalf("fabricating %s's credit ledger row: %v", creditedAddress, err)
	}
	return blockID
}

func TestIntegrationBlockPayoutCLIDispatchErrors(t *testing.T) {
	if err := runBlockPayoutCommand(nil); err == nil {
		t.Error("runBlockPayoutCommand(nil): want an error naming the available subcommands")
	}
	err := runBlockPayoutCommand([]string{"resolve-everything"})
	if err == nil || !strings.Contains(err.Error(), "unrecognized subcommand") {
		t.Errorf("runBlockPayoutCommand(bogus): got %v, want an unrecognized-subcommand error", err)
	}
}

// TestIntegrationBlockPayoutCLIResolveRequiresConfirmationFlags proves
// neither mutating subcommand will move a block's payout state without
// the mandatory -reason and -yes flags, and that a dry run really
// writes nothing.
func TestIntegrationBlockPayoutCLIResolveRequiresConfirmationFlags(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateStuckBlockPayout(t, repo, ctx, dsn, "hash-cli-flags", "alice", 58800)
	id := "-block-id=" + itoa64(blockID)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"credited: no -reason", []string{"resolve-credited", id, "-dsn=" + dsn, "-yes"}},
		{"credited: no -yes", []string{"resolve-credited", id, "-dsn=" + dsn, "-reason=checked"}},
		{"not-credited: no -reason", []string{"resolve-not-credited", id, "-dsn=" + dsn, "-yes"}},
		{"not-credited: no -yes", []string{"resolve-not-credited", id, "-dsn=" + dsn, "-reason=checked"}},
		{"credited: no -block-id", []string{"resolve-credited", "-dsn=" + dsn, "-reason=checked", "-yes"}},
	} {
		if err := runBlockPayoutCommand(tc.args); err == nil {
			t.Errorf("%s: got nil error, want a refusal", tc.name)
		}
	}

	// Nothing above may have changed the row or the balances.
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusPending {
		t.Fatalf("status = %q after only refused/dry-run invocations, want it still PENDING", row.Status)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after only refused/dry-run invocations, want it untouched at 58800", pending)
	}
	if ledger, err := repo.BlockPayoutCredits(ctx, blockID); err != nil || len(ledger) != 1 {
		t.Fatalf("BlockPayoutCredits = %+v (err=%v), want the single fabricated row untouched", ledger, err)
	}
}

// TestIntegrationBlockPayoutCLIResolveCreditedFlow walks the real
// operator path for "the recorded credits are the whole truth":
// list-unresolved finds it, show prints it, resolve-credited closes it
// APPLIED without re-crediting anyone, and a second resolution attempt
// is refused.
func TestIntegrationBlockPayoutCLIResolveCreditedFlow(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateStuckBlockPayout(t, repo, ctx, dsn, "hash-cli-credited", "alice", 58800)
	id := "-block-id=" + itoa64(blockID)

	if err := runBlockPayoutCommand([]string{"list-unresolved", "-dsn=" + dsn}); err != nil {
		t.Fatalf("list-unresolved: %v", err)
	}
	if err := runBlockPayoutCommand([]string{"show", id, "-dsn=" + dsn}); err != nil {
		t.Fatalf("show: %v", err)
	}

	if err := runBlockPayoutCommand([]string{
		"resolve-credited", id, "-dsn=" + dsn, "-reason=verified alice's balance matches the ledger", "-by=tester", "-yes",
	}); err != nil {
		t.Fatalf("resolve-credited: %v", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status = %q after resolve-credited, want APPLIED", row.Status)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "tester" {
		t.Fatalf("resolved_by = %v, want \"tester\"", row.ResolvedBy)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after resolve-credited, want it unchanged at 58800 (nobody is paid again)", pending)
	}
	if unresolved, err := repo.UnresolvedBlockPayouts(ctx, "", ""); err != nil || len(unresolved) != 0 {
		t.Fatalf("UnresolvedBlockPayouts = %+v (err=%v), want none after resolution", unresolved, err)
	}

	// Resolving again, either way, must be refused.
	err = runBlockPayoutCommand([]string{"resolve-credited", id, "-dsn=" + dsn, "-reason=again", "-yes"})
	if err == nil || !strings.Contains(err.Error(), "not PENDING") {
		t.Errorf("resolve-credited (twice): got %v, want a not-PENDING refusal", err)
	}
	err = runBlockPayoutCommand([]string{"resolve-not-credited", id, "-dsn=" + dsn, "-reason=again", "-yes"})
	if err == nil || !strings.Contains(err.Error(), "not PENDING") {
		t.Errorf("resolve-not-credited (on an APPLIED row): got %v, want a not-PENDING refusal", err)
	}
	// show still works on a resolved row, so an operator can confirm.
	if err := runBlockPayoutCommand([]string{"show", id, "-dsn=" + dsn}); err != nil {
		t.Fatalf("show (after resolution): %v", err)
	}
}

// TestIntegrationBlockPayoutCLIResolveNotCreditedFlow walks the real
// operator path for "nothing landed": resolve-not-credited flips the
// row FAILED, clears the voided ledger, touches no balance, and hands
// the block back to the automatic payout path.
func TestIntegrationBlockPayoutCLIResolveNotCreditedFlow(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateStuckBlockPayout(t, repo, ctx, dsn, "hash-cli-not-credited", "", 0)
	id := "-block-id=" + itoa64(blockID)

	if err := runBlockPayoutCommand([]string{
		"resolve-not-credited", id, "-dsn=" + dsn, "-reason=no balance row moved for any payee", "-by=tester", "-yes",
	}); err != nil {
		t.Fatalf("resolve-not-credited: %v", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusFailed {
		t.Fatalf("status = %q after resolve-not-credited, want FAILED", row.Status)
	}
	if row.ResolutionNote == nil || !strings.Contains(*row.ResolutionNote, "no balance row moved") {
		t.Fatalf("resolution_note = %v, want the operator's reason recorded", row.ResolutionNote)
	}

	// FAILED is re-claimable: the block really is back in the
	// automatic path.
	out, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID: blockID, Algo: "RXM", Network: "TESTNET", PoolType: "PPS", Height: 100, Reward: 600000000000,
		Credits: []db.BlockCredit{{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 58800}},
	})
	if err != nil {
		t.Fatalf("ApplyBlockPayout after resolve-not-credited: %v", err)
	}
	if out.AlreadyApplied {
		t.Fatal("ApplyBlockPayout after resolve-not-credited: got AlreadyApplied=true, want a real run")
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after the re-run, want 58800", pending)
	}
}

// TestIntegrationBlockPayoutCLIUnclaimedBlockIsRefused confirms every
// subcommand distinguishes "this block's payout has never been
// claimed" (nothing is stuck, nothing to resolve) from a real failure.
func TestIntegrationBlockPayoutCLIUnclaimedBlockIsRefused(t *testing.T) {
	dsn := payoutTestDSN(t)
	_, _ = blockPayoutTestRepo(t, dsn)

	for _, args := range [][]string{
		{"show", "-block-id=999999", "-dsn=" + dsn},
		{"resolve-credited", "-block-id=999999", "-dsn=" + dsn, "-reason=x", "-yes"},
		{"resolve-not-credited", "-block-id=999999", "-dsn=" + dsn, "-reason=x", "-yes"},
	} {
		err := runBlockPayoutCommand(args)
		if err == nil || !strings.Contains(err.Error(), "has ever been claimed") {
			t.Errorf("%v: got %v, want a \"no payout run has ever been claimed\" refusal", args, err)
		}
	}
}

// itoa64 keeps these tests free of a strconv import purely for flag
// string building, matching the hand-rolled helper style in
// internal/backend/payout's tests.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// fabricateAppliedOrphanedBlockPayout sets up the state
// `reverse-credits` exists for: a `blocks` row whose payout run
// REALLY applied (via the real ApplyBlockPayout transaction, so the
// balance/ledger rows are exactly what the engine itself would leave
// behind), which has SINCE been found orphaned -- blocks.valid =
// FALSE, via the exact SetBlockStatus write the unlocker's real
// checkBlock performs on a genuine reorg-past-maturity orphan (see
// internal/backend/unlocker/unlocker.go's checkBlock).
func fabricateAppliedOrphanedBlockPayout(t *testing.T, repo *db.Repository, ctx context.Context, dsn, hash, creditedAddress string, creditedAmount int64) int64 {
	t.Helper()
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer pool.Close()

	var blockID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO blocks (algo, network, pool_type, hash, height, difficulty, shares, block_timestamp, unlocked, valid, value)
		VALUES ('RXM', 'TESTNET', 'PPS', $1, 100, 1000, 10, 1700000000, FALSE, TRUE, 600000000000)
		RETURNING id`, hash).Scan(&blockID); err != nil {
		t.Fatalf("inserting the test block: %v", err)
	}

	if _, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID: blockID, Algo: "RXM", Network: "TESTNET", PoolType: "PPS", Height: 100, Reward: 600000000000,
		Credits: []db.BlockCredit{{PayoutBucket: "pps", PaymentAddress: creditedAddress, Amount: creditedAmount}},
	}); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}

	// The real unlocker orphan write: valid=FALSE, unlocked=TRUE.
	if err := repo.SetBlockStatus(ctx, blockID, false, true); err != nil {
		t.Fatalf("SetBlockStatus (orphaning): %v", err)
	}
	return blockID
}

// TestIntegrationBlockPayoutCLIReverseCreditsRequiresConfirmationFlags
// proves the `reverse-credits` subcommand never writes anything
// without -reason and -yes, exactly like the two resolve-*
// subcommands, and that its dry run (bare -block-id + -reason,
// without -yes) really writes nothing either.
func TestIntegrationBlockPayoutCLIReverseCreditsRequiresConfirmationFlags(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateAppliedOrphanedBlockPayout(t, repo, ctx, dsn, "hash-reverse-cli-flags", "alice", 58800)
	id := "-block-id=" + itoa64(blockID)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no -reason", []string{"reverse-credits", id, "-dsn=" + dsn, "-yes"}},
		{"no -yes (dry run)", []string{"reverse-credits", id, "-dsn=" + dsn, "-reason=confirmed orphaned"}},
		{"no -block-id", []string{"reverse-credits", "-dsn=" + dsn, "-reason=confirmed orphaned", "-yes"}},
	} {
		if err := runBlockPayoutCommand(tc.args); err == nil {
			t.Errorf("%s: got nil error, want a refusal", tc.name)
		}
	}

	// Nothing above may have changed the row or the balances.
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status = %q after only refused/dry-run invocations, want it still APPLIED", row.Status)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after only refused/dry-run invocations, want it untouched at 58800", pending)
	}
	if ledger, err := repo.BlockPayoutCredits(ctx, blockID); err != nil || len(ledger) != 1 || ledger[0].ReversedAt != nil {
		t.Fatalf("BlockPayoutCredits = %+v (err=%v), want the single fabricated row untouched (reversed_at nil)", ledger, err)
	}
}

// TestIntegrationBlockPayoutCLIReverseCreditsRefusesStillValidBlock
// proves the CLI surfaces the real "still valid" precondition
// failure for a block that has NOT been found orphaned/invalid, even
// with -yes and a -reason -- the CLI must not be a way around the
// real db.Repository.ReverseBlockPayoutCredits precondition.
func TestIntegrationBlockPayoutCLIReverseCreditsRefusesStillValidBlock(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)

	// A block whose payout applied but whose blocks row is STILL
	// valid=TRUE (no orphan write has ever happened to it).
	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer pool.Close()
	var blockID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO blocks (algo, network, pool_type, hash, height, difficulty, shares, block_timestamp, unlocked, valid, value)
		VALUES ('RXM', 'TESTNET', 'PPS', 'hash-reverse-cli-still-valid', 100, 1000, 10, 1700000000, FALSE, TRUE, 600000000000)
		RETURNING id`).Scan(&blockID); err != nil {
		t.Fatalf("inserting the test block: %v", err)
	}
	if _, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID: blockID, Algo: "RXM", Network: "TESTNET", PoolType: "PPS", Height: 100, Reward: 600000000000,
		Credits: []db.BlockCredit{{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 58800}},
	}); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}
	id := "-block-id=" + itoa64(blockID)

	err = runBlockPayoutCommand([]string{"reverse-credits", id, "-dsn=" + dsn, "-reason=trying anyway", "-yes"})
	if err == nil || !strings.Contains(err.Error(), "still valid") && !strings.Contains(err.Error(), "blocks.valid") {
		t.Errorf("reverse-credits (still-valid block): got %v, want a refusal mentioning the block still being valid", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status = %q after a refused reverse-credits, want it still APPLIED", row.Status)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after a refused reverse-credits, want it untouched at 58800", pending)
	}
}

// TestIntegrationBlockPayoutCLIReverseCreditsFlow walks the real
// operator path end-to-end: an APPLIED block is found orphaned, the
// dry run shows what WOULD be debited without writing anything,
// -yes performs the real reversal (debiting exactly the recorded
// credit and flipping the row to REVERSED), and a SECOND -yes
// invocation against the now-REVERSED block is a safe, explicit
// no-op that makes no further writes.
func TestIntegrationBlockPayoutCLIReverseCreditsFlow(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateAppliedOrphanedBlockPayout(t, repo, ctx, dsn, "hash-reverse-cli-flow", "alice", 58800)
	id := "-block-id=" + itoa64(blockID)

	// Dry run: must write nothing.
	if err := runBlockPayoutCommand([]string{"reverse-credits", id, "-dsn=" + dsn, "-reason=confirmed orphaned via chain re-verification"}); err == nil {
		t.Fatal("reverse-credits (dry run): got nil error, want the dry-run-only refusal")
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 58800 {
		t.Fatalf("alice's pending_balance = %d after the dry run, want it untouched at 58800", pending)
	}
	if row, err := repo.GetBlockPayout(ctx, blockID); err != nil || row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status after dry run = %+v (err=%v), want still APPLIED", row, err)
	}

	// Real reversal.
	if err := runBlockPayoutCommand([]string{
		"reverse-credits", id, "-dsn=" + dsn, "-reason=confirmed orphaned via chain re-verification", "-by=tester", "-yes",
	}); err != nil {
		t.Fatalf("reverse-credits: %v", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusReversed {
		t.Fatalf("status = %q after reverse-credits, want REVERSED", row.Status)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "tester" {
		t.Fatalf("resolved_by = %v, want \"tester\"", row.ResolvedBy)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 0 {
		t.Fatalf("alice's pending_balance = %d after reverse-credits, want it debited back to 0", pending)
	}
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	if len(ledger) != 1 || ledger[0].ReversedAt == nil {
		t.Fatalf("BlockPayoutCredits = %+v, want exactly one row with reversed_at set", ledger)
	}

	// A second -yes invocation against the now-REVERSED block must
	// be a safe, explicit no-op: no error, no further debit.
	if err := runBlockPayoutCommand([]string{
		"reverse-credits", id, "-dsn=" + dsn, "-reason=trying again", "-by=tester2", "-yes",
	}); err != nil {
		t.Fatalf("reverse-credits (second attempt on an already-REVERSED block): got an error, want a clean no-op: %v", err)
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 0 {
		t.Fatalf("alice's pending_balance = %d after a second reverse-credits attempt, want it still 0 (no double-debit)", pending)
	}
	rowAfterSecond, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout (after second attempt): %v", err)
	}
	if rowAfterSecond.Status != db.BlockPayoutStatusReversed {
		t.Fatalf("status = %q after a second reverse-credits attempt, want it still REVERSED", rowAfterSecond.Status)
	}
	if rowAfterSecond.ResolvedBy == nil || *rowAfterSecond.ResolvedBy != "tester" {
		t.Fatalf("resolved_by = %v after a no-op second attempt, want it still \"tester\" (the no-op must not overwrite the original audit trail)", rowAfterSecond.ResolvedBy)
	}

	// A REVERSED block must be permanently non-payable via the
	// normal automatic path too.
	out, err := repo.ApplyBlockPayout(ctx, db.BlockPayoutRun{
		BlockID: blockID, Algo: "RXM", Network: "TESTNET", PoolType: "PPS", Height: 100, Reward: 600000000000,
		Credits: []db.BlockCredit{{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 58800}},
	})
	if err != nil {
		t.Fatalf("ApplyBlockPayout after reverse-credits: got an error, want a clean no-op: %v", err)
	}
	if !out.AlreadyApplied {
		t.Fatal("ApplyBlockPayout after reverse-credits: got AlreadyApplied=false, want true -- a REVERSED block must never be re-payable")
	}
	if pending, _ := balanceState(t, repo, ctx, "alice"); pending != 0 {
		t.Fatalf("alice's pending_balance = %d after a post-reversal ApplyBlockPayout attempt, want it still 0", pending)
	}
}

// TestIntegrationBlockPayoutCLIReverseCreditsRefusesUnappliedStatuses
// proves the CLI surfaces a clear, specific refusal for a PENDING
// row (rather than attempting a reversal it cannot support), instead
// of a generic/confusing error.
func TestIntegrationBlockPayoutCLIReverseCreditsRefusesUnappliedStatuses(t *testing.T) {
	dsn := payoutTestDSN(t)
	repo, ctx := blockPayoutTestRepo(t, dsn)
	blockID := fabricateStuckBlockPayout(t, repo, ctx, dsn, "hash-reverse-cli-pending", "alice", 58800)
	id := "-block-id=" + itoa64(blockID)

	err := runBlockPayoutCommand([]string{"reverse-credits", id, "-dsn=" + dsn, "-reason=trying anyway", "-yes"})
	if err == nil || !strings.Contains(err.Error(), "not APPLIED") {
		t.Errorf("reverse-credits (PENDING row): got %v, want a \"not APPLIED\" refusal", err)
	}

	// And a never-claimed block is refused with the same "nothing to
	// reverse" style message the other subcommands use for the same
	// underlying condition.
	err = runBlockPayoutCommand([]string{"reverse-credits", "-block-id=999999", "-dsn=" + dsn, "-reason=x", "-yes"})
	if err == nil || !strings.Contains(err.Error(), "nothing to reverse") {
		t.Errorf("reverse-credits (unclaimed block): got %v, want a \"nothing to reverse\" refusal", err)
	}
}

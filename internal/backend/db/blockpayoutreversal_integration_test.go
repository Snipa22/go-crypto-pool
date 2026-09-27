package db_test

// Integration tests for the block-payout credit REVERSAL path
// (migrations/0014_block_payout_reversal.up.sql,
// internal/backend/db/blockpayout.go's ReverseBlockPayoutCredits)
// against a REAL Postgres instance. Set GCPOOL_TEST_DSN to run them --
// see integration_test.go's package doc comment for the exact setup.
//
// Mirrors blockpayout_integration_test.go's conventions exactly (same
// testPool/resetSchema helpers, same insertTestBlock/pendingBalances
// fixtures) for the same reason that file gives for being
// integration-only rather than mock-based: every property asserted
// here IS a database property -- transaction atomicity, a FOR UPDATE
// row lock serializing against a concurrent SetBlockStatus, and the
// balance_pending_balance_nonnegative CHECK constraint (migration
// 0011) actually firing. A mock would prove nothing about any of
// that.

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// TestIntegrationReverseBlockPayoutCreditsRefusesStillValidBlock is
// requirement #1 from the task brief: a block that is still
// blocks.valid = TRUE (i.e. has NOT been found orphaned/invalid) must
// never have its payout reversed, no matter how APPLIED its payout
// run is. This is the precondition the entire feature exists to
// enforce -- get it wrong and this feature becomes a way to debit any
// miner's balance on a whim.
func TestIntegrationReverseBlockPayoutCreditsRefusesStillValidBlock(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// blocks.valid = TRUE (insertTestBlock's default) -- a normal,
	// still-live block whose payout genuinely applied.
	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-still-valid")
	credits := testRunCredits()
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, credits)); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}

	before := pendingBalances(t, pool, "RXM", "TESTNET")
	beforeRow, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}

	// THE POINT: reversal must be refused, loudly, because
	// blocks.valid is still TRUE.
	_, err = repo.ReverseBlockPayoutCredits(ctx, blockID, "operator-1", "attempting reversal on a still-valid block")
	if err == nil {
		t.Fatal("ReverseBlockPayoutCredits: got nil error for a still-valid block, want a hard refusal")
	}
	if !errors.Is(err, db.ErrBlockStillValid) {
		t.Fatalf("ReverseBlockPayoutCredits: got err=%v, want it to wrap db.ErrBlockStillValid", err)
	}

	// block_payouts.status must be UNCHANGED (still APPLIED).
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout (after refused reversal): %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("block_payouts status = %q after a refused reversal, want it still APPLIED", row.Status)
	}
	if row.Credited == nil || *row.Credited != *beforeRow.Credited || row.TotalPaid == nil || *row.TotalPaid != *beforeRow.TotalPaid {
		t.Fatalf("block_payouts credited/total_paid changed after a refused reversal: before=%v/%v after=%v/%v", beforeRow.Credited, beforeRow.TotalPaid, row.Credited, row.TotalPaid)
	}

	// EVERY balance.pending_balance row must be UNCHANGED -- no debit
	// happened at all.
	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("BALANCES CHANGED on a refused (still-valid) reversal: before=%+v after=%+v", before, after)
	}

	// The credit ledger itself must show no reversed_at markers.
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	for _, c := range ledger {
		if c.ReversedAt != nil {
			t.Fatalf("BlockPayoutCredits: balance_id=%d has reversed_at=%v set after a refused reversal, want nil", c.BalanceID, c.ReversedAt)
		}
	}
}

// TestIntegrationReverseBlockPayoutCreditsDebitsExactlyOnce is
// requirement #2: an orphaned APPLIED block's credits are reversed
// exactly once, debiting EXACTLY the amount block_payout_credits
// recorded for THIS block -- never a miner's whole balance, and never
// touching what a SECOND, unrelated block legitimately credited that
// same payee. This is the headline correctness property of the whole
// feature.
func TestIntegrationReverseBlockPayoutCreditsDebitsExactlyOnce(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Block A: the bad block whose payout will be reversed.
	blockA := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-a")
	creditsA := testRunCredits() // alice=58800, fee-addr=1700, coindev-addr=200, zero-seed-addr=0
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockA, creditsA)); err != nil {
		t.Fatalf("ApplyBlockPayout (block A): %v", err)
	}

	// Block B: a SECOND, unrelated block that ALSO legitimately
	// credits alice -- proving reversing block A must not touch what
	// block B credited her.
	blockB := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-b")
	creditsB := []db.BlockCredit{
		{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 12345},
	}
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockB, creditsB)); err != nil {
		t.Fatalf("ApplyBlockPayout (block B): %v", err)
	}

	// alice's balance is now the SUM of both blocks' credits.
	beforeReversal := pendingBalances(t, pool, "RXM", "TESTNET")
	if beforeReversal["alice"] != 58800+12345 {
		t.Fatalf("alice's pending_balance before reversal = %d, want %d (both blocks' credits)", beforeReversal["alice"], 58800+12345)
	}

	// Now discover block A is orphaned: flip blocks.valid = FALSE,
	// exactly the write the unlocker's real checkBlock performs on a
	// genuine reorg-past-maturity orphan (SetBlockStatus(id, false,
	// true) -- see internal/backend/unlocker/unlocker.go's checkBlock).
	if err := repo.SetBlockStatus(ctx, blockA, false, true); err != nil {
		t.Fatalf("SetBlockStatus (orphaning block A): %v", err)
	}

	outcome, err := repo.ReverseBlockPayoutCredits(ctx, blockA, "operator-1", "confirmed orphaned via unlocker chain re-verification")
	if err != nil {
		t.Fatalf("ReverseBlockPayoutCredits: %v", err)
	}
	if outcome.AlreadyReversed {
		t.Fatal("ReverseBlockPayoutCredits: got AlreadyReversed=true on the first real reversal, want false")
	}
	wantTotalA := int64(58800 + 1700 + 200) // zero-seed-addr contributes 0
	if outcome.TotalReversed != wantTotalA {
		t.Fatalf("ReverseBlockPayoutCredits: TotalReversed=%d, want %d (exactly block A's own credits)", outcome.TotalReversed, wantTotalA)
	}
	if outcome.CreditsReversed != len(creditsA) {
		t.Fatalf("ReverseBlockPayoutCredits: CreditsReversed=%d, want %d (one per block A credit entry, including the zero-amount seed)", outcome.CreditsReversed, len(creditsA))
	}

	// THE POINT: every affected balance.pending_balance row decreased
	// by EXACTLY what block A's own ledger recorded for it -- alice's
	// balance must now be ONLY block B's 12345, not zero, and not
	// block B's amount minus anything extra.
	after := pendingBalances(t, pool, "RXM", "TESTNET")
	if after["alice"] != 12345 {
		t.Fatalf("alice's pending_balance after reversing block A = %d, want exactly 12345 (block B's untouched credit) -- reversing block A must not touch block B's legitimate credit to the same payee", after["alice"])
	}
	if after["fee-addr"] != 0 {
		t.Fatalf("fee-addr's pending_balance after reversal = %d, want 0 (block A's only credit to fee-addr, fully reversed)", after["fee-addr"])
	}
	if after["coindev-addr"] != 0 {
		t.Fatalf("coindev-addr's pending_balance after reversal = %d, want 0", after["coindev-addr"])
	}
	if _, ok := after["zero-seed-addr"]; !ok {
		t.Fatalf("zero-seed-addr's balance row is gone after reversal, want it to still exist (at 0)")
	}
	if after["zero-seed-addr"] != 0 {
		t.Fatalf("zero-seed-addr's pending_balance after reversal = %d, want 0", after["zero-seed-addr"])
	}

	// block_payouts.status == 'REVERSED'.
	row, err := repo.GetBlockPayout(ctx, blockA)
	if err != nil {
		t.Fatalf("GetBlockPayout (block A): %v", err)
	}
	if row.Status != db.BlockPayoutStatusReversed {
		t.Fatalf("block_payouts status = %q after reversal, want REVERSED", row.Status)
	}
	if row.Credited == nil || *row.Credited != outcome.CreditsReversed {
		t.Fatalf("block_payouts.credited = %v after reversal, want %d (reused for the reversal's own totals)", row.Credited, outcome.CreditsReversed)
	}
	if row.TotalPaid == nil || *row.TotalPaid != outcome.TotalReversed {
		t.Fatalf("block_payouts.total_paid = %v after reversal, want %d (reused for the reversal's own totals)", row.TotalPaid, outcome.TotalReversed)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "operator-1" {
		t.Fatalf("block_payouts.resolved_by = %v, want \"operator-1\"", row.ResolvedBy)
	}
	if row.ResolutionNote == nil || *row.ResolutionNote == "" {
		t.Fatalf("block_payouts.resolution_note = %v, want the operator's reason recorded", row.ResolutionNote)
	}

	// Block B must be entirely untouched by any of this.
	rowB, err := repo.GetBlockPayout(ctx, blockB)
	if err != nil {
		t.Fatalf("GetBlockPayout (block B): %v", err)
	}
	if rowB.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("block B's block_payouts status = %q after reversing block A, want it still APPLIED", rowB.Status)
	}

	// The per-credit ledger for block A must show reversed_at set on
	// every row; block B's ledger must show it NOT set on any row.
	ledgerA, err := repo.BlockPayoutCredits(ctx, blockA)
	if err != nil {
		t.Fatalf("BlockPayoutCredits (block A): %v", err)
	}
	if len(ledgerA) != len(creditsA) {
		t.Fatalf("BlockPayoutCredits (block A) has %d row(s), want %d", len(ledgerA), len(creditsA))
	}
	for _, c := range ledgerA {
		if c.ReversedAt == nil {
			t.Errorf("BlockPayoutCredits (block A): balance_id=%d has reversed_at=nil after reversal, want it set", c.BalanceID)
		}
	}
	ledgerB, err := repo.BlockPayoutCredits(ctx, blockB)
	if err != nil {
		t.Fatalf("BlockPayoutCredits (block B): %v", err)
	}
	for _, c := range ledgerB {
		if c.ReversedAt != nil {
			t.Errorf("BlockPayoutCredits (block B): balance_id=%d has reversed_at=%v set, want nil -- reversing block A must not touch block B's ledger rows", c.BalanceID, c.ReversedAt)
		}
	}

	// A REVERSED block must be permanently non-payable: ApplyBlockPayout
	// must treat it exactly like APPLIED -- a safe no-op that credits
	// nothing and does NOT reset the row back to PENDING/re-run the
	// payout.
	applyOut, err := repo.ApplyBlockPayout(ctx, testRun(blockA, creditsA))
	if err != nil {
		t.Fatalf("ApplyBlockPayout after reversal: got an error, want a clean no-op: %v", err)
	}
	if !applyOut.AlreadyApplied {
		t.Fatal("ApplyBlockPayout after reversal: got AlreadyApplied=false, want true -- a REVERSED block must never be re-payable")
	}
	if finalBal := pendingBalances(t, pool, "RXM", "TESTNET"); finalBal["alice"] != 12345 {
		t.Fatalf("alice's pending_balance after a post-reversal ApplyBlockPayout attempt = %d, want it still exactly 12345 -- a REVERSED block must never be re-credited", finalBal["alice"])
	}
	rowAfterApply, err := repo.GetBlockPayout(ctx, blockA)
	if err != nil {
		t.Fatalf("GetBlockPayout (block A, after post-reversal ApplyBlockPayout attempt): %v", err)
	}
	if rowAfterApply.Status != db.BlockPayoutStatusReversed {
		t.Fatalf("block_payouts status = %q after a post-reversal ApplyBlockPayout attempt, want it to STAY REVERSED (never reset to PENDING/APPLIED)", rowAfterApply.Status)
	}
}

// TestIntegrationReverseBlockPayoutCreditsSecondAttemptIsSafeNoOp is
// requirement #3, and the single most important test in this file: a
// second reversal attempt against an already-REVERSED block must be
// a safe no-op, not a double-debit. Reversing twice must debit
// EXACTLY once, ever.
func TestIntegrationReverseBlockPayoutCreditsSecondAttemptIsSafeNoOp(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-double-reversal")
	credits := testRunCredits()
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, credits)); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}
	if err := repo.SetBlockStatus(ctx, blockID, false, true); err != nil {
		t.Fatalf("SetBlockStatus (orphaning): %v", err)
	}

	first, err := repo.ReverseBlockPayoutCredits(ctx, blockID, "operator-1", "first reversal")
	if err != nil {
		t.Fatalf("ReverseBlockPayoutCredits (first): %v", err)
	}
	if first.AlreadyReversed {
		t.Fatal("ReverseBlockPayoutCredits (first): got AlreadyReversed=true on the first real reversal, want false")
	}

	afterFirst := pendingBalances(t, pool, "RXM", "TESTNET")
	ledgerAfterFirst, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits (after first reversal): %v", err)
	}

	// THE POINT: call it again for the same already-REVERSED block.
	second, err := repo.ReverseBlockPayoutCredits(ctx, blockID, "operator-2", "second attempt, should be a no-op")
	if err != nil {
		t.Fatalf("ReverseBlockPayoutCredits (second): got an error, want a clean no-op: %v", err)
	}
	if !second.AlreadyReversed {
		t.Fatal("ReverseBlockPayoutCredits (second): got AlreadyReversed=false, want true")
	}
	if second.TotalReversed != first.TotalReversed || second.CreditsReversed != first.CreditsReversed {
		t.Fatalf("ReverseBlockPayoutCredits (second): got %+v, want the ORIGINAL reversal's recorded totals %+v", second, first)
	}

	// balance.pending_balance UNCHANGED from after the first reversal
	// -- the critical assertion, proving no second debit.
	afterSecond := pendingBalances(t, pool, "RXM", "TESTNET")
	if !sameBalances(afterFirst, afterSecond) {
		t.Fatalf("BALANCES CHANGED on a second reversal attempt: after_first=%+v after_second=%+v -- this is the double-debit bug", afterFirst, afterSecond)
	}

	// block_payouts.status still 'REVERSED', and NOT overwritten with
	// operator-2's resolved_by/resolution_note (the no-op must not
	// write anything at all).
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusReversed {
		t.Fatalf("block_payouts status = %q after the second reversal attempt, want it still REVERSED", row.Status)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "operator-1" {
		t.Fatalf("block_payouts.resolved_by = %v after a no-op second attempt, want it still \"operator-1\" (the second attempt must not overwrite the original audit trail)", row.ResolvedBy)
	}

	// The credit ledger's reversed_at values must be untouched too
	// (not re-stamped with a later timestamp).
	ledgerAfterSecond, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits (after second reversal attempt): %v", err)
	}
	if len(ledgerAfterSecond) != len(ledgerAfterFirst) {
		t.Fatalf("BlockPayoutCredits row count changed from %d to %d on a no-op second attempt", len(ledgerAfterFirst), len(ledgerAfterSecond))
	}
	byBalance := map[int64]*db.BlockPayoutCredit{}
	for i := range ledgerAfterFirst {
		byBalance[ledgerAfterFirst[i].BalanceID] = &ledgerAfterFirst[i]
	}
	for _, c := range ledgerAfterSecond {
		want, ok := byBalance[c.BalanceID]
		if !ok {
			t.Fatalf("BlockPayoutCredits (after second attempt): unexpected balance_id=%d not present after the first reversal", c.BalanceID)
		}
		if c.ReversedAt == nil || want.ReversedAt == nil || !c.ReversedAt.Equal(*want.ReversedAt) {
			t.Errorf("BlockPayoutCredits (after second attempt): balance_id=%d reversed_at changed from %v to %v -- a no-op must not re-stamp it", c.BalanceID, want.ReversedAt, c.ReversedAt)
		}
	}

	// A THIRD attempt, for good measure, must also stay a no-op.
	third, err := repo.ReverseBlockPayoutCredits(ctx, blockID, "operator-3", "third attempt")
	if err != nil {
		t.Fatalf("ReverseBlockPayoutCredits (third): %v", err)
	}
	if !third.AlreadyReversed {
		t.Fatal("ReverseBlockPayoutCredits (third): got AlreadyReversed=false, want true")
	}
	if afterThird := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(afterFirst, afterThird) {
		t.Fatalf("BALANCES CHANGED on a third reversal attempt: after_first=%+v after_third=%+v", afterFirst, afterThird)
	}
}

// TestIntegrationReverseBlockPayoutCreditsRefusesNonAppliedStatuses
// covers the other two branches of the precondition: a PENDING row
// (needs resolve-credited/resolve-not-credited first) and a FAILED
// row (already credited nobody) must both be refused with
// ErrBlockPayoutNotApplied, and a never-claimed block must be refused
// with ErrBlockPayoutNotFound -- none of these should ever reach the
// debit logic at all.
func TestIntegrationReverseBlockPayoutCreditsRefusesNonAppliedStatuses(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Never claimed at all.
	unclaimed := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-unclaimed")
	if _, err := repo.ReverseBlockPayoutCredits(ctx, unclaimed, "op", "why"); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Errorf("ReverseBlockPayoutCredits (unclaimed): got err=%v, want ErrBlockPayoutNotFound", err)
	}

	// PENDING: fabricate a claimed-but-unresolved run (mirrors
	// blockpayout_integration_test.go's own fabrication style).
	pendingBlock := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-pending")
	if err := repo.SetBlockStatus(ctx, pendingBlock, false, true); err != nil {
		t.Fatalf("SetBlockStatus (pendingBlock): %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, pendingBlock); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}
	if _, err := repo.ReverseBlockPayoutCredits(ctx, pendingBlock, "op", "why"); !errors.Is(err, db.ErrBlockPayoutNotApplied) {
		t.Errorf("ReverseBlockPayoutCredits (PENDING): got err=%v, want ErrBlockPayoutNotApplied", err)
	}

	// FAILED: resolve-not-credited a PENDING row into FAILED first.
	failedBlock := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-failed")
	if err := repo.SetBlockStatus(ctx, failedBlock, false, true); err != nil {
		t.Fatalf("SetBlockStatus (failedBlock): %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, failedBlock); err != nil {
		t.Fatalf("fabricating the PENDING claim row (failedBlock): %v", err)
	}
	if err := repo.ResolveBlockPayoutNotCredited(ctx, failedBlock, "op", "nothing landed"); err != nil {
		t.Fatalf("ResolveBlockPayoutNotCredited (failedBlock): %v", err)
	}
	if _, err := repo.ReverseBlockPayoutCredits(ctx, failedBlock, "op", "why"); !errors.Is(err, db.ErrBlockPayoutNotApplied) {
		t.Errorf("ReverseBlockPayoutCredits (FAILED): got err=%v, want ErrBlockPayoutNotApplied", err)
	}

	// A bad blockID (<= 0) is refused as a caller error, same as
	// ApplyBlockPayout's own guard.
	if _, err := repo.ReverseBlockPayoutCredits(ctx, 0, "op", "why"); err == nil {
		t.Error("ReverseBlockPayoutCredits(blockID=0): got nil error, want a refusal")
	}
}

// TestIntegrationReverseBlockPayoutCreditsRejectsNegativeBalance
// covers the documented edge case from migration 0014's doc comment:
// if a debit would drive balance.pending_balance negative (most
// plausibly because a real disbursement already spent some of the
// bad credit), the balance_pending_balance_nonnegative CHECK
// constraint (migration 0011) must reject the WHOLE reversal
// transaction -- no partial debit, no status flip to REVERSED, and
// no other balance in the same run touched either.
func TestIntegrationReverseBlockPayoutCreditsRejectsNegativeBalance(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-reversal-negative")
	credits := testRunCredits()
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, credits)); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}

	// Simulate alice already having been disbursed some of this bad
	// credit: drive her pending_balance below what the reversal would
	// need to debit, via the same raw-SQL debit shape
	// CompletePayoutSent uses.
	if _, err := pool.Exec(ctx, `UPDATE balance SET pending_balance = pending_balance - 58000 WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = 'alice'`); err != nil {
		t.Fatalf("simulating a prior disbursement debit: %v", err)
	}

	if err := repo.SetBlockStatus(ctx, blockID, false, true); err != nil {
		t.Fatalf("SetBlockStatus (orphaning): %v", err)
	}

	before := pendingBalances(t, pool, "RXM", "TESTNET")

	_, err := repo.ReverseBlockPayoutCredits(ctx, blockID, "operator-1", "attempting reversal after a prior disbursement")
	if err == nil {
		t.Fatal("ReverseBlockPayoutCredits: got nil error for a debit that would drive a balance negative, want the CHECK constraint to reject it")
	}

	// The WHOLE transaction must have rolled back: every balance
	// (including fee-addr/coindev-addr, which alone would NOT have
	// gone negative) must be untouched, and the status must still be
	// APPLIED, not REVERSED.
	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("a rejected reversal must touch NO balance row (full rollback): before=%+v after=%+v", before, after)
	}
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("block_payouts status = %q after a rejected reversal, want it still APPLIED (not REVERSED, not corrupted)", row.Status)
	}
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	for _, c := range ledger {
		if c.ReversedAt != nil {
			t.Errorf("BlockPayoutCredits: balance_id=%d has reversed_at=%v set after a rejected reversal, want nil (full rollback)", c.BalanceID, c.ReversedAt)
		}
	}
}

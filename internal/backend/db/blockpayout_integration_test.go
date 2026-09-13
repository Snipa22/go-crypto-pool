package db_test

// Integration tests for the matured-block payout idempotency ledger
// (migrations/0013_block_payouts.up.sql,
// internal/backend/db/blockpayout.go) against a REAL Postgres
// instance. Set GCPOOL_TEST_DSN to run them — see integration_test.go's
// package doc comment for the exact setup.
//
// These are deliberately integration-only rather than unit tests with
// a mocked DB layer. Every property being asserted here IS a database
// property: transaction atomicity, an ON CONFLICT claim, a UNIQUE
// index acting as a row-level idempotency backstop, and a FOR UPDATE
// row lock. A mock would assert only that this file's own Go code
// calls what it thinks it calls, which on money-critical logic is
// worth approximately nothing.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testBlockHeight is the single height every block/claim/run in this
// file uses. ApplyBlockPayout cross-checks a run's identity against
// the recorded claim row (see claimBlockPayout), so the fixtures must
// agree on it; blocks here are made distinct by hash, not height.
const testBlockHeight = 100

// insertTestBlock inserts one `blocks` row and returns its real id,
// since `block_payouts.block_id` is a real foreign key onto it.
func insertTestBlock(t *testing.T, pool *pgxpool.Pool, algo, network, poolType, hash string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO blocks (algo, network, pool_type, hash, height, difficulty, shares, block_timestamp, unlocked, valid, value)
		VALUES ($1, $2, $3, $4, $5, 1000, 10, 1700000000, FALSE, TRUE, 600000000000)
		RETURNING id`, algo, network, poolType, hash, testBlockHeight).Scan(&id)
	if err != nil {
		t.Fatalf("inserting test block %s: %v", hash, err)
	}
	return id
}

// pendingBalances snapshots every (payment_address -> pending_balance)
// for one (algo, network), which is what "no double credit" assertions
// actually compare.
func pendingBalances(t *testing.T, pool *pgxpool.Pool, algo, network string) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT payment_address, pending_balance FROM balance WHERE algo = $1 AND network = $2`, algo, network)
	if err != nil {
		t.Fatalf("querying balances: %v", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var addr string
		var amount int64
		if err := rows.Scan(&addr, &amount); err != nil {
			t.Fatalf("scanning balance row: %v", err)
		}
		out[addr] = amount
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating balance rows: %v", err)
	}
	return out
}

func sameBalances(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// testRunCredits is the payout-shaped credit set used below: a real
// miner plus the fee/dev seed entries every payout calculation emits
// (including a zero-amount one, which must still create its balance
// row — see payout.Apply).
func testRunCredits() []db.BlockCredit {
	return []db.BlockCredit{
		{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 58800},
		{PayoutBucket: "fees", PaymentAddress: "fee-addr", Amount: 1700},
		{PayoutBucket: "fees", PaymentAddress: "coindev-addr", Amount: 200},
		{PayoutBucket: "fees", PaymentAddress: "zero-seed-addr", Amount: 0},
	}
}

func testRun(blockID int64, credits []db.BlockCredit) db.BlockPayoutRun {
	return db.BlockPayoutRun{
		BlockID:  blockID,
		Algo:     "RXM",
		Network:  "TESTNET",
		PoolType: "PPS",
		Height:   testBlockHeight,
		Reward:   600000000000,
		Credits:  credits,
	}
}

// TestIntegrationApplyBlockPayoutIsIdempotent is the headline
// regression test for finding #5: a block whose payout run fully
// succeeds gets `block_payouts` status APPLIED, and a SECOND
// ApplyBlockPayout call for that same block is a safe no-op that
// credits nobody a second time.
//
// Before this change, re-running a matured block's payout (which
// `backend block relock` has always been able to trigger, and which
// the unlocker now does automatically on retry) re-ran the whole
// CreditBalance upsert-increment loop and credited every miner again.
// The balance assertions below are the ones that matter.
func TestIntegrationApplyBlockPayoutIsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-idempotent")
	credits := testRunCredits()

	first, err := repo.ApplyBlockPayout(ctx, testRun(blockID, credits))
	if err != nil {
		t.Fatalf("ApplyBlockPayout (first): %v", err)
	}
	if first.AlreadyApplied {
		t.Fatal("ApplyBlockPayout (first): got AlreadyApplied=true on a block's very first run, want false")
	}
	if first.Credited != len(credits) {
		t.Fatalf("ApplyBlockPayout (first): Credited=%d, want %d (every entry, including the zero-amount seed)", first.Credited, len(credits))
	}
	if first.TotalPaid != 58800+1700+200 {
		t.Fatalf("ApplyBlockPayout (first): TotalPaid=%d, want %d", first.TotalPaid, 58800+1700+200)
	}

	// (a) the claim row is APPLIED, with the run's real summary.
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("block_payouts status = %q after a successful run, want APPLIED", row.Status)
	}
	if row.AppliedAt == nil {
		t.Fatal("block_payouts applied_at is NULL after a successful run, want a timestamp")
	}
	if row.Credited == nil || *row.Credited != len(credits) {
		t.Fatalf("block_payouts credited = %v, want %d", row.Credited, len(credits))
	}
	if row.TotalPaid == nil || *row.TotalPaid != first.TotalPaid {
		t.Fatalf("block_payouts total_paid = %v, want %d", row.TotalPaid, first.TotalPaid)
	}

	// The balances really were credited, and the zero-amount seed
	// entry still got its balance row (payout.Apply relies on that).
	before := pendingBalances(t, pool, "RXM", "TESTNET")
	if before["alice"] != 58800 || before["fee-addr"] != 1700 || before["coindev-addr"] != 200 {
		t.Fatalf("balances after the first run = %+v, want alice=58800 fee-addr=1700 coindev-addr=200", before)
	}
	if _, ok := before["zero-seed-addr"]; !ok {
		t.Fatalf("balances after the first run = %+v, want a (zero) row for the zero-amount seed entry too", before)
	}

	// Every credit is itemised, once each.
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	if len(ledger) != len(credits) {
		t.Fatalf("block_payout_credits has %d row(s), want %d (one per credit)", len(ledger), len(credits))
	}

	// (b) THE POINT: a second, identical call must credit nothing.
	second, err := repo.ApplyBlockPayout(ctx, testRun(blockID, credits))
	if err != nil {
		t.Fatalf("ApplyBlockPayout (second): got an error, want a clean no-op: %v", err)
	}
	if !second.AlreadyApplied {
		t.Fatal("ApplyBlockPayout (second): got AlreadyApplied=false, want true")
	}
	if second.TotalPaid != first.TotalPaid || second.Credited != first.Credited {
		t.Fatalf("ApplyBlockPayout (second): got %+v, want the ORIGINAL run's recorded totals %+v", second, first)
	}

	after := pendingBalances(t, pool, "RXM", "TESTNET")
	if !sameBalances(before, after) {
		t.Fatalf("BALANCES CHANGED on a second ApplyBlockPayout for the same block: before=%+v after=%+v — this is the double-credit bug", before, after)
	}
	ledgerAfter, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits (after second call): %v", err)
	}
	if len(ledgerAfter) != len(ledger) {
		t.Fatalf("block_payout_credits grew from %d to %d rows on a no-op re-apply", len(ledger), len(ledgerAfter))
	}

	// A THIRD call with DIFFERENT (e.g. recalculated, larger) credits
	// must also be refused as a no-op. An APPLIED block is closed,
	// not "closed for this particular payment set".
	bigger := append(testRunCredits(), db.BlockCredit{PayoutBucket: "pps", PaymentAddress: "newcomer", Amount: 999999})
	third, err := repo.ApplyBlockPayout(ctx, testRun(blockID, bigger))
	if err != nil {
		t.Fatalf("ApplyBlockPayout (third, different credits): %v", err)
	}
	if !third.AlreadyApplied {
		t.Fatal("ApplyBlockPayout (third): got AlreadyApplied=false for an APPLIED block, want true")
	}
	if bal := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, bal) {
		t.Fatalf("BALANCES CHANGED on a re-apply carrying different credits: before=%+v after=%+v", before, bal)
	}
}

// TestIntegrationApplyBlockPayoutRefusesPendingClaim covers
// requirement (b): a fabricated partial-failure state (a PENDING
// `block_payouts` row) BLOCKS automatic re-application and is surfaced
// clearly, rather than silently retried.
//
// The row is fabricated by hand here on purpose — as of migration
// 0011 the engine cannot produce one (the claim and the outcome commit
// together), so the only way to reach this state is what this test
// does: something outside that transaction wrote it. The refusal still
// has to be airtight, because that is exactly the "an unknown subset
// of these miners may already hold this credit" case.
func TestIntegrationApplyBlockPayoutRefusesPendingClaim(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-pending")

	// Fabricate the partial-failure state: a claimed run that never
	// recorded an outcome, having already credited ONE of its payees.
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, blockID); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 58800); err != nil {
		t.Fatalf("fabricating alice's partial credit: %v", err)
	}
	var aliceBalanceID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM balance WHERE payment_address = 'alice'`).Scan(&aliceBalanceID); err != nil {
		t.Fatalf("looking up alice's balance id: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payout_bucket, amount)
		VALUES ($1, $2, 'alice', 'pps', 58800)`, blockID, aliceBalanceID); err != nil {
		t.Fatalf("fabricating alice's credit ledger row: %v", err)
	}

	before := pendingBalances(t, pool, "RXM", "TESTNET")

	// THE POINT: re-applying must be refused, loudly, not retried.
	_, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits()))
	if err == nil {
		t.Fatal("ApplyBlockPayout: got nil error for a PENDING claim, want a hard refusal — silently re-running is the double-credit bug")
	}
	if !errors.Is(err, db.ErrBlockPayoutPending) {
		t.Fatalf("ApplyBlockPayout: got err=%v, want it to wrap db.ErrBlockPayoutPending", err)
	}
	// The refusal must actually tell an operator what to do next.
	if !strings.Contains(err.Error(), "block-payout show") || !strings.Contains(err.Error(), "resolve-credited") {
		t.Errorf("ApplyBlockPayout refusal message does not point at the resolution commands, got: %v", err)
	}

	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("a refused PENDING block must credit NOTHING: before=%+v after=%+v", before, after)
	}
	// And it must still be PENDING — a refusal is not a resolution.
	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusPending {
		t.Fatalf("block_payouts status = %q after a refused re-apply, want it still PENDING", row.Status)
	}

	// It is discoverable by the surveys the startup check and CLI use.
	unresolved, err := repo.UnresolvedBlockPayouts(ctx, "", "")
	if err != nil {
		t.Fatalf("UnresolvedBlockPayouts: %v", err)
	}
	if len(unresolved) != 1 || unresolved[0].BlockID != blockID {
		t.Fatalf("UnresolvedBlockPayouts = %+v, want exactly the fabricated PENDING row for block %d", unresolved, blockID)
	}
	if unresolved[0].Credited != nil || unresolved[0].TotalPaid != nil {
		t.Errorf("a PENDING row must carry no recorded summary (it has no trustworthy one), got credited=%v total_paid=%v",
			unresolved[0].Credited, unresolved[0].TotalPaid)
	}
	narrowed, err := repo.UnresolvedBlockPayouts(ctx, "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("UnresolvedBlockPayouts(RXM, TESTNET): %v", err)
	}
	if len(narrowed) != 1 {
		t.Fatalf("UnresolvedBlockPayouts(RXM, TESTNET) = %+v, want the same 1 row", narrowed)
	}
	if other, err := repo.UnresolvedBlockPayouts(ctx, "RXT", "TESTNET"); err != nil || len(other) != 0 {
		t.Fatalf("UnresolvedBlockPayouts(RXT, TESTNET) = %+v (err=%v), want no rows for a different algo", other, err)
	}

	// The itemised ledger is what makes it resolvable at all.
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	if len(ledger) != 1 || ledger[0].PaymentAddress != "alice" || ledger[0].Amount != 58800 {
		t.Fatalf("BlockPayoutCredits = %+v, want exactly alice's already-landed 58800 credit", ledger)
	}
}

// TestIntegrationResolveBlockPayoutCredited exercises the
// `backend block-payout resolve-credited` path: an operator declares a
// PENDING run's recorded credits complete, the row goes APPLIED with
// totals derived from the real ledger, NOBODY is credited again, and
// the block becomes a permanent no-op for ApplyBlockPayout.
func TestIntegrationResolveBlockPayoutCredited(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-resolve-credited")
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, blockID); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 58800); err != nil {
		t.Fatalf("crediting alice: %v", err)
	}
	var aliceBalanceID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM balance WHERE payment_address = 'alice'`).Scan(&aliceBalanceID); err != nil {
		t.Fatalf("looking up alice's balance id: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payout_bucket, amount)
		VALUES ($1, $2, 'alice', 'pps', 58800)`, blockID, aliceBalanceID); err != nil {
		t.Fatalf("fabricating alice's credit ledger row: %v", err)
	}

	before := pendingBalances(t, pool, "RXM", "TESTNET")

	if err := repo.ResolveBlockPayoutCredited(ctx, blockID, "operator-1", "checked alice's balance against the ledger"); err != nil {
		t.Fatalf("ResolveBlockPayoutCredited: %v", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status = %q after resolve-credited, want APPLIED", row.Status)
	}
	if row.Credited == nil || *row.Credited != 1 || row.TotalPaid == nil || *row.TotalPaid != 58800 {
		t.Fatalf("credited/total_paid = %v/%v after resolve-credited, want 1/58800 derived from the ledger", row.Credited, row.TotalPaid)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "operator-1" || row.ResolutionNote == nil || *row.ResolutionNote == "" {
		t.Fatalf("resolved_by/resolution_note = %v/%v, want the audit fields recorded", row.ResolvedBy, row.ResolutionNote)
	}

	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("resolve-credited must credit NOBODY again: before=%+v after=%+v", before, after)
	}

	// Now permanently closed: the automatic path is a no-op.
	out, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits()))
	if err != nil {
		t.Fatalf("ApplyBlockPayout after resolve-credited: %v", err)
	}
	if !out.AlreadyApplied {
		t.Fatal("ApplyBlockPayout after resolve-credited: got AlreadyApplied=false, want true")
	}
	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("balances changed on the post-resolution no-op: before=%+v after=%+v", before, after)
	}

	// Resolving twice is refused, not silently repeated.
	err = repo.ResolveBlockPayoutCredited(ctx, blockID, "operator-2", "second attempt")
	if !errors.Is(err, db.ErrBlockPayoutAlreadyResolved) {
		t.Fatalf("ResolveBlockPayoutCredited (twice): got err=%v, want db.ErrBlockPayoutAlreadyResolved", err)
	}
}

// TestIntegrationResolveBlockPayoutNotCredited exercises the
// `backend block-payout resolve-not-credited` path: an operator
// declares a PENDING run void, the row goes FAILED with its voided
// ledger rows deleted, no balance is touched, and the block is handed
// BACK to the automatic path — a subsequent ApplyBlockPayout re-claims
// the FAILED row and credits for real.
func TestIntegrationResolveBlockPayoutNotCredited(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-resolve-not-credited")
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, blockID); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}

	if err := repo.ResolveBlockPayoutNotCredited(ctx, blockID, "operator-1", "no balance row moved; confirmed against every payee"); err != nil {
		t.Fatalf("ResolveBlockPayoutNotCredited: %v", err)
	}

	row, err := repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout: %v", err)
	}
	if row.Status != db.BlockPayoutStatusFailed {
		t.Fatalf("status = %q after resolve-not-credited, want FAILED", row.Status)
	}
	if row.ResolvedBy == nil || *row.ResolvedBy != "operator-1" {
		t.Fatalf("resolved_by = %v, want the audit field recorded", row.ResolvedBy)
	}
	// No longer unresolved, so it stops blocking/alerting.
	if unresolved, err := repo.UnresolvedBlockPayouts(ctx, "", ""); err != nil || len(unresolved) != 0 {
		t.Fatalf("UnresolvedBlockPayouts = %+v (err=%v), want none after resolution", unresolved, err)
	}

	// FAILED is deliberately re-claimable: the block flows back into
	// the automatic payout path and credits for real this time.
	out, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits()))
	if err != nil {
		t.Fatalf("ApplyBlockPayout after resolve-not-credited: %v", err)
	}
	if out.AlreadyApplied {
		t.Fatal("ApplyBlockPayout after resolve-not-credited: got AlreadyApplied=true, want a real run (FAILED must be re-claimable)")
	}
	if out.TotalPaid != 58800+1700+200 {
		t.Fatalf("ApplyBlockPayout after resolve-not-credited: TotalPaid=%d, want the full recalculated payout", out.TotalPaid)
	}
	bal := pendingBalances(t, pool, "RXM", "TESTNET")
	if bal["alice"] != 58800 {
		t.Fatalf("alice's pending_balance = %d after the re-run, want exactly 58800 (credited once, not twice)", bal["alice"])
	}
	row, err = repo.GetBlockPayout(ctx, blockID)
	if err != nil {
		t.Fatalf("GetBlockPayout (after re-run): %v", err)
	}
	if row.Status != db.BlockPayoutStatusApplied {
		t.Fatalf("status = %q after the re-run, want APPLIED", row.Status)
	}
	// The re-claim must have cleared the previous resolution's stale
	// summary rather than leaving it to be reported as this run's.
	if row.Credited == nil || *row.Credited != len(testRunCredits()) {
		t.Fatalf("credited = %v after the re-run, want %d", row.Credited, len(testRunCredits()))
	}
}

// TestIntegrationResolveBlockPayoutNotCreditedDeletesVoidedLedger
// pins the one subtle half of resolve-not-credited: the voided ledger
// rows must be DELETED, not left behind. Leaving them would make the
// re-run's row-level idempotency backstop (the UNIQUE (block_id,
// balance_id) index) silently skip exactly the credits the operator
// just declared void — the miner would never be paid and nothing
// would say so.
func TestIntegrationResolveBlockPayoutNotCreditedDeletesVoidedLedger(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-voided-ledger")
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payouts (block_id, algo, network, pool_type, height, status, reward)
		VALUES ($1, 'RXM', 'TESTNET', 'PPS', 100, 'PENDING', 600000000000)`, blockID); err != nil {
		t.Fatalf("fabricating the PENDING claim row: %v", err)
	}
	// A ledger row whose credit the operator has reversed by hand:
	// alice's balance is back to zero, but the ledger still names her.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 0); err != nil {
		t.Fatalf("creating alice's (reversed, zero) balance row: %v", err)
	}
	var aliceBalanceID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM balance WHERE payment_address = 'alice'`).Scan(&aliceBalanceID); err != nil {
		t.Fatalf("looking up alice's balance id: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO block_payout_credits (block_id, balance_id, payment_address, payout_bucket, amount)
		VALUES ($1, $2, 'alice', 'pps', 58800)`, blockID, aliceBalanceID); err != nil {
		t.Fatalf("fabricating alice's stale credit ledger row: %v", err)
	}

	if err := repo.ResolveBlockPayoutNotCredited(ctx, blockID, "operator-1", "reversed alice's credit by hand first"); err != nil {
		t.Fatalf("ResolveBlockPayoutNotCredited: %v", err)
	}
	if ledger, err := repo.BlockPayoutCredits(ctx, blockID); err != nil || len(ledger) != 0 {
		t.Fatalf("BlockPayoutCredits = %+v (err=%v), want the voided rows deleted", ledger, err)
	}

	// The re-run must therefore credit alice in full.
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits())); err != nil {
		t.Fatalf("ApplyBlockPayout after resolve-not-credited: %v", err)
	}
	if bal := pendingBalances(t, pool, "RXM", "TESTNET"); bal["alice"] != 58800 {
		t.Fatalf("alice's pending_balance = %d after the re-run, want 58800 — a stale ledger row would have silently skipped her", bal["alice"])
	}
}

// TestIntegrationApplyBlockPayoutRollsBackWholeRunOnFailure proves the
// all-or-nothing property that makes the whole design work: if the run
// cannot complete, NOBODY is credited and no claim row is left behind,
// so the next attempt starts clean rather than from a partial state.
//
// The failure is induced with a temporary CHECK constraint on
// `balance.pending_balance` that the SECOND credit violates — a real
// Postgres error raised by the real credit statement, partway through
// the credit loop, after an earlier credit in the same run has already
// been applied. That is precisely the shape of the old
// partial-failure bug: under the previous per-credit-implicit-
// transaction loop, alice's credit below would have stuck, with
// nothing anywhere recording that it had.
func TestIntegrationApplyBlockPayoutRollsBackWholeRunOnFailure(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-rollback")

	if _, err := pool.Exec(ctx, `
		ALTER TABLE balance ADD CONSTRAINT tmp_rollback_test_cap CHECK (pending_balance < 1000000)`); err != nil {
		t.Fatalf("installing the temporary failure-inducing constraint: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE balance DROP CONSTRAINT IF EXISTS tmp_rollback_test_cap`)
	})

	before := pendingBalances(t, pool, "RXM", "TESTNET")

	_, err := repo.ApplyBlockPayout(ctx, testRun(blockID, []db.BlockCredit{
		// Ordered so a credit that WOULD succeed is applied first.
		{PayoutBucket: "pps", PaymentAddress: "alice", Amount: 58800},
		{PayoutBucket: "pps", PaymentAddress: "over-the-cap", Amount: 2000000},
	}))
	if err == nil {
		t.Fatal("ApplyBlockPayout: got nil error for a credit the database rejects, want a failure")
	}

	if after := pendingBalances(t, pool, "RXM", "TESTNET"); !sameBalances(before, after) {
		t.Fatalf("a failed run must credit NOBODY (full rollback): before=%+v after=%+v", before, after)
	}
	if _, err := repo.GetBlockPayout(ctx, blockID); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Fatalf("GetBlockPayout after a failed run: got err=%v, want ErrBlockPayoutNotFound (the claim must roll back too, so the next attempt starts clean)", err)
	}
	if ledger, err := repo.BlockPayoutCredits(ctx, blockID); err != nil || len(ledger) != 0 {
		t.Fatalf("BlockPayoutCredits after a failed run = %+v (err=%v), want none", ledger, err)
	}

	// And the block is genuinely retryable: with the fault removed, a
	// subsequent run credits everyone exactly once.
	if _, err := pool.Exec(ctx, `ALTER TABLE balance DROP CONSTRAINT tmp_rollback_test_cap`); err != nil {
		t.Fatalf("removing the temporary constraint: %v", err)
	}
	out, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits()))
	if err != nil {
		t.Fatalf("ApplyBlockPayout (retry after rollback): %v", err)
	}
	if out.AlreadyApplied {
		t.Fatal("ApplyBlockPayout (retry after rollback): got AlreadyApplied=true, want a real run")
	}
	if bal := pendingBalances(t, pool, "RXM", "TESTNET"); bal["alice"] != 58800 {
		t.Fatalf("alice's pending_balance = %d after the retry, want exactly 58800", bal["alice"])
	}
}

// TestIntegrationApplyBlockPayoutRejectsBadInput covers the guards
// that keep a malformed run from ever reaching the ledger — most
// importantly the empty-credits case, which would otherwise record a
// block as permanently APPLIED without paying anybody.
func TestIntegrationApplyBlockPayoutRejectsBadInput(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-badinput")

	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, nil)); err == nil {
		t.Error("ApplyBlockPayout: got nil error for a run with no credits, want a refusal (it would mark the block paid while paying nobody)")
	}
	if _, err := repo.GetBlockPayout(ctx, blockID); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Errorf("a rejected empty run must not leave a claim row behind, got err=%v", err)
	}

	bad := testRun(blockID, testRunCredits())
	bad.Algo = "NOPE"
	if _, err := repo.ApplyBlockPayout(ctx, bad); err == nil {
		t.Error("ApplyBlockPayout: got nil error for an invalid algo, want a refusal")
	}
	bad = testRun(blockID, testRunCredits())
	bad.Network = "NOPE"
	if _, err := repo.ApplyBlockPayout(ctx, bad); err == nil {
		t.Error("ApplyBlockPayout: got nil error for an invalid network, want a refusal")
	}
	bad = testRun(blockID, testRunCredits())
	bad.PoolType = "NOPE"
	if _, err := repo.ApplyBlockPayout(ctx, bad); err == nil {
		t.Error("ApplyBlockPayout: got nil error for an invalid pool_type, want a refusal")
	}
	bad = testRun(0, testRunCredits())
	if _, err := repo.ApplyBlockPayout(ctx, bad); err == nil {
		t.Error("ApplyBlockPayout: got nil error for block id 0, want a refusal")
	}

	// A block id that does not exist must be refused by the real
	// foreign key rather than recorded against nothing.
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID+99999, testRunCredits())); err == nil {
		t.Error("ApplyBlockPayout: got nil error for a nonexistent blocks.id, want the foreign key to refuse it")
	}

	// A run whose identity disagrees with the already-recorded claim
	// row must be refused rather than treated as either a no-op or a
	// re-claim: a mismatch there means a reused blocks.id or a
	// hand-edited ledger, and neither conclusion is safe.
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits())); err != nil {
		t.Fatalf("ApplyBlockPayout (establishing the claim): %v", err)
	}
	mismatched := testRun(blockID, testRunCredits())
	mismatched.Height = 99999
	if _, err := repo.ApplyBlockPayout(ctx, mismatched); err == nil {
		t.Error("ApplyBlockPayout: got nil error for a run whose height disagrees with the recorded claim row, want a refusal")
	}
	mismatched = testRun(blockID, testRunCredits())
	mismatched.Algo = "RXT"
	if _, err := repo.ApplyBlockPayout(ctx, mismatched); err == nil {
		t.Error("ApplyBlockPayout: got nil error for a run whose algo disagrees with the recorded claim row, want a refusal")
	}

	// Resolution of a never-claimed block is likewise refused.
	unclaimed := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-unclaimed")
	if err := repo.ResolveBlockPayoutCredited(ctx, unclaimed, "op", "why"); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Errorf("ResolveBlockPayoutCredited on an unclaimed block: got err=%v, want ErrBlockPayoutNotFound", err)
	}
	if err := repo.ResolveBlockPayoutNotCredited(ctx, unclaimed, "op", "why"); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Errorf("ResolveBlockPayoutNotCredited on an unclaimed block: got err=%v, want ErrBlockPayoutNotFound", err)
	}
}

// TestIntegrationApplyBlockPayoutConcurrentRunsCreditOnce is the
// concurrency half of the idempotency guarantee: two ApplyBlockPayout
// calls racing on the SAME block (two poll passes overlapping, two
// backend processes, an operator re-triggering while a pass is in
// flight) must between them credit every payee exactly once.
func TestIntegrationApplyBlockPayoutConcurrentRunsCreditOnce(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-concurrent")

	const racers = 6
	type outcome struct {
		out db.BlockPayoutOutcome
		err error
	}
	results := make(chan outcome, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			out, err := repo.ApplyBlockPayout(context.Background(), testRun(blockID, testRunCredits()))
			results <- outcome{out: out, err: err}
		}()
	}
	close(start)

	var realRuns, noOps int
	for i := 0; i < racers; i++ {
		r := <-results
		switch {
		case r.err != nil:
			t.Errorf("concurrent ApplyBlockPayout returned an error: %v", r.err)
		case r.out.AlreadyApplied:
			noOps++
		default:
			realRuns++
		}
	}
	if realRuns != 1 {
		t.Fatalf("%d of %d concurrent runs credited balances, want exactly 1 (the rest must be no-ops); %d were no-ops", realRuns, racers, noOps)
	}

	bal := pendingBalances(t, pool, "RXM", "TESTNET")
	if bal["alice"] != 58800 || bal["fee-addr"] != 1700 || bal["coindev-addr"] != 200 {
		t.Fatalf("balances after %d concurrent runs = %+v, want each payee credited exactly once", racers, bal)
	}
	ledger, err := repo.BlockPayoutCredits(ctx, blockID)
	if err != nil {
		t.Fatalf("BlockPayoutCredits: %v", err)
	}
	if len(ledger) != len(testRunCredits()) {
		t.Fatalf("block_payout_credits has %d row(s) after %d concurrent runs, want %d", len(ledger), racers, len(testRunCredits()))
	}
}

// TestIntegrationBlockPayoutsCascadeWithBlocks confirms the
// block_payouts -> blocks and block_payout_credits -> block_payouts
// foreign keys really cascade, so an operator deleting a bogus block
// row cannot leave orphaned ledger rows behind (which would then block
// or mis-credit a re-inserted block at the same id).
func TestIntegrationBlockPayoutsCascadeWithBlocks(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	blockID := insertTestBlock(t, pool, "RXM", "TESTNET", "PPS", "hash-cascade")
	if _, err := repo.ApplyBlockPayout(ctx, testRun(blockID, testRunCredits())); err != nil {
		t.Fatalf("ApplyBlockPayout: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM blocks WHERE id = $1`, blockID); err != nil {
		t.Fatalf("deleting the block: %v", err)
	}
	if _, err := repo.GetBlockPayout(ctx, blockID); !errors.Is(err, db.ErrBlockPayoutNotFound) {
		t.Errorf("block_payouts row survived its blocks row being deleted: err=%v", err)
	}
	if ledger, err := repo.BlockPayoutCredits(ctx, blockID); err != nil || len(ledger) != 0 {
		t.Errorf("block_payout_credits rows survived: %+v (err=%v)", ledger, err)
	}
}

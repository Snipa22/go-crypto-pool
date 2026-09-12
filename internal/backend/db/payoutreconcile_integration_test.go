package db_test

// Integration tests for the unresolved/ambiguous payout mechanism
// added by migrations/0010_payouts_ambiguous_status.up.sql and
// internal/backend/db/payoutreconcile.go — i.e. the database half of
// the wallet-transfer double-payment fix.
//
// Same GCPOOL_TEST_DSN opt-in convention, testPool/resetSchema
// helpers as integration_test.go — see that file's package doc
// comment.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// freshSchema is the resetSchema + ApplyMigrations preamble every
// test in this file needs.
func freshSchema(t *testing.T) (*pgxpool.Pool, *db.Repository, context.Context) {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	return pool, db.NewRepository(pool), ctx
}

// TestIntegrationMigration0010AppliesOnFreshSchema proves the new
// migration applies cleanly from scratch: the AMBIGUOUS status is
// accepted by the rewritten CHECK constraint, the three new columns
// exist, the partial index exists, and the three PRE-EXISTING status
// values still work (a botched constraint rewrite that rejected
// 'SENT' would break every payout in the deployment).
func TestIntegrationMigration0010AppliesOnFreshSchema(t *testing.T) {
	pool, _, ctx := freshSchema(t)

	for _, col := range []string{"pending_entries", "resolved_by", "resolution_note"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = 'payouts' AND column_name = $1
			)`, col).Scan(&exists); err != nil {
			t.Fatalf("checking payouts.%s: %v", col, err)
		}
		if !exists {
			t.Errorf("expected migration 0010 to add payouts.%s", col)
		}
	}

	var indexExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_payouts_unresolved')
	`).Scan(&indexExists); err != nil {
		t.Fatalf("checking idx_payouts_unresolved: %v", err)
	}
	if !indexExists {
		t.Error("expected migration 0010 to create idx_payouts_unresolved")
	}

	// Every status value, old and new, must be insertable.
	for _, status := range []string{"PENDING", "SENT", "FAILED", "AMBIGUOUS"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO payouts (algo, network, status, balance_ids, amount) VALUES ('RXM', 'TESTNET', $1, '{1}', 1)`,
			status); err != nil {
			t.Errorf("inserting a %s payout: %v", status, err)
		}
	}
	// And an unknown one must still be rejected — the constraint was
	// widened, not dropped.
	if _, err := pool.Exec(ctx,
		`INSERT INTO payouts (algo, network, status, balance_ids, amount) VALUES ('RXM', 'TESTNET', 'BOGUS', '{1}', 1)`,
	); err == nil {
		t.Error("inserting a BOGUS payout status succeeded, want the CHECK constraint to still reject unknown statuses")
	}
}

// TestIntegrationMigration0010DownRefusesWhileAmbiguousRowsExist
// proves the down migration fails closed. Rewriting an AMBIGUOUS row
// to FAILED would assert "no coin moved" about a payout that may well
// have broadcast, making those balances payable again — a real double
// payment with no trace. The down migration must refuse instead.
func TestIntegrationMigration0010DownRefusesWhileAmbiguousRowsExist(t *testing.T) {
	pool, _, ctx := freshSchema(t)

	down, err := os.ReadFile("migrations/0010_payouts_ambiguous_status.down.sql")
	if err != nil {
		t.Fatalf("reading 0010 down migration: %v", err)
	}

	// With no AMBIGUOUS rows it must apply cleanly...
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("0010 down migration on a schema with no AMBIGUOUS rows: %v", err)
	}
	// ...so re-apply the up migration to get back to current schema.
	up, err := os.ReadFile("migrations/0010_payouts_ambiguous_status.up.sql")
	if err != nil {
		t.Fatalf("reading 0010 up migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(up)); err != nil {
		t.Fatalf("re-applying 0010 up migration: %v", err)
	}

	// Now with an unresolved AMBIGUOUS row present, it must refuse.
	if _, err := pool.Exec(ctx,
		`INSERT INTO payouts (algo, network, status, balance_ids, amount) VALUES ('RXM', 'TESTNET', 'AMBIGUOUS', '{1}', 500)`,
	); err != nil {
		t.Fatalf("inserting an AMBIGUOUS payout: %v", err)
	}
	_, err = pool.Exec(ctx, string(down))
	if err == nil {
		t.Fatal("0010 down migration succeeded with an unresolved AMBIGUOUS row present, want it to refuse")
	}
	if !strings.Contains(err.Error(), "refusing to down-migrate") {
		t.Errorf("got error %q, want one explaining it refuses to down-migrate unresolved AMBIGUOUS rows", err)
	}
	// The row must be untouched by the failed attempt.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM payouts WHERE amount = 500`).Scan(&status); err != nil {
		t.Fatalf("re-reading the AMBIGUOUS payout: %v", err)
	}
	if status != "AMBIGUOUS" {
		t.Errorf("got status=%q after a refused down migration, want it left AMBIGUOUS", status)
	}
}

// TestIntegrationPayableBalancesExcludesRowsUnderUnresolvedPayouts is
// the direct repository-level regression test for the double-payment
// bug: a balance row referenced by an unresolved (PENDING or
// AMBIGUOUS) payout must NOT come back from PayableBalances, no
// matter how large its pending_balance or whether it is
// force_payout-flagged. Resolving the payout must release it again.
func TestIntegrationPayableBalancesExcludesRowsUnderUnresolvedPayouts(t *testing.T) {
	_, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "frozen", nil, 1000); err != nil {
		t.Fatalf("CreditBalance(frozen): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "healthy", nil, 900); err != nil {
		t.Fatalf("CreditBalance(healthy): %v", err)
	}
	// A force_payout-flagged row too: the freeze must beat the
	// force_payout override, which is otherwise the strongest
	// "definitely pay this" signal in the system.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "frozen-forced", nil, 10); err != nil {
		t.Fatalf("CreditBalance(frozen-forced): %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "frozen-forced", nil); err != nil {
		t.Fatalf("SetForcePayout(frozen-forced): %v", err)
	}

	ids := map[string]int64{}
	initial, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances (baseline): %v", err)
	}
	for _, p := range initial {
		ids[p.PaymentAddress] = p.ID
	}
	if len(initial) != 3 {
		t.Fatalf("PayableBalances (baseline): got %d rows, want all 3 payable before any payout exists: %+v", len(initial), initial)
	}

	// One PENDING payout covering "frozen", one AMBIGUOUS covering
	// "frozen-forced".
	pendingID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET",
		[]db.DisburseEntry{{BalanceID: ids["frozen"], Amount: 1000}}, 1000)
	if err != nil {
		t.Fatalf("RecordPendingPayout(frozen): %v", err)
	}
	ambiguousID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET",
		[]db.DisburseEntry{{BalanceID: ids["frozen-forced"], Amount: 10, ForcePayout: true}}, 10)
	if err != nil {
		t.Fatalf("RecordPendingPayout(frozen-forced): %v", err)
	}
	if err := repo.MarkPayoutAmbiguous(ctx, ambiguousID, "", "transfer timed out, may have broadcast"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}

	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 1 || payable[0].PaymentAddress != "healthy" {
		t.Fatalf("PayableBalances: got %+v, want ONLY 'healthy' — rows under a PENDING/AMBIGUOUS payout must be frozen", payable)
	}

	// A minPayout of 0 ("pay everything") must not bypass the freeze
	// either.
	all, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 0)
	if err != nil {
		t.Fatalf("PayableBalances(min=0): %v", err)
	}
	if len(all) != 1 || all[0].PaymentAddress != "healthy" {
		t.Fatalf("PayableBalances(min=0): got %+v, want ONLY 'healthy' — minPayout=0 must not bypass the in-flight freeze", all)
	}

	// The freeze is scoped to its own (algo, network): the same
	// balance ids under a different algo must be unaffected.
	if err := repo.CreditBalance(ctx, "RXT", "TESTNET", "other-algo", nil, 800); err != nil {
		t.Fatalf("CreditBalance(other-algo): %v", err)
	}
	otherAlgo, err := repo.PayableBalances(ctx, "RXT", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances(RXT): %v", err)
	}
	if len(otherAlgo) != 1 {
		t.Fatalf("PayableBalances(RXT): got %+v, want RXT unaffected by an RXM freeze", otherAlgo)
	}

	// Resolving the PENDING one as FAILED releases its balance.
	if err := repo.FailPayout(ctx, pendingID, "provably not broadcast"); err != nil {
		t.Fatalf("FailPayout: %v", err)
	}
	afterFail, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances after FailPayout: %v", err)
	}
	if len(afterFail) != 2 {
		t.Fatalf("PayableBalances after FailPayout: got %+v, want 'frozen' released alongside 'healthy'", afterFail)
	}
}

// TestIntegrationUnresolvedPayoutsAndGetPayoutByID covers the query
// surface the startup check and the operator CLI both depend on,
// including that pending_entries round-trips through JSONB intact
// (that record is what resolve-sent replays, so a silent encoding
// bug there would be a money bug).
func TestIntegrationUnresolvedPayoutsAndGetPayoutByID(t *testing.T) {
	_, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 1000); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	entries := []db.DisburseEntry{{BalanceID: payable[0].ID, Amount: 1000, ForcePayout: true, ForcePayoutFeeAtomic: 25}}
	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", entries, 975)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}

	unresolved, err := repo.UnresolvedPayouts(ctx, "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("UnresolvedPayouts: %v", err)
	}
	if len(unresolved) != 1 || unresolved[0].ID != payoutID || unresolved[0].Status != "PENDING" {
		t.Fatalf("UnresolvedPayouts: got %+v, want the one PENDING row", unresolved)
	}
	if unresolved[0].Amount != 975 {
		t.Errorf("got Amount=%d, want the real on-chain destination total 975 (not the 1000 debit total)", unresolved[0].Amount)
	}
	if len(unresolved[0].Entries) != 1 {
		t.Fatalf("got Entries=%+v, want the one recorded per-balance entry", unresolved[0].Entries)
	}
	e := unresolved[0].Entries[0]
	if e.BalanceID != payable[0].ID || e.Amount != 1000 || !e.ForcePayout || e.ForcePayoutFeeAtomic != 25 {
		t.Errorf("pending_entries round-trip: got %+v, want BalanceID=%d Amount=1000 ForcePayout=true fee=25", e, payable[0].ID)
	}
	if len(unresolved[0].BalanceIDs) != 1 || unresolved[0].BalanceIDs[0] != payable[0].ID {
		t.Errorf("got BalanceIDs=%v, want the balance id derived from entries", unresolved[0].BalanceIDs)
	}

	// The "" = any filters, and a non-matching filter.
	if rows, err := repo.UnresolvedPayouts(ctx, "", ""); err != nil || len(rows) != 1 {
		t.Errorf("UnresolvedPayouts(any, any): got %d rows, err=%v; want 1 row", len(rows), err)
	}
	if rows, err := repo.UnresolvedPayouts(ctx, "RXT", "TESTNET"); err != nil || len(rows) != 0 {
		t.Errorf("UnresolvedPayouts(RXT, TESTNET): got %d rows, err=%v; want 0", len(rows), err)
	}
	// A typo'd algo must ERROR, never return a false all-clear.
	if _, err := repo.UnresolvedPayouts(ctx, "NOTANALGO", ""); err == nil {
		t.Error("UnresolvedPayouts with an invalid algo returned no error; a silent empty result would be a catastrophic false all-clear")
	}

	got, err := repo.GetPayoutByID(ctx, payoutID)
	if err != nil {
		t.Fatalf("GetPayoutByID: %v", err)
	}
	if got.ID != payoutID || got.Status != "PENDING" || len(got.Entries) != 1 {
		t.Errorf("GetPayoutByID: got %+v, want the PENDING row with its one entry", got)
	}
	if _, err := repo.GetPayoutByID(ctx, payoutID+9999); !errors.Is(err, db.ErrPayoutNotFound) {
		t.Errorf("GetPayoutByID(missing): got err=%v, want ErrPayoutNotFound", err)
	}

	// A SENT row must NOT appear in UnresolvedPayouts, but must
	// still be fetchable by id.
	if err := repo.CompletePayoutSent(ctx, payoutID, entries, "txhash", 4); err != nil {
		t.Fatalf("CompletePayoutSent: %v", err)
	}
	if rows, err := repo.UnresolvedPayouts(ctx, "RXM", "TESTNET"); err != nil || len(rows) != 0 {
		t.Errorf("UnresolvedPayouts after SENT: got %d rows, err=%v; want 0", len(rows), err)
	}
	if sent, err := repo.GetPayoutByID(ctx, payoutID); err != nil || sent.Status != "SENT" {
		t.Errorf("GetPayoutByID after SENT: got %+v err=%v, want a SENT row", sent, err)
	}
}

// TestIntegrationMarkPayoutAmbiguousRecordsTxHashAndKeepsRowOpen
// covers MarkPayoutAmbiguous' exact contract: status flips, the error
// is recorded, a supplied tx_hash is stored (it is what the operator
// needs to confirm the transfer), an empty one does not clobber an
// existing hash, and completed_at stays NULL because AMBIGUOUS is an
// open incident rather than a completed outcome.
func TestIntegrationMarkPayoutAmbiguousRecordsTxHashAndKeepsRowOpen(t *testing.T) {
	pool, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 1000); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET",
		[]db.DisburseEntry{{BalanceID: payable[0].ID, Amount: 1000}}, 1000)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}

	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, "realtxhash", "transfer succeeded but recording it failed"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}

	var status, txHash, errMsg string
	var completedAt *string
	if err := pool.QueryRow(ctx,
		`SELECT status, tx_hash, error, completed_at::text FROM payouts WHERE id = $1`, payoutID,
	).Scan(&status, &txHash, &errMsg, &completedAt); err != nil {
		t.Fatalf("querying the ambiguous payout: %v", err)
	}
	if status != "AMBIGUOUS" || txHash != "realtxhash" {
		t.Errorf("got status=%q tx_hash=%q, want AMBIGUOUS/realtxhash", status, txHash)
	}
	if !strings.Contains(errMsg, "recording it failed") {
		t.Errorf("got error=%q, want the supplied message recorded", errMsg)
	}
	if completedAt != nil {
		t.Errorf("got completed_at=%v, want NULL — AMBIGUOUS is an open incident, not a completed outcome", *completedAt)
	}

	// Balance untouched — an ambiguous payout debits nothing.
	var pending, paid int64
	if err := pool.QueryRow(ctx, `SELECT pending_balance, paid_balance FROM balance WHERE id = $1`, payable[0].ID).
		Scan(&pending, &paid); err != nil {
		t.Fatalf("querying alice's balance: %v", err)
	}
	if pending != 1000 || paid != 0 {
		t.Errorf("got pending=%d paid=%d, want 1000/0 — MarkPayoutAmbiguous must not touch balances", pending, paid)
	}

	// An empty txHash must not clobber the recorded hash.
	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, "", "still ambiguous"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous (second call): %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT tx_hash FROM payouts WHERE id = $1`, payoutID).Scan(&txHash); err != nil {
		t.Fatalf("re-querying tx_hash: %v", err)
	}
	if txHash != "realtxhash" {
		t.Errorf("got tx_hash=%q after a second MarkPayoutAmbiguous with an empty hash, want the original preserved", txHash)
	}
}

// TestIntegrationResolvePayoutSentReplaysExactDebitWithoutRepaying is
// the operator-resolution happy path for "the transfer DID broadcast":
// the recorded per-entry debit is replayed exactly (full
// pending_balance moved to paid_balance, force_payout consumed,
// force-payout fee banked), the row becomes SENT with the confirmed
// hash and the resolution audit fields, and no coin is re-sent.
func TestIntegrationResolvePayoutSentReplaysExactDebitWithoutRepaying(t *testing.T) {
	pool, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 400); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "alice", nil); err != nil {
		t.Fatalf("SetForcePayout: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	balanceID := payable[0].ID

	entries := []db.DisburseEntry{{BalanceID: balanceID, Amount: 400, ForcePayout: true, ForcePayoutFeeAtomic: 15}}
	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", entries, 385)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, "confirmedhash", "bookkeeping failed after a successful transfer"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}

	// CRITICAL: the balance accrues MORE while the payout sits
	// unresolved. resolve-sent must debit the RECORDED 400, not the
	// current 900 — debiting the larger figure would overpay the
	// pool against the miner.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 500); err != nil {
		t.Fatalf("CreditBalance (accrual while unresolved): %v", err)
	}

	if err := repo.ResolvePayoutSent(ctx, payoutID, "confirmedhash", 7, "operator-jane", "confirmed on block explorer"); err != nil {
		t.Fatalf("ResolvePayoutSent: %v", err)
	}

	var pending, paid int64
	var forceFlag bool
	if err := pool.QueryRow(ctx, `SELECT pending_balance, paid_balance, force_payout FROM balance WHERE id = $1`, balanceID).
		Scan(&pending, &paid, &forceFlag); err != nil {
		t.Fatalf("querying alice's balance: %v", err)
	}
	if paid != 400 {
		t.Errorf("got paid_balance=%d, want exactly the RECORDED 400 (not the post-accrual 900)", paid)
	}
	if pending != 500 {
		t.Errorf("got pending_balance=%d, want the 500 that accrued after the attempt left intact", pending)
	}
	if forceFlag {
		t.Error("got force_payout=true, want it consumed (reset to false) by the resolution")
	}

	var status, txHash, resolvedBy, note string
	var fee, forceFee int64
	if err := pool.QueryRow(ctx,
		`SELECT status, tx_hash, fee, force_payout_fee_atomic, resolved_by, resolution_note FROM payouts WHERE id = $1`, payoutID,
	).Scan(&status, &txHash, &fee, &forceFee, &resolvedBy, &note); err != nil {
		t.Fatalf("querying the resolved payout: %v", err)
	}
	if status != "SENT" || txHash != "confirmedhash" || fee != 7 || forceFee != 15 {
		t.Errorf("got status=%q tx_hash=%q fee=%d force_fee=%d, want SENT/confirmedhash/7/15", status, txHash, fee, forceFee)
	}
	if resolvedBy != "operator-jane" || note != "confirmed on block explorer" {
		t.Errorf("got resolved_by=%q resolution_note=%q, want the operator audit fields recorded", resolvedBy, note)
	}

	// Now resolved, so no longer blocking — and the remaining 500 is
	// payable again.
	if rows, err := repo.UnresolvedPayouts(ctx, "RXM", "TESTNET"); err != nil || len(rows) != 0 {
		t.Errorf("UnresolvedPayouts after resolution: got %d rows err=%v, want 0", len(rows), err)
	}
	after, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances after resolution: %v", err)
	}
	if len(after) != 1 || after[0].PendingBalance != 500 {
		t.Errorf("got payable=%+v, want alice's remaining 500 payable again", after)
	}

	// Double-resolution must be refused — it would debit twice.
	err = repo.ResolvePayoutSent(ctx, payoutID, "confirmedhash", 7, "operator-jane", "again")
	if !errors.Is(err, db.ErrPayoutAlreadyResolved) {
		t.Errorf("second ResolvePayoutSent: got err=%v, want ErrPayoutAlreadyResolved", err)
	}
	if err := pool.QueryRow(ctx, `SELECT paid_balance FROM balance WHERE id = $1`, balanceID).Scan(&paid); err != nil {
		t.Fatalf("re-querying paid_balance: %v", err)
	}
	if paid != 400 {
		t.Errorf("got paid_balance=%d after a refused double resolution, want it still 400", paid)
	}
}

// TestIntegrationResolvePayoutNotSentReleasesBalances is the
// operator-resolution path for "the transfer did NOT broadcast": no
// balance is touched, the row becomes FAILED, and the balances become
// payable again so the next cycle legitimately retries.
func TestIntegrationResolvePayoutNotSentReleasesBalances(t *testing.T) {
	pool, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 600); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	balanceID := payable[0].ID
	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET",
		[]db.DisburseEntry{{BalanceID: balanceID, Amount: 600}}, 600)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.MarkPayoutAmbiguous(ctx, payoutID, "", "transfer timed out"); err != nil {
		t.Fatalf("MarkPayoutAmbiguous: %v", err)
	}

	if err := repo.ResolvePayoutNotSent(ctx, payoutID, "operator-jane", "no such tx in wallet history"); err != nil {
		t.Fatalf("ResolvePayoutNotSent: %v", err)
	}

	var pending, paid int64
	if err := pool.QueryRow(ctx, `SELECT pending_balance, paid_balance FROM balance WHERE id = $1`, balanceID).
		Scan(&pending, &paid); err != nil {
		t.Fatalf("querying alice's balance: %v", err)
	}
	if pending != 600 || paid != 0 {
		t.Errorf("got pending=%d paid=%d, want 600/0 — resolve-not-sent must not touch balances", pending, paid)
	}

	var status, resolvedBy, note, errMsg string
	if err := pool.QueryRow(ctx,
		`SELECT status, resolved_by, resolution_note, error FROM payouts WHERE id = $1`, payoutID,
	).Scan(&status, &resolvedBy, &note, &errMsg); err != nil {
		t.Fatalf("querying the resolved payout: %v", err)
	}
	if status != "FAILED" || resolvedBy != "operator-jane" {
		t.Errorf("got status=%q resolved_by=%q, want FAILED/operator-jane", status, resolvedBy)
	}
	if !strings.Contains(errMsg, "transfer timed out") || !strings.Contains(errMsg, "no such tx in wallet history") {
		t.Errorf("got error=%q, want BOTH the original ambiguity and the operator's note preserved", errMsg)
	}

	// Released: payable again, and nothing is blocking disbursement.
	if rows, err := repo.UnresolvedPayouts(ctx, "RXM", "TESTNET"); err != nil || len(rows) != 0 {
		t.Errorf("UnresolvedPayouts after resolution: got %d rows err=%v, want 0", len(rows), err)
	}
	after, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances after resolution: %v", err)
	}
	if len(after) != 1 || after[0].ID != balanceID {
		t.Fatalf("got payable=%+v, want the balance payable again", after)
	}

	// And it cannot be resolved twice.
	if err := repo.ResolvePayoutNotSent(ctx, payoutID, "operator-jane", "again"); !errors.Is(err, db.ErrPayoutAlreadyResolved) {
		t.Errorf("second ResolvePayoutNotSent: got err=%v, want ErrPayoutAlreadyResolved", err)
	}
}

// TestIntegrationResolvePayoutSentRefusesRowWithoutRecordedEntries
// covers the pre-0010 historical row case: with no durable per-entry
// detail there is no safe amount to debit, so resolve-sent must
// refuse rather than guess from live balances.
func TestIntegrationResolvePayoutSentRefusesRowWithoutRecordedEntries(t *testing.T) {
	pool, repo, ctx := freshSchema(t)

	// Insert a payout row the way the pre-0010 code did: no
	// pending_entries at all.
	var payoutID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO payouts (algo, network, status, balance_ids, amount)
		VALUES ('RXM', 'TESTNET', 'AMBIGUOUS', '{1}', 500) RETURNING id`).Scan(&payoutID); err != nil {
		t.Fatalf("inserting a legacy-shaped payout: %v", err)
	}

	err := repo.ResolvePayoutSent(ctx, payoutID, "somehash", 0, "operator-jane", "confirmed")
	if err == nil {
		t.Fatal("ResolvePayoutSent on a row with no pending_entries succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "pending_entries") {
		t.Errorf("got err=%v, want one explaining the missing pending_entries record", err)
	}

	// resolve-not-sent, by contrast, is safe on such a row: it
	// debits nothing, so the missing detail does not matter.
	if err := repo.ResolvePayoutNotSent(ctx, payoutID, "operator-jane", "confirmed absent"); err != nil {
		t.Errorf("ResolvePayoutNotSent on a legacy row: %v, want it to succeed (it debits nothing)", err)
	}
}

// TestIntegrationCompletePayoutSentRefusesAlreadyResolvedRow proves
// the status guard inside CompletePayoutSent's transaction: a
// duplicate completion for the same payout id must not debit the
// balances a second time.
func TestIntegrationCompletePayoutSentRefusesAlreadyResolvedRow(t *testing.T) {
	pool, repo, ctx := freshSchema(t)

	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "alice", nil, 300); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	payable, err := repo.PayableBalances(ctx, "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	entries := []db.DisburseEntry{{BalanceID: payable[0].ID, Amount: 300}}
	payoutID, err := repo.RecordPendingPayout(ctx, "RXM", "TESTNET", entries, 300)
	if err != nil {
		t.Fatalf("RecordPendingPayout: %v", err)
	}
	if err := repo.CompletePayoutSent(ctx, payoutID, entries, "tx1", 1); err != nil {
		t.Fatalf("CompletePayoutSent: %v", err)
	}

	if err := repo.CompletePayoutSent(ctx, payoutID, entries, "tx1", 1); err == nil {
		t.Fatal("second CompletePayoutSent succeeded, want it refused — a duplicate completion would double-debit the miner")
	}

	var pending, paid int64
	if err := pool.QueryRow(ctx, `SELECT pending_balance, paid_balance FROM balance WHERE id = $1`, payable[0].ID).
		Scan(&pending, &paid); err != nil {
		t.Fatalf("querying alice's balance: %v", err)
	}
	if pending != 0 || paid != 300 {
		t.Errorf("got pending=%d paid=%d, want 0/300 — the refused duplicate must have rolled back entirely", pending, paid)
	}
}

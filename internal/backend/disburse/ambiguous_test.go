package disburse

// ambiguous_test.go is the regression suite for the wallet-transfer
// double-payment bug: this package used to record EVERY Transfer
// error as FAILED, which left the miner's balance payable and made
// the very next disbursement cycle send the same coin again. See
// disburse.go's package doc comment and
// db/migrations/0010_payouts_ambiguous_status.up.sql.
//
// Every test here asserts on the property that actually matters —
// "the same coin is not sent twice" — by running a SECOND cycle after
// the failure and checking what it does, rather than only inspecting
// the first cycle's return value.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
)

// TestRunOnce_AmbiguousTransferErrorFreezesBalanceAndHalts is the
// core regression test for FIX_BRIEF finding #2 case (1): a
// slow-but-successful monero-wallet-rpc `transfer` that the HTTP
// client abandons on timeout. The coin may well be gone, so the
// balance must NOT be payable next cycle and the next cycle must pay
// out nothing at all.
func TestRunOnce_AmbiguousTransferErrorFreezesBalanceAndHalts(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
	}}
	// A real client-side timeout: NOT marked wallet.ErrNotBroadcast,
	// because a timeout proves nothing about whether the wallet
	// broadcast the transaction.
	w := &fakeWallet{unlocked: 10000, total: 10000,
		transferErr: fmt.Errorf("wallet: monero: transfer: wallet: monero: transfer request failed: context deadline exceeded")}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err == nil {
		t.Fatal("RunOnce: expected an error for an ambiguous transfer outcome")
	}
	if result.BatchesAmbiguous != 1 {
		t.Fatalf("RunOnce: got %+v, want exactly 1 ambiguous batch", result)
	}
	if result.BatchesFailed != 0 {
		t.Fatalf("RunOnce: got %+v, want 0 FAILED batches — an unproven error must never be recorded as FAILED", result)
	}
	if len(repo.failCalls) != 0 {
		t.Fatalf("got %d FailPayout calls, want 0: FailPayout leaves the balance payable, which is exactly the double-payment bug", len(repo.failCalls))
	}
	if len(repo.ambiguousCalls) != 1 {
		t.Fatalf("got %d MarkPayoutAmbiguous calls, want exactly 1", len(repo.ambiguousCalls))
	}
	if len(repo.sentCalls) != 0 {
		t.Fatalf("got %d CompletePayoutSent calls, want 0 — nothing may be debited on an ambiguous outcome", len(repo.sentCalls))
	}

	// THE POINT OF THE WHOLE FIX: the balance is no longer payable.
	payable, err := repo.PayableBalances(context.Background(), "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 0 {
		t.Fatalf("got payable=%+v after an ambiguous transfer, want NONE — a payable row here means the next cycle re-sends coin that may already have moved", payable)
	}

	// And the next cycle refuses outright rather than paying anything.
	transfersBefore := len(w.transferCall)
	result2, err2 := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if !errors.Is(err2, ErrHalted) {
		t.Fatalf("second RunOnce: got err=%v, want one wrapping ErrHalted", err2)
	}
	if result2.Halted != 1 || result2.Unresolved != 1 {
		t.Fatalf("second RunOnce: got %+v, want Halted=1 Unresolved=1", result2)
	}
	if result2.Batches != 0 || result2.TotalSent != 0 {
		t.Fatalf("second RunOnce: got %+v, want zero batches attempted and nothing sent", result2)
	}
	if len(w.transferCall) != transfersBefore {
		t.Fatalf("second RunOnce: got %d total Transfer calls, want no new ones (%d) — a halted cycle must not touch the wallet",
			len(w.transferCall), transfersBefore)
	}
}

// TestRunOnce_CompletePayoutSentFailureHaltsInsteadOfRetrying covers
// FIX_BRIEF finding #2 case (3): the Transfer SUCCEEDED (there is a
// real tx_hash, coin definitely moved) but the local
// CompletePayoutSent bookkeeping write failed. Previously this logged
// a tx_hash "for manual reconciliation" and nothing consumed it —
// the balance stayed payable and got re-paid. It must now halt.
func TestRunOnce_CompletePayoutSentFailureHaltsInsteadOfRetrying(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {
				{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
			},
		},
		completeErr: errors.New("db: completing payout 1: committing transaction: connection reset by peer"),
	}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferFee: 9}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err == nil {
		t.Fatal("RunOnce: expected an error when CompletePayoutSent fails after a successful Transfer")
	}
	if result.BatchesAmbiguous != 1 || result.BatchesSent != 0 || result.TotalSent != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 ambiguous batch, nothing counted as sent", result)
	}
	if len(repo.failCalls) != 0 {
		t.Fatalf("got %d FailPayout calls, want 0 — the coin provably MOVED here, FAILED would be the opposite of the truth", len(repo.failCalls))
	}
	if len(repo.ambiguousCalls) != 1 {
		t.Fatalf("got %d MarkPayoutAmbiguous calls, want exactly 1", len(repo.ambiguousCalls))
	}
	// The real tx_hash must be recorded on the ambiguous row: it is
	// precisely what the operator needs to confirm the transfer and
	// then resolve it with `backend payout resolve-sent`.
	if got := repo.ambiguousCalls[0].txHash; got == "" {
		t.Error("MarkPayoutAmbiguous: got an empty tx_hash, want the real hash from the successful Transfer recorded for the operator")
	}
	if len(w.transferCall) != 1 {
		t.Fatalf("got %d Transfer calls, want exactly 1", len(w.transferCall))
	}

	// Balance frozen, and the next cycle halts rather than re-sending.
	payable, err := repo.PayableBalances(context.Background(), "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 0 {
		t.Fatalf("got payable=%+v, want NONE — the coin already moved, re-paying would be a double payment", payable)
	}

	result2, err2 := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if !errors.Is(err2, ErrHalted) {
		t.Fatalf("second RunOnce: got err=%v, want one wrapping ErrHalted", err2)
	}
	if result2.Batches != 0 {
		t.Fatalf("second RunOnce: got %+v, want zero batches attempted", result2)
	}
	if len(w.transferCall) != 1 {
		t.Fatalf("second RunOnce: got %d total Transfer calls, want still exactly 1 — the same coin must not be sent again", len(w.transferCall))
	}
}

// TestRunOnce_AmbiguousBatchAbandonsRemainingBatches proves an
// ambiguous outcome stops the CURRENT cycle too, not just subsequent
// ones: once the wallet's state is unknown, this engine must not keep
// moving coin for the same (algo, network).
func TestRunOnce_AmbiguousBatchAbandonsRemainingBatches(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "a", PendingBalance: 100},
			{ID: 2, PaymentAddress: "b", PendingBalance: 100},
			{ID: 3, PaymentAddress: "c", PendingBalance: 100},
			{ID: 4, PaymentAddress: "d", PendingBalance: 100},
			{ID: 5, PaymentAddress: "e", PendingBalance: 100},
			{ID: 6, PaymentAddress: "f", PendingBalance: 100},
		},
	}}
	// MaxDestinationsPerBatch is 2 in testConfig, so this is 3
	// batches; the FIRST one goes ambiguous.
	w := &fakeWallet{unlocked: 100000, total: 100000, transferErr: errors.New("i/o timeout")}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err == nil {
		t.Fatal("RunOnce: expected an error for an ambiguous batch")
	}
	if result.Batches != 1 {
		t.Fatalf("RunOnce: got %+v, want exactly 1 batch ATTEMPTED (the remaining 2 must be abandoned)", result)
	}
	if len(w.transferCall) != 1 {
		t.Fatalf("got %d Transfer calls, want exactly 1 — the engine must stop moving coin after an ambiguous outcome", len(w.transferCall))
	}
	if len(repo.pendingCalls) != 1 {
		t.Fatalf("got %d RecordPendingPayout calls, want exactly 1 — no further payout rows may be created", len(repo.pendingCalls))
	}
}

// TestRunOnce_HaltsOnPreexistingPendingPayout covers FIX_BRIEF
// finding #2 case (3)'s other half: a PENDING row (recorded before a
// Transfer call whose process then died) previously had NO reader
// anywhere and blocked nothing. It must now halt disbursement exactly
// like AMBIGUOUS does — a crash mid-transfer is every bit as
// unknown-outcome as a timeout.
func TestRunOnce_HaltsOnPreexistingPendingPayout(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {
				{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
			},
		},
		unresolved: map[string][]UnresolvedPayout{
			key("RXM", "TESTNET"): {{
				ID: 77, Status: "PENDING", Amount: 500, BalanceIDs: []int64{1},
				Created: time.Now().Add(-time.Hour),
			}},
		},
	}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if !errors.Is(err, ErrHalted) {
		t.Fatalf("RunOnce: got err=%v, want one wrapping ErrHalted", err)
	}
	if result.Halted != 1 || result.Unresolved != 1 {
		t.Fatalf("RunOnce: got %+v, want Halted=1 Unresolved=1", result)
	}
	if len(w.transferCall) != 0 {
		t.Fatalf("got %d Transfer calls, want 0 — a halted cycle must not touch the wallet at all", len(w.transferCall))
	}
	if len(repo.pendingCalls) != 0 {
		t.Fatalf("got %d RecordPendingPayout calls, want 0", len(repo.pendingCalls))
	}
}

// TestRunOnce_HaltIsScopedToItsOwnAlgoNetwork proves the halt does not
// leak: a stuck RXM/TESTNET must not stop RXM/MAINNET (or any other
// pair) from paying out. One stuck coin freezing every other coin's
// payouts would be its own incident.
func TestRunOnce_HaltIsScopedToItsOwnAlgoNetwork(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {{ID: 1, PaymentAddress: "alice", PendingBalance: 500}},
			key("RXM", "MAINNET"): {{ID: 2, PaymentAddress: "bob", PendingBalance: 700}},
		},
		unresolved: map[string][]UnresolvedPayout{
			key("RXM", "TESTNET"): {{ID: 5, Status: "AMBIGUOUS", Amount: 500, BalanceIDs: []int64{1}}},
		},
	}
	w := &fakeWallet{unlocked: 100000, total: 100000}
	e := New(repo, testConfig(w))

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); !errors.Is(err, ErrHalted) {
		t.Fatalf("RXM/TESTNET: got err=%v, want ErrHalted", err)
	}

	result, err := e.RunOnce(context.Background(), "RXM", "MAINNET")
	if err != nil {
		t.Fatalf("RXM/MAINNET: unexpected error: %v", err)
	}
	if result.Halted != 0 || result.BatchesSent != 1 || result.TotalSent != 700 {
		t.Fatalf("RXM/MAINNET: got %+v, want an unaffected, fully successful cycle (1 batch, 700 sent)", result)
	}
}

// TestRunOnce_UnresolvedPayoutsQueryErrorIsFatalToTheCycle proves the
// halt gate fails CLOSED: if the engine cannot even determine whether
// an unresolved payout exists, it must not proceed. "The check
// errored" is emphatically not "there is nothing unresolved".
func TestRunOnce_UnresolvedPayoutsQueryErrorIsFatalToTheCycle(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {{ID: 1, PaymentAddress: "alice", PendingBalance: 500}},
		},
		unresolvedErr: errors.New("connection refused"),
	}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w))

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); err == nil {
		t.Fatal("RunOnce: expected an error when the unresolved-payout check itself fails")
	}
	if len(w.transferCall) != 0 {
		t.Fatalf("got %d Transfer calls, want 0 — the engine must not pay out when it cannot verify it is safe to", len(w.transferCall))
	}
}

// TestRunOnce_MarkPayoutAmbiguousFailureStillLeavesBalanceFrozen
// covers the worst case: the transfer outcome is ambiguous AND the
// attempt to record that fails. The PENDING row written before the
// transfer is itself an unresolved status, so the safety property
// must hold anyway — balances frozen, next cycle halted.
func TestRunOnce_MarkPayoutAmbiguousFailureStillLeavesBalanceFrozen(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {{ID: 1, PaymentAddress: "alice", PendingBalance: 500}},
		},
		ambiguousErr: errors.New("db: marking payout ambiguous: connection reset"),
	}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferErr: errors.New("i/o timeout")}
	e := New(repo, testConfig(w))

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); err == nil {
		t.Fatal("RunOnce: expected an error for an ambiguous transfer outcome")
	}

	payable, err := repo.PayableBalances(context.Background(), "RXM", "TESTNET", 100)
	if err != nil {
		t.Fatalf("PayableBalances: %v", err)
	}
	if len(payable) != 0 {
		t.Fatalf("got payable=%+v, want NONE — the PENDING row alone must still freeze the balance", payable)
	}
	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); !errors.Is(err, ErrHalted) {
		t.Fatalf("second RunOnce: got err=%v, want ErrHalted from the still-PENDING row", err)
	}
}

// TestRecordPendingPayoutPersistsPerEntryDebitDetail proves the
// engine hands the FULL per-balance debit detail to
// RecordPendingPayout before attempting the transfer, and that it is
// byte-for-byte what CompletePayoutSent later uses. That durable
// record is what makes `backend payout resolve-sent` able to replay
// the exact debit instead of guessing from live balances.
func TestRecordPendingPayoutPersistsPerEntryDebitDetail(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "forced", PendingBalance: 40, ForcePayout: true},
			{ID: 2, PaymentAddress: "normal", PendingBalance: 500},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferFee: 3}
	cfg := testConfig(w)
	cfg.ForcePayoutFeeAtomic = 10
	e := New(repo, cfg)

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if len(repo.pendingCalls) != 1 {
		t.Fatalf("got %d RecordPendingPayout calls, want 1", len(repo.pendingCalls))
	}
	pending := repo.pendingCalls[0]

	// amount is the real on-chain destination total (40-10 + 500).
	if pending.amount != 530 {
		t.Errorf("RecordPendingPayout: got amount=%d, want 530 (the real destination total, after the force-payout fee)", pending.amount)
	}
	// balance_ids is still derived for the real column.
	if got := pending.balanceIDs(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("RecordPendingPayout: got balance_ids=%v, want [1 2]", got)
	}

	byID := map[int64]DebitEntry{}
	for _, e := range pending.entries {
		byID[e.BalanceID] = e
	}
	forced := byID[1]
	if forced.Amount != 40 || !forced.ForcePayout || forced.ForcePayoutFeeAtomic != 10 {
		t.Errorf("RecordPendingPayout: forced entry = %+v, want Amount=40 (FULL pending_balance) ForcePayout=true fee=10", forced)
	}
	normal := byID[2]
	if normal.Amount != 500 || normal.ForcePayout || normal.ForcePayoutFeeAtomic != 0 {
		t.Errorf("RecordPendingPayout: normal entry = %+v, want Amount=500 ForcePayout=false fee=0", normal)
	}

	// Pre-attempt record and post-success debit must be identical:
	// if they could differ, resolve-sent would replay the wrong
	// amounts.
	if len(repo.sentCalls) != 1 {
		t.Fatalf("got %d CompletePayoutSent calls, want 1", len(repo.sentCalls))
	}
	if fmt.Sprint(repo.sentCalls[0].entries) != fmt.Sprint(pending.entries) {
		t.Errorf("CompletePayoutSent entries %v differ from the pre-attempt RecordPendingPayout entries %v — resolve-sent replays the recorded set, so they must match exactly",
			repo.sentCalls[0].entries, pending.entries)
	}
}

// TestCheckTargets_PartitionsSafeAndBlockedTargets covers the startup
// check cmd/backend runs before starting RunLoop: a pair with any
// unresolved payout must be reported blocked (and so never get a
// loop), while healthy pairs pass through untouched.
func TestCheckTargets_PartitionsSafeAndBlockedTargets(t *testing.T) {
	repo := &fakeRepo{
		unresolved: map[string][]UnresolvedPayout{
			key("SHA3X", "MAINNET"): {{ID: 9, Status: "AMBIGUOUS", Amount: 1234, BalanceIDs: []int64{3}}},
		},
	}
	e := New(repo, testConfig(&fakeWallet{}))

	targets := []Target{
		{Algo: "RXT", Network: "MAINNET"},
		{Algo: "SHA3X", Network: "MAINNET"},
		{Algo: "C29", Network: "MAINNET"},
	}
	safe, blocked, err := e.CheckTargets(context.Background(), targets)
	if err != nil {
		t.Fatalf("CheckTargets: unexpected error: %v", err)
	}
	if len(safe) != 2 || safe[0].Algo != "RXT" || safe[1].Algo != "C29" {
		t.Fatalf("CheckTargets: got safe=%+v, want RXT and C29 in order", safe)
	}
	if len(blocked) != 1 {
		t.Fatalf("CheckTargets: got blocked=%+v, want exactly SHA3X/MAINNET", blocked)
	}
	if blocked[0].Target.Algo != "SHA3X" || len(blocked[0].Unresolved) != 1 || blocked[0].Unresolved[0].ID != 9 {
		t.Fatalf("CheckTargets: got blocked[0]=%+v, want SHA3X/MAINNET carrying unresolved payout id 9", blocked[0])
	}
}

// TestCheckTargets_RepositoryErrorIsReturnedNotSwallowed proves the
// startup check fails closed. cmd/backend treats this error as fatal:
// it must never be possible to start disbursement because the safety
// check happened to be unavailable.
func TestCheckTargets_RepositoryErrorIsReturnedNotSwallowed(t *testing.T) {
	repo := &fakeRepo{unresolvedErr: errors.New("connection refused")}
	e := New(repo, testConfig(&fakeWallet{}))

	safe, blocked, err := e.CheckTargets(context.Background(), []Target{{Algo: "RXM", Network: "TESTNET"}})
	if err == nil {
		t.Fatal("CheckTargets: expected an error when the repository query fails")
	}
	if safe != nil || blocked != nil {
		t.Fatalf("CheckTargets: got safe=%+v blocked=%+v, want both nil on error (a caller must not be able to mistake a failed check for an all-clear)", safe, blocked)
	}
}

// TestRunLoop_HaltedTargetNeverMovesCoin is the belt-and-braces check
// on RunLoop itself: even if a halted target IS passed in (e.g. it
// became halted after the startup check ran), every tick pays out
// nothing for it, and the loop keeps running for everyone else.
func TestRunLoop_HaltedTargetNeverMovesCoin(t *testing.T) {
	repo := &fakeRepo{
		balances: map[string][]PayableBalance{
			key("RXM", "TESTNET"): {{ID: 1, PaymentAddress: "alice", PendingBalance: 500}},
		},
		unresolved: map[string][]UnresolvedPayout{
			key("RXM", "TESTNET"): {{ID: 1, Status: "AMBIGUOUS", Amount: 500, BalanceIDs: []int64{1}}},
		},
	}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.RunLoop(ctx, []Target{{Algo: "RXM", Network: "TESTNET"}}, time.Millisecond)
	}()
	// Let several ticks elapse, then stop the loop.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(w.transferCall) != 0 {
		t.Fatalf("got %d Transfer calls across many ticks, want 0 — a halted target must never move coin", len(w.transferCall))
	}
	if len(repo.pendingCalls) != 0 {
		t.Fatalf("got %d RecordPendingPayout calls, want 0", len(repo.pendingCalls))
	}
}

// TestWalletErrNotBroadcastRoundTripsThroughWrapping guards the one
// mechanism the whole FAILED-vs-AMBIGUOUS decision rests on: the
// marking must survive the fmt.Errorf("%w") wrapping every wallet
// implementation applies on the way out. If this ever breaks, every
// hard rejection silently becomes an ambiguous halt (annoying) — and,
// far worse, a refactor that loses the negative case would turn every
// timeout back into a double payment.
func TestWalletErrNotBroadcastRoundTripsThroughWrapping(t *testing.T) {
	marked := wallet.NotBroadcast(errors.New("monero wallet rpc error -2: invalid address"))
	wrapped := fmt.Errorf("wallet: monero: transfer: %w", marked)
	if !errors.Is(wrapped, wallet.ErrNotBroadcast) {
		t.Error("errors.Is(wrapped, ErrNotBroadcast) = false, want true: the marking must survive wrapping")
	}
	if got, want := wrapped.Error(), "wallet: monero: transfer: monero wallet rpc error -2: invalid address"; got != want {
		t.Errorf("wrapped.Error() = %q, want %q: marking must not alter the message", got, want)
	}

	plain := fmt.Errorf("wallet: monero: transfer: %w", errors.New("context deadline exceeded"))
	if errors.Is(plain, wallet.ErrNotBroadcast) {
		t.Error("errors.Is(plain, ErrNotBroadcast) = true, want false: an unmarked error must default to ambiguous")
	}
	if wallet.NotBroadcast(nil) != nil {
		t.Error("NotBroadcast(nil) != nil, want nil")
	}
}

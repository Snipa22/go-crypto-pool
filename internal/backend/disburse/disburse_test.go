package disburse

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
)

// fakeRepo is an in-memory Repository test double, mirroring
// unlocker/payout's fakeRepo style.
type fakeRepo struct {
	balances     map[string][]PayableBalance // keyed by "algo/network"
	pendingCalls []pendingCall
	sentCalls    []sentCall
	failCalls    []failCall
	nextPayoutID int64
	recordErr    error
	completeErr  error
	failErr      error
}

type pendingCall struct {
	algo, network string
	balanceIDs    []int64
	amount        int64
}

type sentCall struct {
	payoutID int64
	entries  []DebitEntry
	txHash   string
	fee      int64
}

type failCall struct {
	payoutID int64
	errMsg   string
}

func key(algo, network string) string { return algo + "/" + network }

func (f *fakeRepo) PayableBalances(_ context.Context, algo, network string, minPayout int64) ([]PayableBalance, error) {
	var out []PayableBalance
	for _, b := range f.balances[key(algo, network)] {
		// Mirrors db.Repository.PayableBalances' real SQL: a row is
		// payable if it meets minPayout on its own OR is
		// force_payout-flagged, provided pending_balance > 0 either
		// way.
		if b.PendingBalance > 0 && (b.PendingBalance >= minPayout || b.ForcePayout) {
			out = append(out, b)
		}
	}
	return out, nil
}

func (f *fakeRepo) RecordPendingPayout(_ context.Context, algo, network string, balanceIDs []int64, amount int64) (int64, error) {
	if f.recordErr != nil {
		return 0, f.recordErr
	}
	f.nextPayoutID++
	f.pendingCalls = append(f.pendingCalls, pendingCall{algo, network, balanceIDs, amount})
	return f.nextPayoutID, nil
}

func (f *fakeRepo) CompletePayoutSent(_ context.Context, payoutID int64, entries []DebitEntry, txHash string, fee int64) error {
	if f.completeErr != nil {
		return f.completeErr
	}
	f.sentCalls = append(f.sentCalls, sentCall{payoutID, entries, txHash, fee})
	return nil
}

func (f *fakeRepo) FailPayout(_ context.Context, payoutID int64, errMsg string) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.failCalls = append(f.failCalls, failCall{payoutID, errMsg})
	return nil
}

// fakeWallet is an in-memory wallet.WalletClient test double.
type fakeWallet struct {
	unlocked     int64
	total        int64
	transferErr  error
	transferFee  int64
	transferCall []wallet.TransferRequest
	txHashSeq    int
}

func (f *fakeWallet) GetBalance(_ context.Context) (wallet.Balance, error) {
	return wallet.Balance{Total: f.total, Unlocked: f.unlocked}, nil
}

func (f *fakeWallet) Transfer(_ context.Context, req wallet.TransferRequest) (wallet.TransferResult, error) {
	f.transferCall = append(f.transferCall, req)
	if f.transferErr != nil {
		return wallet.TransferResult{}, f.transferErr
	}
	var amount int64
	for _, d := range req.Destinations {
		amount += d.Amount
	}
	f.txHashSeq++
	return wallet.TransferResult{
		TxHash: "tx" + string(rune('0'+f.txHashSeq)),
		Fee:    f.transferFee,
		Amount: amount,
	}, nil
}

func testConfig(w wallet.WalletClient) Config {
	return Config{
		Wallet:                  w,
		MinPayoutAtomic:         100,
		MaxDestinationsPerBatch: 2,
	}
}

func TestRunOnce_NoPayableBalances(t *testing.T) {
	repo := &fakeRepo{}
	w := &fakeWallet{unlocked: 1000, total: 1000}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.Payable != 0 || result.Batches != 0 {
		t.Fatalf("RunOnce: got %+v, want a no-op result", result)
	}
}

func TestRunOnce_SendsBatchAndDebits(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
			{ID: 2, PaymentAddress: "bob", PendingBalance: 300},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferFee: 10}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.Payable != 2 || result.Batches != 1 || result.BatchesSent != 1 || result.BatchesFailed != 0 {
		t.Fatalf("RunOnce: got %+v, want 2 payable / 1 batch sent", result)
	}
	if result.TotalSent != 800 || result.TotalFees != 10 {
		t.Fatalf("RunOnce: got TotalSent=%d TotalFees=%d, want 800/10", result.TotalSent, result.TotalFees)
	}
	if len(repo.pendingCalls) != 1 || repo.pendingCalls[0].amount != 800 {
		t.Fatalf("RunOnce: got pendingCalls=%+v, want one call for amount 800", repo.pendingCalls)
	}
	if len(repo.sentCalls) != 1 || len(repo.sentCalls[0].entries) != 2 {
		t.Fatalf("RunOnce: got sentCalls=%+v, want one completion covering 2 entries", repo.sentCalls)
	}
	if len(w.transferCall) != 1 || len(w.transferCall[0].Destinations) != 2 {
		t.Fatalf("RunOnce: got %d Transfer calls, want exactly 1 with 2 destinations", len(w.transferCall))
	}
}

func TestRunOnce_SplitsIntoMultipleBatches(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "a", PendingBalance: 100},
			{ID: 2, PaymentAddress: "b", PendingBalance: 100},
			{ID: 3, PaymentAddress: "c", PendingBalance: 100},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w)) // MaxDestinationsPerBatch = 2

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.Batches != 2 || result.BatchesSent != 2 {
		t.Fatalf("RunOnce: got %+v, want 2 batches (2+1 destinations)", result)
	}
}

func TestRunOnce_SeparatesDistinctPaymentIDsIntoOwnBatches(t *testing.T) {
	pid1, pid2 := "paymentid-one", "paymentid-two"
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "a", PendingBalance: 100, PaymentID: &pid1},
			{ID: 2, PaymentAddress: "b", PendingBalance: 100},
			{ID: 3, PaymentAddress: "c", PendingBalance: 100, PaymentID: &pid2},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	// One batch for pid1 (single dest), one for the plain address, one
	// for pid2 -- 3 total, none sharing a payment_id.
	if result.Batches != 3 {
		t.Fatalf("RunOnce: got %d batches, want 3 (each distinct payment_id isolated)", result.Batches)
	}
	seenPIDs := map[string]bool{}
	for _, call := range w.transferCall {
		if call.PaymentID != "" {
			if seenPIDs[call.PaymentID] {
				t.Fatalf("RunOnce: payment_id %q used in more than one Transfer call", call.PaymentID)
			}
			seenPIDs[call.PaymentID] = true
		}
	}
}

func TestRunOnce_SkipsWholeCycleOnInsufficientUnlockedBalance(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
	}}
	w := &fakeWallet{unlocked: 100, total: 10000}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.Skipped != 1 || result.Batches != 0 {
		t.Fatalf("RunOnce: got %+v, want the cycle skipped with zero batches attempted", result)
	}
	if len(repo.pendingCalls) != 0 {
		t.Fatalf("RunOnce: got %d RecordPendingPayout calls, want 0 on a skipped cycle", len(repo.pendingCalls))
	}
}

func TestRunOnce_FailedTransferNeverDebitsBalance(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "alice", PendingBalance: 500},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferErr: errors.New("not enough unlocked money")}
	e := New(repo, testConfig(w))

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected top-level error: %v", err)
	}
	if result.BatchesFailed != 1 || result.BatchesSent != 0 || result.TotalSent != 0 {
		t.Fatalf("RunOnce: got %+v, want 1 failed batch and zero sent", result)
	}
	if len(repo.sentCalls) != 0 {
		t.Fatalf("RunOnce: got %d CompletePayoutSent calls, want 0 for a failed transfer", len(repo.sentCalls))
	}
	if len(repo.failCalls) != 1 {
		t.Fatalf("RunOnce: got %d FailPayout calls, want exactly 1", len(repo.failCalls))
	}
}

func TestRunOnce_RequiresWalletAndMaxDestinations(t *testing.T) {
	repo := &fakeRepo{}
	if _, err := New(repo, Config{MaxDestinationsPerBatch: 1}).RunOnce(context.Background(), "RXM", "TESTNET"); err == nil {
		t.Fatal("RunOnce: expected an error when Config.Wallet is nil")
	}
	if _, err := New(repo, Config{Wallet: &fakeWallet{}}).RunOnce(context.Background(), "RXM", "TESTNET"); err == nil {
		t.Fatal("RunOnce: expected an error when Config.MaxDestinationsPerBatch <= 0")
	}
}

// TestRunOnce_ForcePayoutRowBelowThresholdIsPaidWithFeeDeducted covers
// the core bug this package's PayableBalances/runBatch changes fix: a
// force_payout row below the normal MinPayoutAtomic threshold is
// still paid this cycle, and — per Alex's explicit fee requirement —
// has ForcePayoutFeeAtomic deducted from its real Transfer
// destination amount, while a normal (non-forced) row in the very
// same batch is completely unaffected by the fee.
func TestRunOnce_ForcePayoutRowBelowThresholdIsPaidWithFeeDeducted(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			// Below MinPayoutAtomic (100) but force_payout=TRUE --
			// must still be included and paid.
			{ID: 1, PaymentAddress: "forced", PendingBalance: 40, ForcePayout: true},
			// A normal row, well above threshold, not forced.
			{ID: 2, PaymentAddress: "normal", PendingBalance: 500, ForcePayout: false},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000, transferFee: 7}
	cfg := testConfig(w)
	cfg.ForcePayoutFeeAtomic = 10
	e := New(repo, cfg)

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.Payable != 2 || result.BatchesSent != 1 {
		t.Fatalf("RunOnce: got %+v, want both rows payable in one sent batch", result)
	}

	if len(w.transferCall) != 1 {
		t.Fatalf("RunOnce: got %d Transfer calls, want exactly 1", len(w.transferCall))
	}
	dests := map[string]int64{}
	for _, d := range w.transferCall[0].Destinations {
		dests[d.Address] = d.Amount
	}
	if dests["forced"] != 30 {
		t.Errorf("forced row: got Transfer destination amount %d, want 40-10=30", dests["forced"])
	}
	if dests["normal"] != 500 {
		t.Errorf("normal row: got Transfer destination amount %d, want unaffected 500", dests["normal"])
	}

	if len(repo.sentCalls) != 1 {
		t.Fatalf("RunOnce: got %d CompletePayoutSent calls, want 1", len(repo.sentCalls))
	}
	entries := map[int64]DebitEntry{}
	for _, e := range repo.sentCalls[0].entries {
		entries[e.BalanceID] = e
	}
	forcedEntry, ok := entries[1]
	if !ok {
		t.Fatalf("CompletePayoutSent: missing entry for forced balance id 1")
	}
	if !forcedEntry.ForcePayout || forcedEntry.ForcePayoutFeeAtomic != 10 || forcedEntry.Amount != 40 {
		t.Errorf("forced entry: got %+v, want ForcePayout=true ForcePayoutFeeAtomic=10 Amount=40", forcedEntry)
	}
	normalEntry, ok := entries[2]
	if !ok {
		t.Fatalf("CompletePayoutSent: missing entry for normal balance id 2")
	}
	if normalEntry.ForcePayout || normalEntry.ForcePayoutFeeAtomic != 0 || normalEntry.Amount != 500 {
		t.Errorf("normal entry: got %+v, want ForcePayout=false ForcePayoutFeeAtomic=0 Amount=500", normalEntry)
	}
}

// TestRunOnce_ForcePayoutFeeAppliesEvenIfRowAlreadyClearedThreshold
// covers Alex's explicit choice: the fee applies to EVERY
// force_payout row paid this cycle, even one whose PendingBalance
// already met MinPayoutAtomic on its own -- there is no "would have
// qualified anyway" exemption.
func TestRunOnce_ForcePayoutFeeAppliesEvenIfRowAlreadyClearedThreshold(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "forced-but-qualified", PendingBalance: 1000, ForcePayout: true},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	cfg := testConfig(w)
	cfg.ForcePayoutFeeAtomic = 25
	e := New(repo, cfg)

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if len(w.transferCall) != 1 || len(w.transferCall[0].Destinations) != 1 {
		t.Fatalf("RunOnce: got %d Transfer calls, want exactly 1 with 1 destination", len(w.transferCall))
	}
	if got := w.transferCall[0].Destinations[0].Amount; got != 975 {
		t.Errorf("got Transfer destination amount %d, want 1000-25=975 even though the row already cleared MinPayoutAtomic on its own", got)
	}
}

// TestRunOnce_ForcePayoutFeeEdgeCaseCapsAtOneAtomicUnit covers this
// package's chosen edge-case behavior (see runBatch's doc comment):
// when a force_payout row's PendingBalance is <= the configured
// ForcePayoutFeeAtomic, the fee is capped so the miner still receives
// at least 1 atomic unit, rather than sending zero/negative to the
// real wallet RPC or silently skipping the row.
func TestRunOnce_ForcePayoutFeeEdgeCaseCapsAtOneAtomicUnit(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "tiny-forced", PendingBalance: 5, ForcePayout: true},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	cfg := testConfig(w)
	cfg.ForcePayoutFeeAtomic = 500 // way more than the 5-atomic-unit balance
	e := New(repo, cfg)

	result, err := e.RunOnce(context.Background(), "RXM", "TESTNET")
	if err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if result.BatchesSent != 1 {
		t.Fatalf("RunOnce: got %+v, want the edge-case row still sent (not skipped)", result)
	}
	if len(w.transferCall) != 1 || len(w.transferCall[0].Destinations) != 1 {
		t.Fatalf("RunOnce: got %d Transfer calls, want exactly 1 with 1 destination", len(w.transferCall))
	}
	if got := w.transferCall[0].Destinations[0].Amount; got != 1 {
		t.Errorf("got Transfer destination amount %d, want capped to 1 atomic unit (never zero/negative)", got)
	}
	if len(repo.sentCalls) != 1 || len(repo.sentCalls[0].entries) != 1 {
		t.Fatalf("RunOnce: got sentCalls=%+v, want 1 completion with 1 entry", repo.sentCalls)
	}
	entry := repo.sentCalls[0].entries[0]
	if entry.Amount != 5 {
		t.Errorf("got debited Amount %d, want the FULL original PendingBalance 5 debited regardless of the fee cap", entry.Amount)
	}
	if entry.ForcePayoutFeeAtomic != 4 {
		t.Errorf("got ForcePayoutFeeAtomic %d, want the capped fee 5-1=4 (not the full configured 500)", entry.ForcePayoutFeeAtomic)
	}
}

// TestRunOnce_ForcePayoutFeeDefaultZeroMeansNoFee confirms the
// "zero means off" convention: a force_payout row is still paid in
// full (no deduction at all) when ForcePayoutFeeAtomic is left at its
// zero default.
func TestRunOnce_ForcePayoutFeeDefaultZeroMeansNoFee(t *testing.T) {
	repo := &fakeRepo{balances: map[string][]PayableBalance{
		key("RXM", "TESTNET"): {
			{ID: 1, PaymentAddress: "forced", PendingBalance: 40, ForcePayout: true},
		},
	}}
	w := &fakeWallet{unlocked: 10000, total: 10000}
	e := New(repo, testConfig(w)) // ForcePayoutFeeAtomic left at zero default

	if _, err := e.RunOnce(context.Background(), "RXM", "TESTNET"); err != nil {
		t.Fatalf("RunOnce: unexpected error: %v", err)
	}
	if len(w.transferCall) != 1 || len(w.transferCall[0].Destinations) != 1 {
		t.Fatalf("RunOnce: got %d Transfer calls, want exactly 1 with 1 destination", len(w.transferCall))
	}
	if got := w.transferCall[0].Destinations[0].Amount; got != 40 {
		t.Errorf("got Transfer destination amount %d, want the full 40 (no fee configured)", got)
	}
	if len(repo.sentCalls) != 1 || repo.sentCalls[0].entries[0].ForcePayoutFeeAtomic != 0 {
		t.Fatalf("RunOnce: got sentCalls=%+v, want ForcePayoutFeeAtomic=0", repo.sentCalls)
	}
}

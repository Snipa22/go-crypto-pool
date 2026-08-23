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
		if b.PendingBalance >= minPayout {
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

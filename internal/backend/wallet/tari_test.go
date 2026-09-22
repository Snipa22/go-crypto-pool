// Copyright and license: see repository LICENSE (MIT).
package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
)

// fakeTariWalletRPC is an in-memory tariWalletRPC test double.
type fakeTariWalletRPC struct {
	transferResp *tari_generated.TransferResponse
	transferErr  error
	balanceResp  *tari_generated.GetBalanceResponse
	balanceErr   error
	txInfoByID   map[uint64]*tari_generated.TransactionInfo
	txInfoErr    error

	gotRecipients []*tari_generated.PaymentRecipient
	gotTxInfoIDs  []uint64
}

func (f *fakeTariWalletRPC) Transfer(_ context.Context, recipients []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	f.gotRecipients = recipients
	if f.transferErr != nil {
		return nil, f.transferErr
	}
	return f.transferResp, nil
}

func (f *fakeTariWalletRPC) GetBalance(_ context.Context) (*tari_generated.GetBalanceResponse, error) {
	if f.balanceErr != nil {
		return nil, f.balanceErr
	}
	return f.balanceResp, nil
}

func (f *fakeTariWalletRPC) GetTransactionInfo(_ context.Context, transactionID uint64) (*tari_generated.TransactionInfo, error) {
	f.gotTxInfoIDs = append(f.gotTxInfoIDs, transactionID)
	if f.txInfoErr != nil {
		return nil, f.txInfoErr
	}
	return f.txInfoByID[transactionID], nil
}

func TestTariWalletGRPC_Transfer_Success(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{
				{
					Address:       "t1abc",
					TransactionId: 42,
					IsSuccess:     true,
					TransactionInfo: &tari_generated.TransactionInfo{
						TxId:   42,
						Amount: 1000000,
						Fee:    100,
					},
				},
			},
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, 25)

	got, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1abc", Amount: 1000000}},
	})
	if err != nil {
		t.Fatalf("Transfer: unexpected error: %v", err)
	}
	if got.TxHash != "42" {
		t.Fatalf("Transfer: got TxHash=%q, want %q", got.TxHash, "42")
	}
	if got.Fee != 100 {
		t.Fatalf("Transfer: got Fee=%d, want 100", got.Fee)
	}
	if got.Amount != 1000000 {
		t.Fatalf("Transfer: got Amount=%d, want 1000000", got.Amount)
	}
	if len(rpc.gotRecipients) != 1 {
		t.Fatalf("Transfer: got %d recipients sent to RPC, want 1", len(rpc.gotRecipients))
	}
	if rpc.gotRecipients[0].FeePerGram != 25 {
		t.Fatalf("Transfer: got FeePerGram=%d, want default 25 (Priority was 0)", rpc.gotRecipients[0].FeePerGram)
	}
	if rpc.gotRecipients[0].PaymentType != tari_generated.PaymentRecipient_ONE_SIDED_TO_STEALTH_ADDRESS {
		t.Fatalf("Transfer: got PaymentType=%v, want ONE_SIDED_TO_STEALTH_ADDRESS", rpc.gotRecipients[0].PaymentType)
	}
}

func TestTariWalletGRPC_Transfer_PriorityOverridesFeePerGram(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{
				{Address: "t1abc", TransactionId: 1, IsSuccess: true, TransactionInfo: &tari_generated.TransactionInfo{Amount: 5, Fee: 1}},
			},
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1abc", Amount: 5}},
		Priority:     50,
	})
	if err != nil {
		t.Fatalf("Transfer: unexpected error: %v", err)
	}
	if rpc.gotRecipients[0].FeePerGram != 50 {
		t.Fatalf("Transfer: got FeePerGram=%d, want 50 (from req.Priority)", rpc.gotRecipients[0].FeePerGram)
	}
}

func TestTariWalletGRPC_Transfer_MultipleDestinationsRejected(t *testing.T) {
	// Real safety constraint (see Transfer's own doc comment): the
	// real Tari Transfer RPC reports success/failure PER RECIPIENT,
	// but this WalletClient implementation's contract is strictly
	// all-or-nothing (matching disburse.Engine's own real safety
	// assumption). Until the interface carries real per-destination
	// results, more than one destination per call must be refused
	// outright -- not attempted and then silently mis-reported as a
	// single all-or-nothing outcome, which is what the OLD (buggy)
	// behavior did and which risked a real double-payment on a
	// genuine partial failure.
	rpc := &fakeTariWalletRPC{}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1aaa", Amount: 100}, {Address: "t1bbb", Amount: 200}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error for a multi-destination request, got nil")
	}
	if rpc.gotRecipients != nil {
		t.Fatal("Transfer: the real RPC must never be called for a rejected multi-destination request -- no partial on-chain effects can occur if the call never happens")
	}
}

func TestTariWalletGRPC_Transfer_FallsBackToGetTransactionInfoWhenMissingInline(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{
				{Address: "t1abc", TransactionId: 7, IsSuccess: true}, // no inline TransactionInfo
			},
		},
		txInfoByID: map[uint64]*tari_generated.TransactionInfo{
			7: {TxId: 7, Amount: 900, Fee: 9},
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	got, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1abc", Amount: 900}},
	})
	if err != nil {
		t.Fatalf("Transfer: unexpected error: %v", err)
	}
	if got.Fee != 9 || got.Amount != 900 {
		t.Fatalf("Transfer: got Fee=%d Amount=%d, want Fee=9 Amount=900 (from GetTransactionInfo fallback)", got.Fee, got.Amount)
	}
	if len(rpc.gotTxInfoIDs) != 1 || rpc.gotTxInfoIDs[0] != 7 {
		t.Fatalf("Transfer: GetTransactionInfo called with %v, want [7]", rpc.gotTxInfoIDs)
	}
}

func TestTariWalletGRPC_Transfer_RecipientFailureIsAnError(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{
				{Address: "t1bbb", IsSuccess: false, FailureMessage: "insufficient funds"},
			},
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1bbb", Amount: 200}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error when the sole recipient fails")
	}
}

func TestTariWalletGRPC_Transfer_NoDestinations(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{}, defaultFeePerGram)
	if _, err := w.Transfer(context.Background(), TransferRequest{}); err == nil {
		t.Fatal("Transfer: expected an error for zero destinations")
	}
}

func TestTariWalletGRPC_Transfer_NonPositiveAmount(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{}, defaultFeePerGram)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1abc", Amount: 0}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error for a non-positive destination amount")
	}
}

func TestTariWalletGRPC_Transfer_EmptyAddress(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{}, defaultFeePerGram)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "", Amount: 100}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error for an empty destination address")
	}
}

func TestTariWalletGRPC_Transfer_RPCErrorPropagates(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{transferErr: errors.New("connection refused")}, defaultFeePerGram)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1abc", Amount: 100}},
	})
	if err == nil {
		t.Fatal("Transfer: expected an error when the RPC call fails")
	}
}

func TestTariWalletGRPC_Transfer_PaymentIDAttachedToRecipient(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{
				{Address: "t1aaa", TransactionId: 1, IsSuccess: true, TransactionInfo: &tari_generated.TransactionInfo{Amount: 100, Fee: 1}},
			},
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "t1aaa", Amount: 100}},
		PaymentID:    "payout-batch-9",
	})
	if err != nil {
		t.Fatalf("Transfer: unexpected error: %v", err)
	}
	for i, r := range rpc.gotRecipients {
		if string(r.RawPaymentId) != "payout-batch-9" {
			t.Fatalf("Transfer: recipient %d got RawPaymentId=%q, want %q", i, string(r.RawPaymentId), "payout-batch-9")
		}
	}
}

func TestTariWalletGRPC_GetBalance(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		balanceResp: &tari_generated.GetBalanceResponse{
			AvailableBalance:       1000,
			PendingIncomingBalance: 200,
			PendingOutgoingBalance: 50,
			TimelockedBalance:      300,
		},
	}
	w := newTariWalletGRPCWithRPC(rpc, defaultFeePerGram)

	got, err := w.GetBalance(context.Background())
	if err != nil {
		t.Fatalf("GetBalance: unexpected error: %v", err)
	}
	if got.Unlocked != 1000 {
		t.Fatalf("GetBalance: got Unlocked=%d, want 1000 (available_balance only)", got.Unlocked)
	}
	if got.Total != 1500 {
		t.Fatalf("GetBalance: got Total=%d, want 1500 (available+pending_incoming+timelocked, excluding pending_outgoing)", got.Total)
	}
}

func TestTariWalletGRPC_GetBalance_RPCErrorPropagates(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{balanceErr: errors.New("wallet unreachable")}, defaultFeePerGram)
	if _, err := w.GetBalance(context.Background()); err == nil {
		t.Fatal("GetBalance: expected an error when the RPC call fails")
	}
}

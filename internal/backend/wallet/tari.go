// Copyright and license: see repository LICENSE (MIT).
package wallet

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"github.com/Snipa22/go-tari-grpc-lib/v3/walletGRPC"
)

// defaultFeePerGram is the fee-per-gram used when neither
// WithFeePerGram nor a positive TransferRequest.Priority supplies one
// (see Transfer's doc comment on how Priority is reinterpreted for
// Tari). 5 is not invented for this package — it is the exact value
// go-tari-grpc-lib/v3/walletGRPC's own legacy SubmitCoinSplitRequest
// helper hardcodes for its FeePerGram param (wallet.go in that
// package), i.e. the one real fee-per-gram constant already blessed
// elsewhere in this dependency for a real wallet-GRPC call.
const defaultFeePerGram = 5

// tariWalletRPC is the narrow slice of go-tari-grpc-lib/v3's
// walletGRPC package-level API TariWalletGRPC actually needs. This
// mirrors internal/backend/chain/tari.go's tariNodeRPC exactly: it
// exists purely so tests can inject a fake without a real Tari
// console/base wallet, because walletGRPC (like nodeGRPC) exposes a
// package-level singleton connection with no injectable client type.
type tariWalletRPC interface {
	Transfer(recipients []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error)
	GetBalance() (*tari_generated.GetBalanceResponse, error)
	GetTransactionInfo(transactionID uint64) (*tari_generated.TransactionInfo, error)
}

// tariWalletRPCAdapter adapts walletGRPC's package-level functions to
// tariWalletRPC.
type tariWalletRPCAdapter struct{}

func (tariWalletRPCAdapter) Transfer(recipients []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	return walletGRPC.SendTransactions(recipients)
}

func (tariWalletRPCAdapter) GetBalance() (*tari_generated.GetBalanceResponse, error) {
	return walletGRPC.GetBalances()
}

func (tariWalletRPCAdapter) GetTransactionInfo(transactionID uint64) (*tari_generated.TransactionInfo, error) {
	return walletGRPC.GetTransactionInfoByID(transactionID)
}

// TariWalletGRPC is the production WalletClient for Tari (ALGO_RXT/
// ALGO_C29/ALGO_SHA3X — the same three-algo grouping as
// internal/backend/chain.TariVerifier), backed by a real Tari
// console/base wallet GRPC connection. It is deliberately independent
// of TariVerifier: that type talks to a Tari base node (read-only
// chain queries); this one talks to a Tari wallet process (real
// fund-moving RPCs) — same base-node/wallet trust-boundary split this
// package's doc comment (wallet.go) already draws for Monero.
type TariWalletGRPC struct {
	rpc tariWalletRPC
	// feePerGram is the default fee_per_gram used for a Transfer
	// call whose TransferRequest.Priority is zero. See Transfer's
	// doc comment on Priority reinterpretation.
	feePerGram uint64
}

// TariOption configures an optional TariWalletGRPC construction
// knob.
type TariOption func(*tariWalletGRPCOptions)

type tariWalletGRPCOptions struct {
	feePerGram uint64
}

// WithFeePerGram overrides defaultFeePerGram as the fee-per-gram used
// for any Transfer call whose TransferRequest.Priority is zero.
func WithFeePerGram(feePerGram uint64) TariOption {
	return func(o *tariWalletGRPCOptions) {
		o.feePerGram = feePerGram
	}
}

// NewTariWalletGRPC dials address (host:port) via
// walletGRPC.InitWalletGRPC (a process-wide singleton connection —
// see this file's tariWalletRPC doc comment, and
// internal/backend/chain.NewTariVerifier's identical constraint for
// nodeGRPC) and returns a ready-to-use TariWalletGRPC. Only one
// TariWalletGRPC's worth of walletGRPC usage should exist per
// process.
func NewTariWalletGRPC(address string, opts ...TariOption) *TariWalletGRPC {
	o := tariWalletGRPCOptions{feePerGram: defaultFeePerGram}
	for _, opt := range opts {
		opt(&o)
	}
	walletGRPC.InitWalletGRPC(address)
	return &TariWalletGRPC{rpc: tariWalletRPCAdapter{}, feePerGram: o.feePerGram}
}

// newTariWalletGRPCWithRPC is the test seam: constructs a
// TariWalletGRPC against an injected fake tariWalletRPC instead of
// the real process-wide walletGRPC singleton.
func newTariWalletGRPCWithRPC(rpc tariWalletRPC, feePerGram uint64) *TariWalletGRPC {
	if feePerGram == 0 {
		feePerGram = defaultFeePerGram
	}
	return &TariWalletGRPC{rpc: rpc, feePerGram: feePerGram}
}

// Transfer implements WalletClient via a real Tari wallet GRPC
// "Transfer" call. Two coin-agnostic TransferRequest fields do not
// map onto any real Tari concept and are handled as follows:
//
//   - RingSize has no Tari equivalent at all (Tari is not a
//     ring-signature scheme) and is ignored, exactly like
//     MoneroWalletRPC.Transfer ignores fields with no meaning for its
//     coin.
//   - Priority is documented (wallet.go) as "the real
//     monero-wallet-rpc fee-priority value" — Tari has no such enum,
//     but it does have a real, required numeric fee knob
//     (PaymentRecipient.fee_per_gram, see tari_protos/wallet.proto).
//     Rather than silently dropping every caller's fee intent, a
//     positive Priority is reinterpreted directly as this transfer's
//     fee_per_gram; Priority == 0 falls back to feePerGram
//     (defaultFeePerGram unless overridden via WithFeePerGram). This
//     is a deliberate, documented divergence from the field's
//     Monero-oriented doc comment, not an attempt to fake a
//     real Monero priority scale for Tari.
//
// Every Destination becomes its own real PaymentRecipient with
// PaymentType ONE_SIDED_TO_STEALTH_ADDRESS — the only non-deprecated
// payment type in tari_protos/wallet.proto's PaymentRecipient enum,
// and the correct choice for a pool payout: STANDARD_MIMBLEWIMBLE and
// the plain ONE_SIDED variant are both marked deprecated in the real
// .proto, and a pool cannot rely on an arbitrary miner's wallet being
// online to interactively participate in a standard Mimblewimble
// transaction anyway (a one-sided variant is required regardless of
// deprecation).
//
// req.PaymentID, if non-empty, is attached as every recipient's
// RawPaymentId (raw bytes of the string) — the real Tari wallet GRPC
// has no single request-level payment ID field the way monero-wallet-
// rpc's "transfer" does; PaymentRecipient carries it per-recipient
// instead, so the same PaymentID is simply repeated across every
// Destination in the request.
//
// KNOWN GAP: TransferRequest can carry multiple Destinations, and the
// real Tari wallet GRPC's TransferResponse reports success/failure
// PER RECIPIENT (TransferResult.IsSuccess), not for the whole batch.
// If any recipient fails while others succeed, this method returns a
// non-nil error for the whole call — but the succeeded recipients'
// transactions have already been broadcast for real; there is
// currently no way for a caller to learn which specific destinations
// went through in that partial-failure case. Deployments that cannot
// tolerate this should send one Destination per TransferRequest.
func (w *TariWalletGRPC) Transfer(ctx context.Context, req TransferRequest) (TransferResult, error) {
	if len(req.Destinations) == 0 {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: at least one destination is required")
	}
	// SAFETY CONSTRAINT, deliberate and load-bearing, not a
	// placeholder TODO: the real tari.rpc.Wallet/Transfer RPC
	// (SendTransactions) reports success/failure PER RECIPIENT
	// (TransferResult.IsSuccess/FailureMessage below), but this
	// package's coin-agnostic WalletClient.Transfer contract (see
	// wallet.go) is strictly all-or-nothing: one TransferResult, one
	// error. internal/backend/disburse.Engine relies on that
	// all-or-nothing contract for its own core safety property (a
	// failed Transfer call debits NOTHING, so a batch is always
	// safely retriable next cycle) — if this call accepted more than
	// one destination and the real RPC came back with a genuine
	// partial failure (some recipients succeeded, one failed), the
	// real, successfully-broadcast recipients would have already
	// moved real on-chain coin, yet this call would still report a
	// whole-batch error, and disburse.Engine would never debit any of
	// them — causing a real DOUBLE-PAYMENT the next time that same
	// batch is retried. Until WalletClient's interface is extended to
	// carry real per-destination results (a genuine, deliberate
	// design decision for whoever picks this up, not something to
	// improvise here), the only safe thing this implementation can do
	// is refuse more than one destination per call, which makes
	// partial failure structurally impossible (a single destination
	// either succeeds or fails, there is no "partial"). Callers
	// needing to pay multiple Tari recipients must issue one
	// TransferRequest per destination — see
	// disburse.Config.MaxDestinationsPerBatch's doc comment, which
	// callers configuring a Tari WalletClient MUST set to 1.
	if len(req.Destinations) > 1 {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: refusing %d destinations in one call — Tari's real Transfer RPC reports success/failure per recipient, but this WalletClient implementation only supports strictly all-or-nothing batches until the interface carries per-destination results; callers must issue one destination per TransferRequest for Tari (see this method's doc comment)", len(req.Destinations))
	}

	feePerGram := w.feePerGram
	if req.Priority > 0 {
		feePerGram = uint64(req.Priority)
	}

	var rawPaymentID []byte
	if req.PaymentID != "" {
		rawPaymentID = []byte(req.PaymentID)
	}

	recipients := make([]*tari_generated.PaymentRecipient, 0, len(req.Destinations))
	for _, d := range req.Destinations {
		if d.Amount <= 0 {
			return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: destination %s has non-positive amount %d", d.Address, d.Amount)
		}
		if d.Address == "" {
			return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: destination has an empty address")
		}
		recipients = append(recipients, &tari_generated.PaymentRecipient{
			Address:      d.Address,
			Amount:       uint64(d.Amount),
			FeePerGram:   feePerGram,
			PaymentType:  tari_generated.PaymentRecipient_ONE_SIDED_TO_STEALTH_ADDRESS,
			RawPaymentId: rawPaymentID,
		})
	}

	resp, err := w.rpc.Transfer(recipients)
	if err != nil {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: %w", err)
	}
	if resp == nil || len(resp.Results) == 0 {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: RPC reported success but returned no results")
	}

	var (
		totalFee    int64
		totalAmount int64
		txIDs       = make([]string, 0, len(resp.Results))
		failures    []string
	)
	for _, result := range resp.Results {
		if result == nil {
			continue
		}
		if !result.IsSuccess {
			failures = append(failures, fmt.Sprintf("%s: %s", result.GetAddress(), result.GetFailureMessage()))
			continue
		}
		txIDs = append(txIDs, strconv.FormatUint(result.GetTransactionId(), 10))

		info := result.GetTransactionInfo()
		if info == nil {
			// The real Transfer response does not always inline
			// TransactionInfo — fall back to a real
			// GetTransactionInfo lookup for this transaction ID
			// (the same real RPC the legacy
			// walletGRPC.GetTransactionInfoByID helper wraps)
			// rather than reporting a fabricated zero fee/amount.
			info, err = w.rpc.GetTransactionInfo(result.GetTransactionId())
			if err != nil {
				return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: recipient %s succeeded (tx id %d) but fetching its fee/amount via GetTransactionInfo failed: %w",
					result.GetAddress(), result.GetTransactionId(), err)
			}
		}
		if info != nil {
			totalFee += int64(info.GetFee())
			totalAmount += int64(info.GetAmount())
		}
	}

	if len(failures) > 0 {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: %d of %d recipient(s) failed (already-succeeded recipients, if any, were still broadcast for real): %s",
			len(failures), len(resp.Results), strings.Join(failures, "; "))
	}
	if len(txIDs) == 0 {
		return TransferResult{}, fmt.Errorf("wallet: tari: Transfer: RPC reported success but no successful results were returned")
	}

	return TransferResult{
		TxHash: strings.Join(txIDs, ","),
		Fee:    totalFee,
		Amount: totalAmount,
	}, nil
}

// GetBalance implements WalletClient via a real Tari wallet GRPC
// "GetBalance" call. The real GetBalanceResponse has no single
// "total"/"unlocked" pair the way monero-wallet-rpc's get_balance
// does — it reports available_balance, pending_incoming_balance,
// pending_outgoing_balance and timelocked_balance separately (see
// tari_protos/wallet.proto). This maps them as:
//
//   - Unlocked = available_balance: the real, immediately spendable
//     figure, which is exactly the field internal/backend/disburse
//     checks a payout batch against (see wallet.go's Balance.Unlocked
//     doc comment).
//   - Total = available_balance + pending_incoming_balance +
//     timelocked_balance: every real output the wallet already owns,
//     whether or not it is currently spendable — the Tari-side
//     analog of Balance.Total's "including unconfirmed/locked
//     change" doc comment. pending_outgoing_balance is deliberately
//     excluded: those coins have already left the spendable set to
//     pay for an in-flight transaction (they are its inputs, being
//     consumed), not additional funds the wallet still owns on top of
//     available_balance.
func (w *TariWalletGRPC) GetBalance(ctx context.Context) (Balance, error) {
	resp, err := w.rpc.GetBalance()
	if err != nil {
		return Balance{}, fmt.Errorf("wallet: tari: GetBalance: %w", err)
	}
	if resp == nil {
		return Balance{}, fmt.Errorf("wallet: tari: GetBalance: RPC reported success but returned no response")
	}
	return Balance{
		Total:    int64(resp.GetAvailableBalance() + resp.GetPendingIncomingBalance() + resp.GetTimelockedBalance()),
		Unlocked: int64(resp.GetAvailableBalance()),
	}, nil
}

var _ WalletClient = (*TariWalletGRPC)(nil)
